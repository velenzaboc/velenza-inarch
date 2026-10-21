#!/usr/bin/env python3
"""Transparent TCP relay between an ``inr`` client and ``inr serve`` that logs every RPC exchange.

Usage: rpc-relay.py --listen HOST:PORT --upstream HOST:PORT --log FILE

Every byte is forwarded unchanged in both directions. The relay only watches the stream: it splits
the HTTP/1.1 messages on their ``Content-Length`` bodies and, when a connection closes, writes one
CSV row per request/response pair:

    conn,seq,req_first_us,req_done_us,resp_first_us,resp_done_us,req_bytes,resp_bytes,
    req_op,req_compressed,resp_op,resp_compressed

Times are monotonic microseconds since the relay started. ``resp_done_us - req_done_us`` is the
server's service time for that request as seen from the client side of the loopback;
``req_first_us`` minus the previous ``resp_done_us`` on the same connection is the client's think
time between two requests. The op is read from the ``OSRP`` frame: byte 5 of an uncompressed
frame, or the first literal byte of the LZ4 block of a compressed frame. Only the standard library
is used.
"""
import argparse
import asyncio
import re
import socket
import sys
import time

REQ_OPS = {
    1: "PutObjectsBatch", 2: "GetObjectsBatch", 3: "HasObject", 4: "PutChangeset", 5: "GetChangeset",
    6: "GetRef", 7: "ListRefs", 8: "CasRef", 9: "PutDerivedMapping", 10: "GetDerivedMapping",
    11: "WhoAmI", 12: "EnrollPrincipal", 13: "GetPrincipal", 14: "ListPrincipals", 15: "RevokePrincipal",
    16: "CheckoutLease", 17: "GetLease", 18: "RenewLease", 19: "RevokeLease", 20: "ListLeases",
    21: "PutLease", 22: "HasObjectsBatch",
}
RESP_OPS = {
    1: "PutObjectsBatchOk", 2: "GetObjectsBatch", 3: "HasObject", 4: "PutChangeset", 5: "GetChangeset",
    6: "GetRef", 7: "ListRefs", 8: "CasRefOk", 9: "CasRefConflict", 10: "PutDerivedMappingOk",
    11: "GetDerivedMapping", 12: "WhoAmI", 13: "EnrollPrincipalOk", 14: "GetPrincipal", 15: "ListPrincipals",
    16: "RevokePrincipalOk", 17: "CheckoutLease", 18: "GetLease", 19: "RenewLease", 20: "RevokeLeaseOk",
    21: "ListLeases", 22: "PutLeaseOk", 23: "HasObjectsBatch", 255: "Error",
}
T0 = time.monotonic_ns()
CL_RE = re.compile(rb"(?im)^content-length:\s*(\d+)\s*$")


def now_us():
    return (time.monotonic_ns() - T0) // 1000


def frame_op(body, table):
    """Return (op_name, compressed_flag) for one OSRP frame."""
    if len(body) < 6 or body[:4] != b"OSRP":
        return ("not-osrp", 0)
    if body[4] & 0x80:
        # [OSRP][ver|0x80][u32 LE uncompressed length][LZ4 block]; the block's first literal run
        # starts with the op byte because the encoder cannot emit a match at offset 0.
        src = body[9:]
        if not src:
            return ("compressed-empty", 1)
        lit = src[0] >> 4
        pos = 1
        if lit == 15:
            while pos < len(src) and src[pos] == 255:
                pos += 1
            pos += 1
        if lit == 0 or pos >= len(src):
            return ("compressed-nolit", 1)
        return (table.get(src[pos], "op%d" % src[pos]), 1)
    return (table.get(body[5], "op%d" % body[5]), 0)


class Parser:
    """Splits one direction of an HTTP/1.1 keep-alive stream into messages with Content-Length bodies."""

    def __init__(self):
        self.buf = b""
        self.state = "head"
        self.need = 0
        self.first = None
        self.done = []

    def feed(self, data, t):
        if self.first is None and data:
            self.first = t
        self.buf += data
        while True:
            if self.state == "head":
                i = self.buf.find(b"\r\n\r\n")
                if i < 0:
                    return
                head = self.buf[:i]
                self.buf = self.buf[i + 4:]
                m = CL_RE.search(head)
                self.need = int(m.group(1)) if m else 0
                self.state = "body"
            if len(self.buf) < self.need:
                return
            body = self.buf[:self.need]
            self.buf = self.buf[self.need:]
            self.done.append((self.first, t, body))
            self.first = t if self.buf else None
            self.state = "head"


async def pump(reader, writer, parser):
    while True:
        data = await reader.read(1 << 16)
        t = now_us()
        if not data:
            break
        parser.feed(data, t)
        writer.write(data)
        await writer.drain()
    try:
        writer.write_eof()
    except Exception:
        pass


def set_nodelay(writer):
    sock = writer.get_extra_info("socket")
    if sock is not None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


async def handle(client_r, client_w, upstream, log, conn_ids):
    conn_ids[0] += 1
    conn = conn_ids[0]
    host, port = upstream
    up_r, up_w = await asyncio.open_connection(host, port)
    set_nodelay(client_w)
    set_nodelay(up_w)
    req = Parser()
    resp = Parser()
    await asyncio.gather(pump(client_r, up_w, req), pump(up_r, client_w, resp))
    for seq in range(max(len(req.done), len(resp.done))):
        rq = req.done[seq] if seq < len(req.done) else (None, None, b"")
        rs = resp.done[seq] if seq < len(resp.done) else (None, None, b"")
        qop, qc = frame_op(rq[2], REQ_OPS)
        sop, sc = frame_op(rs[2], RESP_OPS)
        log.write("%d,%d,%s,%s,%s,%s,%d,%d,%s,%d,%s,%d\n" % (
            conn, seq + 1, rq[0], rq[1], rs[0], rs[1], len(rq[2]), len(rs[2]), qop, qc, sop, sc))
    log.flush()
    for w in (client_w, up_w):
        try:
            w.close()
        except Exception:
            pass


async def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--listen", required=True, help="HOST:PORT the client connects to")
    ap.add_argument("--upstream", required=True, help="HOST:PORT of inr serve")
    ap.add_argument("--log", required=True, help="CSV file to write")
    a = ap.parse_args()
    lh, lp = a.listen.rsplit(":", 1)
    uh, up = a.upstream.rsplit(":", 1)
    log = open(a.log, "w")
    log.write("conn,seq,req_first_us,req_done_us,resp_first_us,resp_done_us,req_bytes,resp_bytes,"
              "req_op,req_compressed,resp_op,resp_compressed\n")
    log.flush()
    conn_ids = [0]
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, (uh, int(up)), log, conn_ids), lh, int(lp))
    print("relay listening", a.listen, "->", a.upstream, flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
