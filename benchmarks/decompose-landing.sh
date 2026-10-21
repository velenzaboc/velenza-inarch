#!/usr/bin/env bash
# Decompose one remote-mode `inr commit` (the serve_land workload of bench-vs-git.sh) into its RPCs.
#
# Starts one loopback `inr serve` on a scratch tree kept by `bench-vs-git.sh --keep-work`, puts the
# transparent TCP relay `rpc-relay.py` between client and server, lands a one-line change from a
# fresh sparse checkout several times, and records per RPC its kind, bytes, server service time and
# client think time, plus the server process's CPU time and bytes read per landing. One round bypasses
# the relay to show its overhead, one lands the same change through the local filesystem stores of the
# same scratch tree with no server at all (the engine's own `land_patch` cost), and one `inr refs` call
# gives the round-trip floor.
#
# Usage: decompose-landing.sh --work-dir DIR [--inr PATH] [--output-dir DIR] [--prefix P] [--file F]
#                             [--rounds N] [--port PORT] [--host-label LABEL]
set -euo pipefail
if (( BASH_VERSINFO[0] < 4 )); then
  if [[ -x /opt/homebrew/bin/bash ]]; then exec /opt/homebrew/bin/bash "$0" "$@"; fi
  echo "bash 4 or newer is required" >&2
  exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="" INR="" OUT="" PREFIX="services/svc-00" FILE="services/svc-00/mod_0.rs" ROUNDS=3 PORT=17990 HOST_LABEL="host"
while (( $# )); do
  case "$1" in
    --work-dir) WORK="$2"; shift 2 ;;
    --inr) INR="$2"; shift 2 ;;
    --output-dir) OUT="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --file) FILE="$2"; shift 2 ;;
    --rounds) ROUNDS="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --host-label) HOST_LABEL="$2"; shift 2 ;;
    -h|--help) awk 'NR >= 2 && NR <= 11 {sub(/^# ?/, ""); print}' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$WORK" ]] || { echo "--work-dir is required: a scratch tree kept by bench-vs-git.sh --keep-work" >&2; exit 2; }
WORK="$(cd "$WORK" && pwd)"
CFG="$WORK/cfg-server/.inarch/config.toml"
[[ -r "$CFG" && -d "$WORK/bench-home" ]] || { echo "work dir lacks cfg-server/.inarch/config.toml or bench-home" >&2; exit 2; }
LOCAL_CFG="$WORK/cfg-local/.inarch/config.toml"
[[ -r "$LOCAL_CFG" ]] || { echo "work dir lacks cfg-local/.inarch/config.toml" >&2; exit 2; }
[[ -n "$INR" ]] || INR="$HERE/../target/release/inr"
[[ -x "$INR" ]] || { echo "inr binary not executable: $INR" >&2; exit 2; }
INR="$(cd "$(dirname "$INR")" && pwd)/$(basename "$INR")"
MEASURE="$HERE/measure.py"
RELAY="$HERE/rpc-relay.py"
[[ -r "$MEASURE" && -r "$RELAY" ]] || { echo "measure.py and rpc-relay.py must sit beside this script" >&2; exit 2; }
(( ROUNDS >= 1 )) || ROUNDS=1
[[ -n "$OUT" ]] || OUT="$HERE/results/decomposition-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
RPORT=$((PORT + 1))
STARTED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ORIG_USER="$(id -un)"
ORIG_HOST="$(hostname)"
ORIG_HOME="$HOME"

export HOME="$WORK/bench-home" INARCH_USER_CONFIG="$WORK/bench-home/no-user-config.toml"
unset INARCH_REMOTE_URL INARCH_AUTH_TOKEN INARCH_REPO_ID INARCH_STORE_DIR INARCH_CONFIG \
  INARCH_TIER1_CACHE_DIR INARCH_TIER2_CACHE_DIR INARCH_BLOB_BACKEND INARCH_META_BACKEND INARCH_LOG_BACKEND
T1="${XDG_CACHE_HOME:-$HOME/.cache}/velenza-inarch/t1"
WC="$WORK/decompose-wc"
SPID="" RPID=""

cleanup() {
  [[ -n "$RPID" ]] && kill "$RPID" 2>/dev/null || true
  [[ -n "$SPID" ]] && kill "$SPID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$WC"
}
trap cleanup EXIT INT TERM

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }
wait_port() {
  local p="$1" i
  for i in $(seq 1 200); do
    (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null && return 0
    sleep 0.05
  done
  echo "port $p never opened" >&2
  return 1
}
server_cpu_ms() {   # cumulative CPU time of the server process in ms (Linux: /proc ticks; macOS: ps cputime, 10 ms resolution)
  if [[ -r "/proc/$SPID/stat" ]]; then
    awk -v tck="$(getconf CLK_TCK)" '{print int(($14 + $15) * 1000 / tck)}' "/proc/$SPID/stat"
  else
    ps -p "$SPID" -o cputime= | awk -F'[:.]' '{ if (NF == 3 && index($0, ".") > 0) print ($1 * 60 + $2) * 1000 + $3 * 10; else if (NF == 3) print ($1 * 3600 + $2 * 60 + $3) * 1000; else print ($1 * 60 + $2) * 1000 }'
  fi
}
server_rchar() { if [[ -r "/proc/$SPID/io" ]]; then awk '/^rchar:/ {print $2}' "/proc/$SPID/io"; else printf ''; fi; }
fresh_wc() { rm -rf "$WC"; INARCH_CONFIG="$1" "$INR" checkout main "$WC" --prefix "$PREFIX" >/dev/null 2>&1; }   # $1: config of the store to check out from

log "inr $("$INR" --version 2>/dev/null | head -n 1 || true)"
log "serve on 127.0.0.1:$PORT, relay on 127.0.0.1:$RPORT, $ROUNDS relayed round(s), prefix $PREFIX, file $FILE"
( INARCH_CONFIG="$CFG" INARCH_LOG_BACKEND=stderr exec "$INR" serve --listen "127.0.0.1:$PORT" 2>"$OUT/server.jsonl" >/dev/null ) &
SPID=$!
wait_port "$PORT"
( exec python3 "$RELAY" --listen "127.0.0.1:$RPORT" --upstream "127.0.0.1:$PORT" --log "$OUT/rpc.csv" >"$OUT/relay.log" 2>&1 ) &
RPID=$!
wait_port "$RPORT"

printf 'round,mode,wall_us,exit_code,max_rss_kb,land_patch_us,server_cpu_ms,server_rchar_delta,rpc_rows\n' > "$OUT/rounds.csv"
ROWS_BEFORE=0
run_round() {   # $1 label, $2 mode: relay | direct | local | refs
  local label="$1" mode="$2" url cpu0 cpu1 rc0 rc1 res lp rows rcd added
  case "$mode" in
    relay|refs) url="http://127.0.0.1:$RPORT" ;;
    *) url="http://127.0.0.1:$PORT" ;;
  esac
  if [[ "$mode" == local ]]; then
    fresh_wc "$LOCAL_CFG"
    printf '// decompose %s\n' "$label" >> "$WC/$FILE"
  elif [[ "$mode" != refs ]]; then
    fresh_wc "$CFG"
    printf '// decompose %s\n' "$label" >> "$WC/$FILE"
  fi
  cpu0="$(server_cpu_ms)"; rc0="$(server_rchar)"
  if [[ "$mode" == refs ]]; then
    INARCH_CONFIG="$CFG" INARCH_REMOTE_URL="$url" \
      python3 "$MEASURE" "$OUT/round-$label.result" -- "$INR" refs >/dev/null 2>"$OUT/round-$label.client.jsonl" || true
  elif [[ "$mode" == local ]]; then
    INARCH_CONFIG="$LOCAL_CFG" INARCH_LOG_BACKEND=stderr \
      python3 "$MEASURE" "$OUT/round-$label.result" -- "$INR" commit -m "decompose $label" "$WC" >/dev/null 2>"$OUT/round-$label.client.jsonl" || true
  else
    INARCH_CONFIG="$CFG" INARCH_REMOTE_URL="$url" INARCH_LOG_BACKEND=stderr \
      python3 "$MEASURE" "$OUT/round-$label.result" -- "$INR" commit -m "decompose $label" "$WC" >/dev/null 2>"$OUT/round-$label.client.jsonl" || true
  fi
  cpu1="$(server_cpu_ms)"; rc1="$(server_rchar)"
  res="$(cat "$OUT/round-$label.result")"
  lp="$(awk 'match($0, /"duration_us":[0-9]+/) {print substr($0, RSTART + 14, RLENGTH - 14)}' "$OUT/round-$label.client.jsonl" | tail -n 1)"
  rows=$(( $(wc -l < "$OUT/rpc.csv") - 1 ))
  added=$((rows - ROWS_BEFORE))
  ROWS_BEFORE=$rows
  rcd=""; [[ -n "$rc0" && -n "$rc1" ]] && rcd=$((rc1 - rc0))
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$label" "$mode" "$(awk '{print $1}' <<<"$res")" "$(awk '{print $2}' <<<"$res")" \
    "$(awk '{print $3}' <<<"$res")" "$lp" "$((cpu1 - cpu0))" "$rcd" "$added" >> "$OUT/rounds.csv"
  log "round $label ($mode): wall $(awk '{print $1}' <<<"$res") us, exit $(awk '{print $2}' <<<"$res"), land_patch ${lp:-n/a} us, server cpu $((cpu1 - cpu0)) ms, rpcs $added"
}

rm -rf "$T1"
run_round cold relay
for (( i = 2; i <= ROUNDS; i++ )); do run_round "warm$i" relay; done
run_round direct direct
run_round local local
run_round refs refs

kill "$RPID" 2>/dev/null || true; wait "$RPID" 2>/dev/null || true; RPID=""
kill "$SPID" 2>/dev/null || true; wait "$SPID" 2>/dev/null || true; SPID=""
log "server telemetry events: $(wc -l < "$OUT/server.jsonl" | tr -d ' ')"

# Summary, metadata, redaction and sterility scan (standard-library Python).
DECOMP_OUT="$OUT" DECOMP_WORK="$WORK" DECOMP_HOME="$ORIG_HOME" DECOMP_USER="$ORIG_USER" DECOMP_HOST="$ORIG_HOST" \
DECOMP_LABEL="$HOST_LABEL" DECOMP_INR="$INR" DECOMP_STARTED="$STARTED_UTC" DECOMP_PREFIX="$PREFIX" DECOMP_FILE="$FILE" \
DECOMP_SCRIPT="${BASH_SOURCE[0]}" DECOMP_MEASURE="$MEASURE" DECOMP_RELAY="$RELAY" python3 - <<'PY'
import csv, hashlib, json, os, platform, re, subprocess, sys
out = os.environ["DECOMP_OUT"]

def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()

def ms(us):
    return "%.2f" % (int(us) / 1000.0)

rounds = list(csv.DictReader(open(os.path.join(out, "rounds.csv"))))
rpcs = list(csv.DictReader(open(os.path.join(out, "rpc.csv"))))
# Assign relay rows to rounds in order of appearance (rows are written per connection when it closes).
rows_per_round = []
for r in rounds:
    n = int(r["rpc_rows"] or 0)
    if n:
        rows_per_round.append((r["round"], n))
chunks, pos = {}, 0
for label, n in rows_per_round:
    chunks[label] = rpcs[pos:pos + n]
    pos += n

lines = []
lines.append("# One `serve_land` landing decomposed (`%s`)" % os.environ["DECOMP_LABEL"])
lines.append("")
lines.append("Produced by `decompose-landing.sh` with `rpc-relay.py` between `inr commit` and `inr serve` on the loopback interface.")
lines.append("Server service time is `resp_done - req_done` as seen by the relay; client gap is the time from the previous")
lines.append("response on the same connection to the next request. The `direct` round bypasses the relay; `local` lands the")
lines.append("same change through the local filesystem stores of the same scratch tree inside the client process, with no")
lines.append("server and no RPC; `refs` is one `ListRefs` call from a fresh process and gives the floor for process start")
lines.append("plus one round trip.")
lines.append("")
lines.append("## Rounds")
lines.append("")
lines.append("| Round | Mode | Wall ms | `land_patch` ms | Server CPU ms | Server bytes read | RPCs | Exit | Peak RSS MiB |")
lines.append("| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
for r in rounds:
    lines.append("| %s | %s | %s | %s | %s | %s | %s | %s | %.1f |" % (
        r["round"], r["mode"], ms(r["wall_us"]), ms(r["land_patch_us"]) if r["land_patch_us"] else "n/a",
        r["server_cpu_ms"], ("{:,}".format(int(r["server_rchar_delta"])) if r["server_rchar_delta"] else "n/a"),
        r["rpc_rows"], r["exit_code"], int(r["max_rss_kb"]) / 1024.0))
lines.append("")
for label, rows in chunks.items():
    rows = sorted(rows, key=lambda x: int(x["req_first_us"] or 0))
    last_done = {}
    lines.append("## RPCs of round `%s`" % label)
    lines.append("")
    lines.append("| # | Conn | Request | Req bytes | Response | Resp bytes | Client gap ms | Server service ms |")
    lines.append("| ---: | ---: | :--- | ---: | :--- | ---: | ---: | ---: |")
    total_service = 0
    for i, x in enumerate(rows, 1):
        gap = ""
        if x["conn"] in last_done and x["req_first_us"]:
            gap = ms(int(x["req_first_us"]) - last_done[x["conn"]])
        service = ""
        if x["resp_done_us"] and x["req_done_us"]:
            service = ms(int(x["resp_done_us"]) - int(x["req_done_us"]))
            total_service += int(x["resp_done_us"]) - int(x["req_done_us"])
        if x["resp_done_us"]:
            last_done[x["conn"]] = int(x["resp_done_us"])
        lines.append("| %d | %s | %s%s | %s | %s%s | %s | %s | %s |" % (
            i, x["conn"], x["req_op"], " (lz4)" if x["req_compressed"] == "1" else "", "{:,}".format(int(x["req_bytes"])),
            x["resp_op"], " (lz4)" if x["resp_compressed"] == "1" else "", "{:,}".format(int(x["resp_bytes"])), gap, service))
    first = min(int(x["req_first_us"]) for x in rows if x["req_first_us"])
    last = max(int(x["resp_done_us"]) for x in rows if x["resp_done_us"])
    lines.append("")
    lines.append("Sum of server service time: %s ms; first request to last response: %s ms." % (ms(total_service), ms(last - first)))
    lines.append("")
open(os.path.join(out, "summary.md"), "w").write("\n".join(lines) + "\n")

uname = platform.uname()
meta = {
    "host_label": os.environ["DECOMP_LABEL"],
    "started_utc": os.environ["DECOMP_STARTED"],
    "os": uname.system, "os_release": uname.release, "machine": uname.machine,
    "inr_version": (subprocess.run([os.environ["DECOMP_INR"], "--version"], capture_output=True, text=True).stdout.strip().splitlines() or [""])[0],
    "inr_sha256": sha(os.environ["DECOMP_INR"]),
    "script_sha256": sha(os.environ["DECOMP_SCRIPT"]),
    "relay_sha256": sha(os.environ["DECOMP_RELAY"]),
    "measure_sha256": sha(os.environ["DECOMP_MEASURE"]),
    "python": platform.python_version(),
    "prefix": os.environ["DECOMP_PREFIX"], "file": os.environ["DECOMP_FILE"],
    "rounds": rounds,
    "notes": [
        "server CPU time is the server process's cumulative user+system CPU delta across the round (Linux /proc ticks; macOS ps cputime at 10 ms resolution)",
        "server bytes read is the rchar delta from /proc/<pid>/io on Linux and absent on macOS",
        "rpc.csv rows are written when a connection closes; rounds.csv attributes them to rounds by count in order",
    ],
}
json.dump(meta, open(os.path.join(out, "metadata.json"), "w"), indent=2, sort_keys=True)
open(os.path.join(out, "metadata.json"), "a").write("\n")

# Redact absolute paths and scan every text file for identifying byte sequences.
subs = [(os.environ["DECOMP_WORK"], "<work>"), (out, "<out>"), (os.path.dirname(os.environ["DECOMP_INR"]), "<bin>"),
        (os.environ["DECOMP_HOME"], "<home>")]
subs.sort(key=lambda s: -len(s[0]))
pats = [re.compile(r"/(Users|Volumes|home)/[A-Za-z0-9]"), re.compile(r"C:\\Users\\[A-Za-z0-9]"), re.compile(r"C:/Users/[A-Za-z0-9]"),
        re.compile(r"\b100\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
        re.compile(r"\b%s\b" % re.escape(os.environ["DECOMP_USER"]), re.I), re.compile(re.escape(os.environ["DECOMP_HOST"]), re.I)]
bad = []
for name in sorted(os.listdir(out)):
    p = os.path.join(out, name)
    try:
        text = open(p, encoding="utf-8").read()
    except (UnicodeDecodeError, IsADirectoryError):
        continue
    new = text
    for a, b in subs:
        if a:
            new = new.replace(a, b)
    if new != text:
        open(p, "w").write(new)
    for pat in pats:
        m = pat.search(new)
        if m:
            bad.append("%s: %r matches %s" % (name, m.group(0), pat.pattern))
if bad:
    print("STERILITY VIOLATION:\n  " + "\n  ".join(bad), file=sys.stderr)
    sys.exit(3)
print("sterility scan clean:", ", ".join(sorted(os.listdir(out))))
PY
log "done: $OUT"
