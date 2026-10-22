//! Binary-framed batched RPC wire protocol and remote client/server adapters
//! (`RemoteBlobStore`, `RemoteMetadataStore`, and `handle_rpc_request`).
//!
//! Designed for high-throughput, low-latency operation across local daemons,
//! regional caches, and WAN/Tailscale links:
//! - Reuses persistent HTTP/1.1 `keep-alive` TCP connections.
//! - Transfers blobs in batched frames (`PutObjectsBatch`, `GetObjectsBatch`).
//! - Enforces end-to-end 256-bit BLAKE3 content verification on both client and server.
//! - Scopes mutable branch refs (`cas_ref`, `get_ref`, `list_refs`) by `repo_id`.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use inarch_types::bonsai::BonsaiChangeset;
use inarch_types::hash::{ChangesetId, ObjectDomain, ObjectHash};

use crate::{
    BlobStore, DerivedDataKind, JitLeaseRecord, MAX_JIT_LEASE_LIFETIME_SECS, MetadataStore,
    PrincipalRecord, StoreError, mint_jit_lease_token, verify_object_integrity,
};

const RPC_MAGIC: &[u8; 4] = b"OSRP";
const RPC_VERSION: u8 = 1;
/// High bit on the `OSRP` version byte indicating the payload following the 5-byte
/// magic+version header is prefixed with a 4-byte little-endian uncompressed length
/// and compressed with Velenza Inarch's byte-aligned LZ4-compatible frame codec.
pub const RPC_FLAG_COMPRESSED: u8 = 0x80;

/// Cumulative wire telemetry counters for a [`RemoteRpcClient`] / [`RemoteBlobStore`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RpcWireStats {
    pub requests_sent: u64,
    pub wire_bytes_sent: u64,
    pub wire_bytes_received: u64,
    pub uncompressed_bytes_sent: u64,
    pub uncompressed_bytes_received: u64,
}

/// Wire request variants for `/v1/rpc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcRequest {
    PutObjectsBatch {
        objects: Vec<(ObjectDomain, ObjectHash, Vec<u8>)>,
    },
    GetObjectsBatch {
        keys: Vec<(ObjectDomain, ObjectHash)>,
    },
    HasObject {
        domain: ObjectDomain,
        hash: ObjectHash,
    },
    HasObjectsBatch {
        keys: Vec<(ObjectDomain, ObjectHash)>,
    },
    PutChangeset {
        changeset: BonsaiChangeset,
    },
    GetChangeset {
        id: ChangesetId,
    },
    GetRef {
        repo_id: String,
        ref_name: String,
    },
    ListRefs {
        repo_id: String,
    },
    CasRef {
        repo_id: String,
        ref_name: String,
        expected: Option<ChangesetId>,
        new_target: ChangesetId,
    },
    PutDerivedMapping {
        cs_id: ChangesetId,
        kind: DerivedDataKind,
        derived_hash: ObjectHash,
    },
    GetDerivedMapping {
        cs_id: ChangesetId,
        kind: DerivedDataKind,
    },
    WhoAmI,
    EnrollPrincipal {
        record: PrincipalRecord,
    },
    GetPrincipal {
        principal_id: String,
    },
    ListPrincipals,
    RevokePrincipal {
        principal_id: String,
        revoked_at_unix: i64,
    },
    CheckoutLease {
        swarm_id: String,
        task_id: String,
        repo_id: String,
        allowed_ops: Vec<String>,
        allowed_read_prefixes: Vec<String>,
        allowed_write_prefixes: Vec<String>,
        ttl_secs: u64,
        allowed_refs: Vec<String>,
    },
    GetLease {
        lease_id: String,
    },
    RenewLease {
        lease_id: String,
        ttl_secs: u64,
    },
    RevokeLease {
        lease_id: String,
        revoked_at_unix: i64,
    },
    ListLeases {
        repo_id: Option<String>,
    },
    PutLease {
        record: JitLeaseRecord,
    },
}

/// Wire response variants for `/v1/rpc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcResponse {
    PutObjectsBatchOk,
    GetObjectsBatch {
        objects: Vec<Option<Vec<u8>>>,
    },
    HasObject {
        exists: bool,
    },
    HasObjectsBatch {
        present: Vec<bool>,
    },
    PutChangeset {
        id: ChangesetId,
    },
    GetChangeset {
        changeset: Option<BonsaiChangeset>,
    },
    GetRef {
        target: Option<ChangesetId>,
    },
    ListRefs {
        refs: BTreeMap<String, ChangesetId>,
    },
    CasRefOk,
    CasRefConflict {
        ref_name: String,
        expected: Option<ChangesetId>,
        actual: Option<ChangesetId>,
    },
    PutDerivedMappingOk,
    GetDerivedMapping {
        derived_hash: Option<ObjectHash>,
    },
    WhoAmI {
        principal_id: String,
        role: String,
        auth_method: String,
        lease: Option<JitLeaseRecord>,
    },
    EnrollPrincipalOk,
    GetPrincipal {
        record: Option<PrincipalRecord>,
    },
    ListPrincipals {
        principals: Vec<PrincipalRecord>,
    },
    RevokePrincipalOk,
    CheckoutLease {
        lease: JitLeaseRecord,
        token: String,
    },
    GetLease {
        lease: Option<JitLeaseRecord>,
    },
    RenewLease {
        lease: JitLeaseRecord,
        token: String,
    },
    RevokeLeaseOk,
    ListLeases {
        leases: Vec<JitLeaseRecord>,
    },
    PutLeaseOk,
    Error {
        message: String,
    },
}

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32, StoreError> {
    if *pos + 4 > data.len() {
        return Err(StoreError::SnapshotCorrupted(
            "unexpected EOF reading u32".into(),
        ));
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&data[*pos..*pos + 4]);
    *pos += 4;
    Ok(u32::from_le_bytes(b))
}

fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn read_u64(data: &[u8], pos: &mut usize) -> Result<u64, StoreError> {
    if *pos + 8 > data.len() {
        return Err(StoreError::SnapshotCorrupted(
            "unexpected EOF reading u64".into(),
        ));
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[*pos..*pos + 8]);
    *pos += 8;
    Ok(u64::from_le_bytes(b))
}

fn write_i64(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn read_i64(data: &[u8], pos: &mut usize) -> Result<i64, StoreError> {
    if *pos + 8 > data.len() {
        return Err(StoreError::SnapshotCorrupted(
            "unexpected EOF reading i64".into(),
        ));
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[*pos..*pos + 8]);
    *pos += 8;
    Ok(i64::from_le_bytes(b))
}

fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    write_u32(buf, bytes.len() as u32);
    buf.extend_from_slice(bytes);
}

fn read_bytes(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, StoreError> {
    let len = read_u32(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(StoreError::SnapshotCorrupted(
            "unexpected EOF reading bytes".into(),
        ));
    }
    let out = data[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(out)
}

fn write_str(buf: &mut Vec<u8>, s: &str) {
    write_bytes(buf, s.as_bytes());
}

fn read_str(data: &[u8], pos: &mut usize) -> Result<String, StoreError> {
    let bytes = read_bytes(data, pos)?;
    String::from_utf8(bytes).map_err(|e| StoreError::SnapshotCorrupted(e.to_string()))
}

fn write_str_vec(buf: &mut Vec<u8>, list: &[String]) {
    write_u32(buf, list.len() as u32);
    for s in list {
        write_str(buf, s);
    }
}

fn read_str_vec(data: &[u8], pos: &mut usize) -> Result<Vec<String>, StoreError> {
    let count = read_u32(data, pos)? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(read_str(data, pos)?);
    }
    Ok(out)
}

fn write_hash(buf: &mut Vec<u8>, h: &ObjectHash) {
    buf.extend_from_slice(h.as_bytes());
}

fn read_hash(data: &[u8], pos: &mut usize) -> Result<ObjectHash, StoreError> {
    if *pos + 32 > data.len() {
        return Err(StoreError::SnapshotCorrupted(
            "unexpected EOF reading hash".into(),
        ));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&data[*pos..*pos + 32]);
    *pos += 32;
    Ok(ObjectHash(b))
}

fn write_opt_cs_id(buf: &mut Vec<u8>, id: &Option<ChangesetId>) {
    match id {
        Some(cs) => {
            buf.push(1);
            write_hash(buf, &cs.0);
        }
        None => buf.push(0),
    }
}

fn read_opt_cs_id(data: &[u8], pos: &mut usize) -> Result<Option<ChangesetId>, StoreError> {
    if *pos >= data.len() {
        return Err(StoreError::SnapshotCorrupted(
            "unexpected EOF reading opt_cs_id".into(),
        ));
    }
    let tag = data[*pos];
    *pos += 1;
    match tag {
        0 => Ok(None),
        1 => Ok(Some(ChangesetId(read_hash(data, pos)?))),
        other => Err(StoreError::SnapshotCorrupted(format!(
            "invalid opt_cs_id tag: {}",
            other
        ))),
    }
}

fn encode_domain(d: ObjectDomain) -> u8 {
    match d {
        ObjectDomain::Blob => 1,
        ObjectDomain::Chunk => 2,
        ObjectDomain::Changeset => 3,
        ObjectDomain::Fsnode => 4,
        ObjectDomain::UnodeFile => 5,
        ObjectDomain::UnodeManifest => 6,
        ObjectDomain::PathSearchIndex => 7,
        ObjectDomain::CopyInfo => 8,
    }
}

fn decode_domain(b: u8) -> Result<ObjectDomain, StoreError> {
    match b {
        1 => Ok(ObjectDomain::Blob),
        2 => Ok(ObjectDomain::Chunk),
        3 => Ok(ObjectDomain::Changeset),
        4 => Ok(ObjectDomain::Fsnode),
        5 => Ok(ObjectDomain::UnodeFile),
        6 => Ok(ObjectDomain::UnodeManifest),
        7 => Ok(ObjectDomain::PathSearchIndex),
        8 => Ok(ObjectDomain::CopyInfo),
        other => Err(StoreError::SnapshotCorrupted(format!(
            "unknown ObjectDomain tag: {}",
            other
        ))),
    }
}

fn encode_derived_kind(k: DerivedDataKind) -> u8 {
    match k {
        DerivedDataKind::Fsnode => 1,
        DerivedDataKind::Unode => 2,
        DerivedDataKind::BlameV2 => 3,
        DerivedDataKind::CommitGraph => 4,
        DerivedDataKind::PathSearchIndex => 5,
        DerivedDataKind::CopyDetection => 6,
    }
}

fn decode_derived_kind(b: u8) -> Result<DerivedDataKind, StoreError> {
    match b {
        1 => Ok(DerivedDataKind::Fsnode),
        2 => Ok(DerivedDataKind::Unode),
        3 => Ok(DerivedDataKind::BlameV2),
        4 => Ok(DerivedDataKind::CommitGraph),
        5 => Ok(DerivedDataKind::PathSearchIndex),
        6 => Ok(DerivedDataKind::CopyDetection),
        other => Err(StoreError::SnapshotCorrupted(format!(
            "unknown DerivedDataKind tag: {}",
            other
        ))),
    }
}

const RPC_COMPRESS_THRESHOLD: usize = 256;
const MAX_RPC_UNCOMPRESSED_BYTES: usize = 256 * 1024 * 1024;

#[inline]
fn lz4_hash4(bytes: &[u8], pos: usize) -> usize {
    let v = u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
    ((v.wrapping_mul(2654435761)) >> 18) as usize
}

/// Compresses an uncompressed `OSRP` v1 frame (`[b"OSRP", RPC_VERSION, op, ...]`) using
/// a fast, zero-dependency, byte-aligned LZ4 block stream when the payload is at least
/// `RPC_COMPRESS_THRESHOLD` bytes and compression strictly shrinks the frame size.
pub fn compress_rpc_frame(uncompressed_frame: &[u8]) -> Vec<u8> {
    if uncompressed_frame.len() < RPC_COMPRESS_THRESHOLD
        || uncompressed_frame.len() < 6
        || &uncompressed_frame[0..4] != RPC_MAGIC
        || uncompressed_frame[4] != RPC_VERSION
    {
        return uncompressed_frame.to_vec();
    }

    let src = &uncompressed_frame[5..];
    if src.len() > MAX_RPC_UNCOMPRESSED_BYTES {
        return uncompressed_frame.to_vec();
    }

    let mut out = Vec::with_capacity(9 + src.len() / 2);
    out.extend_from_slice(RPC_MAGIC);
    out.push(RPC_VERSION | RPC_FLAG_COMPRESSED);
    out.extend_from_slice(&(src.len() as u32).to_le_bytes());

    let mut dict = [0u32; 1 << 14];
    let mut anchor = 0usize;
    let mut ip = 0usize;
    let limit = src.len().saturating_sub(12);

    while ip < limit {
        let h = lz4_hash4(src, ip);
        let cand = dict[h] as usize;
        dict[h] = ip as u32;

        let offset = ip.wrapping_sub(cand);
        if offset > 0 && offset <= 0xFFFF && src[cand..cand + 4] == src[ip..ip + 4] {
            let lit_len = ip - anchor;
            let mut match_len = 4usize;
            while ip + match_len < src.len() && src[cand + match_len] == src[ip + match_len] {
                match_len += 1;
            }

            let lit_token = lit_len.min(15) as u8;
            let match_token = (match_len - 4).min(15) as u8;
            out.push((lit_token << 4) | match_token);

            if lit_len >= 15 {
                let mut rem = lit_len - 15;
                while rem >= 255 {
                    out.push(255);
                    rem -= 255;
                }
                out.push(rem as u8);
            }
            out.extend_from_slice(&src[anchor..ip]);

            out.extend_from_slice(&(offset as u16).to_le_bytes());

            if match_len - 4 >= 15 {
                let mut rem = (match_len - 4) - 15;
                while rem >= 255 {
                    out.push(255);
                    rem -= 255;
                }
                out.push(rem as u8);
            }

            ip += match_len;
            anchor = ip;
            if ip < limit {
                dict[lz4_hash4(src, ip - 2)] = (ip - 2) as u32;
            }
        } else {
            ip += 1;
        }
    }

    let tail_lit = src.len() - anchor;
    let lit_token = tail_lit.min(15) as u8;
    out.push(lit_token << 4);
    if tail_lit >= 15 {
        let mut rem = tail_lit - 15;
        while rem >= 255 {
            out.push(255);
            rem -= 255;
        }
        out.push(rem as u8);
    }
    out.extend_from_slice(&src[anchor..]);

    if out.len() < uncompressed_frame.len() {
        out
    } else {
        uncompressed_frame.to_vec()
    }
}

/// Decompresses an `OSRP` frame if `RPC_FLAG_COMPRESSED` is set on the version byte.
pub fn decompress_rpc_frame(frame: &[u8]) -> Result<Vec<u8>, StoreError> {
    if frame.len() < 9 || &frame[0..4] != RPC_MAGIC {
        return Err(StoreError::SnapshotCorrupted(
            "invalid compressed RPC frame header".into(),
        ));
    }
    if frame[4] != (RPC_VERSION | RPC_FLAG_COMPRESSED) {
        return Err(StoreError::SnapshotCorrupted(format!(
            "unsupported compressed RPC version byte: 0x{:02x}",
            frame[4]
        )));
    }
    let raw_body_len = u32::from_le_bytes(frame[5..9].try_into().unwrap()) as usize;
    if raw_body_len == 0 || raw_body_len > MAX_RPC_UNCOMPRESSED_BYTES {
        return Err(StoreError::SnapshotCorrupted(format!(
            "invalid uncompressed RPC body length: {}",
            raw_body_len
        )));
    }

    let src = &frame[9..];
    let mut out = Vec::with_capacity(5 + raw_body_len);
    out.extend_from_slice(RPC_MAGIC);
    out.push(RPC_VERSION);

    let target_len = 5 + raw_body_len;
    let mut pos = 0usize;

    while pos < src.len() {
        let token = src[pos];
        pos += 1;

        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            loop {
                if pos >= src.len() {
                    return Err(StoreError::SnapshotCorrupted(
                        "EOF reading LZ4 literal length".into(),
                    ));
                }
                let b = src[pos];
                pos += 1;
                lit_len = lit_len.checked_add(b as usize).ok_or_else(|| {
                    StoreError::SnapshotCorrupted("literal length overflow".into())
                })?;
                if b != 255 {
                    break;
                }
            }
        }

        if pos + lit_len > src.len() || out.len() + lit_len > target_len {
            return Err(StoreError::SnapshotCorrupted(
                "LZ4 literal run exceeds frame bounds".into(),
            ));
        }
        out.extend_from_slice(&src[pos..pos + lit_len]);
        pos += lit_len;

        if pos == src.len() {
            break;
        }

        if pos + 2 > src.len() {
            return Err(StoreError::SnapshotCorrupted(
                "EOF reading LZ4 match offset".into(),
            ));
        }
        let offset = u16::from_le_bytes([src[pos], src[pos + 1]]) as usize;
        pos += 2;
        let current_body_len = out.len() - 5;
        if offset == 0 || offset > current_body_len {
            return Err(StoreError::SnapshotCorrupted(
                "invalid LZ4 match offset".into(),
            ));
        }

        let mut match_len = ((token & 0x0F) as usize) + 4;
        if (token & 0x0F) == 15 {
            loop {
                if pos >= src.len() {
                    return Err(StoreError::SnapshotCorrupted(
                        "EOF reading LZ4 match length".into(),
                    ));
                }
                let b = src[pos];
                pos += 1;
                match_len = match_len
                    .checked_add(b as usize)
                    .ok_or_else(|| StoreError::SnapshotCorrupted("match length overflow".into()))?;
                if b != 255 {
                    break;
                }
            }
        }

        if out.len() + match_len > target_len {
            return Err(StoreError::SnapshotCorrupted(
                "LZ4 match run exceeds uncompressed length".into(),
            ));
        }

        let match_start = out.len() - offset;
        for i in 0..match_len {
            let b = out[match_start + i];
            out.push(b);
        }
    }

    if out.len() != target_len {
        return Err(StoreError::SnapshotCorrupted(
            "decompressed RPC frame length mismatch".into(),
        ));
    }
    Ok(out)
}

fn uncompressed_frame_len(frame: &[u8]) -> u64 {
    if frame.len() >= 9
        && &frame[0..4] == RPC_MAGIC
        && frame[4] == (RPC_VERSION | RPC_FLAG_COMPRESSED)
    {
        let body_len = u32::from_le_bytes(frame[5..9].try_into().unwrap()) as u64;
        5 + body_len
    } else {
        frame.len() as u64
    }
}

impl RpcRequest {
    pub fn encode(&self) -> Vec<u8> {
        compress_rpc_frame(&self.encode_uncompressed())
    }

    pub fn encode_uncompressed(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(RPC_MAGIC);
        buf.push(RPC_VERSION);
        match self {
            RpcRequest::PutObjectsBatch { objects } => {
                buf.push(1);
                write_u32(&mut buf, objects.len() as u32);
                for (domain, hash, bytes) in objects {
                    buf.push(encode_domain(*domain));
                    write_hash(&mut buf, hash);
                    write_bytes(&mut buf, bytes);
                }
            }
            RpcRequest::GetObjectsBatch { keys } => {
                buf.push(2);
                write_u32(&mut buf, keys.len() as u32);
                for (domain, hash) in keys {
                    buf.push(encode_domain(*domain));
                    write_hash(&mut buf, hash);
                }
            }
            RpcRequest::HasObject { domain, hash } => {
                buf.push(3);
                buf.push(encode_domain(*domain));
                write_hash(&mut buf, hash);
            }
            RpcRequest::HasObjectsBatch { keys } => {
                buf.push(22);
                write_u32(&mut buf, keys.len() as u32);
                for (domain, hash) in keys {
                    buf.push(encode_domain(*domain));
                    write_hash(&mut buf, hash);
                }
            }
            RpcRequest::PutChangeset { changeset } => {
                buf.push(4);
                write_bytes(&mut buf, &changeset.to_canonical_bytes());
            }
            RpcRequest::GetChangeset { id } => {
                buf.push(5);
                write_hash(&mut buf, &id.0);
            }
            RpcRequest::GetRef { repo_id, ref_name } => {
                buf.push(6);
                write_str(&mut buf, repo_id);
                write_str(&mut buf, ref_name);
            }
            RpcRequest::ListRefs { repo_id } => {
                buf.push(7);
                write_str(&mut buf, repo_id);
            }
            RpcRequest::CasRef {
                repo_id,
                ref_name,
                expected,
                new_target,
            } => {
                buf.push(8);
                write_str(&mut buf, repo_id);
                write_str(&mut buf, ref_name);
                write_opt_cs_id(&mut buf, expected);
                write_hash(&mut buf, &new_target.0);
            }
            RpcRequest::PutDerivedMapping {
                cs_id,
                kind,
                derived_hash,
            } => {
                buf.push(9);
                write_hash(&mut buf, &cs_id.0);
                buf.push(encode_derived_kind(*kind));
                write_hash(&mut buf, derived_hash);
            }
            RpcRequest::GetDerivedMapping { cs_id, kind } => {
                buf.push(10);
                write_hash(&mut buf, &cs_id.0);
                buf.push(encode_derived_kind(*kind));
            }
            RpcRequest::WhoAmI => {
                buf.push(11);
            }
            RpcRequest::EnrollPrincipal { record } => {
                buf.push(12);
                record.write_into(&mut buf);
            }
            RpcRequest::GetPrincipal { principal_id } => {
                buf.push(13);
                write_str(&mut buf, principal_id);
            }
            RpcRequest::ListPrincipals => {
                buf.push(14);
            }
            RpcRequest::RevokePrincipal {
                principal_id,
                revoked_at_unix,
            } => {
                buf.push(15);
                write_str(&mut buf, principal_id);
                write_i64(&mut buf, *revoked_at_unix);
            }
            RpcRequest::CheckoutLease {
                swarm_id,
                task_id,
                repo_id,
                allowed_ops,
                allowed_read_prefixes,
                allowed_write_prefixes,
                ttl_secs,
                allowed_refs,
            } => {
                buf.push(16);
                write_str(&mut buf, swarm_id);
                write_str(&mut buf, task_id);
                write_str(&mut buf, repo_id);
                write_str_vec(&mut buf, allowed_ops);
                write_str_vec(&mut buf, allowed_read_prefixes);
                write_str_vec(&mut buf, allowed_write_prefixes);
                write_u64(&mut buf, *ttl_secs);
                write_str_vec(&mut buf, allowed_refs);
            }
            RpcRequest::GetLease { lease_id } => {
                buf.push(17);
                write_str(&mut buf, lease_id);
            }
            RpcRequest::RenewLease { lease_id, ttl_secs } => {
                buf.push(18);
                write_str(&mut buf, lease_id);
                write_u64(&mut buf, *ttl_secs);
            }
            RpcRequest::RevokeLease {
                lease_id,
                revoked_at_unix,
            } => {
                buf.push(19);
                write_str(&mut buf, lease_id);
                write_i64(&mut buf, *revoked_at_unix);
            }
            RpcRequest::ListLeases { repo_id } => {
                buf.push(20);
                match repo_id {
                    Some(r) => {
                        buf.push(1);
                        write_str(&mut buf, r);
                    }
                    None => buf.push(0),
                }
            }
            RpcRequest::PutLease { record } => {
                buf.push(21);
                record.write_into(&mut buf);
            }
        }
        buf
    }

    pub fn decode(raw_data: &[u8]) -> Result<Self, StoreError> {
        let decompressed;
        let data: &[u8] = if raw_data.len() >= 5
            && &raw_data[0..4] == RPC_MAGIC
            && (raw_data[4] & RPC_FLAG_COMPRESSED) != 0
        {
            decompressed = decompress_rpc_frame(raw_data)?;
            &decompressed
        } else {
            raw_data
        };

        if data.len() < 6 || &data[0..4] != RPC_MAGIC || data[4] != RPC_VERSION {
            return Err(StoreError::SnapshotCorrupted(
                "invalid RPC request header".into(),
            ));
        }
        let op = data[5];
        let mut pos = 6;
        let req = match op {
            1 => {
                let count = read_u32(data, &mut pos)? as usize;
                let mut objects = Vec::with_capacity(count);
                for _ in 0..count {
                    if pos >= data.len() {
                        return Err(StoreError::SnapshotCorrupted(
                            "EOF in PutObjectsBatch".into(),
                        ));
                    }
                    let domain = decode_domain(data[pos])?;
                    pos += 1;
                    let hash = read_hash(data, &mut pos)?;
                    let bytes = read_bytes(data, &mut pos)?;
                    objects.push((domain, hash, bytes));
                }
                Ok(RpcRequest::PutObjectsBatch { objects })
            }
            2 => {
                let count = read_u32(data, &mut pos)? as usize;
                let mut keys = Vec::with_capacity(count);
                for _ in 0..count {
                    if pos >= data.len() {
                        return Err(StoreError::SnapshotCorrupted(
                            "EOF in GetObjectsBatch".into(),
                        ));
                    }
                    let domain = decode_domain(data[pos])?;
                    pos += 1;
                    let hash = read_hash(data, &mut pos)?;
                    keys.push((domain, hash));
                }
                Ok(RpcRequest::GetObjectsBatch { keys })
            }
            3 => {
                if pos >= data.len() {
                    return Err(StoreError::SnapshotCorrupted("EOF in HasObject".into()));
                }
                let domain = decode_domain(data[pos])?;
                pos += 1;
                let hash = read_hash(data, &mut pos)?;
                Ok(RpcRequest::HasObject { domain, hash })
            }
            22 => {
                let count = read_u32(data, &mut pos)? as usize;
                let mut keys = Vec::with_capacity(count);
                for _ in 0..count {
                    if pos >= data.len() {
                        return Err(StoreError::SnapshotCorrupted(
                            "EOF in HasObjectsBatch".into(),
                        ));
                    }
                    let domain = decode_domain(data[pos])?;
                    pos += 1;
                    let hash = read_hash(data, &mut pos)?;
                    keys.push((domain, hash));
                }
                Ok(RpcRequest::HasObjectsBatch { keys })
            }
            4 => {
                let bytes = read_bytes(data, &mut pos)?;
                let changeset = BonsaiChangeset::from_canonical_bytes(&bytes)
                    .map_err(|e| StoreError::SnapshotCorrupted(e.to_string()))?;
                Ok(RpcRequest::PutChangeset { changeset })
            }
            5 => {
                let id = ChangesetId(read_hash(data, &mut pos)?);
                Ok(RpcRequest::GetChangeset { id })
            }
            6 => {
                let repo_id = read_str(data, &mut pos)?;
                let ref_name = read_str(data, &mut pos)?;
                Ok(RpcRequest::GetRef { repo_id, ref_name })
            }
            7 => {
                let repo_id = read_str(data, &mut pos)?;
                Ok(RpcRequest::ListRefs { repo_id })
            }
            8 => {
                let repo_id = read_str(data, &mut pos)?;
                let ref_name = read_str(data, &mut pos)?;
                let expected = read_opt_cs_id(data, &mut pos)?;
                let new_target = ChangesetId(read_hash(data, &mut pos)?);
                Ok(RpcRequest::CasRef {
                    repo_id,
                    ref_name,
                    expected,
                    new_target,
                })
            }
            9 => {
                let cs_id = ChangesetId(read_hash(data, &mut pos)?);
                if pos >= data.len() {
                    return Err(StoreError::SnapshotCorrupted(
                        "EOF in PutDerivedMapping".into(),
                    ));
                }
                let kind = decode_derived_kind(data[pos])?;
                pos += 1;
                let derived_hash = read_hash(data, &mut pos)?;
                Ok(RpcRequest::PutDerivedMapping {
                    cs_id,
                    kind,
                    derived_hash,
                })
            }
            10 => {
                let cs_id = ChangesetId(read_hash(data, &mut pos)?);
                if pos >= data.len() {
                    return Err(StoreError::SnapshotCorrupted(
                        "EOF in GetDerivedMapping".into(),
                    ));
                }
                let kind = decode_derived_kind(data[pos])?;
                pos += 1;
                Ok(RpcRequest::GetDerivedMapping { cs_id, kind })
            }
            11 => Ok(RpcRequest::WhoAmI),
            12 => Ok(RpcRequest::EnrollPrincipal {
                record: PrincipalRecord::read_from(data, &mut pos)?,
            }),
            13 => Ok(RpcRequest::GetPrincipal {
                principal_id: read_str(data, &mut pos)?,
            }),
            14 => Ok(RpcRequest::ListPrincipals),
            15 => Ok(RpcRequest::RevokePrincipal {
                principal_id: read_str(data, &mut pos)?,
                revoked_at_unix: read_i64(data, &mut pos)?,
            }),
            16 => Ok(RpcRequest::CheckoutLease {
                swarm_id: read_str(data, &mut pos)?,
                task_id: read_str(data, &mut pos)?,
                repo_id: read_str(data, &mut pos)?,
                allowed_ops: read_str_vec(data, &mut pos)?,
                allowed_read_prefixes: read_str_vec(data, &mut pos)?,
                allowed_write_prefixes: read_str_vec(data, &mut pos)?,
                ttl_secs: read_u64(data, &mut pos)?,
                allowed_refs: if pos < data.len() {
                    read_str_vec(data, &mut pos)?
                } else {
                    Vec::new()
                },
            }),
            17 => Ok(RpcRequest::GetLease {
                lease_id: read_str(data, &mut pos)?,
            }),
            18 => Ok(RpcRequest::RenewLease {
                lease_id: read_str(data, &mut pos)?,
                ttl_secs: read_u64(data, &mut pos)?,
            }),
            19 => Ok(RpcRequest::RevokeLease {
                lease_id: read_str(data, &mut pos)?,
                revoked_at_unix: read_i64(data, &mut pos)?,
            }),
            20 => {
                if pos >= data.len() {
                    return Err(StoreError::SnapshotCorrupted("EOF in ListLeases".into()));
                }
                let has_repo = data[pos] != 0;
                pos += 1;
                let repo_id = if has_repo {
                    Some(read_str(data, &mut pos)?)
                } else {
                    None
                };
                Ok(RpcRequest::ListLeases { repo_id })
            }
            21 => Ok(RpcRequest::PutLease {
                record: JitLeaseRecord::read_from(data, &mut pos)?,
            }),
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unknown RpcRequest op: {}",
                other
            ))),
        }?;
        if pos != data.len() {
            return Err(StoreError::SnapshotCorrupted(
                "trailing bytes in RPC request".into(),
            ));
        }
        Ok(req)
    }
}

impl RpcResponse {
    pub fn encode(&self) -> Vec<u8> {
        compress_rpc_frame(&self.encode_uncompressed())
    }

    pub fn encode_uncompressed(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(RPC_MAGIC);
        buf.push(RPC_VERSION);
        match self {
            RpcResponse::PutObjectsBatchOk => {
                buf.push(1);
            }
            RpcResponse::GetObjectsBatch { objects } => {
                buf.push(2);
                write_u32(&mut buf, objects.len() as u32);
                for opt in objects {
                    match opt {
                        Some(bytes) => {
                            buf.push(1);
                            write_bytes(&mut buf, bytes);
                        }
                        None => buf.push(0),
                    }
                }
            }
            RpcResponse::HasObject { exists } => {
                buf.push(3);
                buf.push(if *exists { 1 } else { 0 });
            }
            RpcResponse::HasObjectsBatch { present } => {
                buf.push(23);
                write_u32(&mut buf, present.len() as u32);
                for p in present {
                    buf.push(if *p { 1 } else { 0 });
                }
            }
            RpcResponse::PutChangeset { id } => {
                buf.push(4);
                write_hash(&mut buf, &id.0);
            }
            RpcResponse::GetChangeset { changeset } => {
                buf.push(5);
                match changeset {
                    Some(cs) => {
                        buf.push(1);
                        write_bytes(&mut buf, &cs.to_canonical_bytes());
                    }
                    None => buf.push(0),
                }
            }
            RpcResponse::GetRef { target } => {
                buf.push(6);
                write_opt_cs_id(&mut buf, target);
            }
            RpcResponse::ListRefs { refs } => {
                buf.push(7);
                write_u32(&mut buf, refs.len() as u32);
                for (name, id) in refs {
                    write_str(&mut buf, name);
                    write_hash(&mut buf, &id.0);
                }
            }
            RpcResponse::CasRefOk => {
                buf.push(8);
            }
            RpcResponse::CasRefConflict {
                ref_name,
                expected,
                actual,
            } => {
                buf.push(9);
                write_str(&mut buf, ref_name);
                write_opt_cs_id(&mut buf, expected);
                write_opt_cs_id(&mut buf, actual);
            }
            RpcResponse::PutDerivedMappingOk => {
                buf.push(10);
            }
            RpcResponse::GetDerivedMapping { derived_hash } => {
                buf.push(11);
                match derived_hash {
                    Some(h) => {
                        buf.push(1);
                        write_hash(&mut buf, h);
                    }
                    None => buf.push(0),
                }
            }
            RpcResponse::WhoAmI {
                principal_id,
                role,
                auth_method,
                lease,
            } => {
                buf.push(12);
                write_str(&mut buf, principal_id);
                write_str(&mut buf, role);
                write_str(&mut buf, auth_method);
                match lease {
                    Some(l) => {
                        buf.push(1);
                        l.write_into(&mut buf);
                    }
                    None => buf.push(0),
                }
            }
            RpcResponse::EnrollPrincipalOk => {
                buf.push(13);
            }
            RpcResponse::GetPrincipal { record } => {
                buf.push(14);
                match record {
                    Some(r) => {
                        buf.push(1);
                        r.write_into(&mut buf);
                    }
                    None => buf.push(0),
                }
            }
            RpcResponse::ListPrincipals { principals } => {
                buf.push(15);
                write_u32(&mut buf, principals.len() as u32);
                for p in principals {
                    p.write_into(&mut buf);
                }
            }
            RpcResponse::RevokePrincipalOk => {
                buf.push(16);
            }
            RpcResponse::CheckoutLease { lease, token } => {
                buf.push(17);
                lease.write_into(&mut buf);
                write_str(&mut buf, token);
            }
            RpcResponse::GetLease { lease } => {
                buf.push(18);
                match lease {
                    Some(l) => {
                        buf.push(1);
                        l.write_into(&mut buf);
                    }
                    None => buf.push(0),
                }
            }
            RpcResponse::RenewLease { lease, token } => {
                buf.push(19);
                lease.write_into(&mut buf);
                write_str(&mut buf, token);
            }
            RpcResponse::RevokeLeaseOk => {
                buf.push(20);
            }
            RpcResponse::ListLeases { leases } => {
                buf.push(21);
                write_u32(&mut buf, leases.len() as u32);
                for l in leases {
                    l.write_into(&mut buf);
                }
            }
            RpcResponse::PutLeaseOk => {
                buf.push(22);
            }
            RpcResponse::Error { message } => {
                buf.push(255);
                write_str(&mut buf, message);
            }
        }
        buf
    }

    pub fn decode(raw_data: &[u8]) -> Result<Self, StoreError> {
        let decompressed;
        let data: &[u8] = if raw_data.len() >= 5
            && &raw_data[0..4] == RPC_MAGIC
            && (raw_data[4] & RPC_FLAG_COMPRESSED) != 0
        {
            decompressed = decompress_rpc_frame(raw_data)?;
            &decompressed
        } else {
            raw_data
        };

        if data.len() < 6 || &data[0..4] != RPC_MAGIC || data[4] != RPC_VERSION {
            return Err(StoreError::SnapshotCorrupted(
                "invalid RPC response header".into(),
            ));
        }
        let op = data[5];
        let mut pos = 6;
        let resp = match op {
            1 => Ok(RpcResponse::PutObjectsBatchOk),
            2 => {
                let count = read_u32(data, &mut pos)? as usize;
                let mut objects = Vec::with_capacity(count);
                for _ in 0..count {
                    if pos >= data.len() {
                        return Err(StoreError::SnapshotCorrupted(
                            "EOF in GetObjectsBatch response".into(),
                        ));
                    }
                    let present = data[pos];
                    pos += 1;
                    if present == 1 {
                        objects.push(Some(read_bytes(data, &mut pos)?));
                    } else {
                        objects.push(None);
                    }
                }
                Ok(RpcResponse::GetObjectsBatch { objects })
            }
            3 => {
                if pos >= data.len() {
                    return Err(StoreError::SnapshotCorrupted(
                        "EOF in HasObject response".into(),
                    ));
                }
                let exists = data[pos] != 0;
                pos += 1;
                Ok(RpcResponse::HasObject { exists })
            }
            23 => {
                let count = read_u32(data, &mut pos)? as usize;
                if pos + count > data.len() {
                    return Err(StoreError::SnapshotCorrupted(
                        "EOF in HasObjectsBatch response".into(),
                    ));
                }
                let mut present = Vec::with_capacity(count);
                for i in 0..count {
                    present.push(data[pos + i] != 0);
                }
                pos += count;
                Ok(RpcResponse::HasObjectsBatch { present })
            }
            4 => Ok(RpcResponse::PutChangeset {
                id: ChangesetId(read_hash(data, &mut pos)?),
            }),
            5 => {
                if pos >= data.len() {
                    return Err(StoreError::SnapshotCorrupted(
                        "EOF in GetChangeset response".into(),
                    ));
                }
                let present = data[pos];
                pos += 1;
                if present == 1 {
                    let bytes = read_bytes(data, &mut pos)?;
                    let cs = BonsaiChangeset::from_canonical_bytes(&bytes)
                        .map_err(|e| StoreError::SnapshotCorrupted(e.to_string()))?;
                    Ok(RpcResponse::GetChangeset {
                        changeset: Some(cs),
                    })
                } else {
                    Ok(RpcResponse::GetChangeset { changeset: None })
                }
            }
            6 => Ok(RpcResponse::GetRef {
                target: read_opt_cs_id(data, &mut pos)?,
            }),
            7 => {
                let count = read_u32(data, &mut pos)? as usize;
                let mut refs = BTreeMap::new();
                for _ in 0..count {
                    let name = read_str(data, &mut pos)?;
                    let id = ChangesetId(read_hash(data, &mut pos)?);
                    refs.insert(name, id);
                }
                Ok(RpcResponse::ListRefs { refs })
            }
            8 => Ok(RpcResponse::CasRefOk),
            9 => {
                let ref_name = read_str(data, &mut pos)?;
                let expected = read_opt_cs_id(data, &mut pos)?;
                let actual = read_opt_cs_id(data, &mut pos)?;
                Ok(RpcResponse::CasRefConflict {
                    ref_name,
                    expected,
                    actual,
                })
            }
            10 => Ok(RpcResponse::PutDerivedMappingOk),
            11 => {
                if pos >= data.len() {
                    return Err(StoreError::SnapshotCorrupted(
                        "EOF in GetDerivedMapping response".into(),
                    ));
                }
                let present = data[pos];
                pos += 1;
                if present == 1 {
                    Ok(RpcResponse::GetDerivedMapping {
                        derived_hash: Some(read_hash(data, &mut pos)?),
                    })
                } else {
                    Ok(RpcResponse::GetDerivedMapping { derived_hash: None })
                }
            }
            12 => {
                let principal_id = read_str(data, &mut pos)?;
                let role = read_str(data, &mut pos)?;
                let auth_method = read_str(data, &mut pos)?;
                if pos >= data.len() {
                    return Err(StoreError::SnapshotCorrupted(
                        "EOF in WhoAmI response".into(),
                    ));
                }
                let present = data[pos];
                pos += 1;
                let lease = if present == 1 {
                    Some(JitLeaseRecord::read_from(data, &mut pos)?)
                } else {
                    None
                };
                Ok(RpcResponse::WhoAmI {
                    principal_id,
                    role,
                    auth_method,
                    lease,
                })
            }
            13 => Ok(RpcResponse::EnrollPrincipalOk),
            14 => {
                if pos >= data.len() {
                    return Err(StoreError::SnapshotCorrupted(
                        "EOF in GetPrincipal response".into(),
                    ));
                }
                let present = data[pos];
                pos += 1;
                let record = if present == 1 {
                    Some(PrincipalRecord::read_from(data, &mut pos)?)
                } else {
                    None
                };
                Ok(RpcResponse::GetPrincipal { record })
            }
            15 => {
                let count = read_u32(data, &mut pos)? as usize;
                let mut principals = Vec::with_capacity(count);
                for _ in 0..count {
                    principals.push(PrincipalRecord::read_from(data, &mut pos)?);
                }
                Ok(RpcResponse::ListPrincipals { principals })
            }
            16 => Ok(RpcResponse::RevokePrincipalOk),
            17 => {
                let lease = JitLeaseRecord::read_from(data, &mut pos)?;
                let token = read_str(data, &mut pos)?;
                Ok(RpcResponse::CheckoutLease { lease, token })
            }
            18 => {
                if pos >= data.len() {
                    return Err(StoreError::SnapshotCorrupted(
                        "EOF in GetLease response".into(),
                    ));
                }
                let present = data[pos];
                pos += 1;
                let lease = if present == 1 {
                    Some(JitLeaseRecord::read_from(data, &mut pos)?)
                } else {
                    None
                };
                Ok(RpcResponse::GetLease { lease })
            }
            19 => {
                let lease = JitLeaseRecord::read_from(data, &mut pos)?;
                let token = read_str(data, &mut pos)?;
                Ok(RpcResponse::RenewLease { lease, token })
            }
            20 => Ok(RpcResponse::RevokeLeaseOk),
            21 => {
                let count = read_u32(data, &mut pos)? as usize;
                let mut leases = Vec::with_capacity(count);
                for _ in 0..count {
                    leases.push(JitLeaseRecord::read_from(data, &mut pos)?);
                }
                Ok(RpcResponse::ListLeases { leases })
            }
            22 => Ok(RpcResponse::PutLeaseOk),
            255 => {
                let message = read_str(data, &mut pos)?;
                Ok(RpcResponse::Error { message })
            }
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unknown RpcResponse op: {}",
                other
            ))),
        }?;
        if pos != data.len() {
            return Err(StoreError::SnapshotCorrupted(
                "trailing bytes in RPC response".into(),
            ));
        }
        Ok(resp)
    }
}

/// Namespace helper that scopes a branch ref name to a `repo_id`.
/// For the `"default"` repo, preserves unscoped compatibility while
/// isolating all named repositories (`"frontend"`, `"velenza-inarch"`, etc.).
pub fn scope_ref_key(repo_id: &str, ref_name: &str) -> String {
    let repo = if repo_id.trim().is_empty() {
        "default"
    } else {
        repo_id.trim()
    };
    if repo == "default" {
        ref_name.to_string()
    } else {
        format!("{}::{}", repo, ref_name)
    }
}

/// Unscopes a map of `(scoped_ref_name, ChangesetId)` rows for the requested `repo_id`.
pub fn filter_scoped_refs(
    repo_id: &str,
    all_refs: BTreeMap<String, ChangesetId>,
) -> BTreeMap<String, ChangesetId> {
    let repo = if repo_id.trim().is_empty() {
        "default"
    } else {
        repo_id.trim()
    };
    if repo == "default" {
        all_refs
            .into_iter()
            .filter(|(k, _)| !k.contains("::"))
            .collect()
    } else {
        let prefix = format!("{}::", repo);
        all_refs
            .into_iter()
            .filter_map(|(k, v)| {
                k.strip_prefix(&prefix)
                    .map(|unscoped| (unscoped.to_string(), v))
            })
            .collect()
    }
}

/// Wraps any `MetadataStore` to namespace branch references under `<repo_id>::<ref_name>`.
pub struct ScopedMetadataStore {
    inner: std::sync::Arc<dyn MetadataStore>,
    repo_id: String,
}

impl ScopedMetadataStore {
    pub fn new(inner: std::sync::Arc<dyn MetadataStore>, repo_id: impl Into<String>) -> Self {
        let raw = repo_id.into();
        let trimmed = raw.trim();
        Self {
            inner,
            repo_id: if trimmed.is_empty() {
                "default".to_string()
            } else {
                trimmed.to_string()
            },
        }
    }
}

impl MetadataStore for ScopedMetadataStore {
    fn put_changeset(&self, cs: &BonsaiChangeset) -> Result<ChangesetId, StoreError> {
        self.inner.put_changeset(cs)
    }

    fn get_changeset(&self, id: &ChangesetId) -> Result<Option<BonsaiChangeset>, StoreError> {
        self.inner.get_changeset(id)
    }

    fn get_changeset_parents(
        &self,
        id: &ChangesetId,
    ) -> Result<Option<Vec<ChangesetId>>, StoreError> {
        self.inner.get_changeset_parents(id)
    }

    fn get_ref(&self, ref_name: &str) -> Result<Option<ChangesetId>, StoreError> {
        let scoped = scope_ref_key(&self.repo_id, ref_name);
        self.inner.get_ref(&scoped)
    }

    fn list_refs(&self) -> Result<BTreeMap<String, ChangesetId>, StoreError> {
        let all = self.inner.list_refs()?;
        Ok(filter_scoped_refs(&self.repo_id, all))
    }

    fn cas_ref(
        &self,
        ref_name: &str,
        expected: Option<ChangesetId>,
        new_target: ChangesetId,
    ) -> Result<(), StoreError> {
        let scoped = scope_ref_key(&self.repo_id, ref_name);
        match self.inner.cas_ref(&scoped, expected, new_target) {
            Ok(()) => Ok(()),
            Err(StoreError::CasMismatch {
                expected, actual, ..
            }) => Err(StoreError::CasMismatch {
                ref_name: ref_name.to_string(),
                expected,
                actual,
            }),
            Err(e) => Err(e),
        }
    }

    fn put_derived_mapping(
        &self,
        cs_id: ChangesetId,
        kind: DerivedDataKind,
        derived_hash: ObjectHash,
    ) -> Result<(), StoreError> {
        self.inner.put_derived_mapping(cs_id, kind, derived_hash)
    }

    fn get_derived_mapping(
        &self,
        cs_id: ChangesetId,
        kind: DerivedDataKind,
    ) -> Result<Option<ObjectHash>, StoreError> {
        self.inner.get_derived_mapping(cs_id, kind)
    }

    fn put_principal(&self, record: &PrincipalRecord) -> Result<(), StoreError> {
        self.inner.put_principal(record)
    }

    fn get_principal(&self, principal_id: &str) -> Result<Option<PrincipalRecord>, StoreError> {
        self.inner.get_principal(principal_id)
    }

    fn list_principals(&self) -> Result<Vec<PrincipalRecord>, StoreError> {
        self.inner.list_principals()
    }

    fn put_lease(&self, record: &JitLeaseRecord) -> Result<(), StoreError> {
        self.inner.put_lease(record)
    }

    fn get_lease(&self, lease_id: &str) -> Result<Option<JitLeaseRecord>, StoreError> {
        self.inner.get_lease(lease_id)
    }

    fn list_leases(&self, repo_id: Option<&str>) -> Result<Vec<JitLeaseRecord>, StoreError> {
        self.inner.list_leases(repo_id)
    }
}

/// Executes an `RpcRequest` against any `BlobStore` and `MetadataStore` with default anonymous context.
pub fn handle_rpc_request(
    blobs: &dyn BlobStore,
    meta: &dyn MetadataStore,
    req: RpcRequest,
) -> RpcResponse {
    handle_rpc_request_with_context(blobs, meta, req, "anonymous", "admin", "none", None, None)
}

/// Executes an `RpcRequest` with caller identity and optional JIT lease signing key.
#[allow(clippy::too_many_arguments)]
pub fn handle_rpc_request_with_context(
    blobs: &dyn BlobStore,
    meta: &dyn MetadataStore,
    req: RpcRequest,
    caller_principal_id: &str,
    caller_role: &str,
    auth_method: &str,
    active_lease: Option<&JitLeaseRecord>,
    jit_signing_key: Option<&[u8; 32]>,
) -> RpcResponse {
    match req {
        RpcRequest::PutObjectsBatch { objects } => match blobs.put_objects_batch(&objects) {
            Ok(()) => RpcResponse::PutObjectsBatchOk,
            Err(e) => RpcResponse::Error {
                message: e.to_string(),
            },
        },
        RpcRequest::GetObjectsBatch { keys } => match blobs.get_objects_batch(&keys) {
            Ok(objects) => RpcResponse::GetObjectsBatch { objects },
            Err(e) => RpcResponse::Error {
                message: e.to_string(),
            },
        },
        RpcRequest::HasObject { domain, hash } => match blobs.has_object(domain, &hash) {
            Ok(exists) => RpcResponse::HasObject { exists },
            Err(e) => RpcResponse::Error {
                message: e.to_string(),
            },
        },
        RpcRequest::HasObjectsBatch { keys } => match blobs.has_objects_batch(&keys) {
            Ok(present) => RpcResponse::HasObjectsBatch { present },
            Err(e) => RpcResponse::Error {
                message: e.to_string(),
            },
        },
        RpcRequest::PutChangeset { changeset } => match meta.put_changeset(&changeset) {
            Ok(id) => RpcResponse::PutChangeset { id },
            Err(e) => RpcResponse::Error {
                message: e.to_string(),
            },
        },
        RpcRequest::GetChangeset { id } => match meta.get_changeset(&id) {
            Ok(changeset) => RpcResponse::GetChangeset { changeset },
            Err(e) => RpcResponse::Error {
                message: e.to_string(),
            },
        },
        RpcRequest::GetRef { repo_id, ref_name } => {
            let scoped = scope_ref_key(&repo_id, &ref_name);
            match meta.get_ref(&scoped) {
                Ok(target) => RpcResponse::GetRef { target },
                Err(e) => RpcResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        RpcRequest::ListRefs { repo_id } => match meta.list_refs() {
            Ok(all) => RpcResponse::ListRefs {
                refs: filter_scoped_refs(&repo_id, all),
            },
            Err(e) => RpcResponse::Error {
                message: e.to_string(),
            },
        },
        RpcRequest::CasRef {
            repo_id,
            ref_name,
            expected,
            new_target,
        } => {
            let scoped = scope_ref_key(&repo_id, &ref_name);
            match meta.cas_ref(&scoped, expected, new_target) {
                Ok(()) => RpcResponse::CasRefOk,
                Err(StoreError::CasMismatch {
                    expected, actual, ..
                }) => RpcResponse::CasRefConflict {
                    ref_name,
                    expected,
                    actual,
                },
                Err(e) => RpcResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        RpcRequest::PutDerivedMapping {
            cs_id,
            kind,
            derived_hash,
        } => match meta.put_derived_mapping(cs_id, kind, derived_hash) {
            Ok(()) => RpcResponse::PutDerivedMappingOk,
            Err(e) => RpcResponse::Error {
                message: e.to_string(),
            },
        },
        RpcRequest::GetDerivedMapping { cs_id, kind } => {
            match meta.get_derived_mapping(cs_id, kind) {
                Ok(derived_hash) => RpcResponse::GetDerivedMapping { derived_hash },
                Err(e) => RpcResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        RpcRequest::WhoAmI => RpcResponse::WhoAmI {
            principal_id: caller_principal_id.to_string(),
            role: caller_role.to_string(),
            auth_method: auth_method.to_string(),
            lease: active_lease.cloned(),
        },
        RpcRequest::EnrollPrincipal { record } => match meta.put_principal(&record) {
            Ok(()) => RpcResponse::EnrollPrincipalOk,
            Err(e) => RpcResponse::Error {
                message: e.to_string(),
            },
        },
        RpcRequest::GetPrincipal { principal_id } => match meta.get_principal(&principal_id) {
            Ok(record) => RpcResponse::GetPrincipal { record },
            Err(e) => RpcResponse::Error {
                message: e.to_string(),
            },
        },
        RpcRequest::ListPrincipals => match meta.list_principals() {
            Ok(principals) => RpcResponse::ListPrincipals { principals },
            Err(e) => RpcResponse::Error {
                message: e.to_string(),
            },
        },
        RpcRequest::RevokePrincipal {
            principal_id,
            revoked_at_unix,
        } => match meta.get_principal(&principal_id) {
            Ok(Some(mut record)) => {
                record.status = "revoked".to_string();
                record.revoked_at_unix = Some(revoked_at_unix);
                match meta.put_principal(&record) {
                    Ok(()) => RpcResponse::RevokePrincipalOk,
                    Err(e) => RpcResponse::Error {
                        message: e.to_string(),
                    },
                }
            }
            Ok(None) => RpcResponse::Error {
                message: format!("principal not found: {}", principal_id),
            },
            Err(e) => RpcResponse::Error {
                message: e.to_string(),
            },
        },
        RpcRequest::CheckoutLease {
            repo_id,
            swarm_id,
            task_id,
            allowed_ops,
            allowed_read_prefixes,
            allowed_write_prefixes,
            allowed_refs,
            ttl_secs,
        } => {
            if !allowed_read_prefixes.is_empty() {
                return RpcResponse::Error {
                    message: "read prefixes are not enforced".to_string(),
                };
            }
            let Some(signing_key) = jit_signing_key else {
                return RpcResponse::Error {
                    message: "JIT leases disabled: no jit_signing_key configured".to_string(),
                };
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos();
            let capped_ttl = ttl_secs.clamp(1, 86_400) as i64;
            let expires_at_unix = now + capped_ttl;
            let seed = format!(
                "{}|{}|{}|{}|{}|{}",
                caller_principal_id, repo_id, swarm_id, task_id, now, nanos
            );
            let seed_hash =
                ObjectHash::from_domain(ObjectDomain::Changeset, seed.as_bytes()).to_hex();
            let lease_id = format!("lease_{}", &seed_hash[..24]);
            let lease = JitLeaseRecord {
                lease_id,
                principal_email: caller_principal_id.to_string(),
                swarm_id,
                task_id,
                repo_id,
                allowed_ops,
                allowed_read_prefixes,
                allowed_write_prefixes,
                allowed_refs,
                issued_at_unix: now,
                expires_at_unix,
                revoked: false,
            };
            let token = mint_jit_lease_token(&lease, signing_key);
            match meta.put_lease(&lease) {
                Ok(()) => RpcResponse::CheckoutLease { lease, token },
                Err(e) => RpcResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        RpcRequest::GetLease { lease_id } => match meta.get_lease(&lease_id) {
            Ok(Some(lease)) => {
                let authorized = caller_role == "admin"
                    || active_lease.is_some_and(|l| l.lease_id == lease_id)
                    || (!caller_principal_id.is_empty()
                        && lease.principal_email == caller_principal_id);
                if !authorized {
                    return RpcResponse::Error {
                        message: "permission denied: principal may only inspect its own leases"
                            .to_string(),
                    };
                }
                RpcResponse::GetLease { lease: Some(lease) }
            }
            Ok(None) => RpcResponse::GetLease { lease: None },
            Err(e) => RpcResponse::Error {
                message: e.to_string(),
            },
        },
        RpcRequest::RenewLease { lease_id, ttl_secs } => {
            let Some(signing_key) = jit_signing_key else {
                return RpcResponse::Error {
                    message: "JIT leases disabled: no jit_signing_key configured".to_string(),
                };
            };
            match meta.get_lease(&lease_id) {
                Ok(Some(mut lease)) => {
                    let authorized = caller_role == "admin"
                        || active_lease.is_some_and(|l| l.lease_id == lease_id)
                        || (!caller_principal_id.is_empty()
                            && lease.principal_email == caller_principal_id);
                    if !authorized {
                        return RpcResponse::Error {
                            message:
                                "only the issuing principal or an admin may renew or revoke this lease"
                                    .to_string(),
                        };
                    }
                    if lease.revoked {
                        return RpcResponse::Error {
                            message: format!("cannot renew revoked lease: {}", lease_id),
                        };
                    }
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    if now > lease.expires_at_unix {
                        return RpcResponse::Error {
                            message: format!("cannot renew expired lease: {}", lease_id),
                        };
                    }
                    let max_exp = lease
                        .issued_at_unix
                        .saturating_add(MAX_JIT_LEASE_LIFETIME_SECS);
                    if now >= max_exp {
                        return RpcResponse::Error {
                            message: "lease lifetime cap reached".to_string(),
                        };
                    }
                    let capped_ttl = ttl_secs.clamp(1, 86_400) as i64;
                    lease.expires_at_unix = now.saturating_add(capped_ttl).min(max_exp);
                    let token = mint_jit_lease_token(&lease, signing_key);
                    match meta.put_lease(&lease) {
                        Ok(()) => RpcResponse::RenewLease { lease, token },
                        Err(e) => RpcResponse::Error {
                            message: e.to_string(),
                        },
                    }
                }
                Ok(None) => RpcResponse::Error {
                    message: format!("lease not found: {}", lease_id),
                },
                Err(e) => RpcResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        RpcRequest::RevokeLease {
            lease_id,
            revoked_at_unix: _,
        } => match meta.get_lease(&lease_id) {
            Ok(Some(mut lease)) => {
                let authorized = caller_role == "admin"
                    || active_lease.is_some_and(|l| l.lease_id == lease_id)
                    || (!caller_principal_id.is_empty()
                        && lease.principal_email == caller_principal_id);
                if !authorized {
                    return RpcResponse::Error {
                        message:
                            "only the issuing principal or an admin may renew or revoke this lease"
                                .to_string(),
                    };
                }
                lease.revoked = true;
                match meta.put_lease(&lease) {
                    Ok(()) => RpcResponse::RevokeLeaseOk,
                    Err(e) => RpcResponse::Error {
                        message: e.to_string(),
                    },
                }
            }
            Ok(None) => RpcResponse::Error {
                message: format!("lease not found: {}", lease_id),
            },
            Err(e) => RpcResponse::Error {
                message: e.to_string(),
            },
        },
        RpcRequest::ListLeases { repo_id } => match meta.list_leases(repo_id.as_deref()) {
            Ok(leases) => RpcResponse::ListLeases { leases },
            Err(e) => RpcResponse::Error {
                message: e.to_string(),
            },
        },
        RpcRequest::PutLease { record } => match meta.put_lease(&record) {
            Ok(()) => RpcResponse::PutLeaseOk,
            Err(e) => RpcResponse::Error {
                message: e.to_string(),
            },
        },
    }
}

/// Persistent HTTP/1.1 keep-alive RPC client for `inarch-server`.
#[derive(Clone)]
pub struct RemoteRpcClient {
    host_port: String,
    auth_token: Option<String>,
    repo_id: Option<String>,
    conn: Arc<Mutex<Option<TcpStream>>>,
    stats: Arc<Mutex<RpcWireStats>>,
}

impl RemoteRpcClient {
    /// Validates a remote RPC URL without resolving credentials or opening a connection.
    pub fn validate_remote_url(remote_url: &str) -> Result<(), StoreError> {
        let trimmed = remote_url.trim();
        if trimmed
            .get(..8)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
        {
            return Err(StoreError::Io(
                "HTTPS remote URLs are unsupported because this client has no TLS transport"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn new(remote_url: &str, auth_token: Option<String>) -> Result<Self, StoreError> {
        Self::validate_remote_url(remote_url)?;
        let trimmed = remote_url.trim().trim_end_matches('/');
        let without_scheme = trimmed
            .strip_prefix("http://")
            .unwrap_or(trimmed);
        let host_port = without_scheme
            .split('/')
            .next()
            .unwrap_or(without_scheme)
            .to_string();
        if host_port.is_empty() {
            return Err(StoreError::Io(format!(
                "invalid remote_url: {}",
                remote_url
            )));
        }
        Ok(Self {
            host_port,
            auth_token: auth_token.filter(|t| !t.is_empty()),
            repo_id: None,
            conn: Arc::new(Mutex::new(None)),
            stats: Arc::new(Mutex::new(RpcWireStats::default())),
        })
    }

    pub fn with_repo_id(mut self, repo_id: impl Into<String>) -> Self {
        let r = repo_id.into();
        let trimmed = r.trim();
        if !trimmed.is_empty() {
            self.repo_id = Some(trimmed.to_string());
        }
        self
    }

    pub fn wire_stats(&self) -> RpcWireStats {
        self.stats.lock().map(|g| *g).unwrap_or_default()
    }

    pub fn reset_wire_stats(&self) {
        if let Ok(mut g) = self.stats.lock() {
            *g = RpcWireStats::default();
        }
    }

    pub fn call(&self, req: &RpcRequest) -> Result<RpcResponse, StoreError> {
        let payload = req.encode();
        let mut guard = self
            .conn
            .lock()
            .map_err(|_| StoreError::Io("remote client lock poisoned".into()))?;

        // Try once on existing keep-alive socket; if broken, reconnect once.
        for attempt in 0..2 {
            if guard.is_none() {
                let stream = TcpStream::connect(&self.host_port)
                    .map_err(|e| StoreError::Io(format!("connect {}: {}", self.host_port, e)))?;
                let _ = stream.set_nodelay(true);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));
                *guard = Some(stream);
            }
            let stream = guard.as_mut().unwrap();
            match self.send_and_recv(stream, &payload) {
                Ok(resp_bytes) => {
                    if let Ok(mut st) = self.stats.lock() {
                        st.requests_sent += 1;
                        st.wire_bytes_sent += payload.len() as u64;
                        st.wire_bytes_received += resp_bytes.len() as u64;
                        st.uncompressed_bytes_sent += uncompressed_frame_len(&payload);
                        st.uncompressed_bytes_received += uncompressed_frame_len(&resp_bytes);
                    }
                    return RpcResponse::decode(&resp_bytes);
                }
                Err(e) => {
                    *guard = None;
                    if attempt == 1 {
                        return Err(e);
                    }
                }
            }
        }
        Err(StoreError::Io("remote RPC retry exhausted".into()))
    }

    fn send_and_recv(&self, stream: &mut TcpStream, payload: &[u8]) -> Result<Vec<u8>, StoreError> {
        let auth_header = match &self.auth_token {
            Some(tok) => format!("Authorization: Bearer {}\r\n", tok),
            None => String::new(),
        };
        let repo_header = match &self.repo_id {
            Some(repo) => format!("X-Inarch-Repo: {}\r\n", repo),
            None => String::new(),
        };
        let header = format!(
            "POST /v1/rpc HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-velenza-inarch-rpc\r\nContent-Length: {}\r\nConnection: keep-alive\r\n{}{}\r\n",
            self.host_port,
            payload.len(),
            auth_header,
            repo_header
        );
        stream
            .write_all(header.as_bytes())
            .map_err(|e| StoreError::Io(e.to_string()))?;
        stream
            .write_all(payload)
            .map_err(|e| StoreError::Io(e.to_string()))?;
        stream.flush().map_err(|e| StoreError::Io(e.to_string()))?;

        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        let n = reader
            .read_line(&mut status_line)
            .map_err(|e| StoreError::Io(e.to_string()))?;
        if n == 0 {
            return Err(StoreError::Io("remote closed keep-alive socket".into()));
        }
        let status_code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(500);

        let mut content_length: usize = 0;
        loop {
            let mut line = String::new();
            let read_n = reader
                .read_line(&mut line)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            if read_n == 0 || line == "\r\n" || line == "\n" {
                break;
            }
            if let Some((k, v)) = line.split_once(':')
                && k.trim().eq_ignore_ascii_case("content-length")
            {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }

        let mut body = vec![0u8; content_length];
        reader
            .read_exact(&mut body)
            .map_err(|e| StoreError::Io(e.to_string()))?;

        if status_code == 401 || status_code == 403 {
            let detail = String::from_utf8_lossy(&body);
            let trimmed_detail = detail.trim();
            if trimmed_detail.is_empty() {
                return Err(StoreError::Io(format!(
                    "remote server authentication failed (HTTP {})",
                    status_code
                )));
            } else {
                return Err(StoreError::Io(format!(
                    "remote server authentication failed (HTTP {}): {}",
                    status_code, trimmed_detail
                )));
            }
        }
        if status_code >= 400 && (body.len() < 4 || &body[0..4] != RPC_MAGIC) {
            return Err(StoreError::Io(format!(
                "remote server HTTP {}: {}",
                status_code,
                String::from_utf8_lossy(&body)
            )));
        }
        Ok(body)
    }
}

/// Networked `BlobStore` client speaking batched binary RPC over HTTP/1.1.
#[derive(Clone)]
pub struct RemoteBlobStore {
    client: RemoteRpcClient,
}

impl RemoteBlobStore {
    pub fn new(remote_url: &str, auth_token: Option<String>) -> Result<Self, StoreError> {
        Ok(Self {
            client: RemoteRpcClient::new(remote_url, auth_token)?,
        })
    }

    pub fn with_repo_id(mut self, repo_id: impl Into<String>) -> Self {
        self.client = self.client.with_repo_id(repo_id);
        self
    }

    pub fn client(&self) -> &RemoteRpcClient {
        &self.client
    }

    pub fn wire_stats(&self) -> RpcWireStats {
        self.client.wire_stats()
    }

    pub fn reset_wire_stats(&self) {
        self.client.reset_wire_stats();
    }
}

impl BlobStore for RemoteBlobStore {
    fn put_object(
        &self,
        domain: ObjectDomain,
        hash: ObjectHash,
        data: &[u8],
    ) -> Result<(), StoreError> {
        self.put_objects_batch(&[(domain, hash, data.to_vec())])
    }

    fn get_object(
        &self,
        domain: ObjectDomain,
        hash: &ObjectHash,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let mut objects = self.get_objects_batch(&[(domain, *hash)])?;
        Ok(objects.pop().flatten())
    }

    fn has_object(&self, domain: ObjectDomain, hash: &ObjectHash) -> Result<bool, StoreError> {
        match self.client.call(&RpcRequest::HasObject {
            domain,
            hash: *hash,
        })? {
            RpcResponse::HasObject { exists } => Ok(exists),
            RpcResponse::Error { message } => Err(StoreError::Io(message)),
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unexpected response to HasObject: {:?}",
                other
            ))),
        }
    }

    fn has_objects_batch(
        &self,
        keys: &[(ObjectDomain, ObjectHash)],
    ) -> Result<Vec<bool>, StoreError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let mut results = Vec::with_capacity(keys.len());
        for chunk in keys.chunks(1024) {
            match self.client.call(&RpcRequest::HasObjectsBatch {
                keys: chunk.to_vec(),
            })? {
                RpcResponse::HasObjectsBatch { present } => {
                    if present.len() != chunk.len() {
                        return Err(StoreError::SnapshotCorrupted(
                            "HasObjectsBatch length mismatch".into(),
                        ));
                    }
                    results.extend(present);
                }
                RpcResponse::Error { message } => return Err(StoreError::Io(message)),
                other => {
                    return Err(StoreError::SnapshotCorrupted(format!(
                        "unexpected response to HasObjectsBatch: {:?}",
                        other
                    )));
                }
            }
        }
        Ok(results)
    }

    fn put_objects_batch(
        &self,
        objects: &[(ObjectDomain, ObjectHash, Vec<u8>)],
    ) -> Result<(), StoreError> {
        if objects.is_empty() {
            return Ok(());
        }
        for (domain, hash, bytes) in objects {
            verify_object_integrity(*domain, *hash, bytes)?;
        }

        // Preflight deduplication via HasObjectsBatch (33 bytes per key) so objects already
        // present on the remote store are never re-uploaded over the network.
        let keys: Vec<(ObjectDomain, ObjectHash)> =
            objects.iter().map(|(d, h, _)| (*d, *h)).collect();
        let present = self.has_objects_batch(&keys)?;

        let mut seen = std::collections::HashSet::with_capacity(objects.len());
        let mut batch = Vec::new();
        let mut batch_bytes = 0usize;

        for ((domain, hash, bytes), is_present) in objects.iter().zip(present) {
            if is_present || !seen.insert((*domain, *hash)) {
                continue;
            }
            if !batch.is_empty()
                && (batch.len() >= 256 || batch_bytes + bytes.len() > 8 * 1024 * 1024)
            {
                self.flush_put_batch(std::mem::take(&mut batch))?;
                batch_bytes = 0;
            }
            batch_bytes += bytes.len();
            batch.push((*domain, *hash, bytes.clone()));
        }
        if !batch.is_empty() {
            self.flush_put_batch(batch)?;
        }
        Ok(())
    }

    fn get_objects_batch(
        &self,
        keys: &[(ObjectDomain, ObjectHash)],
    ) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let mut results = Vec::with_capacity(keys.len());
        for chunk in keys.chunks(256) {
            match self.client.call(&RpcRequest::GetObjectsBatch {
                keys: chunk.to_vec(),
            })? {
                RpcResponse::GetObjectsBatch { objects } => {
                    if objects.len() != chunk.len() {
                        return Err(StoreError::SnapshotCorrupted(
                            "GetObjectsBatch length mismatch".into(),
                        ));
                    }
                    // Verify BLAKE3 integrity of every object received over the network.
                    for ((domain, expected_hash), opt_bytes) in chunk.iter().zip(objects) {
                        if let Some(ref bytes) = opt_bytes {
                            verify_object_integrity(*domain, *expected_hash, bytes)?;
                        }
                        results.push(opt_bytes);
                    }
                }
                RpcResponse::Error { message } => return Err(StoreError::Io(message)),
                other => {
                    return Err(StoreError::SnapshotCorrupted(format!(
                        "unexpected response to GetObjectsBatch: {:?}",
                        other
                    )));
                }
            }
        }
        Ok(results)
    }
}

impl RemoteBlobStore {
    fn flush_put_batch(
        &self,
        objects: Vec<(ObjectDomain, ObjectHash, Vec<u8>)>,
    ) -> Result<(), StoreError> {
        match self.client.call(&RpcRequest::PutObjectsBatch { objects })? {
            RpcResponse::PutObjectsBatchOk => Ok(()),
            RpcResponse::Error { message } => Err(StoreError::Io(message)),
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unexpected response to PutObjectsBatch: {:?}",
                other
            ))),
        }
    }
}

/// Networked `MetadataStore` client speaking binary RPC over HTTP/1.1.
#[derive(Clone)]
pub struct RemoteMetadataStore {
    client: RemoteRpcClient,
    repo_id: String,
}

impl RemoteMetadataStore {
    pub fn new(
        remote_url: &str,
        auth_token: Option<String>,
        repo_id: impl Into<String>,
    ) -> Result<Self, StoreError> {
        let r = repo_id.into();
        let normalized_repo = if r.trim().is_empty() {
            "default".to_string()
        } else {
            r.trim().to_string()
        };
        Ok(Self {
            client: RemoteRpcClient::new(remote_url, auth_token)?
                .with_repo_id(normalized_repo.clone()),
            repo_id: normalized_repo,
        })
    }

    pub fn client(&self) -> &RemoteRpcClient {
        &self.client
    }
}

impl MetadataStore for RemoteMetadataStore {
    fn put_changeset(&self, cs: &BonsaiChangeset) -> Result<ChangesetId, StoreError> {
        match self.client.call(&RpcRequest::PutChangeset {
            changeset: cs.clone(),
        })? {
            RpcResponse::PutChangeset { id } => Ok(id),
            RpcResponse::Error { message } => Err(StoreError::Io(message)),
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unexpected response to PutChangeset: {:?}",
                other
            ))),
        }
    }

    fn get_changeset(&self, id: &ChangesetId) -> Result<Option<BonsaiChangeset>, StoreError> {
        match self.client.call(&RpcRequest::GetChangeset { id: *id })? {
            RpcResponse::GetChangeset { changeset } => Ok(changeset),
            RpcResponse::Error { message } => Err(StoreError::Io(message)),
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unexpected response to GetChangeset: {:?}",
                other
            ))),
        }
    }

    fn get_ref(&self, ref_name: &str) -> Result<Option<ChangesetId>, StoreError> {
        match self.client.call(&RpcRequest::GetRef {
            repo_id: self.repo_id.clone(),
            ref_name: ref_name.to_string(),
        })? {
            RpcResponse::GetRef { target } => Ok(target),
            RpcResponse::Error { message } => Err(StoreError::Io(message)),
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unexpected response to GetRef: {:?}",
                other
            ))),
        }
    }

    fn list_refs(&self) -> Result<BTreeMap<String, ChangesetId>, StoreError> {
        match self.client.call(&RpcRequest::ListRefs {
            repo_id: self.repo_id.clone(),
        })? {
            RpcResponse::ListRefs { refs } => Ok(refs),
            RpcResponse::Error { message } => Err(StoreError::Io(message)),
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unexpected response to ListRefs: {:?}",
                other
            ))),
        }
    }

    fn cas_ref(
        &self,
        ref_name: &str,
        expected: Option<ChangesetId>,
        new_target: ChangesetId,
    ) -> Result<(), StoreError> {
        match self.client.call(&RpcRequest::CasRef {
            repo_id: self.repo_id.clone(),
            ref_name: ref_name.to_string(),
            expected,
            new_target,
        })? {
            RpcResponse::CasRefOk => Ok(()),
            RpcResponse::CasRefConflict {
                ref_name,
                expected,
                actual,
            } => Err(StoreError::CasMismatch {
                ref_name,
                expected,
                actual,
            }),
            RpcResponse::Error { message } => Err(StoreError::Io(message)),
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unexpected response to CasRef: {:?}",
                other
            ))),
        }
    }

    fn put_derived_mapping(
        &self,
        cs_id: ChangesetId,
        kind: DerivedDataKind,
        derived_hash: ObjectHash,
    ) -> Result<(), StoreError> {
        match self.client.call(&RpcRequest::PutDerivedMapping {
            cs_id,
            kind,
            derived_hash,
        })? {
            RpcResponse::PutDerivedMappingOk => Ok(()),
            RpcResponse::Error { message } => Err(StoreError::Io(message)),
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unexpected response to PutDerivedMapping: {:?}",
                other
            ))),
        }
    }

    fn get_derived_mapping(
        &self,
        cs_id: ChangesetId,
        kind: DerivedDataKind,
    ) -> Result<Option<ObjectHash>, StoreError> {
        match self
            .client
            .call(&RpcRequest::GetDerivedMapping { cs_id, kind })?
        {
            RpcResponse::GetDerivedMapping { derived_hash } => Ok(derived_hash),
            RpcResponse::Error { message } => Err(StoreError::Io(message)),
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unexpected response to GetDerivedMapping: {:?}",
                other
            ))),
        }
    }

    fn put_principal(&self, record: &PrincipalRecord) -> Result<(), StoreError> {
        match self.client.call(&RpcRequest::EnrollPrincipal {
            record: record.clone(),
        })? {
            RpcResponse::EnrollPrincipalOk => Ok(()),
            RpcResponse::Error { message } => Err(StoreError::Io(message)),
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unexpected response to EnrollPrincipal: {:?}",
                other
            ))),
        }
    }

    fn get_principal(&self, principal_id: &str) -> Result<Option<PrincipalRecord>, StoreError> {
        match self.client.call(&RpcRequest::GetPrincipal {
            principal_id: principal_id.to_string(),
        })? {
            RpcResponse::GetPrincipal { record } => Ok(record),
            RpcResponse::Error { message } => Err(StoreError::Io(message)),
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unexpected response to GetPrincipal: {:?}",
                other
            ))),
        }
    }

    fn list_principals(&self) -> Result<Vec<PrincipalRecord>, StoreError> {
        match self.client.call(&RpcRequest::ListPrincipals)? {
            RpcResponse::ListPrincipals { principals } => Ok(principals),
            RpcResponse::Error { message } => Err(StoreError::Io(message)),
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unexpected response to ListPrincipals: {:?}",
                other
            ))),
        }
    }

    fn put_lease(&self, record: &JitLeaseRecord) -> Result<(), StoreError> {
        match self.client.call(&RpcRequest::PutLease {
            record: record.clone(),
        })? {
            RpcResponse::PutLeaseOk => Ok(()),
            RpcResponse::Error { message } => Err(StoreError::Io(message)),
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unexpected response to PutLease: {:?}",
                other
            ))),
        }
    }

    fn get_lease(&self, lease_id: &str) -> Result<Option<JitLeaseRecord>, StoreError> {
        match self.client.call(&RpcRequest::GetLease {
            lease_id: lease_id.to_string(),
        })? {
            RpcResponse::GetLease { lease } => Ok(lease),
            RpcResponse::Error { message } => Err(StoreError::Io(message)),
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unexpected response to GetLease: {:?}",
                other
            ))),
        }
    }

    fn list_leases(&self, repo_id: Option<&str>) -> Result<Vec<JitLeaseRecord>, StoreError> {
        match self.client.call(&RpcRequest::ListLeases {
            repo_id: repo_id.map(|s| s.to_string()),
        })? {
            RpcResponse::ListLeases { leases } => Ok(leases),
            RpcResponse::Error { message } => Err(StoreError::Io(message)),
            other => Err(StoreError::SnapshotCorrupted(format!(
                "unexpected response to ListLeases: {:?}",
                other
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemBlobStore, MemMetadataStore};
    use inarch_types::bonsai::{FileChange, FileType};
    use inarch_types::hash::BlobId;
    use inarch_types::path::MPath;

    #[test]
    fn test_rpc_wire_roundtrip_all_variants() {
        let h1 = ObjectHash::from_domain(ObjectDomain::Chunk, b"chunk-1");
        let h2 = ObjectHash::from_domain(ObjectDomain::Fsnode, b"fsnode-1");
        let mut fc = BTreeMap::new();
        fc.insert(
            MPath::new("src/lib.rs").unwrap(),
            FileChange::Tracked {
                blob_id: BlobId(h1),
                file_type: FileType::Regular,
                size: 7,
            },
        );
        let cs = BonsaiChangeset::new(
            vec![],
            "agent-1".into(),
            1_700_000_000,
            0,
            "test commit".into(),
            BTreeMap::new(),
            fc,
        )
        .unwrap();
        let cs_id = cs.changeset_id();

        let sample_principal = PrincipalRecord {
            principal_email: "device-workstation-01@example.com".into(),
            principal_kind: "workstation".into(),
            host_label: "workstation-01".into(),
            allowed_repos: vec!["*".into()],
            allowed_ops: vec!["read".into(), "land".into()],
            allowed_write_prefixes: vec!["crates/".into()],
            status: "active".into(),
            enrolled_by: "admin".into(),
            created_at_unix: 1_700_000_000,
            revoked_at_unix: None,
        };
        let sample_lease = JitLeaseRecord {
            lease_id: "lease_0123456789abcdef01234567".into(),
            principal_email: "device-workstation-01@example.com".into(),
            swarm_id: "swarm-alpha".into(),
            task_id: "TASK-42".into(),
            repo_id: "repo-alpha".into(),
            allowed_ops: vec!["read".into(), "land".into()],
            allowed_read_prefixes: vec![],
            allowed_write_prefixes: vec!["crates/".into()],
            allowed_refs: vec!["main".into()],
            issued_at_unix: 1_700_000_000,
            expires_at_unix: 1_700_003_600,
            revoked: false,
        };

        let requests = vec![
            RpcRequest::PutObjectsBatch {
                objects: vec![
                    (ObjectDomain::Chunk, h1, b"chunk-1".to_vec()),
                    (ObjectDomain::Fsnode, h2, b"fsnode-1".to_vec()),
                ],
            },
            RpcRequest::GetObjectsBatch {
                keys: vec![(ObjectDomain::Chunk, h1), (ObjectDomain::Fsnode, h2)],
            },
            RpcRequest::HasObject {
                domain: ObjectDomain::Chunk,
                hash: h1,
            },
            RpcRequest::PutChangeset {
                changeset: cs.clone(),
            },
            RpcRequest::GetChangeset { id: cs_id },
            RpcRequest::GetRef {
                repo_id: "repo-alpha".into(),
                ref_name: "main".into(),
            },
            RpcRequest::ListRefs {
                repo_id: "repo-alpha".into(),
            },
            RpcRequest::CasRef {
                repo_id: "repo-alpha".into(),
                ref_name: "main".into(),
                expected: None,
                new_target: cs_id,
            },
            RpcRequest::PutDerivedMapping {
                cs_id,
                kind: DerivedDataKind::Fsnode,
                derived_hash: h2,
            },
            RpcRequest::GetDerivedMapping {
                cs_id,
                kind: DerivedDataKind::Fsnode,
            },
            RpcRequest::WhoAmI,
            RpcRequest::EnrollPrincipal {
                record: sample_principal.clone(),
            },
            RpcRequest::GetPrincipal {
                principal_id: "device-workstation-01@example.com".into(),
            },
            RpcRequest::ListPrincipals,
            RpcRequest::RevokePrincipal {
                principal_id: "device-workstation-01@example.com".into(),
                revoked_at_unix: 1_700_001_000,
            },
            RpcRequest::CheckoutLease {
                repo_id: "repo-alpha".into(),
                swarm_id: "swarm-alpha".into(),
                task_id: "TASK-42".into(),
                allowed_ops: vec!["read".into(), "land".into()],
                allowed_read_prefixes: vec![],
                allowed_write_prefixes: vec!["crates/".into()],
                allowed_refs: vec!["main".into()],
                ttl_secs: 3600,
            },
            RpcRequest::GetLease {
                lease_id: "lease_0123456789abcdef01234567".into(),
            },
            RpcRequest::RenewLease {
                lease_id: "lease_0123456789abcdef01234567".into(),
                ttl_secs: 1800,
            },
            RpcRequest::RevokeLease {
                lease_id: "lease_0123456789abcdef01234567".into(),
                revoked_at_unix: 1_700_002_000,
            },
            RpcRequest::ListLeases {
                repo_id: Some("repo-alpha".into()),
            },
            RpcRequest::ListLeases { repo_id: None },
            RpcRequest::PutLease {
                record: sample_lease.clone(),
            },
        ];

        for req in requests {
            let encoded = req.encode();
            let decoded = RpcRequest::decode(&encoded).unwrap();
            assert_eq!(req, decoded);
        }

        let mut sample_refs = BTreeMap::new();
        sample_refs.insert("main".into(), cs_id);

        let responses = vec![
            RpcResponse::PutObjectsBatchOk,
            RpcResponse::GetObjectsBatch {
                objects: vec![Some(b"hello".to_vec()), None],
            },
            RpcResponse::HasObject { exists: true },
            RpcResponse::PutChangeset { id: cs_id },
            RpcResponse::GetChangeset {
                changeset: Some(cs),
            },
            RpcResponse::GetChangeset { changeset: None },
            RpcResponse::GetRef {
                target: Some(cs_id),
            },
            RpcResponse::ListRefs { refs: sample_refs },
            RpcResponse::CasRefOk,
            RpcResponse::CasRefConflict {
                ref_name: "main".into(),
                expected: None,
                actual: Some(cs_id),
            },
            RpcResponse::PutDerivedMappingOk,
            RpcResponse::GetDerivedMapping {
                derived_hash: Some(h2),
            },
            RpcResponse::WhoAmI {
                principal_id: "device-workstation-01@example.com".into(),
                role: "workstation".into(),
                auth_method: "oidc_principal".into(),
                lease: Some(sample_lease.clone()),
            },
            RpcResponse::WhoAmI {
                principal_id: "device-workstation-01@example.com".into(),
                role: "workstation".into(),
                auth_method: "oidc_principal".into(),
                lease: None,
            },
            RpcResponse::EnrollPrincipalOk,
            RpcResponse::GetPrincipal {
                record: Some(sample_principal.clone()),
            },
            RpcResponse::GetPrincipal { record: None },
            RpcResponse::ListPrincipals {
                principals: vec![sample_principal],
            },
            RpcResponse::RevokePrincipalOk,
            RpcResponse::CheckoutLease {
                lease: sample_lease.clone(),
                token: "inarch_jit_v1_lease_0123456789abcdef01234567_deadbeef".into(),
            },
            RpcResponse::GetLease {
                lease: Some(sample_lease.clone()),
            },
            RpcResponse::GetLease { lease: None },
            RpcResponse::RenewLease {
                lease: sample_lease.clone(),
                token: "inarch_jit_v1_lease_0123456789abcdef01234567_deadbeef".into(),
            },
            RpcResponse::RevokeLeaseOk,
            RpcResponse::ListLeases {
                leases: vec![sample_lease],
            },
            RpcResponse::PutLeaseOk,
            RpcResponse::Error {
                message: "boom".into(),
            },
        ];

        for resp in responses {
            let encoded = resp.encode();
            let decoded = RpcResponse::decode(&encoded).unwrap();
            assert_eq!(resp, decoded);
        }
    }

    #[test]
    fn test_handle_rpc_request_and_repo_id_isolation() {
        let blobs = MemBlobStore::new();
        let meta = MemMetadataStore::new();

        let cs_a = BonsaiChangeset::new(
            vec![],
            "alice".into(),
            100,
            0,
            "repo A init".into(),
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let cs_b = BonsaiChangeset::new(
            vec![],
            "bob".into(),
            200,
            0,
            "repo B init".into(),
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let id_a = cs_a.changeset_id();
        let id_b = cs_b.changeset_id();

        assert_eq!(
            handle_rpc_request(
                &blobs,
                &meta,
                RpcRequest::PutChangeset {
                    changeset: cs_a.clone()
                }
            ),
            RpcResponse::PutChangeset { id: id_a }
        );
        assert_eq!(
            handle_rpc_request(
                &blobs,
                &meta,
                RpcRequest::PutChangeset {
                    changeset: cs_b.clone()
                }
            ),
            RpcResponse::PutChangeset { id: id_b }
        );

        // Both repo-alpha and repo-beta set their own "main" ref without colliding.
        assert_eq!(
            handle_rpc_request(
                &blobs,
                &meta,
                RpcRequest::CasRef {
                    repo_id: "repo-alpha".into(),
                    ref_name: "main".into(),
                    expected: None,
                    new_target: id_a,
                }
            ),
            RpcResponse::CasRefOk
        );
        assert_eq!(
            handle_rpc_request(
                &blobs,
                &meta,
                RpcRequest::CasRef {
                    repo_id: "repo-beta".into(),
                    ref_name: "main".into(),
                    expected: None,
                    new_target: id_b,
                }
            ),
            RpcResponse::CasRefOk
        );

        assert_eq!(
            handle_rpc_request(
                &blobs,
                &meta,
                RpcRequest::GetRef {
                    repo_id: "repo-alpha".into(),
                    ref_name: "main".into(),
                }
            ),
            RpcResponse::GetRef { target: Some(id_a) }
        );
        assert_eq!(
            handle_rpc_request(
                &blobs,
                &meta,
                RpcRequest::GetRef {
                    repo_id: "repo-beta".into(),
                    ref_name: "main".into(),
                }
            ),
            RpcResponse::GetRef { target: Some(id_b) }
        );
        let mut expected_alpha = BTreeMap::new();
        expected_alpha.insert("main".into(), id_a);
        assert_eq!(
            handle_rpc_request(
                &blobs,
                &meta,
                RpcRequest::ListRefs {
                    repo_id: "repo-alpha".into(),
                }
            ),
            RpcResponse::ListRefs {
                refs: expected_alpha
            }
        );
    }

    #[test]
    fn test_rpc_wire_compression_shrinks_compressible_payloads_and_roundtrips() {
        // Construct realistic structured source code / JSON manifest payload (~32 KiB)
        let mut source_code = Vec::with_capacity(32 * 1024);
        for i in 0..400 {
            source_code.extend_from_slice(
                format!(
                    "pub fn compute_merkle_node_{idx:04}(input: &[u8]) -> Result<ObjectHash, StoreError> {{\n    let digest = ObjectHash::from_domain(ObjectDomain::Fsnode, input);\n    Ok(digest)\n}}\n",
                    idx = i % 16
                )
                .as_bytes(),
            );
        }
        assert!(source_code.len() > 30_000);
        let blob_hash = ObjectHash::from_domain(ObjectDomain::Blob, &source_code);

        let put_req = RpcRequest::PutObjectsBatch {
            objects: vec![(ObjectDomain::Blob, blob_hash, source_code.clone())],
        };
        let raw_req = put_req.encode_uncompressed();
        let compressed_req = put_req.encode();

        // Must set RPC_FLAG_COMPRESSED on byte 4 and shrink wire size below 35% of raw size
        assert_ne!(
            compressed_req[4] & RPC_FLAG_COMPRESSED,
            0,
            "compressible PutObjectsBatch frame must have RPC_FLAG_COMPRESSED set"
        );
        assert!(
            compressed_req.len() < raw_req.len() * 35 / 100,
            "expected compressed request ({}) to be < 35% of uncompressed size ({})",
            compressed_req.len(),
            raw_req.len()
        );
        let decoded_req = RpcRequest::decode(&compressed_req).expect("decode compressed request");
        assert_eq!(decoded_req, put_req);

        // Also verify GetObjectsBatch response compression
        let get_resp = RpcResponse::GetObjectsBatch {
            objects: vec![Some(source_code.clone()), None, Some(source_code)],
        };
        let raw_resp = get_resp.encode_uncompressed();
        let compressed_resp = get_resp.encode();
        assert_ne!(
            compressed_resp[4] & RPC_FLAG_COMPRESSED,
            0,
            "compressible GetObjectsBatch response must have RPC_FLAG_COMPRESSED set"
        );
        assert!(
            compressed_resp.len() < raw_resp.len() * 35 / 100,
            "expected compressed response ({}) to be < 35% of uncompressed size ({})",
            compressed_resp.len(),
            raw_resp.len()
        );
        let decoded_resp =
            RpcResponse::decode(&compressed_resp).expect("decode compressed response");
        assert_eq!(decoded_resp, get_resp);
    }

    #[test]
    fn test_rpc_wire_compression_backward_compatibility_and_incompressible_fallback() {
        let h1 = ObjectHash::from_domain(ObjectDomain::Blob, b"hello");

        // 1. Backward compatibility: uncompressed v1 frames (`encode_uncompressed`) must still decode cleanly
        let req = RpcRequest::PutObjectsBatch {
            objects: vec![(ObjectDomain::Blob, h1, vec![b'A'; 4096])],
        };
        let legacy_uncompressed = req.encode_uncompressed();
        assert_eq!(legacy_uncompressed[4], RPC_VERSION);
        assert_eq!(RpcRequest::decode(&legacy_uncompressed).unwrap(), req);

        // 2. High-entropy incompressible payload must not expand beyond raw uncompressed frame
        let mut high_entropy = Vec::with_capacity(4096);
        for i in 0..128u32 {
            let h = ObjectHash::from_domain(ObjectDomain::Chunk, &i.to_le_bytes());
            high_entropy.extend_from_slice(h.as_bytes());
        }
        let h_ent = ObjectHash::from_domain(ObjectDomain::Blob, &high_entropy);
        let ent_req = RpcRequest::PutObjectsBatch {
            objects: vec![(ObjectDomain::Blob, h_ent, high_entropy)],
        };
        let raw_ent = ent_req.encode_uncompressed();
        let enc_ent = ent_req.encode();
        assert!(
            enc_ent.len() <= raw_ent.len(),
            "incompressible frame must fall back to raw encoding without size expansion ({} vs {})",
            enc_ent.len(),
            raw_ent.len()
        );
        assert_eq!(RpcRequest::decode(&enc_ent).unwrap(), ent_req);

        // 3. Corrupted compressed frame must return Err(StoreError::SnapshotCorrupted) without panicking
        let mut corrupted = Vec::new();
        corrupted.extend_from_slice(RPC_MAGIC);
        corrupted.push(RPC_VERSION | RPC_FLAG_COMPRESSED);
        corrupted.extend_from_slice(&1024u32.to_le_bytes()); // claims 1024 uncompressed bytes
        corrupted.extend_from_slice(&[0xFF, 0x10, 0x00]); // invalid back-reference offset 0
        assert!(RpcRequest::decode(&corrupted).is_err());
        assert!(RpcResponse::decode(&corrupted).is_err());
    }

    #[test]
    fn test_has_objects_batch_wire_and_handler() {
        let blobs = MemBlobStore::new();
        let meta = MemMetadataStore::new();

        let b1 = b"existing-object-one";
        let b2 = b"missing-object-two";
        let b3 = b"existing-object-three";
        let h1 = ObjectHash::from_domain(ObjectDomain::Blob, b1);
        let h2 = ObjectHash::from_domain(ObjectDomain::Blob, b2);
        let h3 = ObjectHash::from_domain(ObjectDomain::Chunk, b3);

        blobs.put_object(ObjectDomain::Blob, h1, b1).unwrap();
        blobs.put_object(ObjectDomain::Chunk, h3, b3).unwrap();

        let req = RpcRequest::HasObjectsBatch {
            keys: vec![
                (ObjectDomain::Blob, h1),
                (ObjectDomain::Blob, h2),
                (ObjectDomain::Chunk, h3),
            ],
        };
        let encoded = req.encode();
        let decoded = RpcRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);

        let resp = handle_rpc_request(&blobs, &meta, decoded);
        assert_eq!(
            resp,
            RpcResponse::HasObjectsBatch {
                present: vec![true, false, true],
            }
        );

        let resp_encoded = resp.encode();
        let resp_decoded = RpcResponse::decode(&resp_encoded).unwrap();
        assert_eq!(resp_decoded, resp);
    }

    #[test]
    fn test_get_lease_authorization_blocks_cross_principal_inspection() {
        let blobs = MemBlobStore::new();
        let meta = MemMetadataStore::new();

        let lease_b = JitLeaseRecord {
            lease_id: "lease-principal-b-001".to_string(),
            principal_email: "principal-b@example.com".to_string(),
            swarm_id: "swarm-b".to_string(),
            task_id: "task-b".to_string(),
            repo_id: "repo-1".to_string(),
            allowed_ops: vec!["read".to_string(), "land".to_string()],
            allowed_read_prefixes: vec!["crates/".to_string()],
            allowed_write_prefixes: vec!["crates/inarch-store/".to_string()],
            allowed_refs: vec!["main".to_string()],
            issued_at_unix: 1_750_000_000,
            expires_at_unix: 1_750_003_600,
            revoked: false,
        };
        meta.put_lease(&lease_b).unwrap();

        // 1. Principal A attempting to inspect Principal B's lease is rejected.
        let denied = handle_rpc_request_with_context(
            &blobs,
            &meta,
            RpcRequest::GetLease {
                lease_id: "lease-principal-b-001".to_string(),
            },
            "principal-a@example.com",
            "workstation",
            "bearer",
            None,
            None,
        );
        match denied {
            RpcResponse::Error { message } => {
                assert!(
                    message
                        .contains("permission denied: principal may only inspect its own leases"),
                    "unexpected error message: {message}"
                );
            }
            other => panic!("expected Error for cross-principal GetLease, got: {other:?}"),
        }

        // 2. Principal B inspecting its own lease succeeds.
        let allowed_owner = handle_rpc_request_with_context(
            &blobs,
            &meta,
            RpcRequest::GetLease {
                lease_id: "lease-principal-b-001".to_string(),
            },
            "principal-b@example.com",
            "workstation",
            "bearer",
            None,
            None,
        );
        assert_eq!(
            allowed_owner,
            RpcResponse::GetLease {
                lease: Some(lease_b.clone()),
            }
        );

        // 3. Caller presenting the matching active lease token succeeds.
        let allowed_active_lease = handle_rpc_request_with_context(
            &blobs,
            &meta,
            RpcRequest::GetLease {
                lease_id: "lease-principal-b-001".to_string(),
            },
            "",
            "agent",
            "jit_lease",
            Some(&lease_b),
            None,
        );
        assert_eq!(
            allowed_active_lease,
            RpcResponse::GetLease {
                lease: Some(lease_b.clone()),
            }
        );

        // 4. Admin inspecting Principal B's lease succeeds.
        let allowed_admin = handle_rpc_request_with_context(
            &blobs,
            &meta,
            RpcRequest::GetLease {
                lease_id: "lease-principal-b-001".to_string(),
            },
            "admin@example.com",
            "admin",
            "bearer",
            None,
            None,
        );
        assert_eq!(
            allowed_admin,
            RpcResponse::GetLease {
                lease: Some(lease_b),
            }
        );
    }
}
