//! Content-Addressed Storage (`BlobStore`), Three-Tier Caching (`TieredBlobStore`),
//! and Lock-Free Atomic CAS Metadata Store (`MetadataStore`) for Velenza Inarch.
//!
//! Models Anthropic Scion's 3-tier immutable caching hierarchy:
//! - Tier 1 (`inarch-daemon`): Host-local NVMe/memory cache shared across local sandboxes/containers
//! - Tier 2 (`inarch-cache`): Regional read-through cache with Strict Tiering (anti-stampede)
//! - Tier 3 (`inarch-server` / Object Storage): Authoritative immutable origin store
//!
//! And Scion's lock-free single-row Compare-And-Swap (`cas_ref`) metadata layer.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use inarch_types::bonsai::BonsaiChangeset;
use inarch_types::cdc::{CdcConfig, FastCdcChunker};
use inarch_types::hash::{
    Blake3Hasher, BlobId, ChangesetId, ObjectDomain, ObjectHash, blake3_keyed_hash,
};

pub mod cloud;
pub mod rpc;
pub mod telemetry;

pub use cloud::{
    GcpTokenProvider, GcsBlobStore, MAX_IDLE_SPANNER_SESSIONS, MAX_SPANNER_ABORT_RETRIES,
    SpannerMetadataStore, is_spanner_aborted, mint_service_account_id_token,
};
pub use rpc::{
    RemoteBlobStore, RemoteMetadataStore, RemoteRpcClient, RpcRequest, RpcResponse, RpcWireStats,
    ScopedMetadataStore, filter_scoped_refs, handle_rpc_request, handle_rpc_request_with_context,
    scope_ref_key,
};
pub use telemetry::{
    GcpCloudLoggingSink, JsonlFileTelemetrySink, LogLevel, MAX_BUFFERED_AUDIT_EVENTS,
    MemoryTelemetrySink, MultiTelemetrySink, NoopTelemetrySink, StderrTelemetrySink,
    TelemetryEvent, TelemetrySink,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    IntegrityMismatch {
        domain: ObjectDomain,
        expected: ObjectHash,
        actual: ObjectHash,
    },
    TierUnavailable(String),
    UnknownChangeset(ChangesetId),
    CasMismatch {
        ref_name: String,
        expected: Option<ChangesetId>,
        actual: Option<ChangesetId>,
    },
    ConflictingDerivedMapping {
        changeset_id: ChangesetId,
        kind: DerivedDataKind,
        existing: ObjectHash,
        attempted: ObjectHash,
    },
    SnapshotCorrupted(String),
    Io(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntegrityMismatch {
                domain,
                expected,
                actual,
            } => write!(
                f,
                "integrity mismatch for {:?}: expected {}, actual {}",
                domain, expected, actual
            ),
            Self::TierUnavailable(tier) => write!(f, "cache tier unavailable: {}", tier),
            Self::UnknownChangeset(cs_id) => {
                write!(f, "cannot reference unknown changeset {}", cs_id)
            }
            Self::CasMismatch {
                ref_name,
                expected,
                actual,
            } => write!(
                f,
                "CAS mismatch on ref '{}': expected {:?}, actual {:?}",
                ref_name, expected, actual
            ),
            Self::ConflictingDerivedMapping {
                changeset_id,
                kind,
                existing,
                attempted,
            } => write!(
                f,
                "conflicting derived mapping for ({}, {:?}): existing {}, attempted {}",
                changeset_id, kind, existing, attempted
            ),
            Self::SnapshotCorrupted(msg) => write!(f, "corrupted cache snapshot: {}", msg),
            Self::Io(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

impl std::error::Error for StoreError {}

/// Derived data family kinds tracked per `ChangesetId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DerivedDataKind {
    Fsnode,
    Unode,
    BlameV2,
    CommitGraph,
    PathSearchIndex,
    CopyDetection,
}

impl DerivedDataKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fsnode => "fsnode",
            Self::Unode => "unode",
            Self::BlameV2 => "blame_v2",
            Self::CommitGraph => "commit_graph",
            Self::PathSearchIndex => "path_search",
            Self::CopyDetection => "copy_detection",
        }
    }
}

fn domain_code(domain: ObjectDomain) -> u8 {
    match domain {
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

fn domain_from_code(code: u8) -> Result<ObjectDomain, StoreError> {
    match code {
        1 => Ok(ObjectDomain::Blob),
        2 => Ok(ObjectDomain::Chunk),
        3 => Ok(ObjectDomain::Changeset),
        4 => Ok(ObjectDomain::Fsnode),
        5 => Ok(ObjectDomain::UnodeFile),
        6 => Ok(ObjectDomain::UnodeManifest),
        7 => Ok(ObjectDomain::PathSearchIndex),
        8 => Ok(ObjectDomain::CopyInfo),
        other => Err(StoreError::SnapshotCorrupted(format!(
            "unknown object domain tag {}",
            other
        ))),
    }
}

fn domain_dir_name(domain: ObjectDomain) -> &'static str {
    match domain {
        ObjectDomain::Blob => "blob",
        ObjectDomain::Chunk => "chunk",
        ObjectDomain::Changeset => "changeset",
        ObjectDomain::Fsnode => "fsnode",
        ObjectDomain::UnodeFile => "unode_file",
        ObjectDomain::UnodeManifest => "unode_manifest",
        ObjectDomain::PathSearchIndex => "path_search_index",
        ObjectDomain::CopyInfo => "copy_info",
    }
}

/// Content-addressed immutable object store trait.
pub trait BlobStore: Send + Sync {
    /// Stores `data` under `(domain, hash)` after verifying `ObjectHash::from_domain(domain, data) == hash`.
    fn put_object(
        &self,
        domain: ObjectDomain,
        hash: ObjectHash,
        data: &[u8],
    ) -> Result<(), StoreError>;

    /// Fetches `data` for `(domain, hash)` and verifies its cryptographic digest before returning.
    fn get_object(
        &self,
        domain: ObjectDomain,
        hash: &ObjectHash,
    ) -> Result<Option<Vec<u8>>, StoreError>;

    /// Checks if `(domain, hash)` exists in the store.
    fn has_object(&self, domain: ObjectDomain, hash: &ObjectHash) -> Result<bool, StoreError> {
        Ok(self.get_object(domain, hash)?.is_some())
    }

    /// Checks whether a batch of `(domain, hash)` objects exist in the store.
    /// Remote and cloud backends override this to coalesce preflight existence checks.
    fn has_objects_batch(
        &self,
        keys: &[(ObjectDomain, ObjectHash)],
    ) -> Result<Vec<bool>, StoreError> {
        let mut out = Vec::with_capacity(keys.len());
        for (domain, hash) in keys {
            out.push(self.has_object(*domain, hash)?);
        }
        Ok(out)
    }

    /// Stores a batch of `(domain, hash, data)` objects.
    /// Remote and cloud backends override this to coalesce network round-trips.
    fn put_objects_batch(
        &self,
        objects: &[(ObjectDomain, ObjectHash, Vec<u8>)],
    ) -> Result<(), StoreError> {
        for (domain, hash, data) in objects {
            self.put_object(*domain, *hash, data)?;
        }
        Ok(())
    }

    /// Fetches a batch of `(domain, hash)` objects.
    /// Remote and cloud backends override this to coalesce network round-trips.
    fn get_objects_batch(
        &self,
        keys: &[(ObjectDomain, ObjectHash)],
    ) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        let mut out = Vec::with_capacity(keys.len());
        for (domain, hash) in keys {
            out.push(self.get_object(*domain, hash)?);
        }
        Ok(out)
    }

    /// Chunks `content` with FastCDC, stores deduplicated chunks under `ObjectDomain::Chunk`
    /// plus a compact `INRCBLK1` chunk manifest under `ObjectDomain::Blob` for multi-chunk files
    /// (or stores single-chunk files directly under `ObjectDomain::Blob`), and returns its `BlobId`.
    fn put_blob_content(&self, content: &[u8]) -> Result<BlobId, StoreError> {
        let blob_id = BlobId::from_content(content);
        let chunker = FastCdcChunker::new(CdcConfig::default()).expect("default CdcConfig valid");
        let chunks = chunker.chunk(content);
        if chunks.len() <= 1 && !content.starts_with(CHUNK_MANIFEST_MAGIC) {
            self.put_objects_batch(&[(ObjectDomain::Blob, blob_id.0, content.to_vec())])?;
            return Ok(blob_id);
        }
        let mut chunk_hashes = Vec::with_capacity(chunks.len());
        let mut batch = Vec::with_capacity(chunks.len() + 1);
        for chunk in chunks {
            chunk_hashes.push(chunk.id.0);
            batch.push((ObjectDomain::Chunk, chunk.id.0, chunk.data));
        }
        let manifest = encode_chunk_manifest(blob_id.0, content.len() as u64, &chunk_hashes);
        batch.push((ObjectDomain::Blob, blob_id.0, manifest));
        self.put_objects_batch(&batch)?;
        Ok(blob_id)
    }

    /// Retrieves and verifies a full file blob by its `BlobId`, reassembling FastCDC chunks when needed.
    fn get_blob_content(&self, blob_id: &BlobId) -> Result<Option<Vec<u8>>, StoreError> {
        let mut batch = self.get_blobs_batch(&[*blob_id])?;
        Ok(batch.pop().flatten())
    }

    /// Chunks and stores multiple file blobs in a single deduplicated `put_objects_batch` call.
    fn put_blobs_batch(&self, contents: &[&[u8]]) -> Result<Vec<BlobId>, StoreError> {
        if contents.is_empty() {
            return Ok(Vec::new());
        }
        let chunker = FastCdcChunker::new(CdcConfig::default()).expect("default CdcConfig valid");
        let mut blob_ids = Vec::with_capacity(contents.len());
        let mut dedup: BTreeMap<(u8, ObjectHash), (ObjectDomain, ObjectHash, Vec<u8>)> =
            BTreeMap::new();
        for content in contents {
            let blob_id = BlobId::from_content(content);
            blob_ids.push(blob_id);
            let chunks = chunker.chunk(content);
            if chunks.len() <= 1 && !content.starts_with(CHUNK_MANIFEST_MAGIC) {
                dedup
                    .entry((domain_code(ObjectDomain::Blob), blob_id.0))
                    .or_insert_with(|| (ObjectDomain::Blob, blob_id.0, content.to_vec()));
            } else {
                let mut chunk_hashes = Vec::with_capacity(chunks.len());
                for chunk in chunks {
                    chunk_hashes.push(chunk.id.0);
                    dedup
                        .entry((domain_code(ObjectDomain::Chunk), chunk.id.0))
                        .or_insert((ObjectDomain::Chunk, chunk.id.0, chunk.data));
                }
                dedup
                    .entry((domain_code(ObjectDomain::Blob), blob_id.0))
                    .or_insert_with(|| {
                        let manifest =
                            encode_chunk_manifest(blob_id.0, content.len() as u64, &chunk_hashes);
                        (ObjectDomain::Blob, blob_id.0, manifest)
                    });
            }
        }
        let batch: Vec<(ObjectDomain, ObjectHash, Vec<u8>)> = dedup.into_values().collect();
        self.put_objects_batch(&batch)?;
        Ok(blob_ids)
    }

    /// Retrieves and verifies multiple file blobs in a single `get_objects_batch` call,
    /// coalescing any multi-chunk FastCDC reassembly into one batch chunk fetch.
    fn get_blobs_batch(&self, blob_ids: &[BlobId]) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        if blob_ids.is_empty() {
            return Ok(Vec::new());
        }
        let keys: Vec<(ObjectDomain, ObjectHash)> =
            blob_ids.iter().map(|b| (ObjectDomain::Blob, b.0)).collect();
        let raw_entries = self.get_objects_batch(&keys)?;

        let mut manifests: Vec<Option<(u64, Vec<ObjectHash>)>> =
            Vec::with_capacity(raw_entries.len());
        let mut unique_chunk_hashes: BTreeMap<ObjectHash, usize> = BTreeMap::new();
        let mut chunk_keys: Vec<(ObjectDomain, ObjectHash)> = Vec::new();

        for (blob_id, opt_bytes) in blob_ids.iter().zip(raw_entries.iter()) {
            if let Some(bytes) = opt_bytes
                && let Some((total_size, chunk_hashes)) = decode_chunk_manifest(blob_id.0, bytes)?
            {
                for ch in &chunk_hashes {
                    if !unique_chunk_hashes.contains_key(ch) {
                        let idx = chunk_keys.len();
                        unique_chunk_hashes.insert(*ch, idx);
                        chunk_keys.push((ObjectDomain::Chunk, *ch));
                    }
                }
                manifests.push(Some((total_size, chunk_hashes)));
                continue;
            }
            manifests.push(None);
        }

        if chunk_keys.is_empty() {
            return Ok(raw_entries);
        }

        let fetched_chunks = self.get_objects_batch(&chunk_keys)?;
        let mut results = Vec::with_capacity(raw_entries.len());
        for ((blob_id, opt_raw), opt_manifest) in blob_ids.iter().zip(raw_entries).zip(manifests) {
            if let Some((total_size, chunk_hashes)) = opt_manifest {
                // `total_size` is untrusted manifest input. Grow only from fetched,
                // integrity-checked chunks and enforce the declaration as a bound.
                let mut reassembled = Vec::new();
                let mut missing = false;
                for ch in chunk_hashes {
                    let idx = unique_chunk_hashes[&ch];
                    if let Some(chunk_bytes) = &fetched_chunks[idx] {
                        let next_size = (reassembled.len() as u64)
                            .checked_add(chunk_bytes.len() as u64)
                            .ok_or_else(|| {
                                StoreError::SnapshotCorrupted(
                                    "chunk manifest reconstructed size overflow".to_string(),
                                )
                            })?;
                        if next_size > total_size {
                            return Err(StoreError::SnapshotCorrupted(format!(
                                "chunk manifest declared {total_size} bytes but chunks exceed that size"
                            )));
                        }
                        reassembled.extend_from_slice(chunk_bytes);
                    } else {
                        missing = true;
                        break;
                    }
                }
                if missing {
                    results.push(None);
                } else {
                    if reassembled.len() as u64 != total_size {
                        return Err(StoreError::SnapshotCorrupted(format!(
                            "chunk manifest declared {total_size} bytes but reconstructed {} bytes",
                            reassembled.len()
                        )));
                    }
                    let actual = ObjectHash::from_domain(ObjectDomain::Blob, &reassembled);
                    if actual != blob_id.0 {
                        return Err(StoreError::IntegrityMismatch {
                            domain: ObjectDomain::Blob,
                            expected: blob_id.0,
                            actual,
                        });
                    }
                    results.push(Some(reassembled));
                }
            } else {
                results.push(opt_raw);
            }
        }
        Ok(results)
    }
}

const CHUNK_MANIFEST_MAGIC: &[u8; 8] = b"INRCBLK1";

fn encode_chunk_manifest(
    blob_hash: ObjectHash,
    total_size: u64,
    chunk_hashes: &[ObjectHash],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(52 + chunk_hashes.len() * 32);
    out.extend_from_slice(CHUNK_MANIFEST_MAGIC);
    out.extend_from_slice(blob_hash.as_bytes());
    out.extend_from_slice(&total_size.to_le_bytes());
    out.extend_from_slice(&(chunk_hashes.len() as u32).to_le_bytes());
    for h in chunk_hashes {
        out.extend_from_slice(h.as_bytes());
    }
    out
}

fn decode_chunk_manifest(
    expected_blob_hash: ObjectHash,
    data: &[u8],
) -> Result<Option<(u64, Vec<ObjectHash>)>, StoreError> {
    if !data.starts_with(CHUNK_MANIFEST_MAGIC) {
        return Ok(None);
    }
    if data.len() < 52 || !(data.len() - 52).is_multiple_of(32) {
        return Err(StoreError::IntegrityMismatch {
            domain: ObjectDomain::Blob,
            expected: expected_blob_hash,
            actual: ObjectHash::from_domain(ObjectDomain::Blob, data),
        });
    }
    let mut stored_blob_bytes = [0u8; 32];
    stored_blob_bytes.copy_from_slice(&data[8..40]);
    let stored_blob_hash = ObjectHash(stored_blob_bytes);
    if stored_blob_hash != expected_blob_hash {
        return Err(StoreError::IntegrityMismatch {
            domain: ObjectDomain::Blob,
            expected: expected_blob_hash,
            actual: stored_blob_hash,
        });
    }
    let total_size = u64::from_le_bytes(data[40..48].try_into().unwrap());
    let chunk_count = u32::from_le_bytes(data[48..52].try_into().unwrap()) as usize;
    if chunk_count == 0 {
        return Err(StoreError::SnapshotCorrupted(
            "chunk manifest must contain at least one chunk".to_string(),
        ));
    }
    let expected_len = chunk_count
        .checked_mul(32)
        .and_then(|chunk_bytes| 52usize.checked_add(chunk_bytes))
        .ok_or_else(|| {
            StoreError::SnapshotCorrupted("chunk manifest length overflow".to_string())
        })?;
    if expected_len != data.len() {
        return Err(StoreError::IntegrityMismatch {
            domain: ObjectDomain::Blob,
            expected: expected_blob_hash,
            actual: ObjectHash::from_domain(ObjectDomain::Blob, data),
        });
    }
    let mut chunks = Vec::with_capacity(chunk_count);
    for idx in 0..chunk_count {
        let off = 52 + idx * 32;
        let mut cb = [0u8; 32];
        cb.copy_from_slice(&data[off..off + 32]);
        chunks.push(ObjectHash(cb));
    }
    Ok(Some((total_size, chunks)))
}

/// Verify that `data` hashes to `expected` under `domain` (or is a structurally valid
/// `INRCBLK1` chunk manifest for `expected` when `domain == ObjectDomain::Blob`).
pub fn verify_object_integrity(
    domain: ObjectDomain,
    expected: ObjectHash,
    data: &[u8],
) -> Result<(), StoreError> {
    if domain == ObjectDomain::Blob && data.starts_with(CHUNK_MANIFEST_MAGIC) {
        decode_chunk_manifest(expected, data)?;
        return Ok(());
    }
    let actual = ObjectHash::from_domain(domain, data);
    if actual != expected {
        return Err(StoreError::IntegrityMismatch {
            domain,
            expected,
            actual,
        });
    }
    Ok(())
}

/// In-memory content-addressed store with snapshot warm-boot support.
#[derive(Default)]
pub struct MemBlobStore {
    objects: RwLock<BTreeMap<(u8, ObjectHash), Vec<u8>>>,
}

const SNAPSHOT_MAGIC: &[u8; 8] = b"INRCSNP1";

impl MemBlobStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Exports all cached objects into a deterministic binary snapshot for warm-booting new daemons.
    pub fn export_snapshot(&self) -> Vec<u8> {
        let guard = self.objects.read().expect("MemBlobStore lock poisoned");
        let mut out = Vec::new();
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.extend_from_slice(&(guard.len() as u32).to_le_bytes());
        for ((domain_tag, hash), bytes) in guard.iter() {
            out.push(*domain_tag);
            out.extend_from_slice(hash.as_bytes());
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        out
    }

    /// Imports and cryptographically verifies every object from a binary cache snapshot.
    pub fn import_snapshot(&self, snapshot: &[u8]) -> Result<usize, StoreError> {
        if snapshot.len() < 12 || &snapshot[0..8] != SNAPSHOT_MAGIC {
            return Err(StoreError::SnapshotCorrupted(
                "invalid snapshot magic".to_string(),
            ));
        }
        let count = u32::from_le_bytes(snapshot[8..12].try_into().unwrap()) as usize;
        let mut pos = 12;
        for _ in 0..count {
            if pos + 1 + 32 + 4 > snapshot.len() {
                return Err(StoreError::SnapshotCorrupted(
                    "unexpected EOF reading entry header".to_string(),
                ));
            }
            let domain = domain_from_code(snapshot[pos])?;
            pos += 1;
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&snapshot[pos..pos + 32]);
            let hash = ObjectHash(hash_bytes);
            pos += 32;
            let len = u32::from_le_bytes(snapshot[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + len > snapshot.len() {
                return Err(StoreError::SnapshotCorrupted(
                    "unexpected EOF reading entry payload".to_string(),
                ));
            }
            let payload = &snapshot[pos..pos + len];
            pos += len;
            self.put_object(domain, hash, payload)?;
        }
        if pos != snapshot.len() {
            return Err(StoreError::SnapshotCorrupted(
                "trailing bytes after snapshot entries".to_string(),
            ));
        }
        Ok(count)
    }
}

impl BlobStore for MemBlobStore {
    fn put_object(
        &self,
        domain: ObjectDomain,
        hash: ObjectHash,
        data: &[u8],
    ) -> Result<(), StoreError> {
        verify_object_integrity(domain, hash, data)?;
        let mut guard = self.objects.write().expect("MemBlobStore lock poisoned");
        guard.insert((domain_code(domain), hash), data.to_vec());
        Ok(())
    }

    fn get_object(
        &self,
        domain: ObjectDomain,
        hash: &ObjectHash,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let guard = self.objects.read().expect("MemBlobStore lock poisoned");
        if let Some(bytes) = guard.get(&(domain_code(domain), *hash)) {
            verify_object_integrity(domain, *hash, bytes)?;
            Ok(Some(bytes.clone()))
        } else {
            Ok(None)
        }
    }

    fn has_object(&self, domain: ObjectDomain, hash: &ObjectHash) -> Result<bool, StoreError> {
        let guard = self.objects.read().expect("MemBlobStore lock poisoned");
        Ok(guard.contains_key(&(domain_code(domain), *hash)))
    }

    fn has_objects_batch(
        &self,
        keys: &[(ObjectDomain, ObjectHash)],
    ) -> Result<Vec<bool>, StoreError> {
        let guard = self.objects.read().expect("MemBlobStore lock poisoned");
        Ok(keys
            .iter()
            .map(|(domain, hash)| guard.contains_key(&(domain_code(*domain), *hash)))
            .collect())
    }
}

/// Filesystem-backed content-addressed store (`inarch-daemon` NVMe cache / local origin store).
/// Stores objects under `<root>/<domain>/<hex[0..2]>/<hex>` with atomic temp-file renames
/// and full BLAKE3 verification on both write and read.
pub struct FsBlobStore {
    root: PathBuf,
    temp_counter: AtomicU64,
}

impl FsBlobStore {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(Self {
            root,
            temp_counter: AtomicU64::new(0),
        })
    }

    pub fn object_path(&self, domain: ObjectDomain, hash: &ObjectHash) -> PathBuf {
        let hex = hash.to_hex();
        self.root
            .join(domain_dir_name(domain))
            .join(&hex[0..2])
            .join(&hex)
    }
}

impl BlobStore for FsBlobStore {
    fn put_object(
        &self,
        domain: ObjectDomain,
        hash: ObjectHash,
        data: &[u8],
    ) -> Result<(), StoreError> {
        verify_object_integrity(domain, hash, data)?;
        let target = self.object_path(domain, &hash);
        if target.exists() {
            return Ok(());
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| StoreError::Io(e.to_string()))?;
        }
        let seq = self.temp_counter.fetch_add(1, Ordering::Relaxed);
        let tmp_path = target.with_extension(format!("tmp.{}.{}", std::process::id(), seq));
        std::fs::write(&tmp_path, data).map_err(|e| StoreError::Io(e.to_string()))?;
        std::fs::rename(&tmp_path, &target).map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    fn get_object(
        &self,
        domain: ObjectDomain,
        hash: &ObjectHash,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let target = self.object_path(domain, hash);
        match std::fs::read(&target) {
            Ok(bytes) => {
                verify_object_integrity(domain, *hash, &bytes)?;
                Ok(Some(bytes))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::Io(e.to_string())),
        }
    }

    fn has_object(&self, domain: ObjectDomain, hash: &ObjectHash) -> Result<bool, StoreError> {
        Ok(self.object_path(domain, hash).exists())
    }

    fn has_objects_batch(
        &self,
        keys: &[(ObjectDomain, ObjectHash)],
    ) -> Result<Vec<bool>, StoreError> {
        Ok(keys
            .iter()
            .map(|(domain, hash)| self.object_path(*domain, hash).exists())
            .collect())
    }
}

/// Telemetry counters for the 3-tier immutable cache hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TierStats {
    pub tier1_hits: u64,
    pub tier1_misses: u64,
    pub tier2_hits: u64,
    pub tier2_misses: u64,
    pub tier3_hits: u64,
    pub tier3_misses: u64,
}

/// Scion 3-tier immutable read-through cache:
/// - Tier 1: Host-local `inarch-daemon`
/// - Tier 2: Regional `inarch-cache`
/// - Tier 3: Origin `inarch-server` / Object Storage
///
/// Enforces Scion's **Strict Tiering** anti-stampede invariant:
/// Tier 1 may ONLY talk to Tier 2. If Tier 2 is unavailable, Tier 1 misses fail closed
/// (`StoreError::TierUnavailable`) rather than stampeding Tier 3 origin directly.
pub struct TieredBlobStore {
    tier1_daemon: Arc<dyn BlobStore>,
    tier2_regional: Arc<dyn BlobStore>,
    tier3_origin: Arc<dyn BlobStore>,
    tier2_available: AtomicBool,
    tier1_hits: AtomicU64,
    tier1_misses: AtomicU64,
    tier2_hits: AtomicU64,
    tier2_misses: AtomicU64,
    tier3_hits: AtomicU64,
    tier3_misses: AtomicU64,
}

impl TieredBlobStore {
    pub fn new<S1, S2, S3>(
        tier1_daemon: Arc<S1>,
        tier2_regional: Arc<S2>,
        tier3_origin: Arc<S3>,
    ) -> Self
    where
        S1: BlobStore + 'static,
        S2: BlobStore + 'static,
        S3: BlobStore + 'static,
    {
        Self::from_dyn(tier1_daemon, tier2_regional, tier3_origin)
    }

    pub fn from_dyn(
        tier1_daemon: Arc<dyn BlobStore>,
        tier2_regional: Arc<dyn BlobStore>,
        tier3_origin: Arc<dyn BlobStore>,
    ) -> Self {
        Self {
            tier1_daemon,
            tier2_regional,
            tier3_origin,
            tier2_available: AtomicBool::new(true),
            tier1_hits: AtomicU64::new(0),
            tier1_misses: AtomicU64::new(0),
            tier2_hits: AtomicU64::new(0),
            tier2_misses: AtomicU64::new(0),
            tier3_hits: AtomicU64::new(0),
            tier3_misses: AtomicU64::new(0),
        }
    }

    pub fn set_tier2_available(&self, available: bool) {
        self.tier2_available.store(available, Ordering::SeqCst);
    }

    pub fn stats(&self) -> TierStats {
        TierStats {
            tier1_hits: self.tier1_hits.load(Ordering::SeqCst),
            tier1_misses: self.tier1_misses.load(Ordering::SeqCst),
            tier2_hits: self.tier2_hits.load(Ordering::SeqCst),
            tier2_misses: self.tier2_misses.load(Ordering::SeqCst),
            tier3_hits: self.tier3_hits.load(Ordering::SeqCst),
            tier3_misses: self.tier3_misses.load(Ordering::SeqCst),
        }
    }
}

impl BlobStore for TieredBlobStore {
    fn put_object(
        &self,
        domain: ObjectDomain,
        hash: ObjectHash,
        data: &[u8],
    ) -> Result<(), StoreError> {
        verify_object_integrity(domain, hash, data)?;
        // Writes go to authoritative Tier 3 origin and warm Tier 2 + Tier 1 if available
        self.tier3_origin.put_object(domain, hash, data)?;
        if self.tier2_available.load(Ordering::SeqCst) {
            let _ = self.tier2_regional.put_object(domain, hash, data);
        }
        let _ = self.tier1_daemon.put_object(domain, hash, data);
        Ok(())
    }

    fn put_objects_batch(
        &self,
        objects: &[(ObjectDomain, ObjectHash, Vec<u8>)],
    ) -> Result<(), StoreError> {
        if objects.is_empty() {
            return Ok(());
        }
        for (domain, hash, data) in objects {
            verify_object_integrity(*domain, *hash, data)?;
        }
        for chunk in objects.chunks(128) {
            self.tier3_origin.put_objects_batch(chunk)?;
            if self.tier2_available.load(Ordering::SeqCst) {
                let _ = self.tier2_regional.put_objects_batch(chunk);
            }
            let _ = self.tier1_daemon.put_objects_batch(chunk);
        }
        Ok(())
    }

    fn has_object(&self, domain: ObjectDomain, hash: &ObjectHash) -> Result<bool, StoreError> {
        if self.tier1_daemon.has_object(domain, hash)? {
            return Ok(true);
        }
        if !self.tier2_available.load(Ordering::SeqCst) {
            return Err(StoreError::TierUnavailable(
                "tier2 (inarch-cache)".to_string(),
            ));
        }
        if self.tier2_regional.has_object(domain, hash)? {
            return Ok(true);
        }
        self.tier3_origin.has_object(domain, hash)
    }

    fn has_objects_batch(
        &self,
        keys: &[(ObjectDomain, ObjectHash)],
    ) -> Result<Vec<bool>, StoreError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let mut present = self.tier1_daemon.has_objects_batch(keys)?;
        let mut missing_indices: Vec<usize> = present
            .iter()
            .enumerate()
            .filter_map(|(i, &p)| if !p { Some(i) } else { None })
            .collect();
        if missing_indices.is_empty() {
            return Ok(present);
        }

        if !self.tier2_available.load(Ordering::SeqCst) {
            return Err(StoreError::TierUnavailable(
                "tier2 (inarch-cache)".to_string(),
            ));
        }

        let t2_keys: Vec<(ObjectDomain, ObjectHash)> =
            missing_indices.iter().map(|&i| keys[i]).collect();
        let t2_present = self.tier2_regional.has_objects_batch(&t2_keys)?;
        let mut still_missing = Vec::new();
        for (idx_pos, is_present) in t2_present.into_iter().enumerate() {
            let orig_idx = missing_indices[idx_pos];
            if is_present {
                present[orig_idx] = true;
            } else {
                still_missing.push(orig_idx);
            }
        }
        missing_indices = still_missing;
        if missing_indices.is_empty() {
            return Ok(present);
        }

        let t3_keys: Vec<(ObjectDomain, ObjectHash)> =
            missing_indices.iter().map(|&i| keys[i]).collect();
        let t3_present = self.tier3_origin.has_objects_batch(&t3_keys)?;
        for (idx_pos, is_present) in t3_present.into_iter().enumerate() {
            if is_present {
                present[missing_indices[idx_pos]] = true;
            }
        }
        Ok(present)
    }

    fn get_object(
        &self,
        domain: ObjectDomain,
        hash: &ObjectHash,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        // 1. Check Tier 1 (node-local daemon)
        if let Some(bytes) = self.tier1_daemon.get_object(domain, hash)? {
            self.tier1_hits.fetch_add(1, Ordering::SeqCst);
            return Ok(Some(bytes));
        }
        self.tier1_misses.fetch_add(1, Ordering::SeqCst);

        // 2. Strict Tiering enforcement: if Tier 2 is down, NEVER bypass to Tier 3!
        if !self.tier2_available.load(Ordering::SeqCst) {
            return Err(StoreError::TierUnavailable(
                "tier2 (inarch-cache)".to_string(),
            ));
        }

        // 3. Check Tier 2 (regional cache)
        if let Some(bytes) = self.tier2_regional.get_object(domain, hash)? {
            self.tier2_hits.fetch_add(1, Ordering::SeqCst);
            self.tier1_daemon.put_object(domain, *hash, &bytes)?;
            return Ok(Some(bytes));
        }
        self.tier2_misses.fetch_add(1, Ordering::SeqCst);

        // 4. Tier 2 fetches from Tier 3 (origin) and backfills Tier 2 -> Tier 1
        if let Some(bytes) = self.tier3_origin.get_object(domain, hash)? {
            self.tier3_hits.fetch_add(1, Ordering::SeqCst);
            self.tier2_regional.put_object(domain, *hash, &bytes)?;
            self.tier1_daemon.put_object(domain, *hash, &bytes)?;
            return Ok(Some(bytes));
        }
        self.tier3_misses.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }

    fn get_objects_batch(
        &self,
        keys: &[(ObjectDomain, ObjectHash)],
    ) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let mut results = vec![None; keys.len()];
        let mut t1_miss_indices = Vec::new();
        let mut t1_miss_keys = Vec::new();

        let t1_res = self.tier1_daemon.get_objects_batch(keys)?;
        for (idx, item) in t1_res.into_iter().enumerate() {
            if let Some(bytes) = item {
                self.tier1_hits.fetch_add(1, Ordering::SeqCst);
                results[idx] = Some(bytes);
            } else {
                self.tier1_misses.fetch_add(1, Ordering::SeqCst);
                t1_miss_indices.push(idx);
                t1_miss_keys.push(keys[idx]);
            }
        }
        if t1_miss_keys.is_empty() {
            return Ok(results);
        }

        if !self.tier2_available.load(Ordering::SeqCst) {
            return Err(StoreError::TierUnavailable(
                "tier2 (inarch-cache)".to_string(),
            ));
        }

        let mut t2_miss_indices = Vec::new();
        let mut t2_miss_keys = Vec::new();
        let mut backfill_t1 = Vec::new();

        let t2_res = self.tier2_regional.get_objects_batch(&t1_miss_keys)?;
        for (miss_pos, item) in t2_res.into_iter().enumerate() {
            let orig_idx = t1_miss_indices[miss_pos];
            let (domain, hash) = t1_miss_keys[miss_pos];
            if let Some(bytes) = item {
                self.tier2_hits.fetch_add(1, Ordering::SeqCst);
                backfill_t1.push((domain, hash, bytes.clone()));
                results[orig_idx] = Some(bytes);
            } else {
                self.tier2_misses.fetch_add(1, Ordering::SeqCst);
                t2_miss_indices.push(orig_idx);
                t2_miss_keys.push((domain, hash));
            }
        }

        if !backfill_t1.is_empty() {
            self.tier1_daemon.put_objects_batch(&backfill_t1)?;
        }
        if t2_miss_keys.is_empty() {
            return Ok(results);
        }

        let mut backfill_t2_t1 = Vec::new();
        let t3_res = self.tier3_origin.get_objects_batch(&t2_miss_keys)?;
        for (miss_pos, item) in t3_res.into_iter().enumerate() {
            let orig_idx = t2_miss_indices[miss_pos];
            let (domain, hash) = t2_miss_keys[miss_pos];
            if let Some(bytes) = item {
                self.tier3_hits.fetch_add(1, Ordering::SeqCst);
                backfill_t2_t1.push((domain, hash, bytes.clone()));
                results[orig_idx] = Some(bytes);
            } else {
                self.tier3_misses.fetch_add(1, Ordering::SeqCst);
            }
        }

        if !backfill_t2_t1.is_empty() {
            self.tier2_regional.put_objects_batch(&backfill_t2_t1)?;
            self.tier1_daemon.put_objects_batch(&backfill_t2_t1)?;
        }

        Ok(results)
    }
}

/// Enrolled device or service principal record (`ScionPrincipals`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalRecord {
    pub principal_email: String,
    pub principal_kind: String,
    pub host_label: String,
    pub allowed_repos: Vec<String>,
    pub allowed_ops: Vec<String>,
    pub status: String,
    pub enrolled_by: String,
    pub created_at_unix: i64,
    pub revoked_at_unix: Option<i64>,
    pub allowed_write_prefixes: Vec<String>,
}

/// Hard ceiling (24 hours) on total JIT lease lifetime from `issued_at_unix`, across all renewals.
pub const MAX_JIT_LEASE_LIFETIME_SECS: i64 = 86_400;

/// Short-lived Just-In-Time (JIT) access lease checked out for a swarm or agent task (`ScionLeases`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JitLeaseRecord {
    pub lease_id: String,
    pub principal_email: String,
    pub swarm_id: String,
    pub task_id: String,
    pub repo_id: String,
    pub allowed_ops: Vec<String>,
    pub allowed_read_prefixes: Vec<String>,
    pub allowed_write_prefixes: Vec<String>,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub revoked: bool,
    pub allowed_refs: Vec<String>,
}

fn bin_write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn bin_read_u32(data: &[u8], pos: &mut usize) -> Result<u32, StoreError> {
    if *pos + 4 > data.len() {
        return Err(StoreError::SnapshotCorrupted("EOF reading u32".into()));
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&data[*pos..*pos + 4]);
    *pos += 4;
    Ok(u32::from_le_bytes(b))
}

fn bin_write_i64(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn bin_read_i64(data: &[u8], pos: &mut usize) -> Result<i64, StoreError> {
    if *pos + 8 > data.len() {
        return Err(StoreError::SnapshotCorrupted("EOF reading i64".into()));
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[*pos..*pos + 8]);
    *pos += 8;
    Ok(i64::from_le_bytes(b))
}

fn bin_write_str(buf: &mut Vec<u8>, s: &str) {
    bin_write_u32(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

fn bin_read_str(data: &[u8], pos: &mut usize) -> Result<String, StoreError> {
    let len = bin_read_u32(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(StoreError::SnapshotCorrupted("EOF reading str".into()));
    }
    let s = std::str::from_utf8(&data[*pos..*pos + len])
        .map_err(|e| StoreError::SnapshotCorrupted(e.to_string()))?
        .to_string();
    *pos += len;
    Ok(s)
}

fn bin_write_str_vec(buf: &mut Vec<u8>, list: &[String]) {
    bin_write_u32(buf, list.len() as u32);
    for item in list {
        bin_write_str(buf, item);
    }
}

fn bin_read_str_vec(data: &[u8], pos: &mut usize) -> Result<Vec<String>, StoreError> {
    let count = bin_read_u32(data, pos)? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(bin_read_str(data, pos)?);
    }
    Ok(out)
}

impl PrincipalRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf);
        buf
    }

    pub fn write_into(&self, buf: &mut Vec<u8>) {
        bin_write_str(buf, &self.principal_email);
        bin_write_str(buf, &self.principal_kind);
        bin_write_str(buf, &self.host_label);
        bin_write_str_vec(buf, &self.allowed_repos);
        bin_write_str_vec(buf, &self.allowed_ops);
        bin_write_str(buf, &self.status);
        bin_write_str(buf, &self.enrolled_by);
        bin_write_i64(buf, self.created_at_unix);
        match self.revoked_at_unix {
            Some(ts) => {
                buf.push(1);
                bin_write_i64(buf, ts);
            }
            None => buf.push(0),
        }
        bin_write_str_vec(buf, &self.allowed_write_prefixes);
    }

    pub fn read_from(data: &[u8], pos: &mut usize) -> Result<Self, StoreError> {
        let principal_email = bin_read_str(data, pos)?;
        let principal_kind = bin_read_str(data, pos)?;
        let host_label = bin_read_str(data, pos)?;
        let allowed_repos = bin_read_str_vec(data, pos)?;
        let allowed_ops = bin_read_str_vec(data, pos)?;
        let status = bin_read_str(data, pos)?;
        let enrolled_by = bin_read_str(data, pos)?;
        let created_at_unix = bin_read_i64(data, pos)?;
        if *pos >= data.len() {
            return Err(StoreError::SnapshotCorrupted(
                "EOF reading revoked_at_unix tag".into(),
            ));
        }
        let rev_tag = data[*pos];
        *pos += 1;
        let revoked_at_unix = if rev_tag == 1 {
            Some(bin_read_i64(data, pos)?)
        } else {
            None
        };
        let allowed_write_prefixes = if *pos < data.len() {
            bin_read_str_vec(data, pos)?
        } else {
            Vec::new()
        };
        Ok(Self {
            principal_email,
            principal_kind,
            host_label,
            allowed_repos,
            allowed_ops,
            status,
            enrolled_by,
            created_at_unix,
            revoked_at_unix,
            allowed_write_prefixes,
        })
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, StoreError> {
        let mut pos = 0;
        Self::read_from(data, &mut pos)
    }
}

impl JitLeaseRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf);
        buf
    }

    pub fn write_into(&self, buf: &mut Vec<u8>) {
        bin_write_str(buf, &self.lease_id);
        bin_write_str(buf, &self.principal_email);
        bin_write_str(buf, &self.swarm_id);
        bin_write_str(buf, &self.task_id);
        bin_write_str(buf, &self.repo_id);
        bin_write_str_vec(buf, &self.allowed_ops);
        bin_write_str_vec(buf, &self.allowed_read_prefixes);
        bin_write_str_vec(buf, &self.allowed_write_prefixes);
        bin_write_i64(buf, self.issued_at_unix);
        bin_write_i64(buf, self.expires_at_unix);
        buf.push(if self.revoked { 1 } else { 0 });
        bin_write_str_vec(buf, &self.allowed_refs);
    }

    pub fn read_from(data: &[u8], pos: &mut usize) -> Result<Self, StoreError> {
        let lease_id = bin_read_str(data, pos)?;
        let principal_email = bin_read_str(data, pos)?;
        let swarm_id = bin_read_str(data, pos)?;
        let task_id = bin_read_str(data, pos)?;
        let repo_id = bin_read_str(data, pos)?;
        let allowed_ops = bin_read_str_vec(data, pos)?;
        let allowed_read_prefixes = bin_read_str_vec(data, pos)?;
        let allowed_write_prefixes = bin_read_str_vec(data, pos)?;
        let issued_at_unix = bin_read_i64(data, pos)?;
        let expires_at_unix = bin_read_i64(data, pos)?;
        if *pos >= data.len() {
            return Err(StoreError::SnapshotCorrupted("EOF reading revoked".into()));
        }
        let revoked = data[*pos] != 0;
        *pos += 1;
        let allowed_refs = if *pos < data.len() {
            bin_read_str_vec(data, pos)?
        } else {
            Vec::new()
        };
        Ok(Self {
            lease_id,
            principal_email,
            swarm_id,
            task_id,
            repo_id,
            allowed_ops,
            allowed_read_prefixes,
            allowed_write_prefixes,
            issued_at_unix,
            expires_at_unix,
            revoked,
            allowed_refs,
        })
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, StoreError> {
        let mut pos = 0;
        Self::read_from(data, &mut pos)
    }

    /// Canonical payload of immutable scope claims covered by the 256-bit BLAKE3 keyed MAC.
    pub fn mac_signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"velenza-inarch.jit.lease.v1\0");
        bin_write_str(&mut buf, &self.lease_id);
        bin_write_str(&mut buf, &self.principal_email);
        bin_write_str(&mut buf, &self.swarm_id);
        bin_write_str(&mut buf, &self.task_id);
        bin_write_str(&mut buf, &self.repo_id);
        bin_write_str_vec(&mut buf, &self.allowed_ops);
        bin_write_str_vec(&mut buf, &self.allowed_read_prefixes);
        bin_write_str_vec(&mut buf, &self.allowed_write_prefixes);
        bin_write_i64(&mut buf, self.issued_at_unix);
        if !self.allowed_refs.is_empty() {
            bin_write_str_vec(&mut buf, &self.allowed_refs);
        }
        buf
    }
}

/// Derives a 32-byte key from a configured secret string using BLAKE3 key derivation.
pub fn derive_jit_signing_key(secret: &str) -> [u8; 32] {
    if secret.len() == 64
        && let Ok(h) = ObjectHash::from_hex(secret)
    {
        return h.0;
    }
    let mut kdf = Blake3Hasher::new_derive_key("velenza-inarch 2026-10 jit-lease-signing-key v1");
    kdf.update(secret.as_bytes());
    kdf.finalize_bytes()
}

/// Mints a quantum-safe 256-bit BLAKE3 keyed MAC token `inarch_jit_v1_<lease_id>_<mac_hex>`.
pub fn mint_jit_lease_token(lease: &JitLeaseRecord, signing_key: &[u8; 32]) -> String {
    let mac = blake3_keyed_hash(signing_key, &lease.mac_signing_bytes());
    format!("inarch_jit_v1_{}_{}", lease.lease_id, mac.to_hex())
}

/// Parses `inarch_jit_v1_<lease_id>_<mac_hex>` into `(lease_id, mac_hex)`.
pub fn parse_jit_lease_token(token: &str) -> Option<(&str, &str)> {
    let rest = token.strip_prefix("inarch_jit_v1_")?;
    let (lease_id, mac_hex) = rest.rsplit_once('_')?;
    if lease_id.is_empty() || mac_hex.len() != 64 {
        return None;
    }
    Some((lease_id, mac_hex))
}

/// Verifies in constant time that `token` carries a valid 256-bit BLAKE3 keyed MAC for `lease`.
pub fn verify_jit_lease_token(token: &str, lease: &JitLeaseRecord, signing_key: &[u8; 32]) -> bool {
    let Some((lease_id, mac_hex)) = parse_jit_lease_token(token) else {
        return false;
    };
    if lease_id != lease.lease_id {
        return false;
    }
    let Ok(provided_mac) = ObjectHash::from_hex(mac_hex) else {
        return false;
    };
    let expected_mac = blake3_keyed_hash(signing_key, &lease.mac_signing_bytes());
    let mut diff = 0u8;
    for (a, b) in provided_mac.0.iter().zip(expected_mac.0.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Authoritative transactional metadata store for `BonsaiChangeset`s, global refs (`main`, `release/*`),
/// derived-data mappings (`(ChangesetId, DerivedDataKind) -> ObjectHash`), enrolled device principals,
/// and Just-In-Time (JIT) swarm access leases.
pub trait MetadataStore: Send + Sync {
    /// Stores a `BonsaiChangeset` keyed by its canonical `ChangesetId`.
    fn put_changeset(&self, changeset: &BonsaiChangeset) -> Result<ChangesetId, StoreError>;

    /// Retrieves a `BonsaiChangeset` by its `ChangesetId`.
    fn get_changeset(
        &self,
        changeset_id: &ChangesetId,
    ) -> Result<Option<BonsaiChangeset>, StoreError>;

    /// Reads only the parent ids of the changeset stored under `changeset_id`.
    ///
    /// The default decodes the whole changeset. Stores that keep canonical bytes override it
    /// to read the header alone, so ancestry walks (fast-forward checks, reachability) cost
    /// nothing proportional to the bodies of the changesets they pass through. The result is
    /// not integrity-checked against the id; use [`MetadataStore::get_changeset`] when the
    /// body or its hash matters.
    fn get_changeset_parents(
        &self,
        changeset_id: &ChangesetId,
    ) -> Result<Option<Vec<ChangesetId>>, StoreError> {
        Ok(self.get_changeset(changeset_id)?.map(|cs| cs.parents))
    }

    /// Reads the current `ChangesetId` pointed to by `ref_name` (e.g., `"main"`).
    fn get_ref(&self, ref_name: &str) -> Result<Option<ChangesetId>, StoreError>;

    /// Lists all global refs and their current `ChangesetId` targets.
    fn list_refs(&self) -> Result<BTreeMap<String, ChangesetId>, StoreError>;

    /// Atomic Compare-And-Swap on a single ref row.
    /// Succeeds iff the current value of `ref_name` equals `expected` AND `new_target` exists in the store.
    fn cas_ref(
        &self,
        ref_name: &str,
        expected: Option<ChangesetId>,
        new_target: ChangesetId,
    ) -> Result<(), StoreError>;

    /// Records an idempotent derived-data root hash mapping for `(changeset_id, kind)`.
    fn put_derived_mapping(
        &self,
        changeset_id: ChangesetId,
        kind: DerivedDataKind,
        derived_hash: ObjectHash,
    ) -> Result<(), StoreError>;

    /// Looks up the derived-data root hash for `(changeset_id, kind)`.
    fn get_derived_mapping(
        &self,
        changeset_id: ChangesetId,
        kind: DerivedDataKind,
    ) -> Result<Option<ObjectHash>, StoreError>;

    /// Upserts an enrolled device/service principal (`ScionPrincipals`).
    fn put_principal(&self, principal: &PrincipalRecord) -> Result<(), StoreError> {
        let _ = principal;
        Err(StoreError::Io(
            "put_principal not supported by this MetadataStore".into(),
        ))
    }

    /// Looks up a device/service principal by `principal_email`.
    fn get_principal(&self, principal_email: &str) -> Result<Option<PrincipalRecord>, StoreError> {
        let _ = principal_email;
        Ok(None)
    }

    /// Lists all enrolled device/service principals ordered by `principal_email`.
    fn list_principals(&self) -> Result<Vec<PrincipalRecord>, StoreError> {
        Ok(Vec::new())
    }

    /// Upserts a JIT swarm access lease (`ScionLeases`).
    fn put_lease(&self, lease: &JitLeaseRecord) -> Result<(), StoreError> {
        let _ = lease;
        Err(StoreError::Io(
            "put_lease not supported by this MetadataStore".into(),
        ))
    }

    /// Looks up a JIT swarm access lease by `lease_id`.
    fn get_lease(&self, lease_id: &str) -> Result<Option<JitLeaseRecord>, StoreError> {
        let _ = lease_id;
        Ok(None)
    }

    /// Lists all JIT swarm access leases (optionally filtered by `repo_id`).
    fn list_leases(&self, repo_filter: Option<&str>) -> Result<Vec<JitLeaseRecord>, StoreError> {
        let _ = repo_filter;
        Ok(Vec::new())
    }
}

#[derive(Default)]
struct MetadataState {
    changesets: BTreeMap<ChangesetId, BonsaiChangeset>,
    refs: BTreeMap<String, ChangesetId>,
    derived: BTreeMap<(ChangesetId, DerivedDataKind), ObjectHash>,
    principals: BTreeMap<String, PrincipalRecord>,
    leases: BTreeMap<String, JitLeaseRecord>,
}

/// Serializable in-memory transactional `MetadataStore` implementation.
#[derive(Default)]
pub struct MemMetadataStore {
    state: RwLock<MetadataState>,
}

impl MemMetadataStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl MetadataStore for MemMetadataStore {
    fn put_changeset(&self, changeset: &BonsaiChangeset) -> Result<ChangesetId, StoreError> {
        let id = changeset.changeset_id();
        let mut guard = self.state.write().expect("MemMetadataStore lock poisoned");
        // Verify all parent changesets exist in the metadata store
        for parent in &changeset.parents {
            if !guard.changesets.contains_key(parent) {
                return Err(StoreError::UnknownChangeset(*parent));
            }
        }
        guard.changesets.insert(id, changeset.clone());
        Ok(id)
    }

    fn get_changeset(
        &self,
        changeset_id: &ChangesetId,
    ) -> Result<Option<BonsaiChangeset>, StoreError> {
        let guard = self.state.read().expect("MemMetadataStore lock poisoned");
        Ok(guard.changesets.get(changeset_id).cloned())
    }

    fn get_ref(&self, ref_name: &str) -> Result<Option<ChangesetId>, StoreError> {
        let guard = self.state.read().expect("MemMetadataStore lock poisoned");
        Ok(guard.refs.get(ref_name).copied())
    }

    fn list_refs(&self) -> Result<BTreeMap<String, ChangesetId>, StoreError> {
        let guard = self.state.read().expect("MemMetadataStore lock poisoned");
        Ok(guard.refs.clone())
    }

    fn cas_ref(
        &self,
        ref_name: &str,
        expected: Option<ChangesetId>,
        new_target: ChangesetId,
    ) -> Result<(), StoreError> {
        let mut guard = self.state.write().expect("MemMetadataStore lock poisoned");
        if !guard.changesets.contains_key(&new_target) {
            return Err(StoreError::UnknownChangeset(new_target));
        }
        let actual = guard.refs.get(ref_name).copied();
        if actual != expected {
            return Err(StoreError::CasMismatch {
                ref_name: ref_name.to_string(),
                expected,
                actual,
            });
        }
        guard.refs.insert(ref_name.to_string(), new_target);
        Ok(())
    }

    fn put_derived_mapping(
        &self,
        changeset_id: ChangesetId,
        kind: DerivedDataKind,
        derived_hash: ObjectHash,
    ) -> Result<(), StoreError> {
        let mut guard = self.state.write().expect("MemMetadataStore lock poisoned");
        if !guard.changesets.contains_key(&changeset_id) {
            return Err(StoreError::UnknownChangeset(changeset_id));
        }
        if let Some(&existing) = guard.derived.get(&(changeset_id, kind)) {
            if existing != derived_hash {
                return Err(StoreError::ConflictingDerivedMapping {
                    changeset_id,
                    kind,
                    existing,
                    attempted: derived_hash,
                });
            }
            return Ok(());
        }
        guard.derived.insert((changeset_id, kind), derived_hash);
        Ok(())
    }

    fn get_derived_mapping(
        &self,
        changeset_id: ChangesetId,
        kind: DerivedDataKind,
    ) -> Result<Option<ObjectHash>, StoreError> {
        let guard = self.state.read().expect("MemMetadataStore lock poisoned");
        Ok(guard.derived.get(&(changeset_id, kind)).copied())
    }

    fn put_principal(&self, principal: &PrincipalRecord) -> Result<(), StoreError> {
        let mut guard = self.state.write().expect("MemMetadataStore lock poisoned");
        guard
            .principals
            .insert(principal.principal_email.clone(), principal.clone());
        Ok(())
    }

    fn get_principal(&self, principal_email: &str) -> Result<Option<PrincipalRecord>, StoreError> {
        let guard = self.state.read().expect("MemMetadataStore lock poisoned");
        Ok(guard.principals.get(principal_email).cloned())
    }

    fn list_principals(&self) -> Result<Vec<PrincipalRecord>, StoreError> {
        let guard = self.state.read().expect("MemMetadataStore lock poisoned");
        Ok(guard.principals.values().cloned().collect())
    }

    fn put_lease(&self, lease: &JitLeaseRecord) -> Result<(), StoreError> {
        let mut guard = self.state.write().expect("MemMetadataStore lock poisoned");
        guard.leases.insert(lease.lease_id.clone(), lease.clone());
        Ok(())
    }

    fn get_lease(&self, lease_id: &str) -> Result<Option<JitLeaseRecord>, StoreError> {
        let guard = self.state.read().expect("MemMetadataStore lock poisoned");
        Ok(guard.leases.get(lease_id).cloned())
    }

    fn list_leases(&self, repo_filter: Option<&str>) -> Result<Vec<JitLeaseRecord>, StoreError> {
        let guard = self.state.read().expect("MemMetadataStore lock poisoned");
        let mut out: Vec<JitLeaseRecord> = guard
            .leases
            .values()
            .filter(|l| match repo_filter {
                Some(r) if !r.trim().is_empty() => l.repo_id == r.trim(),
                _ => true,
            })
            .cloned()
            .collect();
        out.sort_by(|a, b| a.lease_id.cmp(&b.lease_id));
        Ok(out)
    }
}

/// Persistent filesystem-backed `MetadataStore` implementation with atomic write-temp-and-rename
/// and canonical BLAKE3 changeset verification on read.
pub struct FsMetadataStore {
    root: PathBuf,
    lock: RwLock<()>,
    temp_counter: AtomicU64,
}

impl FsMetadataStore {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(root.join("changesets"))
            .map_err(|e| StoreError::Io(e.to_string()))?;
        std::fs::create_dir_all(root.join("refs")).map_err(|e| StoreError::Io(e.to_string()))?;
        std::fs::create_dir_all(root.join("derived")).map_err(|e| StoreError::Io(e.to_string()))?;
        std::fs::create_dir_all(root.join("principals"))
            .map_err(|e| StoreError::Io(e.to_string()))?;
        std::fs::create_dir_all(root.join("leases")).map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(Self {
            root,
            lock: RwLock::new(()),
            temp_counter: AtomicU64::new(0),
        })
    }

    fn changeset_path(&self, id: &ChangesetId) -> PathBuf {
        let hex = id.to_hex();
        self.root.join("changesets").join(&hex[0..2]).join(&hex)
    }

    fn hex_encode_name(name: &str) -> String {
        let mut encoded = String::with_capacity(name.len() * 2);
        for b in name.as_bytes() {
            encoded.push_str(&format!("{:02x}", b));
        }
        encoded
    }

    fn ref_path(&self, ref_name: &str) -> PathBuf {
        self.root.join("refs").join(Self::hex_encode_name(ref_name))
    }

    fn principal_path(&self, email: &str) -> PathBuf {
        self.root
            .join("principals")
            .join(Self::hex_encode_name(email))
    }

    fn lease_path(&self, lease_id: &str) -> PathBuf {
        self.root
            .join("leases")
            .join(Self::hex_encode_name(lease_id))
    }

    fn decode_ref_filename(name: &str) -> Option<String> {
        if !name.len().is_multiple_of(2) {
            return None;
        }
        let mut bytes = Vec::with_capacity(name.len() / 2);
        for i in (0..name.len()).step_by(2) {
            let b = u8::from_str_radix(&name[i..i + 2], 16).ok()?;
            bytes.push(b);
        }
        String::from_utf8(bytes).ok()
    }

    fn derived_path(&self, id: &ChangesetId, kind: DerivedDataKind) -> PathBuf {
        let hex = id.to_hex();
        self.root
            .join("derived")
            .join(kind.as_str())
            .join(&hex[0..2])
            .join(&hex)
    }

    fn atomic_write(&self, target: &Path, data: &[u8]) -> Result<(), StoreError> {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| StoreError::Io(e.to_string()))?;
        }
        let seq = self.temp_counter.fetch_add(1, Ordering::Relaxed);
        let tmp_path = target.with_extension(format!("tmp.{}.{}", std::process::id(), seq));
        std::fs::write(&tmp_path, data).map_err(|e| StoreError::Io(e.to_string()))?;
        std::fs::rename(&tmp_path, target).map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }
}

impl MetadataStore for FsMetadataStore {
    fn put_changeset(&self, changeset: &BonsaiChangeset) -> Result<ChangesetId, StoreError> {
        let _guard = self.lock.write().expect("FsMetadataStore lock poisoned");
        for parent in &changeset.parents {
            if !self.changeset_path(parent).exists() {
                return Err(StoreError::UnknownChangeset(*parent));
            }
        }
        let id = changeset.changeset_id();
        let target = self.changeset_path(&id);
        if !target.exists() {
            let bytes = changeset.to_canonical_bytes();
            self.atomic_write(&target, &bytes)?;
        }
        Ok(id)
    }

    fn get_changeset(
        &self,
        changeset_id: &ChangesetId,
    ) -> Result<Option<BonsaiChangeset>, StoreError> {
        let _guard = self.lock.read().expect("FsMetadataStore lock poisoned");
        let target = self.changeset_path(changeset_id);
        match std::fs::read(&target) {
            Ok(bytes) => {
                let cs = BonsaiChangeset::from_canonical_bytes(&bytes)
                    .map_err(|e| StoreError::SnapshotCorrupted(e.to_string()))?;
                let actual_id = cs.changeset_id();
                if actual_id != *changeset_id {
                    return Err(StoreError::IntegrityMismatch {
                        domain: ObjectDomain::Changeset,
                        expected: changeset_id.0,
                        actual: actual_id.0,
                    });
                }
                Ok(Some(cs))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::Io(e.to_string())),
        }
    }

    /// Reads the canonical header of the stored changeset file and nothing after it: the
    /// magic, the parent count and the parent ids. The body stays on disk unread, so the cost
    /// is proportional to the number of parents, not to the number of file changes.
    fn get_changeset_parents(
        &self,
        changeset_id: &ChangesetId,
    ) -> Result<Option<Vec<ChangesetId>>, StoreError> {
        use std::io::Read;

        let _guard = self.lock.read().expect("FsMetadataStore lock poisoned");
        let target = self.changeset_path(changeset_id);
        let mut file = match std::fs::File::open(&target) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StoreError::Io(e.to_string())),
        };
        let truncated =
            |e: std::io::Error| StoreError::SnapshotCorrupted(format!("changeset header: {e}"));
        let mut header = vec![0u8; BonsaiChangeset::canonical_header_len(0)];
        file.read_exact(&mut header).map_err(truncated)?;
        let parent_count =
            u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
        let header_len = BonsaiChangeset::canonical_header_len(parent_count);
        // A corrupt parent count must not turn into an oversized read: the header can never
        // be longer than the file that holds it.
        let file_len = file
            .metadata()
            .map_err(|e| StoreError::Io(e.to_string()))?
            .len();
        if header_len as u64 > file_len {
            return Err(StoreError::SnapshotCorrupted(format!(
                "changeset header declares {parent_count} parents but the file holds {file_len} bytes"
            )));
        }
        header.resize(header_len, 0);
        file.read_exact(&mut header[BonsaiChangeset::canonical_header_len(0)..])
            .map_err(truncated)?;
        let parents = BonsaiChangeset::parents_from_canonical_bytes(&header)
            .map_err(|e| StoreError::SnapshotCorrupted(e.to_string()))?;
        Ok(Some(parents))
    }

    fn get_ref(&self, ref_name: &str) -> Result<Option<ChangesetId>, StoreError> {
        let _guard = self.lock.read().expect("FsMetadataStore lock poisoned");
        let target = self.ref_path(ref_name);
        match std::fs::read(&target) {
            Ok(bytes) => {
                if bytes.len() != 32 {
                    return Err(StoreError::SnapshotCorrupted(format!(
                        "invalid ref file length {} for '{}'",
                        bytes.len(),
                        ref_name
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(ChangesetId::from_hash(ObjectHash(arr))))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::Io(e.to_string())),
        }
    }

    fn list_refs(&self) -> Result<BTreeMap<String, ChangesetId>, StoreError> {
        let _guard = self.lock.read().expect("FsMetadataStore lock poisoned");
        let mut out = BTreeMap::new();
        let entries =
            std::fs::read_dir(self.root.join("refs")).map_err(|e| StoreError::Io(e.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|e| StoreError::Io(e.to_string()))?;
            let fname = entry.file_name();
            let Some(fname_str) = fname.to_str() else {
                continue;
            };
            if fname_str.contains(".tmp.") {
                continue;
            }
            if let Some(ref_name) = Self::decode_ref_filename(fname_str) {
                let bytes =
                    std::fs::read(entry.path()).map_err(|e| StoreError::Io(e.to_string()))?;
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    out.insert(ref_name, ChangesetId::from_hash(ObjectHash(arr)));
                }
            }
        }
        Ok(out)
    }

    fn cas_ref(
        &self,
        ref_name: &str,
        expected: Option<ChangesetId>,
        new_target: ChangesetId,
    ) -> Result<(), StoreError> {
        let _guard = self.lock.write().expect("FsMetadataStore lock poisoned");
        let refs_lock_path = self.root.join("refs").join(".cas.lock");
        let refs_lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&refs_lock_path)
            .map_err(|e| StoreError::Io(format!("open ref CAS lock: {e}")))?;
        refs_lock
            .lock()
            .map_err(|e| StoreError::Io(format!("lock refs for CAS: {e}")))?;
        if !self.changeset_path(&new_target).exists() {
            return Err(StoreError::UnknownChangeset(new_target));
        }
        let target = self.ref_path(ref_name);
        let actual = match std::fs::read(&target) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(ChangesetId::from_hash(ObjectHash(arr)))
            }
            Ok(bytes) => {
                return Err(StoreError::SnapshotCorrupted(format!(
                    "invalid ref file length {} for '{}'",
                    bytes.len(),
                    ref_name
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(StoreError::Io(e.to_string())),
        };

        if actual != expected {
            return Err(StoreError::CasMismatch {
                ref_name: ref_name.to_string(),
                expected,
                actual,
            });
        }

        self.atomic_write(&target, new_target.as_bytes())
    }

    fn put_derived_mapping(
        &self,
        changeset_id: ChangesetId,
        kind: DerivedDataKind,
        derived_hash: ObjectHash,
    ) -> Result<(), StoreError> {
        let _guard = self.lock.write().expect("FsMetadataStore lock poisoned");
        if !self.changeset_path(&changeset_id).exists() {
            return Err(StoreError::UnknownChangeset(changeset_id));
        }
        let target = self.derived_path(&changeset_id, kind);
        match std::fs::read(&target) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                let existing = ObjectHash(arr);
                if existing != derived_hash {
                    return Err(StoreError::ConflictingDerivedMapping {
                        changeset_id,
                        kind,
                        existing,
                        attempted: derived_hash,
                    });
                }
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Ok(bytes) => {
                return Err(StoreError::SnapshotCorrupted(format!(
                    "invalid derived mapping length {}",
                    bytes.len()
                )));
            }
            Err(e) => return Err(StoreError::Io(e.to_string())),
        }
        self.atomic_write(&target, derived_hash.as_bytes())
    }

    fn get_derived_mapping(
        &self,
        changeset_id: ChangesetId,
        kind: DerivedDataKind,
    ) -> Result<Option<ObjectHash>, StoreError> {
        let _guard = self.lock.read().expect("FsMetadataStore lock poisoned");
        let target = self.derived_path(&changeset_id, kind);
        match std::fs::read(&target) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(ObjectHash(arr)))
            }
            Ok(bytes) => Err(StoreError::SnapshotCorrupted(format!(
                "invalid derived mapping length {}",
                bytes.len()
            ))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::Io(e.to_string())),
        }
    }

    fn put_principal(&self, principal: &PrincipalRecord) -> Result<(), StoreError> {
        let _guard = self.lock.write().expect("FsMetadataStore lock poisoned");
        let target = self.principal_path(&principal.principal_email);
        self.atomic_write(&target, &principal.to_bytes())
    }

    fn get_principal(&self, principal_email: &str) -> Result<Option<PrincipalRecord>, StoreError> {
        let _guard = self.lock.read().expect("FsMetadataStore lock poisoned");
        let target = self.principal_path(principal_email);
        match std::fs::read(&target) {
            Ok(bytes) => Ok(Some(PrincipalRecord::from_bytes(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::Io(e.to_string())),
        }
    }

    fn list_principals(&self) -> Result<Vec<PrincipalRecord>, StoreError> {
        let _guard = self.lock.read().expect("FsMetadataStore lock poisoned");
        let mut out = Vec::new();
        let entries = std::fs::read_dir(self.root.join("principals"))
            .map_err(|e| StoreError::Io(e.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|e| StoreError::Io(e.to_string()))?;
            let fname = entry.file_name();
            if fname.to_string_lossy().contains(".tmp.") {
                continue;
            }
            let bytes = std::fs::read(entry.path()).map_err(|e| StoreError::Io(e.to_string()))?;
            out.push(PrincipalRecord::from_bytes(&bytes)?);
        }
        out.sort_by(|a, b| a.principal_email.cmp(&b.principal_email));
        Ok(out)
    }

    fn put_lease(&self, lease: &JitLeaseRecord) -> Result<(), StoreError> {
        let _guard = self.lock.write().expect("FsMetadataStore lock poisoned");
        let target = self.lease_path(&lease.lease_id);
        self.atomic_write(&target, &lease.to_bytes())
    }

    fn get_lease(&self, lease_id: &str) -> Result<Option<JitLeaseRecord>, StoreError> {
        let _guard = self.lock.read().expect("FsMetadataStore lock poisoned");
        let target = self.lease_path(lease_id);
        match std::fs::read(&target) {
            Ok(bytes) => Ok(Some(JitLeaseRecord::from_bytes(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::Io(e.to_string())),
        }
    }

    fn list_leases(&self, repo_filter: Option<&str>) -> Result<Vec<JitLeaseRecord>, StoreError> {
        let _guard = self.lock.read().expect("FsMetadataStore lock poisoned");
        let mut out = Vec::new();
        let entries = std::fs::read_dir(self.root.join("leases"))
            .map_err(|e| StoreError::Io(e.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|e| StoreError::Io(e.to_string()))?;
            let fname = entry.file_name();
            if fname.to_string_lossy().contains(".tmp.") {
                continue;
            }
            let bytes = std::fs::read(entry.path()).map_err(|e| StoreError::Io(e.to_string()))?;
            let lease = JitLeaseRecord::from_bytes(&bytes)?;
            if let Some(r) = repo_filter
                && !r.trim().is_empty()
                && lease.repo_id != r.trim()
            {
                continue;
            }
            out.push(lease);
        }
        out.sort_by(|a, b| a.lease_id.cmp(&b.lease_id));
        Ok(out)
    }
}
