//! Comprehensive contract tests for `inarch-store` (Iteration 2):
//! - Content-addressed integrity verification on put and get (detects corrupted bytes on disk/memory)
//! - `FsBlobStore` atomic sharded persistence and corruption refusal
//! - `TieredBlobStore` 3-tier read-through caching (Tier 1 daemon -> Tier 2 regional cache -> Tier 3 origin)
//! - Scion Strict Tiering anti-stampede invariant (Tier 2 outage refuses Tier 1 misses without hitting Tier 3)
//! - Daemon snapshot export/import warm-boot with cryptographic verification
//! - `MetadataStore` atomic Compare-And-Swap (`cas_ref`) lock-free ref updates and derived-data mapping idempotency

use std::collections::BTreeMap;
use std::sync::Arc;

use inarch_store::{
    BlobStore, DerivedDataKind, FsBlobStore, FsMetadataStore, MemBlobStore, MemMetadataStore,
    MetadataStore, StoreError, TieredBlobStore,
};
use inarch_types::bonsai::{BonsaiChangeset, FileChange, FileType};
use inarch_types::hash::{BlobId, ObjectDomain, ObjectHash};
use inarch_types::path::MPath;

#[test]
fn mem_blob_store_verifies_hash_on_put_and_roundtrips_objects() {
    let store = MemBlobStore::new();
    let payload = b"fn compute() -> u64 { 42 }\n";
    let valid_hash = ObjectHash::from_domain(ObjectDomain::Blob, payload);
    let wrong_hash = ObjectHash::from_domain(ObjectDomain::Blob, b"different-content");

    // Putting with a mismatched hash must be refused
    let err = store.put_object(ObjectDomain::Blob, wrong_hash, payload);
    assert_eq!(
        err,
        Err(StoreError::IntegrityMismatch {
            domain: ObjectDomain::Blob,
            expected: wrong_hash,
            actual: valid_hash,
        })
    );

    // Putting with valid hash succeeds and can be fetched back
    store
        .put_object(ObjectDomain::Blob, valid_hash, payload)
        .expect("valid put must succeed");
    assert!(store.has_object(ObjectDomain::Blob, &valid_hash).unwrap());
    assert_eq!(
        store.get_object(ObjectDomain::Blob, &valid_hash).unwrap(),
        Some(payload.to_vec())
    );

    // Domain isolation: same hash under a different domain is not present
    assert_eq!(
        store.get_object(ObjectDomain::Fsnode, &valid_hash).unwrap(),
        None
    );
}

#[test]
fn fs_blob_store_persists_sharded_files_and_detects_disk_corruption() {
    let temp_dir = std::env::temp_dir().join(format!(
        "velenza-inarch-fsstore-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&temp_dir);

    let store = FsBlobStore::new(&temp_dir).expect("create FsBlobStore");
    let payload = b"immutable content-addressed blob on disk";
    let hash = ObjectHash::from_domain(ObjectDomain::Blob, payload);

    store
        .put_object(ObjectDomain::Blob, hash, payload)
        .expect("write blob to disk");

    assert_eq!(
        store.get_object(ObjectDomain::Blob, &hash).unwrap(),
        Some(payload.to_vec())
    );

    // Simulate bit-rot / tampering on the underlying file on disk
    let object_path = store.object_path(ObjectDomain::Blob, &hash);
    std::fs::write(&object_path, b"corrupted bytes on disk").unwrap();

    let corrupted_read = store.get_object(ObjectDomain::Blob, &hash);
    assert!(
        matches!(
            corrupted_read,
            Err(StoreError::IntegrityMismatch {
                domain: ObjectDomain::Blob,
                expected,
                ..
            }) if expected == hash
        ),
        "FsBlobStore must verify BLAKE3 hash on read and refuse corrupted disk bytes"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn tiered_blob_store_backfills_caches_and_enforces_strict_tiering_anti_stampede() {
    let tier1_daemon = Arc::new(MemBlobStore::new());
    let tier2_regional = Arc::new(MemBlobStore::new());
    let tier3_origin = Arc::new(MemBlobStore::new());

    let tiered = TieredBlobStore::new(
        Arc::clone(&tier1_daemon),
        Arc::clone(&tier2_regional),
        Arc::clone(&tier3_origin),
    );

    let data_a = b"blob-a-in-origin";
    let hash_a = ObjectHash::from_domain(ObjectDomain::Blob, data_a);
    tier3_origin
        .put_object(ObjectDomain::Blob, hash_a, data_a)
        .unwrap();

    // 1st read: misses Tier 1 and Tier 2, hits Tier 3, backfills Tier 2 and Tier 1
    let fetched = tiered
        .get_object(ObjectDomain::Blob, &hash_a)
        .unwrap()
        .expect("must fetch from origin");
    assert_eq!(fetched, data_a);

    let stats1 = tiered.stats();
    assert_eq!(stats1.tier1_hits, 0);
    assert_eq!(stats1.tier1_misses, 1);
    assert_eq!(stats1.tier2_hits, 0);
    assert_eq!(stats1.tier2_misses, 1);
    assert_eq!(stats1.tier3_hits, 1);

    // 2nd read: hits Tier 1 directly without touching Tier 2 or Tier 3
    let fetched_again = tiered
        .get_object(ObjectDomain::Blob, &hash_a)
        .unwrap()
        .unwrap();
    assert_eq!(fetched_again, data_a);
    let stats2 = tiered.stats();
    assert_eq!(stats2.tier1_hits, 1);
    assert_eq!(stats2.tier2_misses, 1);
    assert_eq!(stats2.tier3_hits, 1);

    // Strict tiering test: put blob_b in Tier 3 only, mark Tier 2 offline, and verify Tier 1 miss
    // fails closed WITHOUT querying Tier 3 (preventing an origin stampede!)
    let data_b = b"blob-b-only-in-origin";
    let hash_b = ObjectHash::from_domain(ObjectDomain::Blob, data_b);
    tier3_origin
        .put_object(ObjectDomain::Blob, hash_b, data_b)
        .unwrap();

    tiered.set_tier2_available(false);
    let res = tiered.get_object(ObjectDomain::Blob, &hash_b);
    assert_eq!(
        res,
        Err(StoreError::TierUnavailable(
            "tier2 (inarch-cache)".to_string()
        ))
    );

    // Verify Tier 3 was NEVER hit during the Tier 2 outage!
    let stats3 = tiered.stats();
    assert_eq!(
        stats3.tier3_hits, 1,
        "strict tiering must never bypass an unavailable Tier 2 to hit Tier 3 origin"
    );
    assert_eq!(stats3.tier3_misses, 0);

    // However, objects already cached in Tier 1 (`hash_a`) continue serving locally even when Tier 2 is down!
    assert_eq!(
        tiered
            .get_object(ObjectDomain::Blob, &hash_a)
            .unwrap()
            .as_deref(),
        Some(&data_a[..])
    );
    assert_eq!(tiered.has_object(ObjectDomain::Blob, &hash_a), Ok(true));
    assert_eq!(
        tiered.has_object(ObjectDomain::Blob, &hash_b),
        Err(StoreError::TierUnavailable(
            "tier2 (inarch-cache)".to_string()
        ))
    );
    assert_eq!(
        tiered.has_objects_batch(&[(ObjectDomain::Blob, hash_a), (ObjectDomain::Blob, hash_b)]),
        Err(StoreError::TierUnavailable(
            "tier2 (inarch-cache)".to_string()
        ))
    );
}

#[test]
fn daemon_cache_snapshot_export_and_import_warm_boots_with_integrity_verification() {
    let source_cache = MemBlobStore::new();
    let b1 = b"snapshot-object-1";
    let h1 = ObjectHash::from_domain(ObjectDomain::Blob, b1);
    let b2 = b"snapshot-fsnode-2";
    let h2 = ObjectHash::from_domain(ObjectDomain::Fsnode, b2);

    source_cache.put_object(ObjectDomain::Blob, h1, b1).unwrap();
    source_cache
        .put_object(ObjectDomain::Fsnode, h2, b2)
        .unwrap();

    let snapshot_bytes = source_cache.export_snapshot();

    let cold_daemon = MemBlobStore::new();
    let imported_count = cold_daemon
        .import_snapshot(&snapshot_bytes)
        .expect("valid snapshot must import cleanly");
    assert_eq!(imported_count, 2);
    assert_eq!(
        cold_daemon.get_object(ObjectDomain::Blob, &h1).unwrap(),
        Some(b1.to_vec())
    );
    assert_eq!(
        cold_daemon.get_object(ObjectDomain::Fsnode, &h2).unwrap(),
        Some(b2.to_vec())
    );
}

#[test]
fn metadata_store_enforces_atomic_cas_on_refs_and_idempotent_derived_mappings() {
    let meta = MemMetadataStore::new();

    let blob_id = BlobId::from_content(b"hello world");
    let mut changes = BTreeMap::new();
    changes.insert(
        MPath::new("README.md").unwrap(),
        FileChange::Tracked {
            blob_id,
            size: 11,
            file_type: FileType::Regular,
        },
    );

    let cs1 = BonsaiChangeset::new(
        vec![],
        "founder@inarch.dev".into(),
        1_760_000_000,
        0,
        "initial commit".into(),
        BTreeMap::new(),
        changes.clone(),
    )
    .unwrap();
    let cs1_id = cs1.changeset_id();

    let cs2 = BonsaiChangeset::new(
        vec![cs1_id],
        "agent@inarch.dev".into(),
        1_760_000_010,
        0,
        "second commit".into(),
        BTreeMap::new(),
        changes,
    )
    .unwrap();
    let cs2_id = cs2.changeset_id();

    // Cannot CAS a ref to a ChangesetId that has not been stored in MetadataStore
    assert_eq!(
        meta.cas_ref("main", None, cs1_id),
        Err(StoreError::UnknownChangeset(cs1_id))
    );

    meta.put_changeset(&cs1).unwrap();
    meta.put_changeset(&cs2).unwrap();

    // Initial creation of `main` with expected = None succeeds
    meta.cas_ref("main", None, cs1_id)
        .expect("initial CAS from None -> cs1_id must succeed");
    assert_eq!(meta.get_ref("main").unwrap(), Some(cs1_id));

    // Stale CAS attempt expecting `None` when `main` is already at `cs1_id` must fail with CasMismatch
    assert_eq!(
        meta.cas_ref("main", None, cs2_id),
        Err(StoreError::CasMismatch {
            ref_name: "main".to_string(),
            expected: None,
            actual: Some(cs1_id),
        })
    );

    // Advancing `main` with expected = Some(cs1_id) -> cs2_id succeeds atomically
    meta.cas_ref("main", Some(cs1_id), cs2_id)
        .expect("CAS from cs1_id -> cs2_id must succeed");
    assert_eq!(meta.get_ref("main").unwrap(), Some(cs2_id));

    // Derived data mappings are idempotent for identical hashes and refuse conflicting hashes
    let fsnode_hash_1 = ObjectHash::from_domain(ObjectDomain::Fsnode, b"fsnode-1");
    let fsnode_hash_2 = ObjectHash::from_domain(ObjectDomain::Fsnode, b"fsnode-2");

    meta.put_derived_mapping(cs1_id, DerivedDataKind::Fsnode, fsnode_hash_1)
        .unwrap();
    // Idempotent repeat put succeeds
    meta.put_derived_mapping(cs1_id, DerivedDataKind::Fsnode, fsnode_hash_1)
        .unwrap();
    assert_eq!(
        meta.get_derived_mapping(cs1_id, DerivedDataKind::Fsnode)
            .unwrap(),
        Some(fsnode_hash_1)
    );

    // Conflicting derived mapping for the same (cs_id, kind) is refused
    assert_eq!(
        meta.put_derived_mapping(cs1_id, DerivedDataKind::Fsnode, fsnode_hash_2),
        Err(StoreError::ConflictingDerivedMapping {
            changeset_id: cs1_id,
            kind: DerivedDataKind::Fsnode,
            existing: fsnode_hash_1,
            attempted: fsnode_hash_2,
        })
    );
}

#[test]
fn blob_store_chunked_blob_helper_deduplicates_chunks_and_reassembles_files() {
    let store = MemBlobStore::new();
    let mut payload = vec![0u8; 64 * 1024];
    let mut state = 0xCAFE_BABE_1234_5678u64;
    for byte in &mut payload {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state & 0xFF) as u8;
    }

    let blob_id = store
        .put_blob_content(&payload)
        .expect("put_blob_content must chunk and store blob");
    assert_eq!(blob_id, BlobId::from_content(&payload));

    let roundtripped = store
        .get_blob_content(&blob_id)
        .expect("get_blob_content must succeed")
        .expect("blob must exist");
    assert_eq!(roundtripped, payload);
}

#[test]
fn fs_metadata_store_persists_changesets_refs_and_derived_mappings_across_reopen() {
    let dir =
        std::env::temp_dir().join(format!("velenza-inarch-fsmeta-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let blob_id = BlobId::from_content(b"fn main() {}\n");
    let mut changes = BTreeMap::new();
    changes.insert(
        MPath::new("src/main.rs").unwrap(),
        FileChange::Tracked {
            blob_id,
            size: 13,
            file_type: FileType::Regular,
        },
    );
    let cs = BonsaiChangeset::new(
        vec![],
        "persist@inarch.dev".into(),
        1_760_800_000,
        0,
        "persistent commit".into(),
        BTreeMap::new(),
        changes,
    )
    .unwrap();
    let cs_id = cs.changeset_id();
    let fsnode_hash = ObjectHash::from_domain(ObjectDomain::Fsnode, b"persistent-fsnode");

    {
        let meta = FsMetadataStore::new(&dir).expect("create FsMetadataStore");
        meta.put_changeset(&cs).expect("persist changeset");
        meta.cas_ref("main", None, cs_id)
            .expect("persist CAS ref main");
        meta.put_derived_mapping(cs_id, DerivedDataKind::Fsnode, fsnode_hash)
            .expect("persist derived mapping");
    }

    // Reopen from cold disk directory
    let reopened = FsMetadataStore::new(&dir).expect("reopen FsMetadataStore");
    assert_eq!(reopened.get_changeset(&cs_id).unwrap(), Some(cs));
    assert_eq!(reopened.get_ref("main").unwrap(), Some(cs_id));
    assert_eq!(
        reopened
            .get_derived_mapping(cs_id, DerivedDataKind::Fsnode)
            .unwrap(),
        Some(fsnode_hash)
    );

    let _ = std::fs::remove_dir_all(&dir);
}
