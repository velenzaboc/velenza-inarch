//! Comprehensive contract tests for `inarch-types` (Slice 1 & Slice 2):
//! - Official BLAKE3 256-bit hashing (empty, single-block, multi-block, multi-chunk >1024B)
//! - Domain separation across object kinds (BlobId, ChunkId, ChangesetId, FsnodeId, UnodeFileId, UnodeManifestId)
//! - Hex encoding/decoding and malformed hex rejection
//! - Validated canonical repository paths (`MPathElement`, `MPath`) and prefix conflict detection
//! - Content-Defined Chunking (`FastCdcChunker`) boundaries, shift-resilience, and lossless reassembly
//! - Tree-Free `BonsaiChangeset` validation, canonical binary serialization round-trip, and O(Delta) conflict detection

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use inarch_types::bonsai::{BonsaiChangeset, BonsaiError, FileChange, FileType};
use inarch_types::cdc::{CdcConfig, FastCdcChunker};
use inarch_types::hash::{
    BlobId, ChangesetId, ChunkId, FsnodeId, HashError, ObjectDomain, ObjectHash, UnodeFileId,
    UnodeManifestId, blake3_hash,
};
use inarch_types::path::{MPath, MPathElement, PathError};

// ============================================================================
// 1. BLAKE3 & Domain-Separated Content-Addressed Hashes
// ============================================================================

#[test]
fn blake3_matches_official_specification_test_vectors() {
    // Official BLAKE3 test vector for empty input (len = 0)
    let empty_hash = blake3_hash(b"");
    assert_eq!(
        empty_hash.to_hex(),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        "empty input must match official BLAKE3 specification vector"
    );

    // Official BLAKE3 test vector for len = 1 (0x00) with repeating 0..251 pattern
    let one_byte = [0u8; 1];
    assert_eq!(
        blake3_hash(&one_byte).to_hex(),
        "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        "1-byte [0x00] input must match official BLAKE3 test vector"
    );

    // Official BLAKE3 test vector for 64 bytes (exact 1 block) of 0, 1, 2, ... 63
    let input_64: Vec<u8> = (0..64).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        blake3_hash(&input_64).to_hex(),
        "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
        "64-byte single-block input must match official BLAKE3 test vector"
    );

    // Official BLAKE3 test vector for 65 bytes (2 blocks in 1 chunk)
    let input_65: Vec<u8> = (0..65).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        blake3_hash(&input_65).to_hex(),
        "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
        "65-byte multi-block input must match BLAKE3 compression output"
    );

    // Multi-chunk Merkle boundary invariance: 1024 bytes (1 chunk) vs 1025 bytes (2 chunks)
    let input_1024: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
    let input_1025: Vec<u8> = (0..1025).map(|i| (i % 251) as u8).collect();
    let hash_1024 = blake3_hash(&input_1024);
    let hash_1025 = blake3_hash(&input_1025);
    assert_ne!(hash_1024, hash_1025);

    // Streaming split-invariance across multi-level Merkle tree (5000 bytes > 4 chunks)
    let input_5000: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
    let oneshot_5000 = blake3_hash(&input_5000);
    for step in [1usize, 3, 7, 63, 64, 65, 512, 1023, 1024, 1025] {
        let mut streaming = inarch_types::hash::Blake3Hasher::new();
        for piece in input_5000.chunks(step) {
            streaming.update(piece);
        }
        assert_eq!(
            streaming.finalize(),
            oneshot_5000,
            "streaming BLAKE3 with chunk size {step} must equal one-shot hash across 5000-byte Merkle tree"
        );
    }

    // Avalanche check: flipping 1 bit in chunk 3 of a 5000-byte input changes ~50% of output bits
    let mut flipped_5000 = input_5000.clone();
    flipped_5000[2500] ^= 0x01;
    let flipped_hash = blake3_hash(&flipped_5000);
    let differing_bits: u32 = oneshot_5000
        .as_bytes()
        .iter()
        .zip(flipped_hash.as_bytes().iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum();
    assert!(
        (90..=166).contains(&differing_bits),
        "expected strong avalanche (~128 of 256 bits changed), got {differing_bits}"
    );
}

#[test]
fn domain_separation_prevents_cross_type_hash_collisions() {
    let payload = b"identical-raw-bytes-across-domains";

    let blob_id = BlobId::from_content(payload);
    let chunk_id = ChunkId::from_content(payload);
    let cs_id = ChangesetId::from_canonical_bytes(payload);
    let fsnode_id = FsnodeId::from_canonical_bytes(payload);
    let unode_file_id = UnodeFileId::from_canonical_bytes(payload);
    let unode_manifest_id = UnodeManifestId::from_canonical_bytes(payload);

    let hashes = [
        *blob_id.as_hash(),
        *chunk_id.as_hash(),
        *cs_id.as_hash(),
        *fsnode_id.as_hash(),
        *unode_file_id.as_hash(),
        *unode_manifest_id.as_hash(),
    ];

    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(
                hashes[i], hashes[j],
                "domain-separated hashes at indices {} and {} must never collide for identical payload",
                i, j
            );
        }
    }

    // Also verify determinism
    assert_eq!(blob_id, BlobId::from_content(payload));
    assert_eq!(
        ObjectHash::from_domain(ObjectDomain::Blob, payload),
        *blob_id.as_hash()
    );
}

#[test]
fn object_hash_hex_roundtrip_and_invalid_input_refusal() {
    let orig = blake3_hash(b"inarch-hash-test");
    let hex_str = orig.to_hex();
    assert_eq!(hex_str.len(), 64);

    let parsed = ObjectHash::from_hex(&hex_str).expect("valid 64-char hex must parse");
    assert_eq!(orig, parsed);

    // Uppercase hex should also parse cleanly and normalize to identical bytes
    let upper = hex_str.to_uppercase();
    let parsed_upper = ObjectHash::from_hex(&upper).expect("uppercase hex must parse");
    assert_eq!(orig, parsed_upper);

    // Refusal cases
    assert_eq!(
        ObjectHash::from_hex(""),
        Err(HashError::InvalidHexLength(0))
    );
    assert_eq!(
        ObjectHash::from_hex("abcd"),
        Err(HashError::InvalidHexLength(4))
    );
    assert!(matches!(
        ObjectHash::from_hex(&"z".repeat(64)),
        Err(HashError::InvalidHexCharacter { index: 0, .. })
    ));
}

// ============================================================================
// 2. Canonical Validated Repository Paths (`MPathElement`, `MPath`)
// ============================================================================

#[test]
fn mpath_validates_and_normalizes_canonical_paths() {
    let path = MPath::new("crates/inarch-types/src/lib.rs").expect("valid relative path");
    assert_eq!(path.as_str(), "crates/inarch-types/src/lib.rs");
    assert_eq!(path.depth(), 4);
    assert_eq!(path.basename().map(MPathElement::as_str), Some("lib.rs"));
    assert_eq!(
        path.parent().as_ref().map(MPath::as_str),
        Some("crates/inarch-types/src")
    );

    let (first, rest) = path.split_first();
    assert_eq!(first.as_str(), "crates");
    assert_eq!(
        rest.expect("has remainder").as_str(),
        "inarch-types/src/lib.rs"
    );

    // Single-element path has parent == None
    let single = MPath::new("README.md").expect("valid single-element path");
    assert_eq!(single.depth(), 1);
    assert!(single.parent().is_none());
    let (first_single, rest_single) = single.split_first();
    assert_eq!(first_single.as_str(), "README.md");
    assert!(rest_single.is_none());
}

#[test]
fn mpath_refuses_traversal_absolute_empty_and_nul_inputs() {
    assert_eq!(MPath::new(""), Err(PathError::EmptyPath));
    assert_eq!(MPath::new("/leading/slash"), Err(PathError::LeadingSlash));
    assert_eq!(MPath::new("trailing/slash/"), Err(PathError::TrailingSlash));
    assert_eq!(MPath::new("double//slash"), Err(PathError::EmptyComponent));
    assert_eq!(MPath::new("src/./lib.rs"), Err(PathError::DotComponent));
    assert_eq!(
        MPath::new("src/../secret.rs"),
        Err(PathError::DotDotComponent)
    );
    assert_eq!(MPath::new("."), Err(PathError::DotComponent));
    assert_eq!(MPath::new(".."), Err(PathError::DotDotComponent));
    assert_eq!(MPath::new("bad\0name/file.rs"), Err(PathError::NulByte));
    assert_eq!(
        MPathElement::new("has/slash"),
        Err(PathError::SlashInElement)
    );
}

#[test]
fn mpath_prefix_and_file_directory_conflict_detection() {
    let dir_a = MPath::new("src/engine").unwrap();
    let file_in_a = MPath::new("src/engine/merge.rs").unwrap();
    let sibling = MPath::new("src/engine_v2/merge.rs").unwrap();

    // Prefix checks must be component-aware, NOT naive string prefix!
    assert!(dir_a.is_prefix_of(&dir_a), "path is prefix of itself");
    assert!(
        dir_a.is_prefix_of(&file_in_a),
        "src/engine is a component prefix of src/engine/merge.rs"
    );
    assert!(
        !dir_a.is_prefix_of(&sibling),
        "src/engine must NOT be treated as a prefix of src/engine_v2/merge.rs"
    );
    assert!(
        dir_a.is_strict_prefix_of(&file_in_a),
        "src/engine is a strict prefix of src/engine/merge.rs"
    );
    assert!(
        !dir_a.is_strict_prefix_of(&dir_a),
        "path is not a strict prefix of itself"
    );
}

// ============================================================================
// 3. Content-Defined Chunking (FastCDC)
// ============================================================================

#[test]
fn fastcdc_chunks_data_within_configured_bounds_and_reassembles_losslessly() {
    let config = CdcConfig {
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
    };
    let chunker = FastCdcChunker::new(config).expect("valid CDC config");

    // Generate 32 KiB of deterministic pseudo-random data
    let mut data = Vec::with_capacity(32 * 1024);
    let mut state: u64 = 0x1234_5678_9ABC_DEF0;
    for _ in 0..(32 * 1024) {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        data.push((state >> 32) as u8);
    }

    let chunks = chunker.chunk(&data);
    assert!(
        chunks.len() > 8,
        "32 KiB stream with 1 KiB avg should produce multiple content-defined chunks, got {}",
        chunks.len()
    );

    // Every non-final chunk must obey [min_size, max_size]
    for (idx, chunk) in chunks.iter().enumerate() {
        if idx + 1 < chunks.len() {
            assert!(
                chunk.data.len() >= config.min_size && chunk.data.len() <= config.max_size,
                "chunk {} length {} outside [{}, {}]",
                idx,
                chunk.data.len(),
                config.min_size,
                config.max_size
            );
        } else {
            assert!(chunk.data.len() <= config.max_size);
        }
    }

    // Reassembled bytes and manifest hash must match original data
    let manifest = chunker.build_manifest(&data, &chunks);
    assert_eq!(manifest.total_size, data.len() as u64);
    assert_eq!(manifest.blob_id, BlobId::from_content(&data));

    let reassembled = FastCdcChunker::reassemble(&manifest, |chunk_id| {
        chunks
            .iter()
            .find(|c| c.id == *chunk_id)
            .map(|c| c.data.clone())
    })
    .expect("reassembly must succeed and verify BlobId");
    assert_eq!(reassembled, data);
}

#[test]
fn fastcdc_is_shift_resilient_under_prefix_insertion() {
    let config = CdcConfig {
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
    };
    let chunker = FastCdcChunker::new(config).unwrap();

    let mut original = Vec::with_capacity(64 * 1024);
    let mut state: u64 = 0xCAFE_BABE_DEAD_BEEF;
    for _ in 0..(64 * 1024) {
        state = state
            .wrapping_mul(2862933555777941757)
            .wrapping_add(3037000493);
        original.push((state >> 24) as u8);
    }

    // Insert 137 bytes at the beginning of the file
    let mut modified = vec![0xAAu8; 137];
    modified.extend_from_slice(&original);

    let orig_chunks = chunker.chunk(&original);
    let mod_chunks = chunker.chunk(&modified);

    let orig_ids: std::collections::BTreeSet<ChunkId> = orig_chunks.iter().map(|c| c.id).collect();
    let shared_count = mod_chunks
        .iter()
        .filter(|c| orig_ids.contains(&c.id))
        .count();

    // After the first chunk or two resynchronizes, all remaining chunks must be identical!
    assert!(
        shared_count + 3 >= orig_chunks.len(),
        "FastCDC must resynchronize after prefix insertion: shared {} of {} original chunks",
        shared_count,
        orig_chunks.len()
    );
}

// ============================================================================
// 4. Tree-Free Bonsai Changesets (O(Delta) Commits & Conflict Detection)
// ============================================================================

#[test]
fn bonsai_changeset_canonical_roundtrip_and_deterministic_id() {
    let p1 = ChangesetId::from_canonical_bytes(b"parent-1");
    let blob_a = BlobId::from_content(b"fn main() {}\n");

    let mut file_changes = BTreeMap::new();
    file_changes.insert(
        MPath::new("src/main.rs").unwrap(),
        FileChange::Tracked {
            blob_id: blob_a,
            size: 13,
            file_type: FileType::Regular,
        },
    );
    file_changes.insert(MPath::new("legacy/old.rs").unwrap(), FileChange::Deleted);

    let mut extra = BTreeMap::new();
    extra.insert("agent_id".to_string(), b"agent-worker-42".to_vec());

    let cs = BonsaiChangeset::new(
        vec![p1],
        "agent@inarch.dev".to_string(),
        1_760_580_000,
        0,
        "Implement entry point and remove legacy file".to_string(),
        extra,
        file_changes,
    )
    .expect("valid BonsaiChangeset");

    let cs_id = cs.changeset_id();
    let encoded = cs.to_canonical_bytes();
    let decoded =
        BonsaiChangeset::from_canonical_bytes(&encoded).expect("canonical bytes must decode");

    assert_eq!(cs, decoded);
    assert_eq!(cs_id, decoded.changeset_id());
}

#[test]
fn bonsai_changeset_refuses_internal_file_directory_conflicts_and_duplicate_parents() {
    let p1 = ChangesetId::from_canonical_bytes(b"parent-1");
    let blob = BlobId::from_content(b"content");

    // Duplicate parent refusal
    let dup_err = BonsaiChangeset::new(
        vec![p1, p1],
        "author".to_string(),
        1000,
        0,
        "msg".to_string(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    assert_eq!(dup_err, Err(BonsaiError::DuplicateParent(p1)));

    // File vs directory conflict: `src/app` is Tracked AND `src/app/mod.rs` is Tracked
    let mut conflicting_changes = BTreeMap::new();
    conflicting_changes.insert(
        MPath::new("src/app").unwrap(),
        FileChange::Tracked {
            blob_id: blob,
            size: 7,
            file_type: FileType::Regular,
        },
    );
    conflicting_changes.insert(
        MPath::new("src/app/mod.rs").unwrap(),
        FileChange::Tracked {
            blob_id: blob,
            size: 7,
            file_type: FileType::Regular,
        },
    );

    let conflict_err = BonsaiChangeset::new(
        vec![p1],
        "author".to_string(),
        1000,
        0,
        "msg".to_string(),
        BTreeMap::new(),
        conflicting_changes,
    );
    assert_eq!(
        conflict_err,
        Err(BonsaiError::PathPrefixConflict {
            prefix: MPath::new("src/app").unwrap(),
            descendant: MPath::new("src/app/mod.rs").unwrap(),
        })
    );
}

/// A tracked regular file at `path` for the validate tests below.
fn tracked_entry(path: &str, blob: BlobId) -> (MPath, FileChange) {
    (
        MPath::new(path).expect("valid test path"),
        FileChange::Tracked {
            blob_id: blob,
            size: 12,
            file_type: FileType::Regular,
        },
    )
}

fn changeset_with(changes: BTreeMap<MPath, FileChange>) -> Result<BonsaiChangeset, BonsaiError> {
    BonsaiChangeset::new(
        vec![ChangesetId::from_canonical_bytes(b"validate-parent")],
        "validate@example.com".to_string(),
        1_761_500_000,
        0,
        "validate".to_string(),
        BTreeMap::new(),
        changes,
    )
}

#[test]
fn bonsai_validate_reports_prefix_conflicts_at_any_depth_in_sorted_order() {
    let blob = BlobId::from_content(b"depth");
    // `a/b` is tracked as a file three directory levels above a tracked descendant. The
    // sibling `a/b-x` and the unrelated `z/last.rs` must not take part in the report. Paths
    // order component-wise, so `a/b/c/d/e.rs` sorts before `a/b-x`, directly after `a/b`.
    let changes: BTreeMap<MPath, FileChange> = [
        tracked_entry("z/last.rs", blob),
        tracked_entry("a/b/c/d/e.rs", blob),
        tracked_entry("a/b-x", blob),
        tracked_entry("a/b", blob),
    ]
    .into_iter()
    .collect();

    assert_eq!(
        changeset_with(changes),
        Err(BonsaiError::PathPrefixConflict {
            prefix: MPath::new("a/b").unwrap(),
            descendant: MPath::new("a/b/c/d/e.rs").unwrap(),
        }),
        "a tracked file that is a strict directory prefix of a deeper tracked path is a conflict"
    );
}

#[test]
fn bonsai_validate_compares_whole_path_components_not_string_prefixes() {
    let blob = BlobId::from_content(b"components");
    // Every name below shares the string prefix `src/app` with `src/app`, yet none is inside it.
    let changes: BTreeMap<MPath, FileChange> = [
        tracked_entry("src/app", blob),
        tracked_entry("src/app.rs", blob),
        tracked_entry("src/apple/mod.rs", blob),
        tracked_entry("src/app-legacy/mod.rs", blob),
    ]
    .into_iter()
    .collect();

    let cs = changeset_with(changes)
        .expect("names that merely share a string prefix with a tracked file must not conflict");
    assert_eq!(cs.validate(), Ok(()));
    assert_eq!(cs.file_changes.len(), 4);
}

#[test]
fn bonsai_validate_ignores_deleted_entries_as_prefixes_and_descendants() {
    let blob = BlobId::from_content(b"deleted");

    // A deletion at the directory name beside a tracked descendant is fine.
    let mut deleted_prefix = BTreeMap::new();
    deleted_prefix.insert(MPath::new("src/app").unwrap(), FileChange::Deleted);
    deleted_prefix.extend([tracked_entry("src/app/mod.rs", blob)]);
    assert_eq!(
        changeset_with(deleted_prefix).map(|cs| cs.file_changes.len()),
        Ok(2),
        "a Deleted entry is never a conflicting prefix"
    );

    // A tracked file beside a deletion below it is fine too.
    let mut deleted_descendant = BTreeMap::new();
    deleted_descendant.extend([tracked_entry("lib/core", blob)]);
    deleted_descendant.insert(MPath::new("lib/core/old.rs").unwrap(), FileChange::Deleted);
    assert_eq!(
        changeset_with(deleted_descendant).map(|cs| cs.file_changes.len()),
        Ok(2),
        "a Deleted entry is never a conflicting descendant"
    );

    // Control: the same two paths both tracked do conflict.
    let both_tracked: BTreeMap<MPath, FileChange> = [
        tracked_entry("lib/core", blob),
        tracked_entry("lib/core/old.rs", blob),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        changeset_with(both_tracked),
        Err(BonsaiError::PathPrefixConflict {
            prefix: MPath::new("lib/core").unwrap(),
            descendant: MPath::new("lib/core/old.rs").unwrap(),
        })
    );
}

#[test]
fn bonsai_validate_and_canonical_round_trip_scale_to_fifty_thousand_paths() {
    const FILES: usize = 50_000;
    const DIRS: usize = 1_000;
    const BUDGET: Duration = Duration::from_secs(5);
    let blob = BlobId::from_content(b"module body\n");

    let mut changes = BTreeMap::new();
    for i in 0..FILES {
        let (path, change) = tracked_entry(
            &format!("services/svc-{:04}/mod_{:05}.rs", i % DIRS, i),
            blob,
        );
        changes.insert(path, change);
    }

    let started = Instant::now();
    let cs = BonsaiChangeset::new(
        Vec::new(),
        "wide@example.com".to_string(),
        1_761_500_001,
        0,
        "wide root".to_string(),
        BTreeMap::new(),
        changes,
    )
    .expect("50000 path-disjoint tracked files are a valid changeset");
    let bytes = cs.to_canonical_bytes();
    let decoded =
        BonsaiChangeset::from_canonical_bytes(&bytes).expect("canonical bytes must decode");
    let elapsed = started.elapsed();

    assert_eq!(decoded.file_changes.len(), FILES);
    assert_eq!(decoded.changeset_id(), cs.changeset_id());
    assert!(
        elapsed < BUDGET,
        "validate + canonical round trip of {FILES} paths took {elapsed:?} (budget {BUDGET:?}); \
         the prefix-conflict check must not be quadratic in the number of tracked paths"
    );

    // A directory name tracked as a file among the 50000 paths is reported against its first
    // descendant in sorted order, and finding it costs no more than the valid case did.
    let mut conflicting = cs.file_changes.clone();
    conflicting.extend([tracked_entry("services/svc-0007", blob)]);
    let started = Instant::now();
    let err = BonsaiChangeset::new(
        Vec::new(),
        "wide@example.com".to_string(),
        1_761_500_001,
        0,
        "wide root with a file at a directory name".to_string(),
        BTreeMap::new(),
        conflicting,
    );
    let elapsed = started.elapsed();
    assert_eq!(
        err,
        Err(BonsaiError::PathPrefixConflict {
            prefix: MPath::new("services/svc-0007").unwrap(),
            descendant: MPath::new("services/svc-0007/mod_00007.rs").unwrap(),
        })
    );
    assert!(
        elapsed < BUDGET,
        "reporting one conflict among {FILES} paths took {elapsed:?} (budget {BUDGET:?})"
    );
}

#[test]
fn bonsai_changeset_detects_disjoint_vs_conflicting_deltas_in_o_delta() {
    let base = ChangesetId::from_canonical_bytes(b"base");
    let blob1 = BlobId::from_content(b"v1");
    let blob2 = BlobId::from_content(b"v2");

    let mut changes_a = BTreeMap::new();
    changes_a.insert(
        MPath::new("services/auth/login.rs").unwrap(),
        FileChange::Tracked {
            blob_id: blob1,
            size: 2,
            file_type: FileType::Regular,
        },
    );

    let mut changes_b_disjoint = BTreeMap::new();
    changes_b_disjoint.insert(
        MPath::new("services/billing/invoice.rs").unwrap(),
        FileChange::Tracked {
            blob_id: blob2,
            size: 2,
            file_type: FileType::Regular,
        },
    );

    let mut changes_c_exact_conflict = BTreeMap::new();
    changes_c_exact_conflict.insert(
        MPath::new("services/auth/login.rs").unwrap(),
        FileChange::Tracked {
            blob_id: blob2,
            size: 2,
            file_type: FileType::Regular,
        },
    );

    let mut changes_d_prefix_conflict = BTreeMap::new();
    changes_d_prefix_conflict.insert(
        MPath::new("services/auth").unwrap(),
        FileChange::Tracked {
            blob_id: blob2,
            size: 2,
            file_type: FileType::Regular,
        },
    );

    let cs_a = BonsaiChangeset::new(
        vec![base],
        "agent-a".into(),
        100,
        0,
        "a".into(),
        BTreeMap::new(),
        changes_a,
    )
    .unwrap();
    let cs_b = BonsaiChangeset::new(
        vec![base],
        "agent-b".into(),
        101,
        0,
        "b".into(),
        BTreeMap::new(),
        changes_b_disjoint,
    )
    .unwrap();
    let cs_c = BonsaiChangeset::new(
        vec![base],
        "agent-c".into(),
        102,
        0,
        "c".into(),
        BTreeMap::new(),
        changes_c_exact_conflict,
    )
    .unwrap();
    let cs_d = BonsaiChangeset::new(
        vec![base],
        "agent-d".into(),
        103,
        0,
        "d".into(),
        BTreeMap::new(),
        changes_d_prefix_conflict,
    )
    .unwrap();

    assert!(
        cs_a.conflicting_paths(&cs_b).is_empty(),
        "disjoint paths must have zero conflict"
    );
    assert_eq!(
        cs_a.conflicting_paths(&cs_c),
        vec![MPath::new("services/auth/login.rs").unwrap()],
        "identical modified path must be reported as conflict"
    );
    assert_eq!(
        cs_a.conflicting_paths(&cs_d),
        vec![MPath::new("services/auth/login.rs").unwrap()],
        "file-vs-directory prefix collision across changesets must be reported as conflict"
    );
}
