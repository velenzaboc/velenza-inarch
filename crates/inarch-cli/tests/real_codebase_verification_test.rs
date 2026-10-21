//! End-to-End Real Codebase Verification Tests for Velenza Inarch (`inarch-cli`).
//!
//! Validates 100% data accuracy across:
//! 1. Self-hosting the entire real `velenza-inarch` multi-crate Rust repository from disk into
//!    persistent storage (`FsBlobStore` + `FsMetadataStore`).
//! 2. Cold-process reopen from disk (zero in-memory state) followed by full byte-for-byte
//!    and BLAKE3 verification of every file via checkout-free `read_file` and `Fsnode` traversal.
//! 3. Full and sparse `checkout_stateless` materialization to disk with 100% byte-for-byte
//!    identity against the original source tree.
//! 4. Multi-commit codebase evolution with executable permissions (`0o755`), symbolic links,
//!    multi-chunk binary files (150 KiB FastCDC), incremental delta detection (add/modify/delete),
//!    and exact revision time-travel checkouts.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use inarch_cli::{checkout_stateless, ingest_directory, verify_codebase_accuracy};
use inarch_engine::{ChangeKind, ScionEngine};
use inarch_store::{FsBlobStore, FsMetadataStore, MemBlobStore, TieredBlobStore};
use inarch_types::path::MPath;

#[test]
fn self_hosts_entire_velenza_inarch_codebase_with_100_percent_byte_and_hash_accuracy() {
    // Locate the real `velenza-inarch` workspace root on disk
    let manifest_dir_str = std::env::var("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string());
    let manifest_dir = Path::new(&manifest_dir_str);
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("locate velenza-inarch workspace root");

    let test_dir = std::env::temp_dir().join(format!(
        "velenza-inarch-selfhost-verify-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&test_dir);
    let blobs_dir = test_dir.join("store/blobs");
    let meta_dir = test_dir.join("store/meta");
    let checkout_dir = test_dir.join("checkout_full");

    let ignore = &[".git", "target", ".inarch"];

    // 1. Ingest the entire real `velenza-inarch` repository into persistent on-disk stores
    let ingest_receipt = {
        let fs_blobs = Arc::new(FsBlobStore::new(&blobs_dir).expect("create FsBlobStore"));
        let fs_meta = Arc::new(FsMetadataStore::new(&meta_dir).expect("create FsMetadataStore"));
        let engine = ScionEngine::new(fs_blobs, fs_meta);

        ingest_directory(
            &engine,
            "main",
            "verifier@inarch.dev",
            1_760_900_000,
            "self-host entire velenza-inarch repository",
            repo_root,
            ignore,
        )
        .expect("ingest real velenza-inarch codebase")
    };

    assert!(
        ingest_receipt.files_scanned >= 30,
        "expected at least 30 real repository files, found {}",
        ingest_receipt.files_scanned
    );
    assert_eq!(ingest_receipt.files_upserted, ingest_receipt.files_scanned);
    assert_eq!(ingest_receipt.files_deleted, 0);

    // 2. Reopen from cold on-disk storage with a 3-tier cache hierarchy (zero shared memory)
    let tier1_daemon = Arc::new(MemBlobStore::new());
    let tier2_regional = Arc::new(MemBlobStore::new());
    let tier3_origin = Arc::new(FsBlobStore::new(&blobs_dir).expect("reopen FsBlobStore"));
    let tiered_blobs = Arc::new(TieredBlobStore::new(
        tier1_daemon,
        tier2_regional,
        tier3_origin,
    ));
    let reopened_meta = Arc::new(FsMetadataStore::new(&meta_dir).expect("reopen FsMetadataStore"));
    let reopened_engine = ScionEngine::new(tiered_blobs, reopened_meta);

    let main_cs = reopened_engine
        .resolve_ref("main")
        .expect("resolve main")
        .expect("main ref must exist on disk");
    assert_eq!(main_cs, ingest_receipt.changeset_id);

    // 3. Verify 100% checkout-free read accuracy and Fsnode summary integrity against `repo_root`
    let report = verify_codebase_accuracy(&reopened_engine, main_cs, repo_root, ignore)
        .expect("verify_codebase_accuracy must succeed with zero mismatches");
    assert_eq!(report.files_verified, ingest_receipt.files_scanned);
    assert_eq!(report.bytes_verified, ingest_receipt.bytes_ingested);

    // 4. Materialize the entire codebase to a fresh directory via `checkout_stateless`
    let checkout_receipt = checkout_stateless(&reopened_engine, main_cs, None, &checkout_dir)
        .expect("stateless full checkout of velenza-inarch must succeed");
    assert_eq!(
        checkout_receipt.files_materialized,
        ingest_receipt.files_scanned
    );
    assert_eq!(
        checkout_receipt.bytes_materialized,
        ingest_receipt.bytes_ingested
    );

    // 5. Verify the materialized checkout directory is 100% byte-for-byte identical to the store
    let checkout_report =
        verify_codebase_accuracy(&reopened_engine, main_cs, &checkout_dir, ignore)
            .expect("materialized checkout directory must pass 100% accuracy verification");
    assert_eq!(checkout_report.files_verified, report.files_verified);
    assert_eq!(checkout_report.bytes_verified, report.bytes_verified);

    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn preserves_executables_symlinks_large_multi_chunk_binaries_and_incremental_commits() {
    let test_dir = std::env::temp_dir().join(format!(
        "velenza-inarch-complex-codebase-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&test_dir);

    let work_src = test_dir.join("work_src");
    let blobs_dir = test_dir.join("store/blobs");
    let meta_dir = test_dir.join("store/meta");
    let out_c1 = test_dir.join("out_c1");
    let out_c2 = test_dir.join("out_c2");

    fs::create_dir_all(work_src.join("scripts")).unwrap();
    fs::create_dir_all(work_src.join("src/engine")).unwrap();
    fs::create_dir_all(work_src.join("assets")).unwrap();

    // 1. Create regular source files
    fs::write(
        work_src.join("src/main.rs"),
        b"fn main() {\n    println!(\"v1\");\n}\n",
    )
    .unwrap();
    fs::write(
        work_src.join("src/engine/old.rs"),
        b"pub const LEGACY: bool = true;\n",
    )
    .unwrap();

    // 2. Create executable script (0o755 on Unix)
    let script_path = work_src.join("scripts/deploy.sh");
    fs::write(&script_path, b"#!/bin/sh\necho deploying\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    // 3. Create symlink (`scripts/current.sh -> deploy.sh`)
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("deploy.sh", work_src.join("scripts/current.sh")).unwrap();
    }

    // 4. Create 150 KiB binary file spanning multiple FastCDC chunks
    let mut binary_v1 = vec![0u8; 150 * 1024];
    for (i, b) in binary_v1.iter_mut().enumerate() {
        *b = ((i.wrapping_mul(31).wrapping_add(17)) & 0xFF) as u8;
    }
    fs::write(work_src.join("assets/weights.bin"), &binary_v1).unwrap();

    let fs_blobs = Arc::new(FsBlobStore::new(&blobs_dir).unwrap());
    let fs_meta = Arc::new(FsMetadataStore::new(&meta_dir).unwrap());
    let engine = ScionEngine::new(fs_blobs, fs_meta);
    let ignore = &[".git", ".inarch"];

    // Commit 1: Ingest initial codebase state
    let c1 = ingest_directory(
        &engine,
        "main",
        "author1@inarch.dev",
        1_760_910_000,
        "commit 1: initial workspace",
        &work_src,
        ignore,
    )
    .expect("ingest commit 1");
    verify_codebase_accuracy(&engine, c1.changeset_id, &work_src, ignore)
        .expect("commit 1 accuracy check");

    // Mutate `work_src` for Commit 2:
    // - Modify `src/main.rs`
    // - Modify a 64-byte slice in the middle of `assets/weights.bin`
    // - Delete `src/engine/old.rs`
    // - Add `src/engine/new.rs`
    // - Leave `scripts/deploy.sh` and `scripts/current.sh` untouched!
    fs::write(
        work_src.join("src/main.rs"),
        b"fn main() {\n    println!(\"v2\");\n}\n",
    )
    .unwrap();
    let mut binary_v2 = binary_v1.clone();
    for b in &mut binary_v2[70_000..70_064] {
        *b ^= 0xFF;
    }
    fs::write(work_src.join("assets/weights.bin"), &binary_v2).unwrap();
    fs::remove_file(work_src.join("src/engine/old.rs")).unwrap();
    fs::write(
        work_src.join("src/engine/new.rs"),
        b"pub const MODERN: bool = true;\n",
    )
    .unwrap();

    // Commit 2: Incremental ingest onto `main`
    let c2 = ingest_directory(
        &engine,
        "main",
        "author2@inarch.dev",
        1_760_910_100,
        "commit 2: incremental update",
        &work_src,
        ignore,
    )
    .expect("ingest commit 2");

    // Verify incremental delta detection only recorded the 3 upserts and 1 deletion!
    assert_eq!(c2.files_upserted, 3);
    assert_eq!(c2.files_deleted, 1);

    verify_codebase_accuracy(&engine, c2.changeset_id, &work_src, ignore)
        .expect("commit 2 accuracy check");

    // Verify Merkle diff between c1 and c2
    let diffs = engine
        .diff_changesets(c1.changeset_id, c2.changeset_id)
        .unwrap();
    assert_eq!(diffs.len(), 4);
    assert!(
        diffs
            .iter()
            .any(|d| d.path == MPath::new("assets/weights.bin").unwrap()
                && d.kind == ChangeKind::Modified)
    );
    assert!(
        diffs
            .iter()
            .any(|d| d.path == MPath::new("src/engine/new.rs").unwrap()
                && d.kind == ChangeKind::Added)
    );
    assert!(diffs.iter().any(
        |d| d.path == MPath::new("src/engine/old.rs").unwrap() && d.kind == ChangeKind::Deleted
    ));
    assert!(diffs.iter().any(|d| d.path == MPath::new("src/main.rs").unwrap() && d.kind == ChangeKind::Modified));

    // Verify Unode history for untouched `scripts/deploy.sh` only has Commit 1 (skipped Commit 2!)
    let script_log = engine
        .log_path(c2.changeset_id, &MPath::new("scripts/deploy.sh").unwrap())
        .unwrap();
    assert_eq!(script_log.len(), 1);
    assert_eq!(script_log[0].changeset_id, c1.changeset_id);

    // Materialize both c1 and c2 to separate directories and verify 100% fidelity
    checkout_stateless(&engine, c1.changeset_id, None, &out_c1).unwrap();
    checkout_stateless(&engine, c2.changeset_id, None, &out_c2).unwrap();

    assert_eq!(
        fs::read(out_c1.join("assets/weights.bin")).unwrap(),
        binary_v1
    );
    assert_eq!(
        fs::read(out_c2.join("assets/weights.bin")).unwrap(),
        binary_v2
    );
    assert!(out_c1.join("src/engine/old.rs").exists());
    assert!(!out_c2.join("src/engine/old.rs").exists());
    assert!(out_c2.join("src/engine/new.rs").exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(out_c2.join("scripts/deploy.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0, "executable permission bit must round-trip");

        let link_target = fs::read_link(out_c2.join("scripts/current.sh")).unwrap();
        assert_eq!(link_target, Path::new("deploy.sh"));
    }

    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn handles_in_place_checkout_switching_empty_files_and_file_directory_transitions_with_100_percent_accuracy()
 {
    let test_dir = std::env::temp_dir().join(format!(
        "velenza-inarch-inplace-transitions-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&test_dir);

    let src_dir = test_dir.join("src_dir");
    let inplace_checkout_dir = test_dir.join("inplace_checkout");
    let blobs_dir = test_dir.join("store/blobs");
    let meta_dir = test_dir.join("store/meta");

    let fs_blobs = Arc::new(FsBlobStore::new(&blobs_dir).unwrap());
    let fs_meta = Arc::new(FsMetadataStore::new(&meta_dir).unwrap());
    let engine = ScionEngine::new(fs_blobs, fs_meta);
    let ignore = &[".git", ".inarch"];

    // Commit 1 state:
    // - `.gitkeep` (0-byte empty file)
    // - `pkg/config` (regular file that will become a directory in Commit 2)
    // - `pkg/module/part1.rs` and `pkg/module/part2.rs` (directory that will become a single file `pkg/module` in Commit 2)
    // - `stale_dir/will_be_removed.txt` (directory that will be completely deleted in Commit 2)
    fs::create_dir_all(src_dir.join("pkg/module")).unwrap();
    fs::create_dir_all(src_dir.join("stale_dir")).unwrap();
    fs::write(src_dir.join(".gitkeep"), b"").unwrap();
    fs::write(src_dir.join("pkg/config"), b"mode = \"simple\"\n").unwrap();
    fs::write(src_dir.join("pkg/module/part1.rs"), b"pub fn p1() {}\n").unwrap();
    fs::write(src_dir.join("pkg/module/part2.rs"), b"pub fn p2() {}\n").unwrap();
    fs::write(
        src_dir.join("stale_dir/will_be_removed.txt"),
        b"ephemeral\n",
    )
    .unwrap();

    let c1 = ingest_directory(
        &engine,
        "main",
        "dev@inarch.dev",
        1_760_920_000,
        "c1: initial state with empty file and file/dir candidates",
        &src_dir,
        ignore,
    )
    .expect("ingest c1");
    verify_codebase_accuracy(&engine, c1.changeset_id, &src_dir, ignore)
        .expect("c1 source accuracy");

    // Mutate `src_dir` into Commit 2:
    // - Turn file `pkg/config` into directory `pkg/config/default.toml`
    // - Turn directory `pkg/module/{part1.rs,part2.rs}` into regular file `pkg/module`
    // - Delete `stale_dir/will_be_removed.txt` and `stale_dir`
    fs::remove_file(src_dir.join("pkg/config")).unwrap();
    fs::create_dir_all(src_dir.join("pkg/config")).unwrap();
    fs::write(
        src_dir.join("pkg/config/default.toml"),
        b"[settings]\nthreads = 8\n",
    )
    .unwrap();

    fs::remove_dir_all(src_dir.join("pkg/module")).unwrap();
    fs::write(src_dir.join("pkg/module"), b"pub fn unified_module() {}\n").unwrap();

    fs::remove_dir_all(src_dir.join("stale_dir")).unwrap();

    let c2 = ingest_directory(
        &engine,
        "main",
        "dev@inarch.dev",
        1_760_920_100,
        "c2: swap file<->directory and delete stale_dir",
        &src_dir,
        ignore,
    )
    .expect("ingest c2");
    verify_codebase_accuracy(&engine, c2.changeset_id, &src_dir, ignore)
        .expect("c2 source accuracy");

    // Now test in-place `checkout_stateless` on the SAME directory (`inplace_checkout_dir`):
    // 1. Checkout Commit 1 into `inplace_checkout_dir` and verify 100% accuracy
    checkout_stateless(&engine, c1.changeset_id, None, &inplace_checkout_dir)
        .expect("checkout c1 in-place");
    let r1 = verify_codebase_accuracy(&engine, c1.changeset_id, &inplace_checkout_dir, ignore)
        .expect("verify c1 in-place checkout");
    assert_eq!(r1.files_verified, 5);
    assert_eq!(
        fs::read(inplace_checkout_dir.join(".gitkeep")).unwrap(),
        b""
    );
    assert!(inplace_checkout_dir.join("pkg/config").is_file());
    assert!(inplace_checkout_dir.join("pkg/module").is_dir());

    // 2. Switch `inplace_checkout_dir` in-place to Commit 2 and verify 100% accuracy (no stale files!)
    checkout_stateless(&engine, c2.changeset_id, None, &inplace_checkout_dir)
        .expect("checkout c2 in-place over c1");
    let r2 = verify_codebase_accuracy(&engine, c2.changeset_id, &inplace_checkout_dir, ignore)
        .expect("verify c2 in-place checkout");
    assert_eq!(r2.files_verified, 3);
    assert!(inplace_checkout_dir.join("pkg/config").is_dir());
    assert!(
        inplace_checkout_dir
            .join("pkg/config/default.toml")
            .is_file()
    );
    assert!(inplace_checkout_dir.join("pkg/module").is_file());
    assert!(!inplace_checkout_dir.join("stale_dir").exists());

    // 3. Switch `inplace_checkout_dir` in-place BACK to Commit 1 and verify 100% accuracy!
    checkout_stateless(&engine, c1.changeset_id, None, &inplace_checkout_dir)
        .expect("checkout c1 in-place over c2");
    let r1_again =
        verify_codebase_accuracy(&engine, c1.changeset_id, &inplace_checkout_dir, ignore)
            .expect("verify c1 in-place checkout after switching back from c2");
    assert_eq!(r1_again, r1);

    let _ = fs::remove_dir_all(&test_dir);
}
