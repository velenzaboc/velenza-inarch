//! Integration tests for Git <-> Velenza Inarch migration (`inr git-import` / `inr git-export`)
//! and the scientific benchmark suite (`inr bench`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use inarch_cli::{
    BenchmarkConfig, GitImportOptions, export_git_revision, import_git_history,
    run_benchmark_suite, verify_codebase_accuracy,
};
use inarch_engine::ScionEngine;
use inarch_store::{MemBlobStore, MemMetadataStore, MetadataStore};
use inarch_types::bonsai::FileChange;
use inarch_types::path::MPath;

fn unique_temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "velenza-inarch-git-bench-{}-{}-{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_git(repo_dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> String {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_dir).args(args);
    cmd.env("GIT_AUTHOR_NAME", "Alice Builder");
    cmd.env("GIT_AUTHOR_EMAIL", "alice@example.com");
    cmd.env("GIT_COMMITTER_NAME", "Alice Builder");
    cmd.env("GIT_COMMITTER_EMAIL", "alice@example.com");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("execute git command");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn test_git_import_preserves_commit_history_authors_deltas_and_git_sha_metadata() {
    let root = unique_temp_dir("git-import");
    let git_dir = root.join("src-git");
    fs::create_dir_all(&git_dir).unwrap();

    // Initialize a multi-commit Git repository with adds, edits, and deletes
    run_git(&git_dir, &["init", "-b", "main"], &[]);

    // Commit 1: root commit with 2 files
    fs::create_dir_all(git_dir.join("src")).unwrap();
    fs::write(git_dir.join("README.md"), b"# Project Alpha\n").unwrap();
    fs::write(
        git_dir.join("src/lib.rs"),
        b"pub fn version() -> u32 { 1 }\n",
    )
    .unwrap();
    run_git(&git_dir, &["add", "."], &[]);
    run_git(
        &git_dir,
        &["commit", "-m", "initial commit"],
        &[
            ("GIT_AUTHOR_NAME", "Alice"),
            ("GIT_AUTHOR_EMAIL", "alice@example.com"),
            ("GIT_AUTHOR_DATE", "1760000100 +0000"),
            ("GIT_COMMITTER_DATE", "1760000100 +0000"),
        ],
    );
    let sha1 = run_git(&git_dir, &["rev-parse", "HEAD"], &[]);

    // Commit 2: modify only src/lib.rs and add src/util.rs (README.md untouched -> O(Delta) check!)
    fs::write(
        git_dir.join("src/lib.rs"),
        b"pub mod util;\npub fn version() -> u32 { 2 }\n",
    )
    .unwrap();
    fs::write(
        git_dir.join("src/util.rs"),
        b"pub fn helper() -> &'static str { \"ok\" }\n",
    )
    .unwrap();
    run_git(&git_dir, &["add", "."], &[]);
    run_git(
        &git_dir,
        &["commit", "-m", "add util module and bump version"],
        &[
            ("GIT_AUTHOR_NAME", "Bob"),
            ("GIT_AUTHOR_EMAIL", "bob@example.com"),
            ("GIT_AUTHOR_DATE", "1760000200 -0400"),
            ("GIT_COMMITTER_DATE", "1760000200 -0400"),
        ],
    );
    let sha2 = run_git(&git_dir, &["rev-parse", "HEAD"], &[]);

    // Commit 3: delete src/util.rs and update src/lib.rs
    fs::remove_file(git_dir.join("src/util.rs")).unwrap();
    fs::write(
        git_dir.join("src/lib.rs"),
        b"pub fn version() -> u32 { 3 }\n",
    )
    .unwrap();
    run_git(&git_dir, &["add", "-A"], &[]);
    run_git(
        &git_dir,
        &["commit", "-m", "remove util and finalize v3"],
        &[
            ("GIT_AUTHOR_NAME", "Carol"),
            ("GIT_AUTHOR_EMAIL", "carol@example.com"),
            ("GIT_AUTHOR_DATE", "1760000300 +0200"),
            ("GIT_COMMITTER_DATE", "1760000300 +0200"),
        ],
    );
    let sha3 = run_git(&git_dir, &["rev-parse", "HEAD"], &[]);

    let blobs = Arc::new(MemBlobStore::new());
    let meta = Arc::new(MemMetadataStore::new());
    let engine = ScionEngine::new(blobs, meta.clone());

    let opts = GitImportOptions {
        git_ref: "main".to_string(),
        target_ref: "main".to_string(),
        max_commits: None,
        ignore_names: vec![".git".to_string(), ".inarch".to_string()],
    };

    let receipt = import_git_history(&engine, &git_dir, &opts).expect("import git history");
    assert_eq!(receipt.commits_examined, 3);
    assert_eq!(receipt.commits_imported, 3);
    assert_eq!(receipt.commits_skipped_existing, 0);
    assert_eq!(receipt.imported_commits.len(), 3);

    // Verify commit 1 metadata and delta
    let c1 = &receipt.imported_commits[0];
    assert_eq!(c1.git_commit_sha, sha1);
    assert_eq!(c1.author, "Alice <alice@example.com>");
    assert_eq!(c1.timestamp, 1_760_000_100);
    assert_eq!(c1.tz_offset_secs, 0);
    assert_eq!(c1.files_changed, 2);

    // Verify commit 2 has ONLY 2 file changes (src/lib.rs and src/util.rs), NOT README.md
    let c2 = &receipt.imported_commits[1];
    assert_eq!(c2.git_commit_sha, sha2);
    assert_eq!(c2.author, "Bob <bob@example.com>");
    assert_eq!(c2.timestamp, 1_760_000_200);
    assert_eq!(c2.tz_offset_secs, -14400);
    assert_eq!(c2.files_changed, 2);
    let cs2 = meta
        .get_changeset(&c2.changeset_id)
        .unwrap()
        .expect("changeset 2 stored");
    assert_eq!(
        cs2.extra.get("git_commit_sha").map(|v| v.as_slice()),
        Some(sha2.as_bytes())
    );
    assert!(
        !cs2.file_changes
            .contains_key(&MPath::new("README.md").unwrap())
    );

    // Verify commit 3 recorded FileChange::Deleted for src/util.rs
    let c3 = &receipt.imported_commits[2];
    assert_eq!(c3.git_commit_sha, sha3);
    assert_eq!(c3.author, "Carol <carol@example.com>");
    assert_eq!(c3.timestamp, 1_760_000_300);
    assert_eq!(c3.tz_offset_secs, 7200);
    let cs3 = meta
        .get_changeset(&c3.changeset_id)
        .unwrap()
        .expect("changeset 3 stored");
    assert_eq!(
        cs3.file_changes.get(&MPath::new("src/util.rs").unwrap()),
        Some(&FileChange::Deleted)
    );

    // Verify 100% byte-for-byte accuracy against the Git working directory at HEAD
    let head_cs = receipt.head_changeset.expect("head changeset");
    let verify =
        verify_codebase_accuracy(&engine, head_cs, &git_dir, &[".git", ".inarch"]).unwrap();
    assert_eq!(verify.files_verified, 2);

    // Verify checkout-free log_path on src/lib.rs shows all 3 commits
    let history = engine
        .log_path(head_cs, &MPath::new("src/lib.rs").unwrap())
        .unwrap();
    assert_eq!(history.len(), 3);

    // Now add a 4th commit in Git and verify incremental `import_git_history` skips the first 3
    fs::write(git_dir.join("README.md"), b"# Project Alpha v4\n").unwrap();
    run_git(&git_dir, &["add", "README.md"], &[]);
    run_git(
        &git_dir,
        &["commit", "-m", "docs update for v4"],
        &[
            ("GIT_AUTHOR_NAME", "Dave"),
            ("GIT_AUTHOR_EMAIL", "dave@example.com"),
            ("GIT_AUTHOR_DATE", "1760000400 +0000"),
            ("GIT_COMMITTER_DATE", "1760000400 +0000"),
        ],
    );
    let sha4 = run_git(&git_dir, &["rev-parse", "HEAD"], &[]);

    let inc_receipt = import_git_history(&engine, &git_dir, &opts).expect("incremental git import");
    assert_eq!(inc_receipt.commits_examined, 4);
    assert_eq!(inc_receipt.commits_skipped_existing, 3);
    assert_eq!(inc_receipt.commits_imported, 1);
    assert_eq!(inc_receipt.imported_commits[0].git_commit_sha, sha4);

    let verify_after_inc = verify_codebase_accuracy(
        &engine,
        inc_receipt.head_changeset.unwrap(),
        &git_dir,
        &[".git", ".inarch"],
    )
    .unwrap();
    assert_eq!(verify_after_inc.files_verified, 2);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_git_export_materializes_valid_git_commit_with_inarch_provenance() {
    let root = unique_temp_dir("git-export");
    let src_git = root.join("src-git");
    let dest_git = root.join("dest-git");
    fs::create_dir_all(&src_git).unwrap();

    run_git(&src_git, &["init", "-b", "main"], &[]);
    fs::create_dir_all(src_git.join("crates/core")).unwrap();
    fs::write(
        src_git.join("crates/core/lib.rs"),
        b"pub const MAGIC: u64 = 42;\n",
    )
    .unwrap();
    fs::write(src_git.join("Cargo.toml"), b"[workspace]\n").unwrap();
    run_git(&src_git, &["add", "."], &[]);
    run_git(&src_git, &["commit", "-m", "initial workspace"], &[]);

    let blobs = Arc::new(MemBlobStore::new());
    let meta = Arc::new(MemMetadataStore::new());
    let engine = ScionEngine::new(blobs, meta);

    let import_rec = import_git_history(&engine, &src_git, &GitImportOptions::default())
        .expect("import git repo");
    let head_cs = import_rec.head_changeset.unwrap();

    // Export the Inarch revision to a brand-new Git repository directory
    let export_rec =
        export_git_revision(&engine, head_cs, &dest_git, "main").expect("export to git");
    assert_eq!(export_rec.changeset_id, head_cs);
    assert_eq!(export_rec.files_exported, 2);
    assert_eq!(export_rec.git_commit_sha.len(), 40);

    // Verify Git commit message contains Inarch-Changeset-Id trailer
    let commit_msg = run_git(&dest_git, &["log", "-1", "--format=%B"], &[]);
    let expected_trailer = format!("Inarch-Changeset-Id: {}", head_cs.to_hex());
    assert!(
        commit_msg.contains(&expected_trailer),
        "expected commit message '{}' to contain '{}'",
        commit_msg,
        expected_trailer
    );

    // Verify exported Git working tree is 100% identical to Inarch changeset
    let verify =
        verify_codebase_accuracy(&engine, head_cs, &dest_git, &[".git", ".inarch"]).unwrap();
    assert_eq!(verify.files_verified, 2);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_benchmark_harness_executes_and_produces_sanitized_csv_and_json_metrics() {
    let cfg = BenchmarkConfig {
        corpus_label: "unit-test-corpus".to_string(),
        host_label: "test-runner".to_string(),
        source_dir: None,
        file_count: 40,
        concurrency_levels: vec![1, 4],
        trials: 2,
        large_file_mb: 1,
    };

    let report = run_benchmark_suite(&cfg).expect("execute scientific benchmark suite");
    assert_eq!(report.corpus_label, "unit-test-corpus");
    assert_eq!(report.host_label, "test-runner");
    assert!(
        report.measurements.len() >= 10,
        "expected measurements across W1..W5 for both git and velenza-inarch, got {}",
        report.measurements.len()
    );

    for workload in [
        "W1_provisioning",
        "W2_commit_scaling",
        "W3_swarm_landing",
        "W4_large_file_wire_dedup",
        "W5_checkout_free_queries",
    ] {
        assert!(
            report
                .measurements
                .iter()
                .any(|m| m.workload_id == workload && m.system == "velenza-inarch"),
            "missing velenza-inarch measurement for {}",
            workload
        );
        assert!(
            report
                .measurements
                .iter()
                .any(|m| m.workload_id == workload && m.system == "git"),
            "missing git baseline measurement for {}",
            workload
        );
    }

    let csv = report.to_csv_string();
    assert!(csv.starts_with(
        "corpus,host,workload_id,system,parameter,trials,p50_us,p95_us,p99_us,mean_us,throughput_ops_per_sec,disk_bytes_written,wire_bytes_transferred,retries_or_rebased,failures\n"
    ));
    assert!(csv.contains("W3_swarm_landing,velenza-inarch"));

    let json = report.to_json_string();
    assert!(json.contains("\"corpus_label\":\"unit-test-corpus\""));
    assert!(json.contains("\"pre_benchmark_baseline\":{"));
    assert!(json.contains("\"W1_provisioning\""));
    assert!(json.contains("\"W5_checkout_free_queries\""));

    // Verify pre-benchmark device settings & ambient system noise baseline are captured
    assert!(!report.baseline.os_family.is_empty());
    assert!(!report.baseline.os_arch.is_empty());
    assert!(report.baseline.logical_cpu_cores >= 1);
    assert!(!report.baseline.git_version.is_empty());
    assert!(report.baseline.pre_bench_4mb_fsync_write_us > 0);
    assert!(report.baseline.pre_bench_100_small_files_us > 0);
    assert!(report.baseline.running_process_count > 0);

    let md = report.to_markdown_string();
    assert!(md.contains("Pre-Benchmark Host Configuration & Ambient Noise Baseline"));
    assert!(md.contains("pre_bench_4mb_fsync_write_us"));
    assert!(md.contains("pre_bench_100_small_files_us"));
}
