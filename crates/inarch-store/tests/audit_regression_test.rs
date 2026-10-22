//! Regression contracts for the storage defects found by the 2026-10-22 audit.

use std::collections::BTreeMap;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use inarch_store::{FsMetadataStore, MetadataStore, StoreError};
use inarch_types::bonsai::{BonsaiChangeset, FileChange, FileType};
use inarch_types::hash::{BlobId, ChangesetId};
use inarch_types::path::MPath;

const CAS_CHILD_MARKER: &str = "INARCH_AUDIT_FS_CAS_CHILD";
const CAS_ROOT_ENV: &str = "INARCH_AUDIT_FS_CAS_ROOT";
const CAS_EXPECTED_ENV: &str = "INARCH_AUDIT_FS_CAS_EXPECTED";
const CAS_TARGET_ENV: &str = "INARCH_AUDIT_FS_CAS_TARGET";
const CAS_INDEX_ENV: &str = "INARCH_AUDIT_FS_CAS_INDEX";

fn unique_temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "inarch-audit-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create audit temp directory");
    dir
}

fn changeset(parent: Option<ChangesetId>, label: &str, timestamp: i64) -> BonsaiChangeset {
    let content = format!("{label}\n");
    BonsaiChangeset::new(
        parent.into_iter().collect(),
        format!("{label}@inarch.dev"),
        timestamp,
        0,
        label.to_string(),
        BTreeMap::new(),
        BTreeMap::from([(
            MPath::new("state.txt").expect("valid path"),
            FileChange::Tracked {
                blob_id: BlobId::from_content(content.as_bytes()),
                size: content.len() as u64,
                file_type: FileType::Regular,
            },
        )]),
    )
    .expect("valid changeset")
}

#[test]
fn fs_cas_child_process() {
    if std::env::var_os(CAS_CHILD_MARKER).is_none() {
        return;
    }

    let root = std::path::PathBuf::from(std::env::var(CAS_ROOT_ENV).expect("CAS root"));
    let expected = ChangesetId::from_hex(&std::env::var(CAS_EXPECTED_ENV).expect("expected id"))
        .expect("parse expected id");
    let target = ChangesetId::from_hex(&std::env::var(CAS_TARGET_ENV).expect("target id"))
        .expect("parse target id");
    let index = std::env::var(CAS_INDEX_ENV).expect("child index");

    std::fs::write(root.join(format!("ready-{index}")), b"ready").expect("write ready marker");
    let deadline = Instant::now() + Duration::from_secs(15);
    while !root.join("go").exists() {
        assert!(Instant::now() < deadline, "timed out waiting for CAS barrier");
        std::thread::sleep(Duration::from_millis(2));
    }

    let store = FsMetadataStore::new(root.join("meta")).expect("open child store");
    let result = store.cas_ref("main", Some(expected), target);
    let result_text = match result {
        Ok(()) => "ok".to_string(),
        Err(StoreError::CasMismatch { .. }) => "conflict".to_string(),
        Err(other) => format!("error:{other:?}"),
    };
    std::fs::write(root.join(format!("result-{index}")), result_text)
        .expect("write CAS result");
}

#[test]
fn independent_process_filesystem_cas_has_exactly_one_winner() {
    let root = unique_temp_dir("fs-cas");
    let meta_root = root.join("meta");
    let store = FsMetadataStore::new(&meta_root).expect("create filesystem metadata store");

    let seed = changeset(None, "seed", 1_760_000_000);
    let seed_id = store.put_changeset(&seed).expect("store seed");
    let candidate = changeset(Some(seed_id), "candidate", 1_760_000_001);
    let candidate_id = store.put_changeset(&candidate).expect("store candidate");
    store
        .cas_ref("main", None, seed_id)
        .expect("initialize main");

    let executable = std::env::current_exe().expect("current test executable");
    let process_count = 32usize;
    let mut children: Vec<Child> = Vec::with_capacity(process_count);
    for index in 0..process_count {
        let child = Command::new(&executable)
            .args(["--exact", "fs_cas_child_process", "--nocapture"])
            .env(CAS_CHILD_MARKER, "1")
            .env(CAS_ROOT_ENV, &root)
            .env(CAS_EXPECTED_ENV, seed_id.to_hex())
            .env(CAS_TARGET_ENV, candidate_id.to_hex())
            .env(CAS_INDEX_ENV, index.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn independent CAS process");
        children.push(child);
    }

    let ready_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let ready = (0..process_count)
            .filter(|index| root.join(format!("ready-{index}")).exists())
            .count();
        if ready == process_count {
            break;
        }
        if Instant::now() >= ready_deadline {
            let _ = std::fs::write(root.join("go"), b"go");
            for child in &mut children {
                let _ = child.kill();
            }
            panic!("only {ready}/{process_count} CAS children reached the barrier");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    std::fs::write(root.join("go"), b"go").expect("release CAS barrier");

    for child in children {
        let output = child.wait_with_output().expect("wait for CAS child");
        assert!(
            output.status.success(),
            "CAS child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let results: Vec<String> = (0..process_count)
        .map(|index| {
            std::fs::read_to_string(root.join(format!("result-{index}")))
                .expect("read child CAS result")
        })
        .collect();
    let winners = results.iter().filter(|result| result.as_str() == "ok").count();
    assert_eq!(
        winners, 1,
        "one expected value permits exactly one cross-process winner; results={results:?}"
    );
    assert!(
        results
            .iter()
            .all(|result| result == "ok" || result == "conflict"),
        "CAS children must return only success or an expected-value conflict: {results:?}"
    );
    assert_eq!(store.get_ref("main").expect("read final ref"), Some(candidate_id));

    let _ = std::fs::remove_dir_all(root);
}
