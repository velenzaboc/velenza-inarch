//! Regression contracts for merge blame, copy detection, and bounded derivation.

use std::collections::BTreeMap;
use std::process::Command;
use std::sync::Arc;

use inarch_derived::{BlameV2, CopyKind, DerivedDataEngine};
use inarch_store::{BlobStore, MemBlobStore, MemMetadataStore, MetadataStore};
use inarch_types::bonsai::{BonsaiChangeset, FileChange, FileType};
use inarch_types::hash::{ChangesetId, ObjectDomain, ObjectHash};
use inarch_types::path::MPath;

const BLAME_LCS_CHILD: &str = "INARCH_AUDIT_BLAME_LCS_CHILD";

fn commit_files(
    blobs: &MemBlobStore,
    meta: &MemMetadataStore,
    parents: Vec<ChangesetId>,
    author: &str,
    timestamp: i64,
    message: &str,
    edits: Vec<(&str, Option<&[u8]>)>,
) -> ChangesetId {
    let mut file_changes = BTreeMap::new();
    for (path_str, maybe_content) in edits {
        let path = MPath::new(path_str).expect("valid path");
        match maybe_content {
            Some(content) => {
                let blob_id = blobs.put_blob_content(content).expect("store blob");
                file_changes.insert(
                    path,
                    FileChange::Tracked {
                        blob_id,
                        size: content.len() as u64,
                        file_type: FileType::Regular,
                    },
                );
            }
            None => {
                file_changes.insert(path, FileChange::Deleted);
            }
        }
    }
    let changeset = BonsaiChangeset::new(
        parents,
        author.to_string(),
        timestamp,
        0,
        message.to_string(),
        BTreeMap::new(),
        file_changes,
    )
    .expect("valid changeset");
    meta.put_changeset(&changeset).expect("store changeset")
}

#[test]
fn merge_blame_preserves_attribution_from_the_second_parent() {
    let blobs = Arc::new(MemBlobStore::new());
    let meta = Arc::new(MemMetadataStore::new());
    let derived = DerivedDataEngine::new(blobs.clone(), meta.clone());
    let path = MPath::new("shared.txt").expect("valid path");

    let base = commit_files(
        &blobs,
        &meta,
        vec![],
        "base@inarch.dev",
        1_760_300_000,
        "base",
        vec![("shared.txt", Some(b"base\n"))],
    );
    let primary = commit_files(
        &blobs,
        &meta,
        vec![base],
        "primary@inarch.dev",
        1_760_300_001,
        "primary branch",
        vec![("shared.txt", Some(b"primary\n"))],
    );
    let secondary = commit_files(
        &blobs,
        &meta,
        vec![base],
        "secondary@inarch.dev",
        1_760_300_002,
        "secondary branch",
        vec![("shared.txt", Some(b"secondary\n"))],
    );
    let merge = commit_files(
        &blobs,
        &meta,
        vec![primary, secondary],
        "merger@inarch.dev",
        1_760_300_003,
        "take secondary content",
        vec![("shared.txt", Some(b"secondary\n"))],
    );

    let blame = derived.blame_file(merge, &path).expect("derive merge blame");
    assert_eq!(blame.lines.len(), 1);
    assert_eq!(blame.lines[0].content, "secondary");
    assert_eq!(blame.lines[0].changeset_id, secondary);
    assert_eq!(blame.lines[0].author, "secondary@inarch.dev");
}

#[test]
fn similar_copy_detection_considers_same_directory_when_extension_changes() {
    let blobs = Arc::new(MemBlobStore::new());
    let meta = Arc::new(MemMetadataStore::new());
    let derived = DerivedDataEngine::new(blobs.clone(), meta.clone());

    let base = commit_files(
        &blobs,
        &meta,
        vec![],
        "base@inarch.dev",
        1_760_400_000,
        "source",
        vec![("docs/source.txt", Some(b"one\ntwo\nthree\nfour\n"))],
    );
    let copied = commit_files(
        &blobs,
        &meta,
        vec![base],
        "copy@inarch.dev",
        1_760_400_001,
        "modified copies with changed and absent extensions",
        vec![
            ("docs/copy.md", Some(b"one\ntwo\nthree\nchanged\n")),
            ("docs/README", Some(b"one\ntwo\nthree\nother\n")),
            (
                "docs/unrelated.bin",
                Some(b"alpha\nbeta\ngamma\ndelta\n"),
            ),
        ],
    );

    let report = derived
        .derive_copy_detection(copied)
        .expect("derive copy detection");
    let record = report
        .records
        .iter()
        .find(|record| record.dest_path.as_str() == "docs/copy.md")
        .expect("same-directory modified copy must be detected despite extension change");
    assert_eq!(record.source_path.as_str(), "docs/source.txt");
    assert_eq!(record.kind, CopyKind::SimilarCopy);
    assert!(record.similarity_bps >= 5_000);

    let extensionless = report
        .records
        .iter()
        .find(|record| record.dest_path.as_str() == "docs/README")
        .expect("same-directory extensionless modified copy must be detected");
    assert_eq!(extensionless.source_path.as_str(), "docs/source.txt");
    assert_eq!(extensionless.kind, CopyKind::SimilarCopy);
    assert!(extensionless.similarity_bps >= 5_000);

    assert!(
        report
            .records
            .iter()
            .all(|record| record.dest_path.as_str() != "docs/unrelated.bin"),
        "same-directory files below the similarity threshold must not be reported as copies"
    );
}

#[test]
fn blame_lcs_memory_child() {
    if std::env::var_os(BLAME_LCS_CHILD).is_none() {
        return;
    }

    let parent_text: String = (0..15_000)
        .map(|i| format!("parent-{i:05}\n"))
        .collect();
    let child_text: String = (0..15_000)
        .map(|i| format!("child-{i:05}\n"))
        .collect();
    let parent_id = ChangesetId::from_hash(ObjectHash::from_domain(
        ObjectDomain::Changeset,
        b"parent",
    ));
    let child_id = ChangesetId::from_hash(ObjectHash::from_domain(
        ObjectDomain::Changeset,
        b"child",
    ));
    let parent = BlameV2::from_initial(&parent_text, parent_id, "parent@inarch.dev");
    let child = BlameV2::derive_from_parent(&parent, &child_text, child_id, "child@inarch.dev");
    assert_eq!(child.lines.len(), 15_000);
    assert!(child.lines.iter().all(|line| line.changeset_id == child_id));
}

#[test]
#[cfg(target_os = "linux")]
fn line_dense_blame_completes_within_a_bounded_address_space() {
    let executable = std::env::current_exe().expect("current test executable");
    let output = Command::new("sh")
        .arg("-c")
        .arg("ulimit -v 524288; exec \"$1\" --exact blame_lcs_memory_child --nocapture")
        .arg("sh")
        .arg(executable)
        .env(BLAME_LCS_CHILD, "1")
        .output()
        .expect("run bounded-memory blame child");
    assert!(
        output.status.success(),
        "line-dense blame exceeded 512 MiB or failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
