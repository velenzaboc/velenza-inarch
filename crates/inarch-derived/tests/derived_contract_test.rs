//! Comprehensive contract tests for `inarch-derived` (Iteration 3 — Slice 4):
//! - Inductive `Fsnode` Merkle tree derivation with $O(\Delta \cdot \text{depth})$ untouched subtree reuse,
//!   empty-directory auto-pruning, and recursive `FsnodeSummary` file/byte counts.
//! - Inductive `Unode` (`UnodeFile` + `UnodeManifest`) per-file and per-directory history graphs
//!   enabling $O(k)$ `file_history` and `directory_history` queries that completely skip commits
//!   not touching the target path.
//! - Inductive `BlameV2` line-by-line attribution across insertions, deletions, and untouched commits.
//! - `CommitGraph` generation numbers and binary-lifting skip pointers for $O(\log N)$ `is_ancestor`
//!   and `lca` (lowest common ancestor / merge-base) queries.

use std::collections::BTreeMap;
use std::sync::Arc;

use inarch_derived::{DerivedDataEngine, FsnodeEntry};
use inarch_store::{BlobStore, MemBlobStore, MemMetadataStore, MetadataStore};
use inarch_types::bonsai::{BonsaiChangeset, FileChange, FileType};
use inarch_types::hash::ChangesetId;
use inarch_types::path::{MPath, MPathElement};

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
        let path = MPath::new(path_str).expect("valid MPath");
        match maybe_content {
            Some(bytes) => {
                let blob_id = blobs.put_blob_content(bytes).expect("store blob");
                file_changes.insert(
                    path,
                    FileChange::Tracked {
                        blob_id,
                        size: bytes.len() as u64,
                        file_type: FileType::Regular,
                    },
                );
            }
            None => {
                file_changes.insert(path, FileChange::Deleted);
            }
        }
    }

    let cs = BonsaiChangeset::new(
        parents,
        author.to_string(),
        timestamp,
        0,
        message.to_string(),
        BTreeMap::new(),
        file_changes,
    )
    .expect("valid BonsaiChangeset");
    meta.put_changeset(&cs).expect("store changeset")
}

#[test]
fn fsnode_derives_merkle_trees_inductively_reuses_untouched_subtrees_and_tracks_summaries() {
    let blobs = Arc::new(MemBlobStore::new());
    let meta = Arc::new(MemMetadataStore::new());
    let engine = DerivedDataEngine::new(Arc::clone(&blobs), Arc::clone(&meta));

    let b_readme = vec![b'R'; 10];
    let b_lib_a1 = vec![b'A'; 100];
    let b_lib_b1 = vec![b'B'; 200];

    let cs1 = commit_files(
        &blobs,
        &meta,
        vec![],
        "alice@inarch.dev",
        1_760_000_001,
        "initial tree",
        vec![
            ("README.md", Some(&b_readme)),
            ("crates/a/src/lib.rs", Some(&b_lib_a1)),
            ("crates/b/src/lib.rs", Some(&b_lib_b1)),
        ],
    );

    let root1_id = engine.derive_fsnode(cs1).expect("derive fsnode cs1");
    let root1 = engine.load_fsnode(&root1_id).expect("load root1");
    let root1_summary = root1.summary();
    assert_eq!(root1_summary.child_files_count, 1);
    assert_eq!(root1_summary.child_dirs_count, 1);
    assert_eq!(root1_summary.descendant_files_count, 3);
    assert_eq!(root1_summary.descendant_files_total_size, 310);

    let crates_b_path = MPath::new("crates/b").unwrap();
    let crates_b_entry_1 = engine
        .lookup_fsnode_path(&root1_id, &crates_b_path)
        .expect("lookup crates/b in cs1")
        .expect("crates/b must exist");
    let crates_b_fsnode_1 = match crates_b_entry_1 {
        FsnodeEntry::Directory { fsnode_id, summary } => {
            assert_eq!(summary.descendant_files_count, 1);
            assert_eq!(summary.descendant_files_total_size, 200);
            fsnode_id
        }
        other => panic!("expected Directory entry for crates/b, got {:?}", other),
    };

    // Commit 2 modifies only `crates/a/src/lib.rs` (150 bytes); `crates/b` is untouched
    let b_lib_a2 = vec![b'a'; 150];
    let cs2 = commit_files(
        &blobs,
        &meta,
        vec![cs1],
        "bob@inarch.dev",
        1_760_000_002,
        "update crates/a only",
        vec![("crates/a/src/lib.rs", Some(&b_lib_a2))],
    );

    let root2_id = engine.derive_fsnode(cs2).expect("derive fsnode cs2");
    assert_ne!(root1_id, root2_id);
    let root2 = engine.load_fsnode(&root2_id).expect("load root2");
    assert_eq!(root2.summary().descendant_files_count, 3);
    assert_eq!(root2.summary().descendant_files_total_size, 360);

    // Untouched subtree `crates/b` MUST have the exact same FsnodeId
    let crates_b_entry_2 = engine
        .lookup_fsnode_path(&root2_id, &crates_b_path)
        .unwrap()
        .unwrap();
    let crates_b_fsnode_2 = match crates_b_entry_2 {
        FsnodeEntry::Directory { fsnode_id, .. } => fsnode_id,
        other => panic!("expected Directory entry, got {:?}", other),
    };
    assert_eq!(
        crates_b_fsnode_1, crates_b_fsnode_2,
        "untouched directory subtree must retain identical content-addressed FsnodeId"
    );

    // Commit 3 deletes `crates/a/src/lib.rs`; empty directory `crates/a` must be pruned automatically
    let cs3 = commit_files(
        &blobs,
        &meta,
        vec![cs2],
        "carol@inarch.dev",
        1_760_000_003,
        "delete crates/a/src/lib.rs",
        vec![("crates/a/src/lib.rs", None)],
    );

    let root3_id = engine.derive_fsnode(cs3).expect("derive fsnode cs3");
    let root3 = engine.load_fsnode(&root3_id).expect("load root3");
    assert_eq!(root3.summary().descendant_files_count, 2);
    assert_eq!(root3.summary().descendant_files_total_size, 210);

    let crates_a_path = MPath::new("crates/a").unwrap();
    assert_eq!(
        engine
            .lookup_fsnode_path(&root3_id, &crates_a_path)
            .unwrap(),
        None,
        "empty directory crates/a must be automatically pruned after last file is deleted"
    );

    // And `crates/` still has `b`
    let crates_dir = match engine
        .lookup_fsnode_path(&root3_id, &MPath::new("crates").unwrap())
        .unwrap()
        .unwrap()
    {
        FsnodeEntry::Directory { fsnode_id, .. } => engine.load_fsnode(&fsnode_id).unwrap(),
        other => panic!("expected crates directory, got {:?}", other),
    };
    assert!(
        crates_dir
            .entries
            .contains_key(&MPathElement::new("b").unwrap())
    );
    assert!(
        !crates_dir
            .entries
            .contains_key(&MPathElement::new("a").unwrap())
    );
}

#[test]
fn unode_derives_per_file_and_directory_history_graphs_in_o_k_skipping_unrelated_commits() {
    let blobs = Arc::new(MemBlobStore::new());
    let meta = Arc::new(MemMetadataStore::new());
    let engine = DerivedDataEngine::new(Arc::clone(&blobs), Arc::clone(&meta));

    let target_file = "crates/core/engine.rs";
    let mut commits = Vec::new();
    let mut prev: Option<ChangesetId> = None;

    for i in 0..50usize {
        let parents = prev.into_iter().collect::<Vec<_>>();
        let edits = if i == 0 || i == 17 || i == 42 {
            let content = format!("// engine revision {}\n", i).into_bytes();
            vec![(target_file.to_string(), Some(content))]
        } else {
            let other_path = format!("crates/other/mod_{}.rs", i);
            let content = format!("// unrelated module {}\n", i).into_bytes();
            vec![(other_path, Some(content))]
        };

        let borrowed_edits: Vec<(&str, Option<&[u8]>)> = edits
            .iter()
            .map(|(p, c)| (p.as_str(), c.as_deref()))
            .collect();
        let cs_id = commit_files(
            &blobs,
            &meta,
            parents,
            "agent@inarch.dev",
            1_760_010_000 + (i as i64),
            &format!("commit {}", i),
            borrowed_edits,
        );
        commits.push(cs_id);
        prev = Some(cs_id);
    }

    let head = *commits.last().unwrap();
    engine.derive_unode(head).expect("derive unode at head");

    // Query O(k) file history for `crates/core/engine.rs`
    let target_mpath = MPath::new(target_file).unwrap();
    let file_hist = engine
        .file_history(head, &target_mpath)
        .expect("query file_history");

    assert_eq!(
        file_hist,
        vec![commits[42], commits[17], commits[0]],
        "Unode file history must return ONLY the 3 commits that touched crates/core/engine.rs in O(k)"
    );

    // Query O(k) directory history for `crates/core`
    let dir_mpath = MPath::new("crates/core").unwrap();
    let dir_hist = engine
        .directory_history(head, &dir_mpath)
        .expect("query directory_history");
    assert_eq!(
        dir_hist,
        vec![commits[42], commits[17], commits[0]],
        "Unode directory history must return ONLY the 3 commits that touched crates/core"
    );
}

#[test]
fn blame_v2_inductively_attributes_lines_across_insertions_deletions_and_untouched_commits() {
    let blobs = Arc::new(MemBlobStore::new());
    let meta = Arc::new(MemMetadataStore::new());
    let engine = DerivedDataEngine::new(Arc::clone(&blobs), Arc::clone(&meta));

    let cs1 = commit_files(
        &blobs,
        &meta,
        vec![],
        "alice@inarch.dev",
        1_760_020_001,
        "add main.rs",
        vec![(
            "src/main.rs",
            Some(b"fn main() {\n    println!(\"v1\");\n}\n"),
        )],
    );

    // Commit 2 touches a completely different file
    let cs2 = commit_files(
        &blobs,
        &meta,
        vec![cs1],
        "bob@inarch.dev",
        1_760_020_002,
        "update readme",
        vec![("README.md", Some(b"# Velenza Inarch\n"))],
    );

    // Commit 3 inserts two lines in `src/main.rs` while keeping lines 1, 2, 3 from cs1 intact
    let cs3 = commit_files(
        &blobs,
        &meta,
        vec![cs2],
        "carol@inarch.dev",
        1_760_020_003,
        "enhance main.rs",
        vec![(
            "src/main.rs",
            Some(
                b"fn main() {\n    let x = 10;\n    println!(\"v1\");\n    println!(\"v3\");\n}\n",
            ),
        )],
    );

    let path = MPath::new("src/main.rs").unwrap();
    let blame = engine
        .blame_file(cs3, &path)
        .expect("derive and fetch BlameV2");

    assert_eq!(blame.lines.len(), 5);

    assert_eq!(blame.lines[0].line_number, 1);
    assert_eq!(blame.lines[0].content, "fn main() {");
    assert_eq!(blame.lines[0].changeset_id, cs1);
    assert_eq!(blame.lines[0].author, "alice@inarch.dev");
    assert_eq!(blame.lines[0].origin_line, 1);

    assert_eq!(blame.lines[1].line_number, 2);
    assert_eq!(blame.lines[1].content, "    let x = 10;");
    assert_eq!(blame.lines[1].changeset_id, cs3);
    assert_eq!(blame.lines[1].author, "carol@inarch.dev");
    assert_eq!(blame.lines[1].origin_line, 2);

    assert_eq!(blame.lines[2].line_number, 3);
    assert_eq!(blame.lines[2].content, "    println!(\"v1\");");
    assert_eq!(blame.lines[2].changeset_id, cs1);
    assert_eq!(blame.lines[2].author, "alice@inarch.dev");
    assert_eq!(blame.lines[2].origin_line, 2);

    assert_eq!(blame.lines[3].line_number, 4);
    assert_eq!(blame.lines[3].content, "    println!(\"v3\");");
    assert_eq!(blame.lines[3].changeset_id, cs3);
    assert_eq!(blame.lines[3].author, "carol@inarch.dev");
    assert_eq!(blame.lines[3].origin_line, 4);

    assert_eq!(blame.lines[4].line_number, 5);
    assert_eq!(blame.lines[4].content, "}");
    assert_eq!(blame.lines[4].changeset_id, cs1);
    assert_eq!(blame.lines[4].author, "alice@inarch.dev");
    assert_eq!(blame.lines[4].origin_line, 3);
}

#[test]
fn commit_graph_computes_generations_skip_pointers_and_answers_is_ancestor_and_lca() {
    let blobs = Arc::new(MemBlobStore::new());
    let meta = Arc::new(MemMetadataStore::new());
    let engine = DerivedDataEngine::new(Arc::clone(&blobs), Arc::clone(&meta));

    let mut linear = Vec::new();
    let mut prev: Option<ChangesetId> = None;
    for i in 0..64usize {
        let parents = prev.into_iter().collect::<Vec<_>>();
        let content = format!("v{}", i).into_bytes();
        let cs = commit_files(
            &blobs,
            &meta,
            parents,
            "dev@inarch.dev",
            1_760_030_000 + (i as i64),
            &format!("linear {}", i),
            vec![("version.txt", Some(&content))],
        );
        linear.push(cs);
        prev = Some(cs);
    }

    // Branch off linear[20]: b1 -> b2
    let b1 = commit_files(
        &blobs,
        &meta,
        vec![linear[20]],
        "branch@inarch.dev",
        1_760_031_001,
        "branch 1",
        vec![("branch.txt", Some(b"b1"))],
    );
    let b2 = commit_files(
        &blobs,
        &meta,
        vec![b1],
        "branch@inarch.dev",
        1_760_031_002,
        "branch 2",
        vec![("branch.txt", Some(b"b2"))],
    );

    // Merge commit m1 with parents [linear[63], b2]
    let m1 = commit_files(
        &blobs,
        &meta,
        vec![linear[63], b2],
        "merger@inarch.dev",
        1_760_031_003,
        "merge b2 into main",
        vec![("branch.txt", Some(b"b2"))],
    );

    let node_0 = engine.derive_commit_graph_node(linear[0]).unwrap();
    let node_63 = engine.derive_commit_graph_node(linear[63]).unwrap();
    let node_b2 = engine.derive_commit_graph_node(b2).unwrap();
    let node_m1 = engine.derive_commit_graph_node(m1).unwrap();

    assert_eq!(node_0.generation, 1);
    assert_eq!(node_63.generation, 64);
    assert_eq!(node_b2.generation, 23);
    assert_eq!(node_m1.generation, 65);

    // Binary lifting skip pointers on linear[63]: 2^0=62, 2^1=61, 2^2=59, 2^3=55, 2^4=47, 2^5=31
    assert_eq!(
        node_63.skip_ancestors,
        vec![
            linear[62], linear[61], linear[59], linear[55], linear[47], linear[31],
        ]
    );

    // O(log N) ancestry checks
    assert!(engine.is_ancestor(linear[0], linear[63]).unwrap());
    assert!(engine.is_ancestor(linear[20], linear[63]).unwrap());
    assert!(engine.is_ancestor(linear[20], b2).unwrap());
    assert!(!engine.is_ancestor(linear[21], b2).unwrap());
    assert!(!engine.is_ancestor(b1, linear[63]).unwrap());
    assert!(engine.is_ancestor(b2, m1).unwrap());
    assert!(engine.is_ancestor(linear[63], m1).unwrap());

    // Lowest Common Ancestor (merge-base)
    assert_eq!(
        engine.lowest_common_ancestor(linear[63], b2).unwrap(),
        Some(linear[20])
    );
    assert_eq!(
        engine
            .lowest_common_ancestor(linear[10], linear[50])
            .unwrap(),
        Some(linear[10])
    );
}

#[test]
fn merge_commit_fsnode_and_unode_inherit_secondary_parent_entries_and_subtrees() {
    let blobs = Arc::new(MemBlobStore::new());
    let meta = Arc::new(MemMetadataStore::new());
    let engine = DerivedDataEngine::new(Arc::clone(&blobs), Arc::clone(&meta));

    let base = commit_files(
        &blobs,
        &meta,
        vec![],
        "alice@inarch.dev",
        1_760_040_000,
        "base commit",
        vec![("crates/shared/lib.rs", Some(b"pub fn base() {}\n"))],
    );

    let p1 = commit_files(
        &blobs,
        &meta,
        vec![base],
        "bob@inarch.dev",
        1_760_040_001,
        "branch 1 adds p1.rs",
        vec![("crates/shared/p1.rs", Some(b"pub fn from_p1() {}\n"))],
    );

    let p2 = commit_files(
        &blobs,
        &meta,
        vec![base],
        "carol@inarch.dev",
        1_760_040_002,
        "branch 2 adds p2.rs and docs/guide.md",
        vec![
            ("crates/shared/p2.rs", Some(b"pub fn from_p2() {}\n")),
            ("docs/guide.md", Some(b"# Guide\n")),
        ],
    );

    // Merge commit lists no explicit file_changes for p2's untouched files
    let merge_cs = commit_files(
        &blobs,
        &meta,
        vec![p1, p2],
        "merger@inarch.dev",
        1_760_040_003,
        "merge p2 into p1",
        vec![],
    );

    let merge_root = engine.derive_fsnode(merge_cs).expect("derive merge fsnode");
    assert!(
        engine
            .lookup_fsnode_path(&merge_root, &MPath::new("crates/shared/p1.rs").unwrap())
            .unwrap()
            .is_some(),
        "primary parent file crates/shared/p1.rs must be present in merged Fsnode"
    );
    assert!(
        engine
            .lookup_fsnode_path(&merge_root, &MPath::new("crates/shared/p2.rs").unwrap())
            .unwrap()
            .is_some(),
        "secondary parent file crates/shared/p2.rs in shared subdirectory must be merged into Fsnode"
    );
    assert!(
        engine
            .lookup_fsnode_path(&merge_root, &MPath::new("docs/guide.md").unwrap())
            .unwrap()
            .is_some(),
        "secondary parent directory docs/guide.md must be merged into Fsnode"
    );

    // Verify Unode history on merge commit also tracks secondary parent files
    engine.derive_unode(merge_cs).expect("derive merge unode");
    let p2_hist = engine
        .file_history(merge_cs, &MPath::new("crates/shared/p2.rs").unwrap())
        .expect("file_history for p2.rs");
    assert_eq!(p2_hist, vec![p2]);
}

#[test]
fn path_search_glob_respects_directory_separators_and_canonical_decoders_reject_trailing_bytes() {
    use inarch_derived::{CopyDetectionReport, PathSearchEntry, PathSearchIndex};
    use inarch_types::hash::BlobId;

    let p_readme = MPath::new("README.md").unwrap();
    let p_lib = MPath::new("crates/core/src/lib.rs").unwrap();
    let p_core_readme = MPath::new("crates/core/README.md").unwrap();

    let idx = PathSearchIndex {
        entries: BTreeMap::from([
            (
                p_readme.clone(),
                PathSearchEntry {
                    path: p_readme,
                    size: 10,
                    file_type: FileType::Regular,
                    blob_id: BlobId::from_content(b"readme"),
                },
            ),
            (
                p_lib.clone(),
                PathSearchEntry {
                    path: p_lib,
                    size: 20,
                    file_type: FileType::Regular,
                    blob_id: BlobId::from_content(b"lib"),
                },
            ),
            (
                p_core_readme.clone(),
                PathSearchEntry {
                    path: p_core_readme,
                    size: 15,
                    file_type: FileType::Regular,
                    blob_id: BlobId::from_content(b"core-readme"),
                },
            ),
        ]),
    };

    // Full-path glob `crates/*/lib.rs` has `/` so it matches against full path; single `*` must NOT cross `/`
    let single_star = idx.search("crates/*/lib.rs", 10);
    assert!(
        single_star.is_empty(),
        "single * must not match across directory separator '/'"
    );

    // Double-star `crates/**/lib.rs` matches across zero or more directory segments
    let double_star = idx.search("crates/**/lib.rs", 10);
    assert_eq!(double_star.len(), 1);
    assert_eq!(double_star[0].path.as_str(), "crates/core/src/lib.rs");

    // `**/README.md` matches both root `README.md` and nested `crates/core/README.md`
    let root_or_nested = idx.search("**/README.md", 10);
    assert_eq!(root_or_nested.len(), 2);

    // Trailing bytes on PathSearchIndex canonical encoding must be rejected
    let mut idx_bytes = idx.to_canonical_bytes();
    idx_bytes.push(0xFF);
    assert!(PathSearchIndex::from_canonical_bytes(&idx_bytes).is_err());

    // Trailing bytes on CopyDetectionReport canonical encoding must be rejected
    let report = CopyDetectionReport {
        changeset_id: ChangesetId::from_canonical_bytes(b"dummy-cs"),
        records: vec![],
    };
    let mut report_bytes = report.to_canonical_bytes();
    report_bytes.push(0x00);
    assert!(CopyDetectionReport::from_canonical_bytes(&report_bytes).is_err());
}

#[test]
fn collect_commits_between_prunes_at_ancestor_generation_in_o_delta() {
    let blobs = Arc::new(MemBlobStore::new());
    let meta = Arc::new(MemMetadataStore::new());
    let engine = DerivedDataEngine::new(Arc::clone(&blobs), Arc::clone(&meta));

    let mut commits = Vec::with_capacity(120);
    let mut prev: Option<ChangesetId> = None;
    for i in 0..120usize {
        let parents = prev.into_iter().collect::<Vec<_>>();
        let content = format!("commit-body-{}\n", i).into_bytes();
        let cs = commit_files(
            &blobs,
            &meta,
            parents,
            "agent@inarch.dev",
            1_760_090_000 + (i as i64),
            &format!("commit {}", i),
            vec![("src/counter.txt", Some(&content))],
        );
        commits.push(cs);
        prev = Some(cs);
    }

    // Collect (commits[114]..commits[119]] -> should be exactly commits[115..=119] in oldest-first topological order
    let delta = engine
        .collect_commits_between(commits[114], commits[119])
        .expect("collect_commits_between")
        .expect("commits[114] is an ancestor of commits[119]");

    let delta_ids: Vec<ChangesetId> = delta.iter().map(|c| c.changeset_id()).collect();
    assert_eq!(delta_ids, commits[115..=119].to_vec());

    // Equal commits -> Some(empty)
    let empty_delta = engine
        .collect_commits_between(commits[50], commits[50])
        .expect("collect_commits_between equal")
        .expect("equal commits are ancestor");
    assert!(empty_delta.is_empty());

    // Reversed (not an ancestor) -> None
    let non_anc = engine
        .collect_commits_between(commits[100], commits[10])
        .expect("collect_commits_between reversed");
    assert!(non_anc.is_none());
}
