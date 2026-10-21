//! Comprehensive contract tests for `inarch-engine` (Iteration 4 — Slice 5):
//! - 50 concurrent AI agents all starting from the same stale `base_changeset` and landing
//!   disjoint file patches onto `main` via zero-tree-read speculative rebase + atomic CAS.
//! - True conflict refusal (`EngineError::MergeConflict`) when an intermediate commit in `(base..head]`
//!   touched an overlapping path or file/directory prefix.
//! - Checkout-free server API operations: `read_file`, `list_directory`, `diff_changesets`,
//!   `log_path`, and `blame`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread;

use inarch_engine::{
    ChangeKind, DiffEntry, EngineError, PatchFileEdit, PatchSubmission, ScionEngine,
};
use inarch_store::{MemBlobStore, MemMetadataStore};
use inarch_types::bonsai::FileType;
use inarch_types::path::MPath;

#[test]
fn fifty_concurrent_agents_from_same_base_land_disjoint_patches_via_speculative_rebase() {
    let engine = Arc::new(ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    ));

    // Seed commit on `main`
    let seed = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: None,
            author: "founder@inarch.dev".to_string(),
            timestamp: 1_760_100_000,
            tz_offset_secs: 0,
            message: "seed repository".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("README.md").unwrap(),
                content: b"# Velenza Inarch Monorepo\n".to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .expect("seed commit must land");

    assert_eq!(seed.rebased_across, 0);

    // Spawn 50 concurrent agent threads ALL referencing the exact same `base_changeset = Some(seed.changeset_id)`
    let mut handles = Vec::new();
    for agent_id in 0..50usize {
        let eng = Arc::clone(&engine);
        let seed_id = seed.changeset_id;
        handles.push(thread::spawn(move || {
            let path = MPath::new(&format!("crates/agent_{:02}/src/lib.rs", agent_id)).unwrap();
            let content = format!("pub const AGENT_ID: usize = {};\n", agent_id).into_bytes();
            eng.land_patch(PatchSubmission {
                target_ref: "main".to_string(),
                base_changeset: Some(seed_id),
                author: format!("agent-{}@inarch.dev", agent_id),
                timestamp: 1_760_100_001 + (agent_id as i64),
                tz_offset_secs: 0,
                message: format!("implement agent_{:02} crate", agent_id),
                extra: BTreeMap::new(),
                edits: vec![PatchFileEdit::Upsert {
                    path,
                    content,
                    file_type: FileType::Regular,
                }],
            })
        }));
    }

    let mut landed_outcomes = Vec::new();
    for h in handles {
        let outcome = h
            .join()
            .expect("agent thread panicked")
            .expect("disjoint agent patch must land via speculative rebase");
        landed_outcomes.push(outcome);
    }

    // Verify all 50 agents landed and at least one rebased across 49 intermediate commits
    let max_rebase_distance = landed_outcomes
        .iter()
        .map(|o| o.rebased_across)
        .max()
        .unwrap();
    assert_eq!(max_rebase_distance, 49);

    // Verify `main` is now at generation 51 and contains all 50 agent files + README.md
    let head_id = engine.resolve_ref("main").unwrap().unwrap();
    let head_node = engine
        .derived()
        .derive_commit_graph_node(head_id)
        .expect("derive commit graph at head");
    assert_eq!(head_node.generation, 51);

    for agent_id in 0..50usize {
        let path = MPath::new(&format!("crates/agent_{:02}/src/lib.rs", agent_id)).unwrap();
        let expected = format!("pub const AGENT_ID: usize = {};\n", agent_id).into_bytes();
        let actual = engine
            .read_file(head_id, &path)
            .expect("checkout-free read_file must succeed");
        assert_eq!(actual, expected);
    }
}

#[test]
fn conflicting_concurrent_patch_is_refused_with_exact_conflicting_paths_and_commit() {
    let engine = ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    );

    let seed = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: None,
            author: "founder@inarch.dev".to_string(),
            timestamp: 1_760_200_000,
            tz_offset_secs: 0,
            message: "seed config".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("crates/shared/config.toml").unwrap(),
                content: b"workers = 4\n".to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .unwrap();

    // Agent 1 lands an update to `crates/shared/config.toml` from `seed`
    let agent1 = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: Some(seed.changeset_id),
            author: "agent-1@inarch.dev".to_string(),
            timestamp: 1_760_200_001,
            tz_offset_secs: 0,
            message: "bump workers to 8".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("crates/shared/config.toml").unwrap(),
                content: b"workers = 8\n".to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .unwrap();

    // Agent 2 also based its patch on `seed` and touched `crates/shared/config.toml`
    let err = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: Some(seed.changeset_id),
            author: "agent-2@inarch.dev".to_string(),
            timestamp: 1_760_200_002,
            tz_offset_secs: 0,
            message: "bump workers to 16".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("crates/shared/config.toml").unwrap(),
                content: b"workers = 16\n".to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .expect_err("overlapping edit from stale base must be refused with MergeConflict");

    assert_eq!(
        err,
        EngineError::MergeConflict {
            base: seed.changeset_id,
            head: agent1.changeset_id,
            conflicting_changeset: agent1.changeset_id,
            conflicting_paths: vec![MPath::new("crates/shared/config.toml").unwrap()],
        }
    );
}

#[test]
fn checkout_free_read_list_diff_log_and_blame_operate_purely_against_stores() {
    let engine = ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    );

    let c1 = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: None,
            author: "alice@inarch.dev".to_string(),
            timestamp: 1_760_300_001,
            tz_offset_secs: 0,
            message: "initial commit".to_string(),
            extra: BTreeMap::new(),
            edits: vec![
                PatchFileEdit::Upsert {
                    path: MPath::new("README.md").unwrap(),
                    content: b"# Velenza Inarch\n".to_vec(),
                    file_type: FileType::Regular,
                },
                PatchFileEdit::Upsert {
                    path: MPath::new("src/lib.rs").unwrap(),
                    content: b"pub fn version() -> u32 {\n    1\n}\n".to_vec(),
                    file_type: FileType::Regular,
                },
                PatchFileEdit::Upsert {
                    path: MPath::new("src/legacy.rs").unwrap(),
                    content: b"// old\n".to_vec(),
                    file_type: FileType::Regular,
                },
            ],
        })
        .unwrap();

    let c2 = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: Some(c1.changeset_id),
            author: "bob@inarch.dev".to_string(),
            timestamp: 1_760_300_002,
            tz_offset_secs: 0,
            message: "upgrade version and remove legacy".to_string(),
            extra: BTreeMap::new(),
            edits: vec![
                PatchFileEdit::Upsert {
                    path: MPath::new("src/lib.rs").unwrap(),
                    content: b"pub fn version() -> u32 {\n    2\n}\n".to_vec(),
                    file_type: FileType::Regular,
                },
                PatchFileEdit::Upsert {
                    path: MPath::new("src/new_mod.rs").unwrap(),
                    content: b"pub const READY: bool = true;\n".to_vec(),
                    file_type: FileType::Regular,
                },
                PatchFileEdit::Delete {
                    path: MPath::new("src/legacy.rs").unwrap(),
                },
            ],
        })
        .unwrap();

    // 1. Checkout-free directory listing at root
    let root_listing = engine.list_directory(c2.changeset_id, None).unwrap();
    assert_eq!(root_listing.len(), 2); // README.md and src/

    // 2. Checkout-free Merkle diff between c1 and c2
    let diff = engine
        .diff_changesets(c1.changeset_id, c2.changeset_id)
        .unwrap();
    assert_eq!(
        diff,
        vec![
            DiffEntry {
                path: MPath::new("src/legacy.rs").unwrap(),
                kind: ChangeKind::Deleted,
            },
            DiffEntry {
                path: MPath::new("src/lib.rs").unwrap(),
                kind: ChangeKind::Modified,
            },
            DiffEntry {
                path: MPath::new("src/new_mod.rs").unwrap(),
                kind: ChangeKind::Added,
            },
        ]
    );

    // 3. Checkout-free O(k) path log
    let lib_log = engine
        .log_path(c2.changeset_id, &MPath::new("src/lib.rs").unwrap())
        .unwrap();
    assert_eq!(lib_log.len(), 2);
    assert_eq!(lib_log[0].changeset_id, c2.changeset_id);
    assert_eq!(lib_log[1].changeset_id, c1.changeset_id);

    // 4. Checkout-free BlameV2
    let blame = engine
        .blame(c2.changeset_id, &MPath::new("src/lib.rs").unwrap())
        .unwrap();
    assert_eq!(blame.lines.len(), 3);
    assert_eq!(blame.lines[0].author, "alice@inarch.dev");
    assert_eq!(blame.lines[1].author, "bob@inarch.dev");
    assert_eq!(blame.lines[2].author, "alice@inarch.dev");
}

#[test]
fn same_file_disjoint_line_edits_auto_merge_via_three_way_merge_while_overlapping_lines_conflict() {
    let engine = ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    );

    let base_file = "\
pub fn alpha() -> u32 {
    1
}

pub fn middle_invariant() -> &'static str {
    \"untouched\"
}

pub fn omega() -> u32 {
    100
}
";

    let seed = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: None,
            author: "founder@inarch.dev".to_string(),
            timestamp: 1_760_400_000,
            tz_offset_secs: 0,
            message: "seed shared lib.rs".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("src/lib.rs").unwrap(),
                content: base_file.as_bytes().to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .expect("seed commit");

    // Agent 1 edits `alpha()` at top of `src/lib.rs` based on `seed`
    let agent1_file = "\
pub fn alpha() -> u32 {
    2
}

pub fn middle_invariant() -> &'static str {
    \"untouched\"
}

pub fn omega() -> u32 {
    100
}
";
    let c1 = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: Some(seed.changeset_id),
            author: "agent-1@inarch.dev".to_string(),
            timestamp: 1_760_400_001,
            tz_offset_secs: 0,
            message: "update alpha to 2".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("src/lib.rs").unwrap(),
                content: agent1_file.as_bytes().to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .expect("agent 1 lands cleanly");

    // Agent 2 ALSO based on `seed` edits `omega()` at bottom of `src/lib.rs` (disjoint lines!)
    let agent2_file = "\
pub fn alpha() -> u32 {
    1
}

pub fn middle_invariant() -> &'static str {
    \"untouched\"
}

pub fn omega() -> u32 {
    200
}
";
    let c2 = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: Some(seed.changeset_id),
            author: "agent-2@inarch.dev".to_string(),
            timestamp: 1_760_400_002,
            tz_offset_secs: 0,
            message: "update omega to 200".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("src/lib.rs").unwrap(),
                content: agent2_file.as_bytes().to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .expect("agent 2 disjoint line edit in same file must auto-merge via 3-way merge");

    assert_eq!(c2.rebased_across, 1);

    let merged_bytes = engine
        .read_file(c2.changeset_id, &MPath::new("src/lib.rs").unwrap())
        .expect("read merged src/lib.rs");
    let merged_str = std::str::from_utf8(&merged_bytes).unwrap();
    let expected_merged = "\
pub fn alpha() -> u32 {
    2
}

pub fn middle_invariant() -> &'static str {
    \"untouched\"
}

pub fn omega() -> u32 {
    200
}
";
    assert_eq!(merged_str, expected_merged);

    // Agent 3 ALSO based on `seed` edits `alpha()` to 999 (overlapping line with Agent 1!) -> must fail with MergeConflict
    let agent3_file = "\
pub fn alpha() -> u32 {
    999
}

pub fn middle_invariant() -> &'static str {
    \"untouched\"
}

pub fn omega() -> u32 {
    100
}
";
    let err = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: Some(seed.changeset_id),
            author: "agent-3@inarch.dev".to_string(),
            timestamp: 1_760_400_003,
            tz_offset_secs: 0,
            message: "conflicting edit to alpha".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("src/lib.rs").unwrap(),
                content: agent3_file.as_bytes().to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .expect_err("overlapping same-line edit must fail with MergeConflict");

    assert_eq!(
        err,
        EngineError::MergeConflict {
            base: seed.changeset_id,
            head: c2.changeset_id,
            conflicting_changeset: c1.changeset_id,
            conflicting_paths: vec![MPath::new("src/lib.rs").unwrap()],
        }
    );
}

#[test]
fn engine_enforces_longest_prefix_path_acl_rules_during_land_patch() {
    use inarch_engine::EnginePathAclRule;

    let engine = ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    );

    engine.set_acl_rules(vec![
        EnginePathAclRule {
            prefix: "".to_string(),
            allowed_actors: vec!["*".to_string()],
        },
        EnginePathAclRule {
            prefix: "crates/kernel".to_string(),
            allowed_actors: vec![
                "kernel-lead@inarch.dev".to_string(),
                "security-bot@inarch.dev".to_string(),
            ],
        },
        EnginePathAclRule {
            prefix: "crates/kernel/tests".to_string(),
            allowed_actors: vec![
                "kernel-lead@inarch.dev".to_string(),
                "qa-agent@inarch.dev".to_string(),
            ],
        },
    ]);

    // 1. General agent can write outside crates/kernel
    engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: None,
            author: "worker-1@inarch.dev".to_string(),
            timestamp: 1_760_500_000,
            tz_offset_secs: 0,
            message: "add docs".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("docs/architecture.md").unwrap(),
                content: b"# Architecture\n".to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .expect("worker-1 allowed by root wildcard rule");

    // 2. General agent is denied writing to `crates/kernel/src/lib.rs`
    let denied = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: engine.resolve_ref("main").unwrap(),
            author: "worker-1@inarch.dev".to_string(),
            timestamp: 1_760_500_001,
            tz_offset_secs: 0,
            message: "unauthorized kernel edit".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("crates/kernel/src/lib.rs").unwrap(),
                content: b"pub fn kernel() {}\n".to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .expect_err("worker-1 must be denied by crates/kernel ACL rule");

    assert_eq!(
        denied,
        EngineError::AclDenied {
            actor: "worker-1@inarch.dev".to_string(),
            path: MPath::new("crates/kernel/src/lib.rs").unwrap(),
            matched_prefix: "crates/kernel".to_string(),
        }
    );

    // 3. `qa-agent@inarch.dev` can write to `crates/kernel/tests/smoke.rs` (longest prefix match)
    let (_, retries) = engine
        .land_patch_with_stats(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: engine.resolve_ref("main").unwrap(),
            author: "qa-agent@inarch.dev".to_string(),
            timestamp: 1_760_500_002,
            tz_offset_secs: 0,
            message: "add kernel smoke test".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("crates/kernel/tests/smoke.rs").unwrap(),
                content: b"#[test] fn smoke() {}\n".to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .expect("qa-agent allowed by more specific crates/kernel/tests ACL rule");
    assert_eq!(retries, 0);
}
