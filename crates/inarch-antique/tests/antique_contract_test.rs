//! Comprehensive contract tests for `inarch-antique` (Iteration 5 — Slice 6):
//! - Directory-level ACL policy (`PathAclPolicy`) with longest-prefix matching.
//! - Antique intent-based `SemanticApproval` rules (`ExactDelta` and `ScopedPaths`) that survive
//!   lock-free rebases and in-scope amendments while automatically invalidating on scope creep.
//! - Post-merge $O(\log N)$ automated binary-search regression bisect (`bisect_regression`).
//! - Instant checkout-free server-side revert (`revert_changeset`) that restores modified/deleted
//!   files and removes newly added files from a culprit commit while preserving later disjoint commits.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use inarch_antique::{
    AntiqueError, AntiqueService, ApprovalConstraint, ApprovalStatus, PathAclPolicy, PathAclRule,
    SemanticApproval,
};
use inarch_engine::{PatchFileEdit, PatchSubmission, ScionEngine};
use inarch_store::{MemBlobStore, MemMetadataStore};
use inarch_types::bonsai::{BonsaiChangeset, FileChange, FileType};
use inarch_types::hash::{BlobId, ChangesetId};
use inarch_types::path::MPath;

#[test]
fn directory_acl_enforces_longest_prefix_rule_and_blocks_unauthorized_agents() {
    let mut policy = PathAclPolicy::new();
    // Root allows any authenticated agent/engineer
    policy.add_rule(PathAclRule {
        prefix: None,
        allowed_actors: BTreeSet::from(["*".to_string()]),
        required_reviewers: BTreeSet::new(),
    });
    // `crates/kernel/crypto` is restricted to crypto owners
    policy.add_rule(PathAclRule {
        prefix: Some(MPath::new("crates/kernel/crypto").unwrap()),
        allowed_actors: BTreeSet::from([
            "security-lead@inarch.dev".to_string(),
            "crypto-agent@inarch.dev".to_string(),
        ]),
        required_reviewers: BTreeSet::from(["security-lead@inarch.dev".to_string()]),
    });

    let dummy_blob = BlobId::from_content(b"code");

    // 1. UI agent modifying `crates/ui/view.rs` is allowed by root rule
    let ui_cs = BonsaiChangeset::new(
        vec![],
        "ui-agent@inarch.dev".to_string(),
        1_760_400_001,
        0,
        "update UI view".to_string(),
        BTreeMap::new(),
        BTreeMap::from([(
            MPath::new("crates/ui/view.rs").unwrap(),
            FileChange::Tracked {
                blob_id: dummy_blob,
                size: 4,
                file_type: FileType::Regular,
            },
        )]),
    )
    .unwrap();
    assert_eq!(policy.evaluate_changeset(&ui_cs), Ok(()));

    // 2. Crypto agent modifying `crates/kernel/crypto/mldsa.rs` is allowed by specific prefix rule
    let crypto_cs = BonsaiChangeset::new(
        vec![],
        "crypto-agent@inarch.dev".to_string(),
        1_760_400_002,
        0,
        "tune ML-DSA-65".to_string(),
        BTreeMap::new(),
        BTreeMap::from([(
            MPath::new("crates/kernel/crypto/mldsa.rs").unwrap(),
            FileChange::Tracked {
                blob_id: dummy_blob,
                size: 4,
                file_type: FileType::Regular,
            },
        )]),
    )
    .unwrap();
    assert_eq!(policy.evaluate_changeset(&crypto_cs), Ok(()));

    // 3. UI agent attempting to touch `crates/kernel/crypto/mldsa.rs` is refused!
    let unauthorized_cs = BonsaiChangeset::new(
        vec![],
        "ui-agent@inarch.dev".to_string(),
        1_760_400_003,
        0,
        "sneaky edit to crypto".to_string(),
        BTreeMap::new(),
        BTreeMap::from([(
            MPath::new("crates/kernel/crypto/mldsa.rs").unwrap(),
            FileChange::Tracked {
                blob_id: dummy_blob,
                size: 4,
                file_type: FileType::Regular,
            },
        )]),
    )
    .unwrap();
    assert_eq!(
        policy.evaluate_changeset(&unauthorized_cs),
        Err(AntiqueError::AclDenied {
            actor: "ui-agent@inarch.dev".to_string(),
            path: MPath::new("crates/kernel/crypto/mldsa.rs").unwrap(),
            rule_prefix: Some(MPath::new("crates/kernel/crypto").unwrap()),
        })
    );
}

#[test]
fn semantic_approvals_survive_rebase_and_in_scope_amend_but_invalidate_on_scope_creep() {
    let b1 = BlobId::from_content(b"fn index() {}");
    let b2 = BlobId::from_content(b"fn query() {}");
    let p_parent1 = ChangesetId::from_canonical_bytes(b"parent-1");
    let p_parent2 = ChangesetId::from_canonical_bytes(b"parent-2");

    let cs_v1 = BonsaiChangeset::new(
        vec![p_parent1],
        "agent@inarch.dev".to_string(),
        1_760_410_001,
        0,
        "search index".to_string(),
        BTreeMap::new(),
        BTreeMap::from([(
            MPath::new("crates/search/index.rs").unwrap(),
            FileChange::Tracked {
                blob_id: b1,
                size: 13,
                file_type: FileType::Regular,
            },
        )]),
    )
    .unwrap();

    let exact_approval = SemanticApproval::new(
        "reviewer@inarch.dev".to_string(),
        &cs_v1,
        ApprovalConstraint::ExactDelta,
    );
    let scoped_approval = SemanticApproval::new(
        "reviewer@inarch.dev".to_string(),
        &cs_v1,
        ApprovalConstraint::ScopedPaths {
            allowed_prefixes: vec![MPath::new("crates/search").unwrap()],
            max_files: 3,
        },
    );

    // 1. Rebase `cs_v1` onto `p_parent2` (changes commit hash, keeps `file_changes` identical)
    let cs_rebased = cs_v1.with_parents(vec![p_parent2]).unwrap();
    assert_ne!(cs_v1.changeset_id(), cs_rebased.changeset_id());
    assert_eq!(exact_approval.evaluate(&cs_rebased), ApprovalStatus::Valid);
    assert_eq!(scoped_approval.evaluate(&cs_rebased), ApprovalStatus::Valid);

    // 2. In-scope amendment: add `crates/search/query.rs` (still within `crates/search`, 2 <= 3 files)
    let cs_amended_in_scope = BonsaiChangeset::new(
        vec![p_parent2],
        "agent@inarch.dev".to_string(),
        1_760_410_002,
        0,
        "search index + query lint fix".to_string(),
        BTreeMap::new(),
        BTreeMap::from([
            (
                MPath::new("crates/search/index.rs").unwrap(),
                FileChange::Tracked {
                    blob_id: b1,
                    size: 13,
                    file_type: FileType::Regular,
                },
            ),
            (
                MPath::new("crates/search/query.rs").unwrap(),
                FileChange::Tracked {
                    blob_id: b2,
                    size: 13,
                    file_type: FileType::Regular,
                },
            ),
        ]),
    )
    .unwrap();
    assert!(matches!(
        exact_approval.evaluate(&cs_amended_in_scope),
        ApprovalStatus::Invalidated(_)
    ));
    assert_eq!(
        scoped_approval.evaluate(&cs_amended_in_scope),
        ApprovalStatus::Valid
    );

    // 3. Out-of-scope amendment: touches `crates/billing/invoice.rs`
    let cs_out_of_scope = BonsaiChangeset::new(
        vec![p_parent2],
        "agent@inarch.dev".to_string(),
        1_760_410_003,
        0,
        "touch billing".to_string(),
        BTreeMap::new(),
        BTreeMap::from([
            (
                MPath::new("crates/search/index.rs").unwrap(),
                FileChange::Tracked {
                    blob_id: b1,
                    size: 13,
                    file_type: FileType::Regular,
                },
            ),
            (
                MPath::new("crates/billing/invoice.rs").unwrap(),
                FileChange::Tracked {
                    blob_id: b2,
                    size: 13,
                    file_type: FileType::Regular,
                },
            ),
        ]),
    )
    .unwrap();
    assert_eq!(
        scoped_approval.evaluate(&cs_out_of_scope),
        ApprovalStatus::Invalidated(
            "path 'crates/billing/invoice.rs' is outside approved prefixes".to_string()
        )
    );
}

#[test]
fn post_merge_bisect_pinpoints_regression_in_o_log_n_and_instant_revert_restores_main() {
    let engine = Arc::new(ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    ));
    let antique = AntiqueService::new(Arc::clone(&engine));

    let scheduler_path = MPath::new("crates/runtime/scheduler.rs").unwrap();
    let bad_helper_path = MPath::new("crates/runtime/bad_helper.rs").unwrap();

    let mut commits = Vec::new();
    let mut prev: Option<ChangesetId> = None;

    for i in 0..64usize {
        let mut edits = Vec::new();
        if i == 0 {
            edits.push(PatchFileEdit::Upsert {
                path: scheduler_path.clone(),
                content: b"pub const MAX_TICKS: u64 = 100;\n".to_vec(),
                file_type: FileType::Regular,
            });
        } else if i == 41 {
            // Commit 41 introduces the regression in `scheduler.rs` and adds `bad_helper.rs`
            edits.push(PatchFileEdit::Upsert {
                path: scheduler_path.clone(),
                content: b"pub const MAX_TICKS: u64 = 0; // BUG\n".to_vec(),
                file_type: FileType::Regular,
            });
            edits.push(PatchFileEdit::Upsert {
                path: bad_helper_path.clone(),
                content: b"pub fn broken() {}\n".to_vec(),
                file_type: FileType::Regular,
            });
        } else {
            edits.push(PatchFileEdit::Upsert {
                path: MPath::new(&format!("crates/metrics/m_{:02}.rs", i)).unwrap(),
                content: format!("pub const M: usize = {};\n", i).into_bytes(),
                file_type: FileType::Regular,
            });
        }

        let outcome = engine
            .land_patch(PatchSubmission {
                target_ref: "main".to_string(),
                base_changeset: prev,
                author: format!("agent-{}@inarch.dev", i),
                timestamp: 1_760_500_000 + (i as i64),
                tz_offset_secs: 0,
                message: format!("commit {}", i),
                extra: BTreeMap::new(),
                edits,
            })
            .unwrap();
        commits.push(outcome.changeset_id);
        prev = Some(outcome.changeset_id);
    }

    // 1. Run O(log N) automated bisect between good = commits[0] and bad = commits[63]
    let bisect = antique
        .bisect_regression(commits[0], commits[63], |cs_id| {
            let bytes = engine
                .read_file(cs_id, &scheduler_path)
                .map_err(|e| e.to_string())?;
            Ok(bytes == b"pub const MAX_TICKS: u64 = 100;\n")
        })
        .expect("bisect_regression must succeed");

    assert_eq!(
        bisect.culprit, commits[41],
        "bisect must pinpoint commit 41 as the exact first bad commit"
    );
    assert!(
        bisect.probes_executed <= 6,
        "binary search over 63 commits must execute at most 6 probes, got {}",
        bisect.probes_executed
    );

    // 2. Instant server-side revert of `commits[41]` onto `main`
    let revert_outcome = antique
        .revert_changeset("main", commits[41], "autorevert@inarch.dev", 1_760_501_000)
        .expect("server-side revert of commit 41 must land cleanly on main");

    let new_head = revert_outcome.changeset_id;

    // Verify `scheduler.rs` is restored to its pre-commit-41 state
    assert_eq!(
        engine.read_file(new_head, &scheduler_path).unwrap(),
        b"pub const MAX_TICKS: u64 = 100;\n"
    );
    // Verify `bad_helper.rs` added by commit 41 was deleted by the revert
    assert!(engine.read_file(new_head, &bad_helper_path).is_err());
    // Verify commits 42..63 that landed after commit 41 are still intact on `main`!
    assert_eq!(
        engine
            .read_file(new_head, &MPath::new("crates/metrics/m_63.rs").unwrap())
            .unwrap(),
        b"pub const M: usize = 63;\n"
    );
}

#[test]
fn revert_changeset_restores_directory_subtree_when_culprit_replaced_dir_with_file() {
    let engine = Arc::new(ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    ));
    let antique = AntiqueService::new(Arc::clone(&engine));

    let nested_a = MPath::new("config/routes/api.toml").unwrap();
    let nested_b = MPath::new("config/routes/admin.toml").unwrap();
    let dir_as_file = MPath::new("config").unwrap();

    // Commit 1 creates `config/routes/api.toml` and `config/routes/admin.toml`
    let c1 = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: None,
            author: "alice@inarch.dev".to_string(),
            timestamp: 1_760_600_001,
            tz_offset_secs: 0,
            message: "seed config directory".to_string(),
            extra: BTreeMap::new(),
            edits: vec![
                PatchFileEdit::Upsert {
                    path: nested_a.clone(),
                    content: b"port = 8080\n".to_vec(),
                    file_type: FileType::Regular,
                },
                PatchFileEdit::Upsert {
                    path: nested_b.clone(),
                    content: b"port = 9090\n".to_vec(),
                    file_type: FileType::Regular,
                },
            ],
        })
        .unwrap();

    // Commit 2 replaces the directory `config` with a single file `config` (without explicitly listing deletes for nested files)
    let c2 = engine
        .land_patch(PatchSubmission {
            target_ref: "main".to_string(),
            base_changeset: Some(c1.changeset_id),
            author: "bob@inarch.dev".to_string(),
            timestamp: 1_760_600_002,
            tz_offset_secs: 0,
            message: "replace config dir with flat file".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: dir_as_file.clone(),
                content: b"flat_config = true\n".to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .unwrap();

    assert!(engine.read_file(c2.changeset_id, &nested_a).is_err());
    assert_eq!(
        engine.read_file(c2.changeset_id, &dir_as_file).unwrap(),
        b"flat_config = true\n"
    );

    // Reverting Commit 2 must delete the flat file `config` and restore both `config/routes/api.toml` and `config/routes/admin.toml`
    let reverted = antique
        .revert_changeset("main", c2.changeset_id, "revert@inarch.dev", 1_760_600_003)
        .expect("revert directory-to-file replacement");

    assert!(
        engine
            .read_file(reverted.changeset_id, &dir_as_file)
            .is_err()
    );
    assert_eq!(
        engine.read_file(reverted.changeset_id, &nested_a).unwrap(),
        b"port = 8080\n"
    );
    assert_eq!(
        engine.read_file(reverted.changeset_id, &nested_b).unwrap(),
        b"port = 9090\n"
    );
}
