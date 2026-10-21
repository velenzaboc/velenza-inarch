//! Antique Intent-Based Code Review, Directory ACL Policy, Semantic Approvals,
//! Post-Merge $O(\log N)$ Automated Bisect, and Instant Server-Side Revert (`inarch-antique`).
//!
//! Modeled on Anthropic's **Antique** companion to Scion:
//! - **Directory ACLs (`PathAclPolicy`)**: Longest-prefix path ownership enforcement so AI agents
//!   and engineers can only modify authorized subtrees.
//! - **Semantic Approvals (`SemanticApproval`)**: Intent-based approvals (`ExactDelta` or `ScopedPaths`)
//!   that survive lock-free rebases and in-scope amendments without requiring re-review.
//! - **Post-Merge $O(\log N)$ Bisect (`bisect_regression`)**: Binary-searches the commit chain
//!   between a known-good checkpoint and a failing checkpoint to pinpoint the exact culprit commit.
//! - **Instant Server-Side Revert (`revert_changeset`)**: Synthesizes and lands an inverse
//!   `BonsaiChangeset` directly on the server without checking out a working copy.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use inarch_derived::FsnodeEntry;
use inarch_engine::{EngineError, LandOutcome, PatchFileEdit, PatchSubmission, ScionEngine};
use inarch_types::bonsai::{BonsaiChangeset, FileChange};
use inarch_types::hash::ChangesetId;
use inarch_types::path::MPath;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AntiqueError {
    Engine(EngineError),
    AclDenied {
        actor: String,
        path: MPath,
        rule_prefix: Option<MPath>,
    },
    InvalidBisectRange {
        good: ChangesetId,
        bad: ChangesetId,
    },
    MergeRevertUnsupported {
        culprit: ChangesetId,
        parent_count: usize,
    },
    BisectPredicateError(String),
}

impl fmt::Display for AntiqueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(e) => write!(f, "engine error: {}", e),
            Self::AclDenied {
                actor,
                path,
                rule_prefix,
            } => write!(
                f,
                "ACL denied for actor '{}' on path '{}' (matched rule prefix: {:?})",
                actor, path, rule_prefix
            ),
            Self::InvalidBisectRange { good, bad } => {
                write!(f, "invalid bisect range ({}..{}]", good, bad)
            }
            Self::MergeRevertUnsupported {
                culprit,
                parent_count,
            } => write!(
                f,
                "cannot revert merge changeset {} with {} parents; only root or single-parent changesets can be reverted automatically",
                culprit, parent_count
            ),
            Self::BisectPredicateError(msg) => write!(f, "bisect predicate failed: {}", msg),
        }
    }
}

impl std::error::Error for AntiqueError {}

impl From<EngineError> for AntiqueError {
    fn from(e: EngineError) -> Self {
        Self::Engine(e)
    }
}

/// A directory-level ACL rule matching all paths under `prefix` (`None` matches the repository root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathAclRule {
    pub prefix: Option<MPath>,
    pub allowed_actors: BTreeSet<String>,
    pub required_reviewers: BTreeSet<String>,
}

/// Policy enforcing longest-prefix directory ACL rules across a monorepo.
#[derive(Debug, Clone, Default)]
pub struct PathAclPolicy {
    rules: Vec<PathAclRule>,
}

impl PathAclPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: PathAclRule) {
        self.rules.push(rule);
    }

    /// Finds the most specific (longest-prefix) rule matching `path`.
    pub fn matching_rule(&self, path: &MPath) -> Option<&PathAclRule> {
        self.rules
            .iter()
            .filter(|r| match &r.prefix {
                Some(p) => p.is_prefix_of(path),
                None => true,
            })
            .max_by_key(|r| r.prefix.as_ref().map(|p| p.depth()).unwrap_or(0))
    }

    /// Verifies that `changeset.author` is authorized to modify every path in `changeset.file_changes`.
    pub fn evaluate_changeset(&self, changeset: &BonsaiChangeset) -> Result<(), AntiqueError> {
        for path in changeset.file_changes.keys() {
            if let Some(rule) = self.matching_rule(path) {
                let allowed = rule.allowed_actors.contains("*")
                    || rule.allowed_actors.contains(&changeset.author);
                if !allowed {
                    return Err(AntiqueError::AclDenied {
                        actor: changeset.author.clone(),
                        path: path.clone(),
                        rule_prefix: rule.prefix.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Constraint governing when a [`SemanticApproval`] remains valid across rebases or amendments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalConstraint {
    /// Approval remains valid across any parent rebase as long as `file_changes` is identical.
    ExactDelta,
    /// Approval remains valid across rebases and amendments as long as every modified path
    /// is under one of `allowed_prefixes` and total modified files $\le$ `max_files`.
    ScopedPaths {
        allowed_prefixes: Vec<MPath>,
        max_files: usize,
    },
}

/// Result of evaluating a [`SemanticApproval`] against an updated [`BonsaiChangeset`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStatus {
    Valid,
    Invalidated(String),
}

/// Intent-based code review approval that binds to semantic constraints rather than a static commit SHA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticApproval {
    pub reviewer: String,
    pub original_changeset_id: ChangesetId,
    pub original_file_changes: BTreeMap<MPath, FileChange>,
    pub constraint: ApprovalConstraint,
}

impl SemanticApproval {
    pub fn new(
        reviewer: String,
        original: &BonsaiChangeset,
        constraint: ApprovalConstraint,
    ) -> Self {
        Self {
            reviewer,
            original_changeset_id: original.changeset_id(),
            original_file_changes: original.file_changes.clone(),
            constraint,
        }
    }

    pub fn evaluate(&self, candidate: &BonsaiChangeset) -> ApprovalStatus {
        match &self.constraint {
            ApprovalConstraint::ExactDelta => {
                if candidate.file_changes == self.original_file_changes {
                    ApprovalStatus::Valid
                } else {
                    ApprovalStatus::Invalidated(
                        "file delta changed under ExactDelta approval".to_string(),
                    )
                }
            }
            ApprovalConstraint::ScopedPaths {
                allowed_prefixes,
                max_files,
            } => {
                if candidate.file_changes.len() > *max_files {
                    return ApprovalStatus::Invalidated(format!(
                        "changeset modifies {} files, exceeding approved max_files {}",
                        candidate.file_changes.len(),
                        max_files
                    ));
                }
                for path in candidate.file_changes.keys() {
                    let in_scope = allowed_prefixes.iter().any(|p| p.is_prefix_of(path));
                    if !in_scope {
                        return ApprovalStatus::Invalidated(format!(
                            "path '{}' is outside approved prefixes",
                            path
                        ));
                    }
                }
                ApprovalStatus::Valid
            }
        }
    }
}

/// Outcome of an automated $O(\log N)$ post-merge regression bisect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BisectOutcome {
    pub culprit: ChangesetId,
    pub probes_executed: usize,
    pub probed_commits: Vec<ChangesetId>,
}

/// Server-side Antique coordinator for post-merge bisect and instant checkout-free reverts.
pub struct AntiqueService {
    engine: Arc<ScionEngine>,
}

impl AntiqueService {
    pub fn new(engine: Arc<ScionEngine>) -> Self {
        Self { engine }
    }

    /// Binary-searches the commit chain `(good..bad]` in $O(\log N)$ probes to find the first
    /// commit where `is_good(changeset_id)` returns `Ok(false)`.
    pub fn bisect_regression<F>(
        &self,
        good: ChangesetId,
        bad: ChangesetId,
        mut is_good: F,
    ) -> Result<BisectOutcome, AntiqueError>
    where
        F: FnMut(ChangesetId) -> Result<bool, String>,
    {
        if good == bad
            || !self
                .engine
                .derived()
                .is_ancestor(good, bad)
                .map_err(EngineError::Derived)?
        {
            return Err(AntiqueError::InvalidBisectRange { good, bad });
        }

        // Collect the ordered first-parent chain in `(good..bad]` from oldest to newest
        let mut chain = Vec::new();
        let mut curr = bad;
        while curr != good {
            chain.push(curr);
            let cs = self
                .engine
                .meta()
                .get_changeset(&curr)
                .map_err(EngineError::Store)?
                .ok_or(EngineError::UnknownChangeset(curr))?;
            let Some(&first_parent) = cs.parents.first() else {
                return Err(AntiqueError::InvalidBisectRange { good, bad });
            };
            curr = first_parent;
        }
        chain.reverse(); // chain[0] is child of `good`, chain[len - 1] is `bad`

        let mut lo = 0usize;
        let mut hi = chain.len() - 1;
        let mut probed_commits = Vec::new();

        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let candidate = chain[mid];
            probed_commits.push(candidate);
            let healthy = is_good(candidate).map_err(AntiqueError::BisectPredicateError)?;
            if healthy {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        Ok(BisectOutcome {
            culprit: chain[lo],
            probes_executed: probed_commits.len(),
            probed_commits,
        })
    }

    /// Synthesizes and lands an inverse `BonsaiChangeset` reverting `culprit_id` onto `target_ref`
    /// without checking out a working copy.
    ///
    /// Uses `culprit_id` as the `base_changeset` for `land_patch`, which automatically verifies
    /// via `ScionEngine`'s speculative rebase that no subsequent commit after `culprit_id`
    /// modified any of the reverted paths!
    pub fn revert_changeset(
        &self,
        target_ref: &str,
        culprit_id: ChangesetId,
        author: &str,
        timestamp: i64,
    ) -> Result<LandOutcome, AntiqueError> {
        let culprit = self
            .engine
            .meta()
            .get_changeset(&culprit_id)
            .map_err(EngineError::Store)?
            .ok_or(EngineError::UnknownChangeset(culprit_id))?;

        if culprit.parents.len() > 1 {
            return Err(AntiqueError::MergeRevertUnsupported {
                culprit: culprit_id,
                parent_count: culprit.parents.len(),
            });
        }

        let parent_fsnode = if let Some(&first_parent) = culprit.parents.first() {
            Some(
                self.engine
                    .derived()
                    .derive_fsnode(first_parent)
                    .map_err(EngineError::Derived)?,
            )
        } else {
            None
        };

        let mut edits_by_path: BTreeMap<MPath, PatchFileEdit> = BTreeMap::new();
        for path in culprit.file_changes.keys() {
            let prior_entry = if let Some(ref p_root) = parent_fsnode {
                self.engine
                    .derived()
                    .lookup_fsnode_path(p_root, path)
                    .map_err(EngineError::Derived)?
            } else {
                None
            };

            match prior_entry {
                Some(FsnodeEntry::File {
                    blob_id, file_type, ..
                }) => {
                    let prior_bytes = self
                        .engine
                        .blobs()
                        .get_blob_content(&blob_id)
                        .map_err(EngineError::Store)?
                        .ok_or_else(|| EngineError::PathNotFound(path.as_str().to_string()))?;
                    edits_by_path.insert(
                        path.clone(),
                        PatchFileEdit::Upsert {
                            path: path.clone(),
                            content: prior_bytes,
                            file_type,
                        },
                    );
                }
                Some(FsnodeEntry::Directory { fsnode_id, .. }) => {
                    edits_by_path
                        .insert(path.clone(), PatchFileEdit::Delete { path: path.clone() });
                    self.collect_fsnode_subtree_upserts(&fsnode_id, path, &mut edits_by_path)?;
                }
                None => {
                    edits_by_path
                        .insert(path.clone(), PatchFileEdit::Delete { path: path.clone() });
                    if let Some(ref p_root) = parent_fsnode {
                        let elems = path.elements();
                        let mut prefix_str = String::new();
                        for (idx, elem) in elems[..elems.len().saturating_sub(1)].iter().enumerate()
                        {
                            if idx > 0 {
                                prefix_str.push('/');
                            }
                            prefix_str.push_str(elem.as_str());
                            if let Ok(anc_path) = MPath::new(&prefix_str)
                                && let Some(FsnodeEntry::File {
                                    blob_id, file_type, ..
                                }) = self
                                    .engine
                                    .derived()
                                    .lookup_fsnode_path(p_root, &anc_path)
                                    .map_err(EngineError::Derived)?
                            {
                                let prior_bytes = self
                                    .engine
                                    .blobs()
                                    .get_blob_content(&blob_id)
                                    .map_err(EngineError::Store)?
                                    .ok_or_else(|| {
                                        EngineError::PathNotFound(anc_path.as_str().to_string())
                                    })?;
                                edits_by_path.insert(
                                    anc_path.clone(),
                                    PatchFileEdit::Upsert {
                                        path: anc_path,
                                        content: prior_bytes,
                                        file_type,
                                    },
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }

        let edits: Vec<PatchFileEdit> = edits_by_path.into_values().collect();

        let head = self
            .engine
            .resolve_ref(target_ref)?
            .ok_or_else(|| EngineError::UnknownRef(target_ref.to_string()))?;

        // Base the revert on `culprit_id` if `culprit_id == head`, or on `culprit_id` so speculative rebase
        // verifies that no commit in `(culprit_id..head]` touched the reverted files!
        let outcome = self.engine.land_patch(PatchSubmission {
            target_ref: target_ref.to_string(),
            base_changeset: Some(if culprit_id == head { head } else { culprit_id }),
            author: author.to_string(),
            timestamp,
            tz_offset_secs: 0,
            message: format!("Revert {}", culprit_id),
            extra: BTreeMap::new(),
            edits,
        })?;

        Ok(outcome)
    }

    fn collect_fsnode_subtree_upserts(
        &self,
        fsnode_id: &inarch_types::hash::FsnodeId,
        prefix: &MPath,
        edits_by_path: &mut BTreeMap<MPath, PatchFileEdit>,
    ) -> Result<(), EngineError> {
        let node = self
            .engine
            .derived()
            .load_fsnode(fsnode_id)
            .map_err(EngineError::Derived)?;
        for (elem, entry) in node.entries {
            let child_path = prefix.join_element(&elem);
            match entry {
                FsnodeEntry::File {
                    blob_id, file_type, ..
                } => {
                    let bytes = self
                        .engine
                        .blobs()
                        .get_blob_content(&blob_id)
                        .map_err(EngineError::Store)?
                        .ok_or_else(|| {
                            EngineError::PathNotFound(child_path.as_str().to_string())
                        })?;
                    edits_by_path.insert(
                        child_path.clone(),
                        PatchFileEdit::Upsert {
                            path: child_path,
                            content: bytes,
                            file_type,
                        },
                    );
                }
                FsnodeEntry::Directory {
                    fsnode_id: child_id,
                    ..
                } => {
                    self.collect_fsnode_subtree_upserts(&child_id, &child_path, edits_by_path)?;
                }
            }
        }
        Ok(())
    }
}
