//! High-Concurrency Server Merge & Checkout-Free Query Engine (`inarch-engine`) for Velenza Inarch.
//!
//! Implements Anthropic Scion's core server-centric capabilities:
//! 1. **Lock-Free Speculative Rebase (`land_patch`)**:
//!    AI agents submit patches against whatever `base_changeset` they observed when starting.
//!    If `main` has advanced to `head`, the server verifies path-disjointness against all
//!    intermediate commits in `(base..head]` in $O(\Delta)$ using tree-free `BonsaiChangeset`s,
//!    rewrites `parents` to `[head]` with **zero Merkle tree reads**, and executes an atomic
//!    single-row Compare-And-Swap (`cas_ref`).
//! 2. **Checkout-Free RPC Operations**:
//!    `read_file`, `list_directory`, `diff_changesets`, `log_path`, and `blame` execute
//!    directly against content-addressed stores without materializing a working copy.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, RwLock};

use inarch_derived::{
    BlameV2, CopyDetectionReport, DerivedDataEngine, DerivedError, FsnodeEntry, FsnodeSummary,
    PathSearchEntry,
};
use inarch_store::{
    BlobStore, DerivedDataKind, MetadataStore, NoopTelemetrySink, StoreError, TelemetryEvent,
    TelemetrySink,
};
use inarch_types::bonsai::{BonsaiChangeset, BonsaiError, FileChange, FileType};
use inarch_types::hash::{BlobId, ChangesetId, FsnodeId};
use inarch_types::path::{MPath, MPathElement};

/// Alias for [`BlobId`] representing a content-addressed file blob identifier.
pub type ContentId = BlobId;

/// Maximum number of Compare-And-Swap retry attempts during [`ScionEngine::land_patch`] under contention.
pub const MAX_LAND_CAS_RETRIES: usize = 64;

/// Longest-prefix path ACL rule enforced by [`ScionEngine`] during [`ScionEngine::land_patch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnginePathAclRule {
    pub prefix: String,
    pub allowed_actors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    Store(StoreError),
    Derived(DerivedError),
    Bonsai(BonsaiError),
    UnknownRef(String),
    UnknownChangeset(ChangesetId),
    NonFastForwardBase {
        base: Option<ChangesetId>,
        head: Option<ChangesetId>,
    },
    MergeConflict {
        base: ChangesetId,
        head: ChangesetId,
        conflicting_changeset: ChangesetId,
        conflicting_paths: Vec<MPath>,
    },
    AclDenied {
        actor: String,
        path: MPath,
        matched_prefix: String,
    },
    InvalidPatch(String),
    Validation(String),
    PathNotFound(String),
    NotAFile(String),
    NotADirectory(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => write!(f, "store error: {}", e),
            Self::Derived(e) => write!(f, "derived data error: {}", e),
            Self::Bonsai(e) => write!(f, "bonsai changeset error: {}", e),
            Self::UnknownRef(r) => write!(f, "unknown ref '{}'", r),
            Self::UnknownChangeset(id) => write!(f, "unknown changeset {}", id),
            Self::NonFastForwardBase { base, head } => {
                write!(f, "cannot rebase from base {:?} onto head {:?}", base, head)
            }
            Self::MergeConflict {
                base,
                head,
                conflicting_changeset,
                conflicting_paths,
            } => write!(
                f,
                "merge conflict rebasing ({}..{}] against {}: {:?} overlapped",
                base, head, conflicting_changeset, conflicting_paths
            ),
            Self::AclDenied {
                actor,
                path,
                matched_prefix,
            } => write!(
                f,
                "ACL denied: actor '{}' is not authorized to modify '{}' (matched rule '{}')",
                actor, path, matched_prefix
            ),
            Self::InvalidPatch(msg) => write!(f, "invalid patch: {}", msg),
            Self::Validation(msg) => write!(f, "validation error: {}", msg),
            Self::PathNotFound(p) => write!(f, "path not found: {}", p),
            Self::NotAFile(p) => write!(f, "not a file: {}", p),
            Self::NotADirectory(p) => write!(f, "not a directory: {}", p),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<StoreError> for EngineError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<DerivedError> for EngineError {
    fn from(e: DerivedError) -> Self {
        Self::Derived(e)
    }
}

impl From<BonsaiError> for EngineError {
    fn from(e: BonsaiError) -> Self {
        Self::Bonsai(e)
    }
}

/// A single file edit in a checkout-free [`PatchSubmission`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchFileEdit {
    Upsert {
        path: MPath,
        content: Vec<u8>,
        file_type: FileType,
    },
    Delete {
        path: MPath,
    },
}

/// Checkout-free patch submission payload sent by an AI agent or CLI client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchSubmission {
    pub target_ref: String,
    pub base_changeset: Option<ChangesetId>,
    pub author: String,
    pub timestamp: i64,
    pub tz_offset_secs: i32,
    pub message: String,
    pub extra: BTreeMap<String, Vec<u8>>,
    pub edits: Vec<PatchFileEdit>,
}

/// Receipt returned when a patch lands on a target ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandOutcome {
    pub changeset_id: ChangesetId,
    pub parent_changeset: Option<ChangesetId>,
    /// Number of intermediate commits on `target_ref` that this patch was speculatively rebased across.
    pub rebased_across: usize,
    /// Number of CAS retry iterations required before landing.
    pub cas_retries: usize,
}

/// Entry returned by checkout-free `list_directory`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryListingEntry {
    File {
        name: MPathElement,
        blob_id: BlobId,
        size: u64,
        file_type: FileType,
    },
    Directory {
        name: MPathElement,
        fsnode_id: FsnodeId,
        summary: FsnodeSummary,
    },
}

/// Kind of change between two commits in a Merkle diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
}

/// A single file delta in `diff_changesets`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffEntry {
    pub path: MPath,
    pub kind: ChangeKind,
}

/// Commit summary returned by `log_path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangesetSummary {
    pub changeset_id: ChangesetId,
    pub author: String,
    pub timestamp: i64,
    pub message: String,
}

/// Authoritative stateless server engine for Velenza Inarch.
pub struct ScionEngine {
    repo_id: String,
    blobs: Arc<dyn BlobStore>,
    meta: Arc<dyn MetadataStore>,
    derived: DerivedDataEngine,
    telemetry: Arc<dyn TelemetrySink>,
    acl_rules: RwLock<Vec<EnginePathAclRule>>,
}

impl ScionEngine {
    pub fn new<B, M>(blobs: Arc<B>, meta: Arc<M>) -> Self
    where
        B: BlobStore + 'static,
        M: MetadataStore + 'static,
    {
        Self::from_dyn(blobs, meta)
    }

    pub fn from_dyn(blobs: Arc<dyn BlobStore>, meta: Arc<dyn MetadataStore>) -> Self {
        Self::with_telemetry("default", blobs, meta, Arc::new(NoopTelemetrySink))
    }

    pub fn with_telemetry(
        repo_id: impl Into<String>,
        blobs: Arc<dyn BlobStore>,
        meta: Arc<dyn MetadataStore>,
        telemetry: Arc<dyn TelemetrySink>,
    ) -> Self {
        let derived = DerivedDataEngine::from_dyn(Arc::clone(&blobs), Arc::clone(&meta));
        Self {
            repo_id: repo_id.into(),
            blobs,
            meta,
            derived,
            telemetry,
            acl_rules: RwLock::new(Vec::new()),
        }
    }

    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    pub fn telemetry(&self) -> &Arc<dyn TelemetrySink> {
        &self.telemetry
    }

    pub fn blobs(&self) -> &Arc<dyn BlobStore> {
        &self.blobs
    }

    pub fn meta(&self) -> &Arc<dyn MetadataStore> {
        &self.meta
    }

    pub fn derived(&self) -> &DerivedDataEngine {
        &self.derived
    }

    /// Configures longest-prefix path ACL rules enforced by [`Self::land_patch`].
    pub fn set_acl_rules(&self, rules: Vec<EnginePathAclRule>) {
        *self.acl_rules.write().expect("acl_rules lock poisoned") = rules;
    }

    /// Returns the currently configured longest-prefix path ACL rules.
    pub fn acl_rules(&self) -> Vec<EnginePathAclRule> {
        self.acl_rules
            .read()
            .expect("acl_rules lock poisoned")
            .clone()
    }

    /// Verifies that `actor` is authorized to modify `path` under the configured longest-prefix
    /// [`EnginePathAclRule`] table. When no rules are configured, all writes are permitted.
    pub fn check_path_acl(&self, actor: &str, path: &MPath) -> Result<(), EngineError> {
        let rules = self.acl_rules.read().expect("acl_rules lock poisoned");
        if rules.is_empty() {
            return Ok(());
        }

        let path_str = path.as_str();
        let mut best_len: Option<usize> = None;
        let mut best_prefix_display = String::new();
        let mut allowed = false;

        for rule in rules.iter() {
            let norm = normalize_acl_prefix(&rule.prefix);
            if !acl_prefix_matches(&norm, path_str) {
                continue;
            }
            let len = norm.len();
            match best_len {
                None => {
                    best_len = Some(len);
                    best_prefix_display = if norm.is_empty() {
                        "/".to_string()
                    } else {
                        norm
                    };
                    allowed = rule.allowed_actors.iter().any(|a| a == "*" || a == actor);
                }
                Some(cur_best) if len > cur_best => {
                    best_len = Some(len);
                    best_prefix_display = if norm.is_empty() {
                        "/".to_string()
                    } else {
                        norm
                    };
                    allowed = rule.allowed_actors.iter().any(|a| a == "*" || a == actor);
                }
                Some(cur_best) if len == cur_best => {
                    if rule.allowed_actors.iter().any(|a| a == "*" || a == actor) {
                        allowed = true;
                    }
                }
                Some(_) => {}
            }
        }

        match best_len {
            None => Err(EngineError::AclDenied {
                actor: actor.to_string(),
                path: path.clone(),
                matched_prefix: "<none>".to_string(),
            }),
            Some(_) if allowed => Ok(()),
            Some(_) => Err(EngineError::AclDenied {
                actor: actor.to_string(),
                path: path.clone(),
                matched_prefix: best_prefix_display,
            }),
        }
    }

    /// Resolves a ref name (e.g., `"main"`) to its current `ChangesetId`.
    pub fn resolve_ref(&self, ref_name: &str) -> Result<Option<ChangesetId>, EngineError> {
        Ok(self.meta.get_ref(ref_name)?)
    }

    /// Resolves `path` at `cs_id` to its `(ContentId, FileType)` if the file exists at `cs_id`.
    ///
    /// Uses already-derived `Fsnode` mappings when available, fast first-parent changeset
    /// delta inspection for shallow histories, and `derive_fsnode` + $O(\text{depth})$ lookup
    /// for deep or multi-parent histories.
    pub fn resolve_file_at_changeset(
        &self,
        cs_id: ChangesetId,
        path: &MPath,
    ) -> Result<Option<(ContentId, FileType)>, EngineError> {
        let mut curr = cs_id;
        let mut steps = 0usize;
        while steps < 64 {
            if let Some(root_hash) = self
                .meta
                .get_derived_mapping(curr, DerivedDataKind::Fsnode)?
            {
                let root_fsnode = FsnodeId::from_hash(root_hash);
                return match self.derived.lookup_fsnode_path(&root_fsnode, path)? {
                    Some(FsnodeEntry::File {
                        blob_id, file_type, ..
                    }) => Ok(Some((blob_id, file_type))),
                    Some(FsnodeEntry::Directory { .. }) | None => Ok(None),
                };
            }

            let cs = self
                .meta
                .get_changeset(&curr)?
                .ok_or(EngineError::UnknownChangeset(curr))?;
            if let Some(change) = cs.file_changes.get(path) {
                return match change {
                    FileChange::Tracked {
                        blob_id, file_type, ..
                    } => Ok(Some((*blob_id, *file_type))),
                    FileChange::Deleted => Ok(None),
                };
            }
            if cs
                .file_changes
                .keys()
                .any(|k| k != path && (k.is_prefix_of(path) || path.is_prefix_of(k)))
            {
                break;
            }
            if cs.parents.is_empty() {
                return Ok(None);
            }
            if cs.parents.len() == 1 {
                curr = cs.parents[0];
                steps += 1;
            } else {
                break;
            }
        }

        let root_fsnode = self.derived.derive_fsnode(curr)?;
        match self.derived.lookup_fsnode_path(&root_fsnode, path)? {
            Some(FsnodeEntry::File {
                blob_id, file_type, ..
            }) => Ok(Some((blob_id, file_type))),
            Some(FsnodeEntry::Directory { .. }) | None => Ok(None),
        }
    }

    /// Lands a [`PatchSubmission`] onto `submission.target_ref` and returns `(changeset_id, cas_retries)`.
    pub fn land_patch_with_stats(
        &self,
        submission: PatchSubmission,
    ) -> Result<(ChangesetId, usize), EngineError> {
        let outcome = self.land_patch(submission)?;
        Ok((outcome.changeset_id, outcome.cas_retries))
    }

    /// Lands a [`PatchSubmission`] onto `submission.target_ref` using lock-free CAS,
    /// zero-tree-read speculative rebase when intermediate commits are path-disjoint,
    /// and deterministic 3-way line-level merge when intermediate commits edit disjoint hunks
    /// of the same UTF-8 file.
    pub fn land_patch(&self, submission: PatchSubmission) -> Result<LandOutcome, EngineError> {
        let start = std::time::Instant::now();

        // 0. Enforce longest-prefix path ACL rules before writing blobs or changesets.
        if !self
            .acl_rules
            .read()
            .expect("acl_rules lock poisoned")
            .is_empty()
        {
            for edit in &submission.edits {
                let edit_path = match edit {
                    PatchFileEdit::Upsert { path, .. } | PatchFileEdit::Delete { path } => path,
                };
                self.check_path_acl(&submission.author, edit_path)?;
            }
        }

        // 1. Store all new file blobs (FastCDC chunked + verified) in a single batch BEFORE entering the CAS loop.
        let mut upserts: Vec<(MPath, Vec<u8>, FileType)> = Vec::new();
        let mut file_changes = BTreeMap::new();
        for edit in submission.edits {
            match edit {
                PatchFileEdit::Upsert {
                    path,
                    content,
                    file_type,
                } => {
                    upserts.push((path, content, file_type));
                }
                PatchFileEdit::Delete { path } => {
                    file_changes.insert(path, FileChange::Deleted);
                }
            }
        }

        if !upserts.is_empty() {
            let slices: Vec<&[u8]> = upserts.iter().map(|(_, c, _)| c.as_slice()).collect();
            let blob_ids = self.blobs.put_blobs_batch(&slices)?;
            for ((path, content, file_type), blob_id) in upserts.into_iter().zip(blob_ids) {
                file_changes.insert(
                    path,
                    FileChange::Tracked {
                        blob_id,
                        size: content.len() as u64,
                        file_type,
                    },
                );
            }
        }

        let initial_parents = submission.base_changeset.into_iter().collect::<Vec<_>>();
        let template_cs = BonsaiChangeset::new(
            initial_parents,
            submission.author,
            submission.timestamp,
            submission.tz_offset_secs,
            submission.message,
            submission.extra,
            file_changes,
        )?;

        let mut last_written_cs_id: Option<ChangesetId> = None;

        // 2. Bounded lock-free speculative rebase + atomic CAS loop
        for attempt in 0..=MAX_LAND_CAS_RETRIES {
            if attempt > 0 {
                let delay_us = 500 * (1u64 << attempt.min(6)) + ((attempt as u64 * 137) % 500);
                std::thread::sleep(std::time::Duration::from_micros(delay_us));
            }

            let current_head = self.meta.get_ref(&submission.target_ref)?;

            if current_head == submission.base_changeset {
                // Fast path: ref is still at `base_changeset`
                let cs_id = template_cs.changeset_id();
                if last_written_cs_id != Some(cs_id) {
                    self.meta.put_changeset(&template_cs)?;
                    last_written_cs_id = Some(cs_id);
                }
                let cas_committed = match self
                    .meta
                    .cas_ref(&submission.target_ref, current_head, cs_id)
                {
                    Ok(()) => true,
                    Err(StoreError::CasMismatch {
                        actual: Some(actual),
                        ..
                    }) if actual == cs_id => true,
                    Err(StoreError::CasMismatch { .. }) => false,
                    Err(other) => return Err(EngineError::Store(other)),
                };
                if cas_committed {
                        self.telemetry.emit(
                            &TelemetryEvent::info(
                                "engine",
                                "land_patch",
                                &self.repo_id,
                                format!(
                                    "Landed changeset {} on '{}' (rebased_across=0, cas_retries={})",
                                    cs_id.to_hex(),
                                    submission.target_ref,
                                    attempt
                                ),
                            )
                            .with_changeset(cs_id.to_hex())
                            .with_duration_us(start.elapsed().as_micros() as u64)
                            .with_attr("target_ref", &submission.target_ref)
                            .with_attr("rebased_across", "0")
                            .with_attr("cas_retries", attempt.to_string()),
                        );
                        return Ok(LandOutcome {
                            changeset_id: cs_id,
                            parent_changeset: current_head,
                            rebased_across: 0,
                            cas_retries: attempt,
                        });
                }
                continue;
            }

            // Speculative rebase path: `target_ref` advanced from `base` to `head`
            let (Some(base), Some(head)) = (submission.base_changeset, current_head) else {
                return Err(EngineError::NonFastForwardBase {
                    base: submission.base_changeset,
                    head: current_head,
                });
            };

            let intermediates = self.collect_commits_between(base, head)?;

            let mut unresolvable_conflicts: BTreeSet<MPath> = BTreeSet::new();
            let mut first_conflicting_cs: Option<ChangesetId> = None;
            let mut same_path_theirs: BTreeMap<MPath, Vec<(ChangesetId, FileChange)>> =
                BTreeMap::new();

            for inter_cs in &intermediates {
                let inter_id = inter_cs.changeset_id();
                let conflicts = template_cs.conflicting_paths(inter_cs);
                for conflict_path in conflicts {
                    if let Some(their_change) = inter_cs.file_changes.get(&conflict_path)
                        && template_cs.file_changes.contains_key(&conflict_path)
                    {
                        same_path_theirs
                            .entry(conflict_path)
                            .or_default()
                            .push((inter_id, their_change.clone()));
                    } else {
                        // Strict file-vs-directory prefix collision
                        if first_conflicting_cs.is_none() {
                            first_conflicting_cs = Some(inter_id);
                        }
                        unresolvable_conflicts.insert(conflict_path);
                    }
                }
            }

            let mut merged_overrides: BTreeMap<MPath, FileChange> = BTreeMap::new();
            for (path, their_history) in same_path_theirs {
                if unresolvable_conflicts.contains(&path) {
                    continue;
                }
                let Some((their_cs_id, their_change)) = their_history.last().cloned() else {
                    continue;
                };
                let our_change = &template_cs.file_changes[&path];
                match (&their_change, our_change) {
                    (
                        FileChange::Tracked {
                            blob_id: their_blob,
                            file_type: their_ft,
                            ..
                        },
                        FileChange::Tracked {
                            blob_id: our_blob,
                            file_type: our_ft,
                            ..
                        },
                    ) if their_ft == our_ft
                        && matches!(our_ft, FileType::Regular | FileType::Executable) =>
                    {
                        if their_blob == our_blob {
                            // Both changesets wrote identical content and file type
                            continue;
                        }
                        let base_resolved = self.resolve_file_at_changeset(base, &path)?;
                        if let Some((_, base_ft)) = base_resolved
                            && base_ft != *our_ft
                        {
                            if first_conflicting_cs.is_none() {
                                first_conflicting_cs = Some(their_history.first().unwrap().0);
                            }
                            unresolvable_conflicts.insert(path);
                            continue;
                        }
                        let base_bytes = match base_resolved {
                            Some((base_blob, _)) => {
                                self.blobs.get_blob_content(&base_blob)?.ok_or_else(|| {
                                    EngineError::PathNotFound(path.as_str().to_string())
                                })?
                            }
                            None => Vec::new(),
                        };
                        let their_bytes = self
                            .blobs
                            .get_blob_content(their_blob)?
                            .ok_or_else(|| EngineError::PathNotFound(path.as_str().to_string()))?;
                        let our_bytes = self
                            .blobs
                            .get_blob_content(our_blob)?
                            .ok_or_else(|| EngineError::PathNotFound(path.as_str().to_string()))?;

                        let merged_opt = if !base_bytes.contains(&0)
                            && !their_bytes.contains(&0)
                            && !our_bytes.contains(&0)
                            && let (Ok(base_str), Ok(their_str), Ok(our_str)) = (
                                std::str::from_utf8(&base_bytes),
                                std::str::from_utf8(&their_bytes),
                                std::str::from_utf8(&our_bytes),
                            ) {
                            three_way_merge_lines(base_str, their_str, our_str)
                        } else {
                            None
                        };

                        if let Some(merged_text) = merged_opt {
                            let merged_bytes = merged_text.into_bytes();
                            let merged_blob_id = self.blobs.put_blob_content(&merged_bytes)?;
                            merged_overrides.insert(
                                path,
                                FileChange::Tracked {
                                    blob_id: merged_blob_id,
                                    size: merged_bytes.len() as u64,
                                    file_type: *our_ft,
                                },
                            );
                        } else {
                            if first_conflicting_cs.is_none() {
                                let mut culprit = their_cs_id;
                                if let (Ok(base_str), Ok(our_str)) = (
                                    std::str::from_utf8(&base_bytes),
                                    std::str::from_utf8(&our_bytes),
                                ) {
                                    for (step_id, step_change) in &their_history {
                                        let step_ok = match step_change {
                                            FileChange::Tracked {
                                                blob_id: step_blob,
                                                file_type: step_ft,
                                                ..
                                            } if step_ft == our_ft => self
                                                .blobs
                                                .get_blob_content(step_blob)
                                                .ok()
                                                .flatten()
                                                .and_then(|b| {
                                                    if b.contains(&0) {
                                                        None
                                                    } else {
                                                        std::str::from_utf8(&b).ok().and_then(|s| {
                                                            three_way_merge_lines(
                                                                base_str, s, our_str,
                                                            )
                                                        })
                                                    }
                                                })
                                                .is_some(),
                                            _ => false,
                                        };
                                        if !step_ok {
                                            culprit = *step_id;
                                            break;
                                        }
                                    }
                                }
                                first_conflicting_cs = Some(culprit);
                            }
                            unresolvable_conflicts.insert(path);
                        }
                    }
                    _ => {
                        if first_conflicting_cs.is_none() {
                            first_conflicting_cs = Some(their_history.first().unwrap().0);
                        }
                        unresolvable_conflicts.insert(path);
                    }
                }
            }

            if !unresolvable_conflicts.is_empty() {
                return Err(EngineError::MergeConflict {
                    base,
                    head,
                    conflicting_changeset: first_conflicting_cs.unwrap_or(head),
                    conflicting_paths: unresolvable_conflicts.into_iter().collect(),
                });
            }

            let rebased_cs = if merged_overrides.is_empty() {
                // Zero-tree-read rebase: rewrite `parents` to `[head]` in O(1)
                template_cs.with_parents(vec![head])?
            } else {
                let mut merged_file_changes = template_cs.file_changes.clone();
                for (path, change) in merged_overrides {
                    merged_file_changes.insert(path, change);
                }
                BonsaiChangeset::new(
                    vec![head],
                    template_cs.author.clone(),
                    template_cs.author_date_secs,
                    template_cs.author_tz_offset_secs,
                    template_cs.message.clone(),
                    template_cs.extra.clone(),
                    merged_file_changes,
                )?
            };

            let rebased_id = rebased_cs.changeset_id();
            if last_written_cs_id != Some(rebased_id) {
                self.meta.put_changeset(&rebased_cs)?;
                last_written_cs_id = Some(rebased_id);
            }

            let cas_committed = match self
                .meta
                .cas_ref(&submission.target_ref, Some(head), rebased_id)
            {
                Ok(()) => true,
                Err(StoreError::CasMismatch {
                    actual: Some(actual),
                    ..
                }) if actual == rebased_id => true,
                Err(StoreError::CasMismatch { .. }) => false,
                Err(other) => return Err(EngineError::Store(other)),
            };
            if cas_committed {
                    self.telemetry.emit(
                        &TelemetryEvent::info(
                            "engine",
                            "land_patch",
                            &self.repo_id,
                            format!(
                                "Landed changeset {} on '{}' (rebased_across={}, cas_retries={})",
                                rebased_id.to_hex(),
                                submission.target_ref,
                                intermediates.len(),
                                attempt
                            ),
                        )
                        .with_changeset(rebased_id.to_hex())
                        .with_duration_us(start.elapsed().as_micros() as u64)
                        .with_attr("target_ref", &submission.target_ref)
                        .with_attr("rebased_across", intermediates.len().to_string())
                        .with_attr("cas_retries", attempt.to_string()),
                    );
                    return Ok(LandOutcome {
                        changeset_id: rebased_id,
                        parent_changeset: Some(head),
                        rebased_across: intermediates.len(),
                        cas_retries: attempt,
                    });
            }
            continue;
        }

        Err(EngineError::InvalidPatch(format!(
            "CAS retry limit ({}) exceeded under contention",
            MAX_LAND_CAS_RETRIES
        )))
    }

    /// Collects all changesets in `(base..head]` in topological order using generation-pruned
    /// commit-graph traversal in [`DerivedDataEngine::collect_commits_between`].
    pub fn collect_commits_between(
        &self,
        base: ChangesetId,
        head: ChangesetId,
    ) -> Result<Vec<BonsaiChangeset>, EngineError> {
        match self.derived.collect_commits_between(base, head)? {
            Some(delta) => Ok(delta),
            None => Err(EngineError::NonFastForwardBase {
                base: Some(base),
                head: Some(head),
            }),
        }
    }

    /// Checkout-free file read at `cs_id` and `path`.
    pub fn read_file(&self, cs_id: ChangesetId, path: &MPath) -> Result<Vec<u8>, EngineError> {
        let start = std::time::Instant::now();
        let root_fsnode = self.derived.derive_fsnode(cs_id)?;
        let entry = self
            .derived
            .lookup_fsnode_path(&root_fsnode, path)?
            .ok_or_else(|| EngineError::PathNotFound(path.as_str().to_string()))?;
        match entry {
            FsnodeEntry::File { blob_id, .. } => {
                let bytes = self
                    .blobs
                    .get_blob_content(&blob_id)?
                    .ok_or_else(|| EngineError::PathNotFound(path.as_str().to_string()))?;
                self.telemetry.emit(
                    &TelemetryEvent::info(
                        "engine",
                        "read_file",
                        &self.repo_id,
                        format!(
                            "Read '{}' ({} bytes) at {}",
                            path.as_str(),
                            bytes.len(),
                            cs_id.to_hex()
                        ),
                    )
                    .with_changeset(cs_id.to_hex())
                    .with_duration_us(start.elapsed().as_micros() as u64)
                    .with_attr("path", path.as_str()),
                );
                Ok(bytes)
            }
            FsnodeEntry::Directory { .. } => Err(EngineError::NotAFile(path.as_str().to_string())),
        }
    }

    /// Checkout-free directory listing at `cs_id` and `path` (`None` for repository root).
    pub fn list_directory(
        &self,
        cs_id: ChangesetId,
        path: Option<&MPath>,
    ) -> Result<Vec<DirectoryListingEntry>, EngineError> {
        let root_fsnode_id = self.derived.derive_fsnode(cs_id)?;
        let target_fsnode_id = if let Some(p) = path {
            let entry = self
                .derived
                .lookup_fsnode_path(&root_fsnode_id, p)?
                .ok_or_else(|| EngineError::PathNotFound(p.as_str().to_string()))?;
            match entry {
                FsnodeEntry::Directory { fsnode_id, .. } => fsnode_id,
                FsnodeEntry::File { .. } => {
                    return Err(EngineError::NotADirectory(p.as_str().to_string()));
                }
            }
        } else {
            root_fsnode_id
        };

        let fsnode = self.derived.load_fsnode(&target_fsnode_id)?;
        let mut out = Vec::with_capacity(fsnode.entries.len());
        for (name, entry) in fsnode.entries {
            match entry {
                FsnodeEntry::File {
                    blob_id,
                    size,
                    file_type,
                } => out.push(DirectoryListingEntry::File {
                    name,
                    blob_id,
                    size,
                    file_type,
                }),
                FsnodeEntry::Directory { fsnode_id, summary } => {
                    out.push(DirectoryListingEntry::Directory {
                        name,
                        fsnode_id,
                        summary,
                    })
                }
            }
        }
        Ok(out)
    }

    /// Computes the exact file delta between `from_cs` and `to_cs` in $O(\Delta \cdot \text{depth})$
    /// by pruning identical `FsnodeId` Merkle subtrees.
    pub fn diff_changesets(
        &self,
        from_cs: ChangesetId,
        to_cs: ChangesetId,
    ) -> Result<Vec<DiffEntry>, EngineError> {
        let from_root = self.derived.derive_fsnode(from_cs)?;
        let to_root = self.derived.derive_fsnode(to_cs)?;
        let mut out = Vec::new();
        self.diff_fsnodes(Some(from_root), Some(to_root), None, &mut out)?;
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    fn diff_fsnodes(
        &self,
        from_id: Option<FsnodeId>,
        to_id: Option<FsnodeId>,
        prefix: Option<MPath>,
        out: &mut Vec<DiffEntry>,
    ) -> Result<(), EngineError> {
        if from_id == to_id {
            return Ok(());
        }
        let from_entries = if let Some(fid) = from_id {
            self.derived.load_fsnode(&fid)?.entries
        } else {
            BTreeMap::new()
        };
        let to_entries = if let Some(tid) = to_id {
            self.derived.load_fsnode(&tid)?.entries
        } else {
            BTreeMap::new()
        };

        for (name, from_entry) in &from_entries {
            let child_path = join_prefix(&prefix, name);
            match (from_entry, to_entries.get(name)) {
                (FsnodeEntry::File { .. }, None) => out.push(DiffEntry {
                    path: child_path,
                    kind: ChangeKind::Deleted,
                }),
                (
                    FsnodeEntry::File {
                        blob_id: b1,
                        file_type: ft1,
                        ..
                    },
                    Some(FsnodeEntry::File {
                        blob_id: b2,
                        file_type: ft2,
                        ..
                    }),
                ) => {
                    if b1 != b2 || ft1 != ft2 {
                        out.push(DiffEntry {
                            path: child_path,
                            kind: ChangeKind::Modified,
                        });
                    }
                }
                (
                    FsnodeEntry::File { .. },
                    Some(FsnodeEntry::Directory {
                        fsnode_id: dir2, ..
                    }),
                ) => {
                    out.push(DiffEntry {
                        path: child_path.clone(),
                        kind: ChangeKind::Deleted,
                    });
                    self.diff_fsnodes(None, Some(*dir2), Some(child_path), out)?;
                }
                (
                    FsnodeEntry::Directory {
                        fsnode_id: dir1, ..
                    },
                    None,
                ) => {
                    self.diff_fsnodes(Some(*dir1), None, Some(child_path), out)?;
                }
                (
                    FsnodeEntry::Directory {
                        fsnode_id: dir1, ..
                    },
                    Some(FsnodeEntry::Directory {
                        fsnode_id: dir2, ..
                    }),
                ) => {
                    self.diff_fsnodes(Some(*dir1), Some(*dir2), Some(child_path), out)?;
                }
                (
                    FsnodeEntry::Directory {
                        fsnode_id: dir1, ..
                    },
                    Some(FsnodeEntry::File { .. }),
                ) => {
                    self.diff_fsnodes(Some(*dir1), None, Some(child_path.clone()), out)?;
                    out.push(DiffEntry {
                        path: child_path,
                        kind: ChangeKind::Added,
                    });
                }
            }
        }

        for (name, to_entry) in &to_entries {
            if from_entries.contains_key(name) {
                continue;
            }
            let child_path = join_prefix(&prefix, name);
            match to_entry {
                FsnodeEntry::File { .. } => out.push(DiffEntry {
                    path: child_path,
                    kind: ChangeKind::Added,
                }),
                FsnodeEntry::Directory {
                    fsnode_id: dir2, ..
                } => {
                    self.diff_fsnodes(None, Some(*dir2), Some(child_path), out)?;
                }
            }
        }

        Ok(())
    }

    /// Checkout-free $O(k)$ path history log using derived Unodes.
    pub fn log_path(
        &self,
        cs_id: ChangesetId,
        path: &MPath,
    ) -> Result<Vec<ChangesetSummary>, EngineError> {
        let cs_ids = match self.derived.file_history(cs_id, path) {
            Ok(ids) => ids,
            Err(DerivedError::NotAFile(_)) => self.derived.directory_history(cs_id, path)?,
            Err(other) => return Err(EngineError::Derived(other)),
        };

        let mut summaries = Vec::with_capacity(cs_ids.len());
        for id in cs_ids {
            let cs = self
                .meta
                .get_changeset(&id)?
                .ok_or(EngineError::UnknownChangeset(id))?;
            summaries.push(ChangesetSummary {
                changeset_id: id,
                author: cs.author,
                timestamp: cs.author_date_secs,
                message: cs.message,
            });
        }
        Ok(summaries)
    }

    /// Checkout-free line-by-line blame attribution using derived `BlameV2`.
    pub fn blame(&self, cs_id: ChangesetId, path: &MPath) -> Result<BlameV2, EngineError> {
        Ok(self.derived.blame_file(cs_id, path)?)
    }

    /// Checkout-free path search using the inductive `PathSearchIndex` derived data type.
    pub fn search_paths(
        &self,
        cs_id: ChangesetId,
        query: &str,
        limit: usize,
    ) -> Result<Vec<PathSearchEntry>, EngineError> {
        let start = std::time::Instant::now();
        let results = self.derived.search_paths(cs_id, query, limit)?;
        self.telemetry.emit(
            &TelemetryEvent::info(
                "engine",
                "search_paths",
                &self.repo_id,
                format!(
                    "Searched paths for '{}' at {} -> {} matches",
                    query,
                    cs_id.to_hex(),
                    results.len()
                ),
            )
            .with_changeset(cs_id.to_hex())
            .with_duration_us(start.elapsed().as_micros() as u64)
            .with_attr("query", query),
        );
        Ok(results)
    }

    /// Checkout-free copy and rename detection using the inductive `CopyDetection` derived data type.
    pub fn detect_copies(&self, cs_id: ChangesetId) -> Result<CopyDetectionReport, EngineError> {
        let start = std::time::Instant::now();
        let report = self.derived.derive_copy_detection(cs_id)?;
        self.telemetry.emit(
            &TelemetryEvent::info(
                "engine",
                "detect_copies",
                &self.repo_id,
                format!(
                    "Detected {} copy/rename records at {}",
                    report.records.len(),
                    cs_id.to_hex()
                ),
            )
            .with_changeset(cs_id.to_hex())
            .with_duration_us(start.elapsed().as_micros() as u64),
        );
        Ok(report)
    }
}

fn join_prefix(prefix: &Option<MPath>, elem: &MPathElement) -> MPath {
    match prefix {
        Some(p) => p.join_element(elem),
        None => MPath::from_elements(vec![elem.clone()]).expect("single element valid"),
    }
}

fn normalize_acl_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim().trim_matches('/');
    if trimmed == "*" {
        String::new()
    } else {
        trimmed.to_string()
    }
}

fn acl_prefix_matches(norm_prefix: &str, path: &str) -> bool {
    if norm_prefix.is_empty() {
        return true;
    }
    if path == norm_prefix {
        return true;
    }
    path.strip_prefix(norm_prefix)
        .map(|rest| rest.starts_with('/'))
        .unwrap_or(false)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DiffHunk<'a> {
    base_start: usize,
    base_end: usize,
    replacement: Vec<&'a str>,
}

fn split_lines_preserving_trailing(text: &str) -> Vec<&str> {
    if text.is_empty() {
        Vec::new()
    } else {
        text.lines().collect()
    }
}

fn compute_diff_hunks<'a>(base: &[&'a str], target: &[&'a str]) -> Vec<DiffHunk<'a>> {
    let n = base.len();
    let m = target.len();

    let mut prefix = 0usize;
    while prefix < n && prefix < m && base[prefix] == target[prefix] {
        prefix += 1;
    }
    let mut suffix = 0usize;
    while suffix < (n - prefix)
        && suffix < (m - prefix)
        && base[n - 1 - suffix] == target[m - 1 - suffix]
    {
        suffix += 1;
    }

    let b_mid = &base[prefix..n - suffix];
    let t_mid = &target[prefix..m - suffix];
    let bn = b_mid.len();
    let tm = t_mid.len();

    if bn == 0 && tm == 0 {
        return Vec::new();
    }

    let base_values: BTreeSet<&str> = b_mid.iter().copied().collect();
    let mut matches = Vec::new();
    if t_mid.iter().any(|line| base_values.contains(*line)) {
        collect_lcs_matches(b_mid, t_mid, prefix, prefix, &mut matches);
    }

    let mut hunks = Vec::new();
    let mut cur_b = prefix;
    let mut cur_t = prefix;
    for (mb, mt) in matches {
        if cur_b < mb || cur_t < mt {
            hunks.push(DiffHunk {
                base_start: cur_b,
                base_end: mb,
                replacement: target[cur_t..mt].to_vec(),
            });
        }
        cur_b = mb + 1;
        cur_t = mt + 1;
    }
    let end_b = n - suffix;
    let end_t = m - suffix;
    if cur_b < end_b || cur_t < end_t {
        hunks.push(DiffHunk {
            base_start: cur_b,
            base_end: end_b,
            replacement: target[cur_t..end_t].to_vec(),
        });
    }
    hunks
}

fn collect_lcs_matches(
    base: &[&str],
    target: &[&str],
    base_offset: usize,
    target_offset: usize,
    matches: &mut Vec<(usize, usize)>,
) {
    if base.is_empty() || target.is_empty() {
        return;
    }
    if base.len() == 1 {
        if let Some(target_index) = target.iter().position(|line| *line == base[0]) {
            matches.push((base_offset, target_offset + target_index));
        }
        return;
    }

    let midpoint = base.len() / 2;
    let forward = lcs_prefix_lengths(&base[..midpoint], target);
    let suffix = lcs_suffix_lengths(&base[midpoint..], target);
    let mut split = 0usize;
    let mut best_score = 0usize;
    for index in 0..=target.len() {
        let score = forward[index] + suffix[index];
        if score > best_score {
            best_score = score;
            split = index;
        }
    }
    drop(forward);
    drop(suffix);

    collect_lcs_matches(
        &base[..midpoint],
        &target[..split],
        base_offset,
        target_offset,
        matches,
    );
    collect_lcs_matches(
        &base[midpoint..],
        &target[split..],
        base_offset + midpoint,
        target_offset + split,
        matches,
    );
}

fn lcs_prefix_lengths(base: &[&str], target: &[&str]) -> Vec<usize> {
    let mut previous = vec![0usize; target.len() + 1];
    let mut current = vec![0usize; target.len() + 1];
    for base_line in base {
        current[0] = 0;
        for (index, target_line) in target.iter().enumerate() {
            current[index + 1] = if base_line == target_line {
                previous[index] + 1
            } else {
                previous[index + 1].max(current[index])
            };
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous
}

fn lcs_suffix_lengths(base: &[&str], target: &[&str]) -> Vec<usize> {
    let mut previous = vec![0usize; target.len() + 1];
    let mut current = vec![0usize; target.len() + 1];
    for base_line in base.iter().rev() {
        current[target.len()] = 0;
        for index in (0..target.len()).rev() {
            current[index] = if *base_line == target[index] {
                previous[index + 1] + 1
            } else {
                previous[index].max(current[index + 1])
            };
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous
}

/// Deterministic 3-way line-level merge of `their_str` and `our_str` relative to `base_str`.
///
/// Returns `Some(merged_text)` when all hunks are disjoint or identical; returns `None`
/// if any hunk between `theirs` and `ours` overlaps with different replacement lines.
pub fn three_way_merge_lines(base_str: &str, their_str: &str, our_str: &str) -> Option<String> {
    if their_str == our_str {
        return Some(our_str.to_string());
    }
    if their_str == base_str {
        return Some(our_str.to_string());
    }
    if our_str == base_str {
        return Some(their_str.to_string());
    }

    let base_lines = split_lines_preserving_trailing(base_str);
    let their_lines = split_lines_preserving_trailing(their_str);
    let our_lines = split_lines_preserving_trailing(our_str);

    let hunks_theirs = compute_diff_hunks(&base_lines, &their_lines);
    let hunks_ours = compute_diff_hunks(&base_lines, &our_lines);

    let mut merged_hunks: Vec<DiffHunk<'_>> = Vec::new();
    let mut ti = 0usize;
    let mut oi = 0usize;

    while ti < hunks_theirs.len() && oi < hunks_ours.len() {
        let ht = &hunks_theirs[ti];
        let ho = &hunks_ours[oi];

        if ht.base_start == ho.base_start
            && ht.base_end == ho.base_end
            && ht.replacement == ho.replacement
        {
            merged_hunks.push(ht.clone());
            ti += 1;
            oi += 1;
            continue;
        }

        let t_strictly_before_o = if ht.base_start == ht.base_end {
            ht.base_start < ho.base_start
        } else if ho.base_start == ho.base_end {
            ht.base_end <= ho.base_start && ht.base_start < ho.base_start
        } else {
            ht.base_end <= ho.base_start
        };

        if t_strictly_before_o {
            merged_hunks.push(ht.clone());
            ti += 1;
            continue;
        }

        let o_strictly_before_t = if ho.base_start == ho.base_end {
            ho.base_start < ht.base_start
        } else if ht.base_start == ht.base_end {
            ho.base_end <= ht.base_start && ho.base_start < ht.base_start
        } else {
            ho.base_end <= ht.base_start
        };

        if o_strictly_before_t {
            merged_hunks.push(ho.clone());
            oi += 1;
            continue;
        }

        return None;
    }

    while ti < hunks_theirs.len() {
        merged_hunks.push(hunks_theirs[ti].clone());
        ti += 1;
    }
    while oi < hunks_ours.len() {
        merged_hunks.push(hunks_ours[oi].clone());
        oi += 1;
    }

    let mut out_lines: Vec<&str> = Vec::new();
    let mut base_idx = 0usize;
    for h in merged_hunks {
        if base_idx < h.base_start {
            out_lines.extend_from_slice(&base_lines[base_idx..h.base_start]);
        }
        out_lines.extend_from_slice(&h.replacement);
        base_idx = h.base_end;
    }
    if base_idx < base_lines.len() {
        out_lines.extend_from_slice(&base_lines[base_idx..]);
    }

    let base_trailing_newline = base_str.ends_with('\n');
    let their_trailing_newline = their_str.ends_with('\n');
    let our_trailing_newline = our_str.ends_with('\n');
    let trailing_newline = if their_trailing_newline == our_trailing_newline {
        their_trailing_newline
    } else if their_trailing_newline == base_trailing_newline {
        our_trailing_newline
    } else {
        their_trailing_newline
    };
    let mut result = out_lines.join("\n");
    if trailing_newline && !result.is_empty() {
        result.push('\n');
    }
    Some(result)
}
