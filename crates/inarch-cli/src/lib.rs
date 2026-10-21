//! Velenza Inarch CLI (`inr`), Stateless Tree-Walk Checkout, and Checkout-Free MCP Server (`inarch-cli`).
//!
//! Provides two primary execution surfaces modeled on Anthropic's Scion (`scn`):
//! 1. **Checkout-Free Model Context Protocol (`McpServer`)**:
//!    AI agents and CI sandboxes read files, list directories, compute Merkle diffs, inspect
//!    $O(k)$ path logs, query line-by-line blame, commit patches via lock-free speculative
//!    rebase, and execute instant post-merge reverts without ever materializing a local working copy.
//! 2. **Stateless Tree-Walk Checkout (`checkout_stateless`)**:
//!    Replaces Git's stateful `have`/`want` packfile negotiation. Clients start at the root
//!    [`FsnodeId`], prune unselected directory subtrees using sparse prefix filters, and walk
//!    selected subtrees top-down through the 3-tier content-addressed cache (`inarch-daemon` ->
//!    `inarch-cache` -> `inarch-server`).

#![allow(clippy::result_large_err, clippy::type_complexity)]

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use inarch_antique::{AntiqueError, AntiqueService};
use inarch_derived::FsnodeEntry;
use inarch_engine::{
    ChangeKind, DirectoryListingEntry, EngineError, PatchFileEdit, PatchSubmission, ScionEngine,
};
use inarch_types::bonsai::FileType;
use inarch_types::hash::{BlobId, ChangesetId, FsnodeId, HashError};
use inarch_types::path::{MPath, PathError};

pub mod arbor;
pub mod bench;
pub mod config;
pub mod git_bridge;
pub mod mount;
pub use arbor::{
    ArborLayerDescriptor, ArborLayerId, ArborStackReport, default_arbor_search_dirs,
    delegate_arbor_subcommand, discover_arbor_stack, resolve_umbrella_subcommand,
    spawn_arbor_subcommand_inherited,
};
pub use bench::{
    BenchmarkConfig, BenchmarkReport, PreBenchmarkBaseline, WorkloadMeasurement,
    run_benchmark_suite,
};
pub use config::{AclRuleConfig, InarchConfig, LocalJitLeaseFile};
pub use git_bridge::{
    GitExportReceipt, GitImportOptions, GitImportReceipt, GitImportedCommit, export_git_revision,
    import_git_history,
};
pub use mount::{
    HydrateReceipt, VirtualMountManifest, VirtualMountReceipt, WebDavMountHandle,
    hydrate_virtual_paths, mount_virtual_workspace, spawn_webdav_virtual_mount,
};

#[derive(Debug)]
pub enum CliError {
    Engine(EngineError),
    Antique(AntiqueError),
    Hash(HashError),
    Path(PathError),
    Io(String),
    InvalidArgument(String),
    VerificationMismatch(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(e) => write!(f, "engine error: {}", e),
            Self::Antique(e) => write!(f, "antique error: {}", e),
            Self::Hash(e) => write!(f, "hash error: {}", e),
            Self::Path(e) => write!(f, "path error: {}", e),
            Self::Io(msg) => write!(f, "I/O error: {}", msg),
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {}", msg),
            Self::VerificationMismatch(msg) => write!(f, "verification mismatch: {}", msg),
        }
    }
}

impl std::error::Error for CliError {}

impl From<EngineError> for CliError {
    fn from(e: EngineError) -> Self {
        Self::Engine(e)
    }
}

impl From<AntiqueError> for CliError {
    fn from(e: AntiqueError) -> Self {
        Self::Antique(e)
    }
}

impl From<HashError> for CliError {
    fn from(e: HashError) -> Self {
        Self::Hash(e)
    }
}

impl From<PathError> for CliError {
    fn from(e: PathError) -> Self {
        Self::Path(e)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Request envelope for the Checkout-Free Model Context Protocol (`McpServer`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpRequest {
    ListTools {
        id: u64,
    },
    CallTool {
        id: u64,
        name: String,
        args: BTreeMap<String, String>,
    },
}

/// Response envelope returned by [`McpServer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpResponse {
    pub id: u64,
    pub result: Option<String>,
    pub error: Option<String>,
}

impl McpResponse {
    pub fn ok(id: u64, result: String) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: u64, error: String) -> Self {
        Self {
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// Checkout-free Model Context Protocol (MCP) tool server for AI coding agents.
pub struct McpServer {
    engine: Arc<ScionEngine>,
    antique: Arc<AntiqueService>,
}

impl McpServer {
    pub fn new(engine: Arc<ScionEngine>, antique: Arc<AntiqueService>) -> Self {
        Self { engine, antique }
    }

    /// Returns the static catalog of checkout-free MCP tools exposed to AI coding agents.
    pub fn tool_catalog() -> &'static [(&'static str, &'static str)] {
        &[
            (
                "inarch_resolve_ref",
                "Resolve a global ref (e.g. 'main') to its 64-char BLAKE3 ChangesetId.",
            ),
            (
                "inarch_commit_patch",
                "Land a checkout-free patch onto target_ref using lock-free speculative rebase.",
            ),
            (
                "inarch_read_file",
                "Read UTF-8 or raw file content at a ref or ChangesetId without a working copy.",
            ),
            (
                "inarch_list_dir",
                "List directory entries and recursive O(1) Fsnode summaries at a ref or ChangesetId.",
            ),
            (
                "inarch_diff",
                "Compute an O(Delta) Merkle tree diff between two revisions.",
            ),
            (
                "inarch_log_path",
                "Query O(k) file or directory commit history via Unode history graphs.",
            ),
            (
                "inarch_blame",
                "Query inductive BlameV2 line-by-line authorship and commit attribution.",
            ),
            (
                "inarch_revert",
                "Synthesize and land an instant server-side inverse BonsaiChangeset reverting a culprit commit.",
            ),
            (
                "inarch_search_paths",
                "Search repository file paths using the inductive PathSearchIndex (glob or substring).",
            ),
            (
                "inarch_detect_copies",
                "Detect exact and content-similar file copies and renames at a revision.",
            ),
        ]
    }

    pub fn handle(&self, req: McpRequest) -> McpResponse {
        match req {
            McpRequest::ListTools { id } => {
                let mut out = String::new();
                for (name, desc) in Self::tool_catalog() {
                    out.push_str(&format!("{}: {}\n", name, desc));
                }
                McpResponse::ok(id, out)
            }
            McpRequest::CallTool { id, name, args } => match self.call_tool(&name, &args) {
                Ok(result) => McpResponse::ok(id, result),
                Err(err) => McpResponse::err(id, err.to_string()),
            },
        }
    }

    fn resolve_revision(&self, rev: &str) -> Result<ChangesetId, CliError> {
        if rev.len() == 64 && rev.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(ChangesetId::from_hex(rev)?);
        }
        self.engine
            .resolve_ref(rev)?
            .ok_or_else(|| CliError::Engine(EngineError::UnknownRef(rev.to_string())))
    }

    fn call_tool(&self, name: &str, args: &BTreeMap<String, String>) -> Result<String, CliError> {
        match name {
            "inarch_resolve_ref" => {
                let ref_name = args
                    .get("ref")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'ref'".to_string()))?;
                match self.engine.resolve_ref(ref_name)? {
                    Some(cs_id) => Ok(cs_id.to_hex()),
                    None => Err(CliError::Engine(EngineError::UnknownRef(ref_name.clone()))),
                }
            }
            "inarch_commit_patch" => {
                let target_ref = args
                    .get("target_ref")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'target_ref'".to_string()))?
                    .clone();
                let author = args
                    .get("author")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'author'".to_string()))?
                    .clone();
                let timestamp = args
                    .get("timestamp")
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);
                let message = args
                    .get("message")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'message'".to_string()))?
                    .clone();

                let raw_base = args
                    .get("base_changeset")
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        CliError::InvalidArgument(
                            "missing required 'base_changeset' (provide 64-hex ChangesetId, 'HEAD', or 'INITIAL')"
                                .to_string(),
                        )
                    })?;
                let base_changeset = if raw_base.eq_ignore_ascii_case("INITIAL")
                    || raw_base.eq_ignore_ascii_case("NONE")
                {
                    None
                } else if raw_base.eq_ignore_ascii_case("HEAD") {
                    self.engine.resolve_ref(&target_ref)?
                } else {
                    Some(self.resolve_revision(raw_base)?)
                };

                let edits = if let Some(raw_edits) = args.get("edits") {
                    let parsed = parse_mcp_edits_array(raw_edits)?;
                    let mut list = Vec::with_capacity(parsed.len());
                    for item in &parsed {
                        list.push(build_mcp_patch_edit(&self.engine, base_changeset, item)?);
                    }
                    list
                } else {
                    vec![build_mcp_patch_edit(&self.engine, base_changeset, args)?]
                };

                let outcome = self.engine.land_patch(PatchSubmission {
                    target_ref,
                    base_changeset,
                    author,
                    timestamp,
                    tz_offset_secs: 0,
                    message,
                    extra: BTreeMap::new(),
                    edits,
                })?;

                Ok(format!(
                    "landed={} rebased_across={}",
                    outcome.changeset_id.to_hex(),
                    outcome.rebased_across
                ))
            }
            "inarch_read_file" => {
                let rev = args
                    .get("rev")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'rev'".to_string()))?;
                let path_str = args
                    .get("path")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'path'".to_string()))?;
                let cs_id = self.resolve_revision(rev)?;
                let path = MPath::new(path_str)?;
                let bytes = self.engine.read_file(cs_id, &path)?;
                Ok(String::from_utf8_lossy(&bytes).into_owned())
            }
            "inarch_list_dir" => {
                let rev = args
                    .get("rev")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'rev'".to_string()))?;
                let cs_id = self.resolve_revision(rev)?;
                let dir_path = match args.get("path") {
                    Some(p) if !p.is_empty() => Some(MPath::new(p)?),
                    _ => None,
                };
                let entries = self.engine.list_directory(cs_id, dir_path.as_ref())?;
                let mut out = String::new();
                for entry in entries {
                    match entry {
                        DirectoryListingEntry::File {
                            name,
                            blob_id,
                            size,
                            ..
                        } => {
                            out.push_str(&format!(
                                "FILE {} size={} blob={}\n",
                                name,
                                size,
                                blob_id.to_hex()
                            ));
                        }
                        DirectoryListingEntry::Directory {
                            name,
                            fsnode_id,
                            summary,
                        } => {
                            out.push_str(&format!(
                                "DIR  {}/ files={} bytes={} fsnode={}\n",
                                name,
                                summary.descendant_files_count,
                                summary.descendant_files_total_size,
                                fsnode_id.to_hex()
                            ));
                        }
                    }
                }
                Ok(out)
            }
            "inarch_diff" => {
                let from_rev = args
                    .get("from")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'from'".to_string()))?;
                let to_rev = args
                    .get("to")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'to'".to_string()))?;
                let from_cs = self.resolve_revision(from_rev)?;
                let to_cs = self.resolve_revision(to_rev)?;
                let diffs = self.engine.diff_changesets(from_cs, to_cs)?;
                let mut out = String::new();
                for d in diffs {
                    let kind_str = match d.kind {
                        ChangeKind::Added => "ADDED",
                        ChangeKind::Modified => "MODIFIED",
                        ChangeKind::Deleted => "DELETED",
                    };
                    out.push_str(&format!("{} {}\n", kind_str, d.path));
                }
                Ok(out)
            }
            "inarch_log_path" => {
                let rev = args
                    .get("rev")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'rev'".to_string()))?;
                let path_str = args
                    .get("path")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'path'".to_string()))?;
                let limit = args
                    .get("limit")
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(50);
                let cs_id = self.resolve_revision(rev)?;
                let path = MPath::new(path_str)?;
                let history = self.engine.log_path(cs_id, &path)?;
                let mut out = String::new();
                for entry in history.into_iter().take(limit) {
                    out.push_str(&format!(
                        "{} {} ({}): {}\n",
                        entry.changeset_id.to_hex(),
                        entry.author,
                        entry.timestamp,
                        entry.message
                    ));
                }
                Ok(out)
            }
            "inarch_blame" => {
                let rev = args
                    .get("rev")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'rev'".to_string()))?;
                let path_str = args
                    .get("path")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'path'".to_string()))?;
                let cs_id = self.resolve_revision(rev)?;
                let path = MPath::new(path_str)?;
                let blame = self.engine.blame(cs_id, &path)?;
                let mut out = String::new();
                for (idx, line) in blame.lines.iter().enumerate() {
                    out.push_str(&format!(
                        "{:>4} | {} | {} | {}\n",
                        idx + 1,
                        &line.changeset_id.to_hex()[..12],
                        line.author,
                        line.content
                    ));
                }
                Ok(out)
            }
            "inarch_revert" => {
                let target_ref = args
                    .get("target_ref")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'target_ref'".to_string()))?;
                let culprit_str = args
                    .get("culprit")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'culprit'".to_string()))?;
                let author = args
                    .get("author")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'author'".to_string()))?;
                let timestamp = args
                    .get("timestamp")
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);
                let culprit_id = self.resolve_revision(culprit_str)?;
                if let Some(cs) = self
                    .engine
                    .meta()
                    .get_changeset(&culprit_id)
                    .map_err(EngineError::Store)?
                {
                    if cs.parents.len() > 1 {
                        return Err(CliError::InvalidArgument(format!(
                            "cannot revert merge changeset {} with {} parents; specify a single-parent changeset",
                            culprit_id,
                            cs.parents.len()
                        )));
                    }
                }
                let outcome = self
                    .antique
                    .revert_changeset(target_ref, culprit_id, author, timestamp)?;
                Ok(format!("reverted_by={}", outcome.changeset_id.to_hex()))
            }
            "inarch_search_paths" => {
                let rev = args
                    .get("rev")
                    .or_else(|| args.get("changeset_id"))
                    .ok_or_else(|| CliError::InvalidArgument("missing 'rev'".to_string()))?;
                let query = args
                    .get("query")
                    .ok_or_else(|| CliError::InvalidArgument("missing 'query'".to_string()))?;
                let limit = args
                    .get("limit")
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(100);
                let cs_id = self.resolve_revision(rev)?;
                let matches = self.engine.search_paths(cs_id, query, limit)?;
                let mut out = String::new();
                for entry in matches {
                    out.push_str(&format!(
                        "{} size={} blob={}\n",
                        entry.path,
                        entry.size,
                        entry.blob_id.to_hex()
                    ));
                }
                Ok(out)
            }
            "inarch_detect_copies" => {
                let rev = args
                    .get("rev")
                    .or_else(|| args.get("changeset_id"))
                    .ok_or_else(|| CliError::InvalidArgument("missing 'rev'".to_string()))?;
                let cs_id = self.resolve_revision(rev)?;
                let report = self.engine.detect_copies(cs_id)?;
                let mut out = String::new();
                for rec in report.records {
                    out.push_str(&format!(
                        "{:?} {} <- {} (similarity={}bps)\n",
                        rec.kind, rec.dest_path, rec.source_path, rec.similarity_bps
                    ));
                }
                Ok(out)
            }
            other => Err(CliError::InvalidArgument(format!(
                "unknown MCP tool '{}'",
                other
            ))),
        }
    }
}

fn lookup_file_type_at_changeset(
    engine: &ScionEngine,
    cs_id: ChangesetId,
    path: &MPath,
) -> Option<FileType> {
    let mut current_fsnode_id = engine.derived().derive_fsnode(cs_id).ok()?;
    let elems = path.elements();
    for (idx, elem) in elems.iter().enumerate() {
        let node = engine.derived().load_fsnode(&current_fsnode_id).ok()?;
        let entry = node.entries.get(elem)?;
        if idx + 1 == elems.len() {
            if let FsnodeEntry::File { file_type, .. } = entry {
                return Some(*file_type);
            }
            return None;
        } else if let FsnodeEntry::Directory { fsnode_id, .. } = entry {
            current_fsnode_id = *fsnode_id;
        } else {
            return None;
        }
    }
    None
}

fn extract_unescaped_json_str(obj: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let idx = obj.find(&needle)?;
    let after_key = &obj[idx + needle.len()..];
    let colon_idx = after_key.find(':')?;
    let val_part = after_key[colon_idx + 1..].trim_start();
    let rest = val_part.strip_prefix('"')?;
    let mut out = String::new();
    let mut escaped = false;
    for ch in rest.chars() {
        if escaped {
            match ch {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                other => out.push(other),
            }
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(out);
        } else {
            out.push(ch);
        }
    }
    None
}

fn parse_mcp_edits_array(raw: &str) -> Result<Vec<BTreeMap<String, String>>, CliError> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Err(CliError::InvalidArgument(
            "expected 'edits' to be a JSON array of edit objects".to_string(),
        ));
    }
    let mut objects = Vec::new();
    let mut depth = 0usize;
    let mut obj_start: Option<usize> = None;
    let mut in_str = false;
    let mut esc = false;
    for (byte_idx, ch) in trimmed.char_indices() {
        if in_str {
            if esc {
                esc = false;
            } else if ch == '\\' {
                esc = true;
            } else if ch == '"' {
                in_str = false;
            }
        } else if ch == '"' {
            in_str = true;
        } else if ch == '{' {
            if depth == 0 {
                obj_start = Some(byte_idx);
            }
            depth += 1;
        } else if ch == '}' {
            if depth == 0 {
                return Err(CliError::InvalidArgument(
                    "malformed 'edits' JSON array".to_string(),
                ));
            }
            depth -= 1;
            if depth == 0 {
                if let Some(start) = obj_start.take() {
                    let slice = &trimmed[start..byte_idx + ch.len_utf8()];
                    let mut map = BTreeMap::new();
                    for k in ["path", "content", "op", "file_type"] {
                        if let Some(v) = extract_unescaped_json_str(slice, k) {
                            map.insert(k.to_string(), v);
                        }
                    }
                    objects.push(map);
                }
            }
        }
    }
    if objects.is_empty() {
        return Err(CliError::InvalidArgument(
            "'edits' array must contain at least one edit".to_string(),
        ));
    }
    Ok(objects)
}

fn build_mcp_patch_edit(
    engine: &ScionEngine,
    base_changeset: Option<ChangesetId>,
    edit_args: &BTreeMap<String, String>,
) -> Result<PatchFileEdit, CliError> {
    let path_str = edit_args
        .get("path")
        .ok_or_else(|| CliError::InvalidArgument("missing 'path'".to_string()))?;
    let path = MPath::new(path_str)?;
    let op = edit_args
        .get("op")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "upsert".to_string());
    match op.as_str() {
        "delete" => Ok(PatchFileEdit::Delete { path }),
        "upsert" | "" => {
            let content = edit_args.get("content").ok_or_else(|| {
                CliError::InvalidArgument(
                    "missing 'content' for upsert operation (set op='delete' to delete a file)"
                        .to_string(),
                )
            })?;
            let file_type = match edit_args
                .get("file_type")
                .map(|s| s.trim().to_ascii_lowercase())
                .as_deref()
            {
                Some("executable") => FileType::Executable,
                Some("symlink") => FileType::Symlink,
                Some("regular") | Some("") => FileType::Regular,
                Some(other) => {
                    return Err(CliError::InvalidArgument(format!(
                        "invalid file_type '{}' (expected 'regular', 'executable', or 'symlink')",
                        other
                    )));
                }
                None => base_changeset
                    .and_then(|base_id| lookup_file_type_at_changeset(engine, base_id, &path))
                    .unwrap_or(FileType::Regular),
            };
            Ok(PatchFileEdit::Upsert {
                path,
                content: content.as_bytes().to_vec(),
                file_type,
            })
        }
        other => Err(CliError::InvalidArgument(format!(
            "invalid edit op '{}' (expected 'upsert' or 'delete')",
            other
        ))),
    }
}

/// Receipt returned by [`checkout_stateless`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutReceipt {
    pub changeset_id: ChangesetId,
    pub root_fsnode_id: FsnodeId,
    pub files_materialized: u64,
    pub bytes_materialized: u64,
}

/// Executes a stateless top-down Merkle tree-walk checkout of `cs_id` into `dest_dir`.
///
/// Unlike Git's stateful fetch negotiation, `checkout_stateless` begins at `root_fsnode_id`,
/// prunes any directory subtree that does not overlap `sparse_prefixes`, and fetches only the
/// missing `Fsnode` and `Blob` objects through the 3-tier content-addressed cache.
pub fn checkout_stateless(
    engine: &ScionEngine,
    cs_id: ChangesetId,
    sparse_prefixes: Option<&[MPath]>,
    dest_dir: &Path,
) -> Result<CheckoutReceipt, CliError> {
    let root_fsnode_id = engine
        .derived()
        .derive_fsnode(cs_id)
        .map_err(EngineError::Derived)?;
    fs::create_dir_all(dest_dir)?;

    let mut pending_files: Vec<(MPath, BlobId, FileType)> = Vec::new();

    walk_fsnode_stateless(
        engine,
        &root_fsnode_id,
        None,
        sparse_prefixes,
        dest_dir,
        &mut pending_files,
    )?;

    // Batch-fetch all unique selected file blobs in one coalesced call
    let mut unique_blob_ids: Vec<BlobId> = Vec::new();
    let mut seen_blobs = std::collections::BTreeSet::new();
    for (_path, blob_id, _ft) in &pending_files {
        if seen_blobs.insert(*blob_id) {
            unique_blob_ids.push(*blob_id);
        }
    }

    let fetched_blobs = engine
        .blobs()
        .get_blobs_batch(&unique_blob_ids)
        .map_err(EngineError::Store)?;

    let mut blob_map: BTreeMap<BlobId, Vec<u8>> = BTreeMap::new();
    for (blob_id, opt_bytes) in unique_blob_ids.into_iter().zip(fetched_blobs) {
        if let Some(bytes) = opt_bytes {
            blob_map.insert(blob_id, bytes);
        }
    }

    let mut files_materialized = 0u64;
    let mut bytes_materialized = 0u64;

    for (child_path, blob_id, file_type) in pending_files {
        let content = blob_map
            .get(&blob_id)
            .ok_or_else(|| CliError::Engine(EngineError::PathNotFound(child_path.to_string())))?;

        let rel_str = child_path.to_string();
        let disk_path = dest_dir.join(&rel_str);
        if let Some(parent_dir) = disk_path.parent() {
            if let Ok(pmeta) = fs::symlink_metadata(parent_dir) {
                if !pmeta.file_type().is_dir() {
                    fs::remove_file(parent_dir)?;
                }
            }
            fs::create_dir_all(parent_dir)?;
        }

        // Remove existing file, symlink, or directory if overwriting
        if let Ok(meta) = fs::symlink_metadata(&disk_path) {
            if meta.file_type().is_dir() {
                fs::remove_dir_all(&disk_path)?;
            } else {
                fs::remove_file(&disk_path)?;
            }
        }

        match file_type {
            FileType::Symlink => {
                #[cfg(unix)]
                {
                    use std::ffi::OsStr;
                    use std::os::unix::ffi::OsStrExt;
                    let target = Path::new(OsStr::from_bytes(content));
                    std::os::unix::fs::symlink(target, &disk_path)?;
                }
                #[cfg(not(unix))]
                {
                    fs::write(&disk_path, content)?;
                }
            }
            FileType::Executable => {
                fs::write(&disk_path, content)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&disk_path, fs::Permissions::from_mode(0o755))?;
                }
            }
            FileType::Regular => {
                fs::write(&disk_path, content)?;
            }
        }

        files_materialized += 1;
        bytes_materialized += content.len() as u64;
    }

    save_workspace_base_changeset(dest_dir, cs_id)?;

    Ok(CheckoutReceipt {
        changeset_id: cs_id,
        root_fsnode_id,
        files_materialized,
        bytes_materialized,
    })
}

/// Loads the workspace base changeset ID recorded in `<dir>/.inarch/workspace_state.toml` if present.
pub fn load_workspace_base_changeset(dir: &Path) -> Result<Option<ChangesetId>, CliError> {
    let state_file = dir.join(".inarch").join("workspace_state.toml");
    let Ok(raw) = fs::read_to_string(&state_file) else {
        return Ok(None);
    };
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            if k.trim() == "changeset_id" {
                let hex = v.trim().trim_matches('"').trim_matches('\'').trim();
                if !hex.is_empty() {
                    return Ok(Some(ChangesetId::from_hex(hex)?));
                }
            }
        }
    }
    Ok(None)
}

/// Persists the workspace base changeset ID in `<dir>/.inarch/workspace_state.toml`.
pub fn save_workspace_base_changeset(dir: &Path, cs_id: ChangesetId) -> Result<(), CliError> {
    let inarch_dir = dir.join(".inarch");
    fs::create_dir_all(&inarch_dir)?;
    let state_file = inarch_dir.join("workspace_state.toml");
    let content = format!("changeset_id = \"{}\"\n", cs_id.to_hex());
    fs::write(&state_file, content)?;
    Ok(())
}

fn walk_fsnode_stateless(
    engine: &ScionEngine,
    fsnode_id: &FsnodeId,
    current_prefix: Option<MPath>,
    sparse_prefixes: Option<&[MPath]>,
    dest_dir: &Path,
    pending_files: &mut Vec<(MPath, BlobId, FileType)>,
) -> Result<(), CliError> {
    let node = engine
        .derived()
        .load_fsnode(fsnode_id)
        .map_err(EngineError::Derived)?;

    let current_disk_dir = match &current_prefix {
        Some(prefix) => dest_dir.join(prefix.as_str()),
        None => dest_dir.to_path_buf(),
    };

    // If `current_disk_dir` exists on disk as a regular file or symlink (e.g. File -> Directory transition),
    // remove the file before creating the directory.
    if let Ok(meta) = fs::symlink_metadata(&current_disk_dir) {
        if !meta.file_type().is_dir() {
            fs::remove_file(&current_disk_dir)?;
        }
    }

    // If `current_disk_dir` already exists on disk as a directory, prune any stale entries
    // (or mismatched file vs directory types) within the active sparse scope.
    if current_disk_dir.is_dir() {
        for dir_entry_res in fs::read_dir(&current_disk_dir)? {
            let dir_entry = dir_entry_res?;
            let fname = dir_entry.file_name();
            let Some(fname_str) = fname.to_str() else {
                continue;
            };
            if current_prefix.is_none() && (fname_str == ".git" || fname_str == ".inarch") {
                continue;
            }

            let entry_path = dir_entry.path();
            let meta = fs::symlink_metadata(&entry_path)?;
            let is_disk_dir = meta.file_type().is_dir();

            let expected_entry = MPath::new(fname_str)
                .ok()
                .and_then(|m| m.elements().first().cloned())
                .and_then(|elem| node.entries.get(&elem));

            let should_remove = match expected_entry {
                None => {
                    // Entry is not present in target Fsnode; remove if within sparse filter scope (or if un-prefixed).
                    if let Ok(elem_mpath) = MPath::new(fname_str) {
                        let candidate_path = match &current_prefix {
                            Some(prefix) => prefix.join_element(&elem_mpath.elements()[0]),
                            None => elem_mpath,
                        };
                        if is_disk_dir {
                            subtree_overlaps_sparse_filter(&candidate_path, sparse_prefixes)
                        } else {
                            file_matches_sparse_filter(&candidate_path, sparse_prefixes)
                        }
                    } else {
                        true
                    }
                }
                Some(FsnodeEntry::File { .. }) => is_disk_dir,
                Some(FsnodeEntry::Directory { .. }) => !is_disk_dir,
            };

            if should_remove {
                if is_disk_dir {
                    fs::remove_dir_all(&entry_path)?;
                } else {
                    fs::remove_file(&entry_path)?;
                }
            }
        }
    }

    // Prefetch matching child Fsnodes at this directory depth in a single batch
    let mut matching_child_fsnodes = Vec::new();
    for (name, entry) in &node.entries {
        if let FsnodeEntry::Directory {
            fsnode_id: child_fsnode_id,
            ..
        } = entry
        {
            let child_path = match &current_prefix {
                Some(prefix) => prefix.join_element(name),
                None => {
                    MPath::from_elements(vec![name.clone()]).expect("single element is non-empty")
                }
            };
            if subtree_overlaps_sparse_filter(&child_path, sparse_prefixes) {
                matching_child_fsnodes
                    .push((inarch_types::hash::ObjectDomain::Fsnode, child_fsnode_id.0));
            }
        }
    }
    if matching_child_fsnodes.len() > 1 {
        let _ = engine
            .blobs()
            .get_objects_batch(&matching_child_fsnodes)
            .map_err(EngineError::Store)?;
    }

    for (name, entry) in &node.entries {
        let child_path = match &current_prefix {
            Some(prefix) => prefix.join_element(name),
            None => MPath::from_elements(vec![name.clone()]).expect("single element is non-empty"),
        };

        match entry {
            FsnodeEntry::Directory {
                fsnode_id: child_fsnode_id,
                ..
            } => {
                if !subtree_overlaps_sparse_filter(&child_path, sparse_prefixes) {
                    // Prune entire directory subtree before fetching child Fsnode or any child Blobs!
                    continue;
                }
                walk_fsnode_stateless(
                    engine,
                    child_fsnode_id,
                    Some(child_path),
                    sparse_prefixes,
                    dest_dir,
                    pending_files,
                )?;
            }
            FsnodeEntry::File {
                blob_id, file_type, ..
            } => {
                if !file_matches_sparse_filter(&child_path, sparse_prefixes) {
                    continue;
                }
                pending_files.push((child_path, *blob_id, *file_type));
            }
        }
    }

    Ok(())
}

fn subtree_overlaps_sparse_filter(dir_path: &MPath, sparse_prefixes: Option<&[MPath]>) -> bool {
    let Some(prefixes) = sparse_prefixes else {
        return true;
    };
    prefixes
        .iter()
        .any(|p| p.is_prefix_of(dir_path) || dir_path.is_prefix_of(p))
}

fn file_matches_sparse_filter(file_path: &MPath, sparse_prefixes: Option<&[MPath]>) -> bool {
    let Some(prefixes) = sparse_prefixes else {
        return true;
    };
    prefixes.iter().any(|p| p.is_prefix_of(file_path))
}

/// Receipt returned by [`ingest_directory`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestReceipt {
    pub changeset_id: ChangesetId,
    pub files_scanned: u64,
    pub files_upserted: u64,
    pub files_deleted: u64,
    pub bytes_ingested: u64,
}

/// Report returned by [`verify_codebase_accuracy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    pub changeset_id: ChangesetId,
    pub root_fsnode_id: FsnodeId,
    pub files_verified: u64,
    pub bytes_verified: u64,
}

impl VerificationReport {
    pub fn is_clean(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
struct DiskFileRecord {
    content: Vec<u8>,
    blob_id: BlobId,
    file_type: FileType,
}

/// Recursively ingests a real codebase directory on disk into `target_ref`.
///
/// If `target_ref` already resolves to a parent commit, `ingest_directory` computes the exact
/// incremental delta against the parent's `Fsnode` tree so only added, modified, or deleted
/// files are recorded in the resulting `BonsaiChangeset`.
pub fn ingest_directory(
    engine: &ScionEngine,
    target_ref: &str,
    author: &str,
    timestamp: i64,
    message: &str,
    source_dir: &Path,
    ignore_names: &[&str],
) -> Result<IngestReceipt, CliError> {
    let virtual_mount = VirtualMountManifest::load_if_present(source_dir)?;
    let mut disk_files = BTreeMap::new();
    scan_disk_directory(source_dir, source_dir, ignore_names, &mut disk_files)?;

    let files_scanned = disk_files.len() as u64;
    let bytes_ingested: u64 = disk_files.values().map(|r| r.content.len() as u64).sum();

    let workspace_base = load_workspace_base_changeset(source_dir)?
        .filter(|cs_id| engine.meta().get_changeset(cs_id).ok().flatten().is_some());
    let base_changeset = if let Some(ws_cs) = workspace_base {
        Some(ws_cs)
    } else if let Some(ref vm) = virtual_mount {
        Some(vm.changeset_id)
    } else {
        engine.resolve_ref(target_ref)?
    };
    let mut prior_files = BTreeMap::new();
    if let Some(base_id) = base_changeset {
        let base_fsnode_id = engine
            .derived()
            .derive_fsnode(base_id)
            .map_err(EngineError::Derived)?;
        collect_fsnode_files(engine, &base_fsnode_id, None, &mut prior_files)?;
    }

    let mut edits = Vec::new();
    let mut files_upserted = 0u64;
    let mut files_deleted = 0u64;

    for (path, disk_rec) in &disk_files {
        let needs_upsert = match prior_files.get(path) {
            Some((prior_blob_id, _prior_size, prior_type)) => {
                *prior_blob_id != disk_rec.blob_id || *prior_type != disk_rec.file_type
            }
            None => true,
        };
        if needs_upsert {
            edits.push(PatchFileEdit::Upsert {
                path: path.clone(),
                content: disk_rec.content.clone(),
                file_type: disk_rec.file_type,
            });
            files_upserted += 1;
        }
    }

    let sparse_filter: Option<Vec<MPath>> = {
        let sp_file = source_dir.join(".inarch").join("sparse_prefixes");
        if let Ok(raw) = fs::read_to_string(&sp_file) {
            let parsed: Vec<MPath> = raw
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .filter_map(|l| MPath::new(l).ok())
                .collect();
            if parsed.is_empty() {
                None
            } else {
                Some(parsed)
            }
        } else {
            None
        }
    };

    for prior_path in prior_files.keys() {
        if !file_matches_sparse_filter(prior_path, sparse_filter.as_deref()) {
            continue;
        }
        // In a virtualized workspace mount, unhydrated files are intentionally absent on disk
        // and must NOT be treated as deletions unless they were hydrated first.
        if let Some(ref vm) = virtual_mount {
            if !vm.hydrated_paths.contains(prior_path.as_str()) {
                continue;
            }
        }
        if !disk_files.contains_key(prior_path) {
            edits.push(PatchFileEdit::Delete {
                path: prior_path.clone(),
            });
            files_deleted += 1;
        }
    }

    let outcome = engine.land_patch(PatchSubmission {
        target_ref: target_ref.to_string(),
        base_changeset,
        author: author.to_string(),
        timestamp,
        tz_offset_secs: 0,
        message: message.to_string(),
        extra: BTreeMap::new(),
        edits,
    })?;

    if let Some(mut vm) = virtual_mount {
        vm.changeset_id = outcome.changeset_id;
        vm.root_fsnode_id = engine
            .derived()
            .derive_fsnode(outcome.changeset_id)
            .map_err(EngineError::Derived)?;
        for p in disk_files.keys() {
            vm.hydrated_paths.insert(p.as_str().to_string());
        }
        vm.save(source_dir)?;
    }

    if workspace_base.is_some()
        || source_dir.join(".inarch").exists()
        || !source_dir.join(".git").exists()
    {
        save_workspace_base_changeset(source_dir, outcome.changeset_id)?;
    }

    Ok(IngestReceipt {
        changeset_id: outcome.changeset_id,
        files_scanned,
        files_upserted,
        files_deleted,
        bytes_ingested,
    })
}

/// Exhaustively verifies that every file in `source_dir` (excluding `ignore_names`) matches
/// the stored codebase at `cs_id` with 100% byte-for-byte, BLAKE3 `BlobId`, `FileType`, and
/// recursive `FsnodeSummary` accuracy.
pub fn verify_codebase_accuracy(
    engine: &ScionEngine,
    cs_id: ChangesetId,
    source_dir: &Path,
    ignore_names: &[&str],
) -> Result<VerificationReport, CliError> {
    let virtual_mount = VirtualMountManifest::load_if_present(source_dir)?;
    let sparse_filter: Option<Vec<MPath>> = {
        let sp_file = source_dir.join(".inarch").join("sparse_prefixes");
        if let Ok(raw) = fs::read_to_string(&sp_file) {
            let parsed: Vec<MPath> = raw
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .filter_map(|l| MPath::new(l).ok())
                .collect();
            if parsed.is_empty() {
                None
            } else {
                Some(parsed)
            }
        } else {
            None
        }
    };
    let mut disk_files = BTreeMap::new();
    scan_disk_directory(source_dir, source_dir, ignore_names, &mut disk_files)?;

    let root_fsnode_id = engine
        .derived()
        .derive_fsnode(cs_id)
        .map_err(EngineError::Derived)?;

    let mut stored_files = BTreeMap::new();
    let (actual_root_count, actual_root_bytes) =
        collect_fsnode_files(engine, &root_fsnode_id, None, &mut stored_files)?;

    // Check that the set of paths matches 100% (no missing or extra files)
    for path in disk_files.keys() {
        if !stored_files.contains_key(path) {
            return Err(CliError::VerificationMismatch(format!(
                "file '{}' exists on disk but is missing from Fsnode tree at {}",
                path, cs_id
            )));
        }
    }
    for path in stored_files.keys() {
        if !disk_files.contains_key(path) {
            if !file_matches_sparse_filter(path, sparse_filter.as_deref()) {
                continue;
            }
            if let Some(ref vm) = virtual_mount {
                if !vm.hydrated_paths.contains(path.as_str()) {
                    continue;
                }
            }
            return Err(CliError::VerificationMismatch(format!(
                "file '{}' exists in Fsnode tree at {} but is missing on disk",
                path, cs_id
            )));
        }
    }

    // Batch-prefetch all unique blobs into Tier-1 cache so subsequent `engine.read_file` calls
    // execute at local cache speed even against a remote or cloud Tier-3 backend.
    let mut unique_blob_ids = Vec::new();
    let mut seen_blobs = std::collections::BTreeSet::new();
    for (blob_id, _, _) in stored_files.values() {
        if seen_blobs.insert(*blob_id) {
            unique_blob_ids.push(*blob_id);
        }
    }
    if unique_blob_ids.len() > 1 {
        let _ = engine
            .blobs()
            .get_blobs_batch(&unique_blob_ids)
            .map_err(EngineError::Store)?;
    }

    let mut files_verified = 0u64;
    let mut bytes_verified = 0u64;

    for (path, disk_rec) in &disk_files {
        let (stored_blob_id, stored_size, stored_type) = stored_files
            .get(path)
            .expect("verified path presence above");

        if *stored_blob_id != disk_rec.blob_id {
            return Err(CliError::VerificationMismatch(format!(
                "BlobId mismatch for '{}': disk={}, fsnode={}",
                path, disk_rec.blob_id, stored_blob_id
            )));
        }

        if *stored_size != disk_rec.content.len() as u64 {
            return Err(CliError::VerificationMismatch(format!(
                "size mismatch for '{}': disk={}, fsnode={}",
                path,
                disk_rec.content.len(),
                stored_size
            )));
        }

        if *stored_type != disk_rec.file_type {
            return Err(CliError::VerificationMismatch(format!(
                "FileType mismatch for '{}': disk={:?}, fsnode={:?}",
                path, disk_rec.file_type, stored_type
            )));
        }

        // Perform a full checkout-free `read_file` (reassembling FastCDC chunks and verifying BLAKE3)
        let read_bytes = engine.read_file(cs_id, path)?;
        if read_bytes != disk_rec.content {
            return Err(CliError::VerificationMismatch(format!(
                "byte-for-byte content mismatch on read_file for '{}'",
                path
            )));
        }

        let recomputed_blob_id = BlobId::from_content(&read_bytes);
        if recomputed_blob_id != disk_rec.blob_id {
            return Err(CliError::VerificationMismatch(format!(
                "recomputed BlobId mismatch for '{}'",
                path
            )));
        }

        files_verified += 1;
        bytes_verified += read_bytes.len() as u64;
    }

    if virtual_mount.is_some() || sparse_filter.is_some() {
        for (path, (stored_blob_id, stored_size, _)) in &stored_files {
            if disk_files.contains_key(path) {
                continue;
            }
            let read_bytes = engine.read_file(cs_id, path)?;
            if read_bytes.len() as u64 != *stored_size {
                return Err(CliError::VerificationMismatch(format!(
                    "virtual unhydrated size mismatch for '{}'",
                    path
                )));
            }
            if BlobId::from_content(&read_bytes) != *stored_blob_id {
                return Err(CliError::VerificationMismatch(format!(
                    "virtual unhydrated BlobId mismatch for '{}'",
                    path
                )));
            }
            files_verified += 1;
            bytes_verified += read_bytes.len() as u64;
        }
    }

    if actual_root_count != files_verified || actual_root_bytes != bytes_verified {
        return Err(CliError::VerificationMismatch(format!(
            "root Fsnode summary ({} files, {} bytes) did not match verified totals ({} files, {} bytes)",
            actual_root_count, actual_root_bytes, files_verified, bytes_verified
        )));
    }

    Ok(VerificationReport {
        changeset_id: cs_id,
        root_fsnode_id,
        files_verified,
        bytes_verified,
    })
}

fn scan_disk_directory(
    root_dir: &Path,
    current_dir: &Path,
    ignore_names: &[&str],
    out: &mut BTreeMap<MPath, DiskFileRecord>,
) -> Result<(), CliError> {
    let mut entries: Vec<_> = fs::read_dir(current_dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let fname = entry.file_name();
        let Some(fname_str) = fname.to_str() else {
            continue;
        };
        if (current_dir == root_dir && (fname_str == ".inarch" || fname_str == ".git"))
            || ignore_names.contains(&fname_str)
        {
            continue;
        }

        let entry_path = entry.path();
        let meta = fs::symlink_metadata(&entry_path)?;
        let ftype = meta.file_type();

        if ftype.is_dir() {
            scan_disk_directory(root_dir, &entry_path, ignore_names, out)?;
        } else if ftype.is_symlink() || ftype.is_file() {
            let rel_path = entry_path
                .strip_prefix(root_dir)
                .map_err(|e| CliError::Io(e.to_string()))?;
            let rel_str = rel_path
                .to_str()
                .ok_or_else(|| CliError::Io("non-UTF8 path".to_string()))?
                .replace('\\', "/");
            let mpath = MPath::new(&rel_str)?;

            let (content, file_type) = if ftype.is_symlink() {
                let link_target = fs::read_link(&entry_path)?;
                #[cfg(unix)]
                let bytes = {
                    use std::os::unix::ffi::OsStrExt;
                    link_target.as_os_str().as_bytes().to_vec()
                };
                #[cfg(not(unix))]
                let bytes = link_target.to_string_lossy().as_bytes().to_vec();
                (bytes, FileType::Symlink)
            } else {
                let bytes = fs::read(&entry_path)?;
                #[cfg(unix)]
                let is_exec = {
                    use std::os::unix::fs::PermissionsExt;
                    meta.permissions().mode() & 0o111 != 0
                };
                #[cfg(not(unix))]
                let is_exec = false;
                let kind = if is_exec {
                    FileType::Executable
                } else {
                    FileType::Regular
                };
                (bytes, kind)
            };

            let blob_id = BlobId::from_content(&content);
            out.insert(
                mpath,
                DiskFileRecord {
                    content,
                    blob_id,
                    file_type,
                },
            );
        }
    }

    Ok(())
}

fn collect_fsnode_files(
    engine: &ScionEngine,
    fsnode_id: &FsnodeId,
    current_prefix: Option<MPath>,
    out: &mut BTreeMap<MPath, (BlobId, u64, FileType)>,
) -> Result<(u64, u64), CliError> {
    let node = engine
        .derived()
        .load_fsnode(fsnode_id)
        .map_err(EngineError::Derived)?;

    let mut child_fsnode_keys = Vec::new();
    for entry in node.entries.values() {
        if let FsnodeEntry::Directory {
            fsnode_id: child_id,
            ..
        } = entry
        {
            child_fsnode_keys.push((inarch_types::hash::ObjectDomain::Fsnode, child_id.0));
        }
    }
    if child_fsnode_keys.len() > 1 {
        let _ = engine
            .blobs()
            .get_objects_batch(&child_fsnode_keys)
            .map_err(EngineError::Store)?;
    }

    let mut total_files = 0u64;
    let mut total_bytes = 0u64;

    for (name, entry) in &node.entries {
        let child_path = match &current_prefix {
            Some(prefix) => prefix.join_element(name),
            None => MPath::from_elements(vec![name.clone()]).expect("single element is non-empty"),
        };

        match entry {
            FsnodeEntry::Directory {
                fsnode_id: child_id,
                summary,
            } => {
                let (sub_files, sub_bytes) =
                    collect_fsnode_files(engine, child_id, Some(child_path.clone()), out)?;
                if summary.descendant_files_count != sub_files
                    || summary.descendant_files_total_size != sub_bytes
                {
                    return Err(CliError::VerificationMismatch(format!(
                        "FsnodeSummary mismatch on directory '{}': summary=({}, {}), actual=({}, {})",
                        child_path,
                        summary.descendant_files_count,
                        summary.descendant_files_total_size,
                        sub_files,
                        sub_bytes
                    )));
                }
                total_files += sub_files;
                total_bytes += sub_bytes;
            }
            FsnodeEntry::File {
                blob_id,
                size,
                file_type,
            } => {
                out.insert(child_path, (*blob_id, *size, *file_type));
                total_files += 1;
                total_bytes += *size;
            }
        }
    }

    Ok((total_files, total_bytes))
}

/// Handle to a background Velenza Inarch HTTP/1.1 RPC server (`inr serve`).
pub struct HttpServerHandle {
    local_addr: std::net::SocketAddr,
    stop: Arc<std::sync::atomic::AtomicBool>,
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl HttpServerHandle {
    /// Returns the bound `SocketAddr` of the running server.
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    /// Returns the base HTTP URL (`http://<ip>:<port>`) of the running server.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.local_addr)
    }

    /// Signals the server to stop and waits for the accept loop thread to exit.
    pub fn shutdown(mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(self.local_addr);
        if let Some(h) = self.join_handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for HttpServerHandle {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(self.local_addr);
        if let Some(h) = self.join_handle.take() {
            let _ = h.join();
        }
    }
}

/// Maximum HTTP request body size accepted by the RPC server (257 MiB).
pub const MAX_HTTP_BODY_BYTES: usize = 257 * 1024 * 1024;

/// Authentication and authorization configuration for the Velenza Inarch HTTP RPC server.
#[derive(Clone, Debug)]
pub struct ServerAuthConfig {
    /// Optional shared admin/bootstrap token (`Authorization: Bearer <token>`).
    pub admin_token: Option<String>,
    /// Optional 32-byte BLAKE3 keyed-hash key used to mint and verify `inarch_jit_v1_...` lease tokens.
    pub jit_signing_key: Option<[u8; 32]>,
    /// Optional OIDC tokeninfo verification URL (e.g. `https://oauth2.googleapis.com/tokeninfo`).
    pub oidc_tokeninfo_url: Option<String>,
    /// Optional expected `aud` claim for OIDC ID tokens.
    pub oidc_audience: Option<String>,
    /// Whether unauthenticated requests (other than `GET /health`) must be rejected.
    pub require_auth: bool,
    /// In-memory cache of verified OIDC `(aud, id_token)` -> `(email, exp_unix)`.
    pub oidc_cache: Arc<std::sync::Mutex<BTreeMap<String, (String, i64)>>>,
}

impl ServerAuthConfig {
    pub fn new(admin_token: Option<String>) -> Self {
        let token = admin_token.and_then(|t| {
            let trimmed = t.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });
        Self {
            admin_token: token,
            jit_signing_key: None,
            oidc_tokeninfo_url: None,
            oidc_audience: None,
            require_auth: true,
            oidc_cache: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        }
    }

    /// Explicitly constructs an unauthenticated server configuration for local unit tests only.
    pub fn insecure_allow_anonymous() -> Self {
        Self {
            admin_token: None,
            jit_signing_key: None,
            oidc_tokeninfo_url: None,
            oidc_audience: None,
            require_auth: false,
            oidc_cache: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        }
    }

    pub fn from_inarch_config(cfg: &InarchConfig) -> Result<Self, CliError> {
        let admin_token = {
            let trimmed = cfg.auth_token.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        };
        let trimmed_key = cfg.jit_signing_key.trim();
        if trimmed_key.is_empty()
            || trimmed_key == "velenza-inarch-default-jit-signing-seed"
            || trimmed_key.starts_with("REPLACE_WITH")
        {
            return Err(CliError::InvalidArgument(
                "jit_signing_key must be explicitly configured with a secret key".to_string(),
            ));
        }
        let jit_signing_key = Some(inarch_store::derive_jit_signing_key(trimmed_key));
        let oidc_tokeninfo_url = {
            let trimmed = cfg.oidc_tokeninfo_url.trim().to_string();
            if trimmed.is_empty() {
                Some("https://oauth2.googleapis.com/tokeninfo".to_string())
            } else {
                Some(trimmed)
            }
        };
        let oidc_audience = {
            let trimmed = cfg.oidc_audience.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        };
        Ok(Self {
            admin_token,
            jit_signing_key,
            oidc_tokeninfo_url,
            oidc_audience,
            require_auth: true,
            oidc_cache: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        })
    }
}

/// Validates that `inr serve` does not bind a plaintext HTTP listener to a non-loopback address
/// unless explicitly overridden via `--allow-plaintext-non-loopback` or
/// `INARCH_ALLOW_PLAINTEXT_NON_LOOPBACK=1`.
pub fn validate_serve_bind_address(
    listen_addr: &str,
    allow_plaintext_non_loopback: bool,
) -> Result<(), CliError> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = listen_addr
        .to_socket_addrs()
        .map_err(|e| {
            CliError::InvalidArgument(format!("invalid listen address '{}': {}", listen_addr, e))
        })?
        .collect();
    if addrs.is_empty() {
        return Err(CliError::InvalidArgument(format!(
            "listen address '{}' did not resolve to any socket addresses",
            listen_addr
        )));
    }
    let env_allow = std::env::var("INARCH_ALLOW_PLAINTEXT_NON_LOOPBACK")
        .map(|v| v.trim() == "1" || v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !allow_plaintext_non_loopback && !env_allow && addrs.iter().any(|a| !a.ip().is_loopback()) {
        return Err(CliError::InvalidArgument(format!(
            "refusing to bind plaintext HTTP server to non-loopback address '{}' without --allow-plaintext-non-loopback or INARCH_ALLOW_PLAINTEXT_NON_LOOPBACK=1 (terminate TLS at a reverse proxy or pass the explicit override)",
            listen_addr
        )));
    }
    Ok(())
}

/// Spawns a non-blocking Velenza Inarch HTTP/1.1 keep-alive RPC server (`GET /health`, `GET /v1/refs`, `POST /v1/rpc`).
pub fn spawn_http_server(
    engine: Arc<ScionEngine>,
    listen_addr: &str,
    auth_token: Option<String>,
) -> Result<HttpServerHandle, CliError> {
    spawn_http_server_with_config(engine, listen_addr, ServerAuthConfig::new(auth_token))
}

/// Spawns a non-blocking Velenza Inarch HTTP/1.1 keep-alive RPC server with full [`ServerAuthConfig`].
pub fn spawn_http_server_with_config(
    engine: Arc<ScionEngine>,
    listen_addr: &str,
    auth_cfg: ServerAuthConfig,
) -> Result<HttpServerHandle, CliError> {
    let listener = std::net::TcpListener::bind(listen_addr)?;
    let local_addr = listener.local_addr()?;
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    let join_handle = std::thread::spawn(move || {
        accept_http_loop(listener, engine, auth_cfg, stop_clone);
    });

    Ok(HttpServerHandle {
        local_addr,
        stop,
        join_handle: Some(join_handle),
    })
}

/// Runs the Velenza Inarch HTTP/1.1 keep-alive RPC server on the current thread until interrupted.
pub fn serve_http_blocking(
    engine: Arc<ScionEngine>,
    listen_addr: &str,
    auth_token: Option<String>,
) -> Result<(), CliError> {
    serve_http_blocking_with_config(engine, listen_addr, ServerAuthConfig::new(auth_token))
}

/// Runs the Velenza Inarch HTTP/1.1 keep-alive RPC server with full [`ServerAuthConfig`] on the current thread.
pub fn serve_http_blocking_with_config(
    engine: Arc<ScionEngine>,
    listen_addr: &str,
    auth_cfg: ServerAuthConfig,
) -> Result<(), CliError> {
    let listener = std::net::TcpListener::bind(listen_addr)?;
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    accept_http_loop(listener, engine, auth_cfg, stop);
    Ok(())
}

fn accept_http_loop(
    listener: std::net::TcpListener,
    engine: Arc<ScionEngine>,
    auth_cfg: ServerAuthConfig,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    for stream_res in listener.incoming() {
        if stop.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        let Ok(stream) = stream_res else {
            continue;
        };
        let _ = stream.set_nodelay(true);
        let eng = Arc::clone(&engine);
        let cfg = auth_cfg.clone();
        let stop_conn = Arc::clone(&stop);
        std::thread::spawn(move || {
            handle_http_connection(stream, eng, cfg, stop_conn);
        });
    }
}

#[derive(Clone, Debug)]
struct RpcAuthContext {
    caller_principal_id: String,
    caller_role: String,
    auth_method: String,
    jit_signing_key: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
struct ResolvedCallerPolicy {
    rpc_ctx: RpcAuthContext,
    allowed_repos: Vec<String>,
    allowed_ops: Vec<String>,
    allowed_write_prefixes: Vec<String>,
    active_lease: Option<inarch_store::JitLeaseRecord>,
}

fn current_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn extract_json_field_str(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let idx = json.find(&needle)?;
    let after_key = &json[idx + needle.len()..];
    let colon_idx = after_key.find(':')?;
    let val_part = after_key[colon_idx + 1..].trim_start();
    if let Some(rest) = val_part.strip_prefix('"') {
        let mut out = String::new();
        let mut escaped = false;
        for ch in rest.chars() {
            if escaped {
                out.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                return Some(out);
            } else {
                out.push(ch);
            }
        }
        None
    } else {
        let end = val_part
            .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
            .unwrap_or(val_part.len());
        let token = val_part[..end].trim();
        if token.is_empty() {
            None
        } else {
            Some(token.to_string())
        }
    }
}

fn verify_oidc_id_token(
    id_token: &str,
    tokeninfo_url: &str,
    expected_aud: &str,
    cache: &Arc<std::sync::Mutex<BTreeMap<String, (String, i64)>>>,
) -> Result<String, String> {
    let now = current_unix_seconds();
    let cache_key = format!("{}::{}", expected_aud, id_token);
    if let Ok(guard) = cache.lock() {
        if let Some((email, exp)) = guard.get(&cache_key) {
            if *exp > now + 10 {
                return Ok(email.clone());
            }
        }
    }

    let full_url = if tokeninfo_url.contains('?') {
        format!("{}&id_token={}", tokeninfo_url, id_token)
    } else {
        format!("{}?id_token={}", tokeninfo_url, id_token)
    };

    let body_str = if let Some(rest) = full_url.strip_prefix("http://") {
        use std::io::{Read, Write};
        let (host_port, path_part) = match rest.split_once('/') {
            Some((hp, p)) => (hp, format!("/{}", p)),
            None => (rest, "/".to_string()),
        };
        let addr = if host_port.contains(':') {
            host_port.to_string()
        } else {
            format!("{}:80", host_port)
        };
        let mut s = std::net::TcpStream::connect(&addr)
            .map_err(|e| format!("failed to connect to OIDC endpoint {}: {}", addr, e))?;
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(10)));
        let _ = s.set_write_timeout(Some(std::time::Duration::from_secs(10)));
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path_part, host_port
        );
        s.write_all(req.as_bytes())
            .map_err(|e| format!("failed to send OIDC request: {}", e))?;
        let mut resp_bytes = Vec::new();
        s.read_to_end(&mut resp_bytes)
            .map_err(|e| format!("failed to read OIDC response: {}", e))?;
        let resp_str = String::from_utf8_lossy(&resp_bytes);
        let Some((hdr, body)) = resp_str.split_once("\r\n\r\n") else {
            return Err("malformed HTTP response from OIDC endpoint".to_string());
        };
        if !hdr.starts_with("HTTP/1.1 200") && !hdr.starts_with("HTTP/1.0 200") {
            return Err(format!("OIDC endpoint rejected token: {}", body.trim()));
        }
        body.to_string()
    } else {
        let output = std::process::Command::new("curl")
            .args(["-sS", "--max-time", "10", &full_url])
            .output()
            .map_err(|e| format!("failed to invoke curl for OIDC tokeninfo: {}", e))?;
        if !output.status.success() {
            return Err(format!(
                "OIDC tokeninfo curl failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        String::from_utf8_lossy(&output.stdout).to_string()
    };

    if let Some(err) = extract_json_field_str(&body_str, "error") {
        let desc = extract_json_field_str(&body_str, "error_description").unwrap_or_default();
        return Err(format!("OIDC token invalid ({}): {}", err, desc));
    }

    if let Some(verified) = extract_json_field_str(&body_str, "email_verified") {
        if verified != "true" {
            return Err("OIDC token email_verified is not true".to_string());
        }
    }

    let aud = extract_json_field_str(&body_str, "aud").unwrap_or_default();
    if aud != expected_aud {
        return Err(format!(
            "OIDC audience mismatch: expected '{}', got '{}'",
            expected_aud, aud
        ));
    }

    let email = extract_json_field_str(&body_str, "email")
        .filter(|e| !e.trim().is_empty())
        .ok_or_else(|| "OIDC token missing 'email' claim".to_string())?;

    let exp = extract_json_field_str(&body_str, "exp")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(now + 300);

    if exp <= now {
        return Err("OIDC token has expired".to_string());
    }

    if let Ok(mut guard) = cache.lock() {
        guard.insert(cache_key, (email.clone(), exp));
    }

    Ok(email)
}

fn authenticate_request_caller(
    auth_header: Option<&str>,
    meta: &dyn inarch_store::MetadataStore,
    auth_cfg: &ServerAuthConfig,
) -> Result<ResolvedCallerPolicy, String> {
    let bearer_tok = auth_header
        .and_then(|h| {
            h.strip_prefix("Bearer ")
                .or_else(|| h.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let Some(tok) = bearer_tok else {
        if auth_cfg.require_auth {
            return Err("missing Authorization Bearer token".to_string());
        }
        return Ok(ResolvedCallerPolicy {
            rpc_ctx: RpcAuthContext {
                caller_principal_id: "anonymous".to_string(),
                caller_role: "admin".to_string(),
                auth_method: "none".to_string(),
                jit_signing_key: auth_cfg.jit_signing_key,
            },
            allowed_repos: vec!["*".to_string()],
            allowed_ops: vec!["*".to_string()],
            allowed_write_prefixes: vec!["*".to_string()],
            active_lease: None,
        });
    };

    // 1. Check shared admin/bootstrap token
    if let Some(expected_admin) = &auth_cfg.admin_token {
        if tok == expected_admin {
            return Ok(ResolvedCallerPolicy {
                rpc_ctx: RpcAuthContext {
                    caller_principal_id: "admin@inarch.system".to_string(),
                    caller_role: "admin".to_string(),
                    auth_method: "admin_token".to_string(),
                    jit_signing_key: auth_cfg.jit_signing_key,
                },
                allowed_repos: vec!["*".to_string()],
                allowed_ops: vec!["*".to_string()],
                allowed_write_prefixes: vec!["*".to_string()],
                active_lease: None,
            });
        }
    }

    // 2. Check JIT Swarm Lease token (`inarch_jit_v1_<lease_id>_<mac>`)
    if tok.starts_with("inarch_jit_v1_") {
        let Some(signing_key) = auth_cfg.jit_signing_key.as_ref() else {
            return Err("JIT leases disabled: no jit_signing_key configured".to_string());
        };
        let (lease_id, _mac) = inarch_store::parse_jit_lease_token(tok)
            .ok_or_else(|| "malformed JIT lease token".to_string())?;
        let lease = meta
            .get_lease(lease_id)
            .map_err(|e| format!("failed to look up JIT lease '{}': {}", lease_id, e))?
            .ok_or_else(|| format!("unknown JIT lease '{}'", lease_id))?;

        if !inarch_store::verify_jit_lease_token(tok, &lease, signing_key) {
            return Err(format!("invalid signature on JIT lease '{}'", lease_id));
        }
        if lease.revoked {
            return Err(format!(
                "JIT lease '{}' has been checked in / revoked",
                lease_id
            ));
        }
        let now = current_unix_seconds();
        if now > lease.expires_at_unix {
            return Err(format!(
                "JIT lease '{}' expired at {} (now={})",
                lease_id, lease.expires_at_unix, now
            ));
        }

        // Also check that the issuing workstation principal (if enrolled in ScionPrincipals) has not been revoked
        if let Ok(Some(issuer)) = meta.get_principal(&lease.principal_email) {
            if issuer.status != "active" {
                return Err(format!(
                    "issuing principal '{}' for JIT lease '{}' is no longer active",
                    lease.principal_email, lease_id
                ));
            }
        }

        return Ok(ResolvedCallerPolicy {
            rpc_ctx: RpcAuthContext {
                caller_principal_id: format!(
                    "swarm:{}:{}:{}",
                    lease.swarm_id, lease.task_id, lease.lease_id
                ),
                caller_role: "jit_swarm".to_string(),
                auth_method: "jit_lease".to_string(),
                jit_signing_key: auth_cfg.jit_signing_key,
            },
            allowed_repos: vec![lease.repo_id.clone()],
            allowed_ops: lease.allowed_ops.clone(),
            allowed_write_prefixes: lease.allowed_write_prefixes.clone(),
            active_lease: Some(lease),
        });
    }

    // 3. Check Workstation / Service Account OIDC ID token
    if let Some(tokeninfo_url) = &auth_cfg.oidc_tokeninfo_url {
        let Some(expected_aud) = auth_cfg
            .oidc_audience
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return Err("OIDC disabled: no oidc_audience configured".to_string());
        };
        let email = verify_oidc_id_token(tok, tokeninfo_url, expected_aud, &auth_cfg.oidc_cache)?;
        let principal = meta
            .get_principal(&email)
            .map_err(|e| format!("failed to look up principal '{}': {}", email, e))?
            .ok_or_else(|| format!("principal '{}' is not enrolled in Velenza Inarch", email))?;

        if principal.status != "active" {
            return Err(format!(
                "principal '{}' has status '{}' (not active)",
                email, principal.status
            ));
        }

        return Ok(ResolvedCallerPolicy {
            rpc_ctx: RpcAuthContext {
                caller_principal_id: principal.principal_email.clone(),
                caller_role: principal.principal_kind.clone(),
                auth_method: "gcp_oidc".to_string(),
                jit_signing_key: auth_cfg.jit_signing_key,
            },
            allowed_repos: principal.allowed_repos.clone(),
            allowed_ops: principal.allowed_ops.clone(),
            allowed_write_prefixes: principal.allowed_write_prefixes.clone(),
            active_lease: None,
        });
    }

    Err("unauthorized bearer token".to_string())
}

fn repo_is_allowed(allowed_repos: &[String], requested_repo: &str) -> bool {
    allowed_repos
        .iter()
        .any(|r| r == "*" || r == requested_repo)
}

fn op_is_allowed(allowed_ops: &[String], required_op: &str) -> bool {
    allowed_ops.iter().any(|op| {
        op == "*"
            || op == "admin"
            || op == required_op
            || (required_op == "land" && op == "write")
            || (required_op == "write" && op == "land")
    })
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    let p = prefix.trim().trim_start_matches('/');
    if p.is_empty() || p == "*" {
        return true;
    }
    let clean_path = path.trim_start_matches('/');
    if p.ends_with('/') {
        clean_path.starts_with(p)
    } else {
        clean_path == p || clean_path.starts_with(&format!("{}/", p))
    }
}

fn authorize_rpc_request(
    engine: &ScionEngine,
    policy: &ResolvedCallerPolicy,
    requested_repo: &str,
    req: &mut inarch_store::RpcRequest,
) -> Result<(), String> {
    use inarch_store::RpcRequest;

    match req {
        RpcRequest::WhoAmI => Ok(()),
        RpcRequest::GetLease { lease_id }
        | RpcRequest::RenewLease { lease_id, .. }
        | RpcRequest::RevokeLease { lease_id, .. } => {
            if let Some(lease) = &policy.active_lease {
                if lease.lease_id != *lease_id {
                    return Err(format!(
                        "JIT swarm lease '{}' may only inspect, renew, or check in its own lease_id",
                        lease.lease_id
                    ));
                }
            } else if policy.rpc_ctx.caller_role != "admin" {
                let target_lease = engine
                    .meta()
                    .get_lease(lease_id)
                    .map_err(|e| format!("failed to look up lease '{}': {}", lease_id, e))?
                    .ok_or_else(|| format!("unknown JIT lease '{}'", lease_id))?;
                if target_lease.principal_email != policy.rpc_ctx.caller_principal_id {
                    return Err(format!(
                        "only the issuing principal or an admin may renew or revoke this lease (principal '{}' may only inspect, renew, or revoke leases it issued; lease '{}' belongs to '{}')",
                        policy.rpc_ctx.caller_principal_id, lease_id, target_lease.principal_email
                    ));
                }
            }
            Ok(())
        }
        RpcRequest::CheckoutLease {
            repo_id,
            allowed_ops,
            allowed_read_prefixes,
            allowed_write_prefixes,
            ..
        } => {
            if !allowed_read_prefixes.is_empty() {
                return Err("read prefixes are not enforced".to_string());
            }
            if policy.active_lease.is_some() {
                return Err(
                    "JIT swarm lease cannot mint sub-leases; only workstation or admin principals may check out a JIT lease"
                        .to_string(),
                );
            }
            if requested_repo != "default"
                && !repo_id.trim().is_empty()
                && repo_id != requested_repo
            {
                return Err(format!(
                    "repo_id '{}' in RPC payload does not match X-Inarch-Repo header '{}'",
                    repo_id, requested_repo
                ));
            }
            if engine.repo_id() != "default" && repo_id != engine.repo_id() {
                return Err(format!(
                    "server is scoped to repository '{}' (requested '{}')",
                    engine.repo_id(),
                    repo_id
                ));
            }
            if !repo_is_allowed(&policy.allowed_repos, repo_id) {
                return Err(format!(
                    "principal '{}' is not authorized to check out a JIT lease for repo '{}'",
                    policy.rpc_ctx.caller_principal_id, repo_id
                ));
            }
            if policy.rpc_ctx.caller_role != "admin" {
                if allowed_ops.is_empty()
                    || allowed_ops
                        .iter()
                        .any(|op| !op_is_allowed(&policy.allowed_ops, op))
                {
                    return Err("lease op exceeds issuing principal".to_string());
                }
                let caller_unrestricted = policy.allowed_write_prefixes.is_empty()
                    || policy
                        .allowed_write_prefixes
                        .iter()
                        .any(|p| p.trim().is_empty() || p.trim() == "*");
                if !caller_unrestricted {
                    if allowed_write_prefixes.is_empty() {
                        *allowed_write_prefixes = policy.allowed_write_prefixes.clone();
                    } else if allowed_write_prefixes.iter().any(|req_p| {
                        let t = req_p.trim();
                        t.is_empty()
                            || t == "*"
                            || !policy
                                .allowed_write_prefixes
                                .iter()
                                .any(|caller_p| path_matches_prefix(t, caller_p))
                    }) {
                        return Err("lease write prefix exceeds issuing principal".to_string());
                    }
                }
            }
            Ok(())
        }
        RpcRequest::PutLease { .. } => {
            if policy.rpc_ctx.caller_role != "admin" {
                return Err("only admin principals may call PutLease directly".to_string());
            }
            Ok(())
        }
        RpcRequest::ListLeases { .. } => {
            if policy.rpc_ctx.caller_role != "admin" {
                return Err(format!(
                    "principal '{}' (role '{}') is not authorized to list all server leases; admin role required",
                    policy.rpc_ctx.caller_principal_id, policy.rpc_ctx.caller_role
                ));
            }
            Ok(())
        }
        RpcRequest::EnrollPrincipal { .. } | RpcRequest::RevokePrincipal { .. } => {
            if policy.rpc_ctx.caller_role != "admin" {
                return Err(format!(
                    "principal '{}' (role '{}') is not authorized to enroll or revoke principals",
                    policy.rpc_ctx.caller_principal_id, policy.rpc_ctx.caller_role
                ));
            }
            Ok(())
        }
        RpcRequest::GetPrincipal { principal_id } => {
            if policy.active_lease.is_some() {
                return Err("JIT swarm lease cannot inspect workstation principals".to_string());
            }
            if policy.rpc_ctx.caller_role != "admin"
                && policy.rpc_ctx.caller_principal_id != *principal_id
            {
                return Err(format!(
                    "principal '{}' may only inspect its own principal record (requested '{}')",
                    policy.rpc_ctx.caller_principal_id, principal_id
                ));
            }
            Ok(())
        }
        RpcRequest::ListPrincipals => {
            if policy.rpc_ctx.caller_role != "admin" {
                return Err(format!(
                    "principal '{}' (role '{}') is not authorized to list all principals; admin role required",
                    policy.rpc_ctx.caller_principal_id, policy.rpc_ctx.caller_role
                ));
            }
            Ok(())
        }
        // Read operations
        RpcRequest::GetObjectsBatch { .. }
        | RpcRequest::HasObject { .. }
        | RpcRequest::GetChangeset { .. }
        | RpcRequest::GetDerivedMapping { .. } => {
            if engine.repo_id() != "default" && requested_repo != engine.repo_id() {
                return Err(format!(
                    "server is scoped to repository '{}' (requested '{}')",
                    engine.repo_id(),
                    requested_repo
                ));
            }
            if !repo_is_allowed(&policy.allowed_repos, requested_repo) {
                return Err(format!(
                    "caller '{}' is not authorized for repository '{}' (allowed: {:?})",
                    policy.rpc_ctx.caller_principal_id, requested_repo, policy.allowed_repos
                ));
            }
            if !op_is_allowed(&policy.allowed_ops, "read") {
                return Err(format!(
                    "caller '{}' does not have 'read' permission (allowed_ops: {:?})",
                    policy.rpc_ctx.caller_principal_id, policy.allowed_ops
                ));
            }
            Ok(())
        }
        RpcRequest::HasObjectsBatch { .. } => {
            if engine.repo_id() != "default" && requested_repo != engine.repo_id() {
                return Err(format!(
                    "server is scoped to repository '{}' (requested '{}')",
                    engine.repo_id(),
                    requested_repo
                ));
            }
            if !repo_is_allowed(&policy.allowed_repos, requested_repo) {
                return Err(format!(
                    "caller '{}' is not authorized for repository '{}' (allowed: {:?})",
                    policy.rpc_ctx.caller_principal_id, requested_repo, policy.allowed_repos
                ));
            }
            if !op_is_allowed(&policy.allowed_ops, "read")
                && !op_is_allowed(&policy.allowed_ops, "land")
            {
                return Err(format!(
                    "caller '{}' does not have 'read' or 'land' permission (allowed_ops: {:?})",
                    policy.rpc_ctx.caller_principal_id, policy.allowed_ops
                ));
            }
            Ok(())
        }
        RpcRequest::GetRef { repo_id, .. } | RpcRequest::ListRefs { repo_id } => {
            if !repo_id.trim().is_empty() && repo_id != requested_repo {
                return Err(format!(
                    "repo_id '{}' in RPC payload does not match X-Inarch-Repo header '{}'",
                    repo_id, requested_repo
                ));
            }
            let target_repo = if repo_id.trim().is_empty() {
                requested_repo
            } else {
                repo_id.as_str()
            };
            if engine.repo_id() != "default" && target_repo != engine.repo_id() {
                return Err(format!(
                    "server is scoped to repository '{}' (requested '{}')",
                    engine.repo_id(),
                    target_repo
                ));
            }
            if !repo_is_allowed(&policy.allowed_repos, target_repo) {
                return Err(format!(
                    "caller '{}' is not authorized for repository '{}' (allowed: {:?})",
                    policy.rpc_ctx.caller_principal_id, target_repo, policy.allowed_repos
                ));
            }
            if !op_is_allowed(&policy.allowed_ops, "read") {
                return Err(format!(
                    "caller '{}' does not have 'read' permission (allowed_ops: {:?})",
                    policy.rpc_ctx.caller_principal_id, policy.allowed_ops
                ));
            }
            Ok(())
        }
        // Write / Land operations
        RpcRequest::PutObjectsBatch { .. } | RpcRequest::PutDerivedMapping { .. } => {
            if engine.repo_id() != "default" && requested_repo != engine.repo_id() {
                return Err(format!(
                    "server is scoped to repository '{}' (requested '{}')",
                    engine.repo_id(),
                    requested_repo
                ));
            }
            if !repo_is_allowed(&policy.allowed_repos, requested_repo) {
                return Err(format!(
                    "caller '{}' is not authorized for repository '{}' (allowed: {:?})",
                    policy.rpc_ctx.caller_principal_id, requested_repo, policy.allowed_repos
                ));
            }
            if !op_is_allowed(&policy.allowed_ops, "land") {
                return Err(format!(
                    "caller '{}' does not have 'land' permission (allowed_ops: {:?})",
                    policy.rpc_ctx.caller_principal_id, policy.allowed_ops
                ));
            }
            Ok(())
        }
        RpcRequest::CasRef { repo_id, .. } => {
            if !repo_id.trim().is_empty() && repo_id != requested_repo {
                return Err(format!(
                    "repo_id '{}' in RPC payload does not match X-Inarch-Repo header '{}'",
                    repo_id, requested_repo
                ));
            }
            let target_repo = if repo_id.trim().is_empty() {
                requested_repo
            } else {
                repo_id.as_str()
            };
            if engine.repo_id() != "default" && target_repo != engine.repo_id() {
                return Err(format!(
                    "server is scoped to repository '{}' (requested '{}')",
                    engine.repo_id(),
                    target_repo
                ));
            }
            if !repo_is_allowed(&policy.allowed_repos, target_repo) {
                return Err(format!(
                    "caller '{}' is not authorized for repository '{}' (allowed: {:?})",
                    policy.rpc_ctx.caller_principal_id, target_repo, policy.allowed_repos
                ));
            }
            if !op_is_allowed(&policy.allowed_ops, "land") {
                return Err(format!(
                    "caller '{}' does not have 'land' permission (allowed_ops: {:?})",
                    policy.rpc_ctx.caller_principal_id, policy.allowed_ops
                ));
            }
            Ok(())
        }
        RpcRequest::PutChangeset { changeset } => {
            if engine.repo_id() != "default" && requested_repo != engine.repo_id() {
                return Err(format!(
                    "server is scoped to repository '{}' (requested '{}')",
                    engine.repo_id(),
                    requested_repo
                ));
            }
            if !repo_is_allowed(&policy.allowed_repos, requested_repo) {
                return Err(format!(
                    "caller '{}' is not authorized for repository '{}' (allowed: {:?})",
                    policy.rpc_ctx.caller_principal_id, requested_repo, policy.allowed_repos
                ));
            }
            if !op_is_allowed(&policy.allowed_ops, "land") {
                return Err(format!(
                    "caller '{}' does not have 'land' permission (allowed_ops: {:?})",
                    policy.rpc_ctx.caller_principal_id, policy.allowed_ops
                ));
            }
            // Enforce JIT lease or principal write-prefix boundary across every touched file in the Bonsai changeset
            if let Some(lease) = &policy.active_lease {
                let has_wildcard = lease.allowed_write_prefixes.is_empty()
                    || lease
                        .allowed_write_prefixes
                        .iter()
                        .any(|p| p.trim().is_empty() || p.trim() == "*");
                if !has_wildcard {
                    for mpath in changeset.file_changes.keys() {
                        let path_str = mpath.as_str();
                        let allowed = lease
                            .allowed_write_prefixes
                            .iter()
                            .any(|prefix| path_matches_prefix(path_str, prefix));
                        if !allowed {
                            return Err(format!(
                                "JIT lease '{}' write prefix violation: path '{}' is outside allowed_write_prefixes {:?}",
                                lease.lease_id, path_str, lease.allowed_write_prefixes
                            ));
                        }
                    }
                }
            } else if policy.rpc_ctx.caller_role != "admin" {
                let has_wildcard = policy.allowed_write_prefixes.is_empty()
                    || policy
                        .allowed_write_prefixes
                        .iter()
                        .any(|p| p.trim().is_empty() || p.trim() == "*");
                if !has_wildcard {
                    for mpath in changeset.file_changes.keys() {
                        let path_str = mpath.as_str();
                        let allowed = policy
                            .allowed_write_prefixes
                            .iter()
                            .any(|prefix| path_matches_prefix(path_str, prefix));
                        if !allowed {
                            return Err(format!(
                                "principal '{}' write prefix violation: path '{}' is outside allowed_write_prefixes {:?}",
                                policy.rpc_ctx.caller_principal_id,
                                path_str,
                                policy.allowed_write_prefixes
                            ));
                        }
                    }
                }
            }
            if policy.rpc_ctx.caller_role != "admin" {
                for mpath in changeset.file_changes.keys() {
                    engine
                        .check_path_acl(&policy.rpc_ctx.caller_principal_id, mpath)
                        .map_err(|e| format!("path ACL violation: {}", e))?;
                }
            }
            Ok(())
        }
    }
}

fn is_ancestor_fast_or_headers(
    engine: &ScionEngine,
    ancestor: ChangesetId,
    descendant: ChangesetId,
) -> bool {
    if ancestor == descendant {
        return true;
    }
    if let Ok(ans) = engine.derived().is_ancestor(ancestor, descendant) {
        return ans;
    }
    let mut queue = std::collections::VecDeque::new();
    let mut seen = std::collections::BTreeSet::new();
    queue.push_back(descendant);
    seen.insert(descendant);
    while let Some(curr) = queue.pop_front() {
        if curr == ancestor {
            return true;
        }
        if let Ok(Some(parents)) = engine.meta().get_changeset_parents(&curr) {
            for p in parents {
                if p == ancestor {
                    return true;
                }
                if seen.insert(p) {
                    queue.push_back(p);
                }
            }
        }
    }
    false
}

fn validate_cas_ref_policy(
    engine: &ScionEngine,
    policy: &ResolvedCallerPolicy,
    target_repo: &str,
    ref_name: &str,
    expected: Option<ChangesetId>,
    new_target: ChangesetId,
) -> Result<(), String> {
    if let Some(lease) = &policy.active_lease {
        let ref_allowed = lease.allowed_refs.iter().any(|r| r == "*" || r == ref_name);
        if !ref_allowed {
            return Err(format!(
                "cas_ref refused: ref not allowed by lease (ref='{}', allowed_refs={:?})",
                ref_name, lease.allowed_refs
            ));
        }
    }

    let _target_cs = engine
        .meta()
        .get_changeset(&new_target)
        .map_err(|e| {
            format!(
                "failed to inspect new_target changeset {}: {}",
                new_target, e
            )
        })?
        .ok_or_else(|| format!("cas_ref refused: unknown target changeset {}", new_target))?;

    let scoped = inarch_store::scope_ref_key(target_repo, ref_name);
    let current_ref = engine
        .meta()
        .get_ref(&scoped)
        .map_err(|e| format!("failed to read ref '{}': {}", scoped, e))?;
    let base_opt = expected.or(current_ref);

    if let Some(base_id) = base_opt {
        if !is_ancestor_fast_or_headers(engine, base_id, new_target) {
            return Err(format!(
                "cas_ref refused: not a fast-forward from {:?} to {}",
                base_opt, new_target
            ));
        }
    }

    let mut visited_from_target = std::collections::BTreeSet::new();
    let mut new_changesets = Vec::new();
    let mut queue = std::collections::VecDeque::new();
    if Some(new_target) != base_opt {
        queue.push_back(new_target);
        visited_from_target.insert(new_target);
    }

    while let Some(curr) = queue.pop_front() {
        if Some(curr) == base_opt {
            continue;
        }
        let cs = engine
            .meta()
            .get_changeset(&curr)
            .map_err(|e| format!("failed to inspect changeset {}: {}", curr, e))?
            .ok_or_else(|| format!("cas_ref refused: unknown ancestor changeset {}", curr))?;
        for parent in &cs.parents {
            if Some(*parent) == base_opt || visited_from_target.contains(parent) {
                continue;
            }
            if let Some(base_id) = base_opt {
                if is_ancestor_fast_or_headers(engine, *parent, base_id) {
                    visited_from_target.insert(*parent);
                    continue;
                }
            }
            if visited_from_target.insert(*parent) {
                queue.push_back(*parent);
            }
        }
        new_changesets.push((curr, cs));
    }

    let caller_unrestricted = policy.rpc_ctx.caller_role == "admin"
        || policy.allowed_write_prefixes.is_empty()
        || policy
            .allowed_write_prefixes
            .iter()
            .any(|p| p.trim().is_empty() || p.trim() == "*");

    if !caller_unrestricted {
        for (cs_id, cs) in &new_changesets {
            for mpath in cs.file_changes.keys() {
                let path_str = mpath.as_str();
                let allowed = policy
                    .allowed_write_prefixes
                    .iter()
                    .any(|prefix| path_matches_prefix(path_str, prefix));
                if !allowed {
                    return Err(format!(
                        "cas_ref refused: changeset outside write prefixes (changeset {} touches '{}', allowed={:?})",
                        cs_id, path_str, policy.allowed_write_prefixes
                    ));
                }
            }
        }
    }

    if policy.rpc_ctx.caller_role != "admin" {
        for (_cs_id, cs) in &new_changesets {
            for mpath in cs.file_changes.keys() {
                engine
                    .check_path_acl(&policy.rpc_ctx.caller_principal_id, mpath)
                    .map_err(|e| format!("cas_ref refused: {}", e))?;
            }
        }
    }

    Ok(())
}

fn handle_http_connection(
    mut stream: std::net::TcpStream,
    engine: Arc<ScionEngine>,
    auth_cfg: ServerAuthConfig,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    use std::io::{Read, Write};

    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(60)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(60)));

    loop {
        if stop.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }

        // Read HTTP headers up to `\r\n\r\n`
        let mut header_buf = Vec::with_capacity(512);
        let mut byte = [0u8; 1];
        let mut clean_eof = false;
        while !header_buf.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(0) => {
                    clean_eof = true;
                    break;
                }
                Ok(_) => {
                    header_buf.push(byte[0]);
                    if header_buf.len() > 32 * 1024 {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
        if clean_eof {
            return;
        }

        let header_str = String::from_utf8_lossy(&header_buf);
        let mut lines = header_str.lines();
        let Some(request_line) = lines.next() else {
            return;
        };
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("");

        let mut content_length = 0usize;
        let mut connection_close = false;
        let mut auth_header: Option<String> = None;
        let mut requested_repo = String::from("default");

        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                let key_lower = k.trim().to_ascii_lowercase();
                let val_trimmed = v.trim();
                if key_lower == "content-length" {
                    content_length = val_trimmed.parse::<usize>().unwrap_or(usize::MAX);
                } else if key_lower == "connection" && val_trimmed.eq_ignore_ascii_case("close") {
                    connection_close = true;
                } else if key_lower == "authorization" {
                    auth_header = Some(val_trimmed.to_string());
                } else if key_lower == "x-inarch-repo" && !val_trimmed.is_empty() {
                    requested_repo = val_trimmed.to_string();
                }
            }
        }

        let conn_hdr = if connection_close {
            "close"
        } else {
            "keep-alive"
        };

        if method == "GET" && path == "/health" {
            let payload = b"{\"status\":\"ok\",\"service\":\"inarch-server\"}";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
                payload.len(),
                conn_hdr
            );
            if stream.write_all(resp.as_bytes()).is_err()
                || stream.write_all(payload).is_err()
                || stream.flush().is_err()
            {
                return;
            }
            if connection_close {
                return;
            }
            continue;
        }

        // Authenticate caller for all non-/health routes BEFORE inspecting or reading the body
        let caller_policy = match authenticate_request_caller(
            auth_header.as_deref(),
            engine.meta().as_ref(),
            &auth_cfg,
        ) {
            Ok(p) => p,
            Err(err_msg) => {
                let msg = format!("{{\"error\":\"unauthorized\",\"detail\":{:?}}}", err_msg);
                let msg_bytes = msg.as_bytes();
                let resp = format!(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    msg_bytes.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(msg_bytes);
                let _ = stream.flush();
                close_http_stream_gracefully(stream);
                return;
            }
        };

        if content_length > MAX_HTTP_BODY_BYTES {
            let msg = b"{\"error\":\"payload_too_large\"}";
            let resp = format!(
                "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                msg.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.write_all(msg);
            let _ = stream.flush();
            close_http_stream_gracefully(stream);
            return;
        }

        let mut body = vec![0u8; content_length];
        if content_length > 0 && stream.read_exact(&mut body).is_err() {
            return;
        }

        match (method, path) {
            ("GET", "/v1/refs") => {
                if (engine.repo_id() != "default" && requested_repo != engine.repo_id())
                    || !repo_is_allowed(&caller_policy.allowed_repos, &requested_repo)
                    || !op_is_allowed(&caller_policy.allowed_ops, "read")
                {
                    let msg = b"{\"error\":\"forbidden\"}";
                    let resp = format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        msg.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.write_all(msg);
                    let _ = stream.flush();
                    close_http_stream_gracefully(stream);
                    return;
                }
                let refs = inarch_store::filter_scoped_refs(
                    &requested_repo,
                    engine.meta().list_refs().unwrap_or_default(),
                );
                let mut json = String::from("{");
                for (idx, (k, v)) in refs.iter().enumerate() {
                    if idx > 0 {
                        json.push(',');
                    }
                    json.push_str(&format!("\"{}\":\"{}\"", k, v.to_hex()));
                }
                json.push('}');
                let payload = json.as_bytes();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
                    payload.len(),
                    conn_hdr
                );
                if stream.write_all(resp.as_bytes()).is_err()
                    || stream.write_all(payload).is_err()
                    || stream.flush().is_err()
                {
                    return;
                }
            }
            ("POST", "/v1/rpc") => {
                let rpc_resp = match inarch_store::RpcRequest::decode(&body) {
                    Ok(mut req) => {
                        match authorize_rpc_request(
                            &engine,
                            &caller_policy,
                            &requested_repo,
                            &mut req,
                        ) {
                            Ok(()) => match req {
                                inarch_store::RpcRequest::PutDerivedMapping {
                                    cs_id,
                                    kind,
                                    derived_hash,
                                } => match kind {
                                    inarch_store::DerivedDataKind::Fsnode => {
                                        match engine.derived().derive_fsnode(cs_id) {
                                            Ok(actual) if actual.0 == derived_hash => {
                                                match engine.meta().put_derived_mapping(
                                                    cs_id,
                                                    kind,
                                                    derived_hash,
                                                ) {
                                                    Ok(()) => {
                                                        inarch_store::RpcResponse::PutDerivedMappingOk
                                                    }
                                                    Err(e) => inarch_store::RpcResponse::Error {
                                                        message: e.to_string(),
                                                    },
                                                }
                                            }
                                            Ok(_) => inarch_store::RpcResponse::Error {
                                                message: "derived mapping mismatch".to_string(),
                                            },
                                            Err(e) => inarch_store::RpcResponse::Error {
                                                message: format!("derived mapping mismatch: {}", e),
                                            },
                                        }
                                    }
                                    inarch_store::DerivedDataKind::Unode => {
                                        match engine.derived().derive_unode(cs_id) {
                                            Ok(actual) if actual.0 == derived_hash => {
                                                match engine.meta().put_derived_mapping(
                                                    cs_id,
                                                    kind,
                                                    derived_hash,
                                                ) {
                                                    Ok(()) => {
                                                        inarch_store::RpcResponse::PutDerivedMappingOk
                                                    }
                                                    Err(e) => inarch_store::RpcResponse::Error {
                                                        message: e.to_string(),
                                                    },
                                                }
                                            }
                                            Ok(_) => inarch_store::RpcResponse::Error {
                                                message: "derived mapping mismatch".to_string(),
                                            },
                                            Err(e) => inarch_store::RpcResponse::Error {
                                                message: format!("derived mapping mismatch: {}", e),
                                            },
                                        }
                                    }
                                    inarch_store::DerivedDataKind::PathSearchIndex => {
                                        match engine.derived().derive_path_search_index(cs_id) {
                                            Ok(actual) if actual.0 == derived_hash => {
                                                match engine.meta().put_derived_mapping(
                                                    cs_id,
                                                    kind,
                                                    derived_hash,
                                                ) {
                                                    Ok(()) => {
                                                        inarch_store::RpcResponse::PutDerivedMappingOk
                                                    }
                                                    Err(e) => inarch_store::RpcResponse::Error {
                                                        message: e.to_string(),
                                                    },
                                                }
                                            }
                                            Ok(_) => inarch_store::RpcResponse::Error {
                                                message: "derived mapping mismatch".to_string(),
                                            },
                                            Err(e) => inarch_store::RpcResponse::Error {
                                                message: format!("derived mapping mismatch: {}", e),
                                            },
                                        }
                                    }
                                    inarch_store::DerivedDataKind::BlameV2
                                    | inarch_store::DerivedDataKind::CommitGraph
                                    | inarch_store::DerivedDataKind::CopyDetection => {
                                        inarch_store::RpcResponse::Error {
                                            message:
                                                "derived mapping kind not accepted from clients"
                                                    .to_string(),
                                        }
                                    }
                                },
                                inarch_store::RpcRequest::CasRef {
                                    ref repo_id,
                                    ref ref_name,
                                    expected,
                                    new_target,
                                } => {
                                    let target_repo = if repo_id.trim().is_empty() {
                                        requested_repo.as_str()
                                    } else {
                                        repo_id.as_str()
                                    };
                                    match validate_cas_ref_policy(
                                        &engine,
                                        &caller_policy,
                                        target_repo,
                                        ref_name,
                                        expected,
                                        new_target,
                                    ) {
                                        Ok(()) => inarch_store::handle_rpc_request_with_context(
                                            engine.blobs().as_ref(),
                                            engine.meta().as_ref(),
                                            req,
                                            &caller_policy.rpc_ctx.caller_principal_id,
                                            &caller_policy.rpc_ctx.caller_role,
                                            &caller_policy.rpc_ctx.auth_method,
                                            caller_policy.active_lease.as_ref(),
                                            caller_policy.rpc_ctx.jit_signing_key.as_ref(),
                                        ),
                                        Err(policy_err) => inarch_store::RpcResponse::Error {
                                            message: policy_err,
                                        },
                                    }
                                }
                                other_req => inarch_store::handle_rpc_request_with_context(
                                    engine.blobs().as_ref(),
                                    engine.meta().as_ref(),
                                    other_req,
                                    &caller_policy.rpc_ctx.caller_principal_id,
                                    &caller_policy.rpc_ctx.caller_role,
                                    &caller_policy.rpc_ctx.auth_method,
                                    caller_policy.active_lease.as_ref(),
                                    caller_policy.rpc_ctx.jit_signing_key.as_ref(),
                                ),
                            },
                            Err(authz_err) => inarch_store::RpcResponse::Error {
                                message: format!("access denied: {}", authz_err),
                            },
                        }
                    }
                    Err(e) => inarch_store::RpcResponse::Error {
                        message: e.to_string(),
                    },
                };
                let payload = rpc_resp.encode();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
                    payload.len(),
                    conn_hdr
                );
                if stream.write_all(resp.as_bytes()).is_err()
                    || stream.write_all(&payload).is_err()
                    || stream.flush().is_err()
                {
                    return;
                }
            }
            _ => {
                let payload = b"{\"error\":\"not_found\"}";
                let resp = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
                    payload.len(),
                    conn_hdr
                );
                if stream.write_all(resp.as_bytes()).is_err()
                    || stream.write_all(payload).is_err()
                    || stream.flush().is_err()
                {
                    return;
                }
            }
        }

        if connection_close {
            return;
        }
    }
}

fn close_http_stream_gracefully(mut stream: std::net::TcpStream) {
    use std::io::Read;
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(200)));
    let mut buf = [0u8; 4096];
    let mut drained = 0usize;
    while drained < 65536 {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}
