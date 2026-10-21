//! Bidirectional Git <-> Velenza Inarch migration and mirroring bridge (`inr git-import` / `inr git-export`).
//!
//! Enables existing Git repositories to migrate their commit history into Velenza Inarch's
//! tree-free [`inarch_types::bonsai::BonsaiChangeset`] DAG in $O(\Delta)$ per commit without
//! mutating the source working tree, and to export any Velenza Inarch revision back to a
//! standard Git repository branch with cryptographic `Inarch-Changeset-Id` provenance trailers.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use inarch_engine::{PatchFileEdit, PatchSubmission, ScionEngine};
use inarch_types::bonsai::FileType;
use inarch_types::hash::ChangesetId;
use inarch_types::path::MPath;

use crate::{CliError, checkout_stateless};

/// Options controlling lossless Git history import into Velenza Inarch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitImportOptions {
    /// Source Git revision or branch to import (default: `"HEAD"`).
    pub git_ref: String,
    /// Target Velenza Inarch ref to advance (default: `"main"`).
    pub target_ref: String,
    /// Optional cap on the most recent `N` commits from `git_ref` to import (`None` = full history).
    pub max_commits: Option<usize>,
    /// Basenames to ignore if encountered in the Git tree (e.g. `.git`, `.inarch`).
    pub ignore_names: Vec<String>,
}

impl Default for GitImportOptions {
    fn default() -> Self {
        Self {
            git_ref: "HEAD".to_string(),
            target_ref: "main".to_string(),
            max_commits: None,
            ignore_names: vec![".git".to_string(), ".inarch".to_string()],
        }
    }
}

/// Summary of a single Git commit converted into a tree-free [`inarch_types::bonsai::BonsaiChangeset`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitImportedCommit {
    pub git_commit_sha: String,
    pub changeset_id: ChangesetId,
    pub author: String,
    pub timestamp: i64,
    pub tz_offset_secs: i32,
    pub files_changed: usize,
}

/// Receipt returned by [`import_git_history`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitImportReceipt {
    pub target_ref: String,
    pub head_changeset: Option<ChangesetId>,
    pub commits_examined: usize,
    pub commits_imported: usize,
    pub commits_skipped_existing: usize,
    pub total_file_changes: usize,
    pub total_bytes_ingested: u64,
    pub imported_commits: Vec<GitImportedCommit>,
}

/// Receipt returned by [`export_git_revision`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitExportReceipt {
    pub changeset_id: ChangesetId,
    pub git_commit_sha: String,
    pub branch: String,
    pub files_exported: usize,
    pub bytes_exported: u64,
}

/// Imports a Git repository's first-parent commit history into Velenza Inarch as tree-free
/// `BonsaiChangeset`s while preserving original authors, timestamps, timezones, commit messages,
/// exact $O(\Delta)$ file deltas, and recording `"git_commit_sha"` in `BonsaiChangeset.extra`.
///
/// Running `import_git_history` repeatedly against a repository that has received new Git commits
/// is idempotent and incrementally imports only commits not yet present on `opts.target_ref`.
pub fn import_git_history(
    engine: &ScionEngine,
    git_repo_dir: &Path,
    opts: &GitImportOptions,
) -> Result<GitImportReceipt, CliError> {
    // 1. Verify `git_repo_dir` is a Git repository
    run_git_raw(git_repo_dir, &["rev-parse", "--git-dir"], &[])?;

    // 2. Discover already-imported Git commit SHAs on `opts.target_ref` for incremental idempotency
    let mut current_head = engine.resolve_ref(&opts.target_ref)?;
    let mut existing_git_shas = BTreeSet::new();
    let mut walk = current_head;
    while let Some(cs_id) = walk {
        let Some(cs) = engine
            .meta()
            .get_changeset(&cs_id)
            .map_err(inarch_engine::EngineError::Store)?
        else {
            break;
        };
        if let Some(sha_bytes) = cs.extra.get("git_commit_sha") {
            if let Ok(sha_str) = std::str::from_utf8(sha_bytes) {
                existing_git_shas.insert(sha_str.to_string());
            }
        }
        walk = cs.parents.first().copied();
    }

    // 3. List commits in topological (oldest -> newest) order along the first-parent chain
    let mut rev_list_args = vec!["rev-list", "--first-parent", "--reverse"];
    let max_str;
    if let Some(limit) = opts.max_commits {
        max_str = limit.to_string();
        rev_list_args.push("-n");
        rev_list_args.push(&max_str);
    }
    rev_list_args.push(&opts.git_ref);

    let rev_list_out = run_git_raw(git_repo_dir, &rev_list_args, &[])?;
    let rev_list_text = String::from_utf8_lossy(&rev_list_out);
    let commit_shas: Vec<String> = rev_list_text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    let mut commits_examined = 0usize;
    let mut commits_imported = 0usize;
    let mut commits_skipped_existing = 0usize;
    let mut total_file_changes = 0usize;
    let mut total_bytes_ingested = 0u64;
    let mut imported_commits = Vec::new();

    for sha in commit_shas {
        commits_examined += 1;
        if existing_git_shas.contains(&sha) {
            commits_skipped_existing += 1;
            continue;
        }

        let meta = read_git_commit_metadata(git_repo_dir, &sha)?;
        let parent_sha = if current_head.is_some() {
            read_git_first_parent(git_repo_dir, &sha)
        } else {
            None
        };

        let (edits, bytes_in_commit) = match parent_sha {
            Some(ref p_sha) => {
                collect_git_diff_edits(git_repo_dir, p_sha, &sha, &opts.ignore_names)?
            }
            None => collect_git_full_tree_edits(git_repo_dir, &sha, &opts.ignore_names)?,
        };

        let files_changed = edits.len();
        total_file_changes += files_changed;
        total_bytes_ingested += bytes_in_commit;

        let mut extra = BTreeMap::new();
        extra.insert("git_commit_sha".to_string(), sha.as_bytes().to_vec());

        let outcome = engine.land_patch(PatchSubmission {
            target_ref: opts.target_ref.clone(),
            base_changeset: current_head,
            author: meta.author.clone(),
            timestamp: meta.timestamp,
            tz_offset_secs: meta.tz_offset_secs,
            message: meta.message,
            extra,
            edits,
        })?;

        current_head = Some(outcome.changeset_id);
        existing_git_shas.insert(sha.clone());
        commits_imported += 1;
        imported_commits.push(GitImportedCommit {
            git_commit_sha: sha,
            changeset_id: outcome.changeset_id,
            author: meta.author,
            timestamp: meta.timestamp,
            tz_offset_secs: meta.tz_offset_secs,
            files_changed,
        });
    }

    Ok(GitImportReceipt {
        target_ref: opts.target_ref.clone(),
        head_changeset: current_head,
        commits_examined,
        commits_imported,
        commits_skipped_existing,
        total_file_changes,
        total_bytes_ingested,
        imported_commits,
    })
}

/// Exports a Velenza Inarch revision (`cs_id`) into a destination Git repository on `branch`,
/// recording `Inarch-Changeset-Id: <hex>` in the Git commit message for deterministic provenance.
pub fn export_git_revision(
    engine: &ScionEngine,
    cs_id: ChangesetId,
    dest_git_dir: &Path,
    branch: &str,
) -> Result<GitExportReceipt, CliError> {
    let cs = engine
        .meta()
        .get_changeset(&cs_id)
        .map_err(inarch_engine::EngineError::Store)?
        .ok_or(inarch_engine::EngineError::UnknownChangeset(cs_id))?;

    fs::create_dir_all(dest_git_dir)?;
    if !dest_git_dir.join(".git").exists() {
        run_git_raw(dest_git_dir, &["init", "-b", branch], &[])?;
    } else {
        run_git_raw(dest_git_dir, &["checkout", "-B", branch], &[])?;
    }

    // Clear existing working tree entries (preserving `.git` and `.inarch`) before stateless checkout
    for entry in fs::read_dir(dest_git_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name == ".git" || name == ".inarch" {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }

    let co = checkout_stateless(engine, cs_id, None, dest_git_dir)?;
    run_git_raw(dest_git_dir, &["add", "-A"], &[])?;

    let (author_name, author_email) = parse_author_name_and_email(&cs.author);
    let date_env = format_git_raw_date(cs.author_date_secs, cs.author_tz_offset_secs);
    let msg_with_trailer = format!(
        "{}\n\nInarch-Changeset-Id: {}\n",
        cs.message.trim_end(),
        cs_id.to_hex()
    );

    run_git_raw(
        dest_git_dir,
        &["commit", "--allow-empty", "-m", &msg_with_trailer],
        &[
            ("GIT_AUTHOR_NAME", &author_name),
            ("GIT_AUTHOR_EMAIL", &author_email),
            ("GIT_COMMITTER_NAME", &author_name),
            ("GIT_COMMITTER_EMAIL", &author_email),
            ("GIT_AUTHOR_DATE", &date_env),
            ("GIT_COMMITTER_DATE", &date_env),
        ],
    )?;

    let head_out = run_git_raw(dest_git_dir, &["rev-parse", "HEAD"], &[])?;
    let git_commit_sha = String::from_utf8_lossy(&head_out).trim().to_string();

    Ok(GitExportReceipt {
        changeset_id: cs_id,
        git_commit_sha,
        branch: branch.to_string(),
        files_exported: co.files_materialized as usize,
        bytes_exported: co.bytes_materialized,
    })
}

struct CommitMetadata {
    author: String,
    timestamp: i64,
    tz_offset_secs: i32,
    message: String,
}

fn read_git_commit_metadata(git_repo_dir: &Path, sha: &str) -> Result<CommitMetadata, CliError> {
    let out = run_git_raw(
        git_repo_dir,
        &[
            "show",
            "-s",
            "--format=%an%x00%ae%x00%at%x00%ad%x00%B",
            "--date=raw",
            sha,
        ],
        &[],
    )?;
    let parts: Vec<&[u8]> = out.splitn(5, |&b| b == 0).collect();
    if parts.len() < 5 {
        return Err(CliError::InvalidArgument(format!(
            "unexpected git show metadata format for commit {sha}"
        )));
    }
    let author_name = String::from_utf8_lossy(parts[0]).trim().to_string();
    let author_email = String::from_utf8_lossy(parts[1]).trim().to_string();
    let author = if author_email.is_empty() {
        author_name
    } else {
        format!("{author_name} <{author_email}>")
    };
    let timestamp = String::from_utf8_lossy(parts[2])
        .trim()
        .parse::<i64>()
        .unwrap_or(0);
    let raw_date = String::from_utf8_lossy(parts[3]).trim().to_string();
    let tz_offset_secs = parse_git_raw_tz_offset(&raw_date);
    let message = String::from_utf8_lossy(parts[4])
        .trim_end_matches(&['\r', '\n'][..])
        .to_string();

    Ok(CommitMetadata {
        author,
        timestamp,
        tz_offset_secs,
        message,
    })
}

fn read_git_first_parent(git_repo_dir: &Path, sha: &str) -> Option<String> {
    let spec = format!("{sha}^1");
    let out = run_git_raw(git_repo_dir, &["rev-parse", "--verify", "-q", &spec], &[]).ok()?;
    let parent = String::from_utf8_lossy(&out).trim().to_string();
    if parent.is_empty() {
        None
    } else {
        Some(parent)
    }
}

fn collect_git_full_tree_edits(
    git_repo_dir: &Path,
    sha: &str,
    ignore_names: &[String],
) -> Result<(Vec<PatchFileEdit>, u64), CliError> {
    let out = run_git_raw(git_repo_dir, &["ls-tree", "-r", "-z", sha], &[])?;
    let mut edits = Vec::new();
    let mut total_bytes = 0u64;

    for record in out.split(|&b| b == 0) {
        if record.is_empty() {
            continue;
        }
        // Format: `<mode> <type> <oid>\t<path>`
        let Some(tab_pos) = record.iter().position(|&b| b == b'\t') else {
            continue;
        };
        let header = String::from_utf8_lossy(&record[..tab_pos]);
        let path_str = String::from_utf8_lossy(&record[tab_pos + 1..]);
        if should_ignore_path(&path_str, ignore_names) {
            continue;
        }
        let mut hdr_parts = header.split_whitespace();
        let mode = hdr_parts.next().unwrap_or("");
        let obj_type = hdr_parts.next().unwrap_or("");
        let blob_oid = hdr_parts.next().unwrap_or("");
        if mode == "160000" || obj_type != "blob" || blob_oid.is_empty() {
            continue;
        }
        let mpath = MPath::new(&path_str)?;
        let content = run_git_raw(git_repo_dir, &["cat-file", "blob", blob_oid], &[])?;
        total_bytes += content.len() as u64;
        edits.push(PatchFileEdit::Upsert {
            path: mpath,
            content,
            file_type: git_mode_to_file_type(mode),
        });
    }

    Ok((edits, total_bytes))
}

fn collect_git_diff_edits(
    git_repo_dir: &Path,
    parent_sha: &str,
    sha: &str,
    ignore_names: &[String],
) -> Result<(Vec<PatchFileEdit>, u64), CliError> {
    let out = run_git_raw(
        git_repo_dir,
        &[
            "diff-tree",
            "-r",
            "--no-commit-id",
            "--raw",
            "-z",
            "--no-renames",
            parent_sha,
            sha,
        ],
        &[],
    )?;
    let tokens: Vec<&[u8]> = out.split(|&b| b == 0).filter(|t| !t.is_empty()).collect();
    let mut edits = Vec::new();
    let mut total_bytes = 0u64;
    let mut idx = 0;

    while idx + 1 < tokens.len() {
        let meta_str = String::from_utf8_lossy(tokens[idx]);
        let path_str = String::from_utf8_lossy(tokens[idx + 1]);
        idx += 2;

        if should_ignore_path(&path_str, ignore_names) {
            continue;
        }

        // Format: `:<old_mode> <new_mode> <old_oid> <new_oid> <status>`
        let parts: Vec<&str> = meta_str
            .trim_start_matches(':')
            .split_whitespace()
            .collect();
        if parts.len() < 5 {
            continue;
        }
        let old_mode = parts[0];
        let new_mode = parts[1];
        let new_oid = parts[3];
        let status = parts[4];

        if old_mode == "160000" || new_mode == "160000" {
            continue;
        }

        let mpath = MPath::new(&path_str)?;
        if status.starts_with('D') {
            edits.push(PatchFileEdit::Delete { path: mpath });
        } else {
            let content = run_git_raw(git_repo_dir, &["cat-file", "blob", new_oid], &[])?;
            total_bytes += content.len() as u64;
            edits.push(PatchFileEdit::Upsert {
                path: mpath,
                content,
                file_type: git_mode_to_file_type(new_mode),
            });
        }
    }

    Ok((edits, total_bytes))
}

fn should_ignore_path(path_str: &str, ignore_names: &[String]) -> bool {
    path_str
        .split('/')
        .any(|comp| ignore_names.iter().any(|ign| ign == comp))
}

fn git_mode_to_file_type(mode: &str) -> FileType {
    match mode {
        "100755" => FileType::Executable,
        "120000" => FileType::Symlink,
        _ => FileType::Regular,
    }
}

fn parse_git_raw_tz_offset(raw_date: &str) -> i32 {
    // `--date=raw` outputs `<unix_timestamp> <+HHMM|-HHMM>`
    let Some(tz_token) = raw_date.split_whitespace().nth(1) else {
        return 0;
    };
    if tz_token.len() != 5 {
        return 0;
    }
    let sign = match &tz_token[0..1] {
        "-" => -1,
        "+" => 1,
        _ => return 0,
    };
    let hours = tz_token[1..3].parse::<i32>().unwrap_or(0);
    let mins = tz_token[3..5].parse::<i32>().unwrap_or(0);
    sign * (hours * 3600 + mins * 60)
}

fn format_git_raw_date(timestamp: i64, tz_offset_secs: i32) -> String {
    let sign = if tz_offset_secs < 0 { '-' } else { '+' };
    let abs = tz_offset_secs.unsigned_abs();
    let hours = abs / 3600;
    let mins = (abs % 3600) / 60;
    format!("{timestamp} {sign}{hours:02}{mins:02}")
}

fn parse_author_name_and_email(author: &str) -> (String, String) {
    if let (Some(lt), Some(gt)) = (author.find('<'), author.rfind('>')) {
        if lt < gt {
            let name = author[..lt].trim().to_string();
            let email = author[lt + 1..gt].trim().to_string();
            return (
                if name.is_empty() {
                    "Velenza Inarch".to_string()
                } else {
                    name
                },
                if email.is_empty() {
                    "inarch@example.com".to_string()
                } else {
                    email
                },
            );
        }
    }
    let trimmed = author.trim();
    let name = if trimmed.is_empty() {
        "Velenza Inarch".to_string()
    } else {
        trimmed.to_string()
    };
    (name, "inarch@example.com".to_string())
}

fn run_git_raw(repo_dir: &Path, args: &[&str], envs: &[(&str, &str)]) -> Result<Vec<u8>, CliError> {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_dir).args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(CliError::InvalidArgument(format!(
            "git {:?} in '{}' failed: {}",
            args,
            repo_dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
}
