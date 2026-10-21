//! Documentation claims must match what the code accepts and does.
//!
//! README.md and every `docs/*.md` file may only advertise backend names that
//! `InarchConfig::open_engine` / `open_server_stores` accept, and must not
//! describe a server-side rebase: landing runs client-side over the RPC
//! metadata store and the server only performs `cas_ref`.

use std::fs;
use std::path::{Path, PathBuf};

const ACCEPTED_BLOB_BACKENDS: &[&str] = &["local", "fs", "gcs", "remote"];
const ACCEPTED_META_BACKENDS: &[&str] = &["local", "fs", "spanner", "remote"];

fn repo_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string());
    Path::new(&manifest_dir).join("..").join("..")
}

/// (display name, contents) for README.md and every `*.md` under docs/.
fn doc_files() -> Vec<(String, String)> {
    let root = repo_root();
    let mut out = Vec::new();

    let readme = root.join("README.md");
    let text = fs::read_to_string(&readme).expect("README.md must be readable");
    out.push(("README.md".to_string(), text));

    let docs_dir = root.join("docs");
    let mut names: Vec<String> = fs::read_dir(&docs_dir)
        .expect("docs/ must be readable")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| name.to_ascii_lowercase().ends_with(".md"))
        .collect();
    names.sort();
    for name in names {
        let text = fs::read_to_string(docs_dir.join(&name))
            .unwrap_or_else(|e| panic!("docs/{name} must be readable: {e}"));
        out.push((format!("docs/{name}"), text));
    }
    out
}

/// Every quoted value assigned to `key` as `key = "value"` (whitespace around
/// `=` tolerated), with the 1-based line number it appears on.
fn quoted_values_for_key(text: &str, key: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let mut rest = line;
        while let Some(pos) = rest.find(key) {
            let after = &rest[pos + key.len()..];
            let trimmed = after.trim_start();
            if let Some(after_eq) = trimmed.strip_prefix('=') {
                let value_part = after_eq.trim_start();
                if let Some(quoted) = value_part.strip_prefix('"') {
                    if let Some(end) = quoted.find('"') {
                        found.push((idx + 1, quoted[..end].to_string()));
                    }
                }
            }
            rest = after;
        }
    }
    found
}

fn check_backend_values(key: &str, accepted: &[&str]) -> (usize, Vec<String>) {
    let mut total = 0usize;
    let mut offenders = Vec::new();
    for (name, text) in doc_files() {
        for (line, value) in quoted_values_for_key(&text, key) {
            total += 1;
            if !accepted.contains(&value.as_str()) {
                offenders.push(format!("{name}:{line}: {key} = \"{value}\""));
            }
        }
    }
    (total, offenders)
}

#[test]
fn docs_blob_backend_values_are_accepted_by_config() {
    let (total, offenders) = check_backend_values("blob_backend", ACCEPTED_BLOB_BACKENDS);
    assert!(
        total > 0,
        "expected at least one documented blob_backend value in README.md/docs"
    );
    assert!(
        offenders.is_empty(),
        "docs advertise blob_backend values the config rejects (accepted: {:?}): {:#?}",
        ACCEPTED_BLOB_BACKENDS,
        offenders
    );
}

#[test]
fn docs_meta_backend_values_are_accepted_by_config() {
    let (total, offenders) = check_backend_values("meta_backend", ACCEPTED_META_BACKENDS);
    assert!(
        total > 0,
        "expected at least one documented meta_backend value in README.md/docs"
    );
    assert!(
        offenders.is_empty(),
        "docs advertise meta_backend values the config rejects (accepted: {:?}): {:#?}",
        ACCEPTED_META_BACKENDS,
        offenders
    );
}

fn files_containing(needles: &[&str], case_insensitive: bool) -> Vec<String> {
    let mut hits = Vec::new();
    for (name, text) in doc_files() {
        let haystack = if case_insensitive {
            text.to_ascii_lowercase()
        } else {
            text.clone()
        };
        for needle in needles {
            let probe = if case_insensitive {
                needle.to_ascii_lowercase()
            } else {
                (*needle).to_string()
            };
            if haystack.contains(&probe) {
                hits.push(format!("{name}: mentions `{needle}`"));
            }
        }
    }
    hits
}

#[test]
fn docs_do_not_mention_unimplemented_aws_backends() {
    let hits = files_containing(&["S3BlobStore", "DynamoDb", "DynamoDB"], false);
    assert!(
        hits.is_empty(),
        "docs mention backends that do not exist: {:#?}",
        hits
    );
}

#[test]
fn docs_do_not_offer_s3_or_dynamodb_as_backend_values_or_pairings() {
    let hits = files_containing(
        &[
            "\"s3\"",
            "\"dynamodb\"",
            "dynamodb+s3",
            "dynamodb + s3",
            "s3+dynamodb",
            "s3 + dynamodb",
        ],
        true,
    );
    assert!(
        hits.is_empty(),
        "docs offer s3/dynamodb as a backend choice: {:#?}",
        hits
    );
}

#[test]
fn docs_do_not_claim_server_side_rebase() {
    let hits = files_containing(
        &[
            "server-side speculative rebase",
            "server's `cas_ref` loop",
            "cas_ref_for_repo",
        ],
        true,
    );
    assert!(
        hits.is_empty(),
        "docs describe a server-side rebase that does not exist (landing is client-side): {:#?}",
        hits
    );
}

#[test]
fn readme_describes_client_side_rebase() {
    let readme = fs::read_to_string(repo_root().join("README.md")).expect("README.md readable");
    assert!(
        readme.contains("client-side rebase"),
        "README.md must state that landing uses a client-side rebase"
    );
}

#[test]
fn readme_documented_cli_subcommands_are_present_in_inr_help() {
    let bin = env!("CARGO_BIN_EXE_inr");
    let output = std::process::Command::new(bin)
        .arg("--help")
        .output()
        .expect("inr --help must run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for cmd in [
        "inr init",
        "inr serve",
        "inr commit",
        "inr checkout",
        "inr mount",
        "inr hydrate",
        "inr status",
        "inr log",
        "inr diff",
        "inr cat",
        "inr ls",
        "inr blame",
        "inr search",
        "inr copies",
        "inr bisect",
        "inr revert",
        "inr principal",
        "inr lease",
        "inr git-import",
        "inr git-export",
        "inr bench",
        "inr mcp-stdio",
        "inr mcp-tools",
        "inr stack",
        "inr cambium|code",
        "inr canon|spec",
        "inr trellis|task",
    ] {
        assert!(
            stdout.contains(cmd),
            "inr --help missing documented command `{cmd}`:\n{stdout}"
        );
    }
}
