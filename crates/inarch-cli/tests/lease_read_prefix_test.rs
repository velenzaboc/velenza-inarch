//! Read-prefix refusal tests (`inarch-cli`).
//!
//! Read prefixes cannot be enforced by the server: object reads are content addressed and carry no
//! path. A lease that advertises `allowed_read_prefixes` would therefore claim a restriction that
//! nothing enforces. The contract is to refuse such requests loudly and to stop documenting the
//! flag:
//!
//! 1. `CheckoutLease` with a non-empty `allowed_read_prefixes` is refused by the server.
//! 2. `inr lease checkout --read-prefix x` / `--read-prefixes x` exits non-zero during argument
//!    parsing, before any network access.
//! 3. `inr checkout ... --read-prefix x` does the same.
//! 4. README.md, docs/ and scripts/ no longer mention the flag.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use inarch_cli::{ServerAuthConfig, spawn_http_server_with_config};
use inarch_engine::ScionEngine;
use inarch_store::{
    MemBlobStore, MemMetadataStore, RemoteRpcClient, RpcRequest, RpcResponse,
    derive_jit_signing_key,
};

const ADMIN_TOKEN: &str = "read-prefix-test-admin-token";
const REFUSAL: &str = "read prefixes are not enforced";
const BINARY_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------------------------
// Server-side refusal
// ---------------------------------------------------------------------------------------------

fn spawn_keyed_server() -> inarch_cli::HttpServerHandle {
    let engine = Arc::new(ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    ));
    let mut auth_cfg = ServerAuthConfig::new(Some(ADMIN_TOKEN.to_string()));
    auth_cfg.jit_signing_key = Some(derive_jit_signing_key("read-prefix-test-signing-material"));
    spawn_http_server_with_config(engine, "127.0.0.1:0", auth_cfg).expect("spawn keyed server")
}

fn checkout_request(read_prefixes: &[&str]) -> RpcRequest {
    RpcRequest::CheckoutLease {
        swarm_id: "s1".to_string(),
        task_id: "t1".to_string(),
        repo_id: "r1".to_string(),
        allowed_ops: vec!["read".to_string(), "land".to_string()],
        allowed_read_prefixes: read_prefixes.iter().map(|s| s.to_string()).collect(),
        allowed_write_prefixes: vec!["crates".to_string()],
        ttl_secs: 600,
        allowed_refs: vec!["main".to_string()],
    }
}

fn lease_count(client: &RemoteRpcClient) -> usize {
    match client
        .call(&RpcRequest::ListLeases {
            repo_id: Some("r1".to_string()),
        })
        .expect("ListLeases transport")
    {
        RpcResponse::ListLeases { leases } => leases.len(),
        other => panic!("unexpected ListLeases response: {other:?}"),
    }
}

#[test]
fn checkout_lease_with_read_prefixes_is_refused_and_stores_nothing() {
    let server = spawn_keyed_server();
    let client = RemoteRpcClient::new(&server.base_url(), Some(ADMIN_TOKEN.to_string()))
        .expect("build admin rpc client");

    let response = client
        .call(&checkout_request(&["crates"]))
        .expect("CheckoutLease transport");
    match response {
        RpcResponse::Error { message } => assert!(
            message.contains(REFUSAL),
            "refusal must say read prefixes are not enforced, got: {message}"
        ),
        other => panic!("CheckoutLease with read prefixes must be refused, got: {other:?}"),
    }
    assert_eq!(
        lease_count(&client),
        0,
        "a refused CheckoutLease must not store a lease"
    );
}

#[test]
fn checkout_lease_without_read_prefixes_still_succeeds() {
    let server = spawn_keyed_server();
    let client = RemoteRpcClient::new(&server.base_url(), Some(ADMIN_TOKEN.to_string()))
        .expect("build admin rpc client");

    let response = client
        .call(&checkout_request(&[]))
        .expect("CheckoutLease transport");
    match response {
        RpcResponse::CheckoutLease { lease, token } => {
            assert!(
                lease.allowed_read_prefixes.is_empty(),
                "minted lease must carry no read prefixes: {lease:?}"
            );
            assert_eq!(lease.allowed_refs, vec!["main".to_string()]);
            assert_eq!(lease.allowed_write_prefixes, vec!["crates".to_string()]);
            assert!(
                token.starts_with("inarch_jit_v1_"),
                "unexpected lease token shape"
            );
        }
        other => panic!("CheckoutLease without read prefixes must succeed, got: {other:?}"),
    }
    assert_eq!(lease_count(&client), 1, "the control lease must be stored");
}

// ---------------------------------------------------------------------------------------------
// CLI refusal (binary)
// ---------------------------------------------------------------------------------------------

struct TempWorkspace {
    dir: PathBuf,
    config: PathBuf,
}

impl TempWorkspace {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "inarch-read-prefix-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp workspace");
        // Port 9 (discard) on loopback: nothing real is contacted, and a request that reaches the
        // network fails with a connection error instead of the frozen refusal text.
        let config = dir.join("inarch-test.toml");
        fs::write(
            &config,
            "[network]\nremote_url = \"http://127.0.0.1:9\"\nauth_token = \"cli-test-token\"\n",
        )
        .expect("write test config");
        Self { dir, config }
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

struct CliOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run_inr(ws: &TempWorkspace, args: &[&str]) -> CliOutput {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_inr"));
    cmd.arg("--config").arg(&ws.config);
    cmd.args(args);
    cmd.current_dir(&ws.dir);
    for (key, _) in std::env::vars() {
        if key.starts_with("INARCH_") {
            cmd.env_remove(key);
        }
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn inr");
    let started = Instant::now();
    loop {
        match child.try_wait().expect("poll inr") {
            Some(_) => break,
            None => {
                if started.elapsed() > BINARY_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("inr {args:?} did not exit within {BINARY_TIMEOUT:?}");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
    let output = child.wait_with_output().expect("collect inr output");
    CliOutput {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn assert_refused(out: &CliOutput, what: &str) {
    assert!(
        !out.success,
        "{what} must exit non-zero; stdout: {}",
        out.stdout
    );
    assert!(
        out.stderr.contains(REFUSAL),
        "{what} must report that read prefixes are not enforced; stderr: {}",
        out.stderr
    );
}

#[test]
fn lease_checkout_rejects_read_prefix_flag() {
    let ws = TempWorkspace::new("lease-singular");
    let out = run_inr(
        &ws,
        &[
            "lease",
            "checkout",
            "--repo",
            "r1",
            "--swarm",
            "s1",
            "--task",
            "t1",
            "--read-prefix",
            "crates",
        ],
    );
    assert_refused(&out, "`inr lease checkout --read-prefix`");
    assert!(
        !ws.dir.join(".inarch").join("jit_lease.json").exists(),
        "a refused lease checkout must not write a lease file"
    );
}

#[test]
fn lease_checkout_rejects_read_prefixes_flag() {
    let ws = TempWorkspace::new("lease-plural");
    let out = run_inr(
        &ws,
        &[
            "lease",
            "checkout",
            "--repo",
            "r1",
            "--swarm",
            "s1",
            "--task",
            "t1",
            "--read-prefixes",
            "crates,docs",
        ],
    );
    assert_refused(&out, "`inr lease checkout --read-prefixes`");
    assert!(
        !ws.dir.join(".inarch").join("jit_lease.json").exists(),
        "a refused lease checkout must not write a lease file"
    );
}

#[test]
fn checkout_rejects_read_prefix_flag() {
    let ws = TempWorkspace::new("checkout-singular");
    let dest = ws.dir.join("dest");
    let dest_arg = dest.to_string_lossy().to_string();
    let out = run_inr(
        &ws,
        &[
            "checkout",
            "main",
            dest_arg.as_str(),
            "--jit-ttl",
            "600",
            "--read-prefix",
            "crates",
        ],
    );
    assert_refused(&out, "`inr checkout --read-prefix`");
    assert!(
        !dest.exists(),
        "a refused checkout must not materialize the destination directory"
    );
}

#[test]
fn checkout_rejects_read_prefixes_flag() {
    let ws = TempWorkspace::new("checkout-plural");
    let dest = ws.dir.join("dest");
    let dest_arg = dest.to_string_lossy().to_string();
    let out = run_inr(
        &ws,
        &[
            "checkout",
            "main",
            dest_arg.as_str(),
            "--read-prefixes",
            "crates",
        ],
    );
    assert_refused(&out, "`inr checkout --read-prefixes`");
    assert!(
        !dest.exists(),
        "a refused checkout must not materialize the destination directory"
    );
}

// ---------------------------------------------------------------------------------------------
// Documentation and scripts no longer advertise the flag
// ---------------------------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string());
    Path::new(&manifest_dir).join("..").join("..")
}

fn collect_files(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_file() {
        out.push(path.to_path_buf());
        return;
    }
    if path.is_dir() {
        let mut entries: Vec<PathBuf> = fs::read_dir(path)
            .unwrap_or_else(|e| panic!("read dir {}: {e}", path.display()))
            .map(|entry| entry.expect("dir entry").path())
            .collect();
        entries.sort();
        for entry in entries {
            collect_files(&entry, out);
        }
    }
}

fn assert_no_read_prefix_flag(root_relative: &str, must_have_files: bool) {
    let mut files = Vec::new();
    collect_files(&repo_root().join(root_relative), &mut files);
    if must_have_files {
        assert!(
            !files.is_empty(),
            "expected files under {root_relative} (is the path wrong?)"
        );
    }
    for file in files {
        let bytes = fs::read(&file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        let text = String::from_utf8_lossy(&bytes);
        for (idx, line) in text.lines().enumerate() {
            assert!(
                !line.contains("--read-prefix"),
                "{}:{} still documents the unenforced read-prefix flag: {line}",
                file.display(),
                idx + 1
            );
        }
    }
}

#[test]
fn readme_does_not_document_read_prefix_flag() {
    assert_no_read_prefix_flag("README.md", true);
}

#[test]
fn docs_do_not_document_read_prefix_flag() {
    assert_no_read_prefix_flag("docs", true);
}

#[test]
fn scripts_do_not_use_read_prefix_flag() {
    assert_no_read_prefix_flag("scripts", true);
}
