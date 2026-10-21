//! No-public-default JIT signing key tests (`inarch-cli`).
//!
//! JIT swarm lease tokens (`inarch_jit_v1_<lease_id>_<mac>`) are only trustworthy when the server
//! holds a private signing key. The server must therefore never fall back to a key derived from a
//! public constant (or from the admin token):
//!
//! - `inr serve` refuses to start without a real `jit_signing_key`;
//! - `ServerAuthConfig::from_inarch_config` rejects empty / placeholder / public-seed keys;
//! - a server constructed without a key answers lease RPCs with `JIT leases disabled` and rejects
//!   every `inarch_jit_v1_` bearer token with HTTP 401;
//! - a token MAC'd with the well-known public seed is never accepted by a server holding a
//!   different key.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use inarch_cli::{
    HttpServerHandle, InarchConfig, ServerAuthConfig, spawn_http_server,
    spawn_http_server_with_config,
};
use inarch_engine::ScionEngine;
use inarch_store::{
    JitLeaseRecord, MemBlobStore, MemMetadataStore, RemoteRpcClient, RpcRequest, RpcResponse,
    derive_jit_signing_key, mint_jit_lease_token,
};

/// The seed that used to be compiled into the server as a fallback key. It is public knowledge.
const PUBLIC_DEFAULT_SEED: &str = "velenza-inarch-default-jit-signing-seed";
const PLACEHOLDER_KEY: &str = "REPLACE_WITH_64_HEX_CHAR_RANDOM_KEY";
const ADMIN_TOKEN: &str = "r07-admin-bootstrap-token";
/// 64 lowercase hex characters: used verbatim as the raw 32-byte key.
const HEX_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const SERVE_EXIT_TIMEOUT: Duration = Duration::from_secs(20);

static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs() as i64
}

/// A unique scratch directory that is removed on drop (also when an assertion fails).
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let seq = DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "inarch-jit-key-{label}-{}-{nanos}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn in_memory_engine() -> Arc<ScionEngine> {
    Arc::new(ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    ))
}

/// Spawns a server that was built through `spawn_http_server`: admin token, no JIT key.
fn spawn_keyless_server() -> HttpServerHandle {
    spawn_http_server(
        in_memory_engine(),
        "127.0.0.1:0",
        Some(ADMIN_TOKEN.to_string()),
    )
    .expect("spawn keyless in-memory server")
}

/// Spawns a server with an explicit private JIT signing key derived from `key_material`.
fn spawn_keyed_server(key_material: &str) -> HttpServerHandle {
    let mut auth_cfg = ServerAuthConfig::new(Some(ADMIN_TOKEN.to_string()));
    auth_cfg.jit_signing_key = Some(derive_jit_signing_key(key_material));
    spawn_http_server_with_config(in_memory_engine(), "127.0.0.1:0", auth_cfg)
        .expect("spawn keyed in-memory server")
}

fn client(server: &HttpServerHandle, token: &str) -> RemoteRpcClient {
    RemoteRpcClient::new(&server.base_url(), Some(token.to_string())).expect("build rpc client")
}

fn checkout_request() -> RpcRequest {
    RpcRequest::CheckoutLease {
        repo_id: "default".to_string(),
        swarm_id: "swarm-r07".to_string(),
        task_id: "TASK-R07".to_string(),
        allowed_ops: vec!["read".to_string(), "land".to_string()],
        allowed_read_prefixes: Vec::new(),
        allowed_write_prefixes: vec!["crates/allowed".to_string()],
        allowed_refs: vec!["main".to_string()],
        ttl_secs: 600,
    }
}

fn stored_lease_record(lease_id: &str) -> JitLeaseRecord {
    let now = now_unix();
    JitLeaseRecord {
        lease_id: lease_id.to_string(),
        principal_email: "issuer@example.com".to_string(),
        swarm_id: "swarm-r07".to_string(),
        task_id: "TASK-R07".to_string(),
        repo_id: "default".to_string(),
        allowed_ops: vec!["read".to_string(), "land".to_string()],
        allowed_read_prefixes: Vec::new(),
        allowed_write_prefixes: vec!["crates/allowed".to_string()],
        issued_at_unix: now,
        expires_at_unix: now + 600,
        revoked: false,
        allowed_refs: vec!["main".to_string()],
    }
}

fn put_lease_as_admin(server: &HttpServerHandle, record: &JitLeaseRecord) {
    let response = client(server, ADMIN_TOKEN)
        .call(&RpcRequest::PutLease {
            record: record.clone(),
        })
        .expect("PutLease transport");
    assert_eq!(
        response,
        RpcResponse::PutLeaseOk,
        "admin must be able to store a lease record directly"
    );
}

// ---------------------------------------------------------------------------------------------
// 1. `inr serve` without a real key must exit non-zero, quickly, naming `jit_signing_key`.
// ---------------------------------------------------------------------------------------------

fn spawn_serve(dir: &TempDir, config_file: &std::path::Path) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_inr"));
    command
        .arg("--config")
        .arg(config_file)
        .arg("serve")
        .current_dir(&dir.path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Only the TOML file may influence the run: drop every ambient `INARCH_*` variable.
    for (key, _) in std::env::vars() {
        if key.starts_with("INARCH_") {
            command.env_remove(key);
        }
    }
    command.spawn().expect("spawn `inr serve`")
}

fn assert_serve_refuses_key(label: &str, key_line: &str) {
    let dir = TempDir::new(label);
    let config_file = dir.path.join("serve.toml");
    // Relative `store_dir` resolves against the child's cwd (the temp dir): no path quoting needed.
    let toml = format!(
        "[network]\n\
         listen_addr = \"127.0.0.1:0\"\n\
         {key_line}\n\
         \n\
         [storage]\n\
         store_dir = \"store\"\n\
         blob_backend = \"local\"\n\
         meta_backend = \"local\"\n"
    );
    std::fs::write(&config_file, toml).expect("write serve config");

    let mut child = spawn_serve(&dir, &config_file);
    let deadline = Instant::now() + SERVE_EXIT_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("poll `inr serve`") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "serve started without a jit_signing_key ({label}): still running after {SERVE_EXIT_TIMEOUT:?}"
                );
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };

    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr).expect("read serve stderr");
    }
    assert!(
        !status.success(),
        "serve must exit non-zero without a usable jit_signing_key ({label}); stderr: {stderr}"
    );
    assert!(
        stderr.contains("jit_signing_key"),
        "serve stderr must name `jit_signing_key` ({label}); stderr: {stderr}"
    );
}

#[test]
fn serve_refuses_to_start_with_empty_jit_signing_key() {
    assert_serve_refuses_key("serve-empty", "jit_signing_key = \"\"");
}

#[test]
fn serve_refuses_to_start_with_placeholder_jit_signing_key() {
    assert_serve_refuses_key(
        "serve-placeholder",
        &format!("jit_signing_key = \"{PLACEHOLDER_KEY}\""),
    );
}

// ---------------------------------------------------------------------------------------------
// 2. `ServerAuthConfig::from_inarch_config` key validation.
// ---------------------------------------------------------------------------------------------

fn config_with_key(key: &str) -> InarchConfig {
    InarchConfig {
        jit_signing_key: key.to_string(),
        ..Default::default()
    }
}

#[test]
fn from_inarch_config_rejects_unusable_signing_keys() {
    let unusable = [
        ("empty", ""),
        ("whitespace only", "   "),
        ("public default seed", PUBLIC_DEFAULT_SEED),
        ("placeholder", PLACEHOLDER_KEY),
    ];
    for (label, key) in unusable {
        match ServerAuthConfig::from_inarch_config(&config_with_key(key)) {
            Ok(_) => panic!("from_inarch_config accepted an unusable jit_signing_key ({label})"),
            Err(err) => {
                let text = err.to_string();
                assert!(
                    text.contains("jit_signing_key"),
                    "error for {label} key must name `jit_signing_key`, got: {text}"
                );
            }
        }
    }
}

#[test]
fn from_inarch_config_never_borrows_the_admin_token_as_signing_key() {
    let mut cfg = config_with_key("");
    cfg.auth_token = ADMIN_TOKEN.to_string();
    match ServerAuthConfig::from_inarch_config(&cfg) {
        Ok(_) => panic!("an admin token must not stand in for a missing jit_signing_key"),
        Err(err) => {
            let text = err.to_string();
            assert!(
                text.contains("jit_signing_key"),
                "error must name `jit_signing_key`, got: {text}"
            );
        }
    }
}

#[test]
fn from_inarch_config_derives_the_configured_key() {
    let mut cfg = config_with_key(HEX_KEY);
    cfg.auth_token = ADMIN_TOKEN.to_string();
    let auth = match ServerAuthConfig::from_inarch_config(&cfg) {
        Ok(auth) => auth,
        Err(err) => panic!("a 64-hex jit_signing_key must be accepted, got: {err}"),
    };
    assert_eq!(
        auth.jit_signing_key,
        Some(derive_jit_signing_key(HEX_KEY)),
        "the server key must be derived from the configured secret"
    );
    assert_eq!(auth.admin_token.as_deref(), Some(ADMIN_TOKEN));
    assert!(auth.require_auth, "a configured server must require auth");

    // Surrounding whitespace is trimmed before derivation.
    let padded = format!("  {HEX_KEY}  ");
    let trimmed_auth = match ServerAuthConfig::from_inarch_config(&config_with_key(&padded)) {
        Ok(auth) => auth,
        Err(err) => panic!("a padded 64-hex jit_signing_key must be accepted, got: {err}"),
    };
    assert_eq!(
        trimmed_auth.jit_signing_key,
        Some(derive_jit_signing_key(HEX_KEY)),
        "the configured secret must be trimmed before key derivation"
    );
}

// ---------------------------------------------------------------------------------------------
// 3. Keyless server: lease issuance is disabled.
// ---------------------------------------------------------------------------------------------

#[test]
fn keyless_server_refuses_checkout_lease() {
    let server = spawn_keyless_server();
    let admin = client(&server, ADMIN_TOKEN);

    let response = admin
        .call(&checkout_request())
        .expect("CheckoutLease transport");
    match response {
        RpcResponse::Error { message } => assert!(
            message.contains("JIT leases disabled"),
            "keyless CheckoutLease must report that leases are disabled, got: {message}"
        ),
        other => panic!("keyless server must not mint a lease, got: {other:?}"),
    }

    // Nothing may have been stored by the refused request.
    match admin
        .call(&RpcRequest::ListLeases { repo_id: None })
        .expect("ListLeases transport")
    {
        RpcResponse::ListLeases { leases } => assert!(
            leases.is_empty(),
            "a refused CheckoutLease must not persist a lease: {leases:?}"
        ),
        other => panic!("unexpected ListLeases response: {other:?}"),
    }
    server.shutdown();
}

#[test]
fn keyless_server_refuses_renew_lease() {
    let server = spawn_keyless_server();
    let record = stored_lease_record("lease_r07keylessrenew0000001");
    put_lease_as_admin(&server, &record);

    let response = client(&server, ADMIN_TOKEN)
        .call(&RpcRequest::RenewLease {
            lease_id: record.lease_id.clone(),
            ttl_secs: 600,
        })
        .expect("RenewLease transport");
    match response {
        RpcResponse::Error { message } => assert!(
            message.contains("JIT leases disabled"),
            "keyless RenewLease must report that leases are disabled, got: {message}"
        ),
        other => panic!("keyless server must not mint a renewed token, got: {other:?}"),
    }
    server.shutdown();
}

// ---------------------------------------------------------------------------------------------
// 4. Keyless server: a token MAC'd with the public default seed is rejected with 401.
// ---------------------------------------------------------------------------------------------

#[test]
fn keyless_server_rejects_public_seed_jit_token() {
    let server = spawn_keyless_server();
    let record = stored_lease_record("lease_r07keylessreject000001");
    put_lease_as_admin(&server, &record);

    let public_key = derive_jit_signing_key(PUBLIC_DEFAULT_SEED);
    let forged = mint_jit_lease_token(&record, &public_key);
    assert!(forged.starts_with("inarch_jit_v1_"));

    let err = client(&server, &forged)
        .call(&RpcRequest::WhoAmI)
        .expect_err("a keyless server must reject every JIT bearer token");
    let text = err.to_string();
    assert!(
        text.contains("401"),
        "rejection must be HTTP 401, got: {text}"
    );
    assert!(
        text.contains("JIT leases disabled"),
        "401 detail must say JIT leases are disabled, got: {text}"
    );
    server.shutdown();
}

// ---------------------------------------------------------------------------------------------
// 5. Keyed server: its own tokens work; tokens MAC'd with public or admin-derived keys do not.
// ---------------------------------------------------------------------------------------------

#[test]
fn keyed_server_accepts_own_token_and_rejects_public_seed_token() {
    let server = spawn_keyed_server("r07-private-test-signing-material");

    // Admin mints a real lease with the server's private key.
    let (lease, token) = match client(&server, ADMIN_TOKEN)
        .call(&checkout_request())
        .expect("CheckoutLease transport")
    {
        RpcResponse::CheckoutLease { lease, token } => (lease, token),
        other => panic!("keyed server must mint a lease for admin, got: {other:?}"),
    };
    assert!(token.starts_with("inarch_jit_v1_"));

    // The genuine token authenticates as the lease.
    match client(&server, &token)
        .call(&RpcRequest::WhoAmI)
        .expect("genuine lease token must authenticate")
    {
        RpcResponse::WhoAmI {
            role,
            auth_method,
            lease: Some(active),
            ..
        } => {
            assert_eq!(role, "jit_swarm");
            assert_eq!(auth_method, "jit_lease");
            assert_eq!(active.lease_id, lease.lease_id);
        }
        other => panic!("unexpected WhoAmI response for genuine lease token: {other:?}"),
    }

    // The same lease MAC'd with the public default key is forged and must be refused.
    let forged_public = mint_jit_lease_token(&lease, &derive_jit_signing_key(PUBLIC_DEFAULT_SEED));
    assert_ne!(
        forged_public, token,
        "forged token must differ from the real one"
    );
    let err = client(&server, &forged_public)
        .call(&RpcRequest::WhoAmI)
        .expect_err("a public-seed token must never authenticate against a keyed server");
    assert!(
        err.to_string().contains("401"),
        "public-seed token must be rejected with HTTP 401, got: {err}"
    );

    // Nor may the admin token double as a signing secret.
    let forged_admin = mint_jit_lease_token(&lease, &derive_jit_signing_key(ADMIN_TOKEN));
    let err = client(&server, &forged_admin)
        .call(&RpcRequest::WhoAmI)
        .expect_err("an admin-token-derived key must never authenticate");
    assert!(
        err.to_string().contains("401"),
        "admin-derived token must be rejected with HTTP 401, got: {err}"
    );
    server.shutdown();
}
