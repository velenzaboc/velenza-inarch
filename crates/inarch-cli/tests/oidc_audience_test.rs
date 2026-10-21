//! OIDC audience enforcement tests (`inarch-cli`).
//!
//! An OIDC bearer token is accepted only when the server has an `oidc_audience` configured and the
//! tokeninfo response carries an `aud` claim that equals it exactly. A mock tokeninfo endpoint
//! (plain `http://` over `127.0.0.1:0`) answers by token:
//!
//! - `tok-good`  -> `aud = https://inarch.example.com`
//! - `tok-wrong` -> `aud = https://other.example.com`
//! - `tok-noaud` -> no `aud` field at all
//!
//! All three tokens identify the same enrolled principal, `dana@example.com`.

#![allow(clippy::field_reassign_with_default)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use inarch_cli::{HttpServerHandle, InarchConfig, ServerAuthConfig, spawn_http_server_with_config};
use inarch_engine::ScionEngine;
use inarch_store::{
    MemBlobStore, MemMetadataStore, PrincipalRecord, RemoteRpcClient, RpcRequest, RpcResponse,
};

const ADMIN_TOKEN: &str = "oidc-audience-admin-secret";
const GOOD_AUDIENCE: &str = "https://inarch.example.com";
const WRONG_AUDIENCE: &str = "https://other.example.com";
const DANA: &str = "dana@example.com";
const SOCKET_TIMEOUT: Duration = Duration::from_secs(20);

/// Mock OIDC tokeninfo endpoint; stops its accept loop when dropped.
struct MockTokeninfo {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl MockTokeninfo {
    fn url(&self) -> String {
        format!("http://{}/tokeninfo", self.addr)
    }
}

impl Drop for MockTokeninfo {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocking accept so the loop observes the stop flag.
        let _ = TcpStream::connect(self.addr);
    }
}

fn tokeninfo_body_for(request: &str) -> (&'static str, String) {
    let claims = |aud: Option<&str>| -> String {
        let aud_field = match aud {
            Some(aud) => format!(r#""aud":"{aud}","#),
            None => String::new(),
        };
        format!(r#"{{{aud_field}"email":"{DANA}","email_verified":"true","exp":"4102444800"}}"#)
    };
    if request.contains("id_token=tok-good") {
        ("200 OK", claims(Some(GOOD_AUDIENCE)))
    } else if request.contains("id_token=tok-wrong") {
        ("200 OK", claims(Some(WRONG_AUDIENCE)))
    } else if request.contains("id_token=tok-noaud") {
        ("200 OK", claims(None))
    } else {
        (
            "400 Bad Request",
            r#"{"error":"invalid_token","error_description":"unknown test token"}"#.to_string(),
        )
    }
}

fn spawn_mock_tokeninfo() -> MockTokeninfo {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock tokeninfo listener");
    let addr = listener.local_addr().expect("mock tokeninfo local addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    std::thread::spawn(move || {
        for stream_res in listener.incoming() {
            if stop_clone.load(Ordering::SeqCst) {
                break;
            }
            let Ok(mut stream) = stream_res else {
                continue;
            };
            let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
            let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));

            // Read until the end of the request headers (the GET has no body).
            let mut raw: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 2048];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        raw.extend_from_slice(&chunk[..n]);
                        if raw.windows(4).any(|w| w == b"\r\n\r\n") || raw.len() > 16 * 1024 {
                            break;
                        }
                    }
                }
            }
            let request = String::from_utf8_lossy(&raw).to_string();
            let (status, body) = tokeninfo_body_for(&request);
            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    MockTokeninfo { addr, stop }
}

fn dana_record() -> PrincipalRecord {
    PrincipalRecord {
        principal_email: DANA.to_string(),
        principal_kind: "workstation".to_string(),
        host_label: "dana-laptop".to_string(),
        allowed_repos: vec!["*".to_string()],
        allowed_ops: vec!["read".to_string()],
        status: "active".to_string(),
        enrolled_by: String::new(),
        created_at_unix: 1_761_400_000,
        revoked_at_unix: None,
        allowed_write_prefixes: vec!["*".to_string()],
    }
}

/// Spawns an in-memory server with an admin token, an explicit JIT signing key, the mock
/// tokeninfo URL and the given audience, then enrolls `dana@example.com` through the admin token.
fn spawn_server(tokeninfo_url: &str, audience: Option<&str>) -> HttpServerHandle {
    let engine = Arc::new(ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    ));

    let mut auth_cfg = ServerAuthConfig::new(Some(ADMIN_TOKEN.to_string()));
    auth_cfg.jit_signing_key = Some(inarch_store::derive_jit_signing_key(
        "oidc-audience-test-signing-material",
    ));
    auth_cfg.oidc_tokeninfo_url = Some(tokeninfo_url.to_string());
    auth_cfg.oidc_audience = audience.map(str::to_string);
    auth_cfg.require_auth = true;

    let server = spawn_http_server_with_config(engine, "127.0.0.1:0", auth_cfg)
        .expect("spawn server with OIDC audience configuration");

    let admin = RemoteRpcClient::new(&server.base_url(), Some(ADMIN_TOKEN.to_string()))
        .expect("build admin rpc client");
    let enroll = admin
        .call(&RpcRequest::EnrollPrincipal {
            record: dana_record(),
        })
        .expect("admin enrolls dana");
    assert_eq!(enroll, RpcResponse::EnrollPrincipalOk);
    server
}

fn oidc_client(server: &HttpServerHandle, token: &str) -> RemoteRpcClient {
    RemoteRpcClient::new(&server.base_url(), Some(token.to_string()))
        .expect("build oidc rpc client")
}

/// Calls `WhoAmI` with `token` and returns the rendered error text; panics if the call succeeds.
fn who_am_i_error(server: &HttpServerHandle, token: &str) -> String {
    match oidc_client(server, token).call(&RpcRequest::WhoAmI) {
        Err(err) => err.to_string(),
        Ok(resp) => panic!("token `{token}` must be rejected, got response: {resp:?}"),
    }
}

#[test]
fn oidc_token_with_matching_audience_is_accepted() {
    let mock = spawn_mock_tokeninfo();
    let server = spawn_server(&mock.url(), Some(GOOD_AUDIENCE));

    let response = oidc_client(&server, "tok-good")
        .call(&RpcRequest::WhoAmI)
        .expect("token with matching aud must authenticate");
    match response {
        RpcResponse::WhoAmI { principal_id, .. } => {
            assert!(
                principal_id.contains(DANA),
                "principal_id `{principal_id}` must identify {DANA}"
            );
        }
        other => panic!("unexpected WhoAmI response: {other:?}"),
    }

    server.shutdown();
}

#[test]
fn oidc_token_with_wrong_audience_is_rejected() {
    let mock = spawn_mock_tokeninfo();
    let server = spawn_server(&mock.url(), Some(GOOD_AUDIENCE));

    let text = who_am_i_error(&server, "tok-wrong");
    assert!(text.contains("401"), "expected HTTP 401, got: {text}");
    assert!(
        text.contains("OIDC audience mismatch"),
        "expected audience mismatch detail, got: {text}"
    );

    server.shutdown();
}

#[test]
fn oidc_token_without_audience_claim_is_rejected() {
    let mock = spawn_mock_tokeninfo();
    let server = spawn_server(&mock.url(), Some(GOOD_AUDIENCE));

    let text = who_am_i_error(&server, "tok-noaud");
    assert!(text.contains("401"), "expected HTTP 401, got: {text}");
    assert!(
        text.contains("OIDC audience mismatch"),
        "expected audience mismatch detail, got: {text}"
    );

    server.shutdown();
}

#[test]
fn oidc_is_disabled_when_no_audience_is_configured() {
    let mock = spawn_mock_tokeninfo();
    // The tokeninfo URL is set and dana is enrolled, but no audience is configured.
    let server = spawn_server(&mock.url(), None);

    let text = who_am_i_error(&server, "tok-good");
    assert!(text.contains("401"), "expected HTTP 401, got: {text}");
    assert!(
        text.contains("OIDC disabled: no oidc_audience configured"),
        "expected OIDC-disabled detail, got: {text}"
    );

    server.shutdown();
}

#[test]
fn oidc_audience_config_round_trips_through_toml_and_server_auth() {
    // Default: no audience configured.
    let default_cfg = InarchConfig::default();
    assert!(
        default_cfg.oidc_audience.is_empty(),
        "default oidc_audience must be empty, got `{}`",
        default_cfg.oidc_audience
    );

    // Serialize and parse back.
    let mut cfg = InarchConfig::default();
    cfg.oidc_audience = GOOD_AUDIENCE.to_string();
    let toml = cfg.to_toml_string();
    assert!(
        toml.contains("oidc_audience"),
        "to_toml_string must emit oidc_audience:\n{toml}"
    );
    let parsed = InarchConfig::from_toml_str(&toml).expect("parse serialized config");
    assert_eq!(parsed.oidc_audience, GOOD_AUDIENCE);

    // Hand-written `[network]` section.
    let handwritten = format!("[network]\noidc_audience = \"{GOOD_AUDIENCE}\"\n");
    let parsed = InarchConfig::from_toml_str(&handwritten).expect("parse hand-written config");
    assert_eq!(parsed.oidc_audience, GOOD_AUDIENCE);

    // The server auth config carries the audience through.
    let mut server_cfg = InarchConfig::default();
    server_cfg.jit_signing_key =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string();
    server_cfg.oidc_audience = GOOD_AUDIENCE.to_string();
    let auth = ServerAuthConfig::from_inarch_config(&server_cfg)
        .expect("valid jit_signing_key must yield a server auth config");
    assert_eq!(auth.oidc_audience, Some(GOOD_AUDIENCE.to_string()));
    assert!(auth.jit_signing_key.is_some());

    // No audience configured -> None.
    server_cfg.oidc_audience = String::new();
    let auth = ServerAuthConfig::from_inarch_config(&server_cfg)
        .expect("valid jit_signing_key must yield a server auth config");
    assert_eq!(auth.oidc_audience, None);
}

#[test]
fn oidc_audience_env_override_reaches_effective_config() {
    // The `inr config` subcommand prints the effective configuration (file plus `INARCH_*`
    // environment overrides). The override is set only on the child process, never on this one.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "inarch-oidc-audience-env-{}-{}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&dir).expect("create temp config dir");
    let file = dir.join("inarch.toml");
    // The file value differs from the env value, so the env override must win.
    std::fs::write(
        &file,
        format!("[network]\noidc_audience = \"{WRONG_AUDIENCE}\"\n"),
    )
    .expect("write temp config file");

    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_inr"));
    command
        .arg("--config")
        .arg(&file)
        .arg("config")
        .current_dir(&dir);
    for (key, _) in std::env::vars() {
        if key.starts_with("INARCH_") {
            command.env_remove(key);
        }
    }
    command.env("INARCH_OIDC_AUDIENCE", GOOD_AUDIENCE);
    let output = command.output().expect("run inr config");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "inr config must succeed; stderr: {stderr}"
    );
    let line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("oidc_audience"))
        .unwrap_or_else(|| panic!("effective config must print oidc_audience:\n{stdout}"));
    assert!(
        line.contains(GOOD_AUDIENCE),
        "INARCH_OIDC_AUDIENCE must override the file value, got line `{line}`"
    );
    assert!(
        !line.contains(WRONG_AUDIENCE),
        "file value must be overridden, got line `{line}`"
    );
}
