//! `CheckoutLease` clamp tests (`inarch-cli`).
//!
//! A JIT lease is minted by an issuing principal, and it must never grant more than that principal
//! holds itself:
//!
//! - every requested op must be allowed for the issuing principal (`land` and `write` are
//!   equivalent), otherwise `lease op exceeds issuing principal`;
//! - when the issuing principal's write prefixes are restricted, an empty request inherits them,
//!   a wildcard (`"*"` or `""`) is refused, and each requested prefix must lie inside one of the
//!   principal's prefixes, otherwise `lease write prefix exceeds issuing principal`;
//! - the shared admin token (and the anonymous-admin caller) stays unrestricted.
//!
//! The server runs with a mock OIDC tokeninfo endpoint (plain `http://` over a `127.0.0.1:0`
//! listener) that answers per-token, an explicit JIT signing key, a configured OIDC audience and an
//! admin bootstrap token. The admin enrolls two principals through `EnrollPrincipal`; the tests then
//! authenticate as each principal with its OIDC bearer token and request leases.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use inarch_cli::{HttpServerHandle, ServerAuthConfig, spawn_http_server_with_config};
use inarch_engine::ScionEngine;
use inarch_store::{
    JitLeaseRecord, MemBlobStore, MemMetadataStore, PrincipalRecord, RemoteRpcClient, RpcRequest,
    RpcResponse, derive_jit_signing_key,
};

const ADMIN_TOKEN: &str = "lease-clamp-admin-secret";
const AUDIENCE: &str = "https://inarch.example.com";
const REPO: &str = "repo-core";
const READER_EMAIL: &str = "reader@example.com";
const READER_TOKEN: &str = "oidc-tok-reader";
const SCOPED_EMAIL: &str = "scoped@example.com";
const SCOPED_TOKEN: &str = "oidc-tok-scoped";
const SCOPED_PREFIX: &str = "crates/allowed";
const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

/// Mock OIDC tokeninfo endpoint: answers `GET /tokeninfo?id_token=<tok>` for the two test tokens.
struct MockTokenInfo {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl MockTokenInfo {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock tokeninfo listener");
        let addr = listener.local_addr().expect("mock tokeninfo addr");
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
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let identity = if request.contains(&format!("id_token={READER_TOKEN}")) {
                    Some(READER_EMAIL)
                } else if request.contains(&format!("id_token={SCOPED_TOKEN}")) {
                    Some(SCOPED_EMAIL)
                } else {
                    None
                };
                let (status, body) = match identity {
                    Some(email) => (
                        "200 OK",
                        format!(
                            "{{\"email\":\"{email}\",\"email_verified\":\"true\",\"exp\":\"4102444800\",\"aud\":\"{AUDIENCE}\"}}"
                        ),
                    ),
                    None => (
                        "400 Bad Request",
                        "{\"error\":\"invalid_token\",\"error_description\":\"unknown test token\"}"
                            .to_string(),
                    ),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Self { addr, stop }
    }

    fn url(&self) -> String {
        format!("http://{}/tokeninfo", self.addr)
    }
}

impl Drop for MockTokenInfo {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

/// A running server with the mock OIDC endpoint, an admin client, and the two enrolled principals.
struct Fixture {
    // Field order matters for drop: the server stops before the mock endpoint goes away.
    server: HttpServerHandle,
    _mock: MockTokenInfo,
    admin: RemoteRpcClient,
    reader: RemoteRpcClient,
    scoped: RemoteRpcClient,
}

fn principal(email: &str, ops: &[&str], write_prefixes: &[&str]) -> PrincipalRecord {
    PrincipalRecord {
        principal_email: email.to_string(),
        principal_kind: "workstation".to_string(),
        host_label: format!("host-{email}"),
        allowed_repos: vec!["*".to_string()],
        allowed_ops: ops.iter().map(|s| s.to_string()).collect(),
        status: "active".to_string(),
        enrolled_by: "admin@inarch.system".to_string(),
        created_at_unix: 1_761_400_000,
        revoked_at_unix: None,
        allowed_write_prefixes: write_prefixes.iter().map(|s| s.to_string()).collect(),
    }
}

fn client(base_url: &str, token: &str) -> RemoteRpcClient {
    RemoteRpcClient::new(base_url, Some(token.to_string()))
        .expect("build rpc client")
        .with_repo_id(REPO)
}

impl Fixture {
    fn start() -> Self {
        let mock = MockTokenInfo::spawn();

        let engine = Arc::new(ScionEngine::new(
            Arc::new(MemBlobStore::new()),
            Arc::new(MemMetadataStore::new()),
        ));
        let mut auth_cfg = ServerAuthConfig::new(Some(ADMIN_TOKEN.to_string()));
        auth_cfg.jit_signing_key =
            Some(derive_jit_signing_key("lease-clamp-test-signing-material"));
        auth_cfg.oidc_tokeninfo_url = Some(mock.url());
        auth_cfg.oidc_audience = Some(AUDIENCE.to_string());
        auth_cfg.require_auth = true;
        let server = spawn_http_server_with_config(engine, "127.0.0.1:0", auth_cfg)
            .expect("spawn server with OIDC + JIT auth");
        let base_url = server.base_url();

        let admin = client(&base_url, ADMIN_TOKEN);
        let reader = client(&base_url, READER_TOKEN);
        let scoped = client(&base_url, SCOPED_TOKEN);

        // The read-only principal holds no write prefix restriction of its own; the scoped
        // principal may read and land, but only under `crates/allowed`.
        for record in [
            principal(READER_EMAIL, &["read"], &["*"]),
            principal(SCOPED_EMAIL, &["read", "land"], &[SCOPED_PREFIX]),
        ] {
            let response = admin
                .call(&RpcRequest::EnrollPrincipal { record })
                .expect("EnrollPrincipal transport");
            assert_eq!(response, RpcResponse::EnrollPrincipalOk);
        }

        Self {
            server,
            _mock: mock,
            admin,
            reader,
            scoped,
        }
    }

    /// Sanity: both OIDC identities authenticate (so later refusals are about the lease clamp, not
    /// about authentication).
    fn assert_identities_authenticate(&self) {
        for (client, email) in [(&self.reader, READER_EMAIL), (&self.scoped, SCOPED_EMAIL)] {
            match client.call(&RpcRequest::WhoAmI).expect("WhoAmI transport") {
                RpcResponse::WhoAmI {
                    principal_id,
                    auth_method,
                    ..
                } => {
                    assert_eq!(principal_id, email);
                    assert_eq!(auth_method, "gcp_oidc");
                }
                other => panic!("unexpected WhoAmI response: {other:?}"),
            }
        }
    }

    /// Every refused request must leave the lease table untouched.
    fn assert_no_leases_stored(&self) {
        match self
            .admin
            .call(&RpcRequest::ListLeases { repo_id: None })
            .expect("ListLeases transport")
        {
            RpcResponse::ListLeases { leases } => assert!(
                leases.is_empty(),
                "a refused CheckoutLease must not persist a lease, found: {leases:?}"
            ),
            other => panic!("unexpected ListLeases response: {other:?}"),
        }
    }
}

fn checkout(client: &RemoteRpcClient, ops: &[&str], write_prefixes: &[&str]) -> RpcResponse {
    client
        .call(&RpcRequest::CheckoutLease {
            swarm_id: "swarm-clamp".to_string(),
            task_id: "TASK-CLAMP".to_string(),
            repo_id: REPO.to_string(),
            allowed_ops: ops.iter().map(|s| s.to_string()).collect(),
            allowed_read_prefixes: Vec::new(),
            allowed_write_prefixes: write_prefixes.iter().map(|s| s.to_string()).collect(),
            ttl_secs: 600,
            allowed_refs: vec!["main".to_string()],
        })
        .expect("CheckoutLease transport")
}

fn expect_refused(response: RpcResponse, frozen_substring: &str, context: &str) {
    match response {
        RpcResponse::Error { message } => assert!(
            message.contains(frozen_substring),
            "{context}: expected an error containing `{frozen_substring}`, got: {message}"
        ),
        other => panic!(
            "{context}: expected an error containing `{frozen_substring}`, got a success: {other:?}"
        ),
    }
}

fn expect_lease(response: RpcResponse, context: &str) -> (JitLeaseRecord, String) {
    match response {
        RpcResponse::CheckoutLease { lease, token } => (lease, token),
        other => panic!("{context}: expected CheckoutLease success, got: {other:?}"),
    }
}

#[test]
fn read_only_principal_cannot_mint_a_land_lease() {
    let fx = Fixture::start();
    fx.assert_identities_authenticate();

    expect_refused(
        checkout(&fx.reader, &["read", "land"], &[]),
        "lease op exceeds issuing principal",
        "read-only principal requesting [read, land]",
    );
    expect_refused(
        checkout(&fx.reader, &["land"], &[]),
        "lease op exceeds issuing principal",
        "read-only principal requesting [land]",
    );
    // `write` is equivalent to `land`, so it is just as far beyond a read-only principal.
    expect_refused(
        checkout(&fx.reader, &["write"], &[]),
        "lease op exceeds issuing principal",
        "read-only principal requesting [write]",
    );
    fx.assert_no_leases_stored();
    fx.server.shutdown();
}

#[test]
fn read_only_principal_can_mint_a_read_only_lease() {
    let fx = Fixture::start();

    let (lease, token) = expect_lease(
        checkout(&fx.reader, &["read"], &[]),
        "read-only principal requesting [read]",
    );
    assert_eq!(lease.principal_email, READER_EMAIL);
    assert_eq!(lease.repo_id, REPO);
    assert_eq!(lease.allowed_ops, vec!["read".to_string()]);
    assert!(lease.allowed_read_prefixes.is_empty());
    assert!(!token.is_empty(), "a minted lease carries a bearer token");
    fx.server.shutdown();
}

#[test]
fn principal_with_write_prefixes_cannot_mint_wildcard_or_outside_prefixes() {
    let fx = Fixture::start();
    fx.assert_identities_authenticate();

    let cases: [(&[&str], &str); 6] = [
        (&["*"], "wildcard `*`"),
        (&[""], "empty-string wildcard"),
        (&["crates/other"], "sibling prefix `crates/other`"),
        (&["crates"], "parent prefix `crates`"),
        (
            &["crates/allowed-evil"],
            "look-alike prefix `crates/allowed-evil`",
        ),
        (
            &["crates/allowed/sub", "crates/other"],
            "one inside and one outside prefix",
        ),
    ];
    for (requested, label) in cases {
        expect_refused(
            checkout(&fx.scoped, &["read", "land"], requested),
            "lease write prefix exceeds issuing principal",
            &format!("scoped principal requesting {label}"),
        );
    }
    fx.assert_no_leases_stored();
    fx.server.shutdown();
}

#[test]
fn empty_write_prefix_request_inherits_the_principals_prefixes() {
    let fx = Fixture::start();

    let (lease, _token) = expect_lease(
        checkout(&fx.scoped, &["read", "land"], &[]),
        "scoped principal requesting no explicit write prefixes",
    );
    assert_eq!(lease.principal_email, SCOPED_EMAIL);
    assert_eq!(
        lease.allowed_write_prefixes,
        vec![SCOPED_PREFIX.to_string()],
        "an empty request must inherit the issuing principal's write prefixes"
    );
    assert_eq!(
        lease.allowed_ops,
        vec!["read".to_string(), "land".to_string()]
    );
    fx.server.shutdown();
}

#[test]
fn prefix_inside_the_principals_prefix_is_accepted() {
    let fx = Fixture::start();

    let (lease, _token) = expect_lease(
        checkout(&fx.scoped, &["read", "land"], &["crates/allowed/sub"]),
        "scoped principal requesting crates/allowed/sub",
    );
    assert_eq!(
        lease.allowed_write_prefixes,
        vec!["crates/allowed/sub".to_string()]
    );

    // The principal's own prefix is also inside itself.
    let (own, _token) = expect_lease(
        checkout(&fx.scoped, &["read"], &[SCOPED_PREFIX]),
        "scoped principal requesting its own prefix",
    );
    assert_eq!(own.allowed_write_prefixes, vec![SCOPED_PREFIX.to_string()]);
    fx.server.shutdown();
}

#[test]
fn principal_without_write_restriction_may_request_any_prefixes() {
    let fx = Fixture::start();

    // The reader's record carries `"*"` write prefixes (unrestricted), so the prefix clamp does
    // not apply to it; only its ops bound the lease.
    let (lease, _token) = expect_lease(
        checkout(&fx.reader, &["read"], &["*"]),
        "unrestricted principal requesting a wildcard prefix",
    );
    assert_eq!(lease.allowed_write_prefixes, vec!["*".to_string()]);

    let (lease, _token) = expect_lease(
        checkout(&fx.reader, &["read"], &["crates/anything"]),
        "unrestricted principal requesting an arbitrary prefix",
    );
    assert_eq!(
        lease.allowed_write_prefixes,
        vec!["crates/anything".to_string()]
    );
    fx.server.shutdown();
}

#[test]
fn admin_token_remains_unrestricted() {
    let fx = Fixture::start();

    let (lease, _token) = expect_lease(
        checkout(&fx.admin, &["read", "land"], &["*"]),
        "admin requesting land with wildcard write prefixes",
    );
    assert_eq!(lease.principal_email, "admin@inarch.system");
    assert_eq!(
        lease.allowed_ops,
        vec!["read".to_string(), "land".to_string()]
    );
    assert_eq!(lease.allowed_write_prefixes, vec!["*".to_string()]);
    fx.server.shutdown();
}
