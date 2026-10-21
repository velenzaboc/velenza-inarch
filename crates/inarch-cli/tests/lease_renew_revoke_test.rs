//! JIT lease lifetime cap and ownership tests (`inarch-cli`).
//!
//! Covers two server-side rules for `RenewLease` / `RevokeLease`:
//! 1. A lease may never live longer than `MAX_JIT_LEASE_LIFETIME_SECS` in total, counted from its
//!    `issued_at_unix`: renewals past that point are refused and an in-window renewal never pushes
//!    `expires_at_unix` beyond `issued_at_unix + 86_400`.
//! 2. Only the issuing principal (the lease's `principal_email`), the lease itself, or an admin may
//!    renew or revoke a lease. Another enrolled principal is refused, and the lease is untouched.
//!
//! The server runs in-memory with an admin bootstrap token, an explicit JIT signing key and a mock
//! OIDC tokeninfo endpoint (plain `http://` on `127.0.0.1:0`) that returns an `aud` claim matching
//! the configured `oidc_audience`. Two principals are enrolled through the admin client.

#![allow(clippy::field_reassign_with_default)]

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

const ADMIN_TOKEN: &str = "lease-test-admin-bootstrap-secret";
const OIDC_AUDIENCE: &str = "inarch-lease-test-audience";
const TOKEN_ALICE: &str = "oidc-tok-lease-alice";
const TOKEN_BOB: &str = "oidc-tok-lease-bob";
const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const REPO: &str = "repo-lease";
const LIFETIME_CAP_SECS: i64 = 86_400;
const IO_TIMEOUT: Duration = Duration::from_secs(20);

const MSG_CAP: &str = "lease lifetime cap reached";
const MSG_OWNER: &str = "only the issuing principal or an admin may renew or revoke this lease";

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs() as i64
}

/// Reads one HTTP request head from `stream` (until the blank line, EOF or timeout).
fn read_request_head(stream: &mut TcpStream) -> String {
    let mut raw: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    while !raw.windows(4).any(|w| w == b"\r\n\r\n") && raw.len() < 16 * 1024 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&raw).to_string()
}

/// Mock Google-style tokeninfo endpoint; answers for the two test tokens, rejects everything else.
fn spawn_mock_tokeninfo(stop: Arc<AtomicBool>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock tokeninfo listener");
    let addr = listener.local_addr().expect("mock tokeninfo local addr");
    std::thread::spawn(move || {
        for stream_res in listener.incoming() {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            let Ok(mut stream) = stream_res else {
                continue;
            };
            let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
            let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
            let head = read_request_head(&mut stream);
            let (status, body) = if head.contains(&format!("id_token={TOKEN_ALICE}")) {
                (
                    "200 OK",
                    format!(
                        r#"{{"email":"{ALICE}","email_verified":"true","exp":"4102444800","aud":"{OIDC_AUDIENCE}"}}"#
                    ),
                )
            } else if head.contains(&format!("id_token={TOKEN_BOB}")) {
                (
                    "200 OK",
                    format!(
                        r#"{{"email":"{BOB}","email_verified":"true","exp":"4102444800","aud":"{OIDC_AUDIENCE}"}}"#
                    ),
                )
            } else {
                (
                    "400 Bad Request",
                    r#"{"error":"invalid_token","error_description":"unknown test token"}"#
                        .to_string(),
                )
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    addr
}

/// A running keyed, audience-checked server plus one client per caller.
struct Env {
    _server: HttpServerHandle,
    mock_addr: SocketAddr,
    mock_stop: Arc<AtomicBool>,
    admin: RemoteRpcClient,
    alice: RemoteRpcClient,
    bob: RemoteRpcClient,
}

impl Drop for Env {
    fn drop(&mut self) {
        self.mock_stop.store(true, Ordering::SeqCst);
        // Wake the blocking accept loop so the mock thread observes the stop flag.
        let _ = TcpStream::connect(self.mock_addr);
    }
}

fn client(remote_url: &str, token: &str) -> RemoteRpcClient {
    RemoteRpcClient::new(remote_url, Some(token.to_string()))
        .expect("build rpc client")
        .with_repo_id(REPO)
}

fn enroll(admin: &RemoteRpcClient, email: &str) {
    let response = admin
        .call(&RpcRequest::EnrollPrincipal {
            record: PrincipalRecord {
                principal_email: email.to_string(),
                principal_kind: "workstation".to_string(),
                host_label: format!("host-{email}"),
                allowed_repos: vec!["*".to_string()],
                allowed_ops: vec!["read".to_string(), "land".to_string()],
                status: "active".to_string(),
                enrolled_by: String::new(),
                created_at_unix: 1_761_400_000,
                revoked_at_unix: None,
                allowed_write_prefixes: vec!["*".to_string()],
            },
        })
        .expect("EnrollPrincipal transport");
    assert_eq!(
        response,
        RpcResponse::EnrollPrincipalOk,
        "enrolling {email} must succeed"
    );
}

fn setup() -> Env {
    let mock_stop = Arc::new(AtomicBool::new(false));
    let mock_addr = spawn_mock_tokeninfo(Arc::clone(&mock_stop));

    let engine = Arc::new(ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    ));
    let mut auth_cfg = ServerAuthConfig::new(Some(ADMIN_TOKEN.to_string()));
    auth_cfg.jit_signing_key = Some(derive_jit_signing_key(
        "lease-renew-revoke-test-key-material",
    ));
    auth_cfg.oidc_tokeninfo_url = Some(format!("http://{mock_addr}/tokeninfo"));
    auth_cfg.oidc_audience = Some(OIDC_AUDIENCE.to_string());
    auth_cfg.require_auth = true;

    let server = spawn_http_server_with_config(engine, "127.0.0.1:0", auth_cfg)
        .expect("spawn keyed OIDC server");
    let remote_url = format!("http://{}", server.local_addr());

    let admin = client(&remote_url, ADMIN_TOKEN);
    enroll(&admin, ALICE);
    enroll(&admin, BOB);

    Env {
        alice: client(&remote_url, TOKEN_ALICE),
        bob: client(&remote_url, TOKEN_BOB),
        admin,
        mock_addr,
        mock_stop,
        _server: server,
    }
}

fn lease_record(lease_id: &str, issued_at_unix: i64, expires_at_unix: i64) -> JitLeaseRecord {
    JitLeaseRecord {
        lease_id: lease_id.to_string(),
        principal_email: ALICE.to_string(),
        swarm_id: "swarm-r05".to_string(),
        task_id: "TASK-R05".to_string(),
        repo_id: REPO.to_string(),
        allowed_ops: vec!["read".to_string(), "land".to_string()],
        allowed_read_prefixes: Vec::new(),
        allowed_write_prefixes: Vec::new(),
        issued_at_unix,
        expires_at_unix,
        revoked: false,
        allowed_refs: vec!["main".to_string()],
    }
}

fn put_lease(admin: &RemoteRpcClient, record: &JitLeaseRecord) {
    let response = admin
        .call(&RpcRequest::PutLease {
            record: record.clone(),
        })
        .expect("PutLease transport");
    assert_eq!(
        response,
        RpcResponse::PutLeaseOk,
        "admin PutLease must succeed"
    );
}

fn get_lease(caller: &RemoteRpcClient, lease_id: &str) -> JitLeaseRecord {
    match caller
        .call(&RpcRequest::GetLease {
            lease_id: lease_id.to_string(),
        })
        .expect("GetLease transport")
    {
        RpcResponse::GetLease { lease: Some(lease) } => lease,
        other => panic!("expected GetLease with a stored lease, got {other:?}"),
    }
}

fn renew(caller: &RemoteRpcClient, lease_id: &str, ttl_secs: u64) -> RpcResponse {
    caller
        .call(&RpcRequest::RenewLease {
            lease_id: lease_id.to_string(),
            ttl_secs,
        })
        .expect("RenewLease transport")
}

fn revoke(caller: &RemoteRpcClient, lease_id: &str) -> RpcResponse {
    caller
        .call(&RpcRequest::RevokeLease {
            lease_id: lease_id.to_string(),
            revoked_at_unix: now_unix(),
        })
        .expect("RevokeLease transport")
}

fn assert_refused(response: RpcResponse, frozen_substring: &str, context: &str) {
    match response {
        RpcResponse::Error { message } => assert!(
            message.contains(frozen_substring),
            "{context}: error must contain `{frozen_substring}`, got `{message}`"
        ),
        other => {
            panic!("{context}: expected a refusal containing `{frozen_substring}`, got {other:?}")
        }
    }
}

fn renewed_lease(response: RpcResponse, context: &str) -> JitLeaseRecord {
    match response {
        RpcResponse::RenewLease { lease, .. } => lease,
        other => panic!("{context}: expected RenewLease success, got {other:?}"),
    }
}

#[test]
fn renew_after_total_lifetime_cap_is_refused_and_expiry_unchanged() {
    let env = setup();
    let now = now_unix();
    // Issued 90000 seconds ago (past the 86400 cap) but still unexpired for another 10 minutes.
    let record = lease_record("lease_r05_cap_exceeded_0001", now - 90_000, now + 600);
    put_lease(&env.admin, &record);

    let response = renew(&env.admin, &record.lease_id, 600);
    assert_refused(response, MSG_CAP, "renew past issued_at + 86400");

    let after = get_lease(&env.admin, &record.lease_id);
    assert_eq!(
        after.expires_at_unix, record.expires_at_unix,
        "a refused renewal must leave expires_at_unix unchanged"
    );
    assert_eq!(after.issued_at_unix, record.issued_at_unix);
    assert!(
        !after.revoked,
        "a refused renewal must not revoke the lease"
    );
}

#[test]
fn renewed_expiry_never_exceeds_issue_time_plus_lifetime_cap() {
    let env = setup();
    let now = now_unix();
    let issued_at = now - 3_600;
    let original_expiry = now + 60;
    let record = lease_record("lease_r05_cap_clamped_0002", issued_at, original_expiry);
    put_lease(&env.admin, &record);

    // Asking for the maximum ttl must be clamped to the remaining lifetime window.
    let lease = renewed_lease(
        renew(&env.admin, &record.lease_id, 86_400),
        "in-window renew with ttl 86400",
    );
    let cap = issued_at + LIFETIME_CAP_SECS;
    assert!(
        lease.expires_at_unix <= cap,
        "renewed expiry {} must not exceed issued_at + 86400 = {cap}",
        lease.expires_at_unix
    );
    assert!(
        lease.expires_at_unix > original_expiry,
        "an in-window renewal must extend the lease beyond {original_expiry}, got {}",
        lease.expires_at_unix
    );
    assert!(
        lease.expires_at_unix >= cap - 5,
        "the clamped expiry should sit at the cap ({cap}), got {}",
        lease.expires_at_unix
    );

    let stored = get_lease(&env.admin, &record.lease_id);
    assert_eq!(
        stored.expires_at_unix, lease.expires_at_unix,
        "the stored lease must carry the clamped expiry"
    );
    assert_eq!(stored.issued_at_unix, issued_at, "issue time is immutable");

    // This lease belongs to alice, so an admin revoking it exercises the admin exemption.
    assert_eq!(
        revoke(&env.admin, &record.lease_id),
        RpcResponse::RevokeLeaseOk,
        "admin must be able to revoke another principal's lease"
    );
    assert!(
        get_lease(&env.admin, &record.lease_id).revoked,
        "admin revoke must mark the lease revoked"
    );
}

#[test]
fn only_issuer_or_admin_may_renew_or_revoke_a_lease() {
    let env = setup();

    // Alice checks out a lease through the real handler.
    let lease_a = match env
        .alice
        .call(&RpcRequest::CheckoutLease {
            swarm_id: "swarm-alice".to_string(),
            task_id: "TASK-ALICE".to_string(),
            repo_id: REPO.to_string(),
            allowed_ops: vec!["read".to_string(), "land".to_string()],
            allowed_read_prefixes: Vec::new(),
            allowed_write_prefixes: Vec::new(),
            ttl_secs: 600,
            allowed_refs: vec!["main".to_string()],
        })
        .expect("alice CheckoutLease transport")
    {
        RpcResponse::CheckoutLease { lease, .. } => lease,
        other => panic!("expected alice CheckoutLease success, got {other:?}"),
    };
    assert_eq!(lease_a.principal_email, ALICE);
    let lease_id = lease_a.lease_id.clone();

    // Bob (a different enrolled principal) can neither renew nor revoke alice's lease.
    assert_refused(renew(&env.bob, &lease_id, 600), MSG_OWNER, "bob renew");
    assert_refused(revoke(&env.bob, &lease_id), MSG_OWNER, "bob revoke");

    let untouched = get_lease(&env.admin, &lease_id);
    assert!(
        !untouched.revoked,
        "bob's refused revoke must leave the lease active"
    );
    assert_eq!(
        untouched.expires_at_unix, lease_a.expires_at_unix,
        "bob's refused renew must leave the expiry unchanged"
    );

    // The issuing principal and an admin may both renew.
    let renewed_by_alice = renewed_lease(renew(&env.alice, &lease_id, 600), "alice renew");
    assert_eq!(renewed_by_alice.lease_id, lease_id);
    let renewed_by_admin = renewed_lease(renew(&env.admin, &lease_id, 600), "admin renew");
    assert_eq!(renewed_by_admin.lease_id, lease_id);

    // The issuing principal can revoke her own lease.
    assert_eq!(
        revoke(&env.alice, &lease_id),
        RpcResponse::RevokeLeaseOk,
        "alice must be able to revoke her own lease"
    );
    let after_revoke = get_lease(&env.admin, &lease_id);
    assert!(
        after_revoke.revoked,
        "the lease must be marked revoked after the issuer revoked it"
    );
}
