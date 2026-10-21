//! HTTP request-body admission tests (`inarch-cli`).
//!
//! The server must authenticate the caller BEFORE it reads (or allocates room for) the request
//! body, and it must refuse an absurd declared `Content-Length` with `413 Payload Too Large`
//! instead of allocating it.
//!
//! Every request in this file declares a `Content-Length` and then sends NO body bytes at all.
//! A server that allocates the declared length or blocks waiting for the body therefore never
//! answers, and the client read timeout turns that into a clear test failure. A server that
//! decides from the headers alone answers immediately and closes the connection.
//!
//! The tests speak raw HTTP/1.1 over `std::net::TcpStream` and parse only the status line.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use inarch_cli::{HttpServerHandle, spawn_http_server};
use inarch_engine::ScionEngine;
use inarch_store::{MemBlobStore, MemMetadataStore, RemoteRpcClient, RpcRequest, RpcResponse};

const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// 2^40 bytes (1 TiB): far above any sane request body, and far above what may be allocated.
const HUGE_CONTENT_LENGTH: u64 = 1_099_511_627_776;

/// A modest declared length that the server would simply wait for if it read the body first.
const SMALL_CONTENT_LENGTH: u64 = 1000;

const ADMIN_TOKEN: &str = "body-limit-test-admin-token";

fn new_engine() -> Arc<ScionEngine> {
    Arc::new(ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    ))
}

/// Server that requires the admin bearer token for every route except `/health`.
fn spawn_auth_required_server() -> HttpServerHandle {
    spawn_http_server(new_engine(), "127.0.0.1:0", Some(ADMIN_TOKEN.to_string()))
        .expect("spawn auth-required in-memory server")
}

/// Server with explicit anonymous opt-in: every caller is anonymous.
fn spawn_anonymous_server() -> HttpServerHandle {
    inarch_cli::spawn_http_server_with_config(
        new_engine(),
        "127.0.0.1:0",
        inarch_cli::ServerAuthConfig::insecure_allow_anonymous(),
    )
    .expect("spawn anonymous in-memory server")
}

/// Sends a header-only `POST /v1/rpc` that declares `content_length` bytes and delivers none,
/// then returns the numeric HTTP status from the response status line.
///
/// Fails the calling test with a descriptive panic if no status line arrives (timeout, reset,
/// or early close).
fn post_rpc_without_body(
    addr: SocketAddr,
    content_length: u64,
    bearer: Option<&str>,
    what: &str,
) -> u16 {
    let mut stream = TcpStream::connect(addr).expect("connect to test server");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("set write timeout");

    let mut request = format!(
        "POST /v1/rpc HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/octet-stream\r\nContent-Length: {content_length}\r\nConnection: close\r\n"
    );
    if let Some(token) = bearer {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .expect("send header-only POST /v1/rpc request");
    stream.flush().expect("flush POST /v1/rpc request");

    // The server must answer from the headers alone; it never needs the body.
    read_status_line(&mut stream, what, Instant::now())
}

/// `GET /health` over a fresh connection; returns the numeric HTTP status.
fn get_health(addr: SocketAddr, what: &str) -> u16 {
    let mut stream = TcpStream::connect(addr).expect("connect to test server for /health");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("set write timeout");
    let request = format!("GET /health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .expect("send GET /health request");
    stream.flush().expect("flush GET /health request");
    read_status_line(&mut stream, what, Instant::now())
}

/// Reads until the first CRLF and parses `HTTP/1.1 <code> ...`.
///
/// A read timeout, a connection reset, or an EOF before a complete status line is a test
/// failure with an explicit message; it is never treated as a successful refusal.
fn read_status_line(stream: &mut TcpStream, what: &str, started: Instant) -> u16 {
    let mut raw: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(pos) = raw.windows(2).position(|w| w == b"\r\n") {
            let line = String::from_utf8_lossy(&raw[..pos]).to_string();
            let mut parts = line.split_whitespace();
            let version = parts.next().unwrap_or("");
            assert!(
                version.starts_with("HTTP/1."),
                "{what}: malformed HTTP status line {line:?}"
            );
            return parts
                .next()
                .and_then(|code| code.parse::<u16>().ok())
                .unwrap_or_else(|| panic!("{what}: malformed HTTP status line {line:?}"));
        }
        match stream.read(&mut chunk) {
            Ok(0) => panic!(
                "{what}: connection closed after {:?} without a complete HTTP status line \
                 (received {} bytes: {:?})",
                started.elapsed(),
                raw.len(),
                String::from_utf8_lossy(&raw)
            ),
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => panic!(
                "{what}: no HTTP status line within {IO_TIMEOUT:?} (waited {:?}); the server is \
                 still waiting for the request body or allocating the declared length instead of \
                 deciding from the headers",
                started.elapsed()
            ),
            Err(e) => panic!(
                "{what}: read failed after {:?} before any HTTP status line (connection \
                 reset or aborted instead of an HTTP refusal): {e}",
                started.elapsed()
            ),
        }
    }
}

#[test]
fn huge_content_length_without_credentials_is_rejected_with_401() {
    let server = spawn_auth_required_server();
    let addr = server.local_addr();

    let status = post_rpc_without_body(
        addr,
        HUGE_CONTENT_LENGTH,
        None,
        "auth-required server, Content-Length 2^40, no Authorization, no body",
    );

    assert_eq!(
        status, 401,
        "an unauthenticated request must be refused with 401 before its body is read"
    );
}

#[test]
fn small_content_length_without_credentials_is_rejected_with_401_before_body_arrives() {
    let server = spawn_auth_required_server();
    let addr = server.local_addr();

    // Only 1000 bytes are declared and none are sent. If the server waited for the body before
    // authenticating, this request would hang until the client timeout.
    let status = post_rpc_without_body(
        addr,
        SMALL_CONTENT_LENGTH,
        None,
        "auth-required server, Content-Length 1000, no Authorization, no body",
    );

    assert_eq!(
        status, 401,
        "authentication must happen before the server waits for the request body"
    );
}

#[test]
fn huge_content_length_with_valid_admin_token_is_rejected_with_413() {
    let server = spawn_auth_required_server();
    let addr = server.local_addr();

    let status = post_rpc_without_body(
        addr,
        HUGE_CONTENT_LENGTH,
        Some(ADMIN_TOKEN),
        "auth-required server, Content-Length 2^40, valid admin token, no body",
    );

    assert_eq!(
        status, 413,
        "an authenticated request declaring a 1 TiB body must be refused with 413 Payload Too Large"
    );
}

#[test]
fn huge_content_length_on_anonymous_server_is_rejected_with_413() {
    let server = spawn_anonymous_server();
    let addr = server.local_addr();

    let status = post_rpc_without_body(
        addr,
        HUGE_CONTENT_LENGTH,
        None,
        "anonymous server, Content-Length 2^40, no body",
    );

    assert_eq!(
        status, 413,
        "an anonymous-admin request declaring a 1 TiB body must be refused with 413 Payload Too Large"
    );
}

#[test]
fn servers_still_answer_health_after_oversized_and_unauthenticated_requests() {
    let auth_server = spawn_auth_required_server();
    let anon_server = spawn_anonymous_server();
    let auth_addr = auth_server.local_addr();
    let anon_addr = anon_server.local_addr();

    // Throw every refusal case at the servers first.
    assert_eq!(
        post_rpc_without_body(
            auth_addr,
            HUGE_CONTENT_LENGTH,
            None,
            "auth-required server, huge length, no token",
        ),
        401,
        "unauthenticated huge request must be 401"
    );
    assert_eq!(
        post_rpc_without_body(
            auth_addr,
            SMALL_CONTENT_LENGTH,
            None,
            "auth-required server, small length, no token",
        ),
        401,
        "unauthenticated small request must be 401"
    );
    assert_eq!(
        post_rpc_without_body(
            auth_addr,
            HUGE_CONTENT_LENGTH,
            Some(ADMIN_TOKEN),
            "auth-required server, huge length, admin token",
        ),
        413,
        "authenticated huge request must be 413"
    );
    assert_eq!(
        post_rpc_without_body(
            anon_addr,
            HUGE_CONTENT_LENGTH,
            None,
            "anonymous server, huge length",
        ),
        413,
        "anonymous huge request must be 413"
    );

    // Both servers must still be alive and serving /health (which needs no credentials).
    assert_eq!(
        get_health(auth_addr, "auth-required server /health after refusals"),
        200,
        "auth-required server must still answer /health after the refused requests"
    );
    assert_eq!(
        get_health(anon_addr, "anonymous server /health after refusals"),
        200,
        "anonymous server must still answer /health after the refused requests"
    );
}

#[test]
fn authenticated_rpc_with_a_normal_body_still_works() {
    let server = spawn_auth_required_server();
    let base_url = server.base_url();

    // The reordering of authentication and body reading must not break ordinary calls.
    let client = RemoteRpcClient::new(&base_url, Some(ADMIN_TOKEN.to_string()))
        .expect("build rpc client with admin token");
    let response = client
        .call(&RpcRequest::WhoAmI)
        .expect("WhoAmI transport with admin token");
    assert!(
        matches!(response, RpcResponse::WhoAmI { .. }),
        "an authenticated WhoAmI with a normal body must succeed, got: {response:?}"
    );
}
