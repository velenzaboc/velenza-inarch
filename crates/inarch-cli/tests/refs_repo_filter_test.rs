//! `GET /v1/refs` repository scoping tests (`inarch-cli`).
//!
//! The ref listing endpoint must return only the refs that belong to the repository named by the
//! `X-Inarch-Repo` request header (default repository: `default`), and it must report them under
//! their unscoped names. Scoped storage keys of the form `<repo>::<ref>` must never leak across
//! repositories, and must never appear in the response at all.
//!
//! Each test seeds an in-memory anonymous server through the binary RPC client (changesets first,
//! then refs created with `expected = None`), then issues a raw HTTP/1.1 request over a plain
//! `TcpStream` and parses the flat JSON object body with a tiny hand-rolled parser.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use inarch_cli::HttpServerHandle;
use inarch_engine::ScionEngine;
use inarch_store::{MemBlobStore, MemMetadataStore, RemoteRpcClient, RpcRequest, RpcResponse};
use inarch_types::bonsai::BonsaiChangeset;
use inarch_types::hash::ChangesetId;

const IO_TIMEOUT: Duration = Duration::from_secs(20);

/// A running anonymous server plus the hex ids of the three seeded root changesets.
///
/// Seeded refs (repository -> ref name -> changeset):
/// - `alpha`   -> `main`, `topic`   -> alpha root
/// - `beta`    -> `main`            -> beta root
/// - `default` -> `main`, `release` -> default root
struct Seeded {
    server: HttpServerHandle,
    alpha_hex: String,
    beta_hex: String,
    default_hex: String,
}

fn root_changeset(author: &str, message: &str, secs: i64) -> BonsaiChangeset {
    BonsaiChangeset::new(
        Vec::new(),
        author.to_string(),
        secs,
        0,
        message.to_string(),
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .expect("construct root changeset")
}

fn client_for(base_url: &str, repo: Option<&str>) -> RemoteRpcClient {
    let client = RemoteRpcClient::new(base_url, None).expect("build rpc client");
    match repo {
        Some(repo) => client.with_repo_id(repo),
        None => client,
    }
}

fn put_changeset(client: &RemoteRpcClient, cs: &BonsaiChangeset) -> ChangesetId {
    let expected = cs.changeset_id();
    let response = client
        .call(&RpcRequest::PutChangeset {
            changeset: cs.clone(),
        })
        .expect("PutChangeset transport");
    match response {
        RpcResponse::PutChangeset { id } => {
            assert_eq!(id, expected, "server stored a different changeset id");
            id
        }
        other => panic!("unexpected PutChangeset response: {other:?}"),
    }
}

fn create_ref(client: &RemoteRpcClient, repo: &str, name: &str, target: ChangesetId) {
    let response = client
        .call(&RpcRequest::CasRef {
            repo_id: repo.to_string(),
            ref_name: name.to_string(),
            expected: None,
            new_target: target,
        })
        .expect("CasRef transport");
    assert_eq!(
        response,
        RpcResponse::CasRefOk,
        "creating ref `{name}` in repo `{repo}` must succeed"
    );
}

fn seed_server() -> Seeded {
    let engine = Arc::new(ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    ));
    let server = inarch_cli::spawn_http_server_with_config(
        engine,
        "127.0.0.1:0",
        inarch_cli::ServerAuthConfig::insecure_allow_anonymous(),
    )
    .expect("spawn anonymous in-memory server");
    let base_url = server.base_url();

    let alpha_client = client_for(&base_url, Some("alpha"));
    let beta_client = client_for(&base_url, Some("beta"));
    let default_client = client_for(&base_url, None);

    let alpha_cs = root_changeset("alpha-dev@example.com", "alpha root", 1_761_300_001);
    let beta_cs = root_changeset("beta-dev@example.com", "beta root", 1_761_300_002);
    let default_cs = root_changeset("default-dev@example.com", "default root", 1_761_300_003);

    let alpha_id = put_changeset(&alpha_client, &alpha_cs);
    let beta_id = put_changeset(&beta_client, &beta_cs);
    let default_id = put_changeset(&default_client, &default_cs);
    assert_ne!(alpha_id, beta_id, "seed changesets must be distinct");
    assert_ne!(alpha_id, default_id, "seed changesets must be distinct");
    assert_ne!(beta_id, default_id, "seed changesets must be distinct");

    create_ref(&alpha_client, "alpha", "main", alpha_id);
    create_ref(&alpha_client, "alpha", "topic", alpha_id);
    create_ref(&beta_client, "beta", "main", beta_id);
    create_ref(&default_client, "default", "main", default_id);
    create_ref(&default_client, "default", "release", default_id);

    Seeded {
        server,
        alpha_hex: alpha_id.to_hex(),
        beta_hex: beta_id.to_hex(),
        default_hex: default_id.to_hex(),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Issues `GET /v1/refs` with an optional `X-Inarch-Repo` header; returns `(status, body)`.
fn http_get_refs(addr: SocketAddr, repo_header: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect to test server");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("set write timeout");

    let mut request = format!("GET /v1/refs HTTP/1.1\r\nHost: {addr}\r\n");
    if let Some(repo) = repo_header {
        request.push_str(&format!("X-Inarch-Repo: {repo}\r\n"));
    }
    request.push_str("Connection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .expect("send GET /v1/refs request");
    stream.flush().expect("flush GET /v1/refs request");

    let mut raw: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find_subslice(&raw, b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut chunk).expect("read response headers");
        assert!(n > 0, "connection closed before response headers completed");
        raw.extend_from_slice(&chunk[..n]);
    };

    let head = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("malformed HTTP status line in {head:?}"));
    let content_length = head
        .lines()
        .skip(1)
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            if key.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .expect("response carries a Content-Length header");

    while raw.len() < header_end + content_length {
        let n = stream.read(&mut chunk).expect("read response body");
        assert!(n > 0, "connection closed before response body completed");
        raw.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&raw[header_end..header_end + content_length]).to_string();
    (status, body)
}

/// Parses a flat JSON object whose keys and values are all strings (the `/v1/refs` shape).
fn parse_flat_json_object(body: &str) -> BTreeMap<String, String> {
    let trimmed = body.trim();
    assert!(
        trimmed.starts_with('{') && trimmed.ends_with('}'),
        "body is not a JSON object: {body:?}"
    );
    let inner = &trimmed[1..trimmed.len() - 1];

    let mut strings: Vec<String> = Vec::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                let mut current = String::new();
                loop {
                    match chars.next() {
                        Some('\\') => {
                            let escaped = chars
                                .next()
                                .unwrap_or_else(|| panic!("dangling escape in body: {body:?}"));
                            current.push(escaped);
                        }
                        Some('"') => break,
                        Some(other) => current.push(other),
                        None => panic!("unterminated JSON string in body: {body:?}"),
                    }
                }
                strings.push(current);
            }
            ':' | ',' => {}
            c if c.is_whitespace() => {}
            other => panic!("unexpected character {other:?} in refs body: {body:?}"),
        }
    }
    assert!(
        strings.len() % 2 == 0,
        "odd number of JSON strings in refs body: {body:?}"
    );

    let mut map = BTreeMap::new();
    for pair in strings.chunks(2) {
        let key = &pair[0];
        let previous = map.insert(key.clone(), pair[1].clone());
        assert!(
            previous.is_none(),
            "duplicate key {key:?} in refs body: {body:?}"
        );
    }
    map
}

/// Fetches and parses the ref listing, asserting HTTP 200.
fn fetch_refs(addr: SocketAddr, repo_header: Option<&str>) -> BTreeMap<String, String> {
    let (status, body) = http_get_refs(addr, repo_header);
    assert_eq!(
        status, 200,
        "GET /v1/refs (repo header {repo_header:?}) must return 200, body: {body}"
    );
    parse_flat_json_object(&body)
}

fn assert_no_scoped_keys(refs: &BTreeMap<String, String>, context: &str) {
    for key in refs.keys() {
        assert!(
            !key.contains("::"),
            "{context}: response leaked scoped ref key `{key}`: {refs:?}"
        );
    }
}

fn assert_hex_absent(refs: &BTreeMap<String, String>, hex: &str, owner: &str, context: &str) {
    assert!(
        !refs.values().any(|value| value == hex),
        "{context}: response leaked a ref that belongs to the {owner} repo: {refs:?}"
    );
}

fn expected_map(pairs: &[(&str, &String)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(name, hex)| ((*name).to_string(), (*hex).clone()))
        .collect()
}

#[test]
fn refs_endpoint_scopes_listing_to_the_alpha_repo() {
    let seeded = seed_server();
    let addr = seeded.server.local_addr();

    let refs = fetch_refs(addr, Some("alpha"));

    assert_eq!(
        refs.get("main"),
        Some(&seeded.alpha_hex),
        "alpha `main` must resolve to the alpha root changeset: {refs:?}"
    );
    assert_hex_absent(&refs, &seeded.beta_hex, "beta", "alpha listing");
    assert_hex_absent(&refs, &seeded.default_hex, "default", "alpha listing");
    assert_no_scoped_keys(&refs, "alpha listing");
    assert_eq!(
        refs,
        expected_map(&[("main", &seeded.alpha_hex), ("topic", &seeded.alpha_hex)]),
        "alpha listing must contain exactly the alpha refs under unscoped names"
    );
}

#[test]
fn refs_endpoint_scopes_listing_to_the_beta_repo() {
    let seeded = seed_server();
    let addr = seeded.server.local_addr();

    let refs = fetch_refs(addr, Some("beta"));

    assert_eq!(
        refs.get("main"),
        Some(&seeded.beta_hex),
        "beta `main` must resolve to the beta root changeset: {refs:?}"
    );
    assert_hex_absent(&refs, &seeded.alpha_hex, "alpha", "beta listing");
    assert_hex_absent(&refs, &seeded.default_hex, "default", "beta listing");
    assert_no_scoped_keys(&refs, "beta listing");
    assert_eq!(
        refs,
        expected_map(&[("main", &seeded.beta_hex)]),
        "beta listing must contain exactly the beta refs under unscoped names"
    );
}

#[test]
fn refs_endpoint_without_repo_header_lists_only_default_repo_refs() {
    let seeded = seed_server();
    let addr = seeded.server.local_addr();
    let expected = expected_map(&[
        ("main", &seeded.default_hex),
        ("release", &seeded.default_hex),
    ]);

    // No `X-Inarch-Repo` header: the default repository.
    let implicit = fetch_refs(addr, None);
    assert_eq!(
        implicit.get("main"),
        Some(&seeded.default_hex),
        "default `main` must resolve to the default root changeset: {implicit:?}"
    );
    assert_hex_absent(&implicit, &seeded.alpha_hex, "alpha", "default listing");
    assert_hex_absent(&implicit, &seeded.beta_hex, "beta", "default listing");
    assert_no_scoped_keys(&implicit, "default listing");
    assert_eq!(
        implicit, expected,
        "default listing must contain exactly the default refs"
    );

    // Naming the default repository explicitly selects the same listing.
    let explicit = fetch_refs(addr, Some("default"));
    assert_no_scoped_keys(&explicit, "explicit default listing");
    assert_eq!(
        explicit, expected,
        "explicit `default` repo header must list exactly the default refs"
    );
}

#[test]
fn refs_endpoint_lists_nothing_for_a_repo_without_refs() {
    let seeded = seed_server();
    let addr = seeded.server.local_addr();

    let refs = fetch_refs(addr, Some("gamma"));

    assert!(
        refs.is_empty(),
        "a repo with no refs must list nothing, got: {refs:?}"
    );
}
