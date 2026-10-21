//! Principal write-prefix tests (`inarch-cli`).
//!
//! An enrolled principal carries `allowed_write_prefixes`. The restriction must be:
//! 1. stored and carried by the binary record codec (with legacy records decoding to an empty list),
//! 2. enforced for OIDC callers on `PutChangeset` (every touched path must lie inside a prefix),
//! 3. enforced when such a caller moves a ref onto changesets that touch outside paths, and
//! 4. settable through `inr principal enroll --write-prefixes a,b` (default: `*`, unrestricted).
//!
//! The OIDC flow uses a mock tokeninfo endpoint on `127.0.0.1:0`; the server only accepts an
//! OIDC bearer token whose `aud` equals the configured audience. The CLI tests spawn the real
//! `inr` binary with an explicit `--config` file and every `INARCH_*` variable removed.

#![allow(clippy::field_reassign_with_default)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use inarch_cli::{
    HttpServerHandle, ServerAuthConfig, spawn_http_server, spawn_http_server_with_config,
};
use inarch_engine::ScionEngine;
use inarch_store::{
    MemBlobStore, MemMetadataStore, PrincipalRecord, RemoteRpcClient, RpcRequest, RpcResponse,
};
use inarch_types::bonsai::{BonsaiChangeset, FileChange, FileType};
use inarch_types::hash::{BlobId, ChangesetId};
use inarch_types::path::MPath;

const AUDIENCE: &str = "inarch-test-audience";
const ADMIN_TOKEN: &str = "write-prefix-admin-secret";
const ERIN_TOKEN: &str = "oidc-tok-erin";
const HEIDI_TOKEN: &str = "oidc-tok-heidi";
const REPO: &str = "repo-docs";
const CLI_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------------------------

fn unique_temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "inarch-write-prefix-test-{}-{}-{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn strs(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

fn principal(email: &str, prefixes: &[&str]) -> PrincipalRecord {
    PrincipalRecord {
        principal_email: email.to_string(),
        principal_kind: "workstation".to_string(),
        host_label: "test-host".to_string(),
        allowed_repos: strs(&["*"]),
        allowed_ops: strs(&["read", "land"]),
        status: "active".to_string(),
        enrolled_by: String::new(),
        created_at_unix: 1_761_400_000,
        revoked_at_unix: None,
        allowed_write_prefixes: strs(prefixes),
    }
}

/// Builds a root changeset. Each entry is `(path, Some(content))` for a tracked file or
/// `(path, None)` for a deletion. `tag` keeps the changeset ids distinct.
fn changeset(
    parents: Vec<ChangesetId>,
    files: &[(&str, Option<&str>)],
    tag: &str,
) -> BonsaiChangeset {
    let mut file_changes = BTreeMap::new();
    for (path, content) in files {
        let change = match content {
            Some(text) => FileChange::Tracked {
                blob_id: BlobId::from_content(text.as_bytes()),
                size: text.len() as u64,
                file_type: FileType::Regular,
            },
            None => FileChange::Deleted,
        };
        file_changes.insert(MPath::new(path).expect("valid test path"), change);
    }
    BonsaiChangeset::new(
        parents,
        "erin@example.com".to_string(),
        1_761_400_100,
        0,
        format!("write prefix test changeset {tag}"),
        BTreeMap::new(),
        file_changes,
    )
    .expect("construct test changeset")
}

fn put_cs(client: &RemoteRpcClient, cs: &BonsaiChangeset) -> RpcResponse {
    client
        .call(&RpcRequest::PutChangeset {
            changeset: cs.clone(),
        })
        .expect("PutChangeset transport")
}

fn put_cs_ok(client: &RemoteRpcClient, cs: &BonsaiChangeset, context: &str) -> ChangesetId {
    match put_cs(client, cs) {
        RpcResponse::PutChangeset { id } => {
            assert_eq!(id, cs.changeset_id(), "{context}: server stored another id");
            id
        }
        other => panic!("{context}: expected PutChangeset ok, got {other:?}"),
    }
}

fn assert_error_contains(resp: &RpcResponse, needle: &str, context: &str) {
    match resp {
        RpcResponse::Error { message } => assert!(
            message.contains(needle),
            "{context}: error should contain {needle:?}, got {message:?}"
        ),
        other => {
            panic!("{context}: expected an Error response containing {needle:?}, got {other:?}")
        }
    }
}

fn cas_ref(
    client: &RemoteRpcClient,
    expected: Option<ChangesetId>,
    new_target: ChangesetId,
) -> RpcResponse {
    client
        .call(&RpcRequest::CasRef {
            repo_id: REPO.to_string(),
            ref_name: "main".to_string(),
            expected,
            new_target,
        })
        .expect("CasRef transport")
}

fn get_ref(client: &RemoteRpcClient) -> Option<ChangesetId> {
    match client
        .call(&RpcRequest::GetRef {
            repo_id: REPO.to_string(),
            ref_name: "main".to_string(),
        })
        .expect("GetRef transport")
    {
        RpcResponse::GetRef { target } => target,
        other => panic!("unexpected GetRef response: {other:?}"),
    }
}

fn get_principal(client: &RemoteRpcClient, email: &str) -> PrincipalRecord {
    match client
        .call(&RpcRequest::GetPrincipal {
            principal_id: email.to_string(),
        })
        .expect("GetPrincipal transport")
    {
        RpcResponse::GetPrincipal {
            record: Some(record),
        } => record,
        other => panic!("principal {email} should be enrolled, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Mock OIDC tokeninfo endpoint
// ---------------------------------------------------------------------------------------------

struct MockOidc {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl MockOidc {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock OIDC listener");
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut s) = stream else {
                    continue;
                };
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
                let mut req = Vec::new();
                let mut buf = [0u8; 2048];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let req_str = String::from_utf8_lossy(&req).to_string();
                let email = if req_str.contains(&format!("id_token={ERIN_TOKEN}")) {
                    Some("erin@example.com")
                } else if req_str.contains(&format!("id_token={HEIDI_TOKEN}")) {
                    Some("heidi@example.com")
                } else {
                    None
                };
                let (status, body) = match email {
                    Some(email) => (
                        "200 OK",
                        format!(
                            "{{\"email\":\"{email}\",\"email_verified\":\"true\",\"aud\":\"{AUDIENCE}\",\"exp\":\"4102444800\"}}"
                        ),
                    ),
                    None => (
                        "400 Bad Request",
                        "{\"error\":\"invalid_token\",\"error_description\":\"unknown test token\"}"
                            .to_string(),
                    ),
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
                let _ = s.flush();
            }
        });
        Self { addr, stop }
    }

    fn shutdown(self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

/// An auth-required server with OIDC (audience-checked) plus an admin bootstrap token.
struct OidcFixture {
    server: HttpServerHandle,
    oidc: MockOidc,
    base_url: String,
}

impl OidcFixture {
    fn start() -> Self {
        let oidc = MockOidc::start();
        let engine = Arc::new(ScionEngine::new(
            Arc::new(MemBlobStore::new()),
            Arc::new(MemMetadataStore::new()),
        ));
        let mut auth_cfg = ServerAuthConfig::new(Some(ADMIN_TOKEN.to_string()));
        auth_cfg.oidc_tokeninfo_url = Some(format!("http://{}/tokeninfo", oidc.addr));
        auth_cfg.oidc_audience = Some(AUDIENCE.to_string());
        auth_cfg.require_auth = true;
        let server = spawn_http_server_with_config(engine, "127.0.0.1:0", auth_cfg)
            .expect("spawn server with OIDC auth");
        let base_url = server.base_url();
        let fixture = Self {
            server,
            oidc,
            base_url,
        };

        // Admin enrolls erin (docs/ only) and heidi (unrestricted, explicit wildcard).
        let admin = fixture.client(ADMIN_TOKEN);
        for record in [
            principal("erin@example.com", &["docs/"]),
            principal("heidi@example.com", &["*"]),
        ] {
            let email = record.principal_email.clone();
            assert_eq!(
                admin
                    .call(&RpcRequest::EnrollPrincipal { record })
                    .expect("EnrollPrincipal transport"),
                RpcResponse::EnrollPrincipalOk,
                "enrolling {email}"
            );
        }
        fixture
    }

    fn client(&self, token: &str) -> RemoteRpcClient {
        RemoteRpcClient::new(&self.base_url, Some(token.to_string()))
            .expect("build rpc client")
            .with_repo_id(REPO)
    }

    fn shutdown(self) {
        self.server.shutdown();
        self.oidc.shutdown();
    }
}

// ---------------------------------------------------------------------------------------------
// 1. Record codec
// ---------------------------------------------------------------------------------------------

fn sample_record(prefixes: &[&str], revoked_at_unix: Option<i64>) -> PrincipalRecord {
    let mut record = principal("codec-user@example.com", prefixes);
    record.revoked_at_unix = revoked_at_unix;
    record
}

fn le_u32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

#[test]
fn principal_record_codec_round_trips_write_prefixes() {
    for revoked in [None, Some(1_761_400_999_i64)] {
        let original = sample_record(&["docs/", "src/app"], revoked);
        let bytes = original.to_bytes();
        let decoded = PrincipalRecord::from_bytes(&bytes).expect("decode record with prefixes");
        assert_eq!(decoded, original, "round trip must preserve every field");
        assert_eq!(
            decoded.allowed_write_prefixes,
            strs(&["docs/", "src/app"]),
            "prefix order and values must survive the codec"
        );

        // The new field is appended after the legacy layout: a u32 count, then length-prefixed
        // strings, with everything before it byte-identical to the legacy encoding.
        let mut tail = Vec::new();
        tail.extend_from_slice(&le_u32(2));
        for item in ["docs/", "src/app"] {
            tail.extend_from_slice(&le_u32(item.len() as u32));
            tail.extend_from_slice(item.as_bytes());
        }
        assert!(
            bytes.ends_with(&tail),
            "allowed_write_prefixes must be the last encoded field"
        );

        let empty_bytes = sample_record(&[], revoked).to_bytes();
        assert!(
            empty_bytes.ends_with(&le_u32(0)),
            "an empty prefix list still encodes a trailing zero count"
        );
        let legacy_prefix = &empty_bytes[..empty_bytes.len() - 4];
        assert_eq!(
            &bytes[..bytes.len() - tail.len()],
            legacy_prefix,
            "bytes before the appended field must equal the legacy encoding"
        );
    }
}

#[test]
fn principal_record_legacy_bytes_decode_with_empty_write_prefixes() {
    for revoked in [None, Some(1_761_400_999_i64)] {
        let expected = sample_record(&[], revoked);
        let full = expected.to_bytes();
        assert!(
            full.ends_with(&le_u32(0)),
            "an empty prefix list encodes as a trailing zero count"
        );
        // Legacy writers never emitted the appended field.
        let legacy = &full[..full.len() - 4];

        let decoded = PrincipalRecord::from_bytes(legacy).expect("legacy bytes must still decode");
        assert!(
            decoded.allowed_write_prefixes.is_empty(),
            "legacy records carry no write prefixes, got {:?}",
            decoded.allowed_write_prefixes
        );
        assert_eq!(decoded, expected, "every other field must be unchanged");
    }
}

// ---------------------------------------------------------------------------------------------
// 2. OIDC enforcement on PutChangeset
// ---------------------------------------------------------------------------------------------

#[test]
fn oidc_principal_with_write_prefixes_is_refused_outside_them() {
    let fx = OidcFixture::start();
    let erin = fx.client(ERIN_TOKEN);
    let admin = fx.client(ADMIN_TOKEN);

    let outside_cases: Vec<(&str, BonsaiChangeset)> = vec![
        (
            "src/main.rs",
            changeset(
                Vec::new(),
                &[("src/main.rs", Some("fn main() {}\n"))],
                "outside",
            ),
        ),
        (
            "mixed docs + src",
            changeset(
                Vec::new(),
                &[
                    ("docs/guide.md", Some("# guide\n")),
                    ("src/lib.rs", Some("pub fn f() {}\n")),
                ],
                "mixed",
            ),
        ),
        (
            "deletion outside prefix",
            changeset(Vec::new(), &[("src/old.rs", None)], "delete-outside"),
        ),
        (
            "sibling directory sharing a name prefix",
            changeset(
                Vec::new(),
                &[("docs-private/notes.md", Some("private\n"))],
                "sibling",
            ),
        ),
    ];

    for (label, cs) in &outside_cases {
        let resp = put_cs(&erin, cs);
        assert_error_contains(&resp, "write prefix violation", label);

        // A refused changeset must not be stored.
        match admin
            .call(&RpcRequest::GetChangeset {
                id: cs.changeset_id(),
            })
            .expect("GetChangeset transport")
        {
            RpcResponse::GetChangeset { changeset: None } => {}
            other => panic!("{label}: refused changeset must not be stored, got {other:?}"),
        }
    }

    fx.shutdown();
}

#[test]
fn oidc_principal_with_write_prefixes_may_write_inside_them() {
    let fx = OidcFixture::start();
    let erin = fx.client(ERIN_TOKEN);

    let inside = changeset(
        Vec::new(),
        &[("docs/guide.md", Some("# guide\n"))],
        "inside",
    );
    put_cs_ok(&erin, &inside, "docs/guide.md");

    let nested = changeset(
        Vec::new(),
        &[
            ("docs/reference/api.md", Some("# api\n")),
            ("docs/old.md", None),
        ],
        "nested",
    );
    put_cs_ok(&erin, &nested, "nested path and in-prefix deletion");

    fx.shutdown();
}

#[test]
fn oidc_principal_with_wildcard_prefix_is_unrestricted() {
    let fx = OidcFixture::start();
    let heidi = fx.client(HEIDI_TOKEN);

    let anywhere = changeset(
        Vec::new(),
        &[("src/main.rs", Some("fn main() {}\n"))],
        "heidi-anywhere",
    );
    put_cs_ok(&heidi, &anywhere, "wildcard principal writing src/main.rs");

    fx.shutdown();
}

// ---------------------------------------------------------------------------------------------
// 3. Moving refs onto changesets outside the principal's prefixes
// ---------------------------------------------------------------------------------------------

#[test]
fn oidc_principal_with_write_prefixes_cannot_move_a_ref_onto_outside_changesets() {
    let fx = OidcFixture::start();
    let erin = fx.client(ERIN_TOKEN);
    let admin = fx.client(ADMIN_TOKEN);

    // The admin is unrestricted and can store a changeset that touches `src/`.
    let outside = changeset(
        Vec::new(),
        &[("src/main.rs", Some("fn main() {}\n"))],
        "admin-outside",
    );
    let outside_id = put_cs_ok(&admin, &outside, "admin stores outside changeset");

    // Erin must not be able to publish it as `main`.
    let resp = cas_ref(&erin, None, outside_id);
    assert_error_contains(
        &resp,
        "changeset outside write prefixes",
        "create ref onto outside",
    );
    assert_eq!(
        get_ref(&admin),
        None,
        "refused CasRef must leave the ref unset"
    );

    // Control: a docs-only changeset is accepted as the ref target.
    let inside = changeset(
        Vec::new(),
        &[("docs/guide.md", Some("# guide\n"))],
        "erin-inside",
    );
    let inside_id = put_cs_ok(&erin, &inside, "erin stores inside changeset");
    assert_eq!(
        cas_ref(&erin, None, inside_id),
        RpcResponse::CasRefOk,
        "fast-forward onto an in-prefix changeset must be accepted"
    );
    assert_eq!(get_ref(&admin), Some(inside_id));

    // A fast-forward whose new range (inside..child] touches `src/` is refused as well.
    let child = changeset(
        vec![inside_id],
        &[("src/lib.rs", Some("pub fn f() {}\n"))],
        "admin-child-outside",
    );
    let child_id = put_cs_ok(&admin, &child, "admin stores outside child");
    let resp = cas_ref(&erin, Some(inside_id), child_id);
    assert_error_contains(
        &resp,
        "changeset outside write prefixes",
        "advance onto outside child",
    );
    assert_eq!(
        get_ref(&admin),
        Some(inside_id),
        "refused CasRef must leave the ref where it was"
    );

    fx.shutdown();
}

// ---------------------------------------------------------------------------------------------
// 4. `inr principal enroll --write-prefixes`
// ---------------------------------------------------------------------------------------------

struct CliFixture {
    server: HttpServerHandle,
    root: PathBuf,
    config_path: PathBuf,
    admin: RemoteRpcClient,
}

impl CliFixture {
    fn start(label: &str) -> Self {
        let engine = Arc::new(ScionEngine::new(
            Arc::new(MemBlobStore::new()),
            Arc::new(MemMetadataStore::new()),
        ));
        let server = spawn_http_server(engine, "127.0.0.1:0", Some(ADMIN_TOKEN.to_string()))
            .expect("spawn admin-token server");
        let base_url = server.base_url();

        let root = unique_temp_dir(label);
        let config_path = root.join("inarch-test.toml");
        fs::write(
            &config_path,
            format!("[network]\nremote_url = \"{base_url}\"\nauth_token = \"{ADMIN_TOKEN}\"\n"),
        )
        .expect("write test config");

        let admin = RemoteRpcClient::new(&base_url, Some(ADMIN_TOKEN.to_string()))
            .expect("build admin client");
        Self {
            server,
            root,
            config_path,
            admin,
        }
    }

    /// Runs `inr --config <file> <args...>` in the fixture directory.
    fn run_inr(&self, args: &[&str]) -> (Option<i32>, String, String) {
        run_inr_binary(&self.config_path, &self.root, args)
    }

    fn shutdown(self) {
        self.server.shutdown();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn run_inr_binary(config_path: &Path, cwd: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_inr"));
    cmd.arg("--config").arg(config_path);
    cmd.args(args);
    cmd.current_dir(cwd);
    for (key, _) in std::env::vars() {
        if key.starts_with("INARCH_") {
            cmd.env_remove(key);
        }
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn inr binary");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let out_thread = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        text
    });
    let err_thread = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });

    let deadline = Instant::now() + CLI_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("poll inr child") {
            Some(status) => break status,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("inr {args:?} did not exit within {CLI_TIMEOUT:?}");
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    };
    let stdout_text = out_thread.join().unwrap_or_default();
    let stderr_text = err_thread.join().unwrap_or_default();
    (status.code(), stdout_text, stderr_text)
}

#[test]
fn cli_principal_enroll_stores_write_prefixes() {
    let fx = CliFixture::start("enroll-prefixes");

    let (code, stdout, stderr) = fx.run_inr(&[
        "principal",
        "enroll",
        "frank@example.com",
        "--host",
        "h1",
        "--write-prefixes",
        "docs/,src/",
    ]);
    assert_eq!(
        code,
        Some(0),
        "principal enroll must succeed; stdout={stdout:?} stderr={stderr:?}"
    );

    let record = get_principal(&fx.admin, "frank@example.com");
    assert_eq!(record.allowed_write_prefixes, strs(&["docs/", "src/"]));
    assert_eq!(record.host_label, "h1");
    assert_eq!(record.status, "active");

    fx.shutdown();
}

#[test]
fn cli_principal_enroll_without_flag_defaults_to_unrestricted_wildcard() {
    let fx = CliFixture::start("enroll-default");

    let (code, stdout, stderr) =
        fx.run_inr(&["principal", "enroll", "grace@example.com", "--host", "h2"]);
    assert_eq!(
        code,
        Some(0),
        "principal enroll must succeed; stdout={stdout:?} stderr={stderr:?}"
    );

    let record = get_principal(&fx.admin, "grace@example.com");
    assert_eq!(
        record.allowed_write_prefixes,
        strs(&["*"]),
        "omitting --write-prefixes must store the unrestricted default"
    );

    fx.shutdown();
}
