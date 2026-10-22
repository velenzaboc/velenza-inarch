mod common;

use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use common::{
    AuditTempDir, make_webdav_engine, response_header, response_status, run_child_test,
    send_raw_http,
};
use inarch_cli::{InarchConfig, spawn_webdav_virtual_mount};
use inarch_store::{BlobStore, GcsBlobStore, MemBlobStore, RemoteRpcClient};
use inarch_types::{BlobId, MPath, MPathElement, ObjectDomain, ObjectHash};

#[test]
fn audit_i1_https_remote_is_rejected_before_use() {
    let err = match RemoteRpcClient::new(
        "https://127.0.0.1:9",
        Some("synthetic-bearer-must-never-be-sent".to_string()),
    ) {
        Ok(_) => panic!("unsupported HTTPS must be rejected instead of downgraded to plaintext"),
        Err(err) => err,
    };
    let message = err.to_string().to_ascii_lowercase();
    assert!(
        message.contains("https") && (message.contains("unsupported") || message.contains("tls")),
        "HTTPS refusal must explain the unsupported secure transport: {err}"
    );

    assert!(
        RemoteRpcClient::new("http://127.0.0.1:9", None).is_ok(),
        "the supported explicit HTTP form must remain valid"
    );
}

#[test]
fn audit_i3_repository_paths_reject_windows_structure_on_every_host() {
    for invalid in [
        r"..\outside",
        r"dir\..\outside",
        r"\rooted",
        r"\\server\share",
        r"C:\outside",
        "C:",
    ] {
        assert!(
            MPathElement::new(invalid).is_err(),
            "MPathElement accepted Windows-structural component {invalid:?}"
        );
        assert!(
            MPath::new(invalid).is_err(),
            "MPath accepted Windows-structural path {invalid:?}"
        );
    }

    for valid in ["main.go", "c-data", "space name", "résumé.txt"] {
        let element = MPathElement::new(valid).expect("portable element must remain valid");
        assert_eq!(element.as_str(), valid);
    }
    assert_eq!(
        MPath::new("src/windows_compat/main.rs")
            .expect("portable slash-separated path")
            .as_str(),
        "src/windows_compat/main.rs"
    );
}

#[derive(Default)]
struct RawBlobStore {
    objects: Mutex<BTreeMap<(ObjectDomain, ObjectHash), Vec<u8>>>,
}

impl RawBlobStore {
    fn insert_raw(&self, domain: ObjectDomain, hash: ObjectHash, bytes: Vec<u8>) {
        self.objects
            .lock()
            .expect("raw blob fixture lock")
            .insert((domain, hash), bytes);
    }
}

impl BlobStore for RawBlobStore {
    fn put_object(
        &self,
        domain: ObjectDomain,
        hash: ObjectHash,
        data: &[u8],
    ) -> Result<(), inarch_store::StoreError> {
        self.insert_raw(domain, hash, data.to_vec());
        Ok(())
    }

    fn get_object(
        &self,
        domain: ObjectDomain,
        hash: &ObjectHash,
    ) -> Result<Option<Vec<u8>>, inarch_store::StoreError> {
        Ok(self
            .objects
            .lock()
            .expect("raw blob fixture lock")
            .get(&(domain, *hash))
            .cloned())
    }
}

fn audit_chunk_manifest(blob: BlobId, total_size: u64, chunks: &[ObjectHash]) -> Vec<u8> {
    let mut manifest = Vec::with_capacity(52 + chunks.len() * 32);
    manifest.extend_from_slice(b"INRCBLK1");
    manifest.extend_from_slice(blob.as_bytes());
    manifest.extend_from_slice(&total_size.to_le_bytes());
    manifest.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
    for chunk in chunks {
        manifest.extend_from_slice(chunk.as_bytes());
    }
    manifest
}

#[test]
fn audit_i4_batch_get_rejects_malformed_zero_chunk_and_size_mismatch_manifests() {
    let malformed_store = RawBlobStore::default();
    let malformed_id = BlobId::from_content(b"malformed logical content");
    malformed_store.insert_raw(
        ObjectDomain::Blob,
        malformed_id.0,
        b"INRCBLK1truncated".to_vec(),
    );
    assert!(
        malformed_store.get_blobs_batch(&[malformed_id]).is_err(),
        "malformed chunk manifest crossed the batch retrieval boundary"
    );

    let zero_store = RawBlobStore::default();
    let zero_id = BlobId::from_content(b"nonempty logical content");
    let zero_manifest = audit_chunk_manifest(zero_id, 0, &[]);
    zero_store.insert_raw(ObjectDomain::Blob, zero_id.0, zero_manifest);
    assert!(
        zero_store.get_blobs_batch(&[zero_id]).is_err(),
        "zero-chunk manifest was returned as if it were file content"
    );

    let size_store = RawBlobStore::default();
    let content = b"complete logical bytes";
    let size_id = BlobId::from_content(content);
    let chunk_hash = ObjectHash::from_domain(ObjectDomain::Chunk, content);
    size_store.insert_raw(ObjectDomain::Chunk, chunk_hash, content.to_vec());
    let wrong_size_manifest = audit_chunk_manifest(size_id, content.len() as u64 + 1, &[chunk_hash]);
    size_store.insert_raw(ObjectDomain::Blob, size_id.0, wrong_size_manifest);
    assert!(
        size_store.get_blobs_batch(&[size_id]).is_err(),
        "manifest total_size was not checked against reconstructed content"
    );

    let positive = MemBlobStore::new();
    let positive_content = b"ordinary verified blob";
    let positive_id = positive
        .put_blob_content(positive_content)
        .expect("store ordinary blob");
    assert_eq!(
        positive
            .get_blobs_batch(&[positive_id])
            .expect("retrieve ordinary blob"),
        vec![Some(positive_content.to_vec())]
    );
}

#[test]
fn audit_i4_untrusted_claimed_size_is_rejected_in_bounded_child() {
    run_child_test(
        "audit_i4_claimed_size_child",
        &[("INARCH_AUDIT_CHILD_CASE", "claimed-size")],
        Duration::from_secs(3),
    );
}

#[test]
fn audit_i4_claimed_size_child() {
    if std::env::var("INARCH_AUDIT_CHILD_CASE")
        .ok()
        .as_deref()
        != Some("claimed-size")
    {
        return;
    }
    let store = RawBlobStore::default();
    let content = b"small verified chunk";
    let blob = BlobId::from_content(content);
    let chunk_hash = ObjectHash::from_domain(ObjectDomain::Chunk, content);
    store.insert_raw(ObjectDomain::Chunk, chunk_hash, content.to_vec());
    let manifest = audit_chunk_manifest(blob, u64::MAX, &[chunk_hash]);
    store.insert_raw(ObjectDomain::Blob, blob.0, manifest);
    assert!(
        store.get_blobs_batch(&[blob]).is_err(),
        "untrusted total_size must be rejected before any capacity reservation"
    );
}

#[test]
fn audit_i5_nonempty_required_reviewers_fail_closed_before_policy_use() {
    let unsupported = InarchConfig::from_toml_str(
        r#"
[[acl_rules]]
prefix = "protected"
allowed_actors = ["author@example.invalid"]
required_reviewers = ["reviewer@example.invalid"]
"#,
    );
    let refusal = match unsupported {
        Err(err) => err.to_string(),
        Ok(config) => match config.build_acl_policy() {
            Ok(_) => panic!(
                "unsupported reviewer policy parsed and built as if it were enforceable"
            ),
            Err(err) => err.to_string(),
        },
    };
    let message = refusal.to_ascii_lowercase();
    assert!(
        message.contains("required_reviewers")
            && (message.contains("unsupported") || message.contains("not implemented")),
        "refusal must identify the unsupported reviewer policy: {refusal}"
    );

    let supported = InarchConfig::from_toml_str(
        r#"
[[acl_rules]]
prefix = "protected"
allowed_actors = ["author@example.invalid"]
required_reviewers = []
"#,
    )
    .expect("empty reviewer policy remains supported");
    supported
        .build_acl_policy()
        .expect("supported actor-only ACL still builds");
}

#[cfg(unix)]
fn audit_mock_path(bin_dir: &Path) -> String {
    let inherited = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
    format!("{}:{inherited}", bin_dir.display())
}

#[cfg(unix)]
#[test]
fn audit_i6_cloud_temp_files_are_private_exclusive_and_cleaned() {
    use common::write_executable;

    let temp = AuditTempDir::new("cloud_parent");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("create mock executable directory");
    write_executable(
        &bin_dir.join("openssl"),
        r#"#!/bin/sh
key=""
for arg in "$@"; do key="$arg"; done
mode=$(stat -f %Lp "$key" 2>/dev/null || stat -c %a "$key")
printf '%s\n%s\n' "$key" "$mode" > "$AUDIT_RECORD"
cat >/dev/null
printf 'synthetic-signature'
"#,
    );
    write_executable(
        &bin_dir.join("curl"),
        r#"#!/bin/sh
if [ "$AUDIT_CURL_MODE" = "token" ]; then
  cat >/dev/null
  printf '{"id_token":"synthetic-audit-token"}'
  exit 0
fi
body_path=""
while IFS= read -r line; do
  case "$line" in
    data-binary*) body_path=${line#*@}; body_path=${body_path%\"} ;;
  esac
done
if [ -z "$body_path" ]; then exit 9; fi
mode=$(stat -f %Lp "$body_path" 2>/dev/null || stat -c %a "$body_path")
printf '%s\n%s\n' "$body_path" "$mode" > "$AUDIT_RECORD"
cat "$body_path" > "$AUDIT_RECORD.body"
printf '\n__HTTP_STATUS__:200'
"#,
    );
    let child_root = temp.path().join("child");
    fs::create_dir(&child_root).expect("create child fixture directory");
    let credentials = child_root.join("credentials.json");
    fs::write(
        &credentials,
        r#"{"client_email":"audit@example.invalid","private_key":"synthetic-private-key","token_uri":"https://oauth.invalid/token"}"#,
    )
    .expect("write synthetic credentials");

    let root = child_root.to_string_lossy().into_owned();
    let temp_dir = child_root.to_string_lossy().into_owned();
    let path = audit_mock_path(&bin_dir);
    let credentials = credentials.to_string_lossy().into_owned();
    let empty_bin = child_root.join("empty-bin");
    fs::create_dir(&empty_bin).expect("create empty executable directory");
    let empty_path = empty_bin.to_string_lossy().into_owned();
    for case in [
        "key-secure",
        "key-symlink",
        "body-secure",
        "body-symlink",
        "body-spawn-failure",
    ] {
        let record = child_root.join(format!("{case}.record"));
        let record = record.to_string_lossy().into_owned();
        let curl_mode = if case.starts_with("key-") {
            "token"
        } else {
            "gcs"
        };
        let child_path = if case == "body-spawn-failure" {
            &empty_path
        } else {
            &path
        };
        run_child_test(
            "audit_i6_cloud_temp_child",
            &[
                ("INARCH_AUDIT_CHILD_CASE", case),
                ("AUDIT_ROOT", &root),
                ("AUDIT_RECORD", &record),
                ("AUDIT_CREDENTIALS", &credentials),
                ("AUDIT_CURL_MODE", curl_mode),
                ("TMPDIR", &temp_dir),
                ("INARCH_GCP_ACCESS_TOKEN", "synthetic-access-token"),
                ("PATH", child_path),
            ],
            Duration::from_secs(5),
        );
    }
}

#[cfg(unix)]
#[test]
fn audit_i6_cloud_temp_child() {
    use std::os::unix::fs::symlink;

    let Ok(case) = std::env::var("INARCH_AUDIT_CHILD_CASE") else {
        return;
    };
    if !matches!(
        case.as_str(),
        "key-secure"
            | "key-symlink"
            | "body-secure"
            | "body-symlink"
            | "body-spawn-failure"
    ) {
        return;
    }
    let root = std::path::PathBuf::from(std::env::var("AUDIT_ROOT").expect("AUDIT_ROOT"));
    let record = std::path::PathBuf::from(std::env::var("AUDIT_RECORD").expect("AUDIT_RECORD"));
    let credentials =
        std::path::PathBuf::from(std::env::var("AUDIT_CREDENTIALS").expect("AUDIT_CREDENTIALS"));

    if case == "body-spawn-failure" {
        let staged = root.join(format!("inarch_req_{}_1.tmp", std::process::id()));
        let body = b"synthetic gcs request body";
        let result =
            GcsBlobStore::with_endpoint("audit-bucket", "audit-prefix", "http://gcs.invalid")
                .and_then(|store| {
                    store.put_object(
                        ObjectDomain::Blob,
                        ObjectHash::from_domain(ObjectDomain::Blob, body),
                        body,
                    )
                });
        assert!(result.is_err(), "missing curl must fail the synthetic upload");
        assert!(
            !staged.exists(),
            "request body staging file survived curl spawn failure"
        );
        return;
    }

    if case == "key-symlink" || case == "body-symlink" {
        let canary = root.join(format!("{case}.canary"));
        fs::write(&canary, b"canary-must-remain").expect("write collision canary");
        let staged = if case == "key-symlink" {
            root.join(format!("inarch_sakey_{}_1.pem", std::process::id()))
        } else {
            root.join(format!("inarch_req_{}_1.tmp", std::process::id()))
        };
        symlink(&canary, &staged).expect("precreate hostile staging symlink");
        let result = if case == "key-symlink" {
            inarch_store::mint_service_account_id_token(
                &credentials,
                Some("https://oauth.invalid/token"),
                "audit-exclusive-key",
            )
            .map(|_| ())
        } else {
            let body = b"synthetic gcs request body";
            GcsBlobStore::with_endpoint("audit-bucket", "audit-prefix", "http://gcs.invalid")
                .and_then(|store| {
                    store.put_object(
                        ObjectDomain::Blob,
                        ObjectHash::from_domain(ObjectDomain::Blob, body),
                        body,
                    )
                })
        };
        assert!(
            result.is_err(),
            "pre-existing staging path must be refused for {case}"
        );
        assert_eq!(
            fs::read(&canary).expect("read collision canary"),
            b"canary-must-remain",
            "staging followed a hostile symlink for {case}"
        );
        return;
    }

    if case == "key-secure" {
        let token = inarch_store::mint_service_account_id_token(
            &credentials,
            Some("https://oauth.invalid/token"),
            "audit-private-key",
        )
        .expect("synthetic token mint");
        assert_eq!(token, "synthetic-audit-token");
    } else {
        let body = b"synthetic gcs request body";
        let store = GcsBlobStore::with_endpoint(
            "audit-bucket",
            "audit-prefix",
            "http://gcs.invalid",
        )
        .expect("synthetic GCS store");
        store
            .put_object(
                ObjectDomain::Blob,
                ObjectHash::from_domain(ObjectDomain::Blob, body),
                body,
            )
            .expect("synthetic GCS upload");
        assert_eq!(
            fs::read(record.with_extension("record.body")).expect("record staged body"),
            body
        );
    }

    let observation = fs::read_to_string(&record).expect("mock staging observation");
    let mut lines = observation.lines();
    let staged_path = lines.next().expect("recorded staged path");
    let mode = lines.next().expect("recorded staged mode");
    assert_eq!(mode, "600", "staged {case} file was not owner-only");
    assert!(
        !Path::new(staged_path).exists(),
        "staged {case} file was not removed after command completion"
    );
}

fn assert_incomplete_webdav_input_is_bounded(addr: std::net::SocketAddr, bytes: &[u8]) {
    let mut stream = TcpStream::connect(addr).expect("connect incomplete WebDAV request");
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set incomplete-request deadline");
    let _ = stream.write_all(bytes);
    let mut one = [0u8; 1];
    match stream.read(&mut one) {
        Ok(_) => {}
        Err(err) if matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
            panic!("WebDAV parser did not bound incomplete pre-auth input before the deadline")
        }
        Err(_) => {}
    }
}

#[test]
fn audit_i11_webdav_bounds_incomplete_request_line_and_header_before_auth() {
    let engine = make_webdav_engine();
    let handle = spawn_webdav_virtual_mount(engine, "refs/heads/main".to_string(), "127.0.0.1:0")
        .expect("spawn loopback WebDAV fixture");
    let addr = handle.local_addr;

    assert_incomplete_webdav_input_is_bounded(addr, &vec![b'G'; 128 * 1024]);
    let mut header = b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Audit: ".to_vec();
    header.extend(std::iter::repeat_n(b'h', 128 * 1024));
    assert_incomplete_webdav_input_is_bounded(addr, &header);

    let positive = send_raw_http(
        addr,
        b"GET /README.md HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(
        response_status(&positive),
        401,
        "ordinary bounded unauthenticated request must still reach authentication"
    );
    handle.shutdown();
}

fn audit_webdav_request(
    addr: std::net::SocketAddr,
    token: &str,
    method: &str,
    path: &str,
    extra_headers: &str,
) -> Vec<u8> {
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n{extra_headers}Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    send_raw_http(addr, request.as_bytes())
}

#[test]
fn audit_i12_unlock_requires_exact_token_and_refusal_preserves_lock() {
    let engine = make_webdav_engine();
    let handle = spawn_webdav_virtual_mount(engine, "refs/heads/main".to_string(), "127.0.0.1:0")
        .expect("spawn loopback WebDAV fixture");
    let addr = handle.local_addr;
    let auth = handle.auth_token.clone();

    let lock = audit_webdav_request(addr, &auth, "LOCK", "/README.md", "");
    assert_eq!(response_status(&lock), 200, "initial LOCK must succeed");
    let lock_token = response_header(&lock, "Lock-Token").expect("LOCK response token");

    let missing = audit_webdav_request(addr, &auth, "UNLOCK", "/README.md", "");
    assert!(
        response_status(&missing) >= 400,
        "UNLOCK without Lock-Token must be refused"
    );
    let conflict_after_missing = audit_webdav_request(addr, &auth, "LOCK", "/README.md", "");
    assert_eq!(
        response_status(&conflict_after_missing),
        423,
        "missing-token refusal must preserve the active lock"
    );

    let wrong = audit_webdav_request(
        addr,
        &auth,
        "UNLOCK",
        "/README.md",
        "Lock-Token: <opaquelocktoken:wrong>\r\n",
    );
    assert!(
        response_status(&wrong) >= 400,
        "UNLOCK with the wrong token must be refused"
    );
    let conflict_after_wrong = audit_webdav_request(addr, &auth, "LOCK", "/README.md", "");
    assert_eq!(
        response_status(&conflict_after_wrong),
        423,
        "wrong-token refusal must preserve the active lock"
    );

    let exact = audit_webdav_request(
        addr,
        &auth,
        "UNLOCK",
        "/README.md",
        &format!("Lock-Token: {lock_token}\r\n"),
    );
    assert_eq!(
        response_status(&exact),
        204,
        "UNLOCK with the exact active token must succeed"
    );
    let relock = audit_webdav_request(addr, &auth, "LOCK", "/README.md", "");
    assert_eq!(
        response_status(&relock),
        200,
        "resource must be lockable again after exact-token UNLOCK"
    );
    handle.shutdown();
}
