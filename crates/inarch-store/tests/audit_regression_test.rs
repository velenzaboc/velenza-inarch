//! Regression contracts for the storage defects found by the 2026-10-22 audit.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use inarch_store::{
    FsMetadataStore, MetadataStore, RemoteMetadataStore, RpcRequest, RpcResponse, StoreError,
};
use inarch_types::bonsai::{BonsaiChangeset, FileChange, FileType};
use inarch_types::hash::{BlobId, ChangesetId};
use inarch_types::path::MPath;

const CAS_CHILD_MARKER: &str = "INARCH_AUDIT_FS_CAS_CHILD";
const CAS_ROOT_ENV: &str = "INARCH_AUDIT_FS_CAS_ROOT";
const CAS_EXPECTED_ENV: &str = "INARCH_AUDIT_FS_CAS_EXPECTED";
const CAS_TARGET_ENV: &str = "INARCH_AUDIT_FS_CAS_TARGET";
const CAS_INDEX_ENV: &str = "INARCH_AUDIT_FS_CAS_INDEX";

struct ScratchDir(std::path::PathBuf);

impl std::ops::Deref for ScratchDir {
    type Target = std::path::Path;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl Drop for ScratchDir {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

fn unique_temp_dir(label: &str) -> ScratchDir {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "inarch-audit-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create audit temp directory");
    ScratchDir(dir)
}

fn changeset(parent: Option<ChangesetId>, label: &str, timestamp: i64) -> BonsaiChangeset {
    let content = format!("{label}\n");
    BonsaiChangeset::new(
        parent.into_iter().collect(),
        format!("{label}@inarch.dev"),
        timestamp,
        0,
        label.to_string(),
        BTreeMap::new(),
        BTreeMap::from([(
            MPath::new("state.txt").expect("valid path"),
            FileChange::Tracked {
                blob_id: BlobId::from_content(content.as_bytes()),
                size: content.len() as u64,
                file_type: FileType::Regular,
            },
        )]),
    )
    .expect("valid changeset")
}

#[test]
fn fs_cas_child_process() {
    if std::env::var_os(CAS_CHILD_MARKER).is_none() {
        return;
    }

    let root = std::path::PathBuf::from(std::env::var(CAS_ROOT_ENV).expect("CAS root"));
    let expected = ChangesetId::from_hex(&std::env::var(CAS_EXPECTED_ENV).expect("expected id"))
        .expect("parse expected id");
    let target = ChangesetId::from_hex(&std::env::var(CAS_TARGET_ENV).expect("target id"))
        .expect("parse target id");
    let index = std::env::var(CAS_INDEX_ENV).expect("child index");

    std::fs::write(root.join(format!("ready-{index}")), b"ready").expect("write ready marker");
    let deadline = Instant::now() + Duration::from_secs(15);
    while !root.join("go").exists() {
        assert!(Instant::now() < deadline, "timed out waiting for CAS barrier");
        std::thread::sleep(Duration::from_millis(2));
    }

    let store = FsMetadataStore::new(root.join("meta")).expect("open child store");
    let result = store.cas_ref("main", Some(expected), target);
    let result_text = match result {
        Ok(()) => "ok".to_string(),
        Err(StoreError::CasMismatch { .. }) => "conflict".to_string(),
        Err(other) => format!("error:{other:?}"),
    };
    std::fs::write(root.join(format!("result-{index}")), result_text)
        .expect("write CAS result");
}

#[test]
fn independent_process_filesystem_cas_has_exactly_one_winner() {
    let root = unique_temp_dir("fs-cas");
    let meta_root = root.join("meta");
    let store = FsMetadataStore::new(&meta_root).expect("create filesystem metadata store");

    let seed = changeset(None, "seed", 1_760_000_000);
    let seed_id = store.put_changeset(&seed).expect("store seed");
    let candidate = changeset(Some(seed_id), "candidate", 1_760_000_001);
    let candidate_id = store.put_changeset(&candidate).expect("store candidate");
    store
        .cas_ref("main", None, seed_id)
        .expect("initialize main");

    let executable = std::env::current_exe().expect("current test executable");
    let process_count = 32usize;
    let mut children: Vec<Child> = Vec::with_capacity(process_count);
    for index in 0..process_count {
        let child = Command::new(&executable)
            .args(["--exact", "fs_cas_child_process", "--nocapture"])
            .env(CAS_CHILD_MARKER, "1")
            .env(CAS_ROOT_ENV, root.as_os_str())
            .env(CAS_EXPECTED_ENV, seed_id.to_hex())
            .env(CAS_TARGET_ENV, candidate_id.to_hex())
            .env(CAS_INDEX_ENV, index.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn independent CAS process");
        children.push(child);
    }

    let ready_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let ready = (0..process_count)
            .filter(|index| root.join(format!("ready-{index}")).exists())
            .count();
        if ready == process_count {
            break;
        }
        if Instant::now() >= ready_deadline {
            let _ = std::fs::write(root.join("go"), b"go");
            for child in &mut children {
                let _ = child.kill();
                let _ = child.wait();
            }
            panic!("only {ready}/{process_count} CAS children reached the barrier");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    std::fs::write(root.join("go"), b"go").expect("release CAS barrier");

    for child in children {
        let output = child.wait_with_output().expect("wait for CAS child");
        assert!(
            output.status.success(),
            "CAS child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let results: Vec<String> = (0..process_count)
        .map(|index| {
            std::fs::read_to_string(root.join(format!("result-{index}")))
                .expect("read child CAS result")
        })
        .collect();
    let winners = results.iter().filter(|result| result.as_str() == "ok").count();
    assert_eq!(
        winners, 1,
        "one expected value permits exactly one cross-process winner; results={results:?}"
    );
    assert!(
        results
            .iter()
            .all(|result| result == "ok" || result == "conflict"),
        "CAS children must return only success or an expected-value conflict: {results:?}"
    );
    assert_eq!(store.get_ref("main").expect("read final ref"), Some(candidate_id));

}

fn accept_before(listener: &TcpListener, deadline: Instant) -> Option<TcpStream> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("make accepted audit RPC stream blocking");
                return Some(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("accept audit RPC connection: {error}"),
        }
    }
}

fn read_rpc_request(stream: &TcpStream) -> RpcRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set audit RPC read timeout");
    let mut reader = BufReader::new(stream.try_clone().expect("clone audit RPC stream"));
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .expect("read audit RPC request line");
    assert!(
        request_line.starts_with("POST /v1/rpc "),
        "unexpected audit RPC request line: {request_line:?}"
    );
    let mut content_length = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).expect("read audit RPC header");
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .expect("numeric audit RPC content length"),
            );
        }
    }
    let mut body = vec![0u8; content_length.expect("audit RPC content length")];
    reader
        .read_exact(&mut body)
        .expect("read complete audit RPC body");
    RpcRequest::decode(&body).expect("decode audit RPC request")
}

fn write_rpc_response(stream: &mut TcpStream, response: RpcResponse) {
    let body = response.encode();
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-velenza-inarch-rpc\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .expect("write audit RPC response header");
    stream
        .write_all(&body)
        .expect("write audit RPC response body");
    stream.flush().expect("flush audit RPC response");
}

#[test]
fn remote_cas_lost_response_is_ambiguous_and_never_replayed_after_an_intervening_writer() {
    let h0 = changeset(None, "rpc-h0", 1_760_010_000).changeset_id();
    let target_a = changeset(Some(h0), "rpc-a", 1_760_010_001).changeset_id();
    let target_b = changeset(Some(target_a), "rpc-b", 1_760_010_002).changeset_id();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind audit RPC listener");
    listener
        .set_nonblocking(true)
        .expect("make audit RPC listener nonblocking");
    let address = listener.local_addr().expect("audit RPC listener address");
    let server = std::thread::spawn(move || {
        let mut requests = Vec::new();
        let first_deadline = Instant::now() + Duration::from_secs(2);
        let first = accept_before(&listener, first_deadline).expect("first CAS transport request");
        requests.push(read_rpc_request(&first));

        // The server committed H0 -> A, then an independent writer committed A -> B.
        // Closing without A's response makes the first result unknowable to the client.
        drop(first);

        // A correct client returns an explicit ambiguous result. The old client reconnects and
        // blindly sends H0 -> A again, so answer that replay with the now-visible B conflict.
        let replay_deadline = Instant::now() + Duration::from_millis(750);
        if let Some(mut replay) = accept_before(&listener, replay_deadline) {
            requests.push(read_rpc_request(&replay));
            write_rpc_response(
                &mut replay,
                RpcResponse::CasRefConflict {
                    ref_name: "main".to_string(),
                    expected: Some(h0),
                    actual: Some(target_b),
                },
            );
        }
        requests
    });

    let remote = RemoteMetadataStore::new(&format!("http://{address}"), None, "audit-repo")
        .expect("construct actual transport metadata client");
    let result = remote.cas_ref("main", Some(h0), target_a);
    let requests = server.join().expect("audit RPC server thread");

    assert_eq!(
        requests.len(),
        1,
        "a response-lost CAS is not safe to replay after another writer may have advanced the ref: {requests:?}"
    );
    assert_eq!(
        requests[0],
        RpcRequest::CasRef {
            repo_id: "audit-repo".to_string(),
            ref_name: "main".to_string(),
            expected: Some(h0),
            new_target: target_a,
        }
    );
    match result {
        Err(StoreError::Io(message)) => assert!(
            message.to_ascii_lowercase().contains("ambiguous"),
            "the caller must be told that the CAS outcome is ambiguous: {message}"
        ),
        other => panic!("lost CAS response must be an explicit ambiguous error: {other:?}"),
    }
}
