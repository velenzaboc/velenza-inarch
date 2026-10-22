#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use inarch_engine::{PatchFileEdit, PatchSubmission, ScionEngine};
use inarch_store::{MemBlobStore, MemMetadataStore};
use inarch_types::{FileType, MPath};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

pub struct AuditTempDir {
    path: PathBuf,
}

impl AuditTempDir {
    pub fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "inarch_audit_{label}_{}_{}_{}",
            std::process::id(),
            nanos,
            NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("create isolated audit temp directory");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for AuditTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub fn make_webdav_engine() -> Arc<ScionEngine> {
    let engine = Arc::new(ScionEngine::new(
        Arc::new(MemBlobStore::new()),
        Arc::new(MemMetadataStore::new()),
    ));
    engine
        .land_patch(PatchSubmission {
            target_ref: "refs/heads/main".to_string(),
            base_changeset: None,
            author: "audit@example.invalid".to_string(),
            timestamp: 1_760_000_000,
            tz_offset_secs: 0,
            message: "audit fixture".to_string(),
            extra: BTreeMap::new(),
            edits: vec![PatchFileEdit::Upsert {
                path: MPath::new("README.md").expect("portable fixture path"),
                content: b"audit fixture\n".to_vec(),
                file_type: FileType::Regular,
            }],
        })
        .expect("seed WebDAV audit fixture");
    engine
}

pub fn send_raw_http(addr: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).expect("connect to loopback WebDAV server");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set WebDAV read timeout");
    stream.write_all(request).expect("write WebDAV request");
    stream
        .shutdown(Shutdown::Write)
        .expect("finish WebDAV request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read WebDAV response");
    response
}

pub fn response_status(response: &[u8]) -> u16 {
    String::from_utf8_lossy(response)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .unwrap_or(0)
}

pub fn response_header(response: &[u8], wanted: &str) -> Option<String> {
    let text = String::from_utf8_lossy(response);
    for line in text.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case(wanted) {
            return Some(value.trim().to_string());
        }
    }
    None
}

fn run_child_command(test_name: &str, command: &mut Command, timeout: Duration) {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn isolated audit child");
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll isolated audit child") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().expect("reap timed-out audit child");
            panic!(
                "isolated audit child {test_name} timed out\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = child.wait_with_output().expect("collect isolated audit child");
    assert!(
        status.success(),
        "isolated audit child {test_name} failed with {status}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn run_child_test(test_name: &str, envs: &[(&str, &str)], timeout: Duration) {
    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    command.arg("--exact").arg(test_name).arg("--nocapture");
    for (key, value) in envs {
        command.env(key, value);
    }
    run_child_command(test_name, &mut command, timeout);
}

#[cfg(target_os = "linux")]
pub fn run_child_test_with_memory_limit(
    test_name: &str,
    envs: &[(&str, &str)],
    timeout: Duration,
    memory_kib: u64,
) {
    let executable = std::env::current_exe().expect("current test executable");
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("set -eu; ulimit -v \"$1\"; shift; exec \"$@\"")
        .arg("inarch-audit-child")
        .arg(memory_kib.to_string())
        .arg(executable)
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture");
    for (key, value) in envs {
        command.env(key, value);
    }
    run_child_command(test_name, &mut command, timeout);
}

#[cfg(unix)]
pub fn write_executable(path: &Path, contents: &str) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(path, contents).expect("write mock executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("make mock executable owner-only");
}
