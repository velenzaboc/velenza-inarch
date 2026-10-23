//! Contract tests for the post-quantum-only transport profile: the L1 listener, the admitted
//! client profile, the L2 partner ingress boundary, the Postgres and Google carriers, and keyless
//! workstation and agent enrollment.
//!
//! Every peer in this file runs in-process on loopback. No test reaches a live TLS endpoint,
//! Postgres server, Cloud KMS, GCS or Spanner, no test reads a real credential, and no fixture
//! carries key material. Steps that need a packaged or deployed build live in
//! `tests/fixtures/transport/test_code_steps.toml`; dated launch-stage readings live in
//! `tests/fixtures/transport/launch_stages.toml`.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use common::{AuditTempDir, run_child_test};
use inarch_cli::CliError;
use inarch_cli::config::InarchConfig;
use inarch_cli::transport::{
    CredentialSource, Dialer, EnrollmentCredentialSource, KeyExchangeGroup, L1Listener,
    NegotiatedTransport, PostgresCarrier, PostgresCarrierConfig, PostgresRefusal,
    PostgresSslPolicy, ServerIdentity, TlsProtocol, TransportEnv, TransportError,
    TransportProfile,
};
use rustls::crypto::{CryptoProvider, SupportedKxGroup, aws_lc_rs};
use rustls::pki_types::ServerName;
use rustls::{
    ClientConfig, ClientConnection, NamedGroup, RootCertStore, ServerConfig, ServerConnection,
};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const RESULT_TIMEOUT: Duration = Duration::from_secs(20);
const CHILD_TIMEOUT: Duration = Duration::from_secs(60);
const CHILD_MARKER: &str = "INARCH_PQ_TRANSPORT_CHILD";
const CREDENTIAL_MARKER: &[u8] = b"pq-transport-contract-credential-marker";
const SERVER_NAME: &str = "localhost";
const APPLICATION_CREDENTIALS: &str = "GOOGLE_APPLICATION_CREDENTIALS";
const GOOGLE_STS_TOKEN_URL: &str = "https://sts.googleapis.com/v1/token";
const DIRECT_PATH_SWITCHES: [&str; 3] = [
    "GOOGLE_CLOUD_ENABLE_DIRECT_PATH",
    "GOOGLE_CLOUD_ENABLE_DIRECT_PATH_XDS",
    "GOOGLE_SPANNER_ENABLE_DIRECT_ACCESS",
];

// ---------------------------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------------------------

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("transport")
        .join(name)
}

fn key_shaped_fixture() -> PathBuf {
    fixture_path("key_shaped_no_secret.json")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

fn set_timeouts(stream: &TcpStream) {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .expect("set the socket read timeout");
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .expect("set the socket write timeout");
}

fn connect_loopback(addr: SocketAddr) -> TcpStream {
    let stream =
        TcpStream::connect_timeout(&addr, IO_TIMEOUT).expect("connect to the loopback peer");
    set_timeouts(&stream);
    stream
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn expect_ok<T>(result: Result<T, TransportError>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: unexpected refusal {error:?}"),
    }
}

fn expect_refusal<T>(result: Result<T, TransportError>, context: &str) -> TransportError {
    match result {
        Ok(_) => panic!("{context}: expected a refusal, but the operation succeeded"),
        Err(error) => error,
    }
}

/// Proves that nothing connected to `listener`: a connect() made before this call has already
/// completed its loopback handshake and would be waiting in the accept queue.
fn assert_no_connection_reached(listener: &TcpListener, context: &str) {
    listener
        .set_nonblocking(true)
        .expect("make the probe listener non-blocking");
    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        Ok((_, peer)) => panic!("{context}: a network connection from {peer} reached the listener"),
        Err(error) => panic!("{context}: the probe listener failed: {error}"),
    }
}

fn ephemeral_identity() -> ServerIdentity {
    expect_ok(
        ServerIdentity::ephemeral_self_signed(&[SERVER_NAME]),
        "create an ephemeral server identity",
    )
}

fn roots_for(identity: &ServerIdentity) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for certificate in identity.cert_chain_der() {
        roots
            .add(certificate)
            .expect("trust the ephemeral server certificate");
    }
    roots
}

fn provider_with(groups: &[&'static dyn SupportedKxGroup]) -> CryptoProvider {
    CryptoProvider {
        kx_groups: groups.to_vec(),
        ..aws_lc_rs::default_provider()
    }
}

/// Drives a raw TLS 1.3 client built from `provider` to the end of its handshake and returns the
/// group the client observed, or the handshake error.
fn raw_tls13_client(
    addr: SocketAddr,
    roots: &RootCertStore,
    provider: CryptoProvider,
) -> Result<Option<NamedGroup>, String> {
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 client configuration")
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    let server_name = ServerName::try_from(SERVER_NAME).expect("loopback server name");
    let mut connection =
        ClientConnection::new(Arc::new(config), server_name).expect("raw client connection");
    let mut socket = connect_loopback(addr);
    while connection.is_handshaking() {
        connection
            .complete_io(&mut socket)
            .map_err(|error| error.to_string())?;
    }
    Ok(connection
        .negotiated_key_exchange_group()
        .map(|group| group.name()))
}

type ServerOutcome = Result<(KeyExchangeGroup, TlsProtocol), String>;

/// An in-process L1 listener that accepts `connections` connections, reports each handshake
/// outcome, and keeps accepted sessions open until `finish`.
struct L1Harness {
    addr: SocketAddr,
    roots: RootCertStore,
    outcomes: mpsc::Receiver<ServerOutcome>,
    release: mpsc::Sender<()>,
}

impl L1Harness {
    fn start(connections: usize) -> Self {
        let identity = ephemeral_identity();
        let roots = roots_for(&identity);
        let listener = expect_ok(
            L1Listener::bind(&TransportProfile::l1(), loopback(), identity),
            "bind the L1 listener",
        );
        let addr = listener.local_addr();
        let (outcome_tx, outcomes) = mpsc::channel();
        let (release, release_rx) = mpsc::channel::<()>();
        thread::spawn(move || {
            let mut sessions = Vec::new();
            for _ in 0..connections {
                match listener.accept() {
                    Ok(session) => {
                        let _ = outcome_tx.send(Ok((
                            session.negotiated_group(),
                            session.negotiated_protocol(),
                        )));
                        sessions.push(session);
                    }
                    Err(error) => {
                        let _ = outcome_tx.send(Err(format!("{error:?}")));
                    }
                }
            }
            let _ = release_rx.recv_timeout(RESULT_TIMEOUT);
            drop(sessions);
        });
        Self {
            addr,
            roots,
            outcomes,
            release,
        }
    }

    fn next_outcome(&self) -> ServerOutcome {
        self.outcomes
            .recv_timeout(RESULT_TIMEOUT)
            .expect("the L1 listener reports the outcome of every connection it accepts")
    }

    fn finish(self) {
        let _ = self.release.send(());
    }
}

/// A credential source that records every request and the transport it was released over.
#[derive(Default)]
struct SpyCredential {
    calls: AtomicUsize,
    seen: Mutex<Vec<(KeyExchangeGroup, TlsProtocol)>>,
}

impl SpyCredential {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn seen(&self) -> Vec<(KeyExchangeGroup, TlsProtocol)> {
        self.seen.lock().expect("spy credential lock").clone()
    }
}

impl CredentialSource for SpyCredential {
    fn credential(&self, negotiated: &NegotiatedTransport) -> Result<Vec<u8>, TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen
            .lock()
            .expect("spy credential lock")
            .push((negotiated.group(), negotiated.protocol()));
        Ok(CREDENTIAL_MARKER.to_vec())
    }
}

fn l1_dialer(roots: RootCertStore) -> Dialer {
    expect_ok(
        Dialer::new(&TransportProfile::l1(), roots),
        "build the admitted client profile",
    )
}

struct PeerObservation {
    received: Vec<u8>,
}

// [pqc-reference-only]: the classical names below are rejection-test inputs this contract must refuse
/// A TLS 1.3 server that offers only the classical X25519 group: the adversary the admitted
/// client profile must refuse before releasing any credential.
fn start_classical_only_tls_server(
    identity: &ServerIdentity,
) -> (SocketAddr, mpsc::Receiver<PeerObservation>) {
    let provider = provider_with(&[aws_lc_rs::kx_group::X25519]);
    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 adversary configuration")
        .with_no_client_auth()
        .with_single_cert(identity.cert_chain_der(), identity.private_key_der())
        .expect("adversary server certificate");
    let config = Arc::new(config);
    let listener = TcpListener::bind(loopback()).expect("bind the adversary listener");
    let addr = listener.local_addr().expect("adversary listener address");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        set_timeouts(&socket);
        let mut connection = ServerConnection::new(config).expect("adversary connection");
        let mut handshake_completed = true;
        while connection.is_handshaking() {
            if connection.complete_io(&mut socket).is_err() {
                handshake_completed = false;
                break;
            }
        }
        let mut received = Vec::new();
        if handshake_completed {
            let _ = rustls::Stream::new(&mut connection, &mut socket).read_to_end(&mut received);
        }
        let _ = tx.send(PeerObservation { received });
    });
    (addr, rx)
}

/// A TCP peer that reads what the client sends first, answers with `reply` (possibly nothing)
/// and closes.
fn start_raw_server(reply: &'static [u8]) -> (SocketAddr, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind(loopback()).expect("bind the raw listener");
    let addr = listener.local_addr().expect("raw listener address");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        set_timeouts(&socket);
        let mut buffer = vec![0_u8; 64 * 1024];
        let read = socket.read(&mut buffer).unwrap_or(0);
        buffer.truncate(read);
        if !reply.is_empty() {
            let _ = socket.write_all(reply);
        }
        let _ = tx.send(buffer);
    });
    (addr, rx)
}

// [pqc-reference-only]: the classical names below are rejection-test inputs this contract must refuse
/// A well-formed ClientHello that offers TLS 1.2 only: legacy_version 0x0303, no
/// supported_versions extension, ECDHE AES-GCM suites, groups x25519 and secp256r1.
fn tls12_only_client_hello() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x5a; 32]);
    body.push(0x00);
    let suites: [u8; 8] = [0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30];
    body.extend_from_slice(&(suites.len() as u16).to_be_bytes());
    body.extend_from_slice(&suites);
    body.extend_from_slice(&[0x01, 0x00]);
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);
    extensions.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    extensions.extend_from_slice(&[0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04]);
    let host = SERVER_NAME.as_bytes();
    let mut server_name = Vec::new();
    server_name.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
    server_name.push(0x00);
    server_name.extend_from_slice(&(host.len() as u16).to_be_bytes());
    server_name.extend_from_slice(host);
    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&server_name);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn run_openssl_probe(openssl: &OsStr, target: &str, flags: &[&str]) -> (bool, String) {
    let mut child = Command::new(openssl)
        .args(["s_client", "-connect", target, "-servername", SERVER_NAME])
        .args(flags)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn openssl s_client");
    let deadline = Instant::now() + RESULT_TIMEOUT;
    loop {
        match child.try_wait().expect("poll openssl s_client") {
            Some(_) => break,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("openssl s_client {flags:?} did not finish within {RESULT_TIMEOUT:?}");
            }
            None => thread::sleep(Duration::from_millis(25)),
        }
    }
    let output = child
        .wait_with_output()
        .expect("collect the openssl s_client output");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), text)
}

fn write_federation_config(dir: &Path, token_url: &str) -> PathBuf {
    let path = dir.join("federation-credential-config.json");
    let body = format!(
        r#"{{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/000000000000/locations/global/workloadIdentityPools/example-pool/providers/example-provider",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_url": "{token_url}",
  "credential_source": {{ "file": "/var/run/secrets/tokens/workload-identity" }}
}}
"#
    );
    fs::write(&path, body).expect("write the federation credential configuration");
    path
}

fn resolve_enrollment(
    config: &InarchConfig,
    pairs: &[(&str, &str)],
) -> Result<EnrollmentCredentialSource, TransportError> {
    EnrollmentCredentialSource::resolve(config, &TransportEnv::from_pairs(pairs))
}

// ---------------------------------------------------------------------------------------------
// Fixture format: [[table]] headers, key = "string" or key = true/false, # comments.
// ---------------------------------------------------------------------------------------------

#[derive(Debug)]
enum FixtureValue {
    Text(String),
    Flag(bool),
}

#[derive(Debug)]
struct FixtureTable {
    header: String,
    fields: BTreeMap<String, FixtureValue>,
}

impl FixtureTable {
    fn text(&self, key: &str) -> &str {
        match self.fields.get(key) {
            Some(FixtureValue::Text(value)) => value.as_str(),
            other => panic!("[[{}]] field {key} is not a string: {other:?}", self.header),
        }
    }

    fn optional_text(&self, key: &str) -> Option<&str> {
        match self.fields.get(key) {
            None => None,
            Some(FixtureValue::Text(value)) => Some(value.as_str()),
            Some(other) => panic!("[[{}]] field {key} is not a string: {other:?}", self.header),
        }
    }

    fn flag(&self, key: &str) -> bool {
        match self.fields.get(key) {
            Some(FixtureValue::Flag(value)) => *value,
            other => panic!("[[{}]] field {key} is not true/false: {other:?}", self.header),
        }
    }

    fn has_id(&self, id: &str) -> bool {
        matches!(self.fields.get("id"), Some(FixtureValue::Text(value)) if value == id)
    }
}

fn parse_fixture(name: &str) -> Vec<FixtureTable> {
    let path = fixture_path(name);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read fixture {}: {error}", path.display()));
    let mut tables: Vec<FixtureTable> = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line_no = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("[[") {
            let header = rest
                .strip_suffix("]]")
                .unwrap_or_else(|| panic!("{name}:{line_no}: malformed table header {line}"));
            tables.push(FixtureTable {
                header: header.trim().to_string(),
                fields: BTreeMap::new(),
            });
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("{name}:{line_no}: expected key = value"));
        let key = key.trim();
        let value = value.trim();
        let parsed = if let Some(rest) = value.strip_prefix('"') {
            let end = rest
                .find('"')
                .unwrap_or_else(|| panic!("{name}:{line_no}: unterminated string"));
            let content = &rest[..end];
            let trailing = rest[end + 1..].trim();
            assert!(
                trailing.is_empty() || trailing.starts_with('#'),
                "{name}:{line_no}: unexpected text after the value"
            );
            assert!(
                !content.contains('\\'),
                "{name}:{line_no}: escapes are outside this fixture format"
            );
            FixtureValue::Text(content.to_string())
        } else {
            match value.split('#').next().unwrap_or_default().trim() {
                "true" => FixtureValue::Flag(true),
                "false" => FixtureValue::Flag(false),
                other => panic!("{name}:{line_no}: unsupported value {other}"),
            }
        };
        let table = tables
            .last_mut()
            .unwrap_or_else(|| panic!("{name}:{line_no}: key {key} appears before any table"));
        assert!(
            table.fields.insert(key.to_string(), parsed).is_none(),
            "{name}:{line_no}: duplicate key {key}"
        );
    }
    tables
}

fn find_table<'a>(tables: &'a [FixtureTable], header: &str, id: &str) -> &'a FixtureTable {
    tables
        .iter()
        .find(|table| table.header == header && table.has_id(id))
        .unwrap_or_else(|| panic!("no [[{header}]] table with id {id}"))
}

fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes.iter().enumerate().all(|(index, byte)| {
            if index == 4 || index == 7 {
                *byte == b'-'
            } else {
                byte.is_ascii_digit()
            }
        })
}

fn assert_dated_record(record: &FixtureTable) {
    let id = record.text("id");
    assert!(!record.text("product").trim().is_empty(), "{id}: product");
    assert!(
        is_iso_date(record.text("measured_on")),
        "{id}: measured_on must be a YYYY-MM-DD measurement date"
    );
    assert!(
        record.text("url").starts_with("https://docs.cloud.google.com/"),
        "{id}: the launch stage must be read from the official Google Cloud documentation"
    );
    assert!(!record.text("quote").trim().is_empty(), "{id}: verbatim quote");
    let status = record.text("status");
    assert!(
        matches!(status, "GA" | "unharmonized"),
        "{id}: status {status} is neither GA nor unharmonized; a pre-GA control is never a production substitute"
    );
    assert!(
        record.flag("remeasure_before_deploy"),
        "{id}: a launch stage is perishable and must be re-measured before deploy"
    );
}

// ---------------------------------------------------------------------------------------------
// Clause: probe suite on L1. The hybrid group negotiates; classical-only groups and TLS 1.2
// fail.
// ---------------------------------------------------------------------------------------------

// [pqc-reference-only]: the classical names below are rejection-test inputs this contract must refuse
#[test]
fn l1_and_google_carrier_profiles_admit_exactly_tls13_and_the_hybrid_group() {
    let profiles = [
        ("L1", TransportProfile::l1()),
        ("Google carrier", TransportProfile::google_carrier()),
    ];
    for (label, profile) in profiles {
        assert_eq!(
            profile.protocol_versions(),
            &[TlsProtocol::Tls13][..],
            "{label}: protocol versions"
        );
        assert_eq!(
            profile.key_exchange_groups(),
            &[KeyExchangeGroup::X25519MLKEM768][..],
            "{label}: key-exchange groups"
        );
    }
    assert_eq!(KeyExchangeGroup::X25519MLKEM768.iana_codepoint(), 0x11EC);
    assert!(KeyExchangeGroup::X25519MLKEM768.is_post_quantum_bearing());
    assert_eq!(KeyExchangeGroup::X25519.iana_codepoint(), 0x001D);
    assert_eq!(KeyExchangeGroup::Secp256r1.iana_codepoint(), 0x0017);
    assert!(!KeyExchangeGroup::X25519.is_post_quantum_bearing());
    assert!(!KeyExchangeGroup::Secp256r1.is_post_quantum_bearing());
    assert_eq!(TlsProtocol::Tls13.iana_codepoint(), 0x0304);
    assert_eq!(TlsProtocol::Tls12.iana_codepoint(), 0x0303);
}

// [pqc-reference-only]: the classical names below are rejection-test inputs this contract must refuse
#[test]
fn l1_configuration_cannot_widen_the_profile() {
    let admitted = expect_ok(
        TransportProfile::l1_from_config(&["TLSv1.3"], &["X25519MLKEM768"]),
        "the exact L1 configuration",
    );
    assert_eq!(admitted.protocol_versions(), &[TlsProtocol::Tls13][..]);
    assert_eq!(
        admitted.key_exchange_groups(),
        &[KeyExchangeGroup::X25519MLKEM768][..]
    );
    let refused: &[(&[&str], &[&str])] = &[
        (&["TLSv1.3"], &["X25519MLKEM768", "X25519"]),
        (&["TLSv1.3"], &["X25519"]),
        (&["TLSv1.3"], &["secp256r1"]),
        (&["TLSv1.3"], &["SecP256r1MLKEM768"]),
        (&["TLSv1.3"], &["X25519MLKEM768", "X25519MLKEM768"]),
        (&["TLSv1.3"], &[]),
        (&["TLSv1.2", "TLSv1.3"], &["X25519MLKEM768"]),
        (&["TLSv1.2"], &["X25519MLKEM768"]),
        (&[], &["X25519MLKEM768"]),
    ];
    for (versions, groups) in refused {
        let result = TransportProfile::l1_from_config(versions, groups);
        assert!(
            matches!(result, Err(TransportError::ProfileNotAdmitted { .. })),
            "L1 configuration versions={versions:?} groups={groups:?} was not refused as ProfileNotAdmitted"
        );
    }
}

#[test]
fn l1_listener_refuses_the_l2_partner_profile() {
    let result = L1Listener::bind(
        &TransportProfile::l2_partner(),
        loopback(),
        ephemeral_identity(),
    );
    assert!(
        matches!(result, Err(TransportError::ProfileNotAdmitted { .. })),
        "the L1 listener must only bind the L1 profile"
    );
}

#[test]
fn l1_negotiates_the_hybrid_group_over_tls13() {
    let harness = L1Harness::start(1);
    let client = raw_tls13_client(
        harness.addr,
        &harness.roots,
        provider_with(&[aws_lc_rs::kx_group::X25519MLKEM768]),
    );
    assert_eq!(client, Ok(Some(NamedGroup::X25519MLKEM768)));
    assert_eq!(
        harness.next_outcome(),
        Ok((KeyExchangeGroup::X25519MLKEM768, TlsProtocol::Tls13))
    );
    harness.finish();
}

// [pqc-reference-only]: the classical names below are rejection-test inputs this contract must refuse
#[test]
fn l1_reaches_the_hybrid_group_from_default_and_classical_first_clients() {
    let clients = [
        ("rustls default groups", aws_lc_rs::default_provider()),
        (
            "classical share first",
            provider_with(&[
                aws_lc_rs::kx_group::X25519,
                aws_lc_rs::kx_group::X25519MLKEM768,
            ]),
        ),
    ];
    for (label, provider) in clients {
        let harness = L1Harness::start(1);
        let client = raw_tls13_client(harness.addr, &harness.roots, provider);
        assert_eq!(client, Ok(Some(NamedGroup::X25519MLKEM768)), "{label}");
        assert_eq!(
            harness.next_outcome(),
            Ok((KeyExchangeGroup::X25519MLKEM768, TlsProtocol::Tls13)),
            "{label}"
        );
        harness.finish();
    }
}

// [pqc-reference-only]: the classical names below are rejection-test inputs this contract must refuse
#[test]
fn l1_refuses_a_client_offering_only_x25519() {
    let harness = L1Harness::start(1);
    let client = raw_tls13_client(
        harness.addr,
        &harness.roots,
        provider_with(&[aws_lc_rs::kx_group::X25519]),
    );
    assert!(
        client.is_err(),
        "L1 completed a handshake with a client offering only X25519: {client:?}"
    );
    let outcome = harness.next_outcome();
    assert!(
        outcome.is_err(),
        "L1 accepted a client offering only X25519: {outcome:?}"
    );
    harness.finish();
}

// [pqc-reference-only]: the classical names below are rejection-test inputs this contract must refuse
#[test]
fn l1_refuses_a_client_offering_only_p256() {
    let harness = L1Harness::start(1);
    let client = raw_tls13_client(
        harness.addr,
        &harness.roots,
        provider_with(&[aws_lc_rs::kx_group::SECP256R1]),
    );
    assert!(
        client.is_err(),
        "L1 completed a handshake with a client offering only P-256: {client:?}"
    );
    let outcome = harness.next_outcome();
    assert!(
        outcome.is_err(),
        "L1 accepted a client offering only P-256: {outcome:?}"
    );
    harness.finish();
}

#[test]
fn l1_refuses_a_tls12_only_client_hello() {
    let harness = L1Harness::start(1);
    let mut socket = connect_loopback(harness.addr);
    socket
        .write_all(&tls12_only_client_hello())
        .expect("send the TLS 1.2-only ClientHello");
    let mut response = Vec::new();
    let _ = socket.read_to_end(&mut response);
    assert!(
        response.first().is_none_or(|first| *first == 0x15),
        "L1 answered a TLS 1.2-only ClientHello with something other than an alert: {:02x?}",
        &response[..response.len().min(16)]
    );
    let outcome = harness.next_outcome();
    assert!(
        outcome.is_err(),
        "L1 accepted a TLS 1.2-only client: {outcome:?}"
    );
    harness.finish();
}

#[test]
fn l1_refuses_plaintext_without_serving_it() {
    let harness = L1Harness::start(1);
    let mut socket = connect_loopback(harness.addr);
    socket
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("send a plaintext request");
    let mut response = Vec::new();
    let _ = socket.read_to_end(&mut response);
    assert!(
        !response.starts_with(b"HTTP/"),
        "L1 served plaintext HTTP"
    );
    let outcome = harness.next_outcome();
    assert!(
        outcome.is_err(),
        "L1 accepted a plaintext client: {outcome:?}"
    );
    harness.finish();
}

// [pqc-reference-only]: the classical names below are rejection-test inputs this contract must refuse
#[test]
#[ignore = "runs openssl s_client against an in-process L1 listener; set INARCH_PROBE_OPENSSL to an OpenSSL 3.5 or newer binary"]
fn l1_openssl_probe_suite() {
    let Some(openssl) = std::env::var_os("INARCH_PROBE_OPENSSL") else {
        eprintln!(
            "SKIPPED l1_openssl_probe_suite: INARCH_PROBE_OPENSSL is not set, so this run did not exercise the openssl probe suite"
        );
        return;
    };
    let harness = L1Harness::start(4);
    let target = harness.addr.to_string();

    let (negotiated, output) = run_openssl_probe(
        &openssl,
        &target,
        &["-tls1_3", "-groups", "X25519MLKEM768"],
    );
    assert!(
        negotiated,
        "openssl -groups X25519MLKEM768 did not negotiate with L1:\n{output}"
    );
    assert!(
        output.contains("X25519MLKEM768"),
        "openssl did not report X25519MLKEM768 as the negotiated group:\n{output}"
    );
    assert_eq!(
        harness.next_outcome(),
        Ok((KeyExchangeGroup::X25519MLKEM768, TlsProtocol::Tls13))
    );

    let refused: [&[&str]; 3] = [&["-groups", "X25519"], &["-groups", "P-256"], &["-tls1_2"]];
    for flags in refused {
        let (negotiated, output) = run_openssl_probe(&openssl, &target, flags);
        assert!(
            !negotiated,
            "openssl {flags:?} completed a session with L1:\n{output}"
        );
        let outcome = harness.next_outcome();
        assert!(
            outcome.is_err(),
            "L1 accepted openssl {flags:?}: {outcome:?}"
        );
    }
    harness.finish();
}

// [pqc-reference-only]: the classical names below are rejection-test inputs this contract must refuse
#[test]
fn l1_probe_steps_cover_the_four_openssl_probes() {
    let steps = parse_fixture("test_code_steps.toml");
    let expected = [
        ("-tls1_3 -groups X25519MLKEM768", "negotiates"),
        ("-groups X25519", "fails"),
        ("-groups P-256", "fails"),
        ("-tls1_2", "fails"),
    ];
    for (flags, outcome) in expected {
        let found = steps.iter().any(|step| {
            step.header == "step"
                && step.text("clause") == "l1-probe"
                && step.text("command").starts_with("openssl s_client -connect ")
                && step.text("command").ends_with(flags)
                && step.text("expect") == outcome
        });
        assert!(
            found,
            "test_code_steps.toml has no l1-probe step ending in {flags} that expects {outcome}"
        );
    }
    for step in &steps {
        assert_eq!(step.header, "step", "unexpected table [[{}]]", step.header);
        let id = step.text("id");
        assert!(
            matches!(
                step.text("clause"),
                "l1-probe" | "l2-load-balancer" | "enrollment"
            ),
            "{id}: unknown clause"
        );
        for key in ["command", "expect", "observe", "requires"] {
            assert!(!step.text(key).trim().is_empty(), "{id}: empty {key}");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Clause: a client facing a classical-only server refuses before any credential.
// ---------------------------------------------------------------------------------------------

#[test]
fn client_attaches_its_credential_only_after_negotiating_the_hybrid_group() {
    let harness = L1Harness::start(1);
    let dialer = l1_dialer(harness.roots.clone());
    let spy = SpyCredential::default();
    let session = expect_ok(
        dialer.connect(harness.addr, SERVER_NAME, &spy),
        "dial the L1 listener",
    );
    assert_eq!(session.negotiated_group(), KeyExchangeGroup::X25519MLKEM768);
    assert_eq!(session.negotiated_protocol(), TlsProtocol::Tls13);
    assert_eq!(
        spy.calls(),
        1,
        "the credential is requested exactly once, after the handshake"
    );
    assert_eq!(
        spy.seen(),
        vec![(KeyExchangeGroup::X25519MLKEM768, TlsProtocol::Tls13)],
        "the credential source sees the negotiated transport it is released over"
    );
    assert_eq!(
        harness.next_outcome(),
        Ok((KeyExchangeGroup::X25519MLKEM768, TlsProtocol::Tls13))
    );
    drop(session);
    harness.finish();
}

#[test]
fn client_refuses_a_classical_only_server_before_any_credential() {
    let identity = ephemeral_identity();
    let (addr, observations) = start_classical_only_tls_server(&identity);
    let dialer = l1_dialer(roots_for(&identity));
    let spy = SpyCredential::default();
    let refusal = expect_refusal(
        dialer.connect(addr, SERVER_NAME, &spy),
        "dial a classical-only server",
    );
    assert!(
        matches!(
            refusal,
            TransportError::Handshake { .. } | TransportError::NegotiatedGroupMismatch { .. }
        ),
        "a classical-only server is refused at the handshake or at the exact negotiated-group compare, got {refusal:?}"
    );
    assert_eq!(
        spy.calls(),
        0,
        "the credential was requested before the transport was proven post-quantum"
    );
    let observation = observations
        .recv_timeout(RESULT_TIMEOUT)
        .expect("the adversary reports what it received");
    assert!(
        !contains(&observation.received, CREDENTIAL_MARKER),
        "the credential reached a classical-only server"
    );
}

#[test]
fn client_refuses_plaintext_and_closing_peers_before_any_credential() {
    let peers: [(&str, &'static [u8]); 2] = [
        (
            "plaintext HTTP server",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        ),
        ("peer that closes after accepting", b""),
    ];
    for (label, reply) in peers {
        let (addr, received) = start_raw_server(reply);
        let identity = ephemeral_identity();
        let dialer = l1_dialer(roots_for(&identity));
        let spy = SpyCredential::default();
        let _ = expect_refusal(dialer.connect(addr, SERVER_NAME, &spy), label);
        assert_eq!(spy.calls(), 0, "{label}: the credential was requested");
        let bytes = received
            .recv_timeout(RESULT_TIMEOUT)
            .expect("the raw peer reports what it received");
        assert!(
            !contains(&bytes, CREDENTIAL_MARKER),
            "{label}: the credential reached the peer"
        );
        assert_eq!(
            bytes.first(),
            Some(&0x16),
            "{label}: the client must open with a TLS handshake record, never plaintext"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Clause: Postgres sslmode disable/prefer/require refuse at startup.
// ---------------------------------------------------------------------------------------------

fn postgres_refusal(reason: &str) -> PostgresRefusal {
    match reason {
        "sslmode" => PostgresRefusal::SslMode,
        "server_ssl_groups" => PostgresRefusal::ServerSslGroups,
        "min_protocol" => PostgresRefusal::MinProtocol,
        "group_not_reportable" => PostgresRefusal::GroupNotReportable,
        other => panic!("postgres_profiles.toml names an unknown refusal reason {other}"),
    }
}

#[test]
fn postgres_carrier_admits_only_verify_full_post_quantum_or_node_internal() {
    let cases = parse_fixture("postgres_profiles.toml");
    assert!(!cases.is_empty(), "postgres_profiles.toml has no cases");
    for case in &cases {
        assert_eq!(case.header, "case", "unexpected table [[{}]]", case.header);
        let name = case.text("name");
        let config = PostgresCarrierConfig {
            url: case.text("url").to_string(),
            server_ssl_groups: case.optional_text("server_ssl_groups").map(str::to_string),
            driver_reports_negotiated_group: case.flag("driver_reports_negotiated_group"),
        };
        let result = PostgresSslPolicy::from_config(&config);
        match case.text("expect") {
            "refuse" => {
                let expected = postgres_refusal(case.text("reason"));
                match result {
                    Err(TransportError::PostgresCarrierRefused { reason, .. }) => {
                        assert_eq!(reason, expected, "{name}")
                    }
                    Err(other) => panic!(
                        "{name}: refused with {other:?}, expected PostgresCarrierRefused({expected:?})"
                    ),
                    Ok(_) => panic!("{name}: admitted at startup, expected refusal {expected:?}"),
                }
            }
            "networked_verify_full" => assert_eq!(
                expect_ok(result, name).carrier(),
                PostgresCarrier::NetworkedVerifyFull,
                "{name}"
            ),
            "node_internal" => assert_eq!(
                expect_ok(result, name).carrier(),
                PostgresCarrier::NodeInternal,
                "{name}"
            ),
            other => panic!("{name}: unknown expectation {other}"),
        }
    }
    for mode in ["sslmode=disable", "sslmode=prefer", "sslmode=require"] {
        let covered = cases.iter().any(|case| {
            case.text("expect") == "refuse"
                && case.text("reason") == "sslmode"
                && case.text("url").contains(mode)
        });
        assert!(covered, "postgres_profiles.toml has no networked {mode} refusal case");
    }
}

// [pqc-reference-only]: the classical names below are rejection-test inputs this contract must refuse
#[test]
fn postgres_carrier_refuses_a_classical_negotiated_group() {
    let config = PostgresCarrierConfig {
        url: "postgresql://ledger@db.example.com:5432/ledger?sslmode=verify-full&ssl_min_protocol_version=TLSv1.3".to_string(),
        server_ssl_groups: Some("X25519MLKEM768".to_string()),
        driver_reports_negotiated_group: true,
    };
    let policy = expect_ok(
        PostgresSslPolicy::from_config(&config),
        "the admitted networked Postgres carrier",
    );
    assert!(
        policy
            .verify_negotiated(KeyExchangeGroup::X25519MLKEM768)
            .is_ok(),
        "the hybrid group is the admitted Postgres negotiation"
    );
    for group in [KeyExchangeGroup::X25519, KeyExchangeGroup::Secp256r1] {
        match policy.verify_negotiated(group) {
            Err(TransportError::PostgresCarrierRefused { reason, .. }) => {
                assert_eq!(reason, PostgresRefusal::NegotiatedGroup, "{group:?}")
            }
            Err(other) => panic!("{group:?}: refused with {other:?}, expected NegotiatedGroup"),
            Ok(()) => panic!("{group:?}: a classical negotiated group was accepted"),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Clause: a DirectPath/ALTS env switch refuses before any byte.
// ---------------------------------------------------------------------------------------------

#[test]
fn google_carrier_refuses_every_direct_path_switch_before_any_byte() {
    for switch in DIRECT_PATH_SWITCHES {
        for value in ["true", "1", "false"] {
            let env = TransportEnv::from_pairs(&[(switch, value)]);
            match Dialer::google_carrier(&env) {
                Err(TransportError::NonTlsCarrierRefused { switch: named, .. }) => {
                    assert_eq!(named, switch, "{switch}={value}")
                }
                Err(other) => panic!("{switch}={value}: refused with {other:?}"),
                Ok(_) => panic!("{switch}={value}: a Google carrier was built"),
            }
        }
    }
    let env = TransportEnv::from_pairs(&[
        ("GOOGLE_CLOUD_DISABLE_DIRECT_PATH", "true"),
        ("GOOGLE_CLOUD_ENABLE_DIRECT_PATH_XDS", "true"),
    ]);
    assert!(
        matches!(
            Dialer::google_carrier(&env),
            Err(TransportError::NonTlsCarrierRefused { .. })
        ),
        "a disable switch never cancels an enable switch"
    );
}

#[test]
fn google_carrier_admits_outer_tls_when_no_switch_is_present() {
    let cases: [&[(&str, &str)]; 3] = [
        &[],
        &[("GOOGLE_CLOUD_DISABLE_DIRECT_PATH", "true")],
        &[("PATH", "/usr/bin")],
    ];
    for pairs in cases {
        let result = Dialer::google_carrier(&TransportEnv::from_pairs(pairs));
        assert!(
            !matches!(result, Err(TransportError::NonTlsCarrierRefused { .. })),
            "outer TLS was refused as a non-TLS carrier for {pairs:?}"
        );
    }
}

#[test]
fn google_carrier_reads_the_direct_path_switch_from_the_process_environment() {
    run_child_test(
        "child_google_carrier_refuses_process_direct_path_switch",
        &[
            (CHILD_MARKER, "1"),
            ("GOOGLE_CLOUD_ENABLE_DIRECT_PATH_XDS", "true"),
        ],
        CHILD_TIMEOUT,
    );
}

#[test]
fn child_google_carrier_refuses_process_direct_path_switch() {
    if std::env::var_os(CHILD_MARKER).is_none() {
        return;
    }
    match Dialer::google_carrier(&TransportEnv::from_process()) {
        Err(TransportError::NonTlsCarrierRefused { switch, .. }) => assert!(
            DIRECT_PATH_SWITCHES.contains(&switch.as_str()),
            "refusal names {switch}"
        ),
        Err(other) => panic!("refused with {other:?}, expected NonTlsCarrierRefused"),
        Ok(_) => panic!("a Google carrier was built under a DirectPath switch"),
    }
}

// ---------------------------------------------------------------------------------------------
// Clause: an LB fronting L2 shows post-quantum-key-exchange=ENABLED with a dated launch-stage
// check.
// ---------------------------------------------------------------------------------------------

#[test]
fn launch_stage_records_are_dated_sourced_and_perishable() {
    let tables = parse_fixture("launch_stages.toml");
    let records: Vec<&FixtureTable> = tables
        .iter()
        .filter(|table| table.header == "record")
        .collect();
    assert!(!records.is_empty(), "launch_stages.toml has no records");
    for record in &records {
        assert_dated_record(record);
    }
    let ids: BTreeSet<&str> = records.iter().map(|record| record.text("id")).collect();
    assert_eq!(ids.len(), records.len(), "duplicate launch-stage record ids");
    for table in &tables {
        assert!(
            matches!(table.header.as_str(), "record" | "reading"),
            "unexpected table [[{}]]",
            table.header
        );
        if table.header == "reading" {
            let record = table.text("record");
            assert!(ids.contains(record), "a reading names unknown record {record}");
            assert!(is_iso_date(table.text("measured_on")), "{record}: reading date");
            assert!(table.text("url").starts_with("https://"), "{record}: reading url");
            assert!(!table.text("quote").trim().is_empty(), "{record}: reading quote");
        }
    }
}

#[test]
fn l2_load_balancer_step_requires_enabled_post_quantum_key_exchange_with_a_dated_launch_stage() {
    let steps = parse_fixture("test_code_steps.toml");
    let records = parse_fixture("launch_stages.toml");
    let step = find_table(&steps, "step", "l2-load-balancer-post-quantum-key-exchange");
    assert_eq!(step.text("clause"), "l2-load-balancer");
    assert_eq!(
        step.text("expect"),
        "ENABLED",
        "the L2 front must set post-quantum key exchange explicitly"
    );
    let command = step.text("command");
    assert!(
        command.starts_with("gcloud compute ssl-policies describe "),
        "{command}"
    );
    assert!(command.contains("postQuantumKeyExchange"), "{command}");
    let record = find_table(&records, "record", step.text("launch_stage_record"));
    assert_dated_record(record);
    let no_front = find_table(&steps, "step", "l1-has-no-load-balancer");
    assert_eq!(no_front.text("clause"), "l2-load-balancer");
    assert_eq!(
        no_front.text("expect"),
        "absent",
        "a load balancer may front only L2"
    );
}

// ---------------------------------------------------------------------------------------------
// Clause: keyless enrollment. No service-account key file is accepted, generated, documented or
// read; refusal precedes any network call; WIF is dated GA; the token exchange rides the Google
// carrier profile.
// ---------------------------------------------------------------------------------------------

#[test]
fn key_shaped_fixture_is_key_shaped_and_carries_no_key_material() {
    let text = fs::read_to_string(key_shaped_fixture()).expect("read the key-shaped fixture");
    assert!(
        text.contains("\"type\": \"service_account\""),
        "the fixture must be shaped like a service-account key file"
    );
    assert!(text.contains("\"private_key\""), "the fixture must carry the key field name");
    assert!(
        !text.contains("-----"),
        "the fixture must not carry PEM armor or key material"
    );
}

#[test]
fn enrollment_refuses_a_configured_key_file_before_any_network_call() {
    let listener = TcpListener::bind(loopback()).expect("bind the probe listener");
    let addr = listener.local_addr().expect("probe listener address");
    let workspace = AuditTempDir::new("pqt_enroll");
    let key_paths = [
        ("key-shaped file present", key_shaped_fixture()),
        (
            "configured path that does not exist",
            workspace.path().join("absent-key.json"),
        ),
    ];
    for (label, key_path) in key_paths {
        let config = InarchConfig {
            remote_url: format!("http://{addr}"),
            oidc_token_uri: format!("http://{addr}/token"),
            oidc_audience: format!("http://{addr}"),
            gcp_credentials_file: key_path.display().to_string(),
            ..InarchConfig::default()
        };
        match config.resolve_effective_auth(workspace.path()) {
            Err(CliError::Transport(TransportError::ServiceAccountKeyFileRefused {
                origin, ..
            })) => assert_eq!(origin, "gcp_credentials_file", "{label}"),
            Err(other) => {
                panic!("{label}: expected the service-account key refusal, got {other:?}")
            }
            Ok(_) => panic!("{label}: enrollment accepted a service-account key file"),
        }
        match config.open_remote_client(workspace.path()) {
            Err(CliError::Transport(TransportError::ServiceAccountKeyFileRefused { .. })) => {}
            Err(other) => panic!(
                "{label}: the remote client expected the service-account key refusal, got {other:?}"
            ),
            Ok(_) => panic!("{label}: the remote client accepted a service-account key file"),
        }
        assert_no_connection_reached(&listener, label);
    }
}

#[test]
fn enrollment_source_refuses_key_shaped_application_credentials() {
    let key = key_shaped_fixture().display().to_string();
    match resolve_enrollment(
        &InarchConfig::default(),
        &[(APPLICATION_CREDENTIALS, key.as_str())],
    ) {
        Err(TransportError::ServiceAccountKeyFileRefused { origin, .. }) => {
            assert_eq!(origin, APPLICATION_CREDENTIALS)
        }
        Err(other) => panic!("expected the service-account key refusal, got {other:?}"),
        Ok(_) => panic!("enrollment accepted a service-account key file"),
    }
}

#[test]
fn enrollment_source_refuses_a_configured_key_file_even_beside_federation() {
    let dir = AuditTempDir::new("pqt_both");
    let federation = write_federation_config(dir.path(), GOOGLE_STS_TOKEN_URL)
        .display()
        .to_string();
    let config = InarchConfig {
        gcp_credentials_file: key_shaped_fixture().display().to_string(),
        ..InarchConfig::default()
    };
    match resolve_enrollment(&config, &[(APPLICATION_CREDENTIALS, federation.as_str())]) {
        Err(TransportError::ServiceAccountKeyFileRefused { origin, .. }) => {
            assert_eq!(origin, "gcp_credentials_file")
        }
        Err(other) => panic!("expected the service-account key refusal, got {other:?}"),
        Ok(_) => panic!("enrollment accepted a configured service-account key file"),
    }
}

#[test]
fn enrollment_reads_application_credentials_from_the_process_environment() {
    let key = key_shaped_fixture().display().to_string();
    run_child_test(
        "child_enrollment_refuses_process_key_shaped_application_credentials",
        &[(CHILD_MARKER, "1"), (APPLICATION_CREDENTIALS, key.as_str())],
        CHILD_TIMEOUT,
    );
}

#[test]
fn child_enrollment_refuses_process_key_shaped_application_credentials() {
    if std::env::var_os(CHILD_MARKER).is_none() {
        return;
    }
    match EnrollmentCredentialSource::resolve(
        &InarchConfig::default(),
        &TransportEnv::from_process(),
    ) {
        Err(TransportError::ServiceAccountKeyFileRefused { origin, .. }) => {
            assert_eq!(origin, APPLICATION_CREDENTIALS)
        }
        Err(other) => panic!("expected the service-account key refusal, got {other:?}"),
        Ok(_) => panic!("enrollment accepted a service-account key file from the environment"),
    }
}

#[test]
fn enrollment_source_accepts_workload_identity_federation_over_the_google_carrier() {
    let dir = AuditTempDir::new("pqt_wif");
    let federation = write_federation_config(dir.path(), GOOGLE_STS_TOKEN_URL)
        .display()
        .to_string();
    let source = expect_ok(
        resolve_enrollment(
            &InarchConfig::default(),
            &[(APPLICATION_CREDENTIALS, federation.as_str())],
        ),
        "resolve a workload identity federation configuration",
    );
    assert!(
        matches!(
            source,
            EnrollmentCredentialSource::WorkloadIdentityFederation { .. }
        ),
        "an external_account configuration resolves to workload identity federation"
    );
    let profile = source.token_exchange_profile();
    assert_eq!(profile.protocol_versions(), &[TlsProtocol::Tls13][..]);
    assert_eq!(
        profile.key_exchange_groups(),
        &[KeyExchangeGroup::X25519MLKEM768][..]
    );
}

#[test]
fn enrollment_token_exchange_refuses_a_direct_path_switch() {
    let dir = AuditTempDir::new("pqt_wifdp");
    let federation = write_federation_config(dir.path(), GOOGLE_STS_TOKEN_URL)
        .display()
        .to_string();
    let result = resolve_enrollment(
        &InarchConfig::default(),
        &[
            (APPLICATION_CREDENTIALS, federation.as_str()),
            ("GOOGLE_CLOUD_ENABLE_DIRECT_PATH_XDS", "true"),
        ],
    );
    assert!(
        matches!(result, Err(TransportError::NonTlsCarrierRefused { .. })),
        "the enrollment token exchange rides the Google carrier profile, which refuses a DirectPath switch"
    );
}

#[test]
fn enrollment_source_refuses_token_exchange_off_the_google_carrier() {
    let dir = AuditTempDir::new("pqt_sts");
    for token_url in [
        "http://sts.googleapis.com/v1/token",
        "https://sts.example.com/v1/token",
    ] {
        let federation = write_federation_config(dir.path(), token_url)
            .display()
            .to_string();
        let result = resolve_enrollment(
            &InarchConfig::default(),
            &[(APPLICATION_CREDENTIALS, federation.as_str())],
        );
        assert!(
            matches!(result, Err(TransportError::CredentialConfigRefused { .. })),
            "token_url {token_url} is not the Google carrier"
        );
    }
}

#[test]
fn enrollment_source_fails_closed_on_unreadable_or_malformed_configuration() {
    let dir = AuditTempDir::new("pqt_bad");
    let malformed = dir.path().join("malformed.json");
    fs::write(&malformed, "{ not json").expect("write the malformed configuration");
    for path in [dir.path().join("absent.json"), malformed] {
        let named = path.display().to_string();
        let result = resolve_enrollment(
            &InarchConfig::default(),
            &[(APPLICATION_CREDENTIALS, named.as_str())],
        );
        assert!(
            matches!(result, Err(TransportError::CredentialConfigRefused { .. })),
            "{named} must fail closed"
        );
    }
}

#[test]
fn enrollment_source_uses_the_platform_native_credential_when_no_file_is_named() {
    let result = resolve_enrollment(&InarchConfig::default(), &[]);
    assert!(
        matches!(
            result,
            Ok(EnrollmentCredentialSource::PlatformNative { .. })
        ),
        "with no credential file named, enrollment uses the platform's native credential"
    );
}

#[test]
fn workload_identity_federation_has_a_dated_ga_launch_stage() {
    let records = parse_fixture("launch_stages.toml");
    let record = find_table(&records, "record", "workload-identity-federation");
    assert_dated_record(record);
    assert_eq!(
        record.text("status"),
        "GA",
        "workload identity federation must be measured GA"
    );
    let steps = parse_fixture("test_code_steps.toml");
    let step = find_table(
        &steps,
        "step",
        "enrollment-workload-identity-federation-token-exchange",
    );
    assert_eq!(step.text("clause"), "enrollment");
    assert_eq!(
        step.text("launch_stage_record"),
        "workload-identity-federation"
    );
    assert!(step.text("observe").contains("X25519MLKEM768"));
    let refusal = find_table(&steps, "step", "enrollment-refuses-key-file-before-network");
    assert_eq!(refusal.text("expect"), "refuses");
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[test]
fn service_account_key_enrollment_is_neither_documented_nor_generated() {
    let root = repo_root();
    let mut files = vec![root.join("README.md"), root.join("inarch.example.toml")];
    for dir in ["docs", "scripts", "deploy", "quickstart"] {
        collect_files(&root.join(dir), &mut files);
    }
    let banned = [
        "--sa-key-path",
        "sa_key_path",
        "service-accounts keys create",
        "service_account.json",
    ];
    let guarded = [
        "gcp_credentials_file",
        "service-account key",
        "service account key",
    ];
    let mut findings = Vec::new();
    for path in &files {
        let Ok(bytes) = fs::read(path) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        let shown = path.strip_prefix(&root).unwrap_or(path).display().to_string();
        for (index, line) in text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            for needle in banned {
                if lower.contains(needle) {
                    findings.push(format!(
                        "{shown}:{}: generates or documents {needle}",
                        index + 1
                    ));
                }
            }
            if guarded.iter().any(|needle| lower.contains(needle)) && !lower.contains("refus") {
                findings.push(format!(
                    "{shown}:{}: mentions a service-account key without stating its refusal",
                    index + 1
                ));
            }
        }
    }
    assert!(
        findings.is_empty(),
        "service-account key enrollment is still documented or generated:\n{}",
        findings.join("\n")
    );
}
