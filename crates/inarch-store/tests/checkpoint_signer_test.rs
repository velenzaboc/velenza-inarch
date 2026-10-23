//! Contract tests for the ML-DSA-65 checkpoint signer and the signed Merkle checkpoint.
//!
//! The only admitted signer is Cloud KMS with a `PQ_SIGN_ML_DSA_65` key version at the
//! SOFTWARE protection level. A checkpoint reaches the store only after KMS has signed it and
//! the signature has verified against the public key fetched at startup, so a blocked KMS
//! route, a classical key, a local signer or an unsigned configuration never yields a stored
//! checkpoint. Verifiers hold the public key alone.
//!
//! The in-process fake replaces the KMS transport (`KmsClient`), never the `Signer`, and signs
//! with a real ML-DSA-65 key generated at run time, so every signature checked here is a
//! genuine FIPS 204 signature that an independent aws-lc-rs verifier also accepts. The two
//! `#[ignore]` tests run the same contract against a real key version named by
//! `INARCH_TEST_KMS_PQ_KEY`; `fixtures/checkpoint/test_code_steps.toml` says how.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{KeyPair, ML_DSA_65, ML_DSA_65_SIGNING, ParsedPublicKey, PqdsaKeyPair};
use inarch_store::checkpoint::{
    CHECKPOINT_SIGNING_DOMAIN, Checkpoint, CheckpointError, CheckpointStore, CheckpointWriter,
    PublicKeyVerifier, SignedCheckpoint,
};
use inarch_store::signer::{
    Algorithm, CloudKmsClient, KmsClient, KmsError, KmsPublicKey, KmsSignature, KmsSigner,
    Signer, SignerConfig, SignerError,
};

const FAKE_KMS: &str = include_str!("fixtures/checkpoint/fake_kms.json");
const KMS_LAUNCH_STAGE: &str = include_str!("fixtures/checkpoint/kms_launch_stage.toml");
const TEST_CODE_STEPS: &str = include_str!("fixtures/checkpoint/test_code_steps.toml");

const ADMITTED_KEY_VERSION: &str = "projects/example-proj/locations/global/keyRings/ledger/cryptoKeys/checkpoint/cryptoKeyVersions/1";
const OTHER_KEY_VERSION: &str = "projects/example-proj/locations/global/keyRings/ledger/cryptoKeys/checkpoint/cryptoKeyVersions/2";
const ADMITTED_ALGORITHM: &str = "PQ_SIGN_ML_DSA_65";
const ADMITTED_PROTECTION_LEVEL: &str = "SOFTWARE";
const NIST_PQC: &str = "NIST_PQC";
const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
const ML_DSA_65_PRIVATE_KEY_LEN: usize = 4032;
const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
/// DER prefix of an ML-DSA-65 SubjectPublicKeyInfo (algorithm OID 2.16.840.1.101.3.4.3.18,
/// no parameters) that precedes the 1952 raw FIPS 204 public key bytes.
const ML_DSA_65_SPKI_PREFIX: [u8; 22] = [
    0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
    0x12, 0x03, 0x82, 0x07, 0xa1, 0x00,
];

const LIVE_KEY_ENV: &str = "INARCH_TEST_KMS_PQ_KEY";
const LIVE_ROUTE_BLOCKED_ENV: &str = "INARCH_TEST_KMS_ROUTE_BLOCKED";
const LIVE_SIGN_TEST: &str = "live_kms_signed_checkpoint_verifies_with_the_public_key_alone";
const LIVE_ROUTE_BLOCKED_TEST: &str = "live_kms_route_blocked_writes_no_checkpoint";

const CLAUSE_VERIFIES: &str = "signed-checkpoint-verifies-with-public-key";
const CLAUSE_REFUSED: &str = "classical-or-local-signer-refused-at-startup";
const CLAUSE_ROUTE_BLOCKED: &str = "kms-route-blocked-writes-no-unsigned-checkpoint";
const CLAUSE_GA_RECORD: &str = "ml-dsa-65-ga-dated-record";

// ---------------------------------------------------------------------------
// ML-DSA-65 helpers backed by aws-lc-rs, the independent oracle for every signature.
// ---------------------------------------------------------------------------

fn generate_ml_dsa_65() -> PqdsaKeyPair {
    PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).expect("generate an ML-DSA-65 key pair")
}

fn spki_der(key_pair: &PqdsaKeyPair) -> Vec<u8> {
    key_pair
        .public_key()
        .as_der()
        .expect("encode the ML-DSA-65 public key as SubjectPublicKeyInfo")
        .as_ref()
        .to_vec()
}

/// The NIST_PQC form Cloud KMS serves: the raw FIPS 204 public key inside the SPKI wrapper.
fn raw_public_key(spki: &[u8]) -> Vec<u8> {
    assert_eq!(
        spki.len(),
        ML_DSA_65_SPKI_PREFIX.len() + ML_DSA_65_PUBLIC_KEY_LEN,
        "an ML-DSA-65 SubjectPublicKeyInfo wraps exactly one 1952-byte public key"
    );
    spki[ML_DSA_65_SPKI_PREFIX.len()..].to_vec()
}

fn spki_from_raw(raw: &[u8]) -> Vec<u8> {
    let mut der = ML_DSA_65_SPKI_PREFIX.to_vec();
    der.extend_from_slice(raw);
    der
}

fn ml_dsa_65_sign(key_pair: &PqdsaKeyPair, message: &[u8]) -> Vec<u8> {
    let mut signature = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
    let written = key_pair
        .sign(message, &mut signature)
        .expect("ML-DSA-65 signing");
    signature.truncate(written);
    signature
}

fn oracle_verifies(spki: &[u8], message: &[u8], signature: &[u8]) -> bool {
    ParsedPublicKey::new(&ML_DSA_65, spki)
        .expect("the oracle parses an ML-DSA-65 SubjectPublicKeyInfo")
        .verify_sig(message, signature)
        .is_ok()
}

// ---------------------------------------------------------------------------
// The fake Cloud KMS transport. It answers GetPublicKey and AsymmetricSign the way the
// Cloud KMS REST API does for a pure ML-DSA key: the public key in NIST_PQC form, the
// signature over the exact request data, and the name of the key version that signed.
// ---------------------------------------------------------------------------

struct FakeSpec {
    algorithm: String,
    protection_level: String,
    public_key_format: String,
    public_key_data: Option<Vec<u8>>,
    public_key_name: Option<String>,
    sign_name: Option<String>,
}

impl FakeSpec {
    fn admitted() -> Self {
        Self {
            algorithm: ADMITTED_ALGORITHM.to_string(),
            protection_level: ADMITTED_PROTECTION_LEVEL.to_string(),
            public_key_format: NIST_PQC.to_string(),
            public_key_data: None,
            public_key_name: None,
            sign_name: None,
        }
    }
}

struct FakeKms {
    key_version: String,
    spec: FakeSpec,
    key_pair: Mutex<PqdsaKeyPair>,
    impostor: Mutex<PqdsaKeyPair>,
    public_key_spki: Vec<u8>,
    public_key_raw: Vec<u8>,
    route_blocked: AtomicBool,
    sign_with_impostor: AtomicBool,
    reject_sign: AtomicBool,
    public_key_calls: AtomicUsize,
    sign_requests: Mutex<Vec<(String, Vec<u8>)>>,
}

impl FakeKms {
    fn new(spec: FakeSpec) -> Arc<Self> {
        let key_pair = generate_ml_dsa_65();
        let public_key_spki = spki_der(&key_pair);
        let public_key_raw = raw_public_key(&public_key_spki);
        Arc::new(Self {
            key_version: ADMITTED_KEY_VERSION.to_string(),
            spec,
            key_pair: Mutex::new(key_pair),
            impostor: Mutex::new(generate_ml_dsa_65()),
            public_key_spki,
            public_key_raw,
            route_blocked: AtomicBool::new(false),
            sign_with_impostor: AtomicBool::new(false),
            reject_sign: AtomicBool::new(false),
            public_key_calls: AtomicUsize::new(0),
            sign_requests: Mutex::new(Vec::new()),
        })
    }

    fn admitted() -> Arc<Self> {
        Self::new(FakeSpec::admitted())
    }

    fn client(self: &Arc<Self>) -> Arc<dyn KmsClient> {
        self.clone()
    }

    fn set_route_blocked(&self, blocked: bool) {
        self.route_blocked.store(blocked, Ordering::SeqCst);
    }

    fn public_key_calls(&self) -> usize {
        self.public_key_calls.load(Ordering::SeqCst)
    }

    fn sign_requests(&self) -> Vec<(String, Vec<u8>)> {
        self.sign_requests.lock().expect("sign request log").clone()
    }

    fn sign_calls(&self) -> usize {
        self.sign_requests.lock().expect("sign request log").len()
    }

    fn unreachable() -> KmsError {
        KmsError::Unreachable("connect cloudkms.googleapis.com:443: route blocked".to_string())
    }
}

impl KmsClient for FakeKms {
    fn get_public_key(&self, key_version: &str) -> Result<KmsPublicKey, KmsError> {
        self.public_key_calls.fetch_add(1, Ordering::SeqCst);
        if self.route_blocked.load(Ordering::SeqCst) {
            return Err(Self::unreachable());
        }
        if key_version != self.key_version {
            return Err(KmsError::Rejected {
                status: 404,
                message: format!("NOT_FOUND: {key_version}"),
            });
        }
        Ok(KmsPublicKey {
            name: self
                .spec
                .public_key_name
                .clone()
                .unwrap_or_else(|| self.key_version.clone()),
            algorithm: self.spec.algorithm.clone(),
            protection_level: self.spec.protection_level.clone(),
            public_key_format: self.spec.public_key_format.clone(),
            data: self
                .spec
                .public_key_data
                .clone()
                .unwrap_or_else(|| self.public_key_raw.clone()),
        })
    }

    fn asymmetric_sign(&self, key_version: &str, data: &[u8]) -> Result<KmsSignature, KmsError> {
        self.sign_requests
            .lock()
            .expect("sign request log")
            .push((key_version.to_string(), data.to_vec()));
        if self.route_blocked.load(Ordering::SeqCst) {
            return Err(Self::unreachable());
        }
        if self.reject_sign.load(Ordering::SeqCst) {
            return Err(KmsError::Rejected {
                status: 400,
                message: "FAILED_PRECONDITION: the key version is not enabled".to_string(),
            });
        }
        if key_version != self.key_version {
            return Err(KmsError::Rejected {
                status: 404,
                message: format!("NOT_FOUND: {key_version}"),
            });
        }
        let key = if self.sign_with_impostor.load(Ordering::SeqCst) {
            &self.impostor
        } else {
            &self.key_pair
        };
        let signature = ml_dsa_65_sign(&key.lock().expect("fake KMS key"), data);
        Ok(KmsSignature {
            name: self
                .spec
                .sign_name
                .clone()
                .unwrap_or_else(|| self.key_version.clone()),
            signature,
        })
    }
}

// ---------------------------------------------------------------------------
// A recording checkpoint store and the shared fixtures.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RecordingStore {
    checkpoints: Mutex<Vec<SignedCheckpoint>>,
}

impl CheckpointStore for RecordingStore {
    fn append(&self, checkpoint: &SignedCheckpoint) -> Result<u64, CheckpointError> {
        let mut checkpoints = self.checkpoints.lock().expect("checkpoint store");
        checkpoints.push(checkpoint.clone());
        Ok((checkpoints.len() - 1) as u64)
    }

    fn count(&self) -> Result<u64, CheckpointError> {
        Ok(self.checkpoints.lock().expect("checkpoint store").len() as u64)
    }

    fn get(&self, index: u64) -> Result<Option<SignedCheckpoint>, CheckpointError> {
        let checkpoints = self.checkpoints.lock().expect("checkpoint store");
        Ok(checkpoints.get(index as usize).cloned())
    }
}

fn root(tag: u8, position: u64) -> [u8; 32] {
    let mut root = [tag; 32];
    root[24..].copy_from_slice(&position.to_be_bytes());
    root
}

fn sample_checkpoint(position: u64) -> Checkpoint {
    Checkpoint {
        position,
        head_root: root(0xa1, position),
        proven_root: root(0xb2, position),
        memo_root: root(0xc3, position),
    }
}

/// One variant per covered field, plus head and proven roots exchanged.
fn field_variants(base: &Checkpoint) -> Vec<(&'static str, Checkpoint)> {
    let mut position = base.clone();
    position.position += 1;
    let mut head = base.clone();
    head.head_root[31] ^= 0x01;
    let mut proven = base.clone();
    proven.proven_root[0] ^= 0x80;
    let mut memo = base.clone();
    memo.memo_root[16] ^= 0x01;
    let mut swapped = base.clone();
    swapped.head_root = base.proven_root;
    swapped.proven_root = base.head_root;
    vec![
        ("position", position),
        ("head_root", head),
        ("proven_root", proven),
        ("memo_root", memo),
        ("head_root and proven_root exchanged", swapped),
    ]
}

fn connect(fake: &Arc<FakeKms>) -> Result<KmsSigner, SignerError> {
    let config = SignerConfig::cloud_kms(ADMITTED_KEY_VERSION)
        .expect("the admitted key version is a valid CryptoKeyVersion resource name");
    KmsSigner::connect(&config, fake.client())
}

fn connected_writer(fake: &Arc<FakeKms>) -> (CheckpointWriter, Arc<RecordingStore>) {
    let signer = connect(fake)
        .unwrap_or_else(|error| panic!("an admitted ML-DSA-65 key must connect: {error:?}"));
    let store = Arc::new(RecordingStore::default());
    let writer = CheckpointWriter::new(signer, store.clone());
    (writer, store)
}

fn refused<T, E>(result: Result<T, E>, what: &str) -> E {
    match result {
        Ok(_) => panic!("{what} must be refused"),
        Err(error) => error,
    }
}

fn assert_signer_interface<S: Signer>(signer: &S) -> Algorithm {
    signer.algorithm()
}

fn fake_kms_fixture() -> serde_json::Value {
    serde_json::from_str(FAKE_KMS).expect("fake_kms.json parses")
}

fn json_str<'a>(entry: &'a serde_json::Value, key: &str) -> &'a str {
    entry[key]
        .as_str()
        .unwrap_or_else(|| panic!("fake_kms.json entry {entry} lacks the string field {key}"))
}

// ---------------------------------------------------------------------------
// Clause 1: a checkpoint signed through a KMS PQ_SIGN_ML_DSA_65 key verifies with the
// public key alone.
// ---------------------------------------------------------------------------

#[test]
fn kms_ml_dsa_65_checkpoint_verifies_with_the_public_key_alone() {
    let fake = FakeKms::admitted();
    let signer = connect(&fake)
        .unwrap_or_else(|error| panic!("an admitted ML-DSA-65 key must connect: {error:?}"));
    assert_eq!(assert_signer_interface(&signer), Algorithm::PqSignMlDsa65);
    assert_eq!(signer.key_version(), ADMITTED_KEY_VERSION);
    assert_eq!(signer.public_key(), fake.public_key_raw.as_slice());
    assert_eq!(signer.public_key().len(), ML_DSA_65_PUBLIC_KEY_LEN);
    assert!(
        fake.public_key_calls() >= 1,
        "the signer must fetch its public key from KMS at startup"
    );
    assert_eq!(fake.sign_calls(), 0, "connecting signs nothing");
    let public_key = signer.public_key().to_vec();

    let store = Arc::new(RecordingStore::default());
    let writer = CheckpointWriter::new(signer, store.clone());
    let first = sample_checkpoint(7);
    let second = sample_checkpoint(8);
    assert_eq!(writer.write(&first).expect("write the first checkpoint"), 0);
    assert_eq!(writer.write(&second).expect("write the second checkpoint"), 1);
    assert_eq!(store.count().expect("count checkpoints"), 2);
    assert_eq!(
        fake.sign_requests(),
        vec![
            (ADMITTED_KEY_VERSION.to_string(), first.signing_bytes()),
            (ADMITTED_KEY_VERSION.to_string(), second.signing_bytes()),
        ],
        "each checkpoint is signed once, by the configured key version, over its signing bytes"
    );

    // From here on nothing can reach KMS: the writer, the signer and the fake are gone.
    drop(writer);
    let spki = fake.public_key_spki.clone();
    drop(fake);

    let verifier = PublicKeyVerifier::ml_dsa_65(&public_key)
        .expect("a 1952-byte ML-DSA-65 public key builds a verifier");
    for (index, expected) in [(0u64, &first), (1, &second)] {
        let stored = store
            .get(index)
            .expect("read a checkpoint")
            .expect("the checkpoint is present");
        assert_eq!(stored.checkpoint(), expected);
        assert_eq!(stored.key_version(), ADMITTED_KEY_VERSION);
        assert_eq!(stored.algorithm(), Algorithm::PqSignMlDsa65);
        assert_eq!(stored.signature().len(), ML_DSA_65_SIGNATURE_LEN);
        assert!(
            oracle_verifies(&spki, &expected.signing_bytes(), stored.signature()),
            "an independent ML-DSA-65 verifier must accept the stored signature"
        );
        verifier
            .verify(&stored)
            .expect("the stored checkpoint verifies with the public key alone");
        let bytes = stored.to_bytes();
        assert_eq!(
            SignedCheckpoint::from_bytes(&bytes).expect("decode a signed checkpoint"),
            stored
        );
        assert_eq!(
            &verifier
                .verify_bytes(&bytes)
                .expect("the encoded checkpoint verifies with the public key alone"),
            expected
        );
    }
}

#[test]
fn checkpoint_signing_bytes_are_domain_separated_and_cover_every_field() {
    assert_eq!(CHECKPOINT_SIGNING_DOMAIN, "velenza-inarch.checkpoint.v1");
    let base = sample_checkpoint(42);
    let bytes = base.signing_bytes();
    assert!(
        bytes.starts_with(CHECKPOINT_SIGNING_DOMAIN.as_bytes()),
        "the signed bytes begin with the checkpoint signing domain"
    );
    assert_eq!(bytes, base.clone().signing_bytes(), "signing bytes are deterministic");
    for (field, variant) in field_variants(&base) {
        assert_ne!(
            variant.signing_bytes(),
            bytes,
            "changing {field} must change the signed bytes"
        );
    }
}

#[test]
fn tampered_checkpoints_and_foreign_signatures_fail_verification() {
    let fake = FakeKms::admitted();
    let (writer, store) = connected_writer(&fake);
    let checkpoint = sample_checkpoint(11);
    writer.write(&checkpoint).expect("write a checkpoint");
    let stored = store
        .get(0)
        .expect("read a checkpoint")
        .expect("the checkpoint is present");
    let verifier = PublicKeyVerifier::ml_dsa_65(&fake.public_key_raw).expect("build a verifier");
    verifier
        .verify(&stored)
        .expect("the untampered checkpoint verifies");

    for (field, variant) in field_variants(&checkpoint) {
        let forged =
            SignedCheckpoint::from_parts(variant, ADMITTED_KEY_VERSION, stored.signature().to_vec())
                .expect("well-formed parts");
        assert!(
            matches!(verifier.verify(&forged), Err(CheckpointError::SignatureInvalid)),
            "a checkpoint with a changed {field} must not verify under the original signature"
        );
    }

    let impostor = generate_ml_dsa_65();
    let foreign = ml_dsa_65_sign(&impostor, &checkpoint.signing_bytes());
    let forged = SignedCheckpoint::from_parts(checkpoint.clone(), ADMITTED_KEY_VERSION, foreign)
        .expect("well-formed parts");
    assert!(
        matches!(verifier.verify(&forged), Err(CheckpointError::SignatureInvalid)),
        "a genuine ML-DSA-65 signature by another key must not verify"
    );

    let impostor_verifier = PublicKeyVerifier::ml_dsa_65(&raw_public_key(&spki_der(&impostor)))
        .expect("build a verifier for an unrelated key");
    assert!(
        matches!(impostor_verifier.verify(&stored), Err(CheckpointError::SignatureInvalid)),
        "an unrelated public key must not verify the checkpoint"
    );

    let mut flipped = stored.signature().to_vec();
    flipped[100] ^= 0x01;
    let forged = SignedCheckpoint::from_parts(checkpoint.clone(), ADMITTED_KEY_VERSION, flipped)
        .expect("well-formed parts");
    assert!(
        matches!(verifier.verify(&forged), Err(CheckpointError::SignatureInvalid)),
        "a signature with one flipped bit must not verify"
    );

    let truncated = stored.signature()[..ML_DSA_65_SIGNATURE_LEN - 1].to_vec();
    match SignedCheckpoint::from_parts(checkpoint.clone(), ADMITTED_KEY_VERSION, truncated) {
        Err(CheckpointError::Malformed(_)) => {}
        Ok(forged) => assert!(
            matches!(
                verifier.verify(&forged),
                Err(CheckpointError::SignatureInvalid | CheckpointError::Malformed(_))
            ),
            "a truncated signature must not verify"
        ),
        Err(other) => panic!("a truncated signature must be malformed or invalid: {other:?}"),
    }

    assert!(
        matches!(
            SignedCheckpoint::from_parts(checkpoint.clone(), ADMITTED_KEY_VERSION, Vec::new()),
            Err(CheckpointError::Unsigned)
        ),
        "a checkpoint without a signature cannot be formed"
    );

    let bytes = stored.to_bytes();
    let mut trailing = bytes.clone();
    trailing.push(0);
    let shortened = bytes[..bytes.len() - 1].to_vec();
    for (label, candidate) in [
        ("a trailing byte", trailing),
        ("a truncated encoding", shortened),
        ("an empty encoding", Vec::new()),
    ] {
        assert!(
            matches!(
                SignedCheckpoint::from_bytes(&candidate),
                Err(CheckpointError::Malformed(_))
            ),
            "{label} must be refused as malformed"
        );
        assert!(
            matches!(
                verifier.verify_bytes(&candidate),
                Err(CheckpointError::Malformed(_))
            ),
            "{label} must not verify"
        );
    }
}

#[test]
fn verifier_holds_only_an_ml_dsa_65_public_key() {
    let real = raw_public_key(&spki_der(&generate_ml_dsa_65()));
    assert!(
        PublicKeyVerifier::ml_dsa_65(&real).is_ok(),
        "a 1952-byte NIST_PQC ML-DSA-65 public key is accepted"
    );
    let mut one_short = real.clone();
    one_short.pop();
    let mut one_long = real.clone();
    one_long.push(0);
    // [pqc-reference-only]: the classical names below are rejection-test inputs this contract must refuse
    let refused_keys: [(&str, Vec<u8>); 8] = [
        ("an empty key", Vec::new()),
        ("a 32-byte Ed25519-sized key", vec![0x42; 32]),
        ("a private-key-sized blob", vec![0x42; ML_DSA_65_PRIVATE_KEY_LEN]),
        ("an ML-DSA-44-sized public key", vec![0x42; 1312]),
        ("an ML-DSA-87-sized public key", vec![0x42; 2592]),
        ("a SubjectPublicKeyInfo instead of NIST_PQC bytes", spki_from_raw(&real)),
        ("a key one byte short", one_short),
        ("a key one byte long", one_long),
    ];
    for (label, key) in refused_keys {
        assert!(
            matches!(
                PublicKeyVerifier::ml_dsa_65(&key),
                Err(CheckpointError::PublicKeyRejected(_))
            ),
            "{label} must be refused as an ML-DSA-65 public key"
        );
    }
}

#[test]
fn ml_dsa_65_spki_prefix_matches_the_oracle_encoding() {
    let key_pair = generate_ml_dsa_65();
    let spki = spki_der(&key_pair);
    assert_eq!(&spki[..ML_DSA_65_SPKI_PREFIX.len()], &ML_DSA_65_SPKI_PREFIX[..]);
    let raw = raw_public_key(&spki);
    assert_eq!(spki_from_raw(&raw), spki);

    let message = b"oracle self-check";
    let signature = ml_dsa_65_sign(&key_pair, message);
    assert_eq!(signature.len(), ML_DSA_65_SIGNATURE_LEN);
    assert!(oracle_verifies(&spki, message, &signature));
    let mut flipped = signature.clone();
    flipped[0] ^= 0x01;
    assert!(
        !oracle_verifies(&spki, message, &flipped),
        "the oracle must be able to fail"
    );
    assert!(!oracle_verifies(&spki, b"another message", &signature));
}

#[test]
fn admitted_algorithm_set_is_exactly_ml_dsa_65() {
    let algorithm = Algorithm::PqSignMlDsa65;
    // An exhaustive single-arm match: admitting a second algorithm breaks this test.
    let kms_name = match algorithm {
        Algorithm::PqSignMlDsa65 => ADMITTED_ALGORITHM,
    };
    assert_eq!(algorithm.kms_name(), kms_name);
}

// ---------------------------------------------------------------------------
// Clause 2: an EC_SIGN_*, RSA_SIGN_* or Ed25519 key, or a local signer, refuses at startup.
// ---------------------------------------------------------------------------

#[test]
fn classical_and_unadmitted_kms_keys_refuse_at_startup_before_any_sign_call() {
    let fixture = fake_kms_fixture();
    let admitted = &fixture["admitted"];
    assert_eq!(json_str(admitted, "name"), ADMITTED_KEY_VERSION);
    assert_eq!(json_str(admitted, "algorithm"), ADMITTED_ALGORITHM);
    assert_eq!(json_str(admitted, "protection_level"), ADMITTED_PROTECTION_LEVEL);
    assert_eq!(json_str(admitted, "public_key_format"), NIST_PQC);
    assert_eq!(
        admitted["public_key_len"].as_u64(),
        Some(ML_DSA_65_PUBLIC_KEY_LEN as u64)
    );
    assert_eq!(
        admitted["signature_len"].as_u64(),
        Some(ML_DSA_65_SIGNATURE_LEN as u64)
    );

    let entries = fixture["refused_at_startup"]
        .as_array()
        .expect("refused_at_startup is an array");
    // [pqc-reference-only]: the classical names below are rejection-test inputs this contract must refuse
    for required in [
        "EC_SIGN_P256_SHA256",
        "EC_SIGN_ED25519",
        "RSA_SIGN_PSS_2048_SHA256",
        "RSA_SIGN_PKCS1_2048_SHA256",
    ] {
        assert!(
            entries
                .iter()
                .any(|entry| entry["algorithm"] == required && entry["refusal"] == "classical_key"),
            "fake_kms.json must refuse {required} as a classical key"
        );
    }
    for refusal in ["classical_key", "algorithm_not_admitted", "protection_level"] {
        assert!(
            entries.iter().any(|entry| entry["refusal"] == refusal),
            "fake_kms.json must exercise the {refusal} refusal"
        );
    }

    for entry in entries {
        let algorithm = json_str(entry, "algorithm");
        let protection_level = json_str(entry, "protection_level");
        let refusal = json_str(entry, "refusal");
        let fake = FakeKms::new(FakeSpec {
            algorithm: algorithm.to_string(),
            protection_level: protection_level.to_string(),
            ..FakeSpec::admitted()
        });
        let error = refused(
            connect(&fake),
            &format!("a {algorithm:?} key at protection level {protection_level:?}"),
        );
        let expected = match refusal {
            "classical_key" => matches!(
                &error,
                SignerError::ClassicalKeyRefused { algorithm: named } if named == algorithm
            ),
            "algorithm_not_admitted" => matches!(
                &error,
                SignerError::AlgorithmNotAdmitted { algorithm: named } if named == algorithm
            ),
            "protection_level" => matches!(
                &error,
                SignerError::ProtectionLevelRefused { protection_level: named }
                    if named == protection_level
            ),
            other => panic!("fake_kms.json names an unknown refusal {other:?}"),
        };
        assert!(
            expected,
            "{algorithm:?} at {protection_level:?} must be refused as {refusal}: {error:?}"
        );
        assert_eq!(
            fake.sign_calls(),
            0,
            "a refused key must never be asked to sign: {algorithm:?} at {protection_level:?}"
        );
    }
}

#[test]
fn local_and_unsigned_signer_configurations_refuse_at_startup() {
    let config = SignerConfig::from_settings("cloud-kms", ADMITTED_KEY_VERSION)
        .expect("the cloud-kms backend with a key version is the admitted configuration");
    assert_eq!(config.key_version(), ADMITTED_KEY_VERSION);

    let fixture = fake_kms_fixture();
    let local = fixture["local_backends"]
        .as_array()
        .expect("local_backends is an array");
    // [pqc-reference-only]: the classical names below are rejection-test inputs this contract must refuse
    for required in ["local", "file", "pkcs8", "ed25519", "ecdsa", "rsa"] {
        assert!(
            local.iter().any(|entry| entry["backend"] == required),
            "fake_kms.json must list the local backend {required:?}"
        );
    }
    for entry in local {
        let backend = json_str(entry, "backend");
        let error = refused(
            SignerConfig::from_settings(backend, ADMITTED_KEY_VERSION),
            &format!("the local signer backend {backend:?}"),
        );
        assert!(
            matches!(&error, SignerError::LocalSignerRefused { backend: named } if named == backend),
            "the local signer backend {backend:?} must be refused at startup: {error:?}"
        );
    }

    let unsigned = fixture["unsigned_backends"]
        .as_array()
        .expect("unsigned_backends is an array");
    for required in ["", "none", "unsigned", "disabled"] {
        assert!(
            unsigned.iter().any(|value| value.as_str() == Some(required)),
            "fake_kms.json must list the unsigned backend {required:?}"
        );
    }
    for value in unsigned {
        let backend = value.as_str().expect("unsigned backends are strings");
        let error = refused(
            SignerConfig::from_settings(backend, ADMITTED_KEY_VERSION),
            &format!("the unsigned configuration {backend:?}"),
        );
        assert!(
            matches!(error, SignerError::SignerRequired),
            "running without a signer must be refused: {backend:?} gave {error:?}"
        );
    }
}

#[test]
fn kms_key_resource_must_name_one_crypto_key_version() {
    let config = SignerConfig::cloud_kms(ADMITTED_KEY_VERSION).expect("a CryptoKeyVersion name");
    assert_eq!(config.key_version(), ADMITTED_KEY_VERSION);

    let invalid = [
        "projects/example-proj/locations/global/keyRings/ledger/cryptoKeys/checkpoint",
        "projects/example-proj/locations/global/keyRings/ledger/cryptoKeys/checkpoint/cryptoKeyVersions/",
        "projects/example-proj/locations/global/keyRings/ledger/cryptoKeys/checkpoint/cryptoKeyVersions/1/",
        "projects//locations/global/keyRings/ledger/cryptoKeys/checkpoint/cryptoKeyVersions/1",
        "projects/example-proj/locations/global/keyRings/ledger/cryptoKeys/checkpoint/versions/1",
        " projects/example-proj/locations/global/keyRings/ledger/cryptoKeys/checkpoint/cryptoKeyVersions/1",
        "keys/checkpoint.pem",
        "file:checkpoint.pem",
        "",
    ];
    for key in invalid {
        let error = refused(SignerConfig::cloud_kms(key), &format!("the key resource {key:?}"));
        assert!(
            matches!(&error, SignerError::InvalidKeyResource { key: named } if named == key),
            "{key:?} does not name one CryptoKeyVersion: {error:?}"
        );
        let error = refused(
            SignerConfig::from_settings("cloud-kms", key),
            &format!("the cloud-kms backend with {key:?}"),
        );
        assert!(
            matches!(&error, SignerError::InvalidKeyResource { key: named } if named == key),
            "{key:?} does not name one CryptoKeyVersion: {error:?}"
        );
    }
}

#[test]
fn kms_public_key_that_is_not_ml_dsa_65_or_names_another_version_refuses_at_startup() {
    let spki = spki_der(&generate_ml_dsa_65());
    for (label, data) in [
        ("an empty public key", Vec::new()),
        ("a 32-byte public key", vec![0x42u8; 32]),
        ("a private-key-sized blob", vec![0x42u8; ML_DSA_65_PRIVATE_KEY_LEN]),
        ("a SubjectPublicKeyInfo instead of NIST_PQC bytes", spki),
    ] {
        let fake = FakeKms::new(FakeSpec {
            public_key_data: Some(data),
            ..FakeSpec::admitted()
        });
        let error = refused(connect(&fake), &format!("KMS serving {label}"));
        assert!(
            matches!(error, SignerError::PublicKeyRejected(_)),
            "KMS serving {label} must be refused at startup: {error:?}"
        );
        assert_eq!(fake.sign_calls(), 0);
    }

    let fake = FakeKms::new(FakeSpec {
        public_key_format: "PEM".to_string(),
        ..FakeSpec::admitted()
    });
    let error = refused(connect(&fake), "a public key in a format other than NIST_PQC");
    assert!(
        matches!(error, SignerError::PublicKeyRejected(_)),
        "a public key in a format other than NIST_PQC must be refused: {error:?}"
    );
    assert_eq!(fake.sign_calls(), 0);

    let fake = FakeKms::new(FakeSpec {
        public_key_name: Some(OTHER_KEY_VERSION.to_string()),
        ..FakeSpec::admitted()
    });
    let error = refused(connect(&fake), "a public key that names another key version");
    assert!(
        matches!(
            &error,
            SignerError::KeyVersionMismatch { expected, actual }
                if expected == ADMITTED_KEY_VERSION && actual == OTHER_KEY_VERSION
        ),
        "a public key for another key version must be refused: {error:?}"
    );
    assert_eq!(fake.sign_calls(), 0);
}

// ---------------------------------------------------------------------------
// Clause 3: with the cloudkms.googleapis.com route blocked no unsigned checkpoint is written.
// ---------------------------------------------------------------------------

#[test]
fn blocked_kms_route_writes_no_checkpoint_and_consults_no_fallback() {
    let fake = FakeKms::admitted();
    let (writer, store) = connected_writer(&fake);
    let first = sample_checkpoint(20);
    let second = sample_checkpoint(21);
    assert_eq!(writer.write(&first).expect("write while KMS is reachable"), 0);

    fake.set_route_blocked(true);
    let attempts_before = fake.sign_calls();
    let error = refused(
        writer.write(&second),
        "writing a checkpoint while the KMS route is blocked",
    );
    assert!(
        matches!(
            error,
            CheckpointError::Signer(SignerError::KmsUnreachable(_))
        ),
        "a blocked KMS route must fail the write: {error:?}"
    );
    assert!(
        fake.sign_calls() > attempts_before,
        "the writer must have asked KMS, and only KMS, to sign"
    );
    assert_eq!(
        store.count().expect("count checkpoints"),
        1,
        "no unsigned checkpoint is written"
    );
    assert!(store.get(1).expect("read index 1").is_none());
    assert_eq!(
        store
            .get(0)
            .expect("read index 0")
            .expect("the first checkpoint is present")
            .checkpoint(),
        &first
    );

    let error = refused(
        writer.write(&second),
        "writing again while the KMS route is still blocked",
    );
    assert!(
        matches!(
            error,
            CheckpointError::Signer(SignerError::KmsUnreachable(_))
        ),
        "a blocked KMS route must keep failing the write: {error:?}"
    );
    assert_eq!(store.count().expect("count checkpoints"), 1);

    fake.set_route_blocked(false);
    assert_eq!(
        writer
            .write(&second)
            .expect("once KMS is reachable the checkpoint is signed and written"),
        1
    );
    let verifier = PublicKeyVerifier::ml_dsa_65(&fake.public_key_raw).expect("build a verifier");
    for index in 0..2 {
        let stored = store
            .get(index)
            .expect("read a checkpoint")
            .expect("the checkpoint is present");
        verifier
            .verify(&stored)
            .expect("every stored checkpoint carries a KMS ML-DSA-65 signature");
    }
}

#[test]
fn blocked_kms_route_at_startup_yields_no_signer() {
    let fake = FakeKms::admitted();
    fake.set_route_blocked(true);
    let error = refused(
        connect(&fake),
        "connecting while the KMS route is blocked",
    );
    assert!(
        matches!(error, SignerError::KmsUnreachable(_)),
        "a blocked KMS route at startup must yield no signer: {error:?}"
    );
    assert!(fake.public_key_calls() >= 1, "startup must try KMS");
    assert_eq!(fake.sign_calls(), 0);
}

#[test]
fn kms_failures_and_invalid_signatures_never_reach_the_store() {
    let fake = FakeKms::admitted();
    let (writer, store) = connected_writer(&fake);
    fake.reject_sign.store(true, Ordering::SeqCst);
    let error = refused(writer.write(&sample_checkpoint(30)), "a KMS sign rejection");
    assert!(
        matches!(
            &error,
            CheckpointError::Signer(SignerError::KmsRejected { status: 400, .. })
        ),
        "a KMS rejection must fail the write: {error:?}"
    );
    assert_eq!(store.count().expect("count checkpoints"), 0);

    let fake = FakeKms::admitted();
    let (writer, store) = connected_writer(&fake);
    fake.sign_with_impostor.store(true, Ordering::SeqCst);
    let error = refused(
        writer.write(&sample_checkpoint(31)),
        "a signature that does not verify under the startup public key",
    );
    assert!(
        matches!(
            error,
            CheckpointError::Signer(SignerError::SignatureRejected(_))
        ),
        "a signature by another key must be rejected before the write: {error:?}"
    );
    assert_eq!(store.count().expect("count checkpoints"), 0);

    let fake = FakeKms::new(FakeSpec {
        sign_name: Some(OTHER_KEY_VERSION.to_string()),
        ..FakeSpec::admitted()
    });
    let (writer, store) = connected_writer(&fake);
    let error = refused(
        writer.write(&sample_checkpoint(32)),
        "a signature attributed to another key version",
    );
    assert!(
        matches!(
            &error,
            CheckpointError::Signer(SignerError::KeyVersionMismatch { expected, actual })
                if expected == ADMITTED_KEY_VERSION && actual == OTHER_KEY_VERSION
        ),
        "a signature from another key version must be rejected: {error:?}"
    );
    assert_eq!(store.count().expect("count checkpoints"), 0);
}

// ---------------------------------------------------------------------------
// Clause 4: a dated check of the KMS release notes records PQ_SIGN_ML_DSA_65 as GA.
// ---------------------------------------------------------------------------

fn toml_str<'a>(table: &'a toml::Table, key: &str) -> Option<&'a str> {
    table.get(key).and_then(toml::Value::as_str)
}

fn toml_strings(table: &toml::Table, key: &str) -> Vec<String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn toml_tables<'a>(table: &'a toml::Table, key: &str) -> Result<Vec<&'a toml::Table>, String> {
    let values = table
        .get(key)
        .and_then(toml::Value::as_array)
        .ok_or_else(|| format!("missing [[{key}]]"))?;
    values
        .iter()
        .map(|value| {
            value
                .as_table()
                .ok_or_else(|| format!("a [[{key}]] entry is not a table"))
        })
        .collect()
}

fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let digits = bytes
        .iter()
        .enumerate()
        .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit());
    if !digits {
        return false;
    }
    let month: u32 = value[5..7].parse().unwrap_or(0);
    let day: u32 = value[8..10].parse().unwrap_or(0);
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

fn dated_quote(entry: &toml::Table) -> Result<&str, String> {
    let subject = toml_str(entry, "subject").ok_or("a record has no subject")?;
    let measured_on = toml_str(entry, "measured_on")
        .ok_or_else(|| format!("{subject}: missing measured_on"))?;
    if !is_iso_date(measured_on) {
        return Err(format!("{subject}: measured_on {measured_on:?} is not YYYY-MM-DD"));
    }
    let source = toml_str(entry, "source").ok_or_else(|| format!("{subject}: missing source"))?;
    if !source.starts_with("https://docs.cloud.google.com/kms/docs/") {
        return Err(format!("{subject}: {source:?} is not official Cloud KMS documentation"));
    }
    let quote = toml_str(entry, "quote").ok_or_else(|| format!("{subject}: missing quote"))?;
    if quote.trim().is_empty() || quote.chars().count() > 200 {
        return Err(format!("{subject}: the quote must be a short verbatim excerpt"));
    }
    Ok(measured_on)
}

fn validate_launch_stage(text: &str) -> Result<(), String> {
    let table: toml::Table = toml::from_str(text).map_err(|error| format!("parse: {error}"))?;
    if toml_str(&table, "schema") != Some("inarch.kms-launch-stage.v1") {
        return Err("schema is not inarch.kms-launch-stage.v1".to_string());
    }
    let measurements = toml_tables(&table, "measurement")?;
    let excluded = toml_tables(&table, "excluded")?;
    for entry in measurements.iter().chain(excluded.iter()) {
        dated_quote(entry)?;
    }

    let algorithm = measurements
        .iter()
        .find(|entry| {
            toml_str(entry, "kind") == Some("algorithm")
                && toml_str(entry, "subject") == Some(ADMITTED_ALGORITHM)
        })
        .ok_or("no algorithm record for PQ_SIGN_ML_DSA_65")?;
    let measured_on = dated_quote(algorithm)?;
    if toml_str(algorithm, "launch_stage") != Some("GA") {
        return Err("PQ_SIGN_ML_DSA_65 is not recorded as GA".to_string());
    }
    if !toml_str(algorithm, "source")
        .is_some_and(|source| source.starts_with("https://docs.cloud.google.com/kms/docs/release-notes"))
    {
        return Err("the GA record does not cite the Cloud KMS release notes".to_string());
    }
    if !toml_str(algorithm, "quote").is_some_and(|quote| quote.contains("General Availability")) {
        return Err("the GA record does not quote General Availability".to_string());
    }
    let release_note_date = toml_str(algorithm, "release_note_date")
        .filter(|date| is_iso_date(date))
        .ok_or("the GA record has no dated release note")?;
    if release_note_date > measured_on {
        return Err("the release note is dated after the measurement".to_string());
    }
    if !toml_strings(algorithm, "listed").iter().any(|name| name == ADMITTED_ALGORITHM) {
        return Err("the GA release note list does not include PQ_SIGN_ML_DSA_65".to_string());
    }

    let level = measurements
        .iter()
        .find(|entry| {
            toml_str(entry, "kind") == Some("protection_level")
                && toml_str(entry, "subject") == Some(ADMITTED_PROTECTION_LEVEL)
                && toml_str(entry, "algorithm") == Some(ADMITTED_ALGORITHM)
        })
        .ok_or("no SOFTWARE protection level record for PQ_SIGN_ML_DSA_65")?;
    if !toml_strings(level, "available").iter().any(|name| name == "software") {
        return Err("the algorithms table does not list the software protection level".to_string());
    }

    for entry in &excluded {
        if toml_str(entry, "launch_stage").is_none_or(|stage| stage == "GA") {
            return Err("an excluded feature must carry its non-GA launch stage".to_string());
        }
        if entry.get("used_by_signer").and_then(toml::Value::as_bool) != Some(false) {
            return Err("the signer must not use an excluded pre-GA feature".to_string());
        }
    }
    Ok(())
}

#[test]
fn kms_launch_stage_record_shows_ml_dsa_65_ga_at_the_software_level() {
    validate_launch_stage(KMS_LAUNCH_STAGE)
        .unwrap_or_else(|problem| panic!("kms_launch_stage.toml: {problem}"));
}

#[test]
fn kms_launch_stage_validator_refuses_preview_undated_or_unquoted_records() {
    // [pqc-reference-only]: the pre-GA launch stages below are rejection-test inputs this contract must refuse
    let mutations = [
        (
            "an algorithm record that is not GA",
            "launch_stage = \"GA\"",
            "launch_stage = \"PREVIEW\"",
        ),
        (
            "an algorithm record for another algorithm",
            "subject = \"PQ_SIGN_ML_DSA_65\"",
            "subject = \"PQ_SIGN_ML_DSA_87\"",
        ),
        (
            "an impossible measurement date",
            "measured_on = \"2026-10-23\"",
            "measured_on = \"2026-13-40\"",
        ),
        (
            "an undated record",
            "measured_on = \"2026-10-23\"",
            "measured_at = \"2026-10-23\"",
        ),
        (
            "an unquoted record",
            "quote = \"Cloud KMS supports the following post-quantum computing (PQC) signing algorithms in General Availability:\"",
            "quote = \"\"",
        ),
        (
            "a quote that does not say General Availability",
            "in General Availability:",
            "in Preview:",
        ),
        (
            "a source that is not https",
            "source = \"https://docs.cloud.google.com/kms/docs/release-notes\"",
            "source = \"http://docs.cloud.google.com/kms/docs/release-notes\"",
        ),
        (
            "a release note dated after the measurement",
            "release_note_date = \"2026-07-16\"",
            "release_note_date = \"2026-12-31\"",
        ),
        (
            "a protection level other than software",
            "available = [\"software\"]",
            "available = [\"hsm\"]",
        ),
        (
            "an excluded pre-GA feature the signer uses",
            "used_by_signer = false",
            "used_by_signer = true",
        ),
    ];
    for (label, from, to) in mutations {
        assert!(
            KMS_LAUNCH_STAGE.contains(from),
            "the mutation for {label} no longer matches kms_launch_stage.toml: {from:?}"
        );
        let mutated = KMS_LAUNCH_STAGE.replacen(from, to, 1);
        assert!(
            validate_launch_stage(&mutated).is_err(),
            "the launch-stage validator must refuse {label}"
        );
    }
}

#[test]
fn test_code_steps_name_every_live_test() {
    let table: toml::Table = toml::from_str(TEST_CODE_STEPS).expect("test_code_steps.toml parses");
    assert_eq!(
        toml_str(&table, "schema"),
        Some("inarch.checkpoint-test-code-steps.v1")
    );
    let steps = toml_tables(&table, "step").expect("test_code_steps.toml lists [[step]] entries");
    for step in &steps {
        for key in ["id", "command", "setup", "passes_when"] {
            assert!(
                toml_str(step, key).is_some_and(|value| !value.trim().is_empty()),
                "every step needs a non-empty {key}"
            );
        }
        assert!(!toml_strings(step, "clauses").is_empty(), "every step names its clauses");
    }

    let in_process = steps
        .iter()
        .find(|step| toml_str(step, "id") == Some("in-process-contract"))
        .expect("an in-process step");
    assert_eq!(
        toml_str(in_process, "command"),
        Some("cargo test -p inarch-store --test checkpoint_signer_test")
    );
    assert!(toml_strings(in_process, "env").is_empty());

    for (test, env_names) in [
        (LIVE_SIGN_TEST, &[LIVE_KEY_ENV][..]),
        (LIVE_ROUTE_BLOCKED_TEST, &[LIVE_KEY_ENV, LIVE_ROUTE_BLOCKED_ENV][..]),
    ] {
        let suffix = format!("--ignored --exact {test}");
        let step = steps
            .iter()
            .find(|step| toml_str(step, "command").is_some_and(|command| command.ends_with(&suffix)))
            .unwrap_or_else(|| panic!("no test-code step runs {test}"));
        let declared = toml_strings(step, "env");
        for name in env_names {
            assert!(
                declared.iter().any(|value| value == name),
                "the step for {test} must declare {name}"
            );
        }
    }

    for clause in [
        CLAUSE_VERIFIES,
        CLAUSE_REFUSED,
        CLAUSE_ROUTE_BLOCKED,
        CLAUSE_GA_RECORD,
    ] {
        assert!(
            steps
                .iter()
                .any(|step| toml_strings(step, "clauses").iter().any(|name| name == clause)),
            "no test-code step covers {clause}"
        );
    }
}

// ---------------------------------------------------------------------------
// Live Cloud KMS checks. Ignored by default; test_code_steps.toml lists how to run them.
// ---------------------------------------------------------------------------

fn required_env(name: &str, test: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => panic!("{test} needs {name}; see fixtures/checkpoint/test_code_steps.toml"),
    }
}

fn live_signer_config(test: &str) -> SignerConfig {
    let key_version = required_env(LIVE_KEY_ENV, test);
    SignerConfig::cloud_kms(&key_version)
        .unwrap_or_else(|error| panic!("{LIVE_KEY_ENV} must name one CryptoKeyVersion: {error:?}"))
}

fn live_client() -> Arc<dyn KmsClient> {
    Arc::new(
        CloudKmsClient::new()
            .unwrap_or_else(|error| panic!("construct the Cloud KMS client: {error:?}")),
    )
}

#[test]
#[ignore = "live Cloud KMS: needs INARCH_TEST_KMS_PQ_KEY and Google credentials"]
fn live_kms_signed_checkpoint_verifies_with_the_public_key_alone() {
    let config = live_signer_config(LIVE_SIGN_TEST);
    let signer = KmsSigner::connect(&config, live_client())
        .unwrap_or_else(|error| panic!("connect to the live ML-DSA-65 key: {error:?}"));
    assert_eq!(signer.algorithm(), Algorithm::PqSignMlDsa65);
    let public_key = signer.public_key().to_vec();
    assert_eq!(public_key.len(), ML_DSA_65_PUBLIC_KEY_LEN);

    let store = Arc::new(RecordingStore::default());
    let writer = CheckpointWriter::new(signer, store.clone());
    let checkpoint = sample_checkpoint(1);
    assert_eq!(writer.write(&checkpoint).expect("live KMS signs the checkpoint"), 0);
    drop(writer);

    let stored = store
        .get(0)
        .expect("read the checkpoint")
        .expect("the checkpoint is present");
    assert_eq!(stored.key_version(), config.key_version());
    assert_eq!(stored.signature().len(), ML_DSA_65_SIGNATURE_LEN);
    assert!(
        oracle_verifies(
            &spki_from_raw(&public_key),
            &checkpoint.signing_bytes(),
            stored.signature()
        ),
        "an independent ML-DSA-65 verifier must accept the live KMS signature"
    );
    let verifier = PublicKeyVerifier::ml_dsa_65(&public_key).expect("build a verifier");
    assert_eq!(
        verifier
            .verify_bytes(&stored.to_bytes())
            .expect("the live checkpoint verifies with the public key alone"),
        checkpoint
    );
}

#[test]
#[ignore = "live Cloud KMS with cloudkms.googleapis.com blocked: needs INARCH_TEST_KMS_PQ_KEY and INARCH_TEST_KMS_ROUTE_BLOCKED=1"]
fn live_kms_route_blocked_writes_no_checkpoint() {
    assert_eq!(
        required_env(LIVE_ROUTE_BLOCKED_ENV, LIVE_ROUTE_BLOCKED_TEST),
        "1",
        "set {LIVE_ROUTE_BLOCKED_ENV}=1 only after blocking the route"
    );
    let config = live_signer_config(LIVE_ROUTE_BLOCKED_TEST);
    let error = refused(
        KmsSigner::connect(&config, live_client()),
        "connecting while cloudkms.googleapis.com is blocked",
    );
    assert!(
        matches!(error, SignerError::KmsUnreachable(_)),
        "a blocked KMS route must yield no signer, and so no writer and no checkpoint: {error:?}"
    );
}
