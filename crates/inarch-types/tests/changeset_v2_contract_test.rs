//! Contract tests for the Changeset v2 and Entry schema of the Ledger Landing design
//! ("Changeset and Entry contract v2: canonical encoding, W/R/deps, states and edge kinds").
//!
//! The suite is written before the implementation. Every public item it uses lives in
//! `inarch_types::changeset_v2`, so this test target does not compile until that module lands.
//!
//! # Public contract pinned by this suite
//!
//! * `SCHEMA_VERSION: u64` is 2. `ID_CONTEXT: &str` is the BLAKE3 key-derivation context of
//!   changeset v2 ids. It is a constant of `changeset_v2`, not an `ObjectDomain` variant.
//! * `ChangesetV2Id` and `PublicationId` are typed ids over `ObjectHash`; `Author` and `SymbolId`
//!   are string newtypes with `new` and `as_str`.
//! * `ChangesetV2Submission` is the client form of a changeset and has no author field.
//!   `ChangesetV2` is the same record stamped by the server with the IdP-bound `Author`;
//!   its `id()` is the BLAKE3 digest of its canonical bytes under `ID_CONTEXT`.
//! * `Entry` is the ledger record: position, changeset id, state, witnesses, edges, head root
//!   and optional checkpoint index.
//! * The canonical encoding is the deterministic serialization of a `CanonicalValue` tree.
//!   The tree layer is public so refusal cases are built by editing a valid value rather than
//!   by hand-assembling bytes. A changeset or entry value is a `Map` whose keys are the field
//!   names; every field is always present except `Entry::checkpoint_index`, which is omitted
//!   when `None`. The keys this suite names are `version` (all three objects), `author`
//!   (stamped changeset only), `state` and `checkpoint_index` (entry). The refusal fixtures
//!   assume the stamped changeset keys are exactly `version`, `author`, `base`, `delta`,
//!   `writes`, `reads`, `deps`, `resolves`, `hints` and `class` (a submission has the same keys
//!   without `author`), and the entry keys are exactly `version`, `position`, `changeset_id`,
//!   `state`, `witnesses`, `edges`, `head_root` and the optional `checkpoint_index`.
//! * Every public record, enum and id derives `Debug`, `Clone`, `PartialEq` and `Eq`. Ids, enums
//!   and every record stored in a set or used as a map key (`SymbolId`, `PointRead`,
//!   `PredicateRead`, `BehaviorRead`, `Witness`, `Edge`) also derive `PartialOrd`, `Ord` and
//!   `Hash`; ids and enums also derive `Copy`. `EntryState` and `EdgeKind` are not
//!   `#[non_exhaustive]`, because this suite matches them exhaustively.
//! * Decoders: `ChangesetV2Submission::decode_canonical(bytes: &[u8], head: u64)`,
//!   `ChangesetV2::decode_canonical(bytes: &[u8])`, `Entry::decode_canonical(bytes: &[u8])` and
//!   `CanonicalValue::decode(bytes: &[u8])`, each returning `Result<_, DecodeError>`. The
//!   decoders check structure only: they do no cross-field or position-consistency check
//!   (for example `writes` need not match `delta`, and a witness or edge target need not be an
//!   existing position), except that a log-position base must not exceed `head`.
//! * Encoders: `encode_canonical()` and `to_canonical_value()` on the three record types and
//!   `CanonicalValue::encode()`; `ChangesetV2::from_submission(submission, author)` stamps a
//!   submission; `ChangesetV2Id::from_canonical_bytes`, `to_hex` and `from_hex` follow the
//!   typed-id convention of `inarch_types::hash`.
//! * `CanonicalValue` has the variants `Uint(u64)`, `Text(String)`, `List(Vec<CanonicalValue>)`
//!   and `Map(BTreeMap<String, CanonicalValue>)`, plus any further variants the encoding needs.
//! * `DecodeError` has the variants `UnknownField(String)`, `UnknownState(String)`,
//!   `UnknownEdgeKind(String)`, `ClientSuppliedAuthor`, `UnsupportedVersion(u64)`,
//!   `MissingField(String)` and `BaseBeyondHead { base, head }`, plus any variants for malformed
//!   input.
//! * `EntryState::ALL: [EntryState; 7]` and `EdgeKind::ALL: [EdgeKind; 4]` list the variants in
//!   the order of the design, and `wire_name(self) -> &'static str` and
//!   `from_wire_name(&str) -> Result<Self, DecodeError>` convert to and from
//!   the exact wire spelling. A state and an edge kind are encoded as `Text` of that spelling.
//! * A submission value that carries an `author` member is refused with `ClientSuppliedAuthor`,
//!   never with `UnknownField`; any other unrecognized top-level member is `UnknownField`.
//!
//! Fixtures live in `tests/vectors/changeset_v2/`: `vectors.json` holds the golden changeset
//! descriptions and `refusals.json` holds the refusal inputs.

use std::collections::{BTreeMap, BTreeSet};

use inarch_types::bonsai::{FileChange, FileType};
use inarch_types::changeset_v2::{
    AgentReceipt, Author, Base, BehaviorRead, CanonicalValue, ChangesetClass, ChangesetV2,
    ChangesetV2Id, ChangesetV2Submission, DecodeError, Edge, EdgeKind, Entry, EntryState,
    FileChangeV2,
};
use inarch_types::changeset_v2::{
    ID_CONTEXT, OperatorClass, OperatorDelta, PointRead, PredicateRead, PublicationId, ReadSet,
    SCHEMA_VERSION, SymbolHashes, SymbolId, Witness, WriteSet,
};
use inarch_types::hash::{Blake3Hasher, BlobId, ChangesetId, ObjectDomain, ObjectHash, blake3_hash};
use inarch_types::path::MPath;

const VECTORS_JSON: &str = include_str!("vectors/changeset_v2/vectors.json");
const REFUSALS_JSON: &str = include_str!("vectors/changeset_v2/refusals.json");

/// A vector that populates every field of a changeset.
const FULL: &str = "g57-full-pre-proven-log-base";
/// A vector with every collection empty.
const MINIMAL: &str = "g01-minimal-pre-proven-base-0";
/// A vector with all three read kinds.
const READS: &str = "g43-all-three-read-kinds-policy-zero";

const ALL_OBJECT_DOMAINS: [ObjectDomain; 8] = [
    ObjectDomain::Blob,
    ObjectDomain::Chunk,
    ObjectDomain::Changeset,
    ObjectDomain::Fsnode,
    ObjectDomain::UnodeFile,
    ObjectDomain::UnodeManifest,
    ObjectDomain::PathSearchIndex,
    ObjectDomain::CopyInfo,
];

const EXPECTED_STATE_NAMES: [&str; 7] = [
    "CLEAN",
    "MERGED",
    "SUSPECT",
    "CONFLICTED",
    "PARKED",
    "INVERSE",
    "HELD",
];

const EXPECTED_EDGE_KIND_NAMES: [&str; 4] = ["symbol", "same-path", "read-from", "learned"];

// ---------------------------------------------------------------------------
// Minimal JSON parser (the workspace has zero external crates).
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(text) => text.parse::<u64>().ok(),
            _ => None,
        }
    }
}

struct JsonParser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> JsonParser<'a> {
    fn parse(text: &'a str) -> Result<Json, String> {
        let mut p = JsonParser {
            b: text.as_bytes(),
            i: 0,
        };
        let v = p.value()?;
        p.ws();
        if p.i != p.b.len() {
            return Err(format!("trailing bytes at offset {}", p.i));
        }
        Ok(v)
    }

    fn ws(&mut self) {
        while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn expect(&mut self, c: u8) -> Result<(), String> {
        if self.b.get(self.i) == Some(&c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at offset {}", c as char, self.i))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        match self.b.get(self.i).copied() {
            None => Err("unexpected end of JSON".to_string()),
            Some(b'{') => {
                self.i += 1;
                let mut entries = Vec::new();
                loop {
                    self.ws();
                    if self.b.get(self.i) == Some(&b'}') {
                        self.i += 1;
                        break;
                    }
                    let key = self.string()?;
                    self.ws();
                    self.expect(b':')?;
                    let v = self.value()?;
                    entries.push((key, v));
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            break;
                        }
                        _ => return Err(format!("expected ',' or '}}' at offset {}", self.i)),
                    }
                }
                Ok(Json::Obj(entries))
            }
            Some(b'[') => {
                self.i += 1;
                let mut items = Vec::new();
                loop {
                    self.ws();
                    if self.b.get(self.i) == Some(&b']') {
                        self.i += 1;
                        break;
                    }
                    items.push(self.value()?);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            break;
                        }
                        _ => return Err(format!("expected ',' or ']' at offset {}", self.i)),
                    }
                }
                Ok(Json::Arr(items))
            }
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') if self.b[self.i..].starts_with(b"true") => {
                self.i += 4;
                Ok(Json::Bool(true))
            }
            Some(b'f') if self.b[self.i..].starts_with(b"false") => {
                self.i += 5;
                Ok(Json::Bool(false))
            }
            Some(b'n') if self.b[self.i..].starts_with(b"null") => {
                self.i += 4;
                Ok(Json::Null)
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => {
                let start = self.i;
                while self.i < self.b.len() && is_number_byte(self.b[self.i]) {
                    self.i += 1;
                }
                let digits = &self.b[start..self.i];
                let text = String::from_utf8_lossy(digits).to_string();
                Ok(Json::Num(text))
            }
            Some(c) => Err(format!("unexpected byte {c} at offset {}", self.i)),
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(c) = self.b.get(self.i).copied() else {
                return Err("unterminated JSON string".to_string());
            };
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let Some(e) = self.b.get(self.i).copied() else {
                        return Err("dangling escape in JSON string".to_string());
                    };
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'u' => {
                            let digits = self.b.get(self.i..self.i + 4);
                            let digits = digits.ok_or_else(|| "short \\u escape".to_string())?;
                            let hex = String::from_utf8_lossy(digits).to_string();
                            let code = u32::from_str_radix(&hex, 16);
                            let code = code.map_err(|_| format!("bad \\u escape {hex}"))?;
                            self.i += 4;
                            let ch = char::from_u32(code).unwrap_or('\u{fffd}');
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        other => out.push(other),
                    }
                }
                other => out.push(other),
            }
        }
        Ok(String::from_utf8_lossy(&out).to_string())
    }
}

fn is_number_byte(b: u8) -> bool {
    matches!(b, b'+' | b'-' | b'.' | b'e' | b'E' | b'0'..=b'9')
}

fn req<'a>(v: &'a Json, key: &str) -> &'a Json {
    v.get(key)
        .unwrap_or_else(|| panic!("missing JSON member {key:?}"))
}

fn req_str<'a>(v: &'a Json, key: &str) -> &'a str {
    req(v, key)
        .as_str()
        .unwrap_or_else(|| panic!("JSON member {key:?} must be a string"))
}

fn req_u64(v: &Json, key: &str) -> u64 {
    req(v, key)
        .as_u64()
        .unwrap_or_else(|| panic!("JSON member {key:?} must be an unsigned integer"))
}

fn arr_or_empty<'a>(v: &'a Json, key: &str) -> &'a [Json] {
    match v.get(key) {
        None | Some(Json::Null) => &[],
        Some(Json::Arr(items)) => items.as_slice(),
        Some(other) => panic!("JSON member {key:?} must be an array, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Golden vector descriptions.
// ---------------------------------------------------------------------------

struct Vector {
    name: String,
    author: Author,
    head: u64,
    submission: ChangesetV2Submission,
    expected_canonical_hex: Option<String>,
    expected_id_hex: Option<String>,
}

fn seed_hash(seed: &str) -> ObjectHash {
    blake3_hash(seed.as_bytes())
}

fn seed_id(seed: &str) -> ChangesetV2Id {
    ChangesetV2Id::from_canonical_bytes(seed.as_bytes())
}

fn string_set(v: &Json, key: &str) -> BTreeSet<String> {
    arr_or_empty(v, key)
        .iter()
        .map(|s| s.as_str().expect("set members are strings").to_string())
        .collect()
}

fn id_set(v: &Json, key: &str) -> BTreeSet<ChangesetV2Id> {
    arr_or_empty(v, key)
        .iter()
        .map(|s| seed_id(s.as_str().expect("id seeds are strings")))
        .collect()
}

fn build_base(v: &Json) -> Base {
    if let Some(position) = v.get("log_position") {
        Base::LogPosition(position.as_u64().expect("log_position is a u64"))
    } else if let Some(seed) = v.get("proven_publication") {
        let seed = seed.as_str().expect("publication seed is a string");
        Base::ProvenPublication(PublicationId::from_hash(seed_hash(seed)))
    } else {
        panic!("base must hold log_position or proven_publication");
    }
}

fn build_delta(items: &[Json]) -> BTreeMap<MPath, FileChangeV2> {
    let mut out = BTreeMap::new();
    for item in items {
        let path = MPath::new(req_str(item, "path")).expect("vector paths are valid");
        let change = if let Some(tracked) = item.get("tracked") {
            let content = req_str(tracked, "content");
            let file_type = match req_str(tracked, "file_type") {
                "regular" => FileType::Regular,
                "executable" => FileType::Executable,
                "symlink" => FileType::Symlink,
                other => panic!("unknown file_type {other:?}"),
            };
            FileChangeV2::WholeContent(FileChange::Tracked {
                blob_id: BlobId::from_content(content.as_bytes()),
                size: content.len() as u64,
                file_type,
            })
        } else if item.get("deleted").is_some() {
            FileChangeV2::WholeContent(FileChange::Deleted)
        } else if let Some(operator) = item.get("operator") {
            let class = match req_str(operator, "class") {
                "set_union" => OperatorClass::SetUnion,
                "mvs_max" => OperatorClass::MvsMax,
                other => panic!("unknown operator class {other:?}"),
            };
            FileChangeV2::OperatorDelta(OperatorDelta {
                class,
                added: string_set(operator, "added"),
                removed: string_set(operator, "removed"),
            })
        } else {
            panic!("a delta item needs tracked, deleted or operator");
        };
        assert!(out.insert(path, change).is_none(), "duplicate delta path");
    }
    out
}

fn build_writes(v: Option<&Json>) -> WriteSet {
    let Some(v) = v else {
        return WriteSet {
            paths: BTreeSet::new(),
            symbols: BTreeMap::new(),
        };
    };
    let paths: BTreeSet<MPath> = arr_or_empty(v, "paths")
        .iter()
        .map(|p| MPath::new(p.as_str().expect("path strings")).expect("valid path"))
        .collect();
    let mut symbols = BTreeMap::new();
    for s in arr_or_empty(v, "symbols") {
        symbols.insert(
            SymbolId::new(req_str(s, "symbol")),
            SymbolHashes {
                interface_hash: seed_hash(req_str(s, "interface")),
                body_hash: seed_hash(req_str(s, "body")),
            },
        );
    }
    WriteSet { paths, symbols }
}

fn build_reads(v: Option<&Json>) -> ReadSet {
    let Some(v) = v else {
        return ReadSet {
            point: BTreeSet::new(),
            predicate: BTreeSet::new(),
            behavior: BTreeSet::new(),
            policy_version: None,
        };
    };
    let policy_version = match v.get("policy_version") {
        None | Some(Json::Null) => None,
        Some(n) => Some(n.as_u64().expect("policy_version is a u64")),
    };
    let mut point = BTreeSet::new();
    for p in arr_or_empty(v, "point") {
        if let Some(i) = p.get("interface") {
            point.insert(PointRead::Interface {
                symbol: SymbolId::new(req_str(i, "symbol")),
                interface_hash: seed_hash(req_str(i, "hash")),
            });
        } else if let Some(d) = p.get("decision") {
            point.insert(PointRead::Decision {
                decision: req_str(d, "id").to_string(),
                version: req_u64(d, "version"),
            });
        } else {
            panic!("a point read needs interface or decision");
        }
    }
    let predicate: BTreeSet<PredicateRead> = arr_or_empty(v, "predicate")
        .iter()
        .map(|p| PredicateRead {
            symbol: SymbolId::new(req_str(p, "symbol")),
            dep_version: req_u64(p, "dep_version"),
        })
        .collect();
    let behavior: BTreeSet<BehaviorRead> = arr_or_empty(v, "behavior")
        .iter()
        .map(|b| BehaviorRead {
            target: req_str(b, "target").to_string(),
            closure_hash: seed_hash(req_str(b, "closure")),
        })
        .collect();
    ReadSet {
        point,
        predicate,
        behavior,
        policy_version,
    }
}

fn build_hints(items: &[Json]) -> Vec<AgentReceipt> {
    items
        .iter()
        .map(|h| AgentReceipt {
            kind: req_str(h, "kind").to_string(),
            digest: seed_hash(req_str(h, "digest")),
        })
        .collect()
}

fn build_vector(v: &Json) -> Vector {
    let name = req_str(v, "name").to_string();
    let class = match req_str(v, "class") {
        "pre_land" => ChangesetClass::PreLand,
        "pre_proven" => ChangesetClass::PreProven,
        other => panic!("vector {name}: unknown class {other:?}"),
    };
    let submission = ChangesetV2Submission {
        base: build_base(req(v, "base")),
        delta: build_delta(arr_or_empty(v, "delta")),
        writes: build_writes(v.get("writes")),
        reads: build_reads(v.get("reads")),
        deps: id_set(v, "deps"),
        resolves: id_set(v, "resolves"),
        hints: build_hints(arr_or_empty(v, "hints")),
        class,
    };
    Vector {
        author: Author::new(req_str(v, "author")),
        head: req_u64(v, "head"),
        expected_canonical_hex: v
            .get("expected_canonical_hex")
            .and_then(Json::as_str)
            .map(str::to_string),
        expected_id_hex: v
            .get("expected_id_hex")
            .and_then(Json::as_str)
            .map(str::to_string),
        name,
        submission,
    }
}

fn load_vectors() -> Vec<Vector> {
    let root = JsonParser::parse(VECTORS_JSON).expect("vectors.json is valid JSON");
    let vectors = req(&root, "vectors");
    let list = vectors.as_arr().expect("vectors is an array");
    list.iter().map(build_vector).collect()
}

fn vector_named<'a>(vectors: &'a [Vector], name: &str) -> &'a Vector {
    vectors
        .iter()
        .find(|v| v.name == name)
        .unwrap_or_else(|| panic!("golden vector {name:?} is missing"))
}

fn stamp(v: &Vector) -> ChangesetV2 {
    ChangesetV2::from_submission(v.submission.clone(), v.author.clone())
}

// ---------------------------------------------------------------------------
// Refusal inputs.
// ---------------------------------------------------------------------------

struct BaseCase {
    head: u64,
    accept: Vec<u64>,
    refuse: Vec<u64>,
}

struct Refusals {
    unknown_field_names: Vec<String>,
    unknown_state_names: Vec<String>,
    unknown_edge_kind_names: Vec<String>,
    client_supplied_authors: Vec<String>,
    unsupported_versions: Vec<u64>,
    base_cases: Vec<BaseCase>,
    sweep_head: u64,
    sweep_refuse_through: u64,
}

fn load_refusals() -> Refusals {
    let root = JsonParser::parse(REFUSALS_JSON).expect("refusals.json is valid JSON");
    let strings = |v: &Json, key: &str| -> Vec<String> {
        req(v, key)
            .as_arr()
            .unwrap_or_else(|| panic!("{key} must be an array"))
            .iter()
            .map(|j| {
                j.as_str()
                    .unwrap_or_else(|| panic!("{key} must hold strings"))
                    .to_string()
            })
            .collect()
    };
    let numbers = |v: &Json, key: &str| -> Vec<u64> {
        req(v, key)
            .as_arr()
            .unwrap_or_else(|| panic!("{key} must be an array"))
            .iter()
            .map(|j| {
                j.as_u64()
                    .unwrap_or_else(|| panic!("{key} must hold unsigned integers"))
            })
            .collect()
    };
    let base_cases = req(&root, "base_cases")
        .as_arr()
        .expect("base_cases is an array")
        .iter()
        .map(|case| BaseCase {
            head: req_u64(case, "head"),
            accept: numbers(case, "accept"),
            refuse: numbers(case, "refuse"),
        })
        .collect();
    let sweep = req(&root, "sweep");
    Refusals {
        unknown_field_names: strings(&root, "unknown_field_names"),
        unknown_state_names: strings(&root, "unknown_state_names"),
        unknown_edge_kind_names: strings(&root, "unknown_edge_kind_names"),
        client_supplied_authors: strings(&root, "client_supplied_authors"),
        unsupported_versions: numbers(&root, "unsupported_versions"),
        base_cases,
        sweep_head: req_u64(sweep, "head"),
        sweep_refuse_through: req_u64(sweep, "refuse_through"),
    }
}

// ---------------------------------------------------------------------------
// Canonical value helpers.
// ---------------------------------------------------------------------------

fn map_of(value: &CanonicalValue) -> &BTreeMap<String, CanonicalValue> {
    match value {
        CanonicalValue::Map(map) => map,
        other => panic!("a changeset or entry value must be a Map, got {other:?}"),
    }
}

fn map_mut(value: &mut CanonicalValue) -> &mut BTreeMap<String, CanonicalValue> {
    match value {
        CanonicalValue::Map(map) => map,
        other => panic!("a changeset or entry value must be a Map, got {other:?}"),
    }
}

/// Encodes `value` with one extra top-level member that no schema field is called.
fn with_extra_field(value: &CanonicalValue, name: &str) -> Vec<u8> {
    let mut edited = value.clone();
    let previous = map_mut(&mut edited).insert(name.to_string(), CanonicalValue::Uint(1));
    assert!(previous.is_none(), "{name:?} collides with a real field");
    edited.encode()
}

/// Encodes `value` after replacing one top-level member.
fn with_member(value: &CanonicalValue, key: &str, member: CanonicalValue) -> Vec<u8> {
    let mut edited = value.clone();
    map_mut(&mut edited).insert(key.to_string(), member);
    edited.encode()
}

/// Encodes `value` after removing one top-level member.
fn without_member(value: &CanonicalValue, key: &str) -> Vec<u8> {
    let mut edited = value.clone();
    let removed = map_mut(&mut edited).remove(key);
    assert!(removed.is_some(), "{key:?} is not a member of the value");
    edited.encode()
}

/// Replaces every text node equal to `from` anywhere in the tree and returns how many.
fn replace_text(value: &mut CanonicalValue, from: &str, to: &str) -> usize {
    match value {
        CanonicalValue::Text(text) if text.as_str() == from => {
            *text = to.to_string();
            1
        }
        CanonicalValue::List(items) => items
            .iter_mut()
            .map(|item| replace_text(item, from, to))
            .sum::<usize>(),
        CanonicalValue::Map(map) => map
            .values_mut()
            .map(|item| replace_text(item, from, to))
            .sum::<usize>(),
        _ => 0,
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Expected-error helpers.
// ---------------------------------------------------------------------------

fn expect_unknown_field<T: std::fmt::Debug>(
    result: Result<T, DecodeError>,
    name: &str,
    what: &str,
) {
    match result {
        Err(DecodeError::UnknownField(found)) => {
            assert_eq!(found, name, "{what}: the error must name the unknown field");
        }
        other => panic!("{what}: unknown field {name:?} must be refused, got {other:?}"),
    }
}

fn expect_unknown_state<T: std::fmt::Debug>(
    result: Result<T, DecodeError>,
    name: &str,
    what: &str,
) {
    match result {
        Err(DecodeError::UnknownState(found)) => {
            assert_eq!(found, name, "{what}: the error must name the unknown state");
        }
        other => panic!("{what}: unknown state {name:?} must be refused, got {other:?}"),
    }
}

fn expect_unknown_edge_kind<T: std::fmt::Debug>(
    result: Result<T, DecodeError>,
    name: &str,
    what: &str,
) {
    match result {
        Err(DecodeError::UnknownEdgeKind(found)) => {
            assert_eq!(found, name, "{what}: the error must name the unknown kind");
        }
        other => panic!("{what}: unknown edge kind {name:?} must be refused, got {other:?}"),
    }
}

fn expect_client_author<T: std::fmt::Debug>(result: Result<T, DecodeError>, what: &str) {
    match result {
        Err(DecodeError::ClientSuppliedAuthor) => {}
        other => panic!("{what}: a client-supplied author must be refused, got {other:?}"),
    }
}

fn expect_unsupported_version<T: std::fmt::Debug>(
    result: Result<T, DecodeError>,
    version: u64,
    what: &str,
) {
    match result {
        Err(DecodeError::UnsupportedVersion(found)) => {
            assert_eq!(found, version, "{what}: the error must carry the version");
        }
        other => panic!("{what}: schema version {version} must be refused, got {other:?}"),
    }
}

fn expect_missing_field<T: std::fmt::Debug>(
    result: Result<T, DecodeError>,
    field: &str,
    what: &str,
) {
    match result {
        Err(DecodeError::MissingField(found)) => {
            assert_eq!(
                found, field,
                "{what}: the error must name the missing field"
            );
        }
        other => panic!("{what}: a missing {field:?} must be refused, got {other:?}"),
    }
}

fn expect_beyond_head<T: std::fmt::Debug>(
    result: Result<T, DecodeError>,
    base: u64,
    head: u64,
    what: &str,
) {
    match result {
        Err(DecodeError::BaseBeyondHead {
            base: found_base,
            head: found_head,
        }) => {
            assert_eq!(found_base, base, "{what}: the error must carry the base");
            assert_eq!(found_head, head, "{what}: the error must carry the head");
        }
        other => panic!("{what}: base {base} past head {head} must be refused, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Builders for submissions and entries.
// ---------------------------------------------------------------------------

fn minimal_submission(base: Base) -> ChangesetV2Submission {
    ChangesetV2Submission {
        base,
        delta: BTreeMap::new(),
        writes: WriteSet {
            paths: BTreeSet::new(),
            symbols: BTreeMap::new(),
        },
        reads: ReadSet {
            point: BTreeSet::new(),
            predicate: BTreeSet::new(),
            behavior: BTreeSet::new(),
            policy_version: None,
        },
        deps: BTreeSet::new(),
        resolves: BTreeSet::new(),
        hints: Vec::new(),
        class: ChangesetClass::PreProven,
    }
}

fn sample_entry(state: EntryState, checkpoint_index: Option<u64>) -> Entry {
    Entry {
        position: 41,
        changeset_id: seed_id("entry-changeset"),
        state,
        witnesses: BTreeSet::from([
            Witness {
                symbol: SymbolId::new("crate::engine::land"),
                position: 17,
            },
            Witness {
                symbol: SymbolId::new("crate::store::append"),
                position: 29,
            },
        ]),
        edges: BTreeSet::from([
            Edge {
                kind: EdgeKind::Symbol,
                target: 3,
            },
            Edge {
                kind: EdgeKind::SamePath,
                target: 9,
            },
            Edge {
                kind: EdgeKind::ReadFrom,
                target: 17,
            },
            Edge {
                kind: EdgeKind::Learned,
                target: 29,
            },
        ]),
        head_root: seed_hash("entry-head-root"),
        checkpoint_index,
    }
}

fn variant(
    label: &'static str,
    full: &ChangesetV2Submission,
    author: &Author,
    edit: impl FnOnce(&mut ChangesetV2Submission),
) -> (&'static str, ChangesetV2) {
    let mut edited = full.clone();
    edit(&mut edited);
    (label, ChangesetV2::from_submission(edited, author.clone()))
}

// ===========================================================================
// 1. Golden changesets: re-encode byte-identically with equal BLAKE3 ids.
// ===========================================================================

#[test]
fn golden_vector_set_has_at_least_fifty_distinct_changesets_covering_every_field_and_form() {
    let vectors = load_vectors();
    assert!(
        vectors.len() >= 50,
        "the golden set must hold at least 50 changesets, found {}",
        vectors.len()
    );
    let names: BTreeSet<&str> = vectors.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names.len(), vectors.len(), "vector names must be unique");
    let ids: BTreeSet<ChangesetV2Id> = vectors.iter().map(|v| stamp(v).id()).collect();
    assert_eq!(
        ids.len(),
        vectors.len(),
        "every golden changeset must have its own id"
    );

    let covered = |what: &str, hit: bool| assert!(hit, "no golden vector covers {what}");
    let any_sub = |pred: &dyn Fn(&ChangesetV2Submission) -> bool| {
        vectors.iter().any(|v| pred(&v.submission))
    };
    let any_change = |pred: &dyn Fn(&FileChangeV2) -> bool| {
        vectors
            .iter()
            .any(|v| v.submission.delta.values().any(pred))
    };

    covered(
        "class pre-land",
        any_sub(&|s| s.class == ChangesetClass::PreLand),
    );
    covered(
        "class pre-proven",
        any_sub(&|s| s.class == ChangesetClass::PreProven),
    );
    covered(
        "base position 0",
        any_sub(&|s| s.base == Base::LogPosition(0)),
    );
    covered(
        "base position u64::MAX",
        any_sub(&|s| s.base == Base::LogPosition(u64::MAX)),
    );
    covered(
        "a proven publication base",
        any_sub(&|s| matches!(s.base, Base::ProvenPublication(_))),
    );
    covered(
        "a base strictly behind the head",
        vectors
            .iter()
            .any(|v| matches!(v.submission.base, Base::LogPosition(p) if p < v.head)),
    );
    covered(
        "a regular tracked file",
        any_change(&|c| {
            matches!(
                c,
                FileChangeV2::WholeContent(FileChange::Tracked {
                    file_type: FileType::Regular,
                    ..
                })
            )
        }),
    );
    covered(
        "an executable tracked file",
        any_change(&|c| {
            matches!(
                c,
                FileChangeV2::WholeContent(FileChange::Tracked {
                    file_type: FileType::Executable,
                    ..
                })
            )
        }),
    );
    covered(
        "a symlink",
        any_change(&|c| {
            matches!(
                c,
                FileChangeV2::WholeContent(FileChange::Tracked {
                    file_type: FileType::Symlink,
                    ..
                })
            )
        }),
    );
    covered(
        "a deleted path",
        any_change(&|c| matches!(c, FileChangeV2::WholeContent(FileChange::Deleted))),
    );
    covered(
        "a set-union operator delta",
        any_change(&|c| {
            matches!(
                c,
                FileChangeV2::OperatorDelta(OperatorDelta {
                    class: OperatorClass::SetUnion,
                    ..
                })
            )
        }),
    );
    covered(
        "a set-union operator delta that removes members",
        any_change(&|c| {
            matches!(
                c,
                FileChangeV2::OperatorDelta(OperatorDelta {
                    class: OperatorClass::SetUnion,
                    removed,
                    ..
                }) if !removed.is_empty()
            )
        }),
    );
    covered(
        "an MVS-max operator delta",
        any_change(&|c| {
            matches!(
                c,
                FileChangeV2::OperatorDelta(OperatorDelta {
                    class: OperatorClass::MvsMax,
                    ..
                })
            )
        }),
    );
    covered("written paths", any_sub(&|s| !s.writes.paths.is_empty()));
    covered(
        "written symbols with interface and body hashes",
        any_sub(&|s| !s.writes.symbols.is_empty()),
    );
    covered(
        "a point interface read",
        any_sub(&|s| {
            s.reads
                .point
                .iter()
                .any(|p| matches!(p, PointRead::Interface { .. }))
        }),
    );
    covered(
        "a point decision read",
        any_sub(&|s| {
            s.reads
                .point
                .iter()
                .any(|p| matches!(p, PointRead::Decision { .. }))
        }),
    );
    covered(
        "a predicate read",
        any_sub(&|s| !s.reads.predicate.is_empty()),
    );
    covered(
        "a behavior read",
        any_sub(&|s| !s.reads.behavior.is_empty()),
    );
    covered(
        "no policy version",
        any_sub(&|s| s.reads.policy_version.is_none()),
    );
    covered(
        "policy version 0",
        any_sub(&|s| s.reads.policy_version == Some(0)),
    );
    covered(
        "policy version u64::MAX",
        any_sub(&|s| s.reads.policy_version == Some(u64::MAX)),
    );
    covered("deps", any_sub(&|s| !s.deps.is_empty()));
    covered("resolves", any_sub(&|s| !s.resolves.is_empty()));
    covered("hints", any_sub(&|s| !s.hints.is_empty()));
    covered("several hints", any_sub(&|s| s.hints.len() >= 3));
    covered(
        "a changeset with every collection empty",
        any_sub(&|s| {
            s.delta.is_empty()
                && s.writes.paths.is_empty()
                && s.writes.symbols.is_empty()
                && s.reads.point.is_empty()
                && s.reads.predicate.is_empty()
                && s.reads.behavior.is_empty()
                && s.deps.is_empty()
                && s.resolves.is_empty()
                && s.hints.is_empty()
        }),
    );
}

#[test]
fn golden_changesets_reencode_byte_identically_with_equal_ids() {
    for v in load_vectors() {
        let original = stamp(&v);
        let first = original.encode_canonical();
        assert!(!first.is_empty(), "vector {}: empty encoding", v.name);

        let decoded = ChangesetV2::decode_canonical(&first)
            .unwrap_or_else(|e| panic!("vector {}: decode failed: {e:?}", v.name));
        assert_eq!(
            decoded, original,
            "vector {}: decoded value differs",
            v.name
        );

        let second = decoded.encode_canonical();
        assert!(
            first == second,
            "vector {}: re-encoding changed the bytes ({} vs {} bytes)",
            v.name,
            first.len(),
            second.len()
        );

        let third = ChangesetV2::decode_canonical(&second)
            .unwrap_or_else(|e| panic!("vector {}: second decode failed: {e:?}", v.name))
            .encode_canonical();
        assert!(
            first == third,
            "vector {}: encode-decode-encode-decode-encode is not stable",
            v.name
        );

        assert_eq!(original.id(), decoded.id(), "vector {}: ids differ", v.name);
        assert_eq!(
            original.id(),
            ChangesetV2Id::from_canonical_bytes(&first),
            "vector {}: id is not the digest of the canonical bytes",
            v.name
        );
        assert_eq!(
            ChangesetV2Id::from_canonical_bytes(&first),
            ChangesetV2Id::from_canonical_bytes(&second),
            "vector {}: equal bytes must give equal ids",
            v.name
        );
    }
}

#[test]
fn golden_submissions_reencode_byte_identically() {
    for v in load_vectors() {
        let first = v.submission.encode_canonical();
        let decoded = ChangesetV2Submission::decode_canonical(&first, v.head)
            .unwrap_or_else(|e| panic!("vector {}: submission decode failed: {e:?}", v.name));
        assert_eq!(
            decoded, v.submission,
            "vector {}: decoded value differs",
            v.name
        );
        let second = decoded.encode_canonical();
        assert!(
            first == second,
            "vector {}: submission re-encoding changed the bytes",
            v.name
        );
    }
}

#[test]
fn canonical_bytes_are_the_encoding_of_the_canonical_value_tree() {
    for v in load_vectors() {
        let stamped = stamp(&v);
        let bytes = stamped.encode_canonical();
        let value = stamped.to_canonical_value();
        assert!(
            value.encode() == bytes,
            "vector {}: encode_canonical must equal the encoding of to_canonical_value",
            v.name
        );
        let reparsed = CanonicalValue::decode(&bytes)
            .unwrap_or_else(|e| panic!("vector {}: value decode failed: {e:?}", v.name));
        assert_eq!(reparsed, value, "vector {}: value tree differs", v.name);
        assert!(
            reparsed.encode() == bytes,
            "vector {}: the value layer is not canonical",
            v.name
        );
        assert_eq!(
            map_of(&value).get("version"),
            Some(&CanonicalValue::Uint(SCHEMA_VERSION)),
            "vector {}: the schema version must be a member of the value",
            v.name
        );
    }
    assert_eq!(SCHEMA_VERSION, 2);
}

#[test]
fn stamping_adds_only_the_server_set_author() {
    for v in load_vectors() {
        let stamped_value = stamp(&v).to_canonical_value();
        let submission_value = v.submission.to_canonical_value();
        assert!(
            !map_of(&submission_value).contains_key("author"),
            "vector {}: a submission carries no author",
            v.name
        );
        let mut stripped = map_of(&stamped_value).clone();
        let author = stripped
            .remove("author")
            .unwrap_or_else(|| panic!("vector {}: a stamped changeset carries its author", v.name));
        assert_eq!(
            author,
            CanonicalValue::Text(v.author.as_str().to_string()),
            "vector {}: the author member must be the author text",
            v.name
        );
        assert_eq!(
            CanonicalValue::Map(stripped),
            submission_value,
            "vector {}: stamping must change nothing but the author",
            v.name
        );
    }
}

#[test]
fn changeset_id_is_the_domain_separated_keyed_blake3_digest_of_the_canonical_bytes() {
    let vectors = load_vectors();
    for v in &vectors {
        let stamped = stamp(v);
        let bytes = stamped.encode_canonical();
        let mut hasher = Blake3Hasher::new_derive_key(ID_CONTEXT);
        hasher.update(&bytes);
        assert_eq!(
            *stamped.id().as_hash(),
            hasher.finalize(),
            "vector {}: id must be derive-key BLAKE3 of the canonical bytes under ID_CONTEXT",
            v.name
        );
    }

    let full = vector_named(&vectors, FULL);
    let bytes = stamp(full).encode_canonical();
    let id = *ChangesetV2Id::from_canonical_bytes(&bytes).as_hash();
    assert_ne!(id, blake3_hash(&bytes), "id must not be the unkeyed digest");
    assert_ne!(
        id,
        *ChangesetId::from_canonical_bytes(&bytes).as_hash(),
        "a v2 id must differ from a v1 changeset id over the same bytes"
    );
    for domain in ALL_OBJECT_DOMAINS {
        assert_ne!(
            id,
            ObjectHash::from_domain(domain, &bytes),
            "id must be separated from the {domain:?} domain"
        );
        assert_ne!(
            ID_CONTEXT,
            domain.context_str(),
            "ID_CONTEXT must differ from the {domain:?} context"
        );
    }
    assert!(
        ID_CONTEXT.starts_with("velenza-inarch"),
        "ID_CONTEXT must follow the repository context prefix, got {ID_CONTEXT:?}"
    );
    let lower = ID_CONTEXT.to_ascii_lowercase();
    assert!(
        lower.contains("changeset") && lower.contains("v2"),
        "ID_CONTEXT must name changeset and v2, got {ID_CONTEXT:?}"
    );
}

#[test]
fn changeset_ids_round_trip_through_hex_and_refuse_malformed_hex() {
    let vectors = load_vectors();
    let id = stamp(vector_named(&vectors, FULL)).id();
    let hex = id.to_hex();
    assert_eq!(hex.len(), 64);
    assert_eq!(
        ChangesetV2Id::from_hex(&hex).expect("lowercase hex parses"),
        id
    );
    assert_eq!(
        ChangesetV2Id::from_hex(&hex.to_uppercase()).expect("uppercase hex parses"),
        id
    );
    assert!(ChangesetV2Id::from_hex("").is_err());
    assert!(ChangesetV2Id::from_hex(&hex[..63]).is_err());
    assert!(ChangesetV2Id::from_hex(&"z".repeat(64)).is_err());
}

#[test]
fn every_field_of_a_changeset_participates_in_its_id() {
    let vectors = load_vectors();
    let full = vector_named(&vectors, FULL);
    let sub = &full.submission;
    let author = full.author.clone();
    let original = stamp(full);

    let variants = vec![
        (
            "author",
            ChangesetV2::from_submission(sub.clone(), Author::new("agent-99@example.com")),
        ),
        variant("base position", sub, &author, |s| {
            s.base = Base::LogPosition(41);
        }),
        variant("base publication", sub, &author, |s| {
            s.base = Base::ProvenPublication(PublicationId::from_hash(seed_hash("pub-other")));
        }),
        variant("class", sub, &author, |s| s.class = ChangesetClass::PreLand),
        variant("delta path removed", sub, &author, |s| {
            let first = s.delta.keys().next().cloned();
            s.delta.remove(&first.expect("delta is not empty"));
        }),
        variant("delta content", sub, &author, |s| {
            s.delta.insert(
                MPath::new("src/engine.rs").expect("valid path"),
                FileChangeV2::WholeContent(FileChange::Tracked {
                    blob_id: BlobId::from_content(b"changed"),
                    size: 7,
                    file_type: FileType::Regular,
                }),
            );
        }),
        variant("delta file type", sub, &author, |s| {
            s.delta.insert(
                MPath::new("src/engine.rs").expect("valid path"),
                FileChangeV2::WholeContent(FileChange::Tracked {
                    blob_id: BlobId::from_content(b"pub fn land() {}\n"),
                    size: 17,
                    file_type: FileType::Executable,
                }),
            );
        }),
        variant("operator delta", sub, &author, |s| {
            s.delta.insert(
                MPath::new("go.mod").expect("valid path"),
                FileChangeV2::OperatorDelta(OperatorDelta {
                    class: OperatorClass::MvsMax,
                    added: BTreeSet::from(["example.com/lib@v1.5.1".to_string()]),
                    removed: BTreeSet::new(),
                }),
            );
        }),
        variant("written path", sub, &author, |s| {
            s.writes
                .paths
                .insert(MPath::new("extra/new.rs").expect("valid path"));
        }),
        variant("written symbol body hash", sub, &author, |s| {
            s.writes.symbols.insert(
                SymbolId::new("crate::engine::land"),
                SymbolHashes {
                    interface_hash: seed_hash("full-interface-1"),
                    body_hash: seed_hash("changed-body"),
                },
            );
        }),
        variant("written symbol interface hash", sub, &author, |s| {
            s.writes.symbols.insert(
                SymbolId::new("crate::engine::land"),
                SymbolHashes {
                    interface_hash: seed_hash("changed-interface"),
                    body_hash: seed_hash("full-body-1"),
                },
            );
        }),
        variant("policy version", sub, &author, |s| {
            s.reads.policy_version = Some(99);
        }),
        variant("policy version absent", sub, &author, |s| {
            s.reads.policy_version = None;
        }),
        variant("point read added", sub, &author, |s| {
            s.reads.point.insert(PointRead::Decision {
                decision: "extra-decision".to_string(),
                version: 1,
            });
        }),
        variant("point interface hash", sub, &author, |s| {
            s.reads.point.remove(&PointRead::Interface {
                symbol: SymbolId::new("crate::store::append"),
                interface_hash: seed_hash("full-point-1"),
            });
            s.reads.point.insert(PointRead::Interface {
                symbol: SymbolId::new("crate::store::append"),
                interface_hash: seed_hash("changed-point"),
            });
        }),
        variant("decision version", sub, &author, |s| {
            s.reads.point.remove(&PointRead::Decision {
                decision: "retry-policy".to_string(),
                version: 3,
            });
            s.reads.point.insert(PointRead::Decision {
                decision: "retry-policy".to_string(),
                version: 4,
            });
        }),
        variant("predicate dep version", sub, &author, |s| {
            s.reads.predicate.remove(&PredicateRead {
                symbol: SymbolId::new("crate::engine::land"),
                dep_version: 9,
            });
            s.reads.predicate.insert(PredicateRead {
                symbol: SymbolId::new("crate::engine::land"),
                dep_version: 10,
            });
        }),
        variant("behavior closure hash", sub, &author, |s| {
            s.reads.behavior.remove(&BehaviorRead {
                target: "//engine:tests".to_string(),
                closure_hash: seed_hash("full-closure-1"),
            });
            s.reads.behavior.insert(BehaviorRead {
                target: "//engine:tests".to_string(),
                closure_hash: seed_hash("changed-closure"),
            });
        }),
        variant("dep added", sub, &author, |s| {
            s.deps.insert(seed_id("extra-dep"));
        }),
        variant("resolves added", sub, &author, |s| {
            s.resolves.insert(seed_id("extra-resolves"));
        }),
        variant("hint appended", sub, &author, |s| {
            s.hints.push(AgentReceipt {
                kind: "audit-receipt".to_string(),
                digest: seed_hash("extra-hint"),
            });
        }),
        variant("hint removed", sub, &author, |s| {
            s.hints.pop();
        }),
    ];

    let mut seen = BTreeSet::new();
    seen.insert(original.id());
    for (label, changeset) in &variants {
        assert_ne!(
            changeset.id(),
            original.id(),
            "changing the {label} must change the id"
        );
        assert!(
            seen.insert(changeset.id()),
            "changing the {label} produced an id that another variant already has"
        );
    }
}

// ===========================================================================
// 2. The decoder refuses an unknown field, an unknown state and a client-supplied author.
// ===========================================================================

#[test]
fn the_decoder_refuses_an_unknown_field_in_every_object_kind() {
    let refusals = load_refusals();
    assert!(!refusals.unknown_field_names.is_empty());
    let vectors = load_vectors();
    let full = vector_named(&vectors, FULL);
    let stamped_value = stamp(full).to_canonical_value();
    let submission_value = full.submission.to_canonical_value();
    let entry_value = sample_entry(EntryState::Suspect, Some(7)).to_canonical_value();

    // Controls: the unedited values decode.
    ChangesetV2::decode_canonical(&stamped_value.encode()).expect("control: stamped decodes");
    ChangesetV2Submission::decode_canonical(&submission_value.encode(), full.head)
        .expect("control: submission decodes");
    Entry::decode_canonical(&entry_value.encode()).expect("control: entry decodes");

    for name in &refusals.unknown_field_names {
        expect_unknown_field(
            ChangesetV2::decode_canonical(&with_extra_field(&stamped_value, name)),
            name,
            "stamped changeset",
        );
        expect_unknown_field(
            ChangesetV2Submission::decode_canonical(
                &with_extra_field(&submission_value, name),
                full.head,
            ),
            name,
            "submission",
        );
        expect_unknown_field(
            Entry::decode_canonical(&with_extra_field(&entry_value, name)),
            name,
            "entry",
        );
    }
}

#[test]
fn the_decoder_refuses_an_unknown_entry_state() {
    let refusals = load_refusals();
    assert!(!refusals.unknown_state_names.is_empty());

    // Controls: every real state decodes from its wire name.
    for state in EntryState::ALL {
        let entry = sample_entry(state, Some(5));
        let decoded = Entry::decode_canonical(&entry.encode_canonical())
            .unwrap_or_else(|e| panic!("control: {state:?} must decode: {e:?}"));
        assert_eq!(decoded.state, state);
    }

    for bad in &refusals.unknown_state_names {
        expect_unknown_state(EntryState::from_wire_name(bad), bad, "wire name parse");
        for state in EntryState::ALL {
            let value = sample_entry(state, Some(5)).to_canonical_value();
            let bytes = with_member(&value, "state", CanonicalValue::Text(bad.clone()));
            expect_unknown_state(Entry::decode_canonical(&bytes), bad, "entry decode");
        }
    }

    // A state that is not text at all is refused as well.
    let value = sample_entry(EntryState::Clean, Some(5)).to_canonical_value();
    let bytes = with_member(&value, "state", CanonicalValue::Uint(1));
    assert!(Entry::decode_canonical(&bytes).is_err());
}

#[test]
fn the_decoder_refuses_an_unknown_edge_kind() {
    let refusals = load_refusals();
    assert!(!refusals.unknown_edge_kind_names.is_empty());
    for bad in &refusals.unknown_edge_kind_names {
        expect_unknown_edge_kind(EdgeKind::from_wire_name(bad), bad, "wire name parse");

        let mut value = sample_entry(EntryState::Clean, Some(5)).to_canonical_value();
        let replaced = replace_text(&mut value, "same-path", bad);
        assert_eq!(
            replaced, 1,
            "the sample entry holds exactly one same-path edge"
        );
        expect_unknown_edge_kind(
            Entry::decode_canonical(&value.encode()),
            bad,
            "entry decode",
        );
    }
}

#[test]
fn the_decoder_refuses_a_client_supplied_author() {
    let refusals = load_refusals();
    assert!(!refusals.client_supplied_authors.is_empty());
    let vectors = load_vectors();
    let full = vector_named(&vectors, FULL);
    let submission_value = full.submission.to_canonical_value();

    // The stamped form, which carries an author, is not accepted as a client submission.
    expect_client_author(
        ChangesetV2Submission::decode_canonical(&stamp(full).encode_canonical(), full.head),
        "stamped bytes sent as a submission",
    );

    // An author member added to a valid submission is refused whatever it holds.
    for author in &refusals.client_supplied_authors {
        let member = CanonicalValue::Text(author.clone());
        let bytes = with_member(&submission_value, "author", member);
        expect_client_author(
            ChangesetV2Submission::decode_canonical(&bytes, full.head),
            "submission with an author member",
        );
    }
    let bytes = with_member(&submission_value, "author", CanonicalValue::Uint(1));
    expect_client_author(
        ChangesetV2Submission::decode_canonical(&bytes, full.head),
        "submission with a non-text author member",
    );

    // Every golden changeset: its stamped bytes are refused as a submission and its
    // submission bytes are accepted, so the refusal is about the author alone.
    for v in &vectors {
        expect_client_author(
            ChangesetV2Submission::decode_canonical(&stamp(v).encode_canonical(), v.head),
            &v.name,
        );
        ChangesetV2Submission::decode_canonical(&v.submission.encode_canonical(), v.head)
            .unwrap_or_else(|e| panic!("vector {}: submission refused: {e:?}", v.name));
    }

    // The stamped decoder is the one place an author is required.
    let stamped_value = stamp(full).to_canonical_value();
    expect_missing_field(
        ChangesetV2::decode_canonical(&without_member(&stamped_value, "author")),
        "author",
        "stamped changeset without an author",
    );
}

#[test]
fn the_decoder_refuses_unsupported_schema_versions() {
    let refusals = load_refusals();
    assert!(!refusals.unsupported_versions.is_empty());
    let vectors = load_vectors();
    let full = vector_named(&vectors, FULL);
    let stamped_value = stamp(full).to_canonical_value();
    let submission_value = full.submission.to_canonical_value();
    let entry_value = sample_entry(EntryState::Clean, Some(5)).to_canonical_value();

    for &version in &refusals.unsupported_versions {
        assert_ne!(
            version, SCHEMA_VERSION,
            "refusals.json must not list the current version"
        );
        let member = CanonicalValue::Uint(version);
        expect_unsupported_version(
            ChangesetV2::decode_canonical(&with_member(&stamped_value, "version", member.clone())),
            version,
            "stamped changeset",
        );
        expect_unsupported_version(
            ChangesetV2Submission::decode_canonical(
                &with_member(&submission_value, "version", member.clone()),
                full.head,
            ),
            version,
            "submission",
        );
        expect_unsupported_version(
            Entry::decode_canonical(&with_member(&entry_value, "version", member)),
            version,
            "entry",
        );
    }
}

#[test]
fn the_decoder_refuses_a_missing_required_field() {
    let vectors = load_vectors();
    let full = vector_named(&vectors, FULL);
    let stamped_value = stamp(full).to_canonical_value();
    let submission_value = full.submission.to_canonical_value();

    for key in map_of(&stamped_value).keys() {
        expect_missing_field(
            ChangesetV2::decode_canonical(&without_member(&stamped_value, key)),
            key,
            "stamped changeset",
        );
    }
    for key in map_of(&submission_value).keys() {
        expect_missing_field(
            ChangesetV2Submission::decode_canonical(
                &without_member(&submission_value, key),
                full.head,
            ),
            key,
            "submission",
        );
    }

    let entry_value = sample_entry(EntryState::Clean, Some(5)).to_canonical_value();
    for key in map_of(&entry_value).keys() {
        let result = Entry::decode_canonical(&without_member(&entry_value, key));
        if key == "checkpoint_index" {
            let decoded = result.expect("checkpoint_index is optional");
            assert_eq!(decoded.checkpoint_index, None);
        } else {
            expect_missing_field(result, key, "entry");
        }
    }
}

#[test]
fn the_decoder_refuses_truncated_and_over_long_input() {
    let vectors = load_vectors();
    for name in [MINIMAL, READS, FULL] {
        let v = vector_named(&vectors, name);
        let stamped = stamp(v).encode_canonical();
        let submission = v.submission.encode_canonical();
        for cut in 0..stamped.len() {
            assert!(
                ChangesetV2::decode_canonical(&stamped[..cut]).is_err(),
                "vector {name}: a {cut}-byte prefix of a stamped changeset must be refused"
            );
        }
        for cut in 0..submission.len() {
            assert!(
                ChangesetV2Submission::decode_canonical(&submission[..cut], v.head).is_err(),
                "vector {name}: a {cut}-byte prefix of a submission must be refused"
            );
        }
        let mut padded = stamped.clone();
        padded.push(0);
        assert!(
            ChangesetV2::decode_canonical(&padded).is_err(),
            "vector {name}: trailing bytes must be refused"
        );
        let doubled = [stamped.clone(), stamped].concat();
        assert!(
            ChangesetV2::decode_canonical(&doubled).is_err(),
            "vector {name}: two concatenated changesets must be refused"
        );
    }

    let entry = sample_entry(EntryState::Held, None).encode_canonical();
    for cut in 0..entry.len() {
        assert!(
            Entry::decode_canonical(&entry[..cut]).is_err(),
            "a {cut}-byte prefix of an entry must be refused"
        );
    }
    let mut padded = entry;
    padded.push(0);
    assert!(Entry::decode_canonical(&padded).is_err());
}

// ===========================================================================
// 3. The state enum and the edge kinds are exactly the specified sets.
// ===========================================================================

/// Exhaustive on purpose, with no wildcard arm: an extra variant fails to compile here, and so
/// does a missing one.
fn state_name(state: EntryState) -> &'static str {
    match state {
        EntryState::Clean => "CLEAN",
        EntryState::Merged => "MERGED",
        EntryState::Suspect => "SUSPECT",
        EntryState::Conflicted => "CONFLICTED",
        EntryState::Parked => "PARKED",
        EntryState::Inverse => "INVERSE",
        EntryState::Held => "HELD",
    }
}

/// Exhaustive on purpose, with no wildcard arm.
fn edge_kind_name(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::Symbol => "symbol",
        EdgeKind::SamePath => "same-path",
        EdgeKind::ReadFrom => "read-from",
        EdgeKind::Learned => "learned",
    }
}

#[test]
fn the_state_enum_is_exactly_the_seven_specified_states() {
    assert_eq!(EntryState::ALL.len(), 7);
    let from_all: Vec<&str> = EntryState::ALL.iter().map(|s| state_name(*s)).collect();
    assert_eq!(
        from_all,
        EXPECTED_STATE_NAMES.to_vec(),
        "ALL must list the seven states in the specified order"
    );
    let distinct: BTreeSet<&str> = from_all.iter().copied().collect();
    assert_eq!(distinct.len(), 7, "the seven states must be distinct");

    for state in EntryState::ALL {
        assert_eq!(state.wire_name(), state_name(state));
        assert_eq!(
            EntryState::from_wire_name(state_name(state)).expect("a specified name parses"),
            state
        );
    }
    for name in EXPECTED_STATE_NAMES {
        let state = EntryState::from_wire_name(name).expect("a specified name parses");
        assert!(EntryState::ALL.contains(&state));
        assert_eq!(state.wire_name(), name);
    }
}

#[test]
fn the_state_wire_names_are_exact_and_nothing_else_parses() {
    let refusals = load_refusals();
    for bad in &refusals.unknown_state_names {
        assert!(
            EntryState::from_wire_name(bad).is_err(),
            "{bad:?} must not parse as an entry state"
        );
    }
    for name in EXPECTED_STATE_NAMES {
        assert!(
            EntryState::from_wire_name(&name.to_ascii_lowercase()).is_err(),
            "state names are case-sensitive: {name:?}"
        );
    }
}

#[test]
fn the_edge_kinds_are_exactly_the_four_specified_kinds() {
    assert_eq!(EdgeKind::ALL.len(), 4);
    let from_all: Vec<&str> = EdgeKind::ALL.iter().map(|k| edge_kind_name(*k)).collect();
    assert_eq!(
        from_all,
        EXPECTED_EDGE_KIND_NAMES.to_vec(),
        "ALL must list the four kinds in the specified order"
    );
    let distinct: BTreeSet<&str> = from_all.iter().copied().collect();
    assert_eq!(distinct.len(), 4, "the four kinds must be distinct");

    for kind in EdgeKind::ALL {
        assert_eq!(kind.wire_name(), edge_kind_name(kind));
        assert_eq!(
            EdgeKind::from_wire_name(edge_kind_name(kind)).expect("a specified name parses"),
            kind
        );
    }
    for name in EXPECTED_EDGE_KIND_NAMES {
        let kind = EdgeKind::from_wire_name(name).expect("a specified name parses");
        assert!(EdgeKind::ALL.contains(&kind));
        assert_eq!(kind.wire_name(), name);
    }

    let refusals = load_refusals();
    for bad in &refusals.unknown_edge_kind_names {
        assert!(
            EdgeKind::from_wire_name(bad).is_err(),
            "{bad:?} must not parse as an edge kind"
        );
    }
}

// ===========================================================================
// 4. Entries: position, state, witnesses, edges, head root and checkpoint index round-trip.
// ===========================================================================

#[test]
fn an_entry_round_trips_in_every_state_with_witnesses_edges_head_root_and_checkpoint_index() {
    let vectors = load_vectors();
    let changeset_id = stamp(vector_named(&vectors, FULL)).id();
    for state in EntryState::ALL {
        for checkpoint_index in [None, Some(0), Some(7), Some(u64::MAX)] {
            for position in [0, 1, 41, u64::MAX] {
                let entry = Entry {
                    position,
                    changeset_id,
                    ..sample_entry(state, checkpoint_index)
                };
                let first = entry.encode_canonical();
                let decoded = Entry::decode_canonical(&first).unwrap_or_else(|e| {
                    panic!("{state:?} at {position} with {checkpoint_index:?}: {e:?}")
                });
                assert_eq!(decoded, entry);
                assert_eq!(decoded.position, position);
                assert_eq!(decoded.state, state);
                assert_eq!(decoded.changeset_id, changeset_id);
                assert_eq!(decoded.witnesses, entry.witnesses);
                assert_eq!(decoded.edges, entry.edges);
                assert_eq!(decoded.head_root, entry.head_root);
                assert_eq!(decoded.checkpoint_index, checkpoint_index);
                assert!(
                    decoded.encode_canonical() == first,
                    "{state:?}: entry re-encoding changed the bytes"
                );
            }
        }
    }
}

#[test]
fn an_entry_carries_every_edge_kind_and_can_have_no_witnesses_or_edges() {
    let entry = sample_entry(EntryState::Suspect, Some(3));
    let decoded = Entry::decode_canonical(&entry.encode_canonical()).expect("entry decodes");
    let kinds: BTreeSet<EdgeKind> = decoded.edges.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        EdgeKind::ALL.iter().copied().collect::<BTreeSet<_>>()
    );
    assert_eq!(decoded.witnesses.len(), 2);

    let bare = Entry {
        witnesses: BTreeSet::new(),
        edges: BTreeSet::new(),
        ..sample_entry(EntryState::Clean, Some(3))
    };
    let decoded = Entry::decode_canonical(&bare.encode_canonical()).expect("bare entry decodes");
    assert_eq!(decoded, bare);
    assert!(decoded.witnesses.is_empty());
    assert!(decoded.edges.is_empty());
}

#[test]
fn an_entry_whose_state_is_not_final_decodes_beside_one_whose_state_is_final() {
    // Land replies with the position first; the state may still be HELD or SUSPECT.
    let held = Entry {
        position: 1_000,
        ..sample_entry(EntryState::Held, None)
    };
    let held_value = held.to_canonical_value();
    assert!(
        !map_of(&held_value).contains_key("checkpoint_index"),
        "an entry with no checkpoint omits the member"
    );
    let decoded = Entry::decode_canonical(&held.encode_canonical()).expect("HELD entry decodes");
    assert_eq!(decoded.position, 1_000);
    assert_eq!(decoded.state, EntryState::Held);
    assert_eq!(decoded.checkpoint_index, None);

    let suspect = sample_entry(EntryState::Suspect, None);
    let decoded =
        Entry::decode_canonical(&suspect.encode_canonical()).expect("SUSPECT entry decodes");
    assert_eq!(decoded.state, EntryState::Suspect);
    assert!(!decoded.witnesses.is_empty());

    let clean = Entry {
        position: 1_000,
        ..sample_entry(EntryState::Clean, Some(12))
    };
    let clean_value = clean.to_canonical_value();
    assert_eq!(
        map_of(&clean_value).get("checkpoint_index"),
        Some(&CanonicalValue::Uint(12))
    );
    let decoded = Entry::decode_canonical(&clean.encode_canonical()).expect("CLEAN entry decodes");
    assert_eq!(decoded.position, 1_000);
    assert_eq!(decoded.state, EntryState::Clean);
    assert_eq!(decoded.checkpoint_index, Some(12));

    // The same position, two states: the entry is identified by both, so the bytes differ.
    assert_ne!(held.encode_canonical(), clean.encode_canonical());
}

// ===========================================================================
// 5. Any base position from 0 to head decodes; no client refresh is required.
// ===========================================================================

#[test]
fn any_base_position_from_zero_to_head_decodes_as_valid_input() {
    let refusals = load_refusals();
    assert!(!refusals.base_cases.is_empty());
    for case in &refusals.base_cases {
        assert!(
            case.accept.contains(&0),
            "head {}: position 0 must be accepted",
            case.head
        );
        assert!(
            case.accept.contains(&case.head),
            "head {}: the head itself must be accepted",
            case.head
        );
        for &base in &case.accept {
            let bytes = minimal_submission(Base::LogPosition(base)).encode_canonical();
            let decoded = ChangesetV2Submission::decode_canonical(&bytes, case.head)
                .unwrap_or_else(|e| panic!("base {base} at head {}: {e:?}", case.head));
            assert_eq!(decoded.base, Base::LogPosition(base));
        }
    }

    // Every position of a small log, one by one.
    let head = refusals.sweep_head;
    for base in 0..=head {
        let bytes = minimal_submission(Base::LogPosition(base)).encode_canonical();
        let decoded = ChangesetV2Submission::decode_canonical(&bytes, head)
            .unwrap_or_else(|e| panic!("base {base} at head {head}: {e:?}"));
        assert_eq!(decoded.base, Base::LogPosition(base));
    }
}

#[test]
fn a_base_position_past_the_head_is_refused_with_a_distinct_error() {
    let refusals = load_refusals();
    for case in &refusals.base_cases {
        for &base in &case.refuse {
            let bytes = minimal_submission(Base::LogPosition(base)).encode_canonical();
            expect_beyond_head(
                ChangesetV2Submission::decode_canonical(&bytes, case.head),
                base,
                case.head,
                "base past head",
            );
        }
    }

    let head = refusals.sweep_head;
    for base in (head + 1)..=refusals.sweep_refuse_through {
        let bytes = minimal_submission(Base::LogPosition(base)).encode_canonical();
        expect_beyond_head(
            ChangesetV2Submission::decode_canonical(&bytes, head),
            base,
            head,
            "sweep past head",
        );
    }

    // The error is its own variant, not one of the other refusals.
    let past = minimal_submission(Base::LogPosition(head + 1)).encode_canonical();
    let beyond = ChangesetV2Submission::decode_canonical(&past, head).expect_err("past head");
    let other = ChangesetV2Submission::decode_canonical(&[], head).expect_err("empty input");
    assert_ne!(
        std::mem::discriminant(&beyond),
        std::mem::discriminant(&other),
        "a base past the head must not share an error kind with malformed input"
    );
}

#[test]
fn a_changeset_stays_valid_as_the_head_advances_so_no_client_refresh_is_needed() {
    let base = 5;
    let bytes = minimal_submission(Base::LogPosition(base)).encode_canonical();
    for head in [base, base + 1, 7, 64, 1_000, 1 << 32, u64::MAX] {
        let decoded = ChangesetV2Submission::decode_canonical(&bytes, head)
            .unwrap_or_else(|e| panic!("base {base} at head {head}: {e:?}"));
        assert_eq!(decoded.base, Base::LogPosition(base));
        assert!(
            decoded.encode_canonical() == bytes,
            "head {head}: decoding must not rewrite the base"
        );
    }
    for head in 0..base {
        expect_beyond_head(
            ChangesetV2Submission::decode_canonical(&bytes, head),
            base,
            head,
            "head behind the base",
        );
    }

    // A base at position 0 stays valid however far the log has grown.
    let oldest = minimal_submission(Base::LogPosition(0)).encode_canonical();
    ChangesetV2Submission::decode_canonical(&oldest, u64::MAX)
        .expect("the oldest base is valid at any head");
}

#[test]
fn a_proven_publication_base_is_valid_at_any_head() {
    let publication = PublicationId::from_hash(seed_hash("pub-any-head"));
    let bytes = minimal_submission(Base::ProvenPublication(publication)).encode_canonical();
    for head in [0, 1, 1_000, u64::MAX] {
        let decoded = ChangesetV2Submission::decode_canonical(&bytes, head)
            .unwrap_or_else(|e| panic!("publication base at head {head}: {e:?}"));
        assert_eq!(decoded.base, Base::ProvenPublication(publication));
    }
    let other = PublicationId::from_hash(seed_hash("pub-another"));
    assert_ne!(
        bytes,
        minimal_submission(Base::ProvenPublication(other)).encode_canonical(),
        "different publications must encode differently"
    );
}

// ===========================================================================
// 6. Frozen regression fixture: a vector may carry `expected_canonical_hex` and `expected_id_hex`,
//    which pin the exact bytes and id. The ignored emitter prints the values to add.
// ===========================================================================

#[test]
fn frozen_encodings_and_ids_match_when_a_vector_carries_them() {
    let mut frozen = 0usize;
    for v in load_vectors() {
        let stamped = stamp(&v);
        if let Some(expected) = &v.expected_canonical_hex {
            assert_eq!(
                &to_hex(&stamped.encode_canonical()),
                expected,
                "vector {}: canonical bytes changed",
                v.name
            );
            frozen += 1;
        }
        if let Some(expected) = &v.expected_id_hex {
            assert_eq!(
                &stamped.id().to_hex(),
                expected,
                "vector {}: id changed",
                v.name
            );
        }
    }
    eprintln!("frozen regression vectors checked: {frozen}");
}

#[test]
#[ignore = "prints the encodings and ids to freeze into vectors.json"]
fn emit_frozen_regression_fixture() {
    for v in load_vectors() {
        let stamped = stamp(&v);
        println!(
            "{} expected_canonical_hex={} expected_id_hex={}",
            v.name,
            to_hex(&stamped.encode_canonical()),
            stamped.id().to_hex()
        );
    }
}
