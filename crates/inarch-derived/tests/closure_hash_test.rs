//! Contract tests for target input-closure hashing for Go, Cargo, TypeScript and Python.
//!
//! `closure_hash(target, tree)` covers every transitive input of a build target: its sources, the
//! toolchain or interpreter pin, configuration, the lockfile entries it resolves and the closure
//! hash of each dependency. `(target, closure_hash)` is the only memo key.
//!
//! Public surface this suite compiles against (namespace `inarch_derived::closure_hash`):
//!
//! * `closure_hash(&Target, &Tree) -> Result<ClosureHash, ClosureError>` and
//!   `memo_key(&Target, &Tree) -> Result<MemoKey, ClosureError>`
//! * `Tree::from_files(iter of (path, bytes))`, `Tree::from_dir(&Path) -> io::Result<Tree>` (skips
//!   `.git`), `Tree::get(&str) -> Option<&[u8]>`
//! * `Target::new(Ecosystem, path)` with `Display` as `<ecosystem>:<path>` using the names
//!   `go`, `cargo`, `typescript` and `python`
//! * `TargetGraph::discover(&Tree, Ecosystem, root)`, `.targets()`, `.declared_closure(&Target)`,
//!   `.closure_hash(&Target, &Tree)`
//! * `Input { kind: InputKind, .. }` whose `Display` is `<kind>:<key>` (see the fixture notes)
//! * `ClosureHash` (`Copy + Eq + Ord + Hash + Debug + Display`, `to_hex`, `as_bytes`),
//!   `MemoKey { target, closure_hash }` (`Clone + Eq + Hash + Debug`, exactly these two public
//!   fields), `CLOSURE_HASH_DOMAIN`, `Ecosystem` (exactly four variants), `InputKind` (exactly five
//!   variants), `ClosureError` (`Debug + Display`, the `Debug` text starts with the error kind)
//!
//! Contract choices the fixtures encode:
//!
//! * Sources are the language source files of a target (`.go`, `.rs`, `.ts`, `.py`); prose files,
//!   backup files and version-control metadata are never inputs.
//! * The toolchain or interpreter version is read from tree content only (`go.mod`,
//!   `rust-toolchain.toml`, `.nvmrc`, `.python-version`); the host is never consulted.
//! * Lockfiles contribute per-entry inputs: only the entries a target resolves, transitively, hold
//!   it. Go treats every `// indirect` module as held by every Go target in the module (a sound
//!   over-approximation, since go.sum alone does not say who imports an indirect module).
//! * In-workspace dependency edges come from the manifests; a refused tree never yields a hash.
//!
//! Cross-host and real-repository clauses are `#[ignore]` probes at the end of this file; their
//! runnable steps are in `fixtures/closure_hash/test_code_steps.toml`.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use inarch_derived::closure_hash::{
    CLOSURE_HASH_DOMAIN, ClosureError, ClosureHash, Ecosystem, InputKind, MemoKey, Target,
    TargetGraph, Tree, closure_hash, memo_key,
};

const TREES_JSON: &str = include_str!("fixtures/closure_hash/trees.json");
const PINNED_REPOS_TOML: &str = include_str!("fixtures/closure_hash/pinned_repos.toml");
const TEST_CODE_STEPS_TOML: &str = include_str!("fixtures/closure_hash/test_code_steps.toml");

const ECOSYSTEM_NAMES: [&str; 4] = ["go", "cargo", "typescript", "python"];
const REFUSAL_KINDS: [&str; 6] = [
    "MissingToolchain",
    "MissingLockfile",
    "UnresolvedDependency",
    "DependencyCycle",
    "Malformed",
    "UnknownTarget",
];
const REQUIRED_STEP_IDS: [&str; 8] = [
    "run-in-process-suite",
    "checkout-pinned-repositories",
    "emit-hash-csv-first-host",
    "emit-hash-csv-second-host",
    "compare-hash-csvs",
    "run-real-repository-mutation-probe",
    "run-real-repository-outside-edit-probe",
    "run-ignored-probes-together",
];
const ORPHAN_ENTRY_NAMES: [&str; 8] = [
    "example.org/stale",
    "unused-crate",
    "orphan-lib",
    "ghostpkg",
    "example.org/old",
    "dead-crate",
    "ghost-pkg",
    "lost-pkg",
];

const CAMPAIGN_ITERATIONS: usize = 900;
const CAMPAIGN_SEED: u64 = 0x5EED_C105_0001;
const MIN_INPUT_MUTATIONS: usize = 1000;
const MIN_PER_CLASS_MUTATIONS: usize = 100;
const PROBE_MUTATIONS_PER_REPO: usize = 150;
const PROBE_CLASSES: [&str; 4] = ["source", "toolchain", "config", "lock"];

const CSV_HEADER: &str = "repo,ecosystem,target,closure_hash";
const ENV_CHECKOUT_ROOT: &str = "CLOSURE_HASH_CHECKOUT_ROOT";
const ENV_CSV_OUT: &str = "CLOSURE_HASH_CSV_OUT";
const ENV_CSV_A: &str = "CLOSURE_HASH_CSV_A";
const ENV_CSV_B: &str = "CLOSURE_HASH_CSV_B";

type Files = BTreeMap<String, Vec<u8>>;
type Hashes = BTreeMap<String, String>;

// ---------------------------------------------------------------------------------------------
// Minimal JSON reader and writer (the repository carries no third-party crates).
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Json {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    fn fail(&self, what: &str) -> String {
        format!("json: {what} at byte {}", self.pos)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.fail(&format!("expected {:?}", char::from(byte))))
        }
    }

    fn parse_document(mut self) -> Result<Json, String> {
        let value = self.parse_value()?;
        self.skip_ws();
        if self.pos != self.bytes.len() {
            return Err(self.fail("trailing characters"));
        }
        Ok(value)
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Json::Str(self.parse_string()?)),
            Some(b't') => self.parse_literal("true", Json::Bool(true)),
            Some(b'f') => self.parse_literal("false", Json::Bool(false)),
            Some(b'n') => self.parse_literal("null", Json::Null),
            Some(byte) if byte == b'-' || byte.is_ascii_digit() => self.parse_number(),
            _ => Err(self.fail("unexpected token")),
        }
    }

    fn parse_literal(&mut self, word: &str, value: Json) -> Result<Json, String> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(self.fail("bad literal"))
        }
    }

    fn parse_number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        while matches!(
            self.peek(),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.pos += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|e| e.to_string())?;
        Ok(Json::Num(text.to_string()))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(self.fail("unterminated string"));
            };
            self.pos += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let Some(escape) = self.peek() else {
                        return Err(self.fail("dangling escape"));
                    };
                    self.pos += 1;
                    match escape {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'u' => {
                            let end = self.pos + 4;
                            if end > self.bytes.len() {
                                return Err(self.fail("short unicode escape"));
                            }
                            let digits = std::str::from_utf8(&self.bytes[self.pos..end])
                                .map_err(|e| e.to_string())?;
                            let code = u32::from_str_radix(digits, 16).map_err(|e| e.to_string())?;
                            let ch =
                                char::from_u32(code).ok_or_else(|| self.fail("bad code point"))?;
                            let mut buffer = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
                            self.pos = end;
                        }
                        _ => return Err(self.fail("unknown escape")),
                    }
                }
                _ => out.push(byte),
            }
        }
        String::from_utf8(out).map_err(|e| e.to_string())
    }

    fn parse_array(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(self.fail("expected , or ]")),
            }
        }
    }

    fn parse_object(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut fields = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(fields));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let value = self.parse_value()?;
            fields.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(fields));
                }
                _ => return Err(self.fail("expected , or }")),
            }
        }
    }
}

impl Json {
    fn opt_field(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    fn field(&self, key: &str) -> &Json {
        self.opt_field(key)
            .unwrap_or_else(|| panic!("fixture object has no field {key}"))
    }

    fn text(&self) -> &str {
        match self {
            Json::Str(text) => text.as_str(),
            other => panic!("fixture value is not a string: {other:?}"),
        }
    }

    fn items(&self) -> &[Json] {
        match self {
            Json::Arr(items) => items.as_slice(),
            other => panic!("fixture value is not an array: {other:?}"),
        }
    }

    fn entries(&self) -> &[(String, Json)] {
        match self {
            Json::Obj(fields) => fields.as_slice(),
            other => panic!("fixture value is not an object: {other:?}"),
        }
    }
}

/// Pretty-prints in the common two-space style: `"key": value`, one array element per line.
fn json_pretty(value: &Json) -> String {
    let mut out = String::new();
    json_write(value, 0, &mut out);
    out
}

fn json_write(value: &Json, depth: usize, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Json::Num(number) => out.push_str(number),
        Json::Str(text) => json_write_string(text, out),
        Json::Arr(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (index, item) in items.iter().enumerate() {
                out.push_str(&"  ".repeat(depth + 1));
                json_write(item, depth + 1, out);
                if index + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&"  ".repeat(depth));
            out.push(']');
        }
        Json::Obj(fields) => {
            if fields.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            for (index, (key, item)) in fields.iter().enumerate() {
                out.push_str(&"  ".repeat(depth + 1));
                json_write_string(key, out);
                out.push_str(": ");
                json_write(item, depth + 1, out);
                if index + 1 < fields.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&"  ".repeat(depth));
            out.push('}');
        }
    }
}

fn json_write_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if u32::from(control) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", u32::from(control)));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// A fixture file value is an array of lines, an object (rendered as pretty JSON) or a raw string.
fn render_file(value: &Json) -> Result<Vec<u8>, String> {
    match value {
        Json::Arr(lines) => {
            let mut text = String::new();
            for line in lines {
                match line {
                    Json::Str(content) => {
                        text.push_str(content);
                        text.push('\n');
                    }
                    other => return Err(format!("file line is not a string: {other:?}")),
                }
            }
            Ok(text.into_bytes())
        }
        Json::Obj(_) => {
            let mut text = json_pretty(value);
            text.push('\n');
            Ok(text.into_bytes())
        }
        Json::Str(raw) => Ok(raw.clone().into_bytes()),
        other => Err(format!("unsupported file value: {other:?}")),
    }
}

// ---------------------------------------------------------------------------------------------
// Minimal TOML reader: root keys and `[[table]]` arrays whose values are basic strings.
// ---------------------------------------------------------------------------------------------

struct TomlDoc {
    root: BTreeMap<String, String>,
    tables: Vec<(String, BTreeMap<String, String>)>,
}

fn parse_toml_subset(text: &str) -> TomlDoc {
    let mut doc = TomlDoc {
        root: BTreeMap::new(),
        tables: Vec::new(),
    };
    for (number, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix("[[")
            .and_then(|rest| rest.strip_suffix("]]"))
        {
            doc.tables.push((name.trim().to_string(), BTreeMap::new()));
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("toml line {} has no '='", number + 1));
        let value = parse_toml_string(value.trim());
        let table = match doc.tables.last_mut() {
            Some((_, table)) => table,
            None => &mut doc.root,
        };
        table.insert(key.trim().to_string(), value);
    }
    doc
}

fn parse_toml_string(value: &str) -> String {
    let inner = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or_else(|| panic!("toml value {value} is not a basic string"));
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            other => panic!("unsupported toml escape {other:?}"),
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Fixture model.
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct TargetModel {
    id: String,
    ecosystem: String,
    root: String,
    deps: Vec<String>,
    own: Vec<String>,
}

struct Site {
    id: String,
    kind: String,
    file: String,
    after: Option<String>,
    prefix: String,
    until: String,
    alphabet: String,
    input: String,
}

enum Op {
    Write { file: String, content: Vec<u8> },
    Replace { file: String, from: String, to: String },
    Delete { file: String },
}

struct Edit {
    name: String,
    ops: Vec<Op>,
    changed: Vec<String>,
    patches: BTreeMap<String, Vec<String>>,
}

struct Refusal {
    name: String,
    target: String,
    expect: String,
    ops: Vec<Op>,
}

struct FixtureTree {
    name: String,
    roots: BTreeMap<String, String>,
    files: Files,
    common: BTreeMap<String, Vec<String>>,
    targets: Vec<TargetModel>,
    sites: Vec<Site>,
    edits: Vec<Edit>,
    refusals: Vec<Refusal>,
}

fn strings(node: &Json) -> Vec<String> {
    node.items()
        .iter()
        .map(|item| item.text().to_string())
        .collect()
}

fn parse_ops(node: &Json) -> Vec<Op> {
    node.items()
        .iter()
        .map(|op| {
            if let Some(file) = op.opt_field("write") {
                Op::Write {
                    file: file.text().to_string(),
                    content: render_file(op.field("content"))
                        .unwrap_or_else(|why| panic!("fixture write content: {why}")),
                }
            } else if let Some(file) = op.opt_field("replace") {
                Op::Replace {
                    file: file.text().to_string(),
                    from: op.field("from").text().to_string(),
                    to: op.field("to").text().to_string(),
                }
            } else if let Some(file) = op.opt_field("delete") {
                Op::Delete {
                    file: file.text().to_string(),
                }
            } else {
                panic!("fixture op has no write, replace or delete key");
            }
        })
        .collect()
}

fn parse_tree(node: &Json) -> FixtureTree {
    let roots: BTreeMap<String, String> = node
        .field("roots")
        .entries()
        .iter()
        .map(|(eco, root)| (eco.clone(), root.text().to_string()))
        .collect();
    let files: Files = node
        .field("files")
        .entries()
        .iter()
        .map(|(path, value)| {
            let bytes = render_file(value).unwrap_or_else(|why| panic!("file {path}: {why}"));
            (path.clone(), bytes)
        })
        .collect();
    let common: BTreeMap<String, Vec<String>> = node
        .field("common")
        .entries()
        .iter()
        .map(|(eco, list)| (eco.clone(), strings(list)))
        .collect();
    let targets: Vec<TargetModel> = node
        .field("targets")
        .items()
        .iter()
        .map(|item| TargetModel {
            id: item.field("id").text().to_string(),
            ecosystem: item.field("ecosystem").text().to_string(),
            root: item.field("root").text().to_string(),
            deps: strings(item.field("deps")),
            own: strings(item.field("own")),
        })
        .collect();
    let sites: Vec<Site> = node
        .field("sites")
        .items()
        .iter()
        .map(|item| Site {
            id: item.field("id").text().to_string(),
            kind: item.field("kind").text().to_string(),
            file: item.field("file").text().to_string(),
            after: item.opt_field("after").map(|v| v.text().to_string()),
            prefix: item.field("prefix").text().to_string(),
            until: item.field("until").text().to_string(),
            alphabet: item.field("alphabet").text().to_string(),
            input: item.field("input").text().to_string(),
        })
        .collect();
    let edits: Vec<Edit> = node
        .field("edits")
        .items()
        .iter()
        .map(|item| Edit {
            name: item.field("name").text().to_string(),
            ops: parse_ops(item.field("ops")),
            changed: strings(item.field("changed")),
            patches: item
                .field("patches")
                .entries()
                .iter()
                .map(|(id, patch)| (id.clone(), strings(patch.field("deps"))))
                .collect(),
        })
        .collect();
    let refusals: Vec<Refusal> = node
        .field("refusals")
        .items()
        .iter()
        .map(|item| Refusal {
            name: item.field("name").text().to_string(),
            target: item.field("target").text().to_string(),
            expect: item.field("expect").text().to_string(),
            ops: parse_ops(item.field("ops")),
        })
        .collect();
    FixtureTree {
        name: node.field("name").text().to_string(),
        roots,
        files,
        common,
        targets,
        sites,
        edits,
        refusals,
    }
}

fn load_fixture_trees() -> Vec<FixtureTree> {
    let document = JsonParser::new(TREES_JSON)
        .parse_document()
        .unwrap_or_else(|why| panic!("trees.json does not parse: {why}"));
    assert_eq!(document.field("schema").text(), "closure-hash-trees/1");
    document.field("trees").items().iter().map(parse_tree).collect()
}

/// The hand-authored model: per target the inputs it holds itself and its direct dependencies.
/// The expected closure is computed here, never by the library under test.
#[derive(Clone)]
struct Model {
    common: BTreeMap<String, Vec<String>>,
    targets: BTreeMap<String, TargetModel>,
}

impl Model {
    fn from_tree(tree: &FixtureTree) -> Self {
        Self {
            common: tree.common.clone(),
            targets: tree
                .targets
                .iter()
                .map(|target| (target.id.clone(), target.clone()))
                .collect(),
        }
    }

    fn patched(&self, patches: &BTreeMap<String, Vec<String>>) -> Self {
        let mut next = self.clone();
        for (id, deps) in patches {
            next.targets
                .get_mut(id)
                .unwrap_or_else(|| panic!("patch names unknown target {id}"))
                .deps = deps.clone();
        }
        next
    }

    fn closure(&self, id: &str) -> BTreeSet<String> {
        let target = self
            .targets
            .get(id)
            .unwrap_or_else(|| panic!("model has no target {id}"));
        let mut set: BTreeSet<String> = self
            .common
            .get(&target.ecosystem)
            .map(|inputs| inputs.iter().cloned().collect())
            .unwrap_or_default();
        set.extend(target.own.iter().cloned());
        for dep in &target.deps {
            set.insert(format!("dep:{dep}"));
            set.extend(self.closure(dep));
        }
        set
    }

    fn holders_of(&self, input: &str) -> BTreeSet<String> {
        if input.is_empty() {
            return BTreeSet::new();
        }
        self.targets
            .keys()
            .filter(|id| self.closure(id).contains(input))
            .cloned()
            .collect()
    }

    fn chain_depth(&self, id: &str) -> usize {
        self.targets[id]
            .deps
            .iter()
            .map(|dep| self.chain_depth(dep) + 1)
            .max()
            .unwrap_or(0)
    }
}

fn apply_ops(files: &mut Files, ops: &[Op]) -> Result<(), String> {
    for op in ops {
        match op {
            Op::Write { file, content } => {
                files.insert(file.clone(), content.clone());
            }
            Op::Delete { file } => {
                if files.remove(file).is_none() {
                    return Err(format!("delete of missing file {file}"));
                }
            }
            Op::Replace { file, from, to } => {
                let Some(bytes) = files.get(file) else {
                    return Err(format!("replace in missing file {file}"));
                };
                let text = String::from_utf8(bytes.clone()).map_err(|e| e.to_string())?;
                let count = text.matches(from.as_str()).count();
                if count != 1 {
                    return Err(format!("replace source occurs {count} times in {file}: {from:?}"));
                }
                files.insert(file.clone(), text.replacen(from.as_str(), to, 1).into_bytes());
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Seeded generator and single-character mutations.
// ---------------------------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        assert!(bound > 0, "bound must be positive");
        usize::try_from(self.next_u64() % u64::try_from(bound).expect("bound fits in u64"))
            .expect("remainder fits in usize")
    }
}

fn alphabet_chars(name: &str) -> Vec<char> {
    match name {
        "lower" => ('a'..='z').collect(),
        "alnum" => ('a'..='z').chain('0'..='9').collect(),
        "digits" => ('0'..='9').collect(),
        "01" => vec!['0', '1'],
        "hex" => ('0'..='9').chain('a'..='f').collect(),
        "sz" => vec!['s', 'z'],
        "b64" => ('A'..='Z')
            .chain('a'..='z')
            .chain('0'..='9')
            .chain(['+', '/'])
            .collect(),
        other => panic!("unknown alphabet {other}"),
    }
}

/// Byte range of the mutable span of a site. The anchor (or the prefix when there is no anchor)
/// must occur exactly once, so a mutation can never land on an unintended occurrence.
fn locate_span(text: &str, site: &Site) -> Result<(usize, usize), String> {
    let base = match &site.after {
        Some(anchor) => {
            if text.matches(anchor.as_str()).count() != 1 {
                return Err(format!("anchor {anchor:?} must occur exactly once"));
            }
            text.find(anchor.as_str()).expect("anchor was counted") + anchor.len()
        }
        None => {
            if text.matches(site.prefix.as_str()).count() != 1 {
                return Err(format!("prefix {:?} must occur exactly once", site.prefix));
            }
            0
        }
    };
    let tail = &text[base..];
    let prefix_at = tail
        .find(site.prefix.as_str())
        .ok_or_else(|| format!("prefix {:?} not found", site.prefix))?;
    let start = prefix_at + site.prefix.len();
    let length = tail[start..]
        .find(site.until.as_str())
        .ok_or_else(|| format!("terminator {:?} not found", site.until))?;
    if length == 0 {
        return Err("span is empty".to_string());
    }
    Ok((base + start, base + start + length))
}

struct EditRecord {
    offset: usize,
    old: char,
    new: char,
}

/// Replaces exactly one character of the site's span with a different character of its alphabet.
fn mutate(files: &mut Files, site: &Site, rng: &mut Rng) -> Result<EditRecord, String> {
    let bytes = files
        .get_mut(&site.file)
        .ok_or_else(|| format!("file {} is absent", site.file))?;
    let (start, end) = {
        let text = std::str::from_utf8(bytes.as_slice()).map_err(|e| e.to_string())?;
        locate_span(text, site)?
    };
    let offset = rng.below(end - start);
    let old = char::from(bytes[start + offset]);
    let pool: Vec<char> = alphabet_chars(&site.alphabet)
        .into_iter()
        .filter(|candidate| *candidate != old)
        .collect();
    let new = pool[rng.below(pool.len())];
    bytes[start + offset] = u8::try_from(u32::from(new)).map_err(|e| e.to_string())?;
    Ok(EditRecord { offset, old, new })
}

// ---------------------------------------------------------------------------------------------
// Library adapters used by the tests.
// ---------------------------------------------------------------------------------------------

fn ecosystem_from_name(name: &str) -> Ecosystem {
    match name {
        "go" => Ecosystem::Go,
        "cargo" => Ecosystem::Cargo,
        "typescript" => Ecosystem::TypeScript,
        "python" => Ecosystem::Python,
        other => panic!("unknown ecosystem name {other}"),
    }
}

/// Exhaustive on purpose: a fifth ecosystem variant stops this suite from compiling.
fn ecosystem_name(ecosystem: Ecosystem) -> &'static str {
    match ecosystem {
        Ecosystem::Go => "go",
        Ecosystem::Cargo => "cargo",
        Ecosystem::TypeScript => "typescript",
        Ecosystem::Python => "python",
    }
}

/// Exhaustive on purpose: the closure is made of exactly these five kinds of input.
fn kind_label(kind: &InputKind) -> &'static str {
    match kind {
        InputKind::Source => "source",
        InputKind::Toolchain => "toolchain",
        InputKind::Config => "config",
        InputKind::Lockfile => "lock",
        InputKind::Dependency => "dep",
    }
}

fn parse_target(id: &str) -> Target {
    let (ecosystem, path) = id
        .split_once(':')
        .unwrap_or_else(|| panic!("target id {id} has no ecosystem prefix"));
    Target::new(ecosystem_from_name(ecosystem), path)
}

fn snapshot(files: &Files) -> Tree {
    Tree::from_files(files.clone())
}

fn hash_snapshot(
    snap: &Tree,
    tree: &FixtureTree,
) -> Result<BTreeMap<String, ClosureHash>, ClosureError> {
    let mut hashes = BTreeMap::new();
    for (eco_name, root) in &tree.roots {
        let graph = TargetGraph::discover(snap, ecosystem_from_name(eco_name), root)?;
        for target in graph.targets() {
            let hash = graph.closure_hash(&target, snap)?;
            hashes.insert(target.to_string(), hash);
        }
    }
    Ok(hashes)
}

fn library_hashes(tree: &FixtureTree, files: &Files) -> Hashes {
    hash_snapshot(&snapshot(files), tree)
        .unwrap_or_else(|err| panic!("{}: the library refused a valid tree: {err}", tree.name))
        .into_iter()
        .map(|(id, hash)| (id, hash.to_hex()))
        .collect()
}

fn input_strings(graph: &TargetGraph, target: &Target) -> BTreeSet<String> {
    graph
        .declared_closure(target)
        .unwrap_or_else(|err| panic!("declared_closure({target}) failed: {err}"))
        .into_iter()
        .map(|input| input.to_string())
        .collect()
}

fn error_kind(err: &ClosureError) -> String {
    format!("{err:?}")
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

fn diff_message(expected: &BTreeSet<String>, actual: &BTreeSet<String>) -> String {
    let missing: Vec<&String> = expected.difference(actual).collect();
    let extra: Vec<&String> = actual.difference(expected).collect();
    format!("missing from the closure: {missing:?}; extra in the closure: {extra:?}")
}

fn changed_targets(baseline: &Hashes, after: &Hashes) -> BTreeSet<String> {
    baseline
        .iter()
        .filter(|(id, hash)| after.get(*id) != Some(*hash))
        .map(|(id, _)| id.clone())
        .collect()
}

fn ecosystem_of_file(tree: &FixtureTree, file: &str) -> Option<String> {
    tree.roots
        .iter()
        .find(|(_, root)| file.starts_with(&format!("{root}/")))
        .map(|(eco, _)| eco.clone())
}

fn std_hash<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

// ---------------------------------------------------------------------------------------------
// Mutation campaign harness.
// ---------------------------------------------------------------------------------------------

struct SiteOutcome {
    log: String,
    changed: BTreeSet<String>,
    misses: Vec<String>,
    extras: Vec<String>,
}

#[derive(Default)]
struct Report {
    mutations: usize,
    outside_mutations: usize,
    per_kind: BTreeMap<String, usize>,
    per_ecosystem: BTreeMap<String, usize>,
    misses: Vec<String>,
    extras: Vec<String>,
    log: Vec<String>,
}

struct Campaign<'a> {
    tree: &'a FixtureTree,
    model: Model,
    baseline: Hashes,
    hasher: &'a dyn Fn(&Files) -> Hashes,
}

impl<'a> Campaign<'a> {
    fn new(tree: &'a FixtureTree, hasher: &'a dyn Fn(&Files) -> Hashes) -> Self {
        Self {
            tree,
            model: Model::from_tree(tree),
            baseline: hasher(&tree.files),
            hasher,
        }
    }

    fn evaluate(&self, site: &Site, rng: &mut Rng) -> SiteOutcome {
        let mut files = self.tree.files.clone();
        let edit = mutate(&mut files, site, rng)
            .unwrap_or_else(|why| panic!("site {} cannot be mutated: {why}", site.id));
        let after = (self.hasher)(&files);
        assert!(
            after.keys().eq(self.baseline.keys()),
            "mutation {} changed the set of targets",
            site.id
        );
        let changed = changed_targets(&self.baseline, &after);
        let expected = self.model.holders_of(&site.input);
        let misses = expected
            .difference(&changed)
            .map(|id| format!("{}: {id}", site.id))
            .collect();
        let extras = changed
            .difference(&expected)
            .map(|id| format!("{}: {id}", site.id))
            .collect();
        let log = format!(
            "{}@{}:{}>{} changed={:?}",
            site.id, edit.offset, edit.old, edit.new, changed
        );
        SiteOutcome {
            log,
            changed,
            misses,
            extras,
        }
    }
}

/// Every pass over the sites visits each one once, in a seeded random order; the character
/// position and the replacement character are drawn from the same generator.
fn run_campaign(campaign: &Campaign, iterations: usize, seed: u64) -> Report {
    let mut rng = Rng(seed);
    let mut report = Report::default();
    let mut order: Vec<usize> = Vec::new();
    for _ in 0..iterations {
        if order.is_empty() {
            order = (0..campaign.tree.sites.len()).collect();
            for index in (1..order.len()).rev() {
                let other = rng.below(index + 1);
                order.swap(index, other);
            }
        }
        let site_index = order.pop().expect("order was just refilled");
        let site = &campaign.tree.sites[site_index];
        let outcome = campaign.evaluate(site, &mut rng);
        report.mutations += 1;
        if site.kind == "outside" {
            report.outside_mutations += 1;
        } else {
            *report.per_kind.entry(site.kind.clone()).or_insert(0) += 1;
            if let Some(eco) = ecosystem_of_file(campaign.tree, &site.file) {
                *report.per_ecosystem.entry(eco).or_insert(0) += 1;
            }
        }
        report.misses.extend(outcome.misses);
        report.extras.extend(outcome.extras);
        report.log.push(outcome.log);
    }
    report
}

// ---------------------------------------------------------------------------------------------
// Negative controls: deliberately wrong hashers the harness must catch.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Control {
    OwnSourcesOnly,
    IgnoresLockfiles,
    IgnoresToolchains,
    WholeTree,
}

fn hash_input(hasher: &mut DefaultHasher, files: &Files, input: &str) {
    input.hash(hasher);
    let (kind, rest) = input.split_once(':').expect("input has a kind prefix");
    if kind != "dep" {
        let path = rest.split('#').next().expect("input has a path");
        files.get(path).hash(hasher);
    }
}

fn control_hashes(control: Control, tree: &FixtureTree, files: &Files) -> Hashes {
    let model = Model::from_tree(tree);
    let mut out = Hashes::new();
    for id in model.targets.keys() {
        let mut hasher = DefaultHasher::new();
        match control {
            Control::WholeTree => {
                for (path, bytes) in files {
                    path.hash(&mut hasher);
                    bytes.hash(&mut hasher);
                }
            }
            Control::OwnSourcesOnly => {
                for input in model.targets[id]
                    .own
                    .iter()
                    .filter(|input| input.starts_with("source:"))
                {
                    hash_input(&mut hasher, files, input);
                }
            }
            Control::IgnoresLockfiles => {
                for input in model
                    .closure(id)
                    .iter()
                    .filter(|input| !input.starts_with("lock:"))
                {
                    hash_input(&mut hasher, files, input);
                }
            }
            Control::IgnoresToolchains => {
                for input in model
                    .closure(id)
                    .iter()
                    .filter(|input| !input.starts_with("toolchain:"))
                {
                    hash_input(&mut hasher, files, input);
                }
            }
        }
        out.insert(id.clone(), format!("{:016x}", hasher.finish()));
    }
    out
}

fn run_control_campaign(control: Control) -> Report {
    let trees = load_fixture_trees();
    let tree = &trees[0];
    let hasher = |files: &Files| control_hashes(control, tree, files);
    let campaign = Campaign::new(tree, &hasher);
    run_campaign(&campaign, 200, CAMPAIGN_SEED)
}

// ---------------------------------------------------------------------------------------------
// Directory helpers for the two-host emulation.
// ---------------------------------------------------------------------------------------------

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let serial = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "closure-hash-{label}-{}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temporary directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn age_file(path: &Path) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open file to update its timestamp");
    file.set_modified(UNIX_EPOCH + Duration::from_secs(1_000_000_000))
        .expect("set modification time");
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("restrict file permissions");
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

/// Writes the files in forward or reverse order; `perturb` gives every file an old timestamp and
/// restrictive permissions, the way a different checkout host might.
fn write_tree(root: &Path, files: &Files, reverse: bool, perturb: bool) {
    let mut entries: Vec<(&String, &Vec<u8>)> = files.iter().collect();
    if reverse {
        entries.reverse();
    }
    for (relative, bytes) in entries {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("file has a parent directory"))
            .expect("create parent directories");
        std::fs::write(&path, bytes).expect("write file");
        if perturb {
            age_file(&path);
            restrict_permissions(&path);
        }
    }
}

fn write_extra(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().expect("file has a parent directory"))
        .expect("create parent directories");
    std::fs::write(&path, bytes).expect("write file");
}

// ---------------------------------------------------------------------------------------------
// Fixture self-checks: the contract data itself must be well formed.
// ---------------------------------------------------------------------------------------------

#[test]
fn fixture_trees_cover_all_four_ecosystems_with_transitive_chains() {
    let trees = load_fixture_trees();
    assert_eq!(trees.len(), 2, "two fixture trees are required");
    for tree in &trees {
        let model = Model::from_tree(tree);
        for name in ECOSYSTEM_NAMES {
            assert!(
                tree.roots.contains_key(name),
                "{}: no workspace root for {name}",
                tree.name
            );
            let members: Vec<&TargetModel> = model
                .targets
                .values()
                .filter(|target| target.ecosystem == name)
                .collect();
            assert!(
                members.len() >= 3,
                "{}: {name} needs at least three targets",
                tree.name
            );
            for target in &members {
                assert_eq!(target.id, format!("{name}:{}", target.root));
            }
            let deepest = members
                .iter()
                .map(|target| model.chain_depth(&target.id))
                .max()
                .unwrap_or(0);
            let required = if tree.name == "tree-a" { 2 } else { 1 };
            assert!(
                deepest >= required,
                "{}: {name} needs a dependency chain of depth {required}, found {deepest}",
                tree.name
            );
        }
    }
}

#[test]
fn fixture_mutation_sites_each_locate_exactly_one_span() {
    for tree in load_fixture_trees() {
        let mut seen = BTreeSet::new();
        for site in &tree.sites {
            assert!(seen.insert(site.id.clone()), "duplicate site id {}", site.id);
            let bytes = tree
                .files
                .get(&site.file)
                .unwrap_or_else(|| panic!("{}: file {} is not in the tree", site.id, site.file));
            let text = std::str::from_utf8(bytes).expect("fixture files are UTF-8");
            let (start, end) =
                locate_span(text, site).unwrap_or_else(|why| panic!("{}: {why}", site.id));
            assert!(text[start..end].is_ascii(), "{}: span is not ASCII", site.id);
            assert!(
                alphabet_chars(&site.alphabet).len() >= 2,
                "{}: alphabet is too small to mutate",
                site.id
            );
            assert!(
                ["source", "toolchain", "config", "lock", "outside"].contains(&site.kind.as_str()),
                "{}: unknown kind {}",
                site.id,
                site.kind
            );
        }
        assert!(
            tree.sites.iter().filter(|s| s.kind != "outside").count() >= 40,
            "{}: too few input sites for a meaningful campaign",
            tree.name
        );
    }
}

#[test]
fn fixture_edits_and_refusals_apply_to_their_base_trees() {
    for tree in load_fixture_trees() {
        for edit in &tree.edits {
            let mut files = tree.files.clone();
            apply_ops(&mut files, &edit.ops)
                .unwrap_or_else(|why| panic!("{}: edit {}: {why}", tree.name, edit.name));
            assert!(!edit.changed.is_empty(), "edit {} expects no change", edit.name);
        }
        for refusal in &tree.refusals {
            let mut files = tree.files.clone();
            apply_ops(&mut files, &refusal.ops)
                .unwrap_or_else(|why| panic!("{}: refusal {}: {why}", tree.name, refusal.name));
            assert!(
                REFUSAL_KINDS.contains(&refusal.expect.as_str()),
                "refusal {} expects an unknown error kind {}",
                refusal.name,
                refusal.expect
            );
        }
    }
}

#[test]
fn pinned_repositories_list_two_per_ecosystem_with_forty_hex_pins() {
    let doc = parse_toml_subset(PINNED_REPOS_TOML);
    assert_eq!(
        doc.root.get("schema").map(String::as_str),
        Some("closure-hash-pinned-repos/1")
    );
    let resolved = doc.root.get("resolved_on").expect("resolved_on is recorded");
    assert!(
        resolved.len() == 10 && resolved.matches('-').count() == 2,
        "resolved_on must be an ISO date: {resolved}"
    );
    assert_eq!(doc.tables.len(), 8, "2 pinned repositories per ecosystem");
    let mut per_ecosystem: BTreeMap<String, usize> = BTreeMap::new();
    let mut names = BTreeSet::new();
    let mut urls = BTreeSet::new();
    let mut shas = BTreeSet::new();
    for (table, repo) in &doc.tables {
        assert_eq!(table.as_str(), "repo");
        for key in [
            "name",
            "ecosystem",
            "url",
            "default_branch",
            "sha",
            "manifest",
            "lockfile",
        ] {
            assert!(
                repo.get(key).is_some_and(|value| !value.is_empty()),
                "repository entry lacks {key}: {repo:?}"
            );
        }
        let ecosystem = repo["ecosystem"].as_str();
        assert!(
            ECOSYSTEM_NAMES.contains(&ecosystem),
            "unknown ecosystem {ecosystem}"
        );
        *per_ecosystem.entry(ecosystem.to_string()).or_insert(0) += 1;
        let sha = repo["sha"].as_str();
        assert!(
            sha.len() == 40 && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "pin must be a lowercase 40-hex commit: {sha}"
        );
        assert!(
            repo["url"].starts_with("https://github.com/"),
            "pinned repositories are public https urls"
        );
        assert!(names.insert(repo["name"].clone()), "duplicate repository name");
        assert!(urls.insert(repo["url"].clone()), "duplicate repository url");
        assert!(shas.insert(repo["sha"].clone()), "duplicate pinned commit");
        let (manifest, lockfile, pin_file) = match ecosystem {
            "go" => ("go.mod", "go.sum", None),
            "cargo" => ("Cargo.toml", "Cargo.lock", Some("rust-toolchain.toml")),
            "typescript" => ("package.json", "package-lock.json", Some(".nvmrc")),
            _ => ("pyproject.toml", "uv.lock", Some(".python-version")),
        };
        assert_eq!(repo["manifest"].as_str(), manifest);
        assert_eq!(repo["lockfile"].as_str(), lockfile);
        assert_eq!(repo.get("pin_file").map(String::as_str), pin_file);
        assert_eq!(
            repo.get("pin_content").is_some(),
            pin_file.is_some(),
            "pin_file and pin_content come together"
        );
    }
    for name in ECOSYSTEM_NAMES {
        assert_eq!(
            per_ecosystem.get(name).copied(),
            Some(2),
            "{name} needs exactly two pinned repositories"
        );
    }
}

#[test]
fn test_code_steps_name_every_cross_host_and_real_repository_probe() {
    let doc = parse_toml_subset(TEST_CODE_STEPS_TOML);
    assert_eq!(
        doc.root.get("schema").map(String::as_str),
        Some("closure-hash-test-code-steps/1")
    );
    let mut by_id: BTreeMap<String, &BTreeMap<String, String>> = BTreeMap::new();
    for (table, step) in &doc.tables {
        assert_eq!(table.as_str(), "step");
        for key in ["id", "clause", "host", "command", "expect"] {
            assert!(
                step.get(key).is_some_and(|value| !value.trim().is_empty()),
                "step lacks {key}: {step:?}"
            );
        }
        assert!(
            ["cross-host", "mutation-sensitivity", "outside-edit", "all"]
                .contains(&step["clause"].as_str()),
            "step {} names an unknown clause",
            step["id"]
        );
        assert!(
            by_id.insert(step["id"].clone(), step).is_none(),
            "duplicate step id {}",
            step["id"]
        );
    }
    for required in REQUIRED_STEP_IDS {
        assert!(by_id.contains_key(required), "missing step {required}");
    }
    assert_ne!(
        by_id["emit-hash-csv-first-host"]["host"],
        by_id["emit-hash-csv-second-host"]["host"],
        "the two CSVs must come from two distinct hosts"
    );
    for step in by_id.values() {
        assert!(
            !step["command"].contains("TODO") && !step["expect"].contains("TODO"),
            "step {} has a placeholder",
            step["id"]
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Positive contract: shape of the public types.
// ---------------------------------------------------------------------------------------------

#[test]
fn exactly_four_ecosystems_and_five_input_kinds_exist() {
    let names: Vec<&str> = [
        Ecosystem::Go,
        Ecosystem::Cargo,
        Ecosystem::TypeScript,
        Ecosystem::Python,
    ]
    .into_iter()
    .map(ecosystem_name)
    .collect();
    assert_eq!(names, ECOSYSTEM_NAMES.to_vec());
    let labels: Vec<&str> = [
        InputKind::Source,
        InputKind::Toolchain,
        InputKind::Config,
        InputKind::Lockfile,
        InputKind::Dependency,
    ]
    .iter()
    .map(kind_label)
    .collect();
    assert_eq!(labels, vec!["source", "toolchain", "config", "lock", "dep"]);
    for name in ECOSYSTEM_NAMES {
        let target = Target::new(ecosystem_from_name(name), "pkg/one");
        assert_eq!(target.to_string(), format!("{name}:pkg/one"));
    }
}

#[test]
fn closure_hash_values_are_fixed_width_hex_under_the_versioned_domain() {
    assert_eq!(CLOSURE_HASH_DOMAIN, "velenza-inarch.closure.v1");
    let trees = load_fixture_trees();
    let tree = &trees[0];
    let hash = closure_hash(&parse_target("go:go/svc/api"), &snapshot(&tree.files))
        .expect("hash of a valid target");
    let hex = hash.to_hex();
    assert_eq!(hex.len(), 64);
    assert!(
        hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "hex must be lowercase: {hex}"
    );
    assert_eq!(hash.as_bytes().len(), 32);
    let rebuilt: String = hash
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(rebuilt, hex);
    assert_eq!(format!("{hash}"), hex);
}

#[test]
fn declared_closure_equals_the_hand_authored_model_for_every_target() {
    for tree in load_fixture_trees() {
        let model = Model::from_tree(&tree);
        let snap = snapshot(&tree.files);
        for (eco_name, root) in &tree.roots {
            let graph = TargetGraph::discover(&snap, ecosystem_from_name(eco_name), root)
                .unwrap_or_else(|err| panic!("{}: discover {eco_name}: {err}", tree.name));
            let discovered: BTreeSet<String> = graph
                .targets()
                .iter()
                .map(|target| target.to_string())
                .collect();
            let modelled: BTreeSet<String> = model
                .targets
                .values()
                .filter(|target| &target.ecosystem == eco_name)
                .map(|target| target.id.clone())
                .collect();
            assert_eq!(discovered, modelled, "{}: {eco_name} target set", tree.name);
            for target in graph.targets() {
                let id = target.to_string();
                let declared = input_strings(&graph, &target);
                let expected = model.closure(&id);
                assert!(
                    declared == expected,
                    "{}: closure of {id} differs from the model: {}",
                    tree.name,
                    diff_message(&expected, &declared)
                );
                for input in graph.declared_closure(&target).expect("declared closure") {
                    let rendered = input.to_string();
                    let label = kind_label(&input.kind);
                    assert!(
                        rendered.starts_with(&format!("{label}:")),
                        "input {rendered} does not carry its kind {label}"
                    );
                }
            }
        }
    }
}

#[test]
fn graph_and_free_function_agree_for_every_target() {
    for tree in load_fixture_trees() {
        let snap = snapshot(&tree.files);
        let hashes = hash_snapshot(&snap, &tree).expect("hashes of a valid tree");
        assert_eq!(hashes.len(), tree.targets.len());
        for (id, graph_hash) in &hashes {
            let direct = closure_hash(&parse_target(id), &snap)
                .unwrap_or_else(|err| panic!("{}: closure_hash({id}): {err}", tree.name));
            assert_eq!(&direct, graph_hash, "{}: {id}", tree.name);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Clause 1 (in-process part): equal hashes across hosts. The real two-host run is a probe below.
// ---------------------------------------------------------------------------------------------

#[test]
fn closure_hash_is_deterministic_for_rebuilt_trees_and_insertion_orders() {
    for tree in load_fixture_trees() {
        let forward = hash_snapshot(&snapshot(&tree.files), &tree).expect("forward hashes");
        let again = hash_snapshot(&snapshot(&tree.files), &tree).expect("repeat hashes");
        let reversed = Tree::from_files(
            tree.files
                .iter()
                .rev()
                .map(|(path, bytes)| (path.clone(), bytes.clone())),
        );
        let reverse_hashes = hash_snapshot(&reversed, &tree).expect("reversed hashes");
        assert_eq!(forward, again, "{}: repeat run differs", tree.name);
        assert_eq!(forward, reverse_hashes, "{}: insertion order matters", tree.name);
        assert!(!forward.is_empty());
    }
}

#[test]
fn closure_hash_is_equal_for_one_tree_materialised_on_two_hosts() {
    for tree in load_fixture_trees() {
        let expected = hash_snapshot(&snapshot(&tree.files), &tree).expect("in-memory hashes");

        let host_one = TempDir::new("host-one");
        write_tree(host_one.path(), &tree.files, false, false);
        let host_two = TempDir::new("host-two");
        write_tree(host_two.path(), &tree.files, true, true);
        write_extra(host_two.path(), ".git/HEAD", b"ref: refs/heads/elsewhere\n");
        write_extra(host_two.path(), ".git/objects/pack/scratch.pack", b"not a real pack");

        let first = Tree::from_dir(host_one.path()).expect("read the first host");
        let second = Tree::from_dir(host_two.path()).expect("read the second host");
        assert!(
            second.get(".git/HEAD").is_none(),
            "version-control metadata must not enter the tree"
        );
        assert_eq!(
            hash_snapshot(&first, &tree).expect("first host hashes"),
            expected,
            "{}: first host differs from the in-memory tree",
            tree.name
        );
        assert_eq!(
            hash_snapshot(&second, &tree).expect("second host hashes"),
            expected,
            "{}: second host differs (timestamps, mode, order and .git must not matter)",
            tree.name
        );

        // Refusal: hosts that disagree on one in-closure byte must not compare equal, and exactly
        // the targets that declare that input differ.
        let site = tree
            .sites
            .iter()
            .find(|site| site.kind == "source")
            .expect("a source site exists");
        let mut drifted = tree.files.clone();
        mutate(&mut drifted, site, &mut Rng(11)).expect("mutate the drifted copy");
        let host_three = TempDir::new("host-three");
        write_tree(host_three.path(), &drifted, false, false);
        let third = Tree::from_dir(host_three.path()).expect("read the drifted host");
        let drifted_hashes = hash_snapshot(&third, &tree).expect("drifted hashes");
        let differing: BTreeSet<String> = expected
            .iter()
            .filter(|(id, hash)| drifted_hashes.get(*id) != Some(*hash))
            .map(|(id, _)| id.clone())
            .collect();
        assert_eq!(
            differing,
            Model::from_tree(&tree).holders_of(&site.input),
            "{}: drift in {} must change exactly its holders",
            tree.name,
            site.id
        );
        assert!(!differing.is_empty());
    }
}

#[test]
fn target_hashes_are_pairwise_distinct_within_a_tree() {
    for tree in load_fixture_trees() {
        let hashes = library_hashes(&tree, &tree.files);
        let distinct: BTreeSet<&String> = hashes.values().collect();
        assert_eq!(
            distinct.len(),
            hashes.len(),
            "{}: two targets share a closure hash",
            tree.name
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Clause 2: single-input mutations, 0 misses and 0 extras.
// ---------------------------------------------------------------------------------------------

#[test]
fn every_mutation_site_flips_exactly_the_targets_that_declare_it() {
    for tree in load_fixture_trees() {
        let hasher = |files: &Files| library_hashes(&tree, files);
        let campaign = Campaign::new(&tree, &hasher);
        let mut failures: Vec<String> = Vec::new();
        for (index, site) in tree.sites.iter().enumerate() {
            let mut rng = Rng(0xA110_0000 + u64::try_from(index).expect("index fits in u64"));
            let outcome = campaign.evaluate(site, &mut rng);
            failures.extend(outcome.misses.iter().map(|miss| format!("miss {miss}")));
            failures.extend(outcome.extras.iter().map(|extra| format!("extra {extra}")));
            if site.kind == "outside" {
                assert!(
                    outcome.changed.is_empty(),
                    "{}: outside site {} changed {:?}",
                    tree.name,
                    site.id,
                    outcome.changed
                );
            } else {
                assert!(
                    !outcome.changed.is_empty(),
                    "{}: input site {} changed no hash",
                    tree.name,
                    site.id
                );
            }
        }
        assert!(failures.is_empty(), "{}: {failures:?}", tree.name);
    }
}

#[test]
fn mutation_campaign_of_one_thousand_single_input_edits_has_zero_misses_and_zero_extras() {
    let mut input_mutations = 0usize;
    let mut per_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut per_ecosystem: BTreeMap<String, usize> = BTreeMap::new();
    let trees = load_fixture_trees();
    for (index, tree) in trees.iter().enumerate() {
        let hasher = |files: &Files| library_hashes(tree, files);
        let campaign = Campaign::new(tree, &hasher);
        let seed = CAMPAIGN_SEED + u64::try_from(index).expect("index fits in u64");
        let report = run_campaign(&campaign, CAMPAIGN_ITERATIONS, seed);
        assert!(
            report.misses.is_empty(),
            "{}: {} misses, first {:?}",
            tree.name,
            report.misses.len(),
            report.misses.first()
        );
        assert!(
            report.extras.is_empty(),
            "{}: {} extras, first {:?}",
            tree.name,
            report.extras.len(),
            report.extras.first()
        );
        input_mutations += report.mutations - report.outside_mutations;
        for (kind, count) in &report.per_kind {
            *per_kind.entry(kind.clone()).or_insert(0) += count;
        }
        for (eco, count) in &report.per_ecosystem {
            *per_ecosystem.entry(eco.clone()).or_insert(0) += count;
        }
    }
    assert!(
        input_mutations >= MIN_INPUT_MUTATIONS,
        "only {input_mutations} single-input mutations ran"
    );
    for kind in ["source", "toolchain", "config", "lock"] {
        let count = per_kind.get(kind).copied().unwrap_or(0);
        assert!(
            count >= MIN_PER_CLASS_MUTATIONS,
            "only {count} {kind} mutations ran"
        );
    }
    for name in ECOSYSTEM_NAMES {
        let count = per_ecosystem.get(name).copied().unwrap_or(0);
        assert!(
            count >= MIN_PER_CLASS_MUTATIONS,
            "only {count} {name} mutations ran"
        );
    }
}

#[test]
fn mutation_campaign_is_reproducible_from_its_seed() {
    let trees = load_fixture_trees();
    let tree = &trees[0];
    let hasher = |files: &Files| library_hashes(tree, files);
    let campaign = Campaign::new(tree, &hasher);
    let first = run_campaign(&campaign, 60, CAMPAIGN_SEED);
    let second = run_campaign(&campaign, 60, CAMPAIGN_SEED);
    let other = run_campaign(&campaign, 60, CAMPAIGN_SEED + 1);
    assert_eq!(first.log, second.log, "the same seed must replay the same campaign");
    assert_ne!(first.log, other.log, "a different seed must change the campaign");
}

#[test]
fn harness_detects_a_hasher_that_ignores_dependencies() {
    let report = run_control_campaign(Control::OwnSourcesOnly);
    assert!(
        !report.misses.is_empty(),
        "a hasher over own sources only must be reported as missing closures"
    );
}

#[test]
fn harness_detects_a_hasher_that_ignores_lockfile_entries() {
    let report = run_control_campaign(Control::IgnoresLockfiles);
    assert!(
        report.misses.iter().any(|miss| miss.contains("-lock-")),
        "a hasher that drops lockfile entries must miss lockfile mutations"
    );
}

#[test]
fn harness_detects_a_hasher_that_ignores_toolchain_pins() {
    let report = run_control_campaign(Control::IgnoresToolchains);
    assert!(
        report.misses.iter().any(|miss| miss.contains("-toolchain")),
        "a hasher that drops toolchain pins must miss toolchain mutations"
    );
}

#[test]
fn harness_detects_a_hasher_that_hashes_the_whole_tree() {
    let report = run_control_campaign(Control::WholeTree);
    assert!(
        !report.extras.is_empty(),
        "a whole-tree hasher must be reported as changing targets it does not feed"
    );
    assert!(
        report.misses.is_empty(),
        "a whole-tree hasher cannot miss a change"
    );
}

// ---------------------------------------------------------------------------------------------
// Clause 3: an edit outside every closure changes no hash.
// ---------------------------------------------------------------------------------------------

#[test]
fn edit_outside_every_closure_changes_no_hash() {
    for tree in load_fixture_trees() {
        let baseline = library_hashes(&tree, &tree.files);

        let outside: Vec<&Site> = tree
            .sites
            .iter()
            .filter(|site| site.kind == "outside")
            .collect();
        assert!(outside.len() >= 6, "{}: too few outside sites", tree.name);
        let covered: BTreeSet<String> = outside
            .iter()
            .filter_map(|site| ecosystem_of_file(&tree, &site.file))
            .collect();
        assert_eq!(
            covered.len(),
            ECOSYSTEM_NAMES.len(),
            "{}: every ecosystem needs an outside site (an unused lockfile entry)",
            tree.name
        );
        for site in &outside {
            for round in 0..8u64 {
                let mut files = tree.files.clone();
                mutate(&mut files, site, &mut Rng(100 + round)).expect("mutate outside site");
                assert_eq!(
                    library_hashes(&tree, &files),
                    baseline,
                    "{}: outside edit {} changed a hash",
                    tree.name,
                    site.id
                );
            }
        }

        // New files that no target reads, anywhere in the tree.
        let mut files = tree.files.clone();
        for (path, content) in [
            ("docs/new_guide.md", "a new guide\n"),
            ("LICENSE", "license text\n"),
            (".gitignore", "target\n"),
            (".git/HEAD", "ref: refs/heads/main\n"),
            ("go/CHANGELOG.md", "changes\n"),
            ("rs/CHANGELOG.md", "changes\n"),
            ("ts/CHANGELOG.md", "changes\n"),
            ("py/CHANGELOG.md", "changes\n"),
            ("go/notes.txt.orig", "backup\n"),
        ] {
            files.insert(path.to_string(), content.as_bytes().to_vec());
        }
        assert_eq!(
            library_hashes(&tree, &files),
            baseline,
            "{}: adding unrelated files changed a hash",
            tree.name
        );

        // Deleting an unrelated file changes nothing either.
        assert!(files.remove("README.md").is_some());
        assert_eq!(
            library_hashes(&tree, &files),
            baseline,
            "{}: deleting an unrelated file changed a hash",
            tree.name
        );
    }
}

#[test]
fn edit_inside_a_closure_is_not_mistaken_for_an_outside_edit() {
    for tree in load_fixture_trees() {
        let baseline = library_hashes(&tree, &tree.files);
        for name in ECOSYSTEM_NAMES {
            let site = tree
                .sites
                .iter()
                .find(|site| {
                    site.kind == "source"
                        && ecosystem_of_file(&tree, &site.file).as_deref() == Some(name)
                })
                .unwrap_or_else(|| panic!("{}: no {name} source site", tree.name));
            let mut files = tree.files.clone();
            mutate(&mut files, site, &mut Rng(7)).expect("mutate source site");
            let after = library_hashes(&tree, &files);
            assert!(
                !changed_targets(&baseline, &after).is_empty(),
                "{}: a source edit in {name} changed no hash",
                tree.name
            );
        }
    }
}

#[test]
fn unused_lock_entries_belong_to_no_closure() {
    for tree in load_fixture_trees() {
        let snap = snapshot(&tree.files);
        for (eco_name, root) in &tree.roots {
            let graph = TargetGraph::discover(&snap, ecosystem_from_name(eco_name), root)
                .unwrap_or_else(|err| panic!("{}: discover {eco_name}: {err}", tree.name));
            for target in graph.targets() {
                for input in input_strings(&graph, &target) {
                    for orphan in ORPHAN_ENTRY_NAMES {
                        assert!(
                            !input.contains(orphan),
                            "{}: {target} holds the unused lock entry {orphan}",
                            tree.name
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn go_indirect_modules_belong_to_every_go_target() {
    let trees = load_fixture_trees();
    let tree = &trees[0];
    assert_eq!(tree.name, "tree-a");
    let snap = snapshot(&tree.files);
    let graph = TargetGraph::discover(&snap, Ecosystem::Go, &tree.roots["go"]).expect("go graph");
    let targets = graph.targets();
    assert!(targets.len() >= 3);
    for target in targets {
        let inputs = input_strings(&graph, &target);
        assert!(
            inputs.contains("lock:go/go.sum#example.org/gamma"),
            "{target} must hold the indirect module"
        );
    }
}

#[test]
fn dependency_edge_edits_change_exactly_the_targets_that_gain_or_lose_the_edge() {
    let trees = load_fixture_trees();
    let tree = &trees[0];
    assert!(tree.edits.len() >= 8, "two edge edits per ecosystem are required");
    let model = Model::from_tree(tree);
    let baseline = library_hashes(tree, &tree.files);
    for edit in &tree.edits {
        let mut files = tree.files.clone();
        apply_ops(&mut files, &edit.ops)
            .unwrap_or_else(|why| panic!("edit {}: {why}", edit.name));
        let after = library_hashes(tree, &files);
        let expected: BTreeSet<String> = edit.changed.iter().cloned().collect();
        assert_eq!(
            changed_targets(&baseline, &after),
            expected,
            "edit {} must change exactly its declared targets",
            edit.name
        );
        let patched = model.patched(&edit.patches);
        let snap = snapshot(&files);
        for (eco_name, root) in &tree.roots {
            let graph = TargetGraph::discover(&snap, ecosystem_from_name(eco_name), root)
                .unwrap_or_else(|err| panic!("edit {}: discover {eco_name}: {err}", edit.name));
            for target in graph.targets() {
                let id = target.to_string();
                assert_eq!(
                    input_strings(&graph, &target),
                    patched.closure(&id),
                    "edit {}: declared closure of {id}",
                    edit.name
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The memo key carries only (target, closure_hash).
// ---------------------------------------------------------------------------------------------

#[test]
fn memo_key_is_exactly_the_target_and_its_closure_hash() {
    let trees = load_fixture_trees();
    let tree = &trees[0];
    let target = parse_target("go:go/svc/api");
    let snap = snapshot(&tree.files);
    let key = memo_key(&target, &snap).expect("memo key");

    // An exhaustive struct pattern: a third field (for example an interface hash) stops this
    // suite from compiling.
    let MemoKey {
        target: key_target,
        closure_hash: key_hash,
    } = key.clone();
    assert_eq!(key_target, target);
    assert_eq!(key_hash, closure_hash(&target, &snap).expect("closure hash"));

    let twin = MemoKey {
        target: target.clone(),
        closure_hash: key_hash,
    };
    assert_eq!(key, twin);
    assert_eq!(std_hash(&key), std_hash(&twin));

    // A body edit that leaves every exported name alone is still a different key.
    let body_site = tree
        .sites
        .iter()
        .find(|site| site.id == "a-go-src-api")
        .expect("body site");
    let mut body_edit = tree.files.clone();
    mutate(&mut body_edit, body_site, &mut Rng(3)).expect("mutate body");
    let edited = memo_key(&target, &snapshot(&body_edit)).expect("edited memo key");
    assert_ne!(edited, key);
    assert_eq!(edited.target, key.target);

    // An edit outside every closure leaves the key untouched.
    let outside_site = tree
        .sites
        .iter()
        .find(|site| site.id == "a-root-readme")
        .expect("outside site");
    let mut outside_edit = tree.files.clone();
    mutate(&mut outside_edit, outside_site, &mut Rng(3)).expect("mutate outside");
    assert_eq!(
        memo_key(&target, &snapshot(&outside_edit)).expect("outside memo key"),
        key
    );
}

// ---------------------------------------------------------------------------------------------
// Refusals: a tree that cannot be hashed soundly yields an error, never a hash.
// ---------------------------------------------------------------------------------------------

fn run_refusals(name_prefix: &str) {
    let trees = load_fixture_trees();
    let tree = &trees[0];
    let selected: Vec<&Refusal> = tree
        .refusals
        .iter()
        .filter(|refusal| refusal.name.starts_with(name_prefix))
        .collect();
    let kinds: BTreeSet<&str> = selected
        .iter()
        .map(|refusal| refusal.expect.as_str())
        .collect();
    for required in [
        "MissingToolchain",
        "MissingLockfile",
        "UnresolvedDependency",
        "DependencyCycle",
        "Malformed",
    ] {
        assert!(
            kinds.contains(required),
            "{name_prefix}: no refusal case expects {required}"
        );
    }
    for refusal in selected {
        let target = parse_target(&refusal.target);
        closure_hash(&target, &snapshot(&tree.files))
            .unwrap_or_else(|err| panic!("{}: the base tree must hash: {err}", refusal.name));

        let mut files = tree.files.clone();
        apply_ops(&mut files, &refusal.ops)
            .unwrap_or_else(|why| panic!("{}: {why}", refusal.name));
        match closure_hash(&target, &snapshot(&files)) {
            Ok(hash) => panic!(
                "{}: expected {} but the tree hashed to {}",
                refusal.name,
                refusal.expect,
                hash.to_hex()
            ),
            Err(err) => {
                assert_eq!(
                    error_kind(&err),
                    refusal.expect,
                    "{}: wrong error kind ({err})",
                    refusal.name
                );
                assert!(
                    !err.to_string().is_empty(),
                    "{}: the error must explain itself",
                    refusal.name
                );
            }
        }
    }
}

#[test]
fn go_trees_with_missing_unresolved_cyclic_or_malformed_inputs_are_refused() {
    run_refusals("go-");
}

#[test]
fn cargo_trees_with_missing_unresolved_cyclic_or_malformed_inputs_are_refused() {
    run_refusals("cargo-");
}

#[test]
fn typescript_trees_with_missing_unresolved_cyclic_or_malformed_inputs_are_refused() {
    run_refusals("ts-");
}

#[test]
fn python_trees_with_missing_unresolved_cyclic_or_malformed_inputs_are_refused() {
    run_refusals("py-");
}

#[test]
fn unknown_target_and_empty_tree_are_refused() {
    let trees = load_fixture_trees();
    let tree = &trees[0];
    let nowhere = Target::new(Ecosystem::Go, "go/lib/nowhere");
    let err = closure_hash(&nowhere, &snapshot(&tree.files)).expect_err("unknown target");
    assert_eq!(error_kind(&err), "UnknownTarget");

    let empty = Tree::from_files(Vec::<(String, Vec<u8>)>::new());
    let known = parse_target("go:go/lib/util");
    let err = closure_hash(&known, &empty).expect_err("empty tree");
    assert!(
        REFUSAL_KINDS.contains(&error_kind(&err).as_str()),
        "unexpected error kind for an empty tree: {err:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Cross-host probe plumbing: CSV comparison, rows and the ignored probes.
// ---------------------------------------------------------------------------------------------

fn compare_csv(first: &str, second: &str) -> Result<(), String> {
    for (label, text) in [("first", first), ("second", second)] {
        let header = text.lines().next().unwrap_or("");
        if header != CSV_HEADER {
            return Err(format!("{label} CSV has header {header:?}"));
        }
        if text.lines().count() < 2 {
            return Err(format!("{label} CSV has no rows"));
        }
    }
    let left: Vec<&str> = first.lines().collect();
    let right: Vec<&str> = second.lines().collect();
    if left.len() != right.len() {
        return Err(format!("row counts differ: {} vs {}", left.len(), right.len()));
    }
    for (number, (a, b)) in left.iter().zip(right.iter()).enumerate() {
        if a != b {
            return Err(format!("line {} differs: {a} vs {b}", number + 1));
        }
    }
    Ok(())
}

#[test]
fn csv_comparison_accepts_identical_files_and_rejects_any_difference() {
    let base = format!("{CSV_HEADER}\ncobra,go,go:cmd/one,aa\ncobra,go,go:cmd/two,bb\n");
    assert!(compare_csv(&base, &base).is_ok());
    let changed_row = base.replace("bb", "bc");
    assert!(compare_csv(&base, &changed_row).is_err());
    let missing_row = format!("{CSV_HEADER}\ncobra,go,go:cmd/one,aa\n");
    assert!(compare_csv(&base, &missing_row).is_err());
    let wrong_header = base.replacen("closure_hash", "hash", 1);
    assert!(compare_csv(&base, &wrong_header).is_err());
    assert!(compare_csv(CSV_HEADER, CSV_HEADER).is_err());
}

fn env_or_skip(variable: &str, probe: &str) -> Option<String> {
    match std::env::var(variable) {
        Ok(value) if !value.trim().is_empty() => Some(value),
        _ => {
            eprintln!("SKIPPED {probe}: set {variable} to run this probe");
            None
        }
    }
}

#[test]
#[ignore = "needs the pinned checkouts; steps are in fixtures/closure_hash/test_code_steps.toml"]
fn pinned_repository_hashes_probe() {
    let probe = "pinned_repository_hashes_probe";
    let Some(root) = env_or_skip(ENV_CHECKOUT_ROOT, probe) else {
        return;
    };
    let Some(out) = env_or_skip(ENV_CSV_OUT, probe) else {
        return;
    };
    let doc = parse_toml_subset(PINNED_REPOS_TOML);
    let mut rows: BTreeSet<String> = BTreeSet::new();
    for (_, repo) in &doc.tables {
        let name = repo["name"].as_str();
        let ecosystem = repo["ecosystem"].as_str();
        let checkout = Path::new(&root).join(name);
        assert!(checkout.is_dir(), "{name}: no checkout at {}", checkout.display());

        let head = Command::new("git")
            .arg("-C")
            .arg(&checkout)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("run git rev-parse");
        assert!(head.status.success(), "{name}: git rev-parse failed");
        assert_eq!(
            String::from_utf8_lossy(&head.stdout).trim(),
            repo["sha"].as_str(),
            "{name}: checkout is not at the pinned commit"
        );

        if let (Some(pin_file), Some(pin_content)) = (repo.get("pin_file"), repo.get("pin_content"))
        {
            let path = checkout.join(pin_file);
            if !path.exists() {
                std::fs::write(&path, pin_content).expect("write the runner's toolchain pin");
            }
        }
        for required in [&repo["manifest"], &repo["lockfile"]] {
            assert!(
                checkout.join(required).is_file(),
                "{name}: {required} is missing at the pinned commit"
            );
        }

        let tree = Tree::from_dir(&checkout).expect("read the checkout");
        let graph = TargetGraph::discover(&tree, ecosystem_from_name(ecosystem), "")
            .unwrap_or_else(|err| panic!("{name}: discover failed: {err}"));
        let mut hashed = 0usize;
        for target in graph.targets() {
            match graph.closure_hash(&target, &tree) {
                Ok(hash) => {
                    hashed += 1;
                    rows.insert(format!("{name},{ecosystem},{target},{}", hash.to_hex()));
                }
                Err(err) => {
                    let kind = error_kind(&err);
                    assert!(
                        REFUSAL_KINDS.contains(&kind.as_str()),
                        "{name}: {target} failed with a non-refusal error: {err:?}"
                    );
                    rows.insert(format!("{name},{ecosystem},{target},ERR:{kind}"));
                }
            }
        }
        assert!(hashed >= 1, "{name}: no target could be hashed");
        eprintln!("{name}: hashed {hashed} of {} targets", graph.targets().len());
    }
    let body: Vec<String> = rows.into_iter().collect();
    if let Some(parent) = Path::new(&out).parent() {
        std::fs::create_dir_all(parent).expect("create the output directory");
    }
    std::fs::write(&out, format!("{CSV_HEADER}\n{}\n", body.join("\n"))).expect("write the CSV");
}

// ---------------------------------------------------------------------------------------------
// Real-repository probes for the mutation-sensitivity and outside-edit clauses. They use the
// declared closure of the library as the oracle, exactly as the clause words it, and only edit
// an in-memory copy of each checkout.
// ---------------------------------------------------------------------------------------------

/// Every regular file under the checkout keyed by its `/`-joined relative path. Version-control
/// metadata is skipped, as it is for `Tree::from_dir`.
fn walk_checkout(root: &Path) -> Files {
    fn visit(dir: &Path, prefix: &str, out: &mut Files) {
        for entry in std::fs::read_dir(dir).expect("read a checkout directory") {
            let entry = entry.expect("read a directory entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == ".git" {
                continue;
            }
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let kind = entry.file_type().expect("read a file type");
            if kind.is_dir() {
                visit(&entry.path(), &relative, out);
            } else if kind.is_file() {
                let bytes = std::fs::read(entry.path()).expect("read a checkout file");
                out.insert(relative, bytes);
            }
        }
    }
    let mut files = Files::new();
    visit(root, "", &mut files);
    files
}

struct ProbeRepo {
    name: String,
    ecosystem: String,
    files: Files,
    tracked: Vec<Target>,
    baseline: BTreeMap<String, ClosureHash>,
    holders: BTreeMap<String, BTreeSet<String>>,
}

/// Loads one pinned checkout in memory (adding the runner's toolchain pin only where the
/// checkout has none) and records, for every target that hashes, its baseline hash and the
/// inputs its declared closure holds.
fn load_probe_repo(root: &str, repo: &BTreeMap<String, String>) -> ProbeRepo {
    let name = repo["name"].clone();
    let ecosystem = repo["ecosystem"].clone();
    let checkout = Path::new(root).join(&name);
    assert!(checkout.is_dir(), "{name}: no checkout at {}", checkout.display());
    let mut files = walk_checkout(&checkout);
    if let (Some(pin_file), Some(pin_content)) = (repo.get("pin_file"), repo.get("pin_content")) {
        files
            .entry(pin_file.clone())
            .or_insert_with(|| pin_content.clone().into_bytes());
    }
    let tree = Tree::from_files(files.clone());
    let graph = TargetGraph::discover(&tree, ecosystem_from_name(&ecosystem), "")
        .unwrap_or_else(|err| panic!("{name}: discover failed: {err}"));
    let mut tracked = Vec::new();
    let mut baseline = BTreeMap::new();
    let mut holders: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for target in graph.targets() {
        let (Ok(hash), Ok(closure)) = (
            graph.closure_hash(&target, &tree),
            graph.declared_closure(&target),
        ) else {
            continue;
        };
        for input in closure {
            holders
                .entry(input.to_string())
                .or_default()
                .insert(target.to_string());
        }
        baseline.insert(target.to_string(), hash);
        tracked.push(target);
    }
    assert!(!tracked.is_empty(), "{name}: no target could be hashed");
    ProbeRepo {
        name,
        ecosystem,
        files,
        tracked,
        baseline,
        holders,
    }
}

/// Hashes every tracked target of a mutated copy and returns those whose hash differs from the
/// baseline. A target that no longer hashes, or a copy that no longer discovers, is a failure.
fn probe_changed(
    repo: &ProbeRepo,
    files: Files,
    context: &str,
    failures: &mut Vec<String>,
) -> BTreeSet<String> {
    let tree = Tree::from_files(files);
    let mut changed = BTreeSet::new();
    let graph = match TargetGraph::discover(&tree, ecosystem_from_name(&repo.ecosystem), "") {
        Ok(graph) => graph,
        Err(err) => {
            failures.push(format!("{}: {context}: discovery failed: {err}", repo.name));
            return changed;
        }
    };
    for target in &repo.tracked {
        let id = target.to_string();
        match graph.closure_hash(target, &tree) {
            Ok(hash) if repo.baseline.get(&id) == Some(&hash) => {}
            Ok(_) => {
                changed.insert(id);
            }
            Err(err) => failures.push(format!(
                "{}: {context}: {id} no longer hashes: {err}",
                repo.name
            )),
        }
    }
    changed
}

/// Splits `kind:path[#section]` into its kind, its file path and its optional section.
fn split_input(input: &str) -> (&str, &str, Option<&str>) {
    let (kind, rest) = input.split_once(':').expect("input has a kind prefix");
    match rest.split_once('#') {
        Some((path, section)) => (kind, path, Some(section)),
        None => (kind, rest, None),
    }
}

enum ProbeAction {
    /// Appends one to eight newlines to the file.
    Append,
    /// Replaces one character of a digest with a different character of its alphabet.
    FlipDigit {
        start: usize,
        end: usize,
        alphabet: &'static str,
    },
    /// Replaces one decimal digit of a toolchain or interpreter version.
    FlipVersion { position: usize },
}

struct ProbeCandidate {
    input: String,
    file: String,
    action: ProbeAction,
}

struct ProbeClasses {
    by_class: Vec<(&'static str, Vec<ProbeCandidate>)>,
    skipped_config: usize,
    skipped_toolchain: usize,
    skipped_lock: usize,
}

/// Byte position of the last digit of the version a pin file declares; for `go.mod` only the
/// `go` directive line is considered.
fn toolchain_position(path: &str, bytes: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(bytes).ok()?;
    let (offset, scope) = if path.ends_with("go.mod") {
        let start = if text.starts_with("go ") {
            0
        } else {
            text.find("\ngo ")? + 1
        };
        let end = text[start..].find('\n').map_or(text.len(), |n| start + n);
        (start, &text[start..end])
    } else {
        (0, text)
    };
    scope
        .rfind(|ch: char| ch.is_ascii_digit())
        .map(|index| offset + index)
}

/// Byte range of the digest inside the lockfile entry for `key`, with the alphabet its
/// characters come from; `None` when the entry has no digest in the expected layout.
fn lock_digest_span(
    ecosystem: &str,
    text: &str,
    key: &str,
) -> Option<(usize, usize, &'static str)> {
    match ecosystem {
        "go" => {
            let line_start = if text.starts_with(&format!("{key} ")) {
                0
            } else {
                text.find(&format!("\n{key} "))? + 1
            };
            let line_end = text[line_start..]
                .find('\n')
                .map_or(text.len(), |n| line_start + n);
            let line = &text[line_start..line_end];
            let digest_at = line.find("h1:")? + 3;
            let length = line[digest_at..]
                .trim_end_matches(|ch: char| ch == '=' || ch.is_whitespace())
                .len();
            (length > 0).then_some((
                line_start + digest_at,
                line_start + digest_at + length,
                "b64",
            ))
        }
        "cargo" | "python" => {
            let needle = format!("name = \"{key}\"\n");
            let after = text.find(&needle)? + needle.len();
            let block_end = text[after..]
                .find("[[package]]")
                .map_or(text.len(), |n| after + n);
            let block = &text[after..block_end];
            let marker = if ecosystem == "cargo" {
                "checksum = \""
            } else {
                "hash = \"sha256:"
            };
            let digest_at = block.find(marker)? + marker.len();
            let length = block[digest_at..].find('"')?;
            (length > 0).then_some((after + digest_at, after + digest_at + length, "hex"))
        }
        "typescript" => {
            let needle = format!("\"{key}\": {{");
            let after = text.find(&needle)? + needle.len();
            let block_end = text[after..]
                .find("\n    \"")
                .map_or(text.len(), |n| after + n);
            let block = &text[after..block_end];
            let marker = "\"integrity\": \"";
            let digest_at = block.find(marker)? + marker.len();
            let quoted = block[digest_at..].find('"')?;
            let prefix = block[digest_at..digest_at + quoted]
                .find('-')
                .map_or(0, |n| n + 1);
            let length = block[digest_at + prefix..digest_at + quoted]
                .trim_end_matches('=')
                .len();
            (length > 0).then_some((
                after + digest_at + prefix,
                after + digest_at + prefix + length,
                "b64",
            ))
        }
        _ => None,
    }
}

/// Sorts every mutable input of a checkout into the four classes of the clause. A source or
/// config file is only mutated when exactly one declared input names it, so that the holders of
/// the mutated input are exactly the targets that must change. Inputs that cannot be mutated
/// that way are counted, not hidden.
fn probe_candidates(repo: &ProbeRepo) -> ProbeClasses {
    let mut inputs_per_path: BTreeMap<&str, usize> = BTreeMap::new();
    for input in repo.holders.keys() {
        let (kind, path, _) = split_input(input);
        if kind != "dep" {
            *inputs_per_path.entry(path).or_insert(0) += 1;
        }
    }
    let mut source = Vec::new();
    let mut toolchain = Vec::new();
    let mut config = Vec::new();
    let mut lock = Vec::new();
    let (mut skipped_config, mut skipped_toolchain, mut skipped_lock) = (0, 0, 0);
    for input in repo.holders.keys() {
        let (kind, path, section) = split_input(input);
        let Some(bytes) = repo.files.get(path) else {
            continue;
        };
        let unique = inputs_per_path.get(path).copied() == Some(1);
        let candidate = |action: ProbeAction| ProbeCandidate {
            input: input.clone(),
            file: path.to_string(),
            action,
        };
        match kind {
            "source" if section.is_none() && unique => source.push(candidate(ProbeAction::Append)),
            "config" if section.is_none() && unique => config.push(candidate(ProbeAction::Append)),
            "config" => skipped_config += 1,
            "toolchain" => match toolchain_position(path, bytes) {
                Some(position) => toolchain.push(candidate(ProbeAction::FlipVersion { position })),
                None => skipped_toolchain += 1,
            },
            "lock" => {
                let entry = section.unwrap_or("");
                let text = std::str::from_utf8(bytes).unwrap_or("");
                match lock_digest_span(&repo.ecosystem, text, entry) {
                    Some((start, end, alphabet)) => lock.push(candidate(ProbeAction::FlipDigit {
                        start,
                        end,
                        alphabet,
                    })),
                    None => skipped_lock += 1,
                }
            }
            _ => {}
        }
    }
    ProbeClasses {
        by_class: vec![
            ("source", source),
            ("toolchain", toolchain),
            ("config", config),
            ("lock", lock),
        ]
        .into_iter()
        .filter(|(_, list)| !list.is_empty())
        .collect(),
        skipped_config,
        skipped_toolchain,
        skipped_lock,
    }
}

fn apply_probe_action(files: &mut Files, candidate: &ProbeCandidate, rng: &mut Rng) {
    let bytes = files
        .get_mut(&candidate.file)
        .expect("candidate file is in the checkout");
    match &candidate.action {
        ProbeAction::Append => {
            for _ in 0..=rng.below(8) {
                bytes.push(b'\n');
            }
        }
        ProbeAction::FlipDigit {
            start,
            end,
            alphabet,
        } => {
            let at = start + rng.below(end - start);
            let old = char::from(bytes[at]);
            let pool: Vec<char> = alphabet_chars(alphabet)
                .into_iter()
                .filter(|ch| *ch != old)
                .collect();
            let new = pool[rng.below(pool.len())];
            bytes[at] = u8::try_from(u32::from(new)).expect("digest characters are ASCII");
        }
        ProbeAction::FlipVersion { position } => {
            let old = u32::from(bytes[*position] - b'0');
            let step = u32::try_from(rng.below(9)).expect("below nine");
            let new = (old + 1 + step) % 10;
            bytes[*position] = b'0' + u8::try_from(new).expect("a single digit");
        }
    }
}

#[test]
#[ignore = "needs the pinned checkouts; steps are in fixtures/closure_hash/test_code_steps.toml"]
fn pinned_repository_mutation_probe() {
    let probe = "pinned_repository_mutation_probe";
    let Some(root) = env_or_skip(ENV_CHECKOUT_ROOT, probe) else {
        return;
    };
    let doc = parse_toml_subset(PINNED_REPOS_TOML);
    let mut total = 0usize;
    let mut per_class: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();
    for (index, (_, repo)) in doc.tables.iter().enumerate() {
        let probe_repo = load_probe_repo(&root, repo);
        let classes = probe_candidates(&probe_repo);
        assert!(
            !classes.by_class.is_empty(),
            "{}: no input could be mutated",
            probe_repo.name
        );
        eprintln!(
            "{}: {} targets hashed; mutable classes {:?}; skipped config {}, toolchain {}, lock {}",
            probe_repo.name,
            probe_repo.tracked.len(),
            classes
                .by_class
                .iter()
                .map(|(class, list)| (*class, list.len()))
                .collect::<Vec<_>>(),
            classes.skipped_config,
            classes.skipped_toolchain,
            classes.skipped_lock
        );
        let mut rng = Rng(CAMPAIGN_SEED ^ u64::try_from(index + 1).expect("index fits in u64"));
        for step in 0..PROBE_MUTATIONS_PER_REPO {
            let (class, list) = &classes.by_class[step % classes.by_class.len()];
            let candidate = &list[rng.below(list.len())];
            let mut files = probe_repo.files.clone();
            apply_probe_action(&mut files, candidate, &mut rng);
            let context = format!("{class} mutation of {}", candidate.input);
            let changed = probe_changed(&probe_repo, files, &context, &mut failures);
            let expected = &probe_repo.holders[&candidate.input];
            for id in expected.difference(&changed) {
                failures.push(format!("{}: miss: {context} left {id} unchanged", probe_repo.name));
            }
            for id in changed.difference(expected) {
                failures.push(format!("{}: extra: {context} changed {id}", probe_repo.name));
            }
            total += 1;
            *per_class.entry(*class).or_insert(0) += 1;
        }
    }
    eprintln!("{total} single-input mutations; by class {per_class:?}");
    assert!(
        failures.is_empty(),
        "{} misses, extras or unhashable targets; first {:?}",
        failures.len(),
        &failures[..failures.len().min(5)]
    );
    assert!(
        total >= MIN_INPUT_MUTATIONS,
        "only {total} single-input mutations ran"
    );
    for class in PROBE_CLASSES {
        assert!(
            per_class.get(class).copied().unwrap_or(0) >= 1,
            "no {class} mutation ran on any pinned repository"
        );
    }
}

#[test]
#[ignore = "needs the pinned checkouts; steps are in fixtures/closure_hash/test_code_steps.toml"]
fn pinned_repository_outside_edit_probe() {
    let probe = "pinned_repository_outside_edit_probe";
    let Some(root) = env_or_skip(ENV_CHECKOUT_ROOT, probe) else {
        return;
    };
    let doc = parse_toml_subset(PINNED_REPOS_TOML);
    for (_, repo) in &doc.tables {
        let probe_repo = load_probe_repo(&root, repo);
        let referenced: BTreeSet<String> = probe_repo
            .holders
            .keys()
            .map(|input| split_input(input).1.to_string())
            .collect();
        let unreferenced_doc = probe_repo
            .files
            .keys()
            .find(|path| path.to_ascii_lowercase().ends_with(".md") && !referenced.contains(*path))
            .unwrap_or_else(|| panic!("{}: no markdown file outside closures", probe_repo.name))
            .clone();

        let mut added = probe_repo.files.clone();
        added.insert(
            "closure_probe_unrelated.md".to_string(),
            b"an unrelated new file\n".to_vec(),
        );
        added.insert(
            "closure_probe_unrelated/notes.txt".to_string(),
            b"more unrelated text\n".to_vec(),
        );
        let mut edited = probe_repo.files.clone();
        edited
            .get_mut(&unreferenced_doc)
            .expect("the markdown file is in the checkout")
            .extend_from_slice(b"\nan unrelated edit\n");
        let mut deleted = probe_repo.files.clone();
        deleted.remove(&unreferenced_doc);

        for (label, files) in [
            ("adding unrelated files", added),
            ("editing an unrelated markdown file", edited),
            ("deleting an unrelated markdown file", deleted),
        ] {
            let mut failures: Vec<String> = Vec::new();
            let changed = probe_changed(&probe_repo, files, label, &mut failures);
            assert!(failures.is_empty(), "{failures:?}");
            assert!(
                changed.is_empty(),
                "{}: {label} changed {changed:?}",
                probe_repo.name
            );
        }
    }
}

#[test]
#[ignore = "needs the two CSVs produced on two distinct hosts"]
fn cross_host_hash_csvs_are_identical() {
    let probe = "cross_host_hash_csvs_are_identical";
    let Some(first_path) = env_or_skip(ENV_CSV_A, probe) else {
        return;
    };
    let Some(second_path) = env_or_skip(ENV_CSV_B, probe) else {
        return;
    };
    let first = std::fs::read_to_string(&first_path).expect("read the first host CSV");
    let second = std::fs::read_to_string(&second_path).expect("read the second host CSV");
    compare_csv(&first, &second).unwrap_or_else(|why| panic!("the hosts disagree: {why}"));

    let doc = parse_toml_subset(PINNED_REPOS_TOML);
    let mut per_ecosystem: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in first.lines().skip(1) {
        let mut columns = line.split(',');
        let repo = columns.next().expect("repo column");
        let ecosystem = columns.next().expect("ecosystem column");
        per_ecosystem
            .entry(ecosystem.to_string())
            .or_default()
            .insert(repo.to_string());
    }
    for (_, repo) in &doc.tables {
        let covered = per_ecosystem
            .get(repo["ecosystem"].as_str())
            .is_some_and(|repos| repos.contains(&repo["name"]));
        assert!(covered, "{} has no rows in the CSV", repo["name"]);
    }
}
