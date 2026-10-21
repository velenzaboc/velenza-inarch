//! R11: `deploy/spanner-schema.sql` must define exactly the tables and columns that
//! `SpannerMetadataStore` reads and writes.
//!
//! The test points a `SpannerMetadataStore` at a recording mock Spanner REST server,
//! drives every `MetadataStore` method the store implements, then parses every recorded
//! mutation (`:commit`) and SQL statement (`:executeSql`) and checks each referenced
//! table and column against the DDL file shipped in the repository.
//!
//! The store talks to Spanner through the `curl` binary, exactly like the unit test in
//! `cloud.rs`, so the mock server is plain `http://` on a loopback listener.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use inarch_store::{
    DerivedDataKind, JitLeaseRecord, MetadataStore, PrincipalRecord, SpannerMetadataStore,
};
use inarch_types::bonsai::{BonsaiChangeset, FileChange, FileType};
use inarch_types::hash::{BlobId, ObjectDomain, ObjectHash};
use inarch_types::path::MPath;

const DDL: &str = include_str!("../../../deploy/spanner-schema.sql");

const DATABASE: &str = "projects/p/instances/i/databases/d";

const EXPECTED_TABLES: [&str; 5] = [
    "ScionChangesets",
    "ScionRefs",
    "ScionDerivedMappings",
    "ScionPrincipals",
    "ScionLeases",
];

// ---------------------------------------------------------------------------
// Minimal JSON parser (the workspace has zero external crates).
// ---------------------------------------------------------------------------

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
                while self.i < self.b.len()
                    && matches!(
                        self.b[self.i],
                        b'+' | b'-' | b'.' | b'e' | b'E' | b'0'..=b'9'
                    )
                {
                    self.i += 1;
                }
                Ok(Json::Num(
                    String::from_utf8_lossy(&self.b[start..self.i]).to_string(),
                ))
            }
            Some(c) => Err(format!(
                "unexpected byte '{}' at offset {}",
                c as char, self.i
            )),
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
                            let hex = self
                                .b
                                .get(self.i..self.i + 4)
                                .ok_or_else(|| "short \\u escape".to_string())?;
                            let hex = String::from_utf8_lossy(hex).to_string();
                            let code = u32::from_str_radix(&hex, 16)
                                .map_err(|_| format!("bad \\u escape {hex}"))?;
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

// ---------------------------------------------------------------------------
// Recording mock Spanner REST server.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Recorded {
    path: String,
    body: String,
}

struct ShutdownGuard(SocketAddr);

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        if let Ok(mut s) = TcpStream::connect_timeout(&self.0, Duration::from_secs(2)) {
            let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
            let _ = s.write_all(
                b"GET /__shutdown HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            );
        }
    }
}

/// Handles one connection; returns true when the shutdown route was hit.
fn serve_connection(mut stream: TcpStream, log: &Mutex<Vec<Recorded>>) -> bool {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
    let Ok(clone) = stream.try_clone() else {
        return false;
    };
    let mut reader = BufReader::new(clone);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return false;
    }
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return false;
    }
    let path = parts[1].to_string();

    let mut content_len = 0usize;
    let mut expect_continue = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            if k == "content-length" {
                content_len = v.trim().parse().unwrap_or(0);
            } else if k == "expect" && v.to_ascii_lowercase().contains("100-continue") {
                expect_continue = true;
            }
        }
    }
    if path == "/__shutdown" {
        let _ =
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        return true;
    }
    if expect_continue {
        let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
    }
    let mut body = vec![0u8; content_len];
    let _ = reader.read_exact(&mut body);
    let body = String::from_utf8_lossy(&body).to_string();

    let (status, payload): (u16, &str) = if path.ends_with("/sessions") {
        (
            200,
            "{\"name\":\"projects/p/instances/i/databases/d/sessions/s1\"}",
        )
    } else if path.ends_with(":beginTransaction") {
        (200, "{\"id\":\"tx-7\"}")
    } else if path.ends_with(":rollback") {
        (200, "{}")
    } else if path.ends_with(":commit") {
        (200, "{\"commitTimestamp\":\"2026-10-19T00:00:00Z\"}")
    } else if path.ends_with(":executeSql") {
        (200, "{\"rows\":[]}")
    } else {
        (404, "unknown route")
    };
    log.lock().unwrap().push(Recorded { path, body });

    let header = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        payload.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(payload.as_bytes());
    false
}

fn spawn_mock_spanner() -> (SocketAddr, Arc<Mutex<Vec<Recorded>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock spanner listener");
    let addr = listener.local_addr().unwrap();
    let log: Arc<Mutex<Vec<Recorded>>> = Arc::new(Mutex::new(Vec::new()));
    let log_for_thread = log.clone();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(stream) = incoming else { break };
            if serve_connection(stream, &log_for_thread) {
                break;
            }
        }
    });
    (addr, log)
}

// ---------------------------------------------------------------------------
// DDL parsing.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct DdlColumn {
    name: String,
    ty: String,
    not_null: bool,
    has_default: bool,
}

#[derive(Debug, Clone, Default)]
struct DdlTable {
    columns: Vec<DdlColumn>,
    primary_key: Vec<String>,
}

impl DdlTable {
    fn column(&self, name: &str) -> Option<&DdlColumn> {
        self.columns.iter().find(|c| c.name == name)
    }
}

fn split_top_level_commas(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in body.chars() {
        match ch {
            '(' => {
                depth += 1;
                cur.push(ch);
            }
            ')' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    out.push(cur);
    out
}

fn parse_ddl(src: &str) -> BTreeMap<String, DdlTable> {
    let cleaned: String = src
        .lines()
        .map(|l| match l.find("--") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let upper = cleaned.to_ascii_uppercase();
    let marker = "CREATE TABLE";
    let mut tables = BTreeMap::new();
    let mut pos = 0usize;
    while let Some(rel) = upper[pos..].find(marker) {
        let start = pos + rel + marker.len();
        let open = cleaned[start..]
            .find('(')
            .map(|i| start + i)
            .expect("CREATE TABLE without an opening parenthesis");
        let name = cleaned[start..open].trim().trim_matches('`').to_string();
        let mut depth = 0i32;
        let mut close = None;
        for (i, ch) in cleaned[open..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close = close.expect("CREATE TABLE without a closing parenthesis");
        let body = &cleaned[open + 1..close];

        let mut table = DdlTable::default();
        for entry in split_top_level_commas(body) {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let col_name = entry.split_whitespace().next().unwrap_or("");
            let col_name_upper = col_name.to_ascii_uppercase();
            if matches!(
                col_name_upper.as_str(),
                "CONSTRAINT" | "FOREIGN" | "CHECK" | "PRIMARY" | "INTERLEAVE"
            ) {
                continue;
            }
            let rest = entry[col_name.len()..].trim().to_string();
            let rest_upper = rest.to_ascii_uppercase();
            table.columns.push(DdlColumn {
                name: col_name.trim_matches('`').to_string(),
                ty: rest,
                not_null: rest_upper.contains("NOT NULL"),
                has_default: rest_upper.contains("DEFAULT") || rest_upper.contains("AS ("),
            });
        }

        let tail_end = cleaned[close..]
            .find(';')
            .map(|i| close + i)
            .unwrap_or(cleaned.len());
        let tail = &cleaned[close + 1..tail_end];
        let tail_upper = tail.to_ascii_uppercase();
        if let Some(i) = tail_upper.find("PRIMARY KEY") {
            let after = &tail[i + "PRIMARY KEY".len()..];
            if let (Some(o), Some(c)) = (after.find('('), after.find(')')) {
                for key in after[o + 1..c].split(',') {
                    if let Some(first) = key.split_whitespace().next() {
                        table.primary_key.push(first.trim_matches('`').to_string());
                    }
                }
            }
        }
        tables.insert(name, table);
        pos = tail_end;
    }
    tables
}

// ---------------------------------------------------------------------------
// Recorded mutation and SQL extraction.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Mutation {
    kind: String,
    table: String,
    columns: Vec<String>,
    rows: Vec<Vec<Json>>,
}

impl Mutation {
    fn cell(&self, row: usize, column: &str) -> Option<&Json> {
        let idx = self.columns.iter().position(|c| c == column)?;
        self.rows.get(row)?.get(idx)
    }
}

fn extract_mutations(log: &[Recorded]) -> Vec<Mutation> {
    let mut out = Vec::new();
    for rec in log.iter().filter(|r| r.path.ends_with(":commit")) {
        let root = JsonParser::parse(&rec.body)
            .unwrap_or_else(|e| panic!("commit body is not valid JSON ({e}): {}", rec.body));
        let Some(muts) = root.get("mutations").and_then(Json::as_arr) else {
            continue;
        };
        for m in muts {
            let Json::Obj(entries) = m else { continue };
            for (kind, inner) in entries {
                let table = inner
                    .get("table")
                    .and_then(Json::as_str)
                    .unwrap_or("")
                    .to_string();
                let columns: Vec<String> = inner
                    .get("columns")
                    .and_then(Json::as_arr)
                    .map(|a| {
                        a.iter()
                            .filter_map(|c| c.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let rows: Vec<Vec<Json>> = inner
                    .get("values")
                    .and_then(Json::as_arr)
                    .map(|rows| {
                        rows.iter()
                            .map(|r| r.as_arr().map(|a| a.to_vec()).unwrap_or_default())
                            .collect()
                    })
                    .unwrap_or_default();
                out.push(Mutation {
                    kind: kind.clone(),
                    table,
                    columns,
                    rows,
                });
            }
        }
    }
    out
}

fn extract_sql(log: &[Recorded]) -> Vec<String> {
    let mut out = Vec::new();
    for rec in log.iter().filter(|r| r.path.ends_with(":executeSql")) {
        let root = JsonParser::parse(&rec.body)
            .unwrap_or_else(|e| panic!("executeSql body is not valid JSON ({e}): {}", rec.body));
        let sql = root
            .get("sql")
            .and_then(Json::as_str)
            .unwrap_or_else(|| panic!("executeSql body has no sql: {}", rec.body));
        out.push(sql.to_string());
    }
    out
}

#[derive(Debug, PartialEq)]
enum Tok {
    Ident(String),
    Literal,
    Param,
    Punct(char),
}

fn tokenize_sql(sql: &str) -> Vec<Tok> {
    let chars: Vec<char> = sql.chars().collect();
    let n = chars.len();
    let mut i = 0usize;
    let mut toks = Vec::new();
    while i < n {
        let c = chars[i];
        if c == '\'' || c == '"' {
            i += 1;
            while i < n && chars[i] != c {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            toks.push(Tok::Literal);
        } else if c == '`' {
            i += 1;
            let s = i;
            while i < n && chars[i] != '`' {
                i += 1;
            }
            toks.push(Tok::Ident(chars[s..i.min(n)].iter().collect()));
            i += 1;
        } else if c == '@' {
            i += 1;
            while i < n && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            toks.push(Tok::Param);
        } else if c.is_ascii_alphabetic() || c == '_' {
            let s = i;
            while i < n && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            toks.push(Tok::Ident(chars[s..i].iter().collect()));
        } else if c.is_ascii_digit() {
            while i < n && chars[i].is_ascii_alphanumeric() {
                i += 1;
            }
            toks.push(Tok::Literal);
        } else if c.is_whitespace() {
            i += 1;
        } else {
            toks.push(Tok::Punct(c));
            i += 1;
        }
    }
    toks
}

fn is_pascal_case(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && s.chars().any(|c| c.is_ascii_lowercase())
}

/// Returns (tables, column identifiers) referenced by one SQL statement.
fn analyze_sql(sql: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let toks = tokenize_sql(sql);
    let mut tables = BTreeSet::new();
    let mut candidates = BTreeSet::new();
    for (idx, tok) in toks.iter().enumerate() {
        let Tok::Ident(name) = tok else { continue };
        let next_is_paren = matches!(toks.get(idx + 1), Some(Tok::Punct('(')));
        let prev_kw = match idx.checked_sub(1).and_then(|p| toks.get(p)) {
            Some(Tok::Ident(p)) => p.to_ascii_uppercase(),
            _ => String::new(),
        };
        if matches!(prev_kw.as_str(), "FROM" | "INTO" | "UPDATE" | "JOIN") && !next_is_paren {
            tables.insert(name.clone());
        } else if prev_kw == "AS" {
            continue;
        } else if is_pascal_case(name) && !next_is_paren {
            candidates.insert(name.clone());
        }
    }
    let columns = candidates
        .into_iter()
        .filter(|c| !tables.contains(c))
        .collect();
    (tables, columns)
}

fn value_matches_type(ty: &str, v: &Json) -> bool {
    if matches!(v, Json::Null) {
        return true;
    }
    let t = ty.trim().to_ascii_uppercase();
    if t.starts_with("ARRAY<") {
        matches!(v, Json::Arr(_))
    } else if t.starts_with("INT64") {
        match v {
            Json::Str(s) => s.parse::<i64>().is_ok(),
            Json::Num(_) => true,
            _ => false,
        }
    } else if t.starts_with("BOOL") {
        matches!(v, Json::Bool(_))
    } else if t.starts_with("STRING") || t.starts_with("BYTES") || t.starts_with("TIMESTAMP") {
        matches!(v, Json::Str(_))
    } else {
        true
    }
}

// ---------------------------------------------------------------------------
// Fixture data.
// ---------------------------------------------------------------------------

fn make_changeset(
    parents: Vec<inarch_types::hash::ChangesetId>,
    path: &str,
    message: &str,
) -> BonsaiChangeset {
    let data = message.as_bytes();
    let blob = BlobId(ObjectHash::from_domain(ObjectDomain::Chunk, data));
    let mut changes = BTreeMap::new();
    changes.insert(
        MPath::new(path).unwrap(),
        FileChange::Tracked {
            blob_id: blob,
            file_type: FileType::Regular,
            size: data.len() as u64,
        },
    );
    BonsaiChangeset::new(
        parents,
        "schema-probe".into(),
        1_750_000_000,
        0,
        message.into(),
        BTreeMap::new(),
        changes,
    )
    .unwrap()
}

const PROBE_PRINCIPAL: &str = "schema-probe@example.com";
const PROBE_LEASE: &str = "lease_schema_probe_0001";
const ENROLLER: &str = "enroller@example.com";

fn probe_principal(email: &str, revoked: Option<i64>, prefixes: Vec<String>) -> PrincipalRecord {
    PrincipalRecord {
        principal_email: email.to_string(),
        principal_kind: "workstation".to_string(),
        host_label: "host-a".to_string(),
        allowed_repos: vec!["default".to_string(), "other".to_string()],
        allowed_ops: vec!["read".to_string(), "land".to_string()],
        status: "active".to_string(),
        enrolled_by: ENROLLER.to_string(),
        created_at_unix: 1_750_000_000,
        revoked_at_unix: revoked,
        allowed_write_prefixes: prefixes,
    }
}

fn probe_lease(
    id: &str,
    revoked: bool,
    prefixes: Vec<String>,
    refs: Vec<String>,
) -> JitLeaseRecord {
    JitLeaseRecord {
        lease_id: id.to_string(),
        principal_email: PROBE_PRINCIPAL.to_string(),
        swarm_id: "swarm-1".to_string(),
        task_id: "task-1".to_string(),
        repo_id: "default".to_string(),
        allowed_ops: vec!["read".to_string(), "land".to_string()],
        allowed_read_prefixes: vec!["docs/".to_string()],
        allowed_write_prefixes: prefixes,
        issued_at_unix: 1_750_000_000,
        expires_at_unix: 1_750_003_600,
        revoked,
        allowed_refs: refs,
    }
}

fn strings_of(v: Option<&Json>) -> Vec<String> {
    v.and_then(Json::as_arr)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn row_index(m: &Mutation, key_column: &str, key_value: &str) -> Option<usize> {
    (0..m.rows.len()).find(|&r| m.cell(r, key_column).and_then(Json::as_str) == Some(key_value))
}

// ---------------------------------------------------------------------------
// The test.
// ---------------------------------------------------------------------------

#[test]
fn spanner_ddl_defines_every_table_and_column_the_store_reads_and_writes() {
    // SAFETY: this integration-test binary contains a single test, so nothing else reads
    // or writes the process environment concurrently.
    unsafe {
        std::env::set_var("INARCH_GCP_ACCESS_TOKEN", "test-token");
    }

    let (addr, log) = spawn_mock_spanner();
    let _guard = ShutdownGuard(addr);
    let endpoint = format!("http://{addr}");
    let new_store = || {
        SpannerMetadataStore::with_endpoint(DATABASE, "schema-probe-repo", endpoint.as_str())
            .expect("construct SpannerMetadataStore")
    };

    // ---- writes (one store so its in-memory changeset cache satisfies parent/target checks) ----
    let writer = new_store();
    let cs1 = make_changeset(vec![], "README.md", "schema probe root");
    let cs1_id = writer.put_changeset(&cs1).expect("put_changeset root");
    let cs2 = make_changeset(vec![cs1_id], "docs/guide.md", "schema probe child");
    let cs2_id = writer.put_changeset(&cs2).expect("put_changeset child");

    writer
        .cas_ref("main", None, cs2_id)
        .expect("cas_ref create main");
    writer
        .cas_ref("other::feature", None, cs1_id)
        .expect("cas_ref create scoped ref");

    let derived_hash = ObjectHash::from_domain(ObjectDomain::Chunk, b"derived root");
    writer
        .put_derived_mapping(cs1_id, DerivedDataKind::Fsnode, derived_hash)
        .expect("put_derived_mapping");

    writer
        .put_principal(&probe_principal(
            PROBE_PRINCIPAL,
            Some(1_750_000_500),
            vec!["docs/".to_string(), "src/".to_string()],
        ))
        .expect("put_principal restricted");
    writer
        .put_principal(&probe_principal(
            "schema-probe-open@example.com",
            None,
            Vec::new(),
        ))
        .expect("put_principal unrestricted");

    writer
        .put_lease(&probe_lease(
            PROBE_LEASE,
            false,
            vec!["src/".to_string()],
            vec!["feature-x".to_string(), "feature-y".to_string()],
        ))
        .expect("put_lease active");
    writer
        .put_lease(&probe_lease(
            "lease_schema_probe_0002",
            true,
            Vec::new(),
            Vec::new(),
        ))
        .expect("put_lease revoked");

    // ---- reads (fresh stores have empty caches, so each read must go to Spanner SQL) ----
    // Results are ignored on purpose: the recorded SQL is what is under test.
    let reader = new_store();
    let _ = reader.get_changeset(&cs1_id);
    let _ = reader.get_ref("main");
    let _ = reader.get_ref("other::feature");
    let _ = reader.list_refs();
    let _ = reader.get_derived_mapping(cs1_id, DerivedDataKind::Fsnode);
    let _ = reader.get_principal(PROBE_PRINCIPAL);
    let _ = reader.list_principals();
    let _ = reader.get_lease(PROBE_LEASE);
    let _ = reader.list_leases(None);
    let _ = reader.list_leases(Some("default"));

    drop(_guard);
    let recorded: Vec<Recorded> = log.lock().unwrap().clone();

    let ddl = parse_ddl(DDL);
    let mutations = extract_mutations(&recorded);
    let statements = extract_sql(&recorded);

    let mut problems: BTreeSet<String> = BTreeSet::new();

    // ---- the DDL defines exactly the five tables ----
    let ddl_tables: BTreeSet<&str> = ddl.keys().map(|s| s.as_str()).collect();
    let expected_tables: BTreeSet<&str> = EXPECTED_TABLES.iter().copied().collect();
    if ddl_tables != expected_tables {
        problems.insert(format!(
            "DDL tables {ddl_tables:?} differ from the tables the store uses {expected_tables:?}"
        ));
    }
    for (name, table) in &ddl {
        for key in &table.primary_key {
            if table.column(key).is_none() {
                problems.insert(format!(
                    "DDL table {name}: primary key column {key} is not declared"
                ));
            }
        }
    }

    // ---- every recorded mutation matches the DDL ----
    let mut mutation_tables: BTreeSet<String> = BTreeSet::new();
    for m in &mutations {
        mutation_tables.insert(m.table.clone());
        let Some(table) = ddl.get(&m.table) else {
            problems.insert(format!(
                "{} mutation targets table {} which is missing from the DDL",
                m.kind, m.table
            ));
            continue;
        };
        for col in &m.columns {
            if table.column(col).is_none() {
                problems.insert(format!(
                    "{} mutation on {} writes column {} which is missing from the DDL",
                    m.kind, m.table, col
                ));
            }
        }
        for (r, row) in m.rows.iter().enumerate() {
            if row.len() != m.columns.len() {
                problems.insert(format!(
                    "{} mutation on {}: row {} has {} values for {} columns",
                    m.kind,
                    m.table,
                    r,
                    row.len(),
                    m.columns.len()
                ));
                continue;
            }
            for (col, value) in m.columns.iter().zip(row.iter()) {
                let Some(def) = table.column(col) else {
                    continue;
                };
                if !value_matches_type(&def.ty, value) {
                    problems.insert(format!(
                        "{} mutation on {}: column {} is declared `{}` but the store writes {:?}",
                        m.kind, m.table, col, def.ty, value
                    ));
                }
                if def.not_null && matches!(value, Json::Null) {
                    problems.insert(format!(
                        "{} mutation on {}: column {} is NOT NULL but the store writes null",
                        m.kind, m.table, col
                    ));
                }
            }
        }
        if matches!(m.kind.as_str(), "insert" | "insertOrUpdate" | "replace") {
            for def in &table.columns {
                if def.not_null && !def.has_default && !m.columns.contains(&def.name) {
                    problems.insert(format!(
                        "{} mutation on {} never writes NOT NULL column {}",
                        m.kind, m.table, def.name
                    ));
                }
            }
        }
    }

    // ---- every recorded SQL statement matches the DDL ----
    let mut sql_tables: BTreeSet<String> = BTreeSet::new();
    let mut sql_by_table: BTreeMap<String, Vec<(String, BTreeSet<String>)>> = BTreeMap::new();
    for sql in &statements {
        let (tables, columns) = analyze_sql(sql);
        if tables.is_empty() {
            problems.insert(format!("could not find a table in SQL: {sql}"));
            continue;
        }
        let mut known_columns: BTreeSet<&str> = BTreeSet::new();
        for t in &tables {
            sql_tables.insert(t.clone());
            sql_by_table
                .entry(t.clone())
                .or_default()
                .push((sql.clone(), columns.clone()));
            match ddl.get(t) {
                Some(def) => known_columns.extend(def.columns.iter().map(|c| c.name.as_str())),
                None => {
                    problems.insert(format!("SQL reads table {t} which is missing from the DDL"));
                }
            }
        }
        for col in &columns {
            if !known_columns.contains(col.as_str()) {
                problems.insert(format!(
                    "SQL references column {} not defined on {:?} in the DDL: {}",
                    col, tables, sql
                ));
            }
        }
    }

    // ---- the test must not pass vacuously ----
    for table in EXPECTED_TABLES {
        if !mutation_tables.contains(table) {
            problems.insert(format!("no mutation was recorded for table {table}"));
        }
        if !sql_tables.contains(table) {
            problems.insert(format!("no SQL statement was recorded for table {table}"));
        }
    }
    if recorded
        .iter()
        .filter(|r| r.path.ends_with(":beginTransaction"))
        .count()
        == 0
    {
        problems.insert("cas_ref never began a transaction".to_string());
    }

    // ---- new persisted fields: written with the right values and read back ----
    let principal_mutations: Vec<&Mutation> = mutations
        .iter()
        .filter(|m| m.table == "ScionPrincipals")
        .collect();
    let mut checked_principal = false;
    for m in &principal_mutations {
        for col in ["AllowedWritePrefixes", "EnrolledBy"] {
            if !m.columns.iter().any(|c| c == col) {
                problems.insert(format!("ScionPrincipals mutation does not write {col}"));
            }
        }
        if let Some(r) = row_index(m, "PrincipalId", PROBE_PRINCIPAL) {
            checked_principal = true;
            let prefixes = strings_of(m.cell(r, "AllowedWritePrefixes"));
            if prefixes != vec!["docs/".to_string(), "src/".to_string()] {
                problems.insert(format!(
                    "ScionPrincipals AllowedWritePrefixes wrote {prefixes:?}, expected docs/ and src/"
                ));
            }
            if m.cell(r, "EnrolledBy").and_then(Json::as_str) != Some(ENROLLER) {
                problems.insert(format!(
                    "ScionPrincipals EnrolledBy wrote {:?}, expected {ENROLLER}",
                    m.cell(r, "EnrolledBy")
                ));
            }
        }
    }
    if !checked_principal {
        problems.insert("no ScionPrincipals mutation carried the probe principal id".to_string());
    }

    let lease_mutations: Vec<&Mutation> = mutations
        .iter()
        .filter(|m| m.table == "ScionLeases")
        .collect();
    let mut checked_lease = false;
    for m in &lease_mutations {
        if !m.columns.iter().any(|c| c == "AllowedRefs") {
            problems.insert("ScionLeases mutation does not write AllowedRefs".to_string());
        }
        if let Some(r) = row_index(m, "LeaseId", PROBE_LEASE) {
            checked_lease = true;
            let refs = strings_of(m.cell(r, "AllowedRefs"));
            if refs != vec!["feature-x".to_string(), "feature-y".to_string()] {
                problems.insert(format!(
                    "ScionLeases AllowedRefs wrote {refs:?}, expected feature-x and feature-y"
                ));
            }
        }
    }
    if !checked_lease {
        problems.insert("no ScionLeases mutation carried the probe lease id".to_string());
    }

    for (sql, columns) in sql_by_table.get("ScionPrincipals").into_iter().flatten() {
        if sql.trim_start().to_ascii_uppercase().starts_with("SELECT") {
            for col in ["AllowedWritePrefixes", "EnrolledBy"] {
                if !columns.contains(col) {
                    problems.insert(format!("ScionPrincipals SELECT does not read {col}: {sql}"));
                }
            }
        }
    }
    for (sql, columns) in sql_by_table.get("ScionLeases").into_iter().flatten() {
        if sql.trim_start().to_ascii_uppercase().starts_with("SELECT")
            && !columns.contains("AllowedRefs")
        {
            problems.insert(format!(
                "ScionLeases SELECT does not read AllowedRefs: {sql}"
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "deploy/spanner-schema.sql does not match what SpannerMetadataStore reads and writes:\n- {}",
        problems.into_iter().collect::<Vec<_>>().join("\n- ")
    );
}
