//! Contract tests for the dated prior-art matrix and the novelty query log lint.
//!
//! The lint is `inarch_cli::docs_lint::prior_art`. It reads the two documents that ship in
//! `docs/`, `prior_art_matrix.md` and `novelty_query_log.md`, and refuses them as described
//! below. This file renders the JSON fixtures in `tests/fixtures/prior_art/` into those two
//! Markdown formats, so it is also the one place that pins the formats the documents follow.
//!
//! `docs_claims_test.rs` parses documentation inside its test. That pattern is not used here:
//! the refusal cases below would then run against the test's own parser instead of the lint
//! that ships, and the committed documents would be held to nothing a user can run.
//!
//! # Public surface imported from `inarch_cli::docs_lint::prior_art`
//!
//! * constants `REQUIRED_SYSTEMS` (an array or slice of the 14 row names, `&'static str`),
//!   `COLUMNS` (an array or slice of `char`: `'A'`, `'B'`, `'C'`), `MAX_QUOTE_CHARS: usize`
//!   (200) and `MIN_DATED_QUERIES: usize` (6);
//! * `lint_matrix_str(&str)` and `lint_query_log_str(&str)` lint document text;
//!   `lint_matrix(&Path)` and `lint_query_log(&Path)` read a file first and report
//!   `MissingFile` when they cannot. They return `Result<Matrix, Vec<MatrixError>>` and
//!   `Result<QueryLog, Vec<QueryLogError>>`, collect every error instead of stopping at the
//!   first, and never return an empty `Err`;
//! * `lint_prior_art(&Path, &Path) -> Result<(Matrix, QueryLog), Vec<PriorArtError>>` lints
//!   both documents, never stopping at the first one that fails, and wraps the errors of the
//!   matrix as `PriorArtError::Matrix(MatrixError)` and those of the query log as
//!   `PriorArtError::QueryLog(QueryLogError)`. `lint_exit_code(&Path, &Path) -> i32` is the
//!   exit status of that lint: 0 when it passes, non-zero when it refuses;
//! * `Matrix::cells() -> &[Cell]` in document order, `Matrix::cell(&str, char) -> Option<&Cell>`
//!   and `Cell { system: String, column: char, holds: bool, url: String, quote: String,
//!   accessed: String }`, where `quote` is the quote without the quotation marks around it;
//! * `QueryLog::queries() -> &[Query]` in document order,
//!   `Query { date: String, source: QuerySource, query: String, result: String }` and
//!   `QuerySource::{Arxiv, Github, Scholar, Patents}` (exactly these four);
//! * `MatrixError`: `MissingFile { path }`, `MalformedTable { reason }`,
//!   `MalformedRow { line, reason }`, `UnknownSystem { system }`, `MissingRow { system }`,
//!   `MissingCell { system, column }`, `DuplicateCell { system, column }`,
//!   `InvalidVerdict { system, column }`, `MissingUrl { system, column }`,
//!   `MissingQuote { system, column }`, `QuoteTooLong { system, column }`,
//!   `MissingAccessDate { system, column }` and `RowTrueOnAllThree { system }`;
//! * `QueryLogError`: `MissingFile { path }`, `MalformedTable { reason }`,
//!   `MalformedRow { line, reason }`, `UnknownSource { line, value }`, `MissingDate { line }`,
//!   `MissingQueryText { line }`, `TooFewQueries { found, required }` and
//!   `MissingSource { source }`.
//!
//! Field types the tests rely on: `path: PathBuf` (the path that was passed in), `system:
//! String`, `column: char`, `found: usize`, `required: usize` and `source: QuerySource`. The
//! `system` of `UnknownSystem` is the spelling found in the document; the `system` of every
//! other variant is the required name, and a `column` is the column letter of the cell.
//! Variants are struct variants; the tests match them with `..`, so a variant may carry more
//! fields, and they never read a line number or a message. Every public type derives `Debug`;
//! `QuerySource` also derives `Clone`, `Copy` and `PartialEq`.
//!
//! # Matrix document format
//!
//! The evidence table is the first Markdown table whose header row, compared cell by cell with
//! surrounding space trimmed and ASCII case ignored, is exactly
//! `System | Column | Holds | URL | Quote | Accessed`, followed by a delimiter row. Prose,
//! headings, every other table and the order of the rows are ignored. Without such a table the
//! document is refused (`MalformedTable`). The rows of the table are the consecutive lines that
//! start with `|` after the delimiter row. Cells are split on a `|` that is not preceded by a
//! backslash, and `\|` is a literal pipe. Lines end in LF or CRLF.
//!
//! One table row is one cell of the 14 by 3 matrix:
//!
//! * a row with other than six cells, or a column other than `A`, `B` or `C`, is `MalformedRow`;
//! * `System` is one of `REQUIRED_SYSTEMS`, spelled exactly (`UnknownSystem` otherwise); a
//!   system with no row at all is `MissingRow`, one that lacks a column is `MissingCell`, and a
//!   second row for the same system and column is `DuplicateCell`;
//! * `Holds` is `yes` or `no`, ASCII case and surrounding space ignored (`InvalidVerdict`);
//! * `URL` is an absolute `http://` or `https://` URL with a host and no whitespace; a blank
//!   cell or anything else is `MissingUrl`;
//! * `Quote` is the verbatim quote. One pair of ASCII double quotation marks around the whole
//!   cell is not part of the quote. A blank quote is `MissingQuote`. A quote of more than
//!   `MAX_QUOTE_CHARS` characters is `QuoteTooLong`; characters are Unicode scalar values, not
//!   bytes, and an escaped pipe counts as one;
//! * `Accessed` is a real calendar date written `YYYY-MM-DD`, with the Gregorian leap-year
//!   rule; a blank cell or anything else is `MissingAccessDate`. The lint never compares the
//!   date with the clock;
//! * a system whose A, B and C cells all hold `yes` is `RowTrueOnAllThree`: the narrowed
//!   novelty claim stands only while no prior system does all three.
//!
//! # Query log document format
//!
//! The same table rules apply, with the header `Date | Source | Query | Result`.
//!
//! * a row with other than four cells is `MalformedRow`;
//! * `Source` is `arXiv`, `GitHub`, `Google Scholar` or `Patents`, ASCII case ignored
//!   (`UnknownSource` otherwise);
//! * `Date` is a real `YYYY-MM-DD` date (`MissingDate`), `Query` is not blank
//!   (`MissingQueryText`), and `Result` is free text;
//! * a row counts as a dated query only when it has none of those faults. Fewer than
//!   `MIN_DATED_QUERIES` counted rows is `TooFewQueries { found, required }`, and a source
//!   with no counted row is `MissingSource { source }`.
//!
//! # Steps only test-code can run
//!
//! "A reviewer re-opens 3 random cited URLs and confirms their quotes" needs the network and a
//! reader. It is described in `fixtures/prior_art/test_code_steps.toml` and marked
//! test_code_only. The `#[ignore]` test at the end of this file prints the three cells to
//! re-open; this file checks that the step description and that test agree.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use inarch_cli::docs_lint::prior_art::{
    COLUMNS, MAX_QUOTE_CHARS, MIN_DATED_QUERIES, MatrixError, PriorArtError, QueryLogError,
    QuerySource, REQUIRED_SYSTEMS, lint_exit_code, lint_matrix, lint_matrix_str, lint_prior_art,
    lint_query_log, lint_query_log_str,
};

const MATRIX_PASS: &str = include_str!("fixtures/prior_art/matrix_pass.json");
const QUERY_LOG_PASS: &str = include_str!("fixtures/prior_art/query_log_pass.json");
const LINT_CASES: &str = include_str!("fixtures/prior_art/lint_cases.json");
const TEST_CODE_STEPS: &str = include_str!("fixtures/prior_art/test_code_steps.toml");
const THIS_FILE: &str = include_str!("prior_art_matrix_lint_test.rs");

const SPOT_CHECK_STEP_ID: &str = "reviewer-reopens-cited-urls";
const SPOT_CHECK_SEED_ENV: &str = "PRIOR_ART_SPOT_CHECK_SEED";
const SPOT_CHECK_SAMPLE_SIZE: usize = 3;
const SPOT_CHECK_TEST: &str = "spot_check_lists_three_cited_cells_from_the_committed_matrix";

const EXPECTED_SYSTEMS: [&str; 14] = [
    "Scion",
    "Mononoke",
    "Piper/TAP",
    "gitai",
    "SubmitQueue",
    "Aviator",
    "Zuul",
    "GitHub merge queue",
    "Jujutsu",
    "Pijul",
    "Bazel",
    "Chromium LKGR",
    "SAP call-graph work",
    "Bernstein",
];

const MATRIX_GROUPS: [&str; 9] = [
    "url",
    "quote_missing",
    "quote_length",
    "date",
    "coverage",
    "verdict",
    "all_three",
    "structure",
    "multi",
];
const QUERY_LOG_GROUPS: [&str; 5] = ["count", "sources", "dates", "rows", "structure"];

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

    fn as_usize(&self) -> Option<usize> {
        match self {
            Json::Num(text) => text.parse().ok(),
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

fn parse_json(text: &str, what: &str) -> Json {
    JsonParser::parse(text).unwrap_or_else(|e| panic!("{what} is not valid JSON: {e}"))
}

fn text_of<'a>(value: &'a Json, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("missing string field {key:?} in {value:?}"))
}

fn number_of(value: &Json, key: &str) -> usize {
    value
        .get(key)
        .and_then(Json::as_usize)
        .unwrap_or_else(|| panic!("missing number field {key:?} in {value:?}"))
}

fn items_of<'a>(value: &'a Json, key: &str) -> &'a [Json] {
    value.get(key).and_then(Json::as_arr).unwrap_or(&[])
}

// ---------------------------------------------------------------------------
// Fixtures and the Markdown renderers that pin the document formats.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CellRow {
    system: String,
    column: String,
    holds: String,
    url: String,
    quote: String,
    accessed: String,
}

#[derive(Debug, Clone)]
struct QueryRow {
    date: String,
    source: String,
    query: String,
    result: String,
}

#[derive(Debug, Clone, Default)]
struct Layout {
    crlf: bool,
    reverse: bool,
    decoy: bool,
    no_table: bool,
    bad_header: bool,
    raw_rows: Vec<String>,
}

fn fixture_cells() -> Vec<CellRow> {
    let doc = parse_json(MATRIX_PASS, "matrix_pass.json");
    items_of(&doc, "cells")
        .iter()
        .map(|cell| CellRow {
            system: text_of(cell, "system").to_string(),
            column: text_of(cell, "column").to_string(),
            holds: text_of(cell, "holds").to_string(),
            url: text_of(cell, "url").to_string(),
            quote: text_of(cell, "quote").to_string(),
            accessed: text_of(cell, "accessed").to_string(),
        })
        .collect()
}

fn fixture_queries() -> Vec<QueryRow> {
    let doc = parse_json(QUERY_LOG_PASS, "query_log_pass.json");
    items_of(&doc, "queries")
        .iter()
        .map(|row| QueryRow {
            date: text_of(row, "date").to_string(),
            source: text_of(row, "source").to_string(),
            query: text_of(row, "query").to_string(),
            result: text_of(row, "result").to_string(),
        })
        .collect()
}

fn layout_of(case: &Json) -> Layout {
    let mut layout = Layout::default();
    for flag in items_of(case, "render") {
        let flag = flag
            .as_str()
            .unwrap_or_else(|| panic!("render flags are strings: {flag:?}"));
        match flag {
            "crlf" => layout.crlf = true,
            "reverse" => layout.reverse = true,
            "decoy" => layout.decoy = true,
            "no_table" => layout.no_table = true,
            "bad_header" => layout.bad_header = true,
            other => match other.strip_prefix("raw_row:") {
                Some(row) => layout.raw_rows.push(row.to_string()),
                None => panic!("unknown render flag {other:?}"),
            },
        }
    }
    layout
}

fn escape_cell(text: &str) -> String {
    text.replace('|', "\\|")
}

fn finish(lines: &[String], crlf: bool) -> String {
    let newline = if crlf { "\r\n" } else { "\n" };
    let mut out = lines.join(newline);
    out.push_str(newline);
    out
}

fn decoy_table() -> Vec<String> {
    vec![
        "| Item | Note |".to_string(),
        "| --- | --- |".to_string(),
        "| alpha | beta |".to_string(),
        String::new(),
    ]
}

fn render_matrix(rows: &[CellRow], layout: &Layout) -> String {
    let mut lines: Vec<String> = vec![
        "# Prior-art matrix".to_string(),
        String::new(),
        "Prose before the table.".to_string(),
        String::new(),
    ];
    if layout.no_table {
        lines.push("There is no evidence table in this document.".to_string());
        return finish(&lines, layout.crlf);
    }
    if layout.decoy {
        lines.extend(decoy_table());
    }
    let url_header = if layout.bad_header { "Link" } else { "URL" };
    lines.push(format!(
        "| System | Column | Holds | {url_header} | Quote | Accessed |"
    ));
    lines.push("| --- | --- | --- | --- | --- | --- |".to_string());
    let ordered: Vec<&CellRow> = if layout.reverse {
        rows.iter().rev().collect()
    } else {
        rows.iter().collect()
    };
    for row in ordered {
        lines.push(format!(
            "| {} | {} | {} | {} | {} | {} |",
            escape_cell(&row.system),
            escape_cell(&row.column),
            escape_cell(&row.holds),
            escape_cell(&row.url),
            escape_cell(&row.quote),
            escape_cell(&row.accessed),
        ));
    }
    lines.extend(layout.raw_rows.iter().cloned());
    lines.push(String::new());
    lines.push("Prose after the table.".to_string());
    finish(&lines, layout.crlf)
}

fn render_query_log(queries: &[QueryRow], layout: &Layout) -> String {
    let mut lines: Vec<String> = vec![
        "# Novelty query log".to_string(),
        String::new(),
        "Prose before the table.".to_string(),
        String::new(),
    ];
    if layout.no_table {
        lines.push("There is no query table in this document.".to_string());
        return finish(&lines, layout.crlf);
    }
    if layout.decoy {
        lines.extend(decoy_table());
    }
    let source_header = if layout.bad_header { "Venue" } else { "Source" };
    lines.push(format!("| Date | {source_header} | Query | Result |"));
    lines.push("| --- | --- | --- | --- |".to_string());
    let ordered: Vec<&QueryRow> = if layout.reverse {
        queries.iter().rev().collect()
    } else {
        queries.iter().collect()
    };
    for row in ordered {
        lines.push(format!(
            "| {} | {} | {} | {} |",
            escape_cell(&row.date),
            escape_cell(&row.source),
            escape_cell(&row.query),
            escape_cell(&row.result),
        ));
    }
    lines.extend(layout.raw_rows.iter().cloned());
    lines.push(String::new());
    lines.push("Prose after the table.".to_string());
    finish(&lines, layout.crlf)
}

// ---------------------------------------------------------------------------
// Data-driven cases: mutations of the pass fixtures and the errors they must raise.
// ---------------------------------------------------------------------------

fn cell_index(rows: &[CellRow], op: &Json) -> usize {
    let system = text_of(op, "system");
    let column = text_of(op, "column");
    rows.iter()
        .position(|r| r.system == system && r.column == column)
        .unwrap_or_else(|| panic!("fixture has no cell {system} {column} for op {op:?}"))
}

fn field_mut<'a>(row: &'a mut CellRow, field: &str) -> &'a mut String {
    match field {
        "system" => &mut row.system,
        "column" => &mut row.column,
        "holds" => &mut row.holds,
        "url" => &mut row.url,
        "quote" => &mut row.quote,
        "accessed" => &mut row.accessed,
        other => panic!("unknown cell field {other:?}"),
    }
}

fn apply_matrix_op(rows: &mut Vec<CellRow>, op: &Json) {
    match text_of(op, "op") {
        "set" => {
            let index = cell_index(rows, op);
            *field_mut(&mut rows[index], text_of(op, "field")) = text_of(op, "value").to_string();
        }
        "set_repeat" => {
            let index = cell_index(rows, op);
            let value = text_of(op, "unit").repeat(number_of(op, "count"));
            *field_mut(&mut rows[index], text_of(op, "field")) = value;
        }
        "append" => {
            let index = cell_index(rows, op);
            field_mut(&mut rows[index], text_of(op, "field")).push_str(text_of(op, "value"));
        }
        "wrap" => {
            let index = cell_index(rows, op);
            let slot = field_mut(&mut rows[index], text_of(op, "field"));
            let wrapped = format!("{}{}{}", text_of(op, "open"), slot, text_of(op, "close"));
            *slot = wrapped;
        }
        "remove_cell" => {
            let index = cell_index(rows, op);
            rows.remove(index);
        }
        "remove_system" => {
            let system = text_of(op, "system");
            rows.retain(|r| r.system != system);
        }
        "rename_system" => {
            let from = text_of(op, "system");
            let to = text_of(op, "value");
            for row in rows.iter_mut().filter(|r| r.system == from) {
                row.system = to.to_string();
            }
        }
        "duplicate_cell" => {
            let index = cell_index(rows, op);
            let copy = rows[index].clone();
            rows.insert(index + 1, copy);
        }
        other => panic!("unknown matrix op {other:?}"),
    }
}

fn apply_query_op(rows: &mut Vec<QueryRow>, op: &Json) {
    match text_of(op, "op") {
        "keep_first" => rows.truncate(number_of(op, "count")),
        "drop_source" => {
            let source = text_of(op, "source");
            rows.retain(|r| r.source != source);
        }
        "set_row" => {
            let index = number_of(op, "index");
            let row = rows
                .get_mut(index)
                .unwrap_or_else(|| panic!("fixture has no query row {index}"));
            let value = text_of(op, "value").to_string();
            match text_of(op, "field") {
                "date" => row.date = value,
                "source" => row.source = value,
                "query" => row.query = value,
                "result" => row.result = value,
                other => panic!("unknown query field {other:?}"),
            }
        }
        other => panic!("unknown query op {other:?}"),
    }
}

/// What an error says, reduced to the facts the cases name.
#[derive(Debug, Default)]
struct Seen {
    kind: String,
    system: Option<String>,
    column: Option<char>,
    source: Option<String>,
    found: Option<usize>,
}

/// What a case expects to find among the errors.
#[derive(Debug)]
struct Want {
    kind: String,
    system: Option<String>,
    column: Option<char>,
    source: Option<String>,
    found: Option<usize>,
}

fn plain(kind: &str) -> Seen {
    Seen {
        kind: kind.to_string(),
        ..Seen::default()
    }
}

fn at_system(kind: &str, system: &str) -> Seen {
    Seen {
        kind: kind.to_string(),
        system: Some(system.to_string()),
        ..Seen::default()
    }
}

fn at_cell(kind: &str, system: &str, column: char) -> Seen {
    Seen {
        kind: kind.to_string(),
        system: Some(system.to_string()),
        column: Some(column),
        ..Seen::default()
    }
}

fn source_label(source: QuerySource) -> &'static str {
    match source {
        QuerySource::Arxiv => "arXiv",
        QuerySource::Github => "GitHub",
        QuerySource::Scholar => "Google Scholar",
        QuerySource::Patents => "Patents",
    }
}

#[allow(unreachable_patterns)]
fn matrix_seen(error: &MatrixError) -> Seen {
    match error {
        MatrixError::MissingFile { .. } => plain("MissingFile"),
        MatrixError::MalformedTable { .. } => plain("MalformedTable"),
        MatrixError::MalformedRow { .. } => plain("MalformedRow"),
        MatrixError::UnknownSystem { system, .. } => at_system("UnknownSystem", system),
        MatrixError::MissingRow { system, .. } => at_system("MissingRow", system),
        MatrixError::MissingCell { system, column, .. } => at_cell("MissingCell", system, *column),
        MatrixError::DuplicateCell { system, column, .. } => {
            at_cell("DuplicateCell", system, *column)
        }
        MatrixError::InvalidVerdict { system, column, .. } => {
            at_cell("InvalidVerdict", system, *column)
        }
        MatrixError::MissingUrl { system, column, .. } => at_cell("MissingUrl", system, *column),
        MatrixError::MissingQuote { system, column, .. } => {
            at_cell("MissingQuote", system, *column)
        }
        MatrixError::QuoteTooLong { system, column, .. } => {
            at_cell("QuoteTooLong", system, *column)
        }
        MatrixError::MissingAccessDate { system, column, .. } => {
            at_cell("MissingAccessDate", system, *column)
        }
        MatrixError::RowTrueOnAllThree { system, .. } => at_system("RowTrueOnAllThree", system),
        _ => plain("Other"),
    }
}

#[allow(unreachable_patterns)]
fn query_log_seen(error: &QueryLogError) -> Seen {
    match error {
        QueryLogError::MissingFile { .. } => plain("MissingFile"),
        QueryLogError::MalformedTable { .. } => plain("MalformedTable"),
        QueryLogError::MalformedRow { .. } => plain("MalformedRow"),
        QueryLogError::UnknownSource { .. } => plain("UnknownSource"),
        QueryLogError::MissingDate { .. } => plain("MissingDate"),
        QueryLogError::MissingQueryText { .. } => plain("MissingQueryText"),
        QueryLogError::TooFewQueries { found, .. } => Seen {
            kind: "TooFewQueries".to_string(),
            found: Some(*found),
            ..Seen::default()
        },
        QueryLogError::MissingSource { source, .. } => Seen {
            kind: "MissingSource".to_string(),
            source: Some(source_label(*source).to_string()),
            ..Seen::default()
        },
        _ => plain("Other"),
    }
}

fn wants_of(case: &Json) -> Vec<Want> {
    items_of(case, "expect")
        .iter()
        .map(|item| Want {
            kind: text_of(item, "kind").to_string(),
            system: item
                .get("system")
                .and_then(Json::as_str)
                .map(str::to_string),
            column: item
                .get("column")
                .and_then(Json::as_str)
                .and_then(|c| c.chars().next()),
            source: item
                .get("source")
                .and_then(Json::as_str)
                .map(str::to_string),
            found: item.get("found").and_then(Json::as_usize),
        })
        .collect()
}

fn want_matches(want: &Want, got: &Seen) -> bool {
    want.kind == got.kind
        && (want.system.is_none() || want.system == got.system)
        && (want.column.is_none() || want.column == got.column)
        && (want.source.is_none() || want.source == got.source)
        && (want.found.is_none() || want.found == got.found)
}

fn check_outcome(case: &Json, outcome: Result<(), Vec<Seen>>) {
    let name = text_of(case, "name");
    let expect_ok = matches!(case.get("expect_ok"), Some(Json::Bool(true)));
    let wants = wants_of(case);
    match outcome {
        Ok(()) => assert!(
            expect_ok,
            "case {name}: the lint accepted a document it must refuse; expected {wants:?}"
        ),
        Err(seen) => {
            assert!(
                !seen.is_empty(),
                "case {name}: the lint returned Err with no errors in it"
            );
            assert!(
                !expect_ok,
                "case {name}: the lint refused a document it must accept: {seen:?}"
            );
            assert!(
                !wants.is_empty(),
                "case {name}: a refusal case must list the error it expects"
            );
            for want in &wants {
                assert!(
                    seen.iter().any(|got| want_matches(want, got)),
                    "case {name}: expected {want:?} among {seen:?}"
                );
            }
        }
    }
}

fn cases_in(list: &str, group: &str) -> Vec<Json> {
    let doc = parse_json(LINT_CASES, "lint_cases.json");
    items_of(&doc, list)
        .iter()
        .filter(|case| text_of(case, "group") == group)
        .cloned()
        .collect()
}

fn is_pass_case(case: &Json) -> bool {
    matches!(case.get("expect_ok"), Some(Json::Bool(true)))
}

fn run_matrix_case(case: &Json) {
    let mut rows = fixture_cells();
    for op in items_of(case, "ops") {
        apply_matrix_op(&mut rows, op);
    }
    let text = render_matrix(&rows, &layout_of(case));
    let outcome = lint_matrix_str(&text)
        .map(|_| ())
        .map_err(|errors| errors.iter().map(matrix_seen).collect::<Vec<Seen>>());
    check_outcome(case, outcome);
}

fn run_query_log_case(case: &Json) {
    let mut rows = fixture_queries();
    for op in items_of(case, "ops") {
        apply_query_op(&mut rows, op);
    }
    let text = render_query_log(&rows, &layout_of(case));
    let outcome = lint_query_log_str(&text)
        .map(|_| ())
        .map_err(|errors| errors.iter().map(query_log_seen).collect::<Vec<Seen>>());
    check_outcome(case, outcome);
}

/// Runs every matrix case of `group`; `min_refusals` and `min_passes` keep a group from
/// passing because its cases were deleted.
fn run_matrix_group(group: &str, min_refusals: usize, min_passes: usize) {
    let cases = cases_in("matrix_cases", group);
    let passes = cases.iter().filter(|case| is_pass_case(case)).count();
    assert!(
        cases.len() - passes >= min_refusals && passes >= min_passes,
        "lint_cases.json matrix group {group} needs {min_refusals} refusal and {min_passes} pass \
         cases, found {} and {passes}",
        cases.len() - passes
    );
    for case in &cases {
        run_matrix_case(case);
    }
}

fn run_query_log_group(group: &str, min_refusals: usize, min_passes: usize) {
    let cases = cases_in("query_log_cases", group);
    let passes = cases.iter().filter(|case| is_pass_case(case)).count();
    assert!(
        cases.len() - passes >= min_refusals && passes >= min_passes,
        "lint_cases.json query log group {group} needs {min_refusals} refusal and {min_passes} \
         pass cases, found {} and {passes}",
        cases.len() - passes
    );
    for case in &cases {
        run_query_log_case(case);
    }
}

// ---------------------------------------------------------------------------
// Temporary files, committed documents and small helpers.
// ---------------------------------------------------------------------------

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let short_label: String = label.chars().take(4).collect();
        let dir = std::env::temp_dir().join(format!(
            "ih-{}-{}-{}",
            short_label,
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        TempDir(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_documents(dir: &TempDir, rows: &[CellRow], queries: &[QueryRow]) -> (PathBuf, PathBuf) {
    let matrix = dir.path().join("prior_art_matrix.md");
    let log = dir.path().join("novelty_query_log.md");
    fs::write(&matrix, render_matrix(rows, &Layout::default())).expect("write matrix");
    fs::write(&log, render_query_log(queries, &Layout::default())).expect("write query log");
    (matrix, log)
}

fn committed_document(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docs")
        .join(name)
}

fn cell_mut<'a>(rows: &'a mut [CellRow], system: &str, column: &str) -> &'a mut CellRow {
    rows.iter_mut()
        .find(|r| r.system == system && r.column == column)
        .unwrap_or_else(|| panic!("fixture has no cell {system} {column}"))
}

// ---------------------------------------------------------------------------
// The contract constants and the pass fixtures.
// ---------------------------------------------------------------------------

#[test]
fn required_constants_match_the_leaf_contract() {
    let systems: Vec<&str> = REQUIRED_SYSTEMS.to_vec();
    assert_eq!(systems, EXPECTED_SYSTEMS.to_vec());
    let columns: Vec<char> = COLUMNS.to_vec();
    assert_eq!(columns, vec!['A', 'B', 'C']);
    assert_eq!(MAX_QUOTE_CHARS, 200);
    assert_eq!(MIN_DATED_QUERIES, 6);
}

#[test]
fn pass_fixture_has_rows_with_two_yes_verdicts_and_none_with_three() {
    // The all-three rule must be exactly "all three": a lint that refused any row with two yes
    // verdicts, or any yes at all, would fail the pass fixture.
    let rows = fixture_cells();
    let mut yes_patterns: BTreeSet<String> = BTreeSet::new();
    for system in EXPECTED_SYSTEMS {
        let yes: String = ["A", "B", "C"]
            .iter()
            .filter(|column| {
                rows.iter()
                    .any(|r| r.system == system && r.column == **column && r.holds == "yes")
            })
            .copied()
            .collect();
        yes_patterns.insert(yes);
    }
    for pair in ["AB", "BC", "AC"] {
        assert!(
            yes_patterns.contains(pair),
            "matrix_pass.json needs a row that is yes on exactly {pair}: {yes_patterns:?}"
        );
    }
    assert!(
        !yes_patterns.contains("ABC"),
        "matrix_pass.json must not hold a row that is yes on A, B and C"
    );
}

#[test]
fn pass_fixture_matrix_lints_clean_and_exposes_every_cell() {
    let rows = fixture_cells();
    assert_eq!(rows.len(), EXPECTED_SYSTEMS.len() * 3);
    let text = render_matrix(&rows, &Layout::default());
    let matrix =
        lint_matrix_str(&text).unwrap_or_else(|errors| panic!("pass fixture refused: {errors:#?}"));
    assert_eq!(matrix.cells().len(), rows.len());
    for row in &rows {
        let column = row.column.chars().next().expect("fixture column letter");
        let cell = matrix
            .cell(&row.system, column)
            .unwrap_or_else(|| panic!("no parsed cell for {} {}", row.system, row.column));
        assert_eq!(cell.system, row.system);
        assert_eq!(cell.column, column);
        assert_eq!(cell.holds, row.holds == "yes");
        assert_eq!(cell.url, row.url);
        assert_eq!(cell.quote, row.quote);
        assert_eq!(cell.accessed, row.accessed);
    }
}

#[test]
fn matrix_verdicts_ignore_case_and_surrounding_space() {
    let mut rows = fixture_cells();
    cell_mut(&mut rows, "Mononoke", "A").holds = "  YES ".to_string();
    cell_mut(&mut rows, "Piper/TAP", "B").holds = "Yes".to_string();
    cell_mut(&mut rows, "Scion", "A").holds = " NO ".to_string();
    cell_mut(&mut rows, "Scion", "B").holds = "No".to_string();
    let text = render_matrix(&rows, &Layout::default());
    let matrix = lint_matrix_str(&text).unwrap_or_else(|errors| panic!("refused: {errors:#?}"));
    let holds = |system: &str, column: char| {
        matrix
            .cell(system, column)
            .unwrap_or_else(|| panic!("no parsed cell for {system} {column}"))
            .holds
    };
    assert!(holds("Mononoke", 'A'));
    assert!(holds("Piper/TAP", 'B'));
    assert!(!holds("Scion", 'A'));
    assert!(!holds("Scion", 'B'));
}

// ---------------------------------------------------------------------------
// Matrix refusals and exceptions (clause: every cell carries a URL, a verbatim quote of at
// most 200 chars and an access date; no row is true on A, B and C together).
// ---------------------------------------------------------------------------

#[test]
fn matrix_cell_without_a_url_is_refused() {
    run_matrix_group("url", 6, 1);
}

#[test]
fn matrix_cell_without_a_quote_is_refused() {
    run_matrix_group("quote_missing", 3, 0);
}

#[test]
fn matrix_quote_limit_is_200_characters_not_bytes() {
    run_matrix_group("quote_length", 4, 4);
}

#[test]
fn matrix_cell_without_a_real_access_date_is_refused() {
    run_matrix_group("date", 8, 2);
}

#[test]
fn matrix_needs_every_system_row_and_every_column_cell() {
    run_matrix_group("coverage", 8, 0);
}

#[test]
fn matrix_verdict_must_be_yes_or_no() {
    run_matrix_group("verdict", 3, 2);
}

#[test]
fn matrix_row_true_on_a_b_and_c_together_is_refused() {
    run_matrix_group("all_three", 5, 1);
}

#[test]
fn matrix_without_a_readable_evidence_table_is_refused() {
    run_matrix_group("structure", 5, 4);
}

#[test]
fn matrix_lint_reports_every_fault_not_only_the_first() {
    run_matrix_group("multi", 1, 0);
}

#[test]
fn missing_matrix_file_is_refused_with_missing_file() {
    let dir = TempDir::new("matrix-missing");
    let path = dir.path().join("prior_art_matrix.md");
    let errors = lint_matrix(&path)
        .err()
        .unwrap_or_else(|| panic!("a matrix file that does not exist must be refused"));
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, MatrixError::MissingFile { path: p, .. } if *p == path)),
        "{errors:?}"
    );
}

#[test]
fn matrix_file_on_disk_is_linted_like_its_text() {
    let dir = TempDir::new("matrix-file");
    let (matrix_path, _) = write_documents(&dir, &fixture_cells(), &fixture_queries());
    let matrix = lint_matrix(&matrix_path).unwrap_or_else(|errors| panic!("refused: {errors:#?}"));
    assert_eq!(matrix.cells().len(), EXPECTED_SYSTEMS.len() * 3);

    let mut rows = fixture_cells();
    rows[0].url.clear();
    let (bad_path, _) = write_documents(&dir, &rows, &fixture_queries());
    let errors = lint_matrix(&bad_path)
        .err()
        .unwrap_or_else(|| panic!("a cell without a URL must be refused from disk too"));
    assert!(
        errors.iter().any(|e| matches!(
            e,
            MatrixError::MissingUrl { system, column, .. } if system == "Scion" && *column == 'A'
        )),
        "{errors:?}"
    );
}

// ---------------------------------------------------------------------------
// Query log refusals and exceptions (clause: fewer than 6 dated queries over arXiv, GitHub,
// Scholar and patents are logged).
// ---------------------------------------------------------------------------

#[test]
fn pass_fixture_query_log_lints_clean_and_keeps_document_order() {
    let queries = fixture_queries();
    assert_eq!(queries.len(), 8);
    let text = render_query_log(&queries, &Layout::default());
    let log = lint_query_log_str(&text)
        .unwrap_or_else(|errors| panic!("pass fixture refused: {errors:#?}"));
    assert_eq!(log.queries().len(), queries.len());
    for (parsed, fixture) in log.queries().iter().zip(queries.iter()) {
        assert_eq!(parsed.date, fixture.date);
        assert_eq!(source_label(parsed.source), fixture.source);
        assert_eq!(parsed.query, fixture.query);
    }
}

#[test]
fn query_log_needs_at_least_six_dated_queries() {
    run_query_log_group("count", 2, 2);
}

#[test]
fn query_log_needs_arxiv_github_scholar_and_patent_queries() {
    run_query_log_group("sources", 5, 1);
}

#[test]
fn query_log_row_without_a_real_date_is_refused_and_not_counted() {
    run_query_log_group("dates", 3, 1);
}

#[test]
fn query_log_row_without_query_text_is_refused_and_not_counted() {
    run_query_log_group("rows", 2, 0);
}

#[test]
fn query_log_without_a_readable_table_is_refused() {
    run_query_log_group("structure", 3, 3);
}

#[test]
fn five_dated_queries_report_how_many_were_found_and_required() {
    let mut queries = fixture_queries();
    queries.truncate(MIN_DATED_QUERIES - 1);
    let text = render_query_log(&queries, &Layout::default());
    let errors = lint_query_log_str(&text)
        .err()
        .unwrap_or_else(|| panic!("five dated queries must be refused"));
    assert!(
        errors.iter().any(|e| matches!(
            e,
            QueryLogError::TooFewQueries { found, required, .. }
                if *found == MIN_DATED_QUERIES - 1 && *required == MIN_DATED_QUERIES
        )),
        "{errors:?}"
    );
}

#[test]
fn query_source_names_map_to_the_four_sources_ignoring_ascii_case() {
    let mut queries = fixture_queries();
    queries[0].source = "ARXIV".to_string();
    queries[1].source = "github".to_string();
    queries[2].source = "google scholar".to_string();
    queries[3].source = "PATENTS".to_string();
    let text = render_query_log(&queries, &Layout::default());
    let log = lint_query_log_str(&text).unwrap_or_else(|errors| panic!("refused: {errors:#?}"));
    let sources: Vec<QuerySource> = log.queries().iter().take(4).map(|q| q.source).collect();
    assert_eq!(
        sources,
        vec![
            QuerySource::Arxiv,
            QuerySource::Github,
            QuerySource::Scholar,
            QuerySource::Patents
        ]
    );
}

#[test]
fn missing_query_log_file_is_refused_with_missing_file() {
    let dir = TempDir::new("log-missing");
    let path = dir.path().join("novelty_query_log.md");
    let errors = lint_query_log(&path)
        .err()
        .unwrap_or_else(|| panic!("a query log file that does not exist must be refused"));
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, QueryLogError::MissingFile { path: p, .. } if *p == path)),
        "{errors:?}"
    );
}

#[test]
fn query_log_file_on_disk_is_linted_like_its_text() {
    let dir = TempDir::new("log-file");
    let (_, log_path) = write_documents(&dir, &fixture_cells(), &fixture_queries());
    let log = lint_query_log(&log_path).unwrap_or_else(|errors| panic!("refused: {errors:#?}"));
    assert_eq!(log.queries().len(), 8);

    let mut queries = fixture_queries();
    queries.truncate(MIN_DATED_QUERIES - 1);
    let (_, short_path) = write_documents(&dir, &fixture_cells(), &queries);
    assert!(lint_query_log(&short_path).is_err());
}

// ---------------------------------------------------------------------------
// The lint as a command: both documents, and the exit status.
// ---------------------------------------------------------------------------

const EXIT_FAULTS: [&str; 6] = [
    "blank_url",
    "overlong_quote",
    "blank_date",
    "five_queries",
    "no_patent_search",
    "all_three",
];

fn apply_fault(fault: &str, rows: &mut [CellRow], queries: &mut Vec<QueryRow>) {
    match fault {
        "blank_url" => rows[0].url.clear(),
        "overlong_quote" => rows[0].quote = "x".repeat(MAX_QUOTE_CHARS + 1),
        "blank_date" => rows[0].accessed.clear(),
        "five_queries" => queries.truncate(MIN_DATED_QUERIES - 1),
        "no_patent_search" => queries.retain(|q| q.source != "Patents"),
        "all_three" => cell_mut(rows, "SubmitQueue", "C").holds = "yes".to_string(),
        other => panic!("unknown fault {other:?}"),
    }
}

#[test]
fn combined_lint_passes_the_pass_fixtures_and_exits_zero() {
    let dir = TempDir::new("pass");
    let (matrix, log) = write_documents(&dir, &fixture_cells(), &fixture_queries());
    match lint_prior_art(&matrix, &log) {
        Ok((parsed_matrix, parsed_log)) => {
            assert_eq!(parsed_matrix.cells().len(), EXPECTED_SYSTEMS.len() * 3);
            assert_eq!(parsed_log.queries().len(), 8);
        }
        Err(errors) => panic!("pass fixtures refused: {errors:#?}"),
    }
    assert_eq!(lint_exit_code(&matrix, &log), 0);
}

#[test]
fn lint_exits_nonzero_for_each_clause_fault_and_blames_the_right_document() {
    let dir = TempDir::new("exit");
    for fault in EXIT_FAULTS {
        let mut rows = fixture_cells();
        let mut queries = fixture_queries();
        apply_fault(fault, &mut rows, &mut queries);
        let (matrix, log) = write_documents(&dir, &rows, &queries);
        let errors = lint_prior_art(&matrix, &log)
            .err()
            .unwrap_or_else(|| panic!("fault {fault} must be refused"));
        assert!(!errors.is_empty(), "fault {fault}: Err with no errors");
        let in_matrix = errors.iter().any(|e| matches!(e, PriorArtError::Matrix(_)));
        let in_log = errors.iter().any(|e| matches!(e, PriorArtError::QueryLog(_)));
        match fault {
            "five_queries" | "no_patent_search" => {
                assert!(in_log && !in_matrix, "fault {fault}: {errors:?}")
            }
            _ => assert!(in_matrix && !in_log, "fault {fault}: {errors:?}"),
        }
        assert_ne!(
            lint_exit_code(&matrix, &log),
            0,
            "fault {fault}: the lint must exit non-zero"
        );
    }
}

#[test]
fn combined_lint_reports_both_documents_together() {
    let dir = TempDir::new("both");
    let mut rows = fixture_cells();
    let mut queries = fixture_queries();
    apply_fault("blank_url", &mut rows, &mut queries);
    apply_fault("five_queries", &mut rows, &mut queries);
    let (matrix, log) = write_documents(&dir, &rows, &queries);
    let errors = lint_prior_art(&matrix, &log)
        .err()
        .unwrap_or_else(|| panic!("two faulty documents must be refused"));
    assert!(
        errors.iter().any(|e| matches!(
            e,
            PriorArtError::Matrix(MatrixError::MissingUrl { system, column, .. })
                if system == "Scion" && *column == 'A'
        )),
        "{errors:?}"
    );
    assert!(
        errors.iter().any(|e| matches!(
            e,
            PriorArtError::QueryLog(QueryLogError::TooFewQueries { found: 5, .. })
        )),
        "{errors:?}"
    );
    assert_ne!(lint_exit_code(&matrix, &log), 0);
}

#[test]
fn lint_exits_nonzero_when_a_document_is_missing() {
    let dir = TempDir::new("gone");
    let (matrix, log) = write_documents(&dir, &fixture_cells(), &fixture_queries());
    let absent = dir.path().join("absent.md");
    assert_ne!(lint_exit_code(&absent, &log), 0);
    assert_ne!(lint_exit_code(&matrix, &absent), 0);
    assert_eq!(lint_exit_code(&matrix, &log), 0);
}

// ---------------------------------------------------------------------------
// The committed documents. These fail until the documents exist and pass the lint.
// ---------------------------------------------------------------------------

#[test]
fn committed_prior_art_matrix_passes_the_lint() {
    let path = committed_document("prior_art_matrix.md");
    match lint_matrix(&path) {
        Ok(matrix) => assert_eq!(matrix.cells().len(), REQUIRED_SYSTEMS.len() * COLUMNS.len()),
        Err(errors) => panic!("docs/prior_art_matrix.md must pass the matrix lint: {errors:#?}"),
    }
}

#[test]
fn committed_novelty_query_log_passes_the_lint() {
    let path = committed_document("novelty_query_log.md");
    match lint_query_log(&path) {
        Ok(log) => assert!(log.queries().len() >= MIN_DATED_QUERIES),
        Err(errors) => {
            panic!("docs/novelty_query_log.md must pass the query log lint: {errors:#?}")
        }
    }
}

#[test]
fn committed_documents_pass_the_combined_lint_and_exit_zero() {
    let matrix = committed_document("prior_art_matrix.md");
    let log = committed_document("novelty_query_log.md");
    if let Err(errors) = lint_prior_art(&matrix, &log) {
        panic!("the committed prior-art documents must pass the lint: {errors:#?}");
    }
    assert_eq!(lint_exit_code(&matrix, &log), 0);
}

// ---------------------------------------------------------------------------
// The step only test-code can run: a reviewer re-opens 3 random cited URLs.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum TomlValue {
    Str(String),
    Int(i64),
    List(Vec<String>),
}

type Step = BTreeMap<String, TomlValue>;

fn parse_string_list(inner: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    for ch in inner.chars() {
        match (in_string, ch) {
            (false, '"') => {
                in_string = true;
                current.clear();
            }
            (true, '"') => {
                in_string = false;
                items.push(current.clone());
            }
            (true, c) => current.push(c),
            (false, _) => {}
        }
    }
    items
}

/// Reads the `[[step]]` tables of `test_code_steps.toml`: one `key = value` per line, a value
/// is a double-quoted string without escapes, an integer, or a one-line array of such strings.
fn parse_steps(text: &str) -> Vec<Step> {
    let mut steps: Vec<Step> = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[step]]" {
            steps.push(Step::new());
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            panic!("test_code_steps.toml line {}: expected key = value", idx + 1);
        };
        let value = value.trim();
        let parsed = if let Some(inner) = value
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            TomlValue::List(parse_string_list(inner))
        } else if let Some(inner) = value
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
        {
            TomlValue::Str(inner.to_string())
        } else {
            TomlValue::Int(value.parse().unwrap_or_else(|_| {
                panic!("test_code_steps.toml line {}: bad value {value:?}", idx + 1)
            }))
        };
        steps
            .last_mut()
            .unwrap_or_else(|| {
                panic!(
                    "test_code_steps.toml line {}: key before the first [[step]]",
                    idx + 1
                )
            })
            .insert(key.trim().to_string(), parsed);
    }
    steps
}

fn toml_str<'a>(step: &'a Step, key: &str) -> &'a str {
    match step.get(key) {
        Some(TomlValue::Str(s)) => s.as_str(),
        other => panic!("step key {key:?} must be a string, found {other:?}"),
    }
}

fn toml_int(step: &Step, key: &str) -> i64 {
    match step.get(key) {
        Some(TomlValue::Int(n)) => *n,
        other => panic!("step key {key:?} must be an integer, found {other:?}"),
    }
}

fn toml_list<'a>(step: &'a Step, key: &str) -> &'a [String] {
    match step.get(key) {
        Some(TomlValue::List(items)) => items.as_slice(),
        other => panic!("step key {key:?} must be a list, found {other:?}"),
    }
}

/// splitmix64, the generator the step description names.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn system_rank(system: &str) -> usize {
    REQUIRED_SYSTEMS
        .iter()
        .position(|name| *name == system)
        .unwrap_or(usize::MAX)
}

/// The sampling rule of the step description: order the cells by system (as listed in
/// `REQUIRED_SYSTEMS`) then column, then pick `count` of them by a partial Fisher-Yates shuffle
/// driven by splitmix64 seeded with `seed`.
fn sample_cells<T: Clone>(
    cells: &[T],
    key: impl Fn(&T) -> (usize, char),
    seed: u64,
    count: usize,
) -> Vec<T> {
    let mut ordered: Vec<T> = cells.to_vec();
    ordered.sort_by_key(&key);
    let mut rng = SplitMix64(seed);
    let mut picked = Vec::new();
    for i in 0..count.min(ordered.len()) {
        let remaining = (ordered.len() - i) as u64;
        let j = i + (rng.next_u64() % remaining) as usize;
        ordered.swap(i, j);
        picked.push(ordered[i].clone());
    }
    picked
}

fn parse_seed(text: &str) -> Option<u64> {
    let text = text.trim();
    match text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

#[test]
fn test_code_steps_describe_the_reviewer_url_spot_check() {
    let steps = parse_steps(TEST_CODE_STEPS);
    assert!(!steps.is_empty(), "test_code_steps.toml holds no [[step]]");
    for step in &steps {
        let id = toml_str(step, "id");
        assert_eq!(toml_str(step, "kind"), "test_code_only", "step {id}");
        assert!(!toml_str(step, "clause").trim().is_empty(), "step {id}");
    }

    let step = steps
        .iter()
        .find(|step| toml_str(step, "id") == SPOT_CHECK_STEP_ID)
        .unwrap_or_else(|| panic!("test_code_steps.toml needs the step {SPOT_CHECK_STEP_ID}"));
    assert!(
        toml_str(step, "clause").contains("re-opens 3 random cited URLs and confirms their quotes"),
        "the step must quote the clause it covers"
    );
    assert_eq!(
        toml_int(step, "sample_size"),
        SPOT_CHECK_SAMPLE_SIZE as i64,
        "the clause names 3 random cited URLs"
    );
    assert_eq!(toml_str(step, "seed_env"), SPOT_CHECK_SEED_ENV);
    for key in ["sampling", "pass_when", "fail_when"] {
        assert!(!toml_str(step, key).trim().is_empty(), "step key {key}");
    }
    assert!(
        toml_str(step, "sampling").contains("splitmix64"),
        "the sampling rule must name the generator the ignored test uses"
    );
    assert!(
        toml_list(step, "reviewer_procedure").len() >= 3,
        "the reviewer procedure needs its steps"
    );

    let command = toml_str(step, "command");
    for part in [
        "cargo test",
        "-p inarch-cli",
        "--test prior_art_matrix_lint_test",
        "--ignored",
        SPOT_CHECK_SEED_ENV,
        SPOT_CHECK_TEST,
    ] {
        assert!(
            command.contains(part),
            "the step command must contain {part:?}: {command}"
        );
    }

    // The test the command names exists in this file and is ignored by default.
    let lines: Vec<&str> = THIS_FILE.lines().collect();
    let declared = format!("fn {SPOT_CHECK_TEST}(");
    let at = lines
        .iter()
        .position(|line| line.trim_start().starts_with(&declared))
        .unwrap_or_else(|| panic!("this file declares no test named {SPOT_CHECK_TEST}"));
    let attributes = &lines[at.saturating_sub(3)..at];
    assert!(
        attributes.iter().any(|line| line.contains("#[ignore")),
        "{SPOT_CHECK_TEST} must be #[ignore]"
    );
}

#[test]
fn spot_check_sampler_is_deterministic_and_picks_three_distinct_cells() {
    let text = render_matrix(&fixture_cells(), &Layout::default());
    let matrix = lint_matrix_str(&text).unwrap_or_else(|errors| panic!("refused: {errors:#?}"));
    let cells: Vec<(String, char)> = matrix
        .cells()
        .iter()
        .map(|cell| (cell.system.clone(), cell.column))
        .collect();
    let key = |cell: &(String, char)| (system_rank(&cell.0), cell.1);
    let mut first_picks: BTreeSet<(String, char)> = BTreeSet::new();
    for seed in 0..64u64 {
        let picked = sample_cells(&cells, key, seed, SPOT_CHECK_SAMPLE_SIZE);
        let again = sample_cells(&cells, key, seed, SPOT_CHECK_SAMPLE_SIZE);
        assert_eq!(picked, again, "seed {seed} must give the same sample twice");
        assert_eq!(picked.len(), SPOT_CHECK_SAMPLE_SIZE);
        let distinct: BTreeSet<&(String, char)> = picked.iter().collect();
        assert_eq!(distinct.len(), SPOT_CHECK_SAMPLE_SIZE, "seed {seed}");
        first_picks.insert(picked[0].clone());
    }
    assert!(
        first_picks.len() > 8,
        "64 seeds must reach many different cells, reached {}",
        first_picks.len()
    );
}

#[test]
fn spot_check_seed_reads_decimal_and_hex() {
    assert_eq!(parse_seed("42"), Some(42));
    assert_eq!(parse_seed(" 0x2a "), Some(42));
    assert_eq!(parse_seed("0X2A"), Some(42));
    assert_eq!(parse_seed("not-a-seed"), None);
    assert_eq!(parse_seed("0xzz"), None);
}

#[test]
fn every_lint_case_belongs_to_a_group_a_test_runs() {
    let doc = parse_json(LINT_CASES, "lint_cases.json");
    let mut names: BTreeSet<String> = BTreeSet::new();
    for (list, groups) in [
        ("matrix_cases", MATRIX_GROUPS.as_slice()),
        ("query_log_cases", QUERY_LOG_GROUPS.as_slice()),
    ] {
        for case in items_of(&doc, list) {
            let name = text_of(case, "name");
            let group = text_of(case, "group");
            assert!(
                groups.contains(&group),
                "case {name} in {list} names group {group}, which no test runs"
            );
            assert!(
                names.insert(format!("{list}/{name}")),
                "case name {name} is used twice in {list}"
            );
        }
    }
}

/// Test-code step: lists the three cells a reviewer re-opens. It makes no network call; the
/// reviewer opens each printed URL and confirms the printed quote. It is skipped, with a
/// message, when the seed variable is not set.
#[test]
#[ignore = "test-code step: needs PRIOR_ART_SPOT_CHECK_SEED and the committed matrix"]
fn spot_check_lists_three_cited_cells_from_the_committed_matrix() {
    let Ok(raw_seed) = std::env::var(SPOT_CHECK_SEED_ENV) else {
        eprintln!(
            "SKIPPED: set {SPOT_CHECK_SEED_ENV} (decimal or 0x-prefixed hex) to list the three \
             cited cells a reviewer re-opens"
        );
        return;
    };
    let seed = parse_seed(&raw_seed).unwrap_or_else(|| {
        panic!("{SPOT_CHECK_SEED_ENV} must be a decimal or 0x-prefixed hex integer: {raw_seed:?}")
    });
    let matrix = lint_matrix(&committed_document("prior_art_matrix.md"))
        .unwrap_or_else(|errors| panic!("docs/prior_art_matrix.md refused: {errors:#?}"));
    let cells: Vec<(String, char, String, String)> = matrix
        .cells()
        .iter()
        .map(|cell| {
            (
                cell.system.clone(),
                cell.column,
                cell.url.clone(),
                cell.quote.clone(),
            )
        })
        .collect();
    let key = |cell: &(String, char, String, String)| (system_rank(&cell.0), cell.1);
    let picked = sample_cells(&cells, key, seed, SPOT_CHECK_SAMPLE_SIZE);
    assert_eq!(picked.len(), SPOT_CHECK_SAMPLE_SIZE);
    for (system, column, url, quote) in &picked {
        println!("SPOT-CHECK system={system} column={column} url={url} quote={quote}");
    }
}
