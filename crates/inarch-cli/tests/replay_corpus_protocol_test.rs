//! Replay corpus, isolated-host benchmark protocol and four-term swarm cost metrics.
//!
//! This file is the frozen contract for the benchmark substrate in
//! `inarch_cli::bench`. It names five acceptance clauses and every test below
//! backs one of them:
//!
//! 1. The corpus lint exits 0 only if every repository is pinned by commit SHA,
//!    none is synthetic, at least one has 100000 or more commits and at least
//!    three languages are present.
//! 2. The runner aborts a cell when the pre-run load is 1.0 or more per core.
//! 3. A dry run writes a per-run CSV with exit codes, stderr and all four terms.
//! 4. The protocol defines a submission-ingest term beside landings per minute:
//!    sustained Land submissions per second, with p50 and p99 time-to-position
//!    and time-to-state measured separately.
//! 5. The replay mix (commit size, file overlap, touch rate) is re-measured from
//!    pinned real histories, never uniform, and the lint rejects a cell that
//!    deviates by more than 10% on any moment.
//!
//! The four cost terms are model minutes, broken-base minutes, CI compute (every
//! run counts, and a key is only green with at least two passed runs from
//! distinct runners) and latency (landings per minute, ingest rate, and the
//! position and state percentiles).
//!
//! Public surface this file imports from `inarch_cli::bench` (all new; the
//! existing benchmark suite items are untouched):
//!
//! * Corpus: `CorpusManifest { repos }`, `CorpusRepo { name, url, language,
//!   commit_sha, commit_count: u64, synthetic }`, `CorpusManifest::from_toml_str`,
//!   `CorpusViolation::{kind, repo}`, `CorpusLintReport { violations }` with
//!   `exit_code`, `lint_corpus`, `lint_corpus_toml`, and the constants
//!   `MIN_LARGE_HISTORY_COMMITS` and `MIN_CORPUS_LANGUAGES`. The manifest is a
//!   `schema_version` integer plus `[[repo]]` tables with exactly the six keys
//!   above; a missing or ill-typed key is a malformed manifest. `kind()` is one
//!   of `unpinned_repo`, `synthetic_repo`, `no_large_history`,
//!   `too_few_languages`, `malformed_manifest`. A pin is a lowercase hexadecimal
//!   commit id of 40 (or 64) digits that is not all zero. Language names compare
//!   without case.
//!   The command line mirrors it: `inr bench corpus-lint --manifest <path>`
//!   prints each violation's kind and repository, exits 0 when the lint finds
//!   nothing and 1 otherwise, including for a manifest that is unreadable.
//! * Host and runner: `HostLoad { load_1m: f64, logical_cores: u32 }` with
//!   `per_core`, `MAX_PRE_RUN_LOAD_PER_CORE`, `trait LoadSource { fn sample(&self)
//!   -> HostLoad }`, `CellAbort::LoadTooHigh { load_1m, logical_cores }` (plus any
//!   other variant for an invalid host), `preflight(&HostLoad) -> Result<(),
//!   CellAbort>`, `CellSpec { cell_id: String, runs: u32 }`, `trait RunExecutor {
//!   fn execute(&mut self, &CellSpec, run_index: u32) -> RunObservation }`,
//!   `RunObservation { exit_code: i32, stderr: String, window_ms: u64,
//!   model_active_ms: Vec<u64>, broken_base_intervals_ms: Vec<(u64, u64)>,
//!   ci_runs: Vec<CiRun>, landings: Vec<LandingSample> }`, `CiRun { key, runner,
//!   cpu_ms: u64, passed: bool }`, `LandingSample { submit_ms: u64, position_ms:
//!   Option<u64>, state_ms: Option<u64> }`, `RunMetrics { model_minutes,
//!   broken_base_minutes, ci_compute_seconds, ci_keys_green: usize,
//!   ci_keys_not_green: usize, landings_per_min, ingest_land_per_sec,
//!   time_to_position_p50_ms, time_to_position_p99_ms, time_to_state_p50_ms,
//!   time_to_state_p99_ms }` (the percentiles are `Option<f64>`, the rest `f64`),
//!   `RunRecord { run_index: u32, observation, metrics }`,
//!   `run_cell(&CellSpec, &dyn LoadSource, &mut dyn RunExecutor) ->
//!   Result<Vec<RunRecord>, CellAbort>`, `dry_run(&CellSpec, &dyn LoadSource,
//!   &Path) -> Result<Vec<RunRecord>, BenchRunError>`, `BenchRunError::{Aborted(
//!   CellAbort), Io(String)}`, `compute_run_metrics(&RunObservation) ->
//!   RunMetrics`, `percentile_nearest_rank(&[f64], pct: f64) -> Option<f64>`,
//!   `RUN_CSV_HEADER: &str` and `render_run_csv(&str, &[RunRecord]) -> String`.
//!   `run_cell` samples the load once, before the first run, and starts no run
//!   when `preflight` refuses; it calls the executor once per run in order and
//!   never aborts on a nonzero exit code. `dry_run` is `run_cell` with a built-in
//!   deterministic executor that touches no repository and no network; it writes
//!   the CSV only after the cell ran. CSV fields follow RFC 4180 and every record
//!   ends with a line feed.
//! * Mix: `Moments { m1, m2, m3 }`, `MixMoments { commit_size, file_overlap,
//!   touch_rate }`, `SampledCommit { id: String, lines: u64, files: Vec<u64> }`,
//!   `WorkloadSample { source_url, source_commit_sha, commits }` with
//!   `from_json_str` (reads `source.url`, `source.commit_sha` and
//!   `commits[].{id, lines, files}`; other keys are descriptive) and
//!   `is_pinned_by(&CorpusManifest)` (true only when a non-synthetic repository
//!   has the same url and the same commit id), `measure_mix(&[SampledCommit]) ->
//!   MixMoments`, `MomentDeviation { distribution: &'static str, moment: u8,
//!   reference, cell, relative }` with `label()` giving `<distribution>:<moment>`,
//!   `MixLintReport { deviations (all nine, commit_size then file_overlap then
//!   touch_rate, m1 to m3), violations (those past the limit) }` with `exit_code`,
//!   `lint_mix_moments(&MixMoments, &MixMoments)`, `lint_cell_mix(&MixMoments,
//!   &[SampledCommit])`, `MAX_MIX_DEVIATION`, `ReplayCell { cell_id, base_commit,
//!   commits }`, `build_replay_cell(cell_id, base_commit, history, count)` and
//!   `MIN_REPLAY_COMMITS`. A replay cell takes the first `count` commits of the
//!   history in order, all from the one base, and refuses a `count` below 500, a
//!   history shorter than `count`, or a base that is not a full lowercase commit
//!   id.
//!
//! Every data type derives `Debug` and `Clone`; `Moments` and `MixMoments` also
//! derive `Copy`; `SampledCommit`, `CorpusManifest`, `CorpusRepo`, `RunObservation`,
//! `CiRun` and `LandingSample` also derive `PartialEq`.
//!
//! Mix definitions. A cell is one batch of concurrent changes from one base.
//! `commit_size` is the number of distinct files a commit touches. `file_overlap`
//! is, per commit, the share of its distinct files that at least one other commit
//! in the batch also touches (a commit with no files has size 0 and overlap 0).
//! `touch_rate` is, per distinct file in the batch, the number of commits
//! touching it divided by the number of commits in the batch. Each distribution
//! is summarised by its raw moments m1, m2 and m3 (mean of x, x squared, x
//! cubed) over commits for the first two and over distinct files for the third.
//! A moment is rejected when `|cell - reference| / |reference|` is strictly
//! greater than `MAX_MIX_DEVIATION`; a zero reference accepts only a zero cell
//! value, and any other cell value has relative deviation `f64::INFINITY`.
//! Reference and cell are measured over batches of comparable length, so the
//! reference is re-measured from the same pinned history range for each cell.
//!
//! Metric definitions. Window rates use `window_ms`; a zero window gives 0.0 for
//! both rates, so no metric is ever NaN or infinite and an undefined percentile
//! is `None` (an empty CSV field). `model_minutes` is the summed model-active
//! milliseconds over 60000. `broken_base_minutes` is the length of the union of
//! the half-open intervals over 60000, so overlapping or touching intervals count
//! once. `ci_compute_seconds` is the CPU milliseconds of every CI run, passed or
//! not, over 1000. A CI key is green with at least two passed runs from at least
//! two distinct runners. `landings_per_min` counts samples that reached state.
//! `ingest_land_per_sec` counts samples that were assigned a position. Time to
//! position is `position_ms - submit_ms` and time to state is `state_ms -
//! submit_ms`, each taken only over the samples that have that field, and
//! percentiles use the nearest-rank rule (rank `ceil(p / 100 * n)`, one-based).

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use inarch_cli::bench::{
    BenchRunError, CellAbort, CellSpec, CiRun, CorpusLintReport, CorpusManifest, HostLoad,
    LandingSample, LoadSource, MAX_MIX_DEVIATION, MAX_PRE_RUN_LOAD_PER_CORE, MIN_CORPUS_LANGUAGES,
    MIN_LARGE_HISTORY_COMMITS, MIN_REPLAY_COMMITS, MixLintReport, MixMoments, MomentDeviation,
    Moments, RUN_CSV_HEADER, RunExecutor, RunObservation, SampledCommit, WorkloadSample,
    build_replay_cell, compute_run_metrics, dry_run, lint_cell_mix, lint_corpus, lint_corpus_toml,
    lint_mix_moments, measure_mix, percentile_nearest_rank, preflight, render_run_csv, run_cell,
};

// ---------------------------------------------------------------------------
// Fixture access and a small reader for the fixture subset of TOML
// ---------------------------------------------------------------------------

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("bench")
}

fn fixture_text(name: &str) -> String {
    fs::read_to_string(fixture_dir().join(name))
        .unwrap_or_else(|e| panic!("fixture {name} must be readable: {e}"))
}

#[derive(Debug, Clone)]
enum Val {
    Str(String),
    Int(i64),
    Bool(bool),
    List(Vec<String>),
}

struct Table {
    name: String,
    fields: BTreeMap<String, Val>,
}

impl Table {
    fn val(&self, key: &str) -> &Val {
        self.fields
            .get(key)
            .unwrap_or_else(|| panic!("fixture table [[{}]] lacks key {key}", self.name))
    }

    fn str(&self, key: &str) -> &str {
        match self.val(key) {
            Val::Str(s) => s.as_str(),
            other => panic!("[[{}]] {key} must be a string, got {other:?}", self.name),
        }
    }

    fn int(&self, key: &str) -> i64 {
        match self.val(key) {
            Val::Int(i) => *i,
            other => panic!("[[{}]] {key} must be an integer, got {other:?}", self.name),
        }
    }

    fn bool_(&self, key: &str) -> bool {
        match self.val(key) {
            Val::Bool(b) => *b,
            other => panic!("[[{}]] {key} must be a boolean, got {other:?}", self.name),
        }
    }

    fn list(&self, key: &str) -> &[String] {
        match self.val(key) {
            Val::List(items) => items.as_slice(),
            other => panic!("[[{}]] {key} must be a list, got {other:?}", self.name),
        }
    }

    fn opt_str(&self, key: &str) -> Option<&str> {
        match self.fields.get(key) {
            Some(Val::Str(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    fn opt_list(&self, key: &str) -> Option<&[String]> {
        match self.fields.get(key) {
            Some(Val::List(items)) => Some(items.as_slice()),
            _ => None,
        }
    }
}

fn parse_scalar(raw: &str) -> Val {
    let raw = raw.trim();
    if let Some(inner) = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return Val::Str(inner.to_string());
    }
    if let Some(inner) = raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        return Val::Str(inner.to_string());
    }
    match raw {
        "true" => Val::Bool(true),
        "false" => Val::Bool(false),
        _ => Val::Int(
            raw.parse::<i64>()
                .unwrap_or_else(|_| panic!("fixture value not understood by the reader: {raw}")),
        ),
    }
}

fn parse_list(raw: &str) -> Vec<String> {
    let inner = raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or_else(|| panic!("fixture list must open and close on one line: {raw}"));
    inner
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| item.trim_matches('"').to_string())
        .collect()
}

/// Reads `[[name]]` tables of `key = value` lines. Values are quoted strings,
/// integers, booleans or one-line lists of quoted strings. The first table
/// (name empty) holds any keys that precede the first header.
fn read_tables(text: &str) -> Vec<Table> {
    let mut tables = vec![Table {
        name: String::new(),
        fields: BTreeMap::new(),
    }];
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix("[[").and_then(|s| s.strip_suffix("]]")) {
            tables.push(Table {
                name: name.trim().to_string(),
                fields: BTreeMap::new(),
            });
            continue;
        }
        let (key, raw) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("fixture line {} has no '=': {line}", idx + 1));
        let raw = raw.trim();
        let value = if raw.starts_with('[') {
            Val::List(parse_list(raw))
        } else {
            parse_scalar(raw)
        };
        tables
            .last_mut()
            .expect("the root table always exists")
            .fields
            .insert(key.trim().to_string(), value);
    }
    tables
}

fn tables_named<'a>(tables: &'a [Table], name: &str) -> Vec<&'a Table> {
    tables.iter().filter(|t| t.name == name).collect()
}

// ---------------------------------------------------------------------------
// Scratch directory, process helpers, CSV reader, numeric helpers
// ---------------------------------------------------------------------------

static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(1);

struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rcp-{label}-{}-{}",
            std::process::id(),
            NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("create scratch directory");
        Scratch { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_inr(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_inr"))
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("inr must run")
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// RFC 4180 reader: quoted fields may hold commas, doubled quotes and line breaks.
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            match c {
                '"' => {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        field.push('"');
                    } else {
                        in_quotes = false;
                    }
                }
                other => field.push(other),
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => row.push(std::mem::take(&mut field)),
                '\r' => {}
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                other => field.push(other),
            }
        }
    }
    assert!(!in_quotes, "the CSV ended inside a quoted field");
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

const RUN_CSV_COLUMNS: [&str; 15] = [
    "cell_id",
    "run_index",
    "exit_code",
    "stderr",
    "model_minutes",
    "broken_base_minutes",
    "ci_compute_seconds",
    "ci_keys_green",
    "ci_keys_not_green",
    "landings_per_min",
    "ingest_land_per_sec",
    "time_to_position_p50_ms",
    "time_to_position_p99_ms",
    "time_to_state_p50_ms",
    "time_to_state_p99_ms",
];

/// Columns that carry a measured term, in header order, after the identity,
/// exit code and stderr columns.
const TERM_COLUMNS: &[&str] = &[
    "model_minutes",
    "broken_base_minutes",
    "ci_compute_seconds",
    "ci_keys_green",
    "ci_keys_not_green",
    "landings_per_min",
    "ingest_land_per_sec",
    "time_to_position_p50_ms",
    "time_to_position_p99_ms",
    "time_to_state_p50_ms",
    "time_to_state_p99_ms",
];

fn column(header: &[String], name: &str) -> usize {
    header
        .iter()
        .position(|h| h.as_str() == name)
        .unwrap_or_else(|| panic!("the CSV lacks column {name}"))
}

fn number(header: &[String], row: &[String], name: &str) -> f64 {
    let raw = &row[column(header, name)];
    raw.parse::<f64>()
        .unwrap_or_else(|_| panic!("column {name} must hold a number, got {raw:?}"))
}

fn assert_close(actual: f64, expected: f64, what: &str) {
    let tolerance = 1e-9 * expected.abs();
    assert!(
        (actual - expected).abs() <= tolerance,
        "{what}: expected {expected}, got {actual}"
    );
}

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

// ---------------------------------------------------------------------------
// Clause 1: corpus lint
// ---------------------------------------------------------------------------

fn load_manifest() -> CorpusManifest {
    CorpusManifest::from_toml_str(&fixture_text("corpus_manifest.toml"))
        .expect("the committed corpus manifest parses")
}

fn kinds_of(report: &CorpusLintReport) -> Vec<&'static str> {
    let kinds: BTreeSet<&'static str> = report.violations.iter().map(|v| v.kind()).collect();
    kinds.into_iter().collect()
}

/// Applies one `<repo or *>:<field>=<value>` mutation from `lint_cases.toml`.
fn apply_mutation(manifest: &mut CorpusManifest, entry: &str) {
    let (target, rest) = entry
        .split_once(':')
        .unwrap_or_else(|| panic!("mutation {entry:?} is not <repo>:<field>=<value>"));
    let (field, value) = rest
        .split_once('=')
        .unwrap_or_else(|| panic!("mutation {entry:?} is not <repo>:<field>=<value>"));
    if field == "remove" {
        let before = manifest.repos.len();
        manifest
            .repos
            .retain(|r| target != "*" && r.name.as_str() != target);
        assert!(
            manifest.repos.len() < before,
            "mutation {entry:?} removed nothing"
        );
        return;
    }
    let mut touched = 0;
    for repo in manifest
        .repos
        .iter_mut()
        .filter(|r| target == "*" || r.name.as_str() == target)
    {
        touched += 1;
        match field {
            "commit_sha" => repo.commit_sha = value.to_string(),
            "commit_count" => {
                repo.commit_count = value
                    .parse()
                    .unwrap_or_else(|_| panic!("commit_count {value:?} is not a number"));
            }
            "language" => repo.language = value.to_string(),
            "synthetic" => {
                repo.synthetic = value
                    .parse()
                    .unwrap_or_else(|_| panic!("synthetic {value:?} is not a boolean"));
            }
            other => panic!("unknown mutation field {other}"),
        }
    }
    assert!(touched > 0, "mutation {entry:?} matched no repository");
}

#[test]
fn protocol_thresholds_are_the_acceptance_numbers() {
    assert_eq!(MIN_LARGE_HISTORY_COMMITS, 100_000u64);
    assert_eq!(MIN_CORPUS_LANGUAGES, 3usize);
    assert_eq!(MIN_REPLAY_COMMITS, 500usize);
    assert_eq!(MAX_MIX_DEVIATION, 0.10);
    assert_eq!(MAX_PRE_RUN_LOAD_PER_CORE, 1.0);
}

#[test]
fn committed_manifest_parses_like_an_independent_reader_and_lints_clean() {
    let text = fixture_text("corpus_manifest.toml");
    let manifest = CorpusManifest::from_toml_str(&text).expect("the committed manifest parses");
    let tables = read_tables(&text);
    let raw_repos = tables_named(&tables, "repo");
    assert_eq!(manifest.repos.len(), raw_repos.len());
    for (parsed, raw) in manifest.repos.iter().zip(raw_repos.iter()) {
        assert_eq!(parsed.name, raw.str("name"));
        assert_eq!(parsed.url, raw.str("url"));
        assert_eq!(parsed.language, raw.str("language"));
        assert_eq!(parsed.commit_sha, raw.str("commit_sha"));
        assert_eq!(i64::try_from(parsed.commit_count).ok(), Some(raw.int("commit_count")));
        assert_eq!(parsed.synthetic, raw.bool_("synthetic"));
    }

    let report = lint_corpus(&manifest);
    assert_eq!(report.exit_code(), 0, "violations: {:?}", report.violations);
    assert!(report.violations.is_empty());
    assert_eq!(lint_corpus_toml(&text).exit_code(), 0);

    // Facts about the committed corpus itself, so the fixture cannot be thinned.
    let languages: BTreeSet<String> = manifest
        .repos
        .iter()
        .map(|r| r.language.to_ascii_lowercase())
        .collect();
    assert!(languages.contains("go") && languages.contains("typescript") && languages.contains("python"));
    assert!(manifest.repos.iter().any(|r| r.commit_count >= MIN_LARGE_HISTORY_COMMITS));
    for repo in &manifest.repos {
        assert!(!repo.synthetic, "{} must be a real repository", repo.name);
        assert!(is_lower_hex(&repo.commit_sha, 40), "{} must be pinned by commit id", repo.name);
        assert!(repo.url.starts_with("https://"), "{} must be listed by URL", repo.name);
    }
}

#[test]
fn corpus_lint_cases_match_the_expected_exit_and_violation_kinds() {
    let base = load_manifest();
    let tables = read_tables(&fixture_text("lint_cases.toml"));
    let cases = tables_named(&tables, "corpus_case");
    assert!(cases.len() >= 15, "lint_cases.toml lost corpus cases: {}", cases.len());

    let mut seen_kinds: BTreeSet<String> = BTreeSet::new();
    for case in cases {
        let name = case.str("name");
        let mut manifest = base.clone();
        for entry in case.list("mutate") {
            apply_mutation(&mut manifest, entry);
        }
        let report = lint_corpus(&manifest);
        let want_exit = case.int("expect_exit");
        assert_eq!(
            i64::from(report.exit_code()),
            want_exit,
            "case {name}: exit code, violations {:?}",
            report.violations
        );
        assert_eq!(
            report.violations.is_empty(),
            want_exit == 0,
            "case {name}: the lint exits 0 exactly when it finds nothing"
        );
        let want_kinds: Vec<String> = case.list("expect_kinds").to_vec();
        let got_kinds: Vec<String> = kinds_of(&report).into_iter().map(String::from).collect();
        assert_eq!(got_kinds, want_kinds, "case {name}: violation kinds");
        if let Some(repo) = case.opt_str("expect_repo") {
            let named: Vec<&str> = report.violations.iter().filter_map(|v| v.repo()).collect();
            assert!(
                !named.is_empty() && named.iter().all(|n| *n == repo),
                "case {name}: per-repository violations must name {repo}, got {named:?}"
            );
        }
        seen_kinds.extend(got_kinds);
    }
    for kind in ["unpinned_repo", "synthetic_repo", "no_large_history", "too_few_languages"] {
        assert!(
            seen_kinds.contains(kind),
            "lint_cases.toml no longer exercises {kind}"
        );
    }
}

#[test]
fn malformed_manifests_are_reported_as_malformed_and_never_exit_zero() {
    let good = fixture_text("corpus_manifest.toml");
    let kubernetes_pin = "commit_sha = \"d285472482503c249133440979b51e49949030ea\"\n";
    let variants: Vec<(&str, String)> = vec![
        ("commit_sha omitted", good.replacen(kubernetes_pin, "", 1)),
        (
            "commit_count is not a number",
            good.replacen("commit_count = 142463", "commit_count = \"many\"", 1),
        ),
        ("synthetic omitted", good.replacen("synthetic = false\n", "", 1)),
        ("not a manifest at all", "this is { not toml".to_string()),
    ];
    for (what, text) in variants {
        assert_ne!(text, good, "{what}: the variant must differ from the good manifest");
        assert!(
            CorpusManifest::from_toml_str(&text).is_err(),
            "{what}: the parser must refuse it"
        );
        let report = lint_corpus_toml(&text);
        assert_eq!(report.exit_code(), 1, "{what}");
        assert_eq!(kinds_of(&report), vec!["malformed_manifest"], "{what}");
    }
}

#[test]
fn cli_corpus_lint_exits_zero_only_for_a_clean_manifest() {
    let scratch = Scratch::new("corpus-lint");
    let good_path = fixture_dir().join("corpus_manifest.toml");
    let good = run_inr(
        scratch.path(),
        &["bench", "corpus-lint", "--manifest", good_path.to_str().expect("utf-8 path")],
    );
    assert_eq!(good.status.code(), Some(0), "clean manifest: {}", combined_output(&good));

    let unpinned = fixture_text("corpus_manifest.toml").replacen(
        "commit_sha = \"d285472482503c249133440979b51e49949030ea\"",
        "commit_sha = \"master\"",
        1,
    );
    let bad_path = scratch.path().join("unpinned.toml");
    fs::write(&bad_path, unpinned).expect("write the unpinned manifest");
    let bad = run_inr(
        scratch.path(),
        &["bench", "corpus-lint", "--manifest", bad_path.to_str().expect("utf-8 path")],
    );
    assert_eq!(bad.status.code(), Some(1), "unpinned manifest: {}", combined_output(&bad));
    let text = combined_output(&bad);
    assert!(text.contains("unpinned_repo"), "the output must name the violation: {text}");
    assert!(text.contains("kubernetes"), "the output must name the repository: {text}");

    let missing_path = scratch.path().join("absent.toml");
    let missing = run_inr(
        scratch.path(),
        &["bench", "corpus-lint", "--manifest", missing_path.to_str().expect("utf-8 path")],
    );
    let code = missing.status.code();
    assert!(
        matches!(code, Some(c) if c != 0 && c != 101),
        "a missing manifest must be refused with an ordinary error exit, got {code:?}"
    );
}

#[test]
#[ignore = "needs network access to the pinned public remotes"]
fn real_corpus_pins_resolve_on_the_remote() {
    let manifest = load_manifest();
    for repo in &manifest.repos {
        let scratch = Scratch::new("pin");
        run_git(scratch.path(), &["init", "--quiet"]);
        run_git(
            scratch.path(),
            &["fetch", "--quiet", "--depth", "1", repo.url.as_str(), repo.commit_sha.as_str()],
        );
        let fetched = run_git(scratch.path(), &["rev-parse", "FETCH_HEAD"]);
        assert_eq!(
            fetched.trim(),
            repo.commit_sha,
            "{} must fetch back as its pinned commit",
            repo.name
        );
    }
}

fn run_git(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("git must run");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

// ---------------------------------------------------------------------------
// Clause 2: the runner refuses a loaded host
// ---------------------------------------------------------------------------

struct FixedLoad {
    load_1m: f64,
    logical_cores: u32,
    calls: Cell<u32>,
}

impl FixedLoad {
    fn new(load_1m: f64, logical_cores: u32) -> Self {
        FixedLoad {
            load_1m,
            logical_cores,
            calls: Cell::new(0),
        }
    }
}

impl LoadSource for FixedLoad {
    fn sample(&self) -> HostLoad {
        self.calls.set(self.calls.get() + 1);
        HostLoad {
            load_1m: self.load_1m,
            logical_cores: self.logical_cores,
        }
    }
}

struct ScriptedExecutor {
    script: Vec<RunObservation>,
    calls: Vec<u32>,
}

impl ScriptedExecutor {
    fn new(script: Vec<RunObservation>) -> Self {
        ScriptedExecutor {
            script,
            calls: Vec::new(),
        }
    }
}

impl RunExecutor for ScriptedExecutor {
    fn execute(&mut self, _cell: &CellSpec, run_index: u32) -> RunObservation {
        self.calls.push(run_index);
        self.script[run_index as usize].clone()
    }
}

fn ci(key: &str, runner: &str, passed: bool, cpu_ms: u64) -> CiRun {
    CiRun {
        key: key.to_string(),
        runner: runner.to_string(),
        cpu_ms,
        passed,
    }
}

/// Submission `i` is assigned its position `i + 1` ms after it was submitted
/// and, for the first eight only, reaches state `i + 11` ms after it.
fn landing(i: u64) -> LandingSample {
    LandingSample {
        submit_ms: i * 1_000,
        position_ms: Some(i * 1_000 + i + 1),
        state_ms: if i < 8 { Some(i * 1_000 + i + 11) } else { None },
    }
}

fn quiet_observation() -> RunObservation {
    RunObservation {
        exit_code: 0,
        stderr: String::new(),
        window_ms: 10_000,
        model_active_ms: vec![60_000, 90_000, 30_000],
        broken_base_intervals_ms: vec![
            (300_000, 330_000),
            (0, 60_000),
            (30_000, 120_000),
            (120_000, 150_000),
        ],
        ci_runs: vec![
            ci("k1", "r1", true, 3_000),
            ci("k1", "r2", true, 4_000),
            ci("k2", "r1", true, 2_000),
            ci("k2", "r1", true, 2_000),
            ci("k3", "r1", true, 1_000),
            ci("k4", "r1", true, 500),
            ci("k4", "r2", false, 500),
        ],
        landings: (0..10u64).map(landing).collect(),
    }
}

fn failed_observation() -> RunObservation {
    RunObservation {
        exit_code: 7,
        stderr: "error: base \"main\" moved, retry\nsecond line, with comma".to_string(),
        window_ms: 0,
        model_active_ms: Vec::new(),
        broken_base_intervals_ms: Vec::new(),
        ci_runs: Vec::new(),
        landings: Vec::new(),
    }
}

#[test]
fn pre_run_load_of_one_per_core_or_more_aborts() {
    assert_eq!(HostLoad { load_1m: 6.0, logical_cores: 8 }.per_core(), 0.75);

    let table: [(f64, u32, bool); 11] = [
        (0.0, 8, false),
        (0.99, 1, false),
        (7.99, 8, false),
        (3.9, 4, false),
        (1.0, 1, true),
        (8.0, 8, true),
        (8.01, 8, true),
        (4.0, 4, true),
        (f64::NAN, 8, true),
        (f64::INFINITY, 8, true),
        (0.0, 0, true),
    ];
    for (load_1m, logical_cores, aborts) in table {
        let result = preflight(&HostLoad { load_1m, logical_cores });
        assert_eq!(
            result.is_err(),
            aborts,
            "load {load_1m} on {logical_cores} cores: abort expected = {aborts}"
        );
    }

    match preflight(&HostLoad { load_1m: 8.0, logical_cores: 8 }) {
        Err(CellAbort::LoadTooHigh { load_1m, logical_cores }) => {
            assert_eq!(load_1m, 8.0);
            assert_eq!(logical_cores, 8);
        }
        other => panic!("a saturated host must abort with LoadTooHigh, got {other:?}"),
    }
}

#[test]
fn loaded_host_aborts_the_cell_before_any_run_starts() {
    let load = FixedLoad::new(8.0, 8);
    let mut executor = ScriptedExecutor::new(vec![quiet_observation(); 3]);
    let cell = CellSpec {
        cell_id: "cell-a".to_string(),
        runs: 3,
    };
    let outcome = run_cell(&cell, &load, &mut executor);
    assert!(
        matches!(outcome, Err(CellAbort::LoadTooHigh { .. })),
        "a host at one per core must abort the cell"
    );
    assert!(executor.calls.is_empty(), "no run may start on a loaded host");
    assert_eq!(load.calls.get(), 1, "the load is sampled once, before the first run");
}

#[test]
fn quiet_host_runs_every_run_once_in_order() {
    let load = FixedLoad::new(0.5, 8);
    let mut executor = ScriptedExecutor::new(vec![
        quiet_observation(),
        failed_observation(),
        quiet_observation(),
    ]);
    let cell = CellSpec {
        cell_id: "cell-a".to_string(),
        runs: 3,
    };
    let records = run_cell(&cell, &load, &mut executor).expect("a quiet host runs the cell");
    assert_eq!(executor.calls, vec![0, 1, 2]);
    assert_eq!(load.calls.get(), 1);
    let exit_codes: Vec<i32> = records.iter().map(|r| r.observation.exit_code).collect();
    assert_eq!(exit_codes, vec![0, 7, 0], "a failing run is recorded, never an abort");
    let indexes: Vec<u32> = records.iter().map(|r| r.run_index).collect();
    assert_eq!(indexes, vec![0, 1, 2]);
}

// ---------------------------------------------------------------------------
// Clause 3: dry run and the per-run CSV
// ---------------------------------------------------------------------------

#[test]
fn csv_header_is_frozen() {
    assert_eq!(RUN_CSV_HEADER, RUN_CSV_COLUMNS.join(","));
    for term in TERM_COLUMNS {
        assert!(RUN_CSV_COLUMNS.contains(term));
    }
}

#[test]
fn dry_run_writes_one_csv_row_per_run_with_exit_code_stderr_and_every_term() {
    let scratch = Scratch::new("dry-run");
    let csv_path = scratch.path().join("runs.csv");
    let cell = CellSpec {
        cell_id: "dry-cell".to_string(),
        runs: 3,
    };
    let quiet = FixedLoad::new(0.5, 8);
    let records = dry_run(&cell, &quiet, &csv_path).expect("a quiet host dry run succeeds");
    assert_eq!(records.len(), 3);
    assert_eq!(quiet.calls.get(), 1);

    let text = fs::read_to_string(&csv_path).expect("the dry run writes its CSV");
    assert_eq!(text.lines().next(), Some(RUN_CSV_HEADER));
    let rows = parse_csv(&text);
    assert_eq!(rows.len(), 4, "one header row and one row per run");
    let header = &rows[0];
    assert_eq!(header.len(), RUN_CSV_COLUMNS.len());
    for (i, row) in rows.iter().enumerate().skip(1) {
        assert_eq!(row.len(), RUN_CSV_COLUMNS.len(), "row {i} width");
        assert_eq!(row[column(header, "cell_id")], "dry-cell");
        assert_eq!(row[column(header, "run_index")], (i - 1).to_string());
        assert_eq!(row[column(header, "exit_code")], "0");
        assert_eq!(row[column(header, "stderr")], "");
        for term in TERM_COLUMNS {
            let value = number(header, row, term);
            assert!(value.is_finite() && value >= 0.0, "row {i} {term} = {value}");
        }
        assert!(
            number(header, row, "time_to_state_p50_ms")
                > number(header, row, "time_to_position_p50_ms"),
            "row {i}: state is reached after the position is assigned"
        );
    }

    let second_path = scratch.path().join("again.csv");
    dry_run(&cell, &FixedLoad::new(0.5, 8), &second_path).expect("a second dry run succeeds");
    assert_eq!(
        fs::read(&csv_path).expect("first CSV"),
        fs::read(&second_path).expect("second CSV"),
        "a dry run is repeatable byte for byte"
    );
}

#[test]
fn aborted_dry_run_writes_no_csv() {
    let scratch = Scratch::new("dry-abort");
    let csv_path = scratch.path().join("runs.csv");
    let cell = CellSpec {
        cell_id: "dry-cell".to_string(),
        runs: 3,
    };
    let err = dry_run(&cell, &FixedLoad::new(16.0, 8), &csv_path)
        .expect_err("a loaded host must abort the dry run");
    assert!(
        matches!(err, BenchRunError::Aborted(CellAbort::LoadTooHigh { .. })),
        "got {err:?}"
    );
    assert!(!csv_path.exists(), "an aborted cell leaves no measurements behind");
}

#[test]
fn csv_records_exit_codes_and_stderr_exactly_and_never_prints_nan() {
    let load = FixedLoad::new(0.5, 8);
    let mut executor = ScriptedExecutor::new(vec![
        quiet_observation(),
        failed_observation(),
        quiet_observation(),
    ]);
    let cell = CellSpec {
        cell_id: "cell-a".to_string(),
        runs: 3,
    };
    let records = run_cell(&cell, &load, &mut executor).expect("a quiet host runs the cell");
    let csv = render_run_csv(&cell.cell_id, &records);
    assert!(csv.ends_with('\n'));

    let rows = parse_csv(&csv);
    assert_eq!(rows.len(), 4);
    let header = &rows[0];
    assert_eq!(header.iter().map(String::as_str).collect::<Vec<_>>(), RUN_CSV_COLUMNS);
    for row in rows.iter().skip(1) {
        for term in TERM_COLUMNS {
            let field = row[column(header, term)].to_ascii_lowercase();
            assert!(
                !matches!(field.as_str(), "nan" | "inf" | "-inf" | "infinity" | "-infinity"),
                "{term} must be a number or empty, got {field:?}"
            );
        }
    }

    let failed = &rows[2];
    assert_eq!(failed[column(header, "run_index")], "1");
    assert_eq!(failed[column(header, "exit_code")], "7");
    assert_eq!(
        failed[column(header, "stderr")],
        "error: base \"main\" moved, retry\nsecond line, with comma",
        "stderr survives quoting exactly"
    );
    for term in ["model_minutes", "broken_base_minutes", "ci_compute_seconds", "landings_per_min", "ingest_land_per_sec"] {
        assert_eq!(number(header, failed, term), 0.0, "{term} of a run that measured nothing");
    }
    for term in [
        "time_to_position_p50_ms",
        "time_to_position_p99_ms",
        "time_to_state_p50_ms",
        "time_to_state_p99_ms",
    ] {
        assert_eq!(failed[column(header, term)], "", "{term} has no samples to rank");
    }

    for (row, index) in [(&rows[1], "0"), (&rows[3], "2")] {
        assert_eq!(row[column(header, "cell_id")], "cell-a");
        assert_eq!(row[column(header, "run_index")], index);
        assert_eq!(row[column(header, "exit_code")], "0");
        assert_eq!(row[column(header, "stderr")], "");
        assert_close(number(header, row, "model_minutes"), 3.0, "model_minutes");
        assert_close(number(header, row, "broken_base_minutes"), 3.0, "broken_base_minutes");
        assert_close(number(header, row, "ci_compute_seconds"), 13.0, "ci_compute_seconds");
        assert_close(number(header, row, "ci_keys_green"), 1.0, "ci_keys_green");
        assert_close(number(header, row, "ci_keys_not_green"), 3.0, "ci_keys_not_green");
        assert_close(number(header, row, "landings_per_min"), 48.0, "landings_per_min");
        assert_close(number(header, row, "ingest_land_per_sec"), 1.0, "ingest_land_per_sec");
        assert_close(number(header, row, "time_to_position_p50_ms"), 5.0, "position p50");
        assert_close(number(header, row, "time_to_position_p99_ms"), 10.0, "position p99");
        assert_close(number(header, row, "time_to_state_p50_ms"), 14.0, "state p50");
        assert_close(number(header, row, "time_to_state_p99_ms"), 18.0, "state p99");
    }
}

// ---------------------------------------------------------------------------
// Clauses 3 and 4: the four cost terms
// ---------------------------------------------------------------------------

#[test]
fn model_minutes_sum_the_model_active_time() {
    let metrics = compute_run_metrics(&quiet_observation());
    assert_close(metrics.model_minutes, 3.0, "60 s + 90 s + 30 s of model time");
}

#[test]
fn broken_base_minutes_count_overlapping_time_once() {
    // The intervals are unsorted on purpose. Their union is [0, 150000) plus
    // [300000, 330000) = 180000 ms; adding the lengths instead would give 210000.
    let metrics = compute_run_metrics(&quiet_observation());
    assert_close(metrics.broken_base_minutes, 3.0, "union of broken-base intervals");
}

#[test]
fn ci_compute_counts_every_run_and_green_needs_two_passes_from_distinct_runners() {
    let metrics = compute_run_metrics(&quiet_observation());
    assert_close(metrics.ci_compute_seconds, 13.0, "every run is paid for, passed or not");
    assert_eq!(metrics.ci_keys_green, 1, "only k1 has two passes on two runners");
    assert_eq!(
        metrics.ci_keys_not_green, 3,
        "k2 passed twice on one runner, k3 once, k4 passed once and failed once"
    );
}

#[test]
fn percentiles_use_the_nearest_rank_rule() {
    let hundred: Vec<f64> = (1..=100).map(|n| n as f64).collect();
    assert_eq!(percentile_nearest_rank(&hundred, 50.0), Some(50.0));
    assert_eq!(percentile_nearest_rank(&hundred, 99.0), Some(99.0));
    assert_eq!(percentile_nearest_rank(&hundred, 100.0), Some(100.0));

    let ten_unsorted: Vec<f64> = (1..=10).rev().map(|n| n as f64).collect();
    assert_eq!(percentile_nearest_rank(&ten_unsorted, 50.0), Some(5.0));
    assert_eq!(percentile_nearest_rank(&ten_unsorted, 99.0), Some(10.0));

    assert_eq!(percentile_nearest_rank(&[7.0], 50.0), Some(7.0));
    assert_eq!(percentile_nearest_rank(&[7.0], 99.0), Some(7.0));
    assert_eq!(percentile_nearest_rank(&[], 50.0), None);
}

#[test]
fn submission_ingest_is_a_separate_term_from_landings_per_minute() {
    let metrics = compute_run_metrics(&quiet_observation());
    assert_close(
        metrics.ingest_land_per_sec,
        1.0,
        "10 submissions were assigned a position over a 10 s window",
    );
    assert_close(
        metrics.landings_per_min,
        48.0,
        "only 8 submissions reached state over the same 10 s window",
    );
    assert_ne!(
        metrics.ingest_land_per_sec * 60.0,
        metrics.landings_per_min,
        "ingest and landings per minute are different measurements"
    );

    // A submission that was never assigned a position is not ingest.
    let mut with_refused = quiet_observation();
    with_refused.landings.push(LandingSample { submit_ms: 9_500, position_ms: None, state_ms: None });
    with_refused.landings.push(LandingSample { submit_ms: 9_600, position_ms: None, state_ms: None });
    let again = compute_run_metrics(&with_refused);
    assert_close(again.ingest_land_per_sec, 1.0, "refused submissions add no ingest");
    assert_close(again.landings_per_min, 48.0, "refused submissions add no landings");
}

#[test]
fn time_to_position_and_time_to_state_are_ranked_separately() {
    let metrics = compute_run_metrics(&quiet_observation());
    // Position latencies are 1..=10 ms over ten samples; state latencies are
    // 11..=18 ms over the eight samples that reached state.
    assert_eq!(metrics.time_to_position_p50_ms, Some(5.0));
    assert_eq!(metrics.time_to_position_p99_ms, Some(10.0));
    assert_eq!(metrics.time_to_state_p50_ms, Some(14.0));
    assert_eq!(metrics.time_to_state_p99_ms, Some(18.0));
    assert_ne!(metrics.time_to_position_p50_ms, metrics.time_to_state_p50_ms);
    assert_ne!(metrics.time_to_position_p99_ms, metrics.time_to_state_p99_ms);
}

#[test]
fn a_run_that_measured_nothing_has_zero_rates_and_no_percentiles() {
    let metrics = compute_run_metrics(&failed_observation());
    assert_eq!(metrics.model_minutes, 0.0);
    assert_eq!(metrics.broken_base_minutes, 0.0);
    assert_eq!(metrics.ci_compute_seconds, 0.0);
    assert_eq!(metrics.ci_keys_green, 0);
    assert_eq!(metrics.ci_keys_not_green, 0);
    assert_eq!(metrics.landings_per_min, 0.0);
    assert_eq!(metrics.ingest_land_per_sec, 0.0);
    assert_eq!(metrics.time_to_position_p50_ms, None);
    assert_eq!(metrics.time_to_state_p99_ms, None);

    let mut open_window = failed_observation();
    open_window.window_ms = 10_000;
    let metrics = compute_run_metrics(&open_window);
    assert_eq!(metrics.landings_per_min, 0.0);
    assert_eq!(metrics.ingest_land_per_sec, 0.0);
}

// ---------------------------------------------------------------------------
// Clause 5: the replay mix
// ---------------------------------------------------------------------------

const REF_COMMIT_SIZE: [f64; 3] = [8.916666666666666, 361.75, 20867.166666666668];
const REF_FILE_OVERLAP: [f64; 3] = [0.14027777777777778, 0.08467592592592593, 0.06196141975308642];
const REF_TOUCH_RATE: [f64; 3] = [0.042868589743589786, 0.0018863514957264905, 8.694466702279198e-05];

fn load_sample() -> WorkloadSample {
    WorkloadSample::from_json_str(&fixture_text("workload_sample.json"))
        .expect("the recorded sample parses")
}

fn commit(id: &str, files: &[u64]) -> SampledCommit {
    SampledCommit {
        id: id.to_string(),
        lines: 1,
        files: files.to_vec(),
    }
}

fn uniform_history(count: usize, files_per_commit: usize) -> Vec<SampledCommit> {
    (0..count)
        .map(|i| SampledCommit {
            id: format!("{i:040x}"),
            lines: 10,
            files: (0..files_per_commit)
                .map(|k| (i * files_per_commit + k) as u64 + 1)
                .collect(),
        })
        .collect()
}

fn assert_moments(actual: Moments, expected: [f64; 3], what: &str) {
    assert_close(actual.m1, expected[0], &format!("{what} m1"));
    assert_close(actual.m2, expected[1], &format!("{what} m2"));
    assert_close(actual.m3, expected[2], &format!("{what} m3"));
}

fn moment_value(mix: &MixMoments, distribution: &str, moment: u8) -> f64 {
    let m = match distribution {
        "commit_size" => mix.commit_size,
        "file_overlap" => mix.file_overlap,
        "touch_rate" => mix.touch_rate,
        other => panic!("unknown distribution {other}"),
    };
    match moment {
        1 => m.m1,
        2 => m.m2,
        3 => m.m3,
        other => panic!("unknown moment {other}"),
    }
}

fn with_moment(mix: &MixMoments, distribution: &str, moment: u8, value: f64) -> MixMoments {
    let mut out = *mix;
    let target = match distribution {
        "commit_size" => &mut out.commit_size,
        "file_overlap" => &mut out.file_overlap,
        "touch_rate" => &mut out.touch_rate,
        other => panic!("unknown distribution {other}"),
    };
    match moment {
        1 => target.m1 = value,
        2 => target.m2 = value,
        3 => target.m3 = value,
        other => panic!("unknown moment {other}"),
    }
    out
}

fn labels(report: &MixLintReport) -> Vec<String> {
    report.violations.iter().map(MomentDeviation::label).collect()
}

#[test]
fn recorded_sample_parses_and_matches_what_was_recorded() {
    let text = fixture_text("workload_sample.json");
    let sample = load_sample();
    assert_eq!(sample.commits.len(), 24);
    assert_eq!(text.matches("\"id\": \"").count(), sample.commits.len());
    let file_refs: usize = sample.commits.iter().map(|c| c.files.len()).sum();
    assert_eq!(file_refs, 214);
    assert_eq!(sample.commits[0].id, "ee58415993a418d368f6d09b600bfc2c4a2bad4e");
    assert_eq!(sample.commits[0].files.len(), 59);
    assert_eq!(sample.commits[0].lines, 179);
    assert_eq!(sample.commits[4].files.len(), 65);
    assert_eq!(sample.commits[23].id, "8d091db4aaa612f724b7409c77903042e4ecd6f4");
    assert_eq!(sample.commits[23].files, vec![1667441769, 703112774, 1116904730]);
    assert_eq!(sample.source_url, "https://github.com/kubernetes/kubernetes.git");
    assert!(is_lower_hex(&sample.source_commit_sha, 40));

    for bad in ["{ not json", "{\"source\": {\"url\": \"u\", \"commit_sha\": \"s\"}}", ""] {
        assert!(WorkloadSample::from_json_str(bad).is_err(), "must refuse {bad:?}");
    }
}

#[test]
fn sample_is_pinned_by_the_committed_corpus_and_a_moved_pin_is_refused() {
    let sample = load_sample();
    let manifest = load_manifest();
    assert!(sample.is_pinned_by(&manifest));

    let at = manifest
        .repos
        .iter()
        .position(|r| r.url == sample.source_url)
        .expect("the sample's repository is listed in the corpus manifest");
    assert_eq!(manifest.repos[at].commit_sha, sample.source_commit_sha);

    let mut moved = manifest.clone();
    moved.repos[at].commit_sha = "0123456789abcdef0123456789abcdef01234567".to_string();
    assert!(!sample.is_pinned_by(&moved), "a sample from a different commit is not pinned");

    let mut absent = manifest.clone();
    absent.repos.remove(at);
    assert!(!sample.is_pinned_by(&absent), "a sample from an unlisted repository is not pinned");
}

#[test]
fn measured_moments_match_values_computed_independently_from_the_sample() {
    let measured = measure_mix(&load_sample().commits);
    assert_moments(measured.commit_size, REF_COMMIT_SIZE, "commit_size");
    assert_moments(measured.file_overlap, REF_FILE_OVERLAP, "file_overlap");
    assert_moments(measured.touch_rate, REF_TOUCH_RATE, "touch_rate");
}

#[test]
fn measure_matches_hand_computed_moments() {
    // c1 = {1, 2} (file 2 listed twice), c2 = {2, 3}, c3 = {4}.
    let batch = [commit("c1", &[1, 2, 2]), commit("c2", &[2, 3]), commit("c3", &[4])];
    let mix = measure_mix(&batch);
    assert_moments(mix.commit_size, [5.0 / 3.0, 3.0, 17.0 / 3.0], "size");
    assert_moments(mix.file_overlap, [1.0 / 3.0, 1.0 / 6.0, 1.0 / 12.0], "overlap");
    assert_moments(mix.touch_rate, [5.0 / 12.0, 7.0 / 36.0, 11.0 / 108.0], "touch");

    // A commit that touches nothing has size 0 and overlap 0.
    let with_empty = [commit("c1", &[1, 2]), commit("c2", &[2, 3]), commit("c3", &[])];
    let mix = measure_mix(&with_empty);
    assert_moments(mix.commit_size, [4.0 / 3.0, 8.0 / 3.0, 16.0 / 3.0], "size");
    assert_moments(mix.file_overlap, [1.0 / 3.0, 1.0 / 6.0, 1.0 / 12.0], "overlap");
    assert_moments(mix.touch_rate, [4.0 / 9.0, 2.0 / 9.0, 10.0 / 81.0], "touch");
}

#[test]
fn mix_is_invariant_to_commit_order_and_file_naming() {
    let sample = load_sample();
    let reference = measure_mix(&sample.commits);
    let mut shuffled: Vec<SampledCommit> = sample.commits.iter().rev().cloned().collect();
    for c in &mut shuffled {
        c.id.push_str("-replayed");
        c.files = c.files.iter().map(|f| f + 1_000_000_000_000).collect();
    }
    let report = lint_mix_moments(&reference, &measure_mix(&shuffled));
    assert_eq!(report.deviations.len(), 9);
    for deviation in &report.deviations {
        assert!(
            deviation.relative <= 1e-9,
            "{} moved by {} under a pure renaming and reordering",
            deviation.label(),
            deviation.relative
        );
    }
}

#[test]
fn mix_lint_boundary_is_exactly_ten_percent_on_every_moment() {
    let reference = MixMoments {
        commit_size: Moments { m1: 10.0, m2: 100.0, m3: 1000.0 },
        file_overlap: Moments { m1: 20.0, m2: 200.0, m3: 2000.0 },
        touch_rate: Moments { m1: 40.0, m2: 400.0, m3: 4000.0 },
    };
    let identical = lint_mix_moments(&reference, &reference);
    assert_eq!(identical.deviations.len(), 9);
    assert!(identical.violations.is_empty());
    assert_eq!(identical.exit_code(), 0);

    for distribution in ["commit_size", "file_overlap", "touch_rate"] {
        for moment in 1..=3u8 {
            let r = moment_value(&reference, distribution, moment);
            let what = format!("{distribution}:{moment}");

            // Exactly 10% high and 10% low is accepted: the rule is "more than".
            for edge in [r + r / 10.0, r - r / 10.0] {
                let cell = with_moment(&reference, distribution, moment, edge);
                let report = lint_mix_moments(&reference, &cell);
                assert!(report.violations.is_empty(), "{what}: {edge} is within 10% of {r}");
                assert_eq!(report.exit_code(), 0, "{what}: {edge}");
            }

            // 10.1% either way is rejected, and only on that moment.
            for beyond in [r * 1.101, r * 0.899] {
                let cell = with_moment(&reference, distribution, moment, beyond);
                let report = lint_mix_moments(&reference, &cell);
                assert_eq!(labels(&report), vec![what.clone()], "{what}: {beyond} vs {r}");
                assert_eq!(report.exit_code(), 1, "{what}: {beyond}");
                let violation = &report.violations[0];
                assert_eq!(violation.reference, r);
                assert_eq!(violation.cell, beyond);
                assert!(violation.relative > MAX_MIX_DEVIATION);
            }
        }
    }
}

#[test]
fn mix_lint_with_a_zero_reference_accepts_only_zero() {
    let zero = Moments { m1: 0.0, m2: 0.0, m3: 0.0 };
    let reference = MixMoments { commit_size: zero, file_overlap: zero, touch_rate: zero };
    assert_eq!(lint_mix_moments(&reference, &reference).exit_code(), 0);

    let cell = with_moment(&reference, "file_overlap", 1, 0.5);
    let report = lint_mix_moments(&reference, &cell);
    assert_eq!(labels(&report), vec!["file_overlap:1".to_string()]);
    assert_eq!(report.violations[0].relative, f64::INFINITY);
}

#[test]
fn mix_cases_from_the_recorded_sample_are_judged_as_recorded() {
    let sample = load_sample();
    let reference = measure_mix(&sample.commits);
    let tables = read_tables(&fixture_text("lint_cases.toml"));
    let cases = tables_named(&tables, "mix_case");
    assert!(cases.len() >= 4, "lint_cases.toml lost mix cases: {}", cases.len());

    for case in cases {
        let name = case.str("name");
        let drop: BTreeSet<usize> = case
            .list("drop")
            .iter()
            .map(|s| s.parse().expect("drop indexes are numbers"))
            .collect();
        let kept: Vec<SampledCommit> = sample
            .commits
            .iter()
            .enumerate()
            .filter(|(i, _)| !drop.contains(i))
            .map(|(_, c)| c.clone())
            .collect();
        assert_eq!(kept.len(), sample.commits.len() - drop.len(), "case {name}");

        let report = lint_cell_mix(&reference, &kept);
        assert_eq!(report.deviations.len(), 9, "case {name}");
        let mut got = labels(&report);
        got.sort();
        let mut want: Vec<String> = case.list("expect_violations").to_vec();
        want.sort();
        assert_eq!(got, want, "case {name}: moments past 10%");
        assert_eq!(
            report.exit_code(),
            if want.is_empty() { 0 } else { 1 },
            "case {name}: exit code"
        );

        if let Some(pins) = case.opt_list("expect_relative") {
            for pin in pins {
                let (label, expected) = pin
                    .split_once('=')
                    .unwrap_or_else(|| panic!("case {name}: pin {pin:?} is not <label>=<value>"));
                let expected: f64 = expected
                    .parse()
                    .unwrap_or_else(|_| panic!("case {name}: pin {pin:?} has no number"));
                let found = report
                    .deviations
                    .iter()
                    .find(|d| d.label() == label)
                    .unwrap_or_else(|| panic!("case {name}: no deviation labelled {label}"));
                assert_close(found.relative, expected, &format!("case {name}: {label}"));
            }
        }
    }
}

#[test]
fn a_uniform_cell_is_rejected_on_every_distribution() {
    let sample = load_sample();
    let reference = measure_mix(&sample.commits);
    // Five hundred commits that each touch three files nobody else touches:
    // equal sizes, no overlap and an even touch rate.
    let uniform = uniform_history(500, 3);
    let report = lint_cell_mix(&reference, &uniform);
    assert_eq!(report.exit_code(), 1);
    assert_eq!(report.violations.len(), 9, "violations: {:?}", labels(&report));
    let distributions: BTreeSet<&str> = report.violations.iter().map(|v| v.distribution).collect();
    assert_eq!(
        distributions.into_iter().collect::<Vec<_>>(),
        vec!["commit_size", "file_overlap", "touch_rate"]
    );
}

#[test]
fn the_reference_sample_is_not_itself_uniform() {
    let measured = measure_mix(&load_sample().commits);
    let size = measured.commit_size;
    assert!(size.m2 > 2.0 * size.m1 * size.m1, "commit sizes must be heavy-tailed");
    let overlap = measured.file_overlap;
    assert!(overlap.m2 > 1.5 * overlap.m1 * overlap.m1, "file overlap must vary between commits");
    assert!(overlap.m1 > 0.0, "some commits must overlap others");
}

#[test]
fn replay_cell_takes_at_least_five_hundred_commits_from_one_pinned_base() {
    let history = uniform_history(600, 2);
    let base = "d285472482503c249133440979b51e49949030ea";
    let cell = build_replay_cell("replay-a", base, &history, 500)
        .expect("500 commits from a long enough history");
    assert_eq!(cell.cell_id, "replay-a");
    assert_eq!(cell.base_commit, base, "every change replays from this one base");
    assert_eq!(cell.commits.len(), 500);
    assert_eq!(cell.commits[0], history[0]);
    assert_eq!(cell.commits[499], history[499]);

    assert!(build_replay_cell("replay-b", base, &history[..500], 500).is_ok());
    assert!(build_replay_cell("replay-c", base, &history, 499).is_err(), "fewer than 500");
    assert!(build_replay_cell("replay-d", base, &history, 601).is_err(), "more than the history holds");
    assert!(build_replay_cell("replay-e", base, &history[..499], 500).is_err(), "history too short");
    assert!(build_replay_cell("replay-f", "main", &history, 500).is_err(), "a branch is not a base");
    assert!(build_replay_cell("replay-g", "", &history, 500).is_err(), "an empty base");
}

// ---------------------------------------------------------------------------
// Steps that need the network
// ---------------------------------------------------------------------------

#[test]
fn network_steps_name_existing_ignored_tests() {
    let tables = read_tables(&fixture_text("test_code_steps.toml"));
    let steps = tables_named(&tables, "step");
    assert!(steps.len() >= 3, "test_code_steps.toml lost steps: {}", steps.len());
    let source = include_str!("replay_corpus_protocol_test.rs");

    let mut ids = BTreeSet::new();
    let mut clauses = BTreeSet::new();
    for step in steps {
        let id = step.str("id");
        assert!(ids.insert(id.to_string()), "duplicate step id {id}");
        let clause = step.int("clause");
        assert!((1..=5).contains(&clause), "step {id}: clause {clause} is not one of the five");
        clauses.insert(clause);
        assert!(!step.str("command").is_empty(), "step {id}: empty command");
        assert!(!step.str("expect").is_empty(), "step {id}: empty expectation");
        if let Some(test) = step.opt_str("test") {
            assert!(step.str("command").contains(test), "step {id}: the command must run {test}");
            let needle = format!("fn {test}()");
            let at = source
                .find(&needle)
                .unwrap_or_else(|| panic!("step {id}: no test function {test}"));
            let attributes: Vec<&str> = source[..at].lines().rev().take(3).collect();
            assert!(
                attributes.iter().any(|l| l.trim_start().starts_with("#[ignore")),
                "step {id}: {test} must be marked ignored so the offline pass skips it"
            );
        }
    }
    assert!(clauses.contains(&1) && clauses.contains(&5), "network steps back clauses 1 and 5");
}
