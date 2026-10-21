#!/usr/bin/env python3
"""Independent verification of a bench-vs-git.sh results directory.

This is a second implementation of every statistic the benchmark script publishes, written in a
different language so the two cannot share a bug. It re-derives aggregate.csv from the raw per-trial
and per-batch rows, checks the structural invariants a reviewer would otherwise have to trust, and
rescans every file for identifying byte sequences.

    python3 benchmarks/verify-run.py benchmarks/results/<run-id> [more run dirs ...]
    python3 benchmarks/verify-run.py --compare <run-a> <run-b>      # run-to-run p50 agreement
    python3 benchmarks/verify-run.py --forbid <token> ... <run-dir>   # extra identifying tokens
    python3 benchmarks/verify-run.py --require-clean <run-dir>        # also fail on any failed agent or lost update

Verification is about the integrity of the published data: every statistic is recomputed from the raw
rows, every batch has exactly K agent rows, every cell is either measured, recorded as skipped by the
memory-fit guard, or measured for its first trials and recorded as skipped for the rest (with the two
counts adding up to the design), and no file carries an identifying byte sequence. Failed agents (non-zero exit) and
`land` batches with fewer verified changes than K are results about the systems under test, so they are
printed as notes and only fail the run with --require-clean.

Exit status 0 means every check passed for every run directory; 1 otherwise. Standard library only.
"""

from __future__ import annotations

import csv
import json
import math
import re
import sys
from pathlib import Path

PATH_RE = re.compile(r"/(Users|Volumes|home)/[A-Za-z0-9]|C:\\Users\\[A-Za-z0-9]|C:/Users/[A-Za-z0-9]")
ADDR_RE = re.compile(r"(^|[^0-9A-Za-z.])(100\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})")
RAW_FIELDS = ["run_id", "workload", "system", "variant", "k", "trial", "agent", "latency_us", "exit_code", "disk_bytes", "max_rss_kb", "extra", "warmup"]
BATCH_FIELDS = ["run_id", "workload", "system", "variant", "k", "trial", "batch_wall_us", "disk_bytes", "agents_ok", "agents_failed", "extra", "warmup"]
AGG_FIELDS = ["workload", "system", "variant", "k", "samples", "failures", "min_ms", "p50_ms", "mean_ms", "p95_ms", "p99_ms", "max_ms",
              "max_rss_kb_p50", "max_rss_kb_max", "batch_wall_p50_ms", "batch_wall_mean_ms", "disk_bytes_mean", "agents_ok_mean", "trials"]
TOL_MS = 0.0015  # the script prints three decimals; allow one rounding unit


def nearest_rank(sorted_values: list[float], pct: int) -> float:
    n = len(sorted_values)
    rank = -(-pct * n // 100)  # ceil(pct * n / 100)
    rank = min(max(rank, 1), n)
    return sorted_values[rank - 1]


class Report:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.failures: list[str] = []
        self.passes: list[str] = []
        self.notes: list[str] = []

    def check(self, ok: bool, label: str, detail: str = "") -> None:
        if ok:
            self.passes.append(label)
        else:
            self.failures.append(f"{label}: {detail}" if detail else label)

    def note(self, text: str) -> None:
        self.notes.append(text)


def read_csv(path: Path, fields: list[str], rep: Report) -> list[dict[str, str]]:
    with path.open(newline="") as fh:
        reader = csv.DictReader(fh)
        rep.check(reader.fieldnames == fields, f"{path.name} header", f"got {reader.fieldnames}")
        rows = list(reader)
    rep.check(all(len(r) == len(fields) and None not in r.values() for r in rows), f"{path.name} row shape")
    return rows


def group_key(r: dict[str, str]) -> tuple[str, str, str, str]:
    return (r["workload"], r["system"], r["variant"], r["k"])


def verify_run(run_dir: Path, forbid: list[str], require_clean: bool = False) -> Report:
    rep = Report(run_dir)

    def result_check(ok: bool, label: str, detail: str = "") -> None:
        """A fact about the systems under test: a note by default, a failure with --require-clean."""
        if ok:
            rep.passes.append(label)
        elif require_clean:
            rep.failures.append(f"{label}: {detail}" if detail else label)
        else:
            rep.note(f"{label}: {detail}" if detail else label)

    required = ["metadata.json", "raw_trials.csv", "raw_batches.csv", "aggregate.csv", "results.json", "summary.md", "run.log"]
    for name in required:
        rep.check((run_dir / name).is_file(), f"{name} present")
    if rep.failures:
        return rep

    meta = json.loads((run_dir / "metadata.json").read_text())
    run_id = meta.get("run_id", "")
    trials = int(meta["design"]["trials"])
    warmup = int(meta["design"]["warmup_trials"])
    k_levels = [str(k) for k in meta["design"]["concurrency_levels"]]
    rep.check(run_dir.name == run_id, "run_id matches directory name", f"{run_id} vs {run_dir.name}")
    rep.check(meta.get("schema") == "velenza-inarch-bench-vs-git/1", "metadata schema")
    for field in ["os", "kernel", "arch", "cpu_model", "cpu_logical_cores", "mem_total_kb", "mem_cgroup_limit_kb",
                  "mem_available_to_process_kb_at_start", "work_fs_type", "loadavg_1_5_15_at_start", "loadavg_1_5_15_at_end"]:
        rep.check(field in meta["host"] and meta["host"][field] not in ("", None), f"host telemetry {field}")
    for field in ["git_version", "inr_source_rev", "inr_binary_sha256", "bench_script_sha256", "measure_script_sha256",
                  "rustc_version", "bash_version", "python_version"]:
        rep.check(field in meta["toolchain"] and meta["toolchain"][field] not in ("", None, "unknown"), f"toolchain {field}")
    rep.check(int(meta["corpus"]["files"]) >= 100, "corpus file count recorded")
    rep.check(k_levels == sorted(k_levels, key=int), "concurrency levels recorded in ascending order", str(k_levels))
    skipped = meta.get("skipped_cells", [])
    rep.check(isinstance(skipped, list), "skipped_cells is a list")
    skipped_by_key = {(s["workload"], s["system"], s["variant"], str(s["k"])): s for s in skipped}
    skipped_keys = set(skipped_by_key)
    rep.check(len(skipped_by_key) == len(skipped), "each skipped cell is recorded once")
    for s in skipped:
        label = f"skipped cell {s['workload']}/{s['system']}/{s['variant']} k={s['k']}"
        rep.check(int(s["predicted_peak_rss_kb"]) == int(s["k"]) * int(s["peak_rss_kb_basis"]), f"{label} prediction = k x basis")
        rep.check(int(s["predicted_peak_rss_kb"]) * 10 > int(s["available_kb"]) * 9, f"{label} exceeded 90% of available memory")
        rep.check("trials_measured" in s and "trials_skipped" in s and int(s["trials_measured"]) + int(s["trials_skipped"]) == trials,
                  f"{label} trials_measured + trials_skipped = trials", f"{s.get('trials_measured')} + {s.get('trials_skipped')} != {trials}")
        rep.check(0 <= int(s.get("trials_measured", -1)) < trials, f"{label} skipped at least one trial")

    raw = read_csv(run_dir / "raw_trials.csv", RAW_FIELDS, rep)
    batches = read_csv(run_dir / "raw_batches.csv", BATCH_FIELDS, rep)
    agg = read_csv(run_dir / "aggregate.csv", AGG_FIELDS, rep)
    if rep.failures:
        return rep

    rep.check(all(r["run_id"] == run_id for r in raw + batches), "every raw row carries the run_id")
    rep.check(all(r["exit_code"].lstrip("-").isdigit() and r["max_rss_kb"].isdigit() and r["latency_us"].isdigit() for r in raw), "raw numeric fields are integers")
    rep.check(all(int(r["max_rss_kb"]) > 0 for r in raw if r["exit_code"] == "0"), "every successful sample has a positive peak RSS")
    bad = [r for r in raw if r["exit_code"] != "0"]
    result_check(not bad, "every raw trial exited 0", f"{len(bad)} non-zero exit codes: " + ", ".join(sorted({f"{r['workload']}/{r['system']}/{r['variant']} k={r['k']} rc={r['exit_code']}" for r in bad})))
    if warmup > 0:
        rep.check(any(r["warmup"] == "1" for r in raw), "warm-up rows recorded")
    rep.check(all(r["warmup"] in ("0", "1") for r in raw + batches), "warmup flag is 0/1")

    # ---- batch invariants -------------------------------------------------------------------
    for b in batches:
        k = int(b["k"])
        if b["workload"] in ("provision", "land"):
            rep.check(int(b["agents_ok"]) + int(b["agents_failed"]) == k,
                      f"batch {b['workload']}/{b['system']}/{b['variant']} k={k} trial={b['trial']} accounts for every agent",
                      f"agents_ok={b['agents_ok']} agents_failed={b['agents_failed']}")
            result_check(int(b["agents_ok"]) == k,
                         f"batch {b['workload']}/{b['system']}/{b['variant']} k={k} trial={b['trial']} all agents verified",
                         f"agents_ok={b['agents_ok']} agents_failed={b['agents_failed']}" + (" (lost update: a change did not reach the branch head)" if b["workload"] == "land" else ""))
    # raw agents per batch
    per_batch: dict[tuple[str, str, str, str, str], int] = {}
    for r in raw:
        per_batch[(r["workload"], r["system"], r["variant"], r["k"], r["trial"])] = per_batch.get((r["workload"], r["system"], r["variant"], r["k"], r["trial"]), 0) + 1
    for b in batches:
        key = (b["workload"], b["system"], b["variant"], b["k"], b["trial"])
        expected = int(b["k"]) if b["workload"] in ("provision", "land") else 1
        rep.check(per_batch.get(key, 0) == expected, f"raw agent rows for batch {key}", f"{per_batch.get(key, 0)} != {expected}")

    # ---- aggregate recomputation -----------------------------------------------------------
    measured_raw = [r for r in raw if r["warmup"] == "0"]
    measured_batches = [b for b in batches if b["warmup"] == "0"]
    groups: dict[tuple[str, str, str, str], list[dict[str, str]]] = {}
    for r in measured_raw:
        groups.setdefault(group_key(r), []).append(r)
    bgroups: dict[tuple[str, str, str, str], list[dict[str, str]]] = {}
    for b in measured_batches:
        bgroups.setdefault(group_key(b), []).append(b)
    agg_by_key = {group_key(a): a for a in agg}
    rep.check(set(agg_by_key) == set(groups), "aggregate has exactly one row per measured group",
              f"missing={sorted(set(groups) - set(agg_by_key))} extra={sorted(set(agg_by_key) - set(groups))}")
    # a cell the guard stopped after some trials keeps those trials: measured batches = trials_measured, rows iff > 0
    for key, s in sorted(skipped_by_key.items()):
        measured = len(bgroups.get(key, []))
        rep.check(measured == int(s["trials_measured"]), f"{'/'.join(key)} skipped-cell record matches the measured batches",
                  f"trials_measured={s['trials_measured']} batches={measured}")
        rep.check((key in groups) == (measured > 0), f"{'/'.join(key)} carries measured rows only when batches were measured")
        if measured:
            rep.note(f"cell partially measured: {'/'.join(key)}: {measured} of {trials} trials, the rest skipped by the memory-fit guard")
    for key, rows in sorted(groups.items()):
        a = agg_by_key.get(key)
        if a is None:
            continue
        label = "/".join(key)
        n = len(rows)
        k = int(key[3])
        cell_trials = trials - int(skipped_by_key[key]["trials_skipped"]) if key in skipped_by_key else trials
        expected_n = cell_trials * k if key[0] in ("provision", "land") else trials
        rep.check(n == expected_n, f"{label} sample count", f"{n} != {expected_n}")
        rep.check(int(a["samples"]) == n, f"{label} aggregate samples", f"{a['samples']} != {n}")
        good = [r for r in rows if r["exit_code"] == "0"]
        fails = n - len(good)
        rep.check(int(a["failures"]) == fails, f"{label} aggregate failures", f"{a['failures']} != {fails}")
        lat = sorted(int(r["latency_us"]) / 1000.0 for r in good)
        rss = sorted(int(r["max_rss_kb"]) for r in good)
        if good:
            expect = {
                "min_ms": lat[0], "p50_ms": nearest_rank(lat, 50), "mean_ms": sum(lat) / len(lat),
                "p95_ms": nearest_rank(lat, 95), "p99_ms": nearest_rank(lat, 99), "max_ms": lat[-1],
            }
            rep.check(int(a["max_rss_kb_p50"]) == nearest_rank(rss, 50), f"{label} max_rss_kb_p50", f"{a['max_rss_kb_p50']} vs {nearest_rank(rss, 50)}")
            rep.check(int(a["max_rss_kb_max"]) == rss[-1], f"{label} max_rss_kb_max", f"{a['max_rss_kb_max']} vs {rss[-1]}")
        else:
            expect = {c: 0.0 for c in ["min_ms", "p50_ms", "mean_ms", "p95_ms", "p99_ms", "max_ms"]}
            rep.check(a["max_rss_kb_p50"] == "0" and a["max_rss_kb_max"] == "0", f"{label} RSS statistics are 0 for a cell without successes")
        for col, val in expect.items():
            rep.check(abs(float(a[col]) - val) <= TOL_MS, f"{label} {col}", f"aggregate {a[col]} vs recomputed {val:.3f}")
        bl = bgroups.get(key, [])
        expected_batches = cell_trials if key[0] in ("provision", "land") else 0  # commit is single-agent and has no batch rows
        rep.check(int(a["trials"]) == len(bl) == expected_batches, f"{label} batch count",
                  f"aggregate {a['trials']}, batches {len(bl)}, expected {expected_batches}")
        if bl:
            walls = sorted(int(b["batch_wall_us"]) / 1000.0 for b in bl)
            rep.check(abs(float(a["batch_wall_p50_ms"]) - nearest_rank(walls, 50)) <= TOL_MS, f"{label} batch_wall_p50_ms")
            rep.check(abs(float(a["batch_wall_mean_ms"]) - sum(walls) / len(walls)) <= TOL_MS, f"{label} batch_wall_mean_ms")
            disk = sum(int(b["disk_bytes"]) for b in bl) / len(bl)
            rep.check(abs(float(a["disk_bytes_mean"]) - disk) <= 1.0, f"{label} disk_bytes_mean")
            oks = sum(int(b["agents_ok"]) for b in bl) / len(bl)
            rep.check(abs(float(a["agents_ok_mean"]) - oks) <= 0.0015, f"{label} agents_ok_mean")
            # a batch can never finish before its slowest agent
            for b in bl:
                agents = [int(r["latency_us"]) for r in rows if r["trial"] == b["trial"]]
                rep.check(int(b["batch_wall_us"]) >= max(agents), f"{label} trial {b['trial']} batch wall >= slowest agent")
        if key[0] == "land":
            result_check(abs(float(a["agents_ok_mean"]) - k) < 1e-9, f"{label} every landed change read back from the head", f"agents_ok_mean={a['agents_ok_mean']}")
    # every variant that was measured at all is either measured or recorded as skipped at every K level
    variants = sorted({key[:3] for key in groups if key[0] in ("provision", "land")})
    rep.check(bool(variants), "provision and land variants present")
    for wsv in variants:
        for k in k_levels:
            cell = (*wsv, k)
            rep.check(cell in groups or cell in skipped_keys, f"{'/'.join(wsv)} measured or skipped at K={k}")
    for s in skipped:
        result_check(False, f"cell skipped by the memory-fit guard: {s['workload']}/{s['system']}/{s['variant']} k={s['k']}",
                     f"{s['trials_skipped']} of {trials} trials skipped after {s['trials_measured']} measured; "
                     f"predicted {int(s['predicted_peak_rss_kb']) // 1024} MiB > 90% of {int(s['available_kb']) // 1024} MiB available")

    # ---- results.json agrees with the CSV files -------------------------------------------
    results = json.loads((run_dir / "results.json").read_text())
    rep.check(results.get("metadata") == meta, "results.json metadata equals metadata.json")
    rep.check(len(results.get("aggregate", [])) == len(agg), "results.json aggregate row count")
    rep.check(len(results.get("raw_trials", [])) == len(raw), "results.json raw_trials row count")
    rep.check(len(results.get("raw_batches", [])) == len(batches), "results.json raw_batches row count")
    for a, j in zip(agg, results.get("aggregate", [])):
        for col in AGG_FIELDS:
            rep.check(str(j.get(col)) == a[col] or (isinstance(j.get(col), (int, float)) and abs(float(j[col]) - float(a[col])) < 1e-9),
                      f"results.json aggregate {'/'.join(group_key(a))} {col}", f"{j.get(col)} vs {a[col]}")

    summary = (run_dir / "summary.md").read_text()
    rep.check(run_id in summary, "summary.md names the run")
    rep.check(all(a["variant"] in summary for a in agg), "summary.md lists every variant")

    # ---- sterility -------------------------------------------------------------------------
    for path in sorted(p for p in run_dir.rglob("*") if p.is_file()):
        text = path.read_text(errors="replace")
        rel = path.relative_to(run_dir)
        rep.check(not PATH_RE.search(text), f"no workstation path in {rel}")
        rep.check(not ADDR_RE.search(text), f"no private address in {rel}")
        low = text.lower()
        for tok in forbid:
            rep.check(re.search(r"(?<![A-Za-z0-9_])" + re.escape(tok.lower()) + r"(?![A-Za-z0-9_])", low) is None, f"token {tok!r} absent from {rel}")
    return rep


def p50_table(run_dir: Path) -> dict[tuple[str, str, str, str], tuple[float, float]]:
    with (run_dir / "aggregate.csv").open(newline="") as fh:
        return {group_key(r): (float(r["p50_ms"]), float(r["batch_wall_p50_ms"])) for r in csv.DictReader(fh)}


def compare(a: Path, b: Path) -> int:
    ta, tb = p50_table(a), p50_table(b)
    keys = sorted(set(ta) & set(tb), key=lambda key: (key[0], key[1], key[2], int(key[3])))
    print(f"run-to-run p50 agreement: {a.name} (A) vs {b.name} (B)")
    print(f"{'cell':44} {'p50 A ms':>12} {'p50 B ms':>12} {'B/A':>7} {'batch A ms':>12} {'batch B ms':>12} {'B/A':>7}")
    worst = 0.0
    for key in keys:
        (pa, ba), (pb, bb) = ta[key], tb[key]
        ratio = pb / pa if pa else math.inf
        bratio = bb / ba if ba else (0.0 if bb == 0 else math.inf)
        if ratio and ratio != math.inf:
            worst = max(worst, abs(math.log(ratio)))
        print(f"{'/'.join(key):44} {pa:12.3f} {pb:12.3f} {ratio:7.2f} {ba:12.3f} {bb:12.3f} {bratio:7.2f}")
    only_a = sorted(set(ta) - set(tb)); only_b = sorted(set(tb) - set(ta))
    if only_a or only_b:
        print(f"cells only in A: {['/'.join(k) for k in only_a]}; only in B: {['/'.join(k) for k in only_b]}")
    print(f"largest |ln(B/A)| of per-agent p50 = {worst:.3f} over {len(keys)} shared cells")
    return 0


def main(argv: list[str]) -> int:
    forbid: list[str] = []
    dirs: list[Path] = []
    require_clean = False
    i = 0
    while i < len(argv):
        if argv[i] == "--forbid":
            forbid.append(argv[i + 1]); i += 2
        elif argv[i] == "--require-clean":
            require_clean = True; i += 1
        elif argv[i] == "--compare":
            return compare(Path(argv[i + 1]), Path(argv[i + 2]))
        else:
            dirs.append(Path(argv[i])); i += 1
    if not dirs:
        print(__doc__)
        return 2
    rc = 0
    for d in dirs:
        rep = verify_run(d, forbid, require_clean)
        status = "PASS" if not rep.failures else "FAIL"
        print(f"{status} {d}: {len(rep.passes)} checks passed, {len(rep.failures)} failed")
        for f in rep.failures:
            print(f"  FAIL {f}")
        for n in rep.notes:
            print(f"  note {n}")
        if rep.failures:
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
