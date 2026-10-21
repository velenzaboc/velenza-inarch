#!/usr/bin/env python3
"""Render Markdown comparison tables from benchmark result sets produced by bench-vs-git.sh.

usage: report-tables.py <run_dir> [<run_dir> ...]

Runs are grouped by host_label and ordered by started_utc within a host; the first run of a host is
"A", the second "B", and so on. A run may cover only some workloads (a land-only re-run after a code
change, or one provisioning cell on an extra host): each workload table lists the runs that measured
that workload, the Runs table says what every run covers and which inr source revision it ran, host
rows that differ between runs show every value with its run letters, and run-to-run agreement is
computed between consecutive runs of one host at one inr source revision. Every figure is read from
that run's aggregate.csv (which verify-run.py recomputes from the raw rows), metadata.json and
raw_trials.csv. Output is Markdown on stdout. Standard library only.
"""
import csv
import json
import math
import sys
from pathlib import Path

WORKLOAD_ORDER = ["provision", "commit", "land"]
VARIANT_ORDER = {
    "provision": [("git", "clone_full"), ("git", "clone_sparse"), ("git", "worktree_add"),
                  ("inr", "checkout_full"), ("inr", "checkout_sparse"), ("inr", "mount")],
    "commit": [("git", "commit_path"), ("git", "commit_scan"), ("git", "commit_scan_push"),
               ("inr", "commit_full"), ("inr", "commit_sparse")],
    "land": [("git", "push_rebase"), ("inr", "serve_land")],
}
PAIRS = [
    ("provision", "clone_full", "checkout_full", "full working copy"),
    ("provision", "clone_sparse", "checkout_sparse", "one service directory"),
    ("provision", "worktree_add", "mount", "cheapest working copy each side"),
    ("provision", "clone_full", "mount", "full clone vs virtual mount"),
    ("land", "push_rebase", "serve_land", "K concurrent single-file landings"),
]


def load_run(path):
    d = Path(path)
    meta = json.loads((d / "metadata.json").read_text())
    agg = {}
    with open(d / "aggregate.csv", newline="") as f:
        for row in csv.DictReader(f):
            agg[(row["workload"], row["system"], row["variant"], int(row["k"]))] = row
    skipped = {}
    for c in meta.get("skipped_cells", []):
        skipped[(c["workload"], c["system"], c["variant"], int(c["k"]))] = c
    fails = {}
    with open(d / "raw_trials.csv", newline="") as f:
        for row in csv.DictReader(f):
            if row["warmup"] != "0":
                continue
            rc = int(row["exit_code"])
            if rc == 0:
                continue
            key = (row["workload"], row["system"], row["variant"], int(row["k"]))
            fails.setdefault(key, {})
            fails[key][rc] = fails[key].get(rc, 0) + 1
    return {"dir": d, "meta": meta, "agg": agg, "skipped": skipped, "fails": fails}


def ms(v):
    v = float(v)
    if v < 10:
        return f"{v:.2f}"
    if v < 100:
        return f"{v:.1f}"
    return f"{v:,.0f}"


def mib(kb):
    return f"{float(kb) / 1024:.0f}"


def gib(kb):
    return f"{float(kb) / 1024 / 1024:.1f}"


def k_levels(runs):
    ks = set()
    for r in runs:
        ks.update(r["meta"]["design"]["concurrency_levels"])
    return sorted(ks)


def cell_keys(r):
    return list(r["agg"]) + list(r["skipped"])


def runs_with(runs, wl):
    """The runs that measured or skipped at least one cell of workload wl."""
    return [r for r in runs if any(key[0] == wl for key in cell_keys(r))]


def inr_rev(meta):
    return meta["toolchain"]["inr_source_rev"][:12]


def grouped_values(runs, fn):
    """fn(meta) of every run: the value alone when every run agrees, else every distinct value
    followed by the letters of the runs that carry it."""
    groups = []
    for r in runs:
        value = fn(r["meta"])
        for group in groups:
            if group[0] == value:
                group[1].append(r["letter"])
                break
        else:
            groups.append([value, [r["letter"]]])
    if len(groups) == 1:
        return groups[0][0]
    return "; ".join(f"{value} ({', '.join(letters)})" for value, letters in groups)


def coverage(r):
    """The workloads and K levels a run measured or skipped, e.g. 'land (K 1, 8, 16, 32)'."""
    keys = cell_keys(r)
    wls = [wl for wl in WORKLOAD_ORDER if any(key[0] == wl for key in keys)]
    ks = sorted({key[3] for key in keys if key[0] != "commit"})
    text = ", ".join(wls)
    if ks:
        text += f" (K {', '.join(str(k) for k in ks)})"
    return text


def cell(runs, key, fn, skipped_text="skipped"):
    parts = []
    for r in runs:
        row = r["agg"].get(key)
        if row is not None:
            parts.append(fn(row))
        elif key in r["skipped"]:
            parts.append(skipped_text)
        else:
            parts.append("n/a")
    return " / ".join(parts)


def failures_cell(runs, key):
    parts = []
    for r in runs:
        row = r["agg"].get(key)
        if row is None:
            parts.append("skipped" if key in r["skipped"] else "n/a")
            continue
        text = f"{row['failures']}/{row['samples']}"
        codes = r["fails"].get(key)
        if codes:
            text += " (rc " + ", ".join(f"{rc}x{n}" for rc, n in sorted(codes.items())) + ")"
        if key in r["skipped"]:  # the guard stopped this cell after some trials; the figures cover those trials only
            text += f" ({row['trials']} of {r['meta']['design']['trials']} trials, rest skipped)"
        parts.append(text)
    return " / ".join(parts)


def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(":---" for _ in headers) + " |"]
    for row in rows:
        out.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(out)


def duration(meta):
    from datetime import datetime
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    try:
        a = datetime.strptime(meta["started_utc"], fmt)
        b = datetime.strptime(meta["finished_utc"], fmt)
        secs = int((b - a).total_seconds())
        return f"{secs // 3600}h {secs % 3600 // 60:02d}m"
    except (KeyError, ValueError):
        return "n/a"


def hosts_section(by_host):
    labels = list(by_host)
    rows = []

    def add(name, fn):
        rows.append([name] + [grouped_values(by_host[h], fn) for h in labels])

    add("OS", lambda m: m["host"]["os_release"])
    add("Kernel", lambda m: m["host"]["kernel"])
    add("Architecture", lambda m: m["host"]["arch"])
    add("CPU", lambda m: m["host"]["cpu_model"])
    add("Cores (logical / physical)", lambda m: f"{m['host']['cpu_logical_cores']} / {m['host']['cpu_physical_cores']}")
    add("Memory", lambda m: f"{gib(m['host']['mem_total_kb'])} GiB")
    add("Memory cgroup limit", lambda m: (f"{gib(m['host']['mem_cgroup_limit_kb'])} GiB" if int(m["host"]["mem_cgroup_limit_kb"]) else "none"))
    add("Power / low-power mode", lambda m: f"{m['host']['power_source']} / {m['host']['low_power_mode']}")
    add("Scratch filesystem", lambda m: m["host"]["work_fs_type"])
    add("git", lambda m: m["toolchain"]["git_version"])
    add("inr source revision", inr_rev)
    add("inr binary SHA-256 (prefix)", lambda m: m["toolchain"]["inr_binary_sha256"][:16])
    add("rustc", lambda m: m["toolchain"]["rustc_version"])
    add("bash / awk / python", lambda m: f"{m['toolchain']['bash_version']} / {m['toolchain']['awk_version']} / {m['toolchain']['python_version']}")
    add("bench-vs-git.sh SHA-256 (prefix)", lambda m: m["toolchain"]["bench_script_sha256"][:16])
    add("measure.py SHA-256 (prefix)", lambda m: m["toolchain"]["measure_script_sha256"][:16])
    out = ["### Hosts", "", table(["", *labels], rows), "", "### Runs", ""]
    run_rows = []
    for h in labels:
        for r in by_host[h]:
            m = r["meta"]
            run_rows.append([
                h, r["letter"], f"`{m['run_id']}`", inr_rev(m), coverage(r), m["started_utc"], duration(m),
                m["host"]["loadavg_1_5_15_at_start"], m["host"]["loadavg_1_5_15_at_end"],
                f"{gib(m['host']['mem_available_to_process_kb_at_start'])} GiB",
                f"{gib(m['host']['work_fs_free_kb_at_start'])} GiB",
            ])
    out.append(table(["Host", "Run", "Result set", "inr revision", "Covers", "Started (UTC)", "Duration",
                      "Load 1/5/15 at start", "Load 1/5/15 at end", "Memory available to the process at start",
                      "Free disk at start"], run_rows))
    return "\n".join(out)


def revision_line(runs):
    """A line naming the inr source revision of each run when the runs differ, else nothing."""
    revs = grouped_values(runs, inr_rev)
    return [f"inr source revision: {revs}.", ""] if ";" in revs else []


def workload_tables(host, all_runs):
    out = []
    for wl in WORKLOAD_ORDER:
        runs = runs_with(all_runs, wl)
        if not runs:
            continue
        ks = k_levels(runs)
        run_names = " / ".join(r["letter"] for r in runs)
        out.append(f"#### {wl} on {host} (runs {run_names})")
        out.append("")
        out += revision_line(runs)
        rows = []
        if wl == "commit":
            headers = ["System", "Variant", "p50 ms", "min ms", "max ms", "peak RSS p50 MiB", "failures/samples"]
            for sysname, variant in VARIANT_ORDER[wl]:
                key = (wl, sysname, variant, 1)
                if not any(key in r["agg"] or key in r["skipped"] for r in runs):
                    continue
                rows.append([sysname, f"`{variant}`",
                             cell(runs, key, lambda r: ms(r["p50_ms"])),
                             cell(runs, key, lambda r: ms(r["min_ms"])),
                             cell(runs, key, lambda r: ms(r["max_ms"])),
                             cell(runs, key, lambda r: mib(r["max_rss_kb_p50"])),
                             failures_cell(runs, key)])
        else:
            headers = ["System", "Variant", "K", "agent p50 ms", "agent p95 ms", "batch p50 ms",
                       "peak RSS p50 MiB", "failures/samples"]
            if wl == "land":
                headers.append("landed per batch")
            for sysname, variant in VARIANT_ORDER[wl]:
                for k in ks:
                    key = (wl, sysname, variant, k)
                    if not any(key in r["agg"] or key in r["skipped"] for r in runs):
                        continue
                    row = [sysname, f"`{variant}`", k,
                           cell(runs, key, lambda r: ms(r["p50_ms"])),
                           cell(runs, key, lambda r: ms(r["p95_ms"])),
                           cell(runs, key, lambda r: ms(r["batch_wall_p50_ms"])),
                           cell(runs, key, lambda r: mib(r["max_rss_kb_p50"])),
                           failures_cell(runs, key)]
                    if wl == "land":
                        row.append(cell(runs, key, lambda r, k=k: f"{float(r['agents_ok_mean']):.1f}/{k}"))
                    rows.append(row)
        out.append(table(headers, rows))
        out.append("")
    return "\n".join(out)


def ratio_tables(host, all_runs):
    out = [f"#### git versus inr on {host} (git p50 divided by inr p50; above 1 means inr is faster)", ""]
    out += revision_line(all_runs)
    rows = []
    for wl, gv, iv, what in PAIRS:
        runs = runs_with(all_runs, wl)
        for k in k_levels(runs):
            gk, ik = (wl, "git", gv, k), (wl, "inr", iv, k)
            if not any(gk in r["agg"] or ik in r["agg"] for r in runs):
                continue
            agent, batch = [], []
            for r in runs:
                g, i = r["agg"].get(gk), r["agg"].get(ik)
                if g is None or i is None:
                    why = "skipped" if (gk in r["skipped"] or ik in r["skipped"]) else "n/a"
                    agent.append(why)
                    batch.append(why)
                    continue
                agent.append(f"{float(g['p50_ms']) / float(i['p50_ms']):.2f}")
                batch.append(f"{float(g['batch_wall_p50_ms']) / float(i['batch_wall_p50_ms']):.2f}")
            rows.append([f"`{gv}` vs `{iv}`", what, k, " / ".join(r["letter"] for r in runs),
                         cell(runs, gk, lambda r: ms(r["p50_ms"])),
                         cell(runs, ik, lambda r: ms(r["p50_ms"])),
                         " / ".join(agent), " / ".join(batch)])
    out.append(table(["Pair", "What", "K", "Runs", "git p50 ms", "inr p50 ms", "agent ratio", "batch ratio"], rows))
    out.append("")
    return "\n".join(out)


def agreement_section(by_host):
    out = ["### Run-to-run agreement", "",
           "For every cell measured in two consecutive runs of one host at one inr source revision, "
           "the difference of the per-agent p50 is |ln(second/first)|, expressed below as a "
           "percentage: 10% means the two runs' medians differ by a factor of 1.10 in one direction "
           "or the other. Runs at different inr source revisions are not compared.", ""]
    rows = []
    for host, runs in by_host.items():
        groups = {}
        for r in runs:
            groups.setdefault(inr_rev(r["meta"]), []).append(r)
        for rev, group in groups.items():
            if len(group) < 2:
                rows.append([host, rev, group[0]["letter"], "one run", "n/a", "n/a", "n/a"])
                continue
            for a, b in zip(group, group[1:]):
                pair = f"{a['letter']} vs {b['letter']}"
                diffs = []
                for key, ra in a["agg"].items():
                    rb = b["agg"].get(key)
                    if rb is None:
                        continue
                    pa, pb = float(ra["p50_ms"]), float(rb["p50_ms"])
                    if pa > 0 and pb > 0:
                        diffs.append((abs(math.log(pb / pa)), key))
                if not diffs:
                    rows.append([host, rev, pair, "0", "n/a", "n/a", "n/a"])
                    continue
                diffs.sort()
                med = diffs[len(diffs) // 2][0]
                mx, key = diffs[-1]
                within10 = sum(1 for d, _ in diffs if d <= math.log(1.10))
                rows.append([host, rev, pair, str(len(diffs)), f"{(math.exp(med) - 1) * 100:.1f}%",
                             f"{(math.exp(mx) - 1) * 100:.0f}% (`{key[1]}/{key[2]}` K={key[3]})",
                             f"{within10}/{len(diffs)}"])
    out.append(table(["Host", "inr revision", "Runs", "Cells compared", "Median difference",
                      "Largest difference", "Cells within 10%"], rows))
    out.append("")
    return "\n".join(out)


def skipped_and_failures(by_host):
    out = ["### Skipped cells (memory-fit guard)", ""]
    rows = []
    for host, runs in by_host.items():
        for r in runs:
            for key, c in sorted(r["skipped"].items()):
                rows.append([host, r["letter"], f"`{key[1]}/{key[2]}`", key[3],
                             c.get("trials_measured", "n/a"), c["trials_skipped"],
                             mib(c["peak_rss_kb_basis"]), mib(c["predicted_peak_rss_kb"]), mib(c["available_kb"])])
    out.append(table(["Host", "Run", "Cell", "K", "trials measured", "trials skipped", "peak RSS basis MiB",
                      "predicted K x peak MiB", "available MiB"], rows) if rows else "None.")
    out += ["", "### Failed agents", ""]
    rows = []
    for host, runs in by_host.items():
        for r in runs:
            for key, codes in sorted(r["fails"].items()):
                row = r["agg"][key]
                rows.append([host, r["letter"], f"`{key[1]}/{key[2]}`", key[3],
                             f"{row['failures']}/{row['samples']}",
                             ", ".join(f"{rc} x{n}" for rc, n in sorted(codes.items()))])
    out.append(table(["Host", "Run", "Cell", "K", "failures/samples", "exit codes"], rows) if rows else "None.")
    out.append("")
    return "\n".join(out)


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    runs = [load_run(p) for p in argv[1:]]
    runs.sort(key=lambda r: (r["meta"]["host_label"], r["meta"]["started_utc"]))
    by_host = {}
    for r in runs:
        by_host.setdefault(r["meta"]["host_label"], []).append(r)
    for hruns in by_host.values():
        for i, r in enumerate(hruns):
            r["letter"] = chr(ord("A") + i)
    print(hosts_section(by_host))
    print()
    for host, hruns in by_host.items():
        print(f"### {host}")
        print()
        print(workload_tables(host, hruns))
        print(ratio_tables(host, hruns))
    print(agreement_section(by_host))
    print(skipped_and_failures(by_host))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
