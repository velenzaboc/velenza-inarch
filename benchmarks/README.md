# Benchmarks

Reproducible, publishable measurements of Git against Velenza Inarch (`inr`) on the same machine, the
same corpus and the same concurrency levels. Everything here is produced by one script, and every
number in a results directory can be traced back to a raw per-trial row.

## What `bench-vs-git.sh` measures

Each sample is one operating-system process timed from spawn to exit by `measure.py`, which also
records the peak resident set size of the agent's process tree. Both systems pay their own start-up,
configuration discovery and store-open cost inside the measurement.

| Workload | Git variants | `inr` variants | Question answered |
| :--- | :--- | :--- | :--- |
| `provision` | `worktree_add`, `clone_full` (file:// transport), `clone_sparse` (partial clone + cone sparse-checkout) | `checkout_full`, `checkout_sparse` (`--prefix`), `mount` (virtual workspace, zero blob writes) | How long until K agents each have a working copy of an N-file repository? |
| `commit` | `commit_path` (`add <file>` + `commit`), `commit_scan` (`add -A` + `commit`), `commit_scan_push` (+ `push`) | `commit_full` (scan N files, land), `commit_sparse` (scan one service slice, land) | How long does one agent take to record a single-file change? |
| `land` | `push_rebase` (one `bash -c` child: commit, push, `pull --rebase` and retry on rejection) | `serve_land` (`inr commit` from K client processes through one loopback `inr serve`) | How long until K concurrent single-file changes are all on the branch head? |

For `land` the script reads every agent's file back from the branch head after the batch and counts
how many changes actually arrived. A count below K is a lost update and is reported, not hidden.

Per sample the script records latency, exit code, disk bytes and peak RSS. Latency and RSS statistics
are computed over the successful samples of a cell; failed samples are counted in `failures` and
listed with their exit codes in `summary.md`, so a crash or an OOM kill never disappears into a
percentile and never distorts one either.

### Memory-fit guard

K concurrent agents of one variant need roughly K times that variant's peak RSS. Before every batch with
K > 1, which is before every measured trial, the script multiplies the largest peak RSS it has observed so
far for the system/variant by K and skips the rest of the cell when the product exceeds 90% of the memory
available to the benchmark process. On
Linux that is `MemAvailable`, bounded by the limiting cgroup's headroom (`memory.max` minus
`memory.current`) plus the clean, non-shmem page cache charged to that cgroup; the cache term matters
because `memory.current` counts the page cache of every file the benchmark itself writes, and the
kernel reclaims that cache before it kills anything. On macOS it is physical memory minus wired,
compressor-occupied and anonymous pages. K levels therefore run in ascending order. A skipped cell is
recorded in `metadata.json` under `skipped_cells` with the prediction, the available memory and the
number of trials measured before the skip and skipped after it, and `summary.md` lists it. A cell the
guard stops after some trials keeps the measured ones; its aggregate row carries the smaller sample and
trial counts. This is the documented alternative to publishing OOM-killed or swap-thrashing samples.
`--no-memory-guard` disables the check.

### Corpus

`--files N` deterministic Rust-like source files named `services/svc-NN/mod_I.rs` across `--svc-dirs`
service directories (default 50), each padded to about `--file-bytes` bytes (default 2048). File `i`
lives in service `i mod svc-dirs`. Agent `a` works on `services/svc-<a-1>`, so with `--svc-dirs` at least
the largest K every agent owns a disjoint slice.

### Fairness controls

- Separate OS processes for both systems; no in-process timing.
- Git runs with `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`, a fixed benchmark
  identity, and `core.fsmonitor=false` plus `feature.manyFiles=true` enabled on benchmark repositories
  for large-tree fairness. The origin is a packed bare repository served over
  `file://`, so clones transfer packs instead of hard-linking objects. The base repository that
  `worktree_add` attaches to is packed in the foreground before any measurement, so no detached
  `gc --auto` runs during the benchmark.
- `inr` runs from configuration files written by `inr init`, with the local filesystem blob and
  metadata backends, no configured tier cache directories, logging off, and `HOME` redirected into
  the scratch tree so no user-global configuration leaks in. Processes on the local store keep only
  in-memory tiers; the `land` clients run in remote mode, where `inr` keeps its default on-disk
  tier-1 blob cache, which the `HOME` redirection places inside the scratch tree, shared by the K
  agents.
- Concurrent `inr` landing goes through one loopback `inr serve` process. The local filesystem
  metadata store serialises its compare-and-swap inside one process, so several client processes
  writing one local store directly would not be a fair or correct comparison.
- One warm-up batch per variant, at the smallest K, is recorded with `warmup=1` and excluded from
  aggregates; the origin, the base repository and the stores are then in the page cache for every
  later cell of that variant.
- Provisioning destinations are deleted between trials; working copies for `land` are reset to the
  branch head between batches on both sides (untimed).

### Outputs

Everything lands under `<output-dir>/<run-id>/`:

| File | Content |
| :--- | :--- |
| `metadata.json` | OS release, kernel, architecture, CPU model, logical and physical cores, governor, power source and low-power mode (macOS), memory, cgroup memory limit and memory available to the process, filesystem type, free space, load averages at start and end, git and `inr` versions, `inr` binary digest, the digests of the script and of `measure.py`, rustc, cargo, bash, awk and python versions, corpus sizes, design notes, skipped cells |
| `raw_trials.csv` | one row per (workload, system, variant, K, trial, agent): latency in microseconds, exit code, disk bytes, peak RSS in KiB, extra fields such as push attempts |
| `raw_batches.csv` | one row per batch: wall time from first agent start to last agent exit, disk bytes, agents verified on the head, agents failed |
| `aggregate.csv` | samples, failures, min, p50, mean, p95, p99, max latency and p50 and max peak RSS per (workload, system, variant, K); nearest-rank percentiles over successful samples; warm-up excluded |
| `results.json` | metadata, aggregate and both raw tables in one machine-readable bundle |
| `summary.md` | human-readable tables, git/`inr` p50 ratios, failures by exit code, skipped cells |
| `run.log` | the script's log with absolute paths redacted |
| `inr-bench/` | the built-in `inr bench` suite run on the same N and K list, unless `--skip-inr-bench` |

### Sterility

Results are meant to be published. Before the script exits it redacts the scratch, output and
repository paths from every text output and then scans every file for workstation path prefixes,
private IPv4 literals, the user name, the host name and the home directory. A violation fails the run.
The host is identified only by `--host-label` and the hardware fields in `metadata.json`.

## Verifying a run

`verify-run.py` is an independent second implementation of every published statistic, in Python
rather than awk, so the two cannot share a bug. It re-derives `aggregate.csv` from the raw rows,
checks that every batch carries exactly K agent rows and accounts for every agent, that every
variant is either measured or recorded as skipped at every K (or measured for its first trials and
skipped for the rest, with the two counts adding up to the design), that skipped cells really exceeded
the guard, that `results.json` matches the CSV files, and rescans every file for identifying byte
sequences. Failed agents and `land` batches with fewer verified changes than K are facts about the
systems under test: they are printed as notes and fail verification only with `--require-clean`.
`--compare` prints the per-agent and batch p50 agreement between two runs.

```bash
python3 benchmarks/verify-run.py benchmarks/results/<run-id>
python3 benchmarks/verify-run.py --compare benchmarks/results/<run-a> benchmarks/results/<run-b>
```

## Decomposing a landing

`decompose-landing.sh` explains a `serve_land` number instead of just reporting it. It starts one
loopback `inr serve` on a scratch tree kept by `bench-vs-git.sh --keep-work` (any run that includes the
`land` workload leaves `cfg-server/`, `store-server/` and `bench-home/` there), puts `rpc-relay.py`, a
transparent TCP relay that forwards every byte unchanged, between client and server, lands a one-line
change from a fresh sparse checkout a few times, and records per RPC its kind, bytes, server service time
and client think time, plus the server process's CPU time and bytes read per landing. One round bypasses
the relay to show its overhead, one lands the same change through the scratch tree's local filesystem
stores with no server at all (the engine's own `land_patch` cost), and one `inr refs` call gives the
round-trip floor. Outputs go to
`results/decomposition-<timestamp>/` (`rpc.csv`, `rounds.csv`, `summary.md`, `metadata.json`) and pass
the same redaction and sterility scan as a benchmark run.

```bash
benchmarks/bench-vs-git.sh --workloads land --concurrency 1 --trials 1 --keep-work --work-dir /path/scratch --inr target/release/inr
benchmarks/decompose-landing.sh --work-dir /path/scratch --inr target/release/inr --host-label <neutral-label>
```

## Running it

Requirements: Linux or macOS, bash 5 or newer (Homebrew `bash` on macOS; the script re-executes
itself through it), coreutils, awk, python3 (standard library only), git 2.25 or newer, and an `inr`
binary. Build one with `cargo build --release -p inarch-cli` or pass `--build`.

```bash
benchmarks/bench-vs-git.sh \
  --files 50000 \
  --concurrency 1,8,16,32 \
  --trials 5 --warmup 1 \
  --host-label linux-worker-a \
  --inr target/release/inr \
  --output-dir benchmarks/results
```

A full run at N=50,000 and K up to 32 needs roughly 20 GiB of free space under the scratch directory
(32 full clones plus stores); the script refuses to start below `--min-free-gb`. Use `--work-dir` to
put the scratch tree on the filesystem you want to measure and `--keep-work` to inspect it afterwards.

| Flag | Default | Meaning |
| :--- | :--- | :--- |
| `--files` | 50000 | corpus size |
| `--concurrency` | 1,8,16,32 | K values for `provision` and `land`; run in ascending order |
| `--trials` | 5 | measured trials per cell |
| `--warmup` | 1 | warm-up trials per cell (recorded, excluded from aggregates) |
| `--host-label` | linux-worker | neutral host identifier written to the outputs |
| `--output-dir` | benchmarks/results | parent of the per-run results directory |
| `--inr` / `--build` | auto-detect | `inr` binary to measure, or build it with cargo |
| `--source-rev` | git HEAD of this checkout | `inr` source revision recorded in metadata |
| `--svc-dirs` | 50 | service directories in the corpus; must be at least the largest K for `land` |
| `--no-memory-guard` | off | run every cell even when K x peak RSS exceeds the memory available to the process |
| `--file-bytes` | 2048 | target size of each corpus file |
| `--workloads` | provision,commit,land | subset to run |
| `--work-dir` | mktemp under `$TMPDIR` | scratch tree |
| `--keep-work` | off | keep the scratch tree |
| `--skip-inr-bench` | off | skip the built-in `inr bench` suite |
| `--min-free-gb` | 20 | refuse to start with less free space under the scratch tree |
| `--run-id` | `<UTC timestamp>-n<files>` | results directory name |

## Results

Generated runs live under `benchmarks/results/<run-id>/`, and the result sets of the v0.1.0 release campaign are committed there. Start with a run's `summary.md`, then `aggregate.csv`; the raw tables are there so any statistic can be recomputed by `verify-run.py` and rendered into multi-run Markdown tables by `report-tables.py`. `REPORT.md` section 7 reads the committed sets, including the cells where `inr` is slower than Git. A new run you generate is not ignored by Git, so commit only sets that pass `verify-run.py` and the open-source hygiene test. `decompose-landing.sh` writes per-RPC breakdowns under `benchmarks/results/decomposition-<id>/`. `REPORT.md` also walks through the methodology, architectural tradeoffs, and reproduction steps.
