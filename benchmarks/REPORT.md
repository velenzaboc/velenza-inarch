# Git vs Velenza Inarch at 50,000 files: Benchmark Methodology, Tradeoffs & Reproduction Guide

This document describes the benchmark methodology, fairness controls, independent verification pipeline, and architectural mechanisms measured by the harness in `benchmarks/`. The raw per-trial CSV and JSON result sets of the v0.1.0 release campaign are committed under `benchmarks/results/<run-id>/`, and section 7 reads them. Timings are host-dependent, so every script, timing wrapper, verifier, and table renderer is included in this directory and anyone can run the comparison on their own hardware and generate verified tables.

## 1. Executive Summary of Architectural Tradeoffs

The benchmark compares Git and Velenza Inarch (`inr`) across three agent-oriented workloads on a deterministic 50,000-file repository (`N=50,000`, ~200 MiB tree across 50 service directories) with concurrency levels `K in {1, 8, 16, 32}`:

1. **Workspace provisioning (`provision`)**:
   - **Virtual & sparse workspaces (`inr mount` and `inr checkout --prefix`)**: `inr mount` writes only the directory skeleton and `.inarch/` workspace metadata with zero upfront blob writes, hydrating files on demand. `inr checkout --prefix` prunes the derived `Fsnode` tree to the requested service slice before fetching blobs, scaling memory and I/O with the slice ($O(|\text{slice}|)$) rather than repository size $N$.
   - **Full materialization (`inr checkout` vs `git clone` / `git worktree add`)**: A full `inr checkout` materializes all $N$ files from content-addressed chunk/blob storage and therefore scales in time and resident memory with total tree size, whereas `git worktree add` shares the local object store and index infrastructure. For multi-agent fleets operating on bounded service slices, `inr mount` and `inr checkout --prefix` are the intended provisioning modes.
2. **Single-agent commit (`commit`)**:
   - **Scoped vs full working-copy scan**: `inr commit` resolves the workspace's persisted base revision from `.inarch/workspace_state.toml` (falling back to the target branch head for uninitialized directories), derives the `Fsnode` tree, and scans the checked-out files to build a `BonsaiChangeset` containing only modified paths. On a 1,000-file sparse slice (`commit_sparse`), `inr commit` scans only the slice; on a 50,000-file full checkout (`commit_full`), it walks all 50,000 files. Git's `commit_path` (`git add <file> && git commit`) updates a single index entry, while `git add -A` (`commit_scan`) stats the working tree against the index (with `core.fsmonitor=false` and `feature.manyFiles=true` enabled for fair large-tree index behavior).
3. **Concurrent multi-agent landing (`land`)**:
   - **Tree-free $O(\Delta)$ compare-and-swap vs push-rebase retry**: When $K$ agents concurrently land path-disjoint changes onto `main`, Git agents (`push_rebase`) race on `git push` and must repeatedly `git pull --rebase` and re-push on non-fast-forward rejection ($O(K^2)$ total push attempts per batch). Inarch agents (`serve_land`) submit `BonsaiChangeset`s through `inr serve`, where `ScionEngine::land_patch` verifies path-disjointness against intermediate changesets and rewrites the changeset parent pointer in $O(\Delta)$ without recomputing or rewriting Merkle directory trees on CAS retry.

## 2. What the Harness Measures

Git was designed around long-lived clones maintained by human developers. An autonomous agent fleet provisions isolated workspaces for bounded tasks, edits a small slice of files, and lands changes concurrently alongside dozens of sibling agents. The benchmark measures three workloads as end-to-end operating-system processes (never in-process library calls):

| Workload | Question | Git variants | `inr` variants |
| :--- | :--- | :--- | :--- |
| `provision` | How long until $K$ agents each have a working copy of a 50,000-file repository, and how much memory does each process require? | `worktree_add`, `clone_full` (`file://` transport), `clone_sparse` (partial clone + cone sparse-checkout) | `checkout_full`, `checkout_sparse` (`--prefix` of one service directory), `mount` (virtual workspace, zero blob writes) |
| `commit` | How long does one agent take to record a single-file change? | `commit_path` (`add <file>` + `commit`), `commit_scan` (`add -A` + `commit`), `commit_scan_push` (+ `push`) | `commit_full` (scan 50,000 files, land), `commit_sparse` (scan one 1,000-file service slice, land) |
| `land` | How long until $K$ concurrent single-file changes are all on the branch head, and did all $K$ arrive? | `push_rebase` (commit, push, `pull --rebase` and retry on rejection) | `serve_land` (`inr commit` from $K$ client processes through one loopback `inr serve`) |

$K$ is the number of concurrent agents (`1, 8, 16, 32` by default). $N$ is `50,000` files of ~2 KiB across `50` service directories (`services/svc-00` through `services/svc-49`), generated deterministically by `bench-vs-git.sh`.

## 3. Method

### 3.1 One script, one machine, one corpus

`bench-vs-git.sh` generates the synthetic corpus, initializes the Git baseline (one commit, packed in the foreground with `git gc --prune=now`, served as a bare origin over `file://`) and the `inr` baseline (a local store for `provision`/`commit` and a server store for `land`, both seeded with the identical commit), and runs the selected workloads in ascending $K$ order. Each variant executes warm-up batch(es) at the smallest $K$ (recorded with `warmup=1` and excluded from aggregate percentiles) followed by `--trials` measured batches. Provisioning destinations are removed between trials.

### 3.2 Timing and memory

Each agent is one child process timed by `benchmarks/measure.py` using `time.perf_counter_ns()` immediately before `Popen` and immediately after `wait()`. Every latency sample includes process startup, configuration discovery, and store initialization for both systems. After reaping the child, `measure.py` records `getrusage(RUSAGE_CHILDREN).ru_maxrss` (converted to KiB on both Linux and macOS), capturing the peak resident set size of the largest process in the reaped process tree. Batch wall time (`batch_wall_us`) is measured from the first agent fork to the final `wait` completion using bash's `EPOCHREALTIME`.

### 3.3 Fairness controls

- **Separate OS processes**: Nothing is timed in-process.
- **Git configuration**: Git runs with `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`, a fixed benchmark identity, and `core.fsmonitor=false` plus `feature.manyFiles=true` configured on every benchmark repository and working copy so large working-tree index operations use Git's recommended multi-file settings without background daemon interference. Both the `worktree_add` base repository and the bare `origin.git` are packed in the foreground (`gc --prune=now` with `gc.auto=0` during initial commit) before any measurement.
- **Inarch configuration**: `inr` runs from configuration files produced by `inr init` using local filesystem blob and metadata backends, logging disabled (`INARCH_LOG_BACKEND=none`), and `HOME` redirected into the scratch directory so no operator state leaks in.
- **Concurrent landing topology**: Concurrent `inr` landings run against a single loopback `inr serve` instance (`serve_land`), while each `inr` agent operates in a sparse checkout of its assigned service slice (`services/svc-<a-1>`). Each workspace persists its base changeset in `.inarch/workspace_state.toml`, allowing `inr commit` to diff against the workspace's base revision, advance `.inarch/workspace_state.toml` to the newly landed changeset, and rebase onto the moving `main` ref in $O(\Delta)$ via `land_patch`. Each Git agent works in an independent clone and runs `commit` followed by a `push` / `pull --rebase` retry loop against `origin.git`.
- **Post-batch verification**: After every `land` batch, the harness reads each agent's target file back from the `main` branch head (`git cat-file -p` / `inr cat`) and records the verified count in `agents_ok`.

### 3.4 Statistics and Memory-Fit Guard

Percentiles (`min`, `p50`, `p95`, `p99`, `max`) are nearest-rank over the successful (`exit_code == 0`), non-warm-up samples of each `(workload, system, variant, k)` cell, while non-zero exit codes are tallied in `failures` and broken down in `summary.md`.

Before each measured batch with $K > 1$, the memory-fit guard compares $K \times \text{peak RSS}$ (from smaller $K$ trials of the same variant) against 90% of available memory (`MemAvailable` bounded by cgroup v2 `memory.max - memory.current + reclaimable_file_cache` on Linux; physical memory minus wired, compressor, and anonymous pages on macOS). Cells that would exceed 90% of available memory are recorded in `metadata.json` (`skipped_cells`) and `summary.md` rather than triggering OOM kills or swap thrashing. Pass `--no-memory-guard` to disable this check.

### 3.5 Sterility and Independent Verification

Before exiting, `bench-vs-git.sh` redacts scratch, output, home, and repository paths (`<work>`, `<out>`, `<home>`, `<repo>`) across all generated files and scans every output file for workstation path prefixes, private IPv4 addresses, usernames, and hostnames.

`benchmarks/verify-run.py` provides an independent Python implementation of all aggregate statistics:
- Re-derives `aggregate.csv` from `raw_trials.csv` and `raw_batches.csv` and checks exact agreement.
- Verifies that every batch has $K$ agent rows, that `batch_wall_us` is at least the slowest agent's latency, that `results.json` matches the CSVs, and that all files pass the sterility scan.

## 4. Reproducing a Benchmark Run and Rendering Tables

```bash
# 1. Build the release binary
cargo build --release -p inarch-cli

# 2. Run the benchmark suite (adjust --files / --concurrency for quick smoke runs vs full 50k runs)
bash benchmarks/bench-vs-git.sh \
  --files 50000 \
  --concurrency 1,8,16,32 \
  --trials 5 \
  --warmup 1 \
  --host-label linux-worker-a \
  --inr target/release/inr \
  --output-dir benchmarks/results

# 3. Independently verify the generated result set
python3 benchmarks/verify-run.py benchmarks/results/<run-id>

# 4. Render Markdown comparison tables across one or more verified runs
python3 benchmarks/report-tables.py benchmarks/results/<run-id>
```

A full `N=50,000`, `K=1,8,16,32` run requires approximately 20 GiB of free disk space under `--work-dir` (or `$TMPDIR`). For a fast smoke check on smaller hardware, pass `--files 1000 --concurrency 1,4 --trials 2 --min-free-gb 2`.

## 5. Reading the Underlying Mechanisms

### 5.1 Provisioning: Full Checkout vs Sparse Checkout vs Virtual Mount

- `checkout_stateless` (`crates/inarch-cli/src/lib.rs`) walks the derived `Fsnode` directory tree, collects pending file entries, fetches the required blobs in batches, writes the working tree, and records the checked-out `BonsaiChangesetId` in `.inarch/workspace_state.toml`. For `checkout_full` on a 50,000-file tree, memory and I/O scale with the full tree size.
- `checkout_sparse` (`--prefix services/svc-NN`) prunes the `Fsnode` traversal to the requested directory prefix before fetching blobs, so both I/O and peak RSS scale with the 1,000-file service slice.
- `mount_virtual_workspace` (`crates/inarch-cli/src/mount.rs`) materializes the directory skeleton and `.inarch/mount.toml` + `.inarch/workspace_state.toml` without writing file blobs upfront.

### 5.2 Working-Copy Diff and Workspace Base Tracking

`ingest_directory` (`crates/inarch-cli/src/lib.rs`) reads `.inarch/workspace_state.toml` when present to determine the exact base changeset the working copy was provisioned or last committed from, derives its `Fsnode` tree, and compares tracked paths against the working directory on disk. Because the diff is computed against the workspace's own base changeset rather than a moving branch tip, concurrent commits landed by other agents on `main` are never mistaken for local file deletions or edits, and `.inarch/workspace_state.toml` is updated to the newly landed changeset ID as soon as `land_patch` succeeds.

### 5.3 Concurrent Landing (`land_patch` and `CasRef`)

`ScionEngine::land_patch` (`crates/inarch-engine/src/lib.rs`) stores modified blobs and enters a compare-and-swap loop on the target branch ref:
- If the branch tip still matches the workspace's base changeset, `land_patch` writes the `BonsaiChangeset` and swaps the ref in one step.
- If concurrent agents have advanced the branch tip, `land_patch` walks the intermediate changesets between the workspace base and the current tip, verifies that all modified paths are disjoint (including directory/file prefix checks), rewrites the changeset's parent pointer to the new tip in $O(1)$, and retries `cas_ref` without reading or rewriting any Merkle tree (`Fsnode`) objects.
- On the server side (`validate_cas_ref_policy` in `crates/inarch-cli/src/lib.rs`), fast-forward ancestry is verified by walking parent headers (`get_changeset_parents`), and path-prefix validation (`BonsaiChangeset::validate` in `crates/inarch-types/src/bonsai.rs`) probes directory ancestors in $O(n \times \text{depth})$ time.

### 5.4 Illustrative Single-Landing RPC Decomposition (`decompose-landing.sh`)

To inspect where time is spent inside a single remote `inr commit` against `inr serve`, run `benchmarks/decompose-landing.sh` against a scratch directory retained by `bench-vs-git.sh --keep-work`. The script places `benchmarks/rpc-relay.py` between client and server to measure per-RPC payload sizes, server service time, and client scan/walk gaps.

An illustrative microbenchmark trace of a warm single-file sparse landing (`N=50,000`, 1,000-file sparse slice, loopback `inr serve`) exhibits 10 RPCs across two keep-alive connections:

| # | Conn | Request | Req bytes | Response | Resp bytes | Client gap ms | Server service ms |
| ---: | ---: | :--- | ---: | :--- | ---: | ---: | ---: |
| 1 | 1 | `GetRef` | 25 | `GetRef` | 39 | — | ~0.3 |
| 2 | 1 | `GetDerivedMapping` | 39 | `GetDerivedMapping` | 39 | ~0.1 | ~0.2 |
| 3 | 2 | `GetObjectsBatch` | 43 | `GetObjectsBatch` | 110 | — | ~0.3 |
| 4 | 2 | `GetObjectsBatch` | 43 | `GetObjectsBatch (lz4)` | 2,267 | ~0.2 | ~0.2 |
| 5 | 2 | `GetObjectsBatch` | 43 | `GetObjectsBatch (lz4)` | 39,655 | ~6.7 | ~0.8 |
| 6 | 2 | `HasObjectsBatch` | 43 | `HasObjectsBatch` | 11 | ~47.4 | ~0.3 |
| 7 | 2 | `PutObjectsBatch (lz4)` | 414 | `PutObjectsBatchOk` | 6 | ~0.1 | ~0.3 |
| 8 | 1 | `GetRef` | 25 | `GetRef` | 39 | ~56.8 | ~0.2 |
| 9 | 1 | `PutChangeset` | 184 | `PutChangeset` | 38 | ~0.1 | ~0.2 |
| 10 | 1 | `CasRef` | 90 | `CasRefOk` | 6 | ~0.1 | ~0.3 |

Total server service time across all 10 RPCs is ~3 ms; the remaining wall time is spent in the client's working-copy scan and `Fsnode` comparison between RPCs 5–6 and 7–8.

## 6. Files in `benchmarks/`

| Path | Purpose |
| :--- | :--- |
| `benchmarks/bench-vs-git.sh` | End-to-end Git vs `inr` benchmark harness |
| `benchmarks/measure.py` | Per-process wall-clock timing and peak-RSS wrapper |
| `benchmarks/verify-run.py` | Independent verification and run-to-run comparison |
| `benchmarks/report-tables.py` | Renders Markdown summary tables from generated result directories |
| `benchmarks/rpc-relay.py` | Transparent loopback TCP relay that logs per-RPC timings and byte counts |
| `benchmarks/decompose-landing.sh` | Decomposes a single `serve_land` commit through `rpc-relay.py` |
| `benchmarks/results/<run-id>/` | Raw and aggregate result sets of the v0.1.0 release campaign (section 7) |
| `benchmarks/bench-arbor-4repos.py` | Runner and verifier for the four-repository Arbor Stack dogfood study |
| `benchmarks/arbor_4repo_results.json` | Committed dataset of that study, checked with `bench-arbor-4repos.py --verify` |
| `benchmarks/ARBOR_4REPO_STUDY.md` | Write-up of the four-repository Arbor Stack study |

## 7. Results: the v0.1.0 Release Campaign

This section reports the result sets committed under `benchmarks/results/`. All eight were produced on 2026-10-21 (UTC) by `bench-vs-git.sh` (SHA-256 prefix `52d477d26dd49c84` on every host) against `inr` built from release commit `c15d5e5558bf29103d21102c4c63a77038818c90`, with `N=50,000` files, five measured trials and one warm-up batch per cell. Each set passed `verify-run.py` with zero failed checks (418 to 1,994 checks per set). The built-in `inr bench` suite was skipped (`--skip-inr-bench`). Four hosts were used, each run twice:

- `linux-worker-a`, `linux-worker-b` and `macos-laptop-a` ran `provision`, `commit` and `land` at `K` in {1, 8, 16, 32}. The second laptop run repeated `land` only.
- `linux-worker-c` ran `provision` at `K=32` only. It has 30.6 GiB of memory and no cgroup limit, so it is the one host that measured the `K=32` full checkout.

### 7.1 Summary

Ratios are Git p50 divided by `inr` p50 per agent, so a value above 1 means `inr` is faster and a value below 1 means `inr` is slower. A host with two runs shows run A / run B. "skipped" means the memory-fit guard declined to run the cell (section 3.4).

| Comparison | Host | K=1 | K=32 |
| :--- | :--- | :--- | :--- |
| Full working copy (`clone_full` vs `checkout_full`) | linux-worker-a | 0.82 / 0.70 | skipped / skipped |
| | linux-worker-b | 0.85 / 0.88 | skipped / skipped |
| | linux-worker-c | not run | 0.93 / 0.91 |
| | macos-laptop-a | 0.74 | skipped |
| One service directory (`clone_sparse` vs `checkout_sparse`) | linux-worker-a | 3.78 / 4.19 | 9.31 / 9.90 |
| | linux-worker-b | 7.06 / 5.22 | 10.93 / 11.72 |
| | linux-worker-c | not run | 6.59 / 6.80 |
| | macos-laptop-a | 2.74 | 1.12 |
| Cheapest working copy (`worktree_add` vs `mount`) | linux-worker-a | 48.01 / 52.38 | 428.08 / 772.79 |
| | linux-worker-b | 33.16 / 45.43 | 128.45 / 139.62 |
| | linux-worker-c | not run | 35.98 / 35.82 |
| | macos-laptop-a | 91.05 | 2376.71 |
| `K` concurrent single-file landings (`push_rebase` vs `serve_land`) | linux-worker-a | 0.73 / 0.74 | 29.49 / 51.31 |
| | linux-worker-b | 0.79 / 0.67 | 9.80 / 9.21 |
| | linux-worker-c | not run | not run |
| | macos-laptop-a | 1.53 / 1.54 | 173.68 / 205.19 |

Where `inr` is faster:

- **Landing many changes at once.** At `K=32`, `serve_land` has a per-agent p50 of 1.0 to 4.6 s on the two shared Linux hosts against 39.5 to 53.4 s for `push_rebase`, and 2.8 to 3.0 s against 526 to 583 s on the laptop. At `K=8` the ratio is 4.15 to 9.77 on the Linux hosts and 36.15 to 38.94 on the laptop.
- **Provisioning a slice or a virtual workspace.** `checkout_sparse` is 3.8 to 7.1 times faster than `clone_sparse` at `K=1` and 6.6 to 11.7 times faster at `K=32` on the Linux hosts. `mount` is 33 to 91 times faster than `worktree_add` at `K=1` and 36 to 2,377 times faster at `K=32`. `mount` writes no file blobs, so this compares provisioning cost, not the cost of reading the files afterwards.

Where `inr` is slower or only level:

- **Full working copy.** `checkout_full` is slower than `clone_full` in 12 of the 14 (run, `K`) cells where both ran. In the other two it is ahead by 18% and 3% (`linux-worker-a` run A at `K=8`, `linux-worker-b` run A at `K=8`). At `K=1` it takes 1.1 to 1.4 times as long as `git clone` on every host. At `K=32` on `linux-worker-c`, the only host where it ran, it takes 17.4 s against 16.2 s for `clone_full` and 10.1 s for `worktree_add`.
- **Memory per process.** Peak resident memory of `checkout_full` is 430 to 449 MiB per process against 42 to 51 MiB for `clone_full` and 45 to 53 MiB for `worktree_add`, roughly nine to ten times more. This is why the memory-fit guard skipped the cell wherever memory was limited (section 7.4).
- **Recording one change.** `commit_full`, which scans all 50,000 files, takes 795 to 1,512 ms against 62 to 162 ms for Git's `add -A` plus `commit` (`commit_scan`), roughly 9 to 13 times as long. `commit_sparse` takes 92 to 157 ms on the Linux hosts against 35 to 72 ms for `commit_path`, 1.9 to 2.6 times as long, and 95 ms against 90 ms on the laptop.
- **Landing one change.** At `K=1` on the Linux hosts `serve_land` takes 1.3 to 1.5 times as long as `push_rebase` (79 to 119 ms against 58 to 90 ms). On the laptop it is faster, at 91 ms against 139 to 140 ms.
- **Sparse checkout on the laptop at larger `K`.** `checkout_sparse` is only 1.09 and 1.12 times faster than `clone_sparse` at `K=16` and `K=32`.

What went wrong for Git or for the harness:

- Git's `worktree_add` had 17 failed agents out of 1,760 sampled at `K` of 16 or 32 across the four hosts, all exit code 128 (`linux-worker-a` 1 and 2, `linux-worker-c` 3, `macos-laptop-a` 8 and 3). No `inr` agent failed in any measured cell. Latency percentiles cover successful agents only (section 3.4), so these cells exclude the failed `worktree_add` agents. The logs show `fatal: failed to read .git/worktrees/<agent>/commondir` and `fatal: '<work>/prov-git-worktree_add/<agent>' is not a working tree` on both Linux and macOS. This campaign did not isolate the cause.
- 9 cells were skipped by the memory-fit guard and one landing cell was only partly measured (3 of 5 trials). Section 7.4 lists them.
- Run-to-run agreement is poor on the two shared Linux hosts (section 7.4), so their individual ratios indicate order of magnitude and direction, not precise factors.
| `benchmarks/README.md` | Quick-start guide for running and verifying benchmarks |
| `benchmarks/REPORT.md` | Methodology, architectural tradeoffs, and reproduction guide |
