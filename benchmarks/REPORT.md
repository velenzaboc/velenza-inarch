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
| `benchmarks/README.md` | Quick-start guide for running and verifying benchmarks |
| `benchmarks/REPORT.md` | Methodology, architectural tradeoffs, and reproduction guide |

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
- **Provisioning a slice or a virtual workspace.** `checkout_sparse` is 3.8 to 7.1 times faster than `clone_sparse` at `K=1` and 6.6 to 11.7 times faster at `K=32` on the Linux hosts. Across the hosts that ran each `K`, `mount` is 33 to 91 times faster than `worktree_add` at `K=1` and 36 to 2,377 times faster at `K=32`. `mount` writes no file blobs up front (section 5.1), so this compares provisioning cost, not the cost of reading the files afterwards.

Where `inr` is slower or only level:

- **Full working copy.** `checkout_full` is slower than `clone_full` in 12 of the 14 (run, `K`) cells where both ran. In the other two it is ahead by 18% and 3% (`linux-worker-a` run A at `K=8`, `linux-worker-b` run A at `K=8`). At `K=1` it takes 1.1 to 1.4 times as long as `git clone` on every host that ran `K=1`. At `K=32` on `linux-worker-c`, the only host where it ran, run A takes 17.4 s against 16.2 s for `clone_full` and 10.1 s for `worktree_add`.
- **Memory per process.** Peak resident memory of `checkout_full` is 430 to 449 MiB per process against 42 to 51 MiB for `clone_full` and 45 to 53 MiB for `worktree_add`, roughly eight to ten times more. This is why the memory-fit guard skipped the cell wherever memory was limited (section 7.4). The other `inr` commands that do work also use more memory than the Git commands they are compared with: `commit_full` 148 to 154 MiB against 14 to 18 MiB for `commit_scan`, `commit_sparse` 32 to 38 MiB against 14 to 18 MiB for `commit_path`, and `serve_land` 27 to 29 MiB at `K=1` and 57 to 59 MiB at `K` of 8 or more against 14 to 19 MiB and 28 to 33 MiB for `push_rebase`. Only `checkout_sparse` (12 to 13 MiB) and `mount` (14 to 16 MiB) use less than the Git provisioning commands.
- **Recording one change.** `commit_full`, which scans all 50,000 files, takes 795 to 1,512 ms against 62 to 162 ms for Git's `add -A` plus `commit` (`commit_scan`), roughly 9 to 13 times as long. `commit_sparse` takes 92 to 157 ms on the Linux hosts against 35 to 72 ms for `commit_path`, 1.9 to 2.6 times as long, and 95 ms against 90 ms on the laptop.
- **Landing one change.** At `K=1` on the Linux hosts `serve_land` takes 1.3 to 1.5 times as long as `push_rebase` (79 to 119 ms against 58 to 90 ms). On the laptop it is faster, at 91 ms against 139 to 140 ms.
- **Sparse checkout on the laptop at larger `K`.** `checkout_sparse` is only 1.09 and 1.12 times faster than `clone_sparse` at `K=16` and `K=32`.

What went wrong for Git or for the harness:

- Git's `worktree_add` had 17 failed agents out of 1,520 sampled at `K` of 16 or 32 across the four hosts, all exit code 128 (`linux-worker-a` 1 and 2, `linux-worker-c` 3, `macos-laptop-a` 8 and 3). No `inr` agent failed in any measured cell. Latency percentiles cover successful agents only (section 3.4), so these cells exclude the failed `worktree_add` agents. The logs show `fatal: failed to read .git/worktrees/<agent>/commondir` and `fatal: '<work>/prov-git-worktree_add/<agent>' is not a working tree` on both Linux and macOS. This campaign did not isolate the cause.
- The memory-fit guard skipped 8 cells entirely, all `checkout_full`, and 2 of the 5 trials of one `serve_land` cell. Section 7.4 lists them.
- Run-to-run agreement is uneven on the shared Linux hosts: only 18 of 35 and 8 of 35 comparable cells agree within 10%, and the largest gap between two runs is a factor of 3.1 (section 7.4). Their individual ratios therefore indicate order of magnitude and direction, not precise factors.

### 7.2 Hosts and runs

The tables from here to the end of section 7.4 are the output of `benchmarks/report-tables.py` over the eight result sets, in the order `linux-worker-a` A and B, `linux-worker-b` A and B, `linux-worker-c` A and B, `macos-laptop-a` A and B, with the renderer's headings moved down one level; the prose around them is written for this report. Tables show run A / run B in one cell where a host ran twice. Host labels are neutral by design (section 3.5).

Conditions that affect how far the numbers can be trusted:

- `linux-worker-a` and `linux-worker-b` are shared machines. Before its runs began `linux-worker-a` already had a 1-minute load of 8.5 and 16.9, so other work was running; the 1-minute load at the end of the four runs was 15 to 25. Both have cgroup memory limits (11.0 GiB and 5.0 GiB of the physical memory), which is what triggers the memory-fit guard.
- `linux-worker-c` is the only host with ample memory and no cgroup limit (about 27 GiB available), but it ran `provision` at `K=32` only.
- `macos-laptop-a` is a laptop on AC power with a 1-minute load of 18.1 at the start of run A. Its runs took 5 h 6 min and 1 h 59 min and ended with 15-minute load averages of 117.6 and 113.1 on 10 cores.
- No host was dedicated to the campaign, so absolute times are not comparable between hosts. Git and `inr` cells of one run were measured in the same run but not at the same moment, so a change in background load during a run can favour one side of a pair. Section 7.4 gives the run-to-run agreement.

|  | linux-worker-a | linux-worker-b | linux-worker-c | macos-laptop-a |
| :--- | :--- | :--- | :--- | :--- |
| OS | Debian GNU/Linux 13 (trixie) | Ubuntu 26.04.1 LTS | Ubuntu 26.04.1 LTS | macOS 27.0.1 (26A434) |
| Kernel | 6.12.111+deb13-amd64 | 7.0.0-34-generic | 7.0.0-34-generic | 27.0.0 |
| Architecture | x86_64 | x86_64 | x86_64 | arm64 |
| CPU | AMD Ryzen 9 5900X 12-Core Processor | Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz | 11th Gen Intel(R) Core(TM) i7-1195G7 @ 2.90GHz | Apple M1 Pro (8 performance + 2 efficiency cores) |
| Cores (logical / physical) | 24 / 12 | 8 / 4 | 8 / 4 | 10 / 10 |
| Memory | 31.3 GiB | 14.8 GiB | 30.6 GiB | 16.0 GiB |
| Memory cgroup limit | 11.0 GiB | 5.0 GiB | none | none |
| Power / low-power mode | n/a / n/a | n/a / n/a | n/a / n/a | AC Power / 0 |
| Scratch filesystem | ext4 | ext4 | ext4 | apfs |
| git | 2.47.3 | 2.53.0 | 2.53.0 | 2.56.0 |
| inr source revision | c15d5e5558bf | c15d5e5558bf | c15d5e5558bf | c15d5e5558bf |
| inr binary SHA-256 (prefix) | f4281ffcdcd4e40f | ff7cbe5619cef338 | f4281ffcdcd4e40f | 1dd38ec46c4e50f6 |
| rustc | rustc 1.99.1 (58cf8f9c3 2026-10-13) | rustc 1.99.1 (58cf8f9c3 2026-10-13) | unavailable | rustc 1.98.1 (48a229cea 2026-09-01) (Homebrew) |
| bash / awk / python | 5.2.37(1)-release / mawk 1.3.4 20250131 / Python 3.13.5 | 5.3.9(1)-release / GNU Awk 5.3.2, API 4.0, PMA Avon 8-g1, (GNU MPFR 4.2.2, GNU MP 6.3.0) / Python 3.14.4 | 5.3.9(1)-release / GNU Awk 5.3.2, API 4.0, PMA Avon 8-g1, (GNU MPFR 4.2.2, GNU MP 6.3.0) / Python 3.14.4 | 5.3.20(1)-release / awk version 20200816 / Python 3.14.7 |
| bench-vs-git.sh SHA-256 (prefix) | 52d477d26dd49c84 | 52d477d26dd49c84 | 52d477d26dd49c84 | 52d477d26dd49c84 |
| measure.py SHA-256 (prefix) | b8fb1cf8c71736b7 | b8fb1cf8c71736b7 | b8fb1cf8c71736b7 | b8fb1cf8c71736b7 |

| Host | Run | Result set | inr revision | Covers | Started (UTC) | Duration | Load 1/5/15 at start | Load 1/5/15 at end | Memory available to the process at start | Free disk at start |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| linux-worker-a | A | `20261021T023424Z-n50000` | c15d5e5558bf | provision, commit, land (K 1, 8, 16, 32) | 2026-10-21T02:34:24Z | 0h 46m | 8.52 8.00 8.06 | 19.32 28.08 27.84 | 3.7 GiB | 185.8 GiB |
| linux-worker-a | B | `20261021T032119Z-n50000` | c15d5e5558bf | provision, commit, land (K 1, 8, 16, 32) | 2026-10-21T03:21:19Z | 0h 52m | 16.89 26.75 27.40 | 19.59 28.92 25.14 | 5.3 GiB | 185.6 GiB |
| linux-worker-b | A | `20261021T022647Z-n50000` | c15d5e5558bf | provision, commit, land (K 1, 8, 16, 32) | 2026-10-21T02:26:47Z | 0h 51m | 2.15 2.02 2.22 | 15.30 28.19 25.25 | 2.3 GiB | 88.1 GiB |
| linux-worker-b | B | `20261021T032742Z-n50000` | c15d5e5558bf | provision, commit, land (K 1, 8, 16, 32) | 2026-10-21T03:27:42Z | 0h 43m | 1.51 4.96 14.03 | 24.59 32.31 25.56 | 3.9 GiB | 88.1 GiB |
| linux-worker-c | A | `20261021T022252Z-n50000` | c15d5e5558bf | provision (K 32) | 2026-10-21T02:22:52Z | 0h 11m | 1.41 3.23 3.57 | 11.88 16.07 11.14 | 27.1 GiB | 288.7 GiB |
| linux-worker-c | B | `20261021T024201Z-n50000` | c15d5e5558bf | provision (K 32) | 2026-10-21T02:42:01Z | 0h 11m | 0.66 3.50 6.72 | 14.93 17.06 13.03 | 26.9 GiB | 288.7 GiB |
| macos-laptop-a | A | `20261021T022321Z-n50000` | c15d5e5558bf | provision, commit, land (K 1, 8, 16, 32) | 2026-10-21T02:23:21Z | 5h 06m | 18.14 6.81 3.64 | 6.05 59.39 117.61 | 5.8 GiB | 46.0 GiB |
| macos-laptop-a | B | `20261021T074706Z-n50000` | c15d5e5558bf | land (K 1, 8, 16, 32) | 2026-10-21T07:47:06Z | 1h 59m | 5.14 5.83 34.77 | 8.57 55.15 113.08 | 6.3 GiB | 44.0 GiB |

### 7.3 Results per host

Latencies are per-agent and batch wall-clock times in milliseconds, and `peak RSS p50 MiB` is the peak resident memory of one agent process. `failures/samples` counts agents that exited non-zero against agents sampled; latency and memory statistics cover successful agents only.

#### linux-worker-a

##### provision on linux-worker-a (runs A / B)

| System | Variant | K | agent p50 ms | agent p95 ms | batch p50 ms | peak RSS p50 MiB | failures/samples |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| git | `clone_full` | 1 | 2,298 / 1,958 | 2,574 / 1,997 | 2,323 / 1,982 | 44 / 44 | 0/5 / 0/5 |
| git | `clone_full` | 8 | 11,288 / 3,587 | 12,480 / 3,824 | 11,819 / 3,731 | 43 / 45 | 0/40 / 0/40 |
| git | `clone_full` | 16 | 24,318 / 21,876 | 30,003 / 28,249 | 26,445 / 22,716 | 43 / 44 | 0/80 / 0/80 |
| git | `clone_full` | 32 | 52,102 / 61,612 | 151,774 / 70,529 | 53,739 / 65,464 | 42 / 43 | 0/160 / 0/160 |
| git | `clone_sparse` | 1 | 220 / 225 | 223 / 318 | 240 / 246 | 23 / 22 | 0/5 / 0/5 |
| git | `clone_sparse` | 8 | 375 / 391 | 410 / 408 | 431 / 426 | 20 / 20 | 0/40 / 0/40 |
| git | `clone_sparse` | 16 | 616 / 616 | 1,230 / 673 | 699 / 704 | 21 / 21 | 0/80 / 0/80 |
| git | `clone_sparse` | 32 | 1,073 / 1,078 | 4,530 / 1,488 | 1,256 / 1,226 | 21 / 21 | 0/160 / 0/160 |
| git | `worktree_add` | 1 | 1,723 / 1,818 | 1,822 / 2,149 | 1,744 / 1,842 | 46 / 46 | 0/5 / 0/5 |
| git | `worktree_add` | 8 | 11,174 / 10,433 | 13,275 / 12,132 | 11,424 / 10,650 | 46 / 46 | 0/40 / 0/40 |
| git | `worktree_add` | 16 | 16,984 / 25,370 | 25,473 / 30,334 | 17,671 / 28,356 | 46 / 45 | 0/80 / 0/80 |
| git | `worktree_add` | 32 | 34,114 / 60,124 | 63,950 / 70,933 | 40,355 / 63,636 | 45 / 45 | 1/160 (rc 128x1) / 2/160 (rc 128x2) |
| inr | `checkout_full` | 1 | 2,790 / 2,787 | 2,799 / 3,075 | 2,811 / 2,808 | 431 / 431 | 0/5 / 0/5 |
| inr | `checkout_full` | 8 | 9,605 / 13,965 | 10,417 / 18,987 | 10,232 / 14,233 | 432 / 431 | 0/40 / 0/40 |
| inr | `checkout_full` | 16 | skipped / 29,877 | skipped / 47,036 | skipped / 30,044 | skipped / 430 | skipped / 0/80 |
| inr | `checkout_full` | 32 | skipped / skipped | skipped / skipped | skipped / skipped | skipped / skipped | skipped / skipped |
| inr | `checkout_sparse` | 1 | 58.2 / 53.8 | 59.5 / 63.5 | 79.3 / 74.5 | 12 / 12 | 0/5 / 0/5 |
| inr | `checkout_sparse` | 8 | 63.9 / 63.4 | 225 / 767 | 102 / 108 | 12 / 12 | 0/40 / 0/40 |
| inr | `checkout_sparse` | 16 | 81.6 / 75.6 | 718 / 624 | 141 / 108 | 12 / 12 | 0/80 / 0/80 |
| inr | `checkout_sparse` | 32 | 115 / 109 | 661 / 262 | 247 / 212 | 12 / 12 | 0/160 / 0/160 |
| inr | `mount` | 1 | 35.9 / 34.7 | 46.8 / 37.2 | 57.6 / 55.1 | 14 / 14 | 0/5 / 0/5 |
| inr | `mount` | 8 | 41.4 / 36.2 | 53.5 / 44.7 | 79.3 / 64.4 | 14 / 14 | 0/40 / 0/40 |
| inr | `mount` | 16 | 57.4 / 56.1 | 66.0 / 97.6 | 96.2 / 90.7 | 14 / 14 | 0/80 / 0/80 |
| inr | `mount` | 32 | 79.7 / 77.8 | 143 / 111 | 194 / 161 | 14 / 14 | 0/160 / 0/160 |

##### commit on linux-worker-a (runs A / B)

| System | Variant | p50 ms | min ms | max ms | peak RSS p50 MiB | failures/samples |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| git | `commit_path` | 48.9 / 34.8 | 44.4 / 33.7 | 258 / 39.1 | 14 / 15 | 0/5 / 0/5 |
| git | `commit_scan` | 76.7 / 61.6 | 71.9 / 56.3 | 448 / 63.1 | 14 / 15 | 0/5 / 0/5 |
| git | `commit_scan_push` | 113 / 89.3 | 101 / 88.9 | 327 / 97.3 | 14 / 15 | 0/5 / 0/5 |
| inr | `commit_full` | 850 / 795 | 822 / 791 | 982 / 826 | 148 / 148 | 0/5 / 0/5 |
| inr | `commit_sparse` | 105 / 91.8 | 98.0 / 89.5 | 278 / 104 | 32 / 32 | 0/5 / 0/5 |

##### land on linux-worker-a (runs A / B)

| System | Variant | K | agent p50 ms | agent p95 ms | batch p50 ms | peak RSS p50 MiB | failures/samples | landed per batch |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| git | `push_rebase` | 1 | 59.5 / 58.1 | 62.4 / 104 | 80.7 / 77.7 | 14 / 15 | 0/5 / 0/5 | 1.0/1 / 1.0/1 |
| git | `push_rebase` | 8 | 2,970 / 2,917 | 4,946 / 5,512 | 4,739 / 3,992 | 32 / 32 | 0/40 / 0/40 | 8.0/8 / 8.0/8 |
| git | `push_rebase` | 16 | 12,522 / 13,823 | 18,968 / 19,899 | 17,663 / 19,003 | 31 / 32 | 0/80 / 0/80 | 16.0/16 / 16.0/16 |
| git | `push_rebase` | 32 | 47,238 / 53,367 | 67,646 / 77,654 | 66,496 / 73,386 | 30 / 32 | 0/160 / 0/160 | 32.0/32 / 32.0/32 |
| inr | `serve_land` | 1 | 81.5 / 78.8 | 88.8 / 86.9 | 101 / 98.1 | 27 / 27 | 0/5 / 0/5 | 1.0/1 / 1.0/1 |
| inr | `serve_land` | 8 | 374 / 298 | 644 / 485 | 431 / 353 | 57 / 57 | 0/40 / 0/40 | 8.0/8 / 8.0/8 |
| inr | `serve_land` | 16 | 589 / 482 | 780 / 674 | 835 / 696 | 57 / 57 | 0/80 / 0/80 | 16.0/16 / 16.0/16 |
| inr | `serve_land` | 32 | 1,602 / 1,040 | 3,472 / 2,230 | 2,041 / 1,514 | 58 / 58 | 0/96 (3 of 5 trials, rest skipped) / 0/160 | 32.0/32 / 32.0/32 |

##### git versus inr on linux-worker-a (git p50 divided by inr p50; above 1 means inr is faster)

| Pair | What | K | Runs | git p50 ms | inr p50 ms | agent ratio | batch ratio |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `clone_full` vs `checkout_full` | full working copy | 1 | A / B | 2,298 / 1,958 | 2,790 / 2,787 | 0.82 / 0.70 | 0.83 / 0.71 |
| `clone_full` vs `checkout_full` | full working copy | 8 | A / B | 11,288 / 3,587 | 9,605 / 13,965 | 1.18 / 0.26 | 1.16 / 0.26 |
| `clone_full` vs `checkout_full` | full working copy | 16 | A / B | 24,318 / 21,876 | skipped / 29,877 | skipped / 0.73 | skipped / 0.76 |
| `clone_full` vs `checkout_full` | full working copy | 32 | A / B | 52,102 / 61,612 | skipped / skipped | skipped / skipped | skipped / skipped |
| `clone_sparse` vs `checkout_sparse` | one service directory | 1 | A / B | 220 / 225 | 58.2 / 53.8 | 3.78 / 4.19 | 3.03 / 3.31 |
| `clone_sparse` vs `checkout_sparse` | one service directory | 8 | A / B | 375 / 391 | 63.9 / 63.4 | 5.87 / 6.16 | 4.23 / 3.92 |
| `clone_sparse` vs `checkout_sparse` | one service directory | 16 | A / B | 616 / 616 | 81.6 / 75.6 | 7.55 / 8.15 | 4.96 / 6.49 |
| `clone_sparse` vs `checkout_sparse` | one service directory | 32 | A / B | 1,073 / 1,078 | 115 / 109 | 9.31 / 9.90 | 5.09 / 5.79 |
| `worktree_add` vs `mount` | cheapest working copy each side | 1 | A / B | 1,723 / 1,818 | 35.9 / 34.7 | 48.01 / 52.38 | 30.30 / 33.40 |
| `worktree_add` vs `mount` | cheapest working copy each side | 8 | A / B | 11,174 / 10,433 | 41.4 / 36.2 | 270.20 / 287.90 | 144.00 / 165.47 |
| `worktree_add` vs `mount` | cheapest working copy each side | 16 | A / B | 16,984 / 25,370 | 57.4 / 56.1 | 296.02 / 452.58 | 183.75 / 312.80 |
| `worktree_add` vs `mount` | cheapest working copy each side | 32 | A / B | 34,114 / 60,124 | 79.7 / 77.8 | 428.08 / 772.79 | 208.35 / 394.30 |
| `clone_full` vs `mount` | full clone vs virtual mount | 1 | A / B | 2,298 / 1,958 | 35.9 / 34.7 | 64.03 / 56.40 | 40.37 / 35.94 |
| `clone_full` vs `mount` | full clone vs virtual mount | 8 | A / B | 11,288 / 3,587 | 41.4 / 36.2 | 272.97 / 98.97 | 148.98 / 57.97 |
| `clone_full` vs `mount` | full clone vs virtual mount | 16 | A / B | 24,318 / 21,876 | 57.4 / 56.1 | 423.86 / 390.24 | 274.98 / 250.58 |
| `clone_full` vs `mount` | full clone vs virtual mount | 32 | A / B | 52,102 / 61,612 | 79.7 / 77.8 | 653.80 / 791.90 | 277.46 / 405.63 |
| `push_rebase` vs `serve_land` | K concurrent single-file landings | 1 | A / B | 59.5 / 58.1 | 81.5 / 78.8 | 0.73 / 0.74 | 0.79 / 0.79 |
| `push_rebase` vs `serve_land` | K concurrent single-file landings | 8 | A / B | 2,970 / 2,917 | 374 / 298 | 7.93 / 9.77 | 11.00 / 11.32 |
| `push_rebase` vs `serve_land` | K concurrent single-file landings | 16 | A / B | 12,522 / 13,823 | 589 / 482 | 21.25 / 28.67 | 21.15 / 27.29 |
| `push_rebase` vs `serve_land` | K concurrent single-file landings | 32 | A / B | 47,238 / 53,367 | 1,602 / 1,040 | 29.49 / 51.31 | 32.59 / 48.49 |

#### linux-worker-b

##### provision on linux-worker-b (runs A / B)

| System | Variant | K | agent p50 ms | agent p95 ms | batch p50 ms | peak RSS p50 MiB | failures/samples |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| git | `clone_full` | 1 | 3,203 / 2,758 | 4,314 / 3,455 | 3,246 / 2,788 | 46 / 46 | 0/5 / 0/5 |
| git | `clone_full` | 8 | 11,750 / 7,371 | 14,117 / 9,478 | 12,651 / 7,550 | 46 / 46 | 0/40 / 0/40 |
| git | `clone_full` | 16 | 24,365 / 18,016 | 44,514 / 22,272 | 27,328 / 19,741 | 46 / 46 | 0/80 / 0/80 |
| git | `clone_full` | 32 | 61,530 / 47,442 | 70,861 / 83,323 | 70,562 / 53,537 | 45 / 46 | 0/160 / 0/160 |
| git | `clone_sparse` | 1 | 493 / 327 | 571 / 412 | 524 / 359 | 23 / 23 | 0/5 / 0/5 |
| git | `clone_sparse` | 8 | 1,410 / 740 | 3,259 / 2,568 | 1,591 / 834 | 22 / 22 | 0/40 / 0/40 |
| git | `clone_sparse` | 16 | 1,729 / 3,230 | 3,759 / 3,558 | 2,025 / 3,420 | 22 / 22 | 0/80 / 0/80 |
| git | `clone_sparse` | 32 | 4,168 / 3,466 | 6,564 / 5,595 | 5,490 / 4,191 | 22 / 22 | 0/160 / 0/160 |
| git | `worktree_add` | 1 | 2,076 / 2,368 | 2,184 / 2,491 | 2,108 / 2,407 | 48 / 48 | 0/5 / 0/5 |
| git | `worktree_add` | 8 | 8,762 / 5,886 | 12,299 / 9,864 | 9,280 / 6,177 | 48 / 48 | 0/40 / 0/40 |
| git | `worktree_add` | 16 | 15,918 / 13,728 | 22,729 / 17,454 | 21,164 / 16,225 | 47 / 48 | 0/80 / 0/80 |
| git | `worktree_add` | 32 | 46,396 / 43,959 | 55,491 / 53,562 | 54,401 / 50,050 | 47 / 48 | 0/160 / 0/160 |
| inr | `checkout_full` | 1 | 3,762 / 3,123 | 3,915 / 3,251 | 3,797 / 3,152 | 433 / 433 | 0/5 / 0/5 |
| inr | `checkout_full` | 8 | 11,463 / 11,246 | 26,388 / 17,324 | 12,452 / 11,481 | 432 / 432 | 0/40 / 0/40 |
| inr | `checkout_full` | 16 | skipped / skipped | skipped / skipped | skipped / skipped | skipped / skipped | skipped / skipped |
| inr | `checkout_full` | 32 | skipped / skipped | skipped / skipped | skipped / skipped | skipped / skipped | skipped / skipped |
| inr | `checkout_sparse` | 1 | 69.9 / 62.7 | 74.4 / 63.0 | 103 / 92.2 | 12 / 12 | 0/5 / 0/5 |
| inr | `checkout_sparse` | 8 | 138 / 110 | 187 / 134 | 236 / 184 | 12 / 12 | 0/40 / 0/40 |
| inr | `checkout_sparse` | 16 | 209 / 196 | 418 / 290 | 410 / 359 | 12 / 12 | 0/80 / 0/80 |
| inr | `checkout_sparse` | 32 | 381 / 296 | 793 / 447 | 1,005 / 667 | 12 / 12 | 0/160 / 0/160 |
| inr | `mount` | 1 | 62.6 / 52.1 | 82.0 / 53.9 | 98.8 / 81.4 | 14 / 14 | 0/5 / 0/5 |
| inr | `mount` | 8 | 123 / 98.2 | 153 / 103 | 209 / 155 | 14 / 14 | 0/40 / 0/40 |
| inr | `mount` | 16 | 221 / 186 | 297 / 249 | 405 / 341 | 14 / 14 | 0/80 / 0/80 |
| inr | `mount` | 32 | 361 / 315 | 646 / 499 | 819 / 674 | 14 / 14 | 0/160 / 0/160 |

##### commit on linux-worker-b (runs A / B)

| System | Variant | p50 ms | min ms | max ms | peak RSS p50 MiB | failures/samples |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| git | `commit_path` | 72.3 / 63.7 | 62.0 / 58.9 | 78.8 / 74.0 | 15 / 15 | 0/5 / 0/5 |
| git | `commit_scan` | 120 / 99.2 | 117 / 93.6 | 153 / 480 | 15 / 15 | 0/5 / 0/5 |
| git | `commit_scan_push` | 205 / 137 | 146 / 134 | 215 / 219 | 15 / 15 | 0/5 / 0/5 |
| inr | `commit_full` | 1,126 / 983 | 1,020 / 929 | 1,198 / 1,051 | 149 / 149 | 0/5 / 0/5 |
| inr | `commit_sparse` | 157 / 123 | 126 / 120 | 225 / 125 | 33 / 33 | 0/5 / 0/5 |

##### land on linux-worker-b (runs A / B)

| System | Variant | K | agent p50 ms | agent p95 ms | batch p50 ms | peak RSS p50 MiB | failures/samples | landed per batch |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| git | `push_rebase` | 1 | 90.1 / 79.2 | 103 / 89.5 | 119 / 108 | 15 / 15 | 0/5 / 0/5 | 1.0/1 / 1.0/1 |
| git | `push_rebase` | 8 | 2,756 / 3,317 | 4,094 / 4,710 | 4,011 / 4,586 | 33 / 33 | 0/40 / 0/40 | 8.0/8 / 8.0/8 |
| git | `push_rebase` | 16 | 10,019 / 9,589 | 15,219 / 15,049 | 15,406 / 15,288 | 32 / 32 | 0/80 / 0/80 | 16.0/16 / 16.0/16 |
| git | `push_rebase` | 32 | 45,186 / 39,543 | 76,354 / 64,175 | 76,296 / 58,849 | 31 / 31 | 0/160 / 0/160 | 32.0/32 / 32.0/32 |
| inr | `serve_land` | 1 | 114 / 119 | 159 / 204 | 143 / 147 | 28 / 28 | 0/5 / 0/5 | 1.0/1 / 1.0/1 |
| inr | `serve_land` | 8 | 664 / 618 | 1,048 / 1,037 | 775 / 700 | 58 / 58 | 0/40 / 0/40 | 8.0/8 / 8.0/8 |
| inr | `serve_land` | 16 | 1,454 / 1,420 | 1,903 / 2,376 | 1,737 / 1,738 | 58 / 58 | 0/80 / 0/80 | 16.0/16 / 16.0/16 |
| inr | `serve_land` | 32 | 4,609 / 4,292 | 9,988 / 5,490 | 6,018 / 5,025 | 59 / 58 | 0/160 / 0/160 | 32.0/32 / 32.0/32 |

##### git versus inr on linux-worker-b (git p50 divided by inr p50; above 1 means inr is faster)

| Pair | What | K | Runs | git p50 ms | inr p50 ms | agent ratio | batch ratio |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `clone_full` vs `checkout_full` | full working copy | 1 | A / B | 3,203 / 2,758 | 3,762 / 3,123 | 0.85 / 0.88 | 0.86 / 0.88 |
| `clone_full` vs `checkout_full` | full working copy | 8 | A / B | 11,750 / 7,371 | 11,463 / 11,246 | 1.03 / 0.66 | 1.02 / 0.66 |
| `clone_full` vs `checkout_full` | full working copy | 16 | A / B | 24,365 / 18,016 | skipped / skipped | skipped / skipped | skipped / skipped |
| `clone_full` vs `checkout_full` | full working copy | 32 | A / B | 61,530 / 47,442 | skipped / skipped | skipped / skipped | skipped / skipped |
| `clone_sparse` vs `checkout_sparse` | one service directory | 1 | A / B | 493 / 327 | 69.9 / 62.7 | 7.06 / 5.22 | 5.07 / 3.89 |
| `clone_sparse` vs `checkout_sparse` | one service directory | 8 | A / B | 1,410 / 740 | 138 / 110 | 10.22 / 6.74 | 6.74 / 4.54 |
| `clone_sparse` vs `checkout_sparse` | one service directory | 16 | A / B | 1,729 / 3,230 | 209 / 196 | 8.27 / 16.48 | 4.95 / 9.53 |
| `clone_sparse` vs `checkout_sparse` | one service directory | 32 | A / B | 4,168 / 3,466 | 381 / 296 | 10.93 / 11.72 | 5.46 / 6.29 |
| `worktree_add` vs `mount` | cheapest working copy each side | 1 | A / B | 2,076 / 2,368 | 62.6 / 52.1 | 33.16 / 45.43 | 21.33 / 29.56 |
| `worktree_add` vs `mount` | cheapest working copy each side | 8 | A / B | 8,762 / 5,886 | 123 / 98.2 | 71.26 / 59.95 | 44.39 / 39.88 |
| `worktree_add` vs `mount` | cheapest working copy each side | 16 | A / B | 15,918 / 13,728 | 221 / 186 | 72.11 / 73.93 | 52.22 / 47.54 |
| `worktree_add` vs `mount` | cheapest working copy each side | 32 | A / B | 46,396 / 43,959 | 361 / 315 | 128.45 / 139.62 | 66.43 / 74.29 |
| `clone_full` vs `mount` | full clone vs virtual mount | 1 | A / B | 3,203 / 2,758 | 62.6 / 52.1 | 51.16 / 52.91 | 32.85 / 34.25 |
| `clone_full` vs `mount` | full clone vs virtual mount | 8 | A / B | 11,750 / 7,371 | 123 / 98.2 | 95.56 / 75.07 | 60.52 / 48.75 |
| `clone_full` vs `mount` | full clone vs virtual mount | 16 | A / B | 24,365 / 18,016 | 221 / 186 | 110.38 / 97.03 | 67.43 / 57.84 |
| `clone_full` vs `mount` | full clone vs virtual mount | 32 | A / B | 61,530 / 47,442 | 361 / 315 | 170.34 / 150.68 | 86.16 / 79.47 |
| `push_rebase` vs `serve_land` | K concurrent single-file landings | 1 | A / B | 90.1 / 79.2 | 114 / 119 | 0.79 / 0.67 | 0.83 / 0.74 |
| `push_rebase` vs `serve_land` | K concurrent single-file landings | 8 | A / B | 2,756 / 3,317 | 664 / 618 | 4.15 / 5.37 | 5.17 / 6.55 |
| `push_rebase` vs `serve_land` | K concurrent single-file landings | 16 | A / B | 10,019 / 9,589 | 1,454 / 1,420 | 6.89 / 6.75 | 8.87 / 8.79 |
| `push_rebase` vs `serve_land` | K concurrent single-file landings | 32 | A / B | 45,186 / 39,543 | 4,609 / 4,292 | 9.80 / 9.21 | 12.68 / 11.71 |

#### linux-worker-c

##### provision on linux-worker-c (runs A / B)

| System | Variant | K | agent p50 ms | agent p95 ms | batch p50 ms | peak RSS p50 MiB | failures/samples |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| git | `clone_full` | 32 | 16,188 / 15,712 | 21,263 / 24,783 | 17,304 / 16,389 | 46 / 46 | 0/160 / 0/160 |
| git | `clone_sparse` | 32 | 1,786 / 1,817 | 1,939 / 1,921 | 2,068 / 2,048 | 22 / 22 | 0/160 / 0/160 |
| git | `worktree_add` | 32 | 10,105 / 9,885 | 10,870 / 10,830 | 10,858 / 10,703 | 48 / 48 | 0/160 / 3/160 (rc 128x3) |
| inr | `checkout_full` | 32 | 17,380 / 17,314 | 18,621 / 20,270 | 18,206 / 19,133 | 433 / 433 | 0/160 / 0/160 |
| inr | `checkout_sparse` | 32 | 271 / 267 | 346 / 555 | 465 / 457 | 13 / 13 | 0/160 / 0/160 |
| inr | `mount` | 32 | 281 / 276 | 349 / 335 | 479 / 474 | 15 / 15 | 0/160 / 0/160 |

##### git versus inr on linux-worker-c (git p50 divided by inr p50; above 1 means inr is faster)

| Pair | What | K | Runs | git p50 ms | inr p50 ms | agent ratio | batch ratio |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `clone_full` vs `checkout_full` | full working copy | 32 | A / B | 16,188 / 15,712 | 17,380 / 17,314 | 0.93 / 0.91 | 0.95 / 0.86 |
| `clone_sparse` vs `checkout_sparse` | one service directory | 32 | A / B | 1,786 / 1,817 | 271 / 267 | 6.59 / 6.80 | 4.45 / 4.48 |
| `worktree_add` vs `mount` | cheapest working copy each side | 32 | A / B | 10,105 / 9,885 | 281 / 276 | 35.98 / 35.82 | 22.69 / 22.60 |
| `clone_full` vs `mount` | full clone vs virtual mount | 32 | A / B | 16,188 / 15,712 | 281 / 276 | 57.65 / 56.94 | 36.16 / 34.61 |

#### macos-laptop-a

##### provision on macos-laptop-a (run A)

| System | Variant | K | agent p50 ms | agent p95 ms | batch p50 ms | peak RSS p50 MiB | failures/samples |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| git | `clone_full` | 1 | 3,619 | 3,652 | 3,650 | 51 | 0/5 |
| git | `clone_full` | 8 | 17,710 | 17,903 | 17,883 | 51 | 0/40 |
| git | `clone_full` | 16 | 57,452 | 57,774 | 57,624 | 50 | 0/80 |
| git | `clone_full` | 32 | 236,354 | 245,597 | 236,668 | 50 | 0/160 |
| git | `clone_sparse` | 1 | 276 | 324 | 307 | 26 | 0/5 |
| git | `clone_sparse` | 8 | 671 | 1,001 | 720 | 25 | 0/40 |
| git | `clone_sparse` | 16 | 1,680 | 1,720 | 1,771 | 25 | 0/80 |
| git | `clone_sparse` | 32 | 5,667 | 5,884 | 5,873 | 25 | 0/160 |
| git | `worktree_add` | 1 | 3,173 | 3,347 | 3,205 | 53 | 0/5 |
| git | `worktree_add` | 8 | 16,779 | 17,520 | 16,880 | 53 | 0/40 |
| git | `worktree_add` | 16 | 41,811 | 55,686 | 41,947 | 53 | 8/80 (rc 128x8) |
| git | `worktree_add` | 32 | 237,652 | 240,476 | 238,010 | 53 | 3/160 (rc 128x3) |
| inr | `checkout_full` | 1 | 4,887 | 4,930 | 4,918 | 446 | 0/5 |
| inr | `checkout_full` | 8 | 29,051 | 29,382 | 29,145 | 449 | 0/40 |
| inr | `checkout_full` | 16 | 73,400 | 74,646 | 73,591 | 447 | 0/80 |
| inr | `checkout_full` | 32 | skipped | skipped | skipped | skipped | skipped |
| inr | `checkout_sparse` | 1 | 101 | 103 | 131 | 12 | 0/5 |
| inr | `checkout_sparse` | 8 | 513 | 521 | 555 | 12 | 0/40 |
| inr | `checkout_sparse` | 16 | 1,543 | 1,613 | 1,633 | 12 | 0/80 |
| inr | `checkout_sparse` | 32 | 5,079 | 5,563 | 5,293 | 12 | 0/160 |
| inr | `mount` | 1 | 34.9 | 35.8 | 66.2 | 16 | 0/5 |
| inr | `mount` | 8 | 53.3 | 54.2 | 92.7 | 16 | 0/40 |
| inr | `mount` | 16 | 63.4 | 90.5 | 154 | 16 | 0/80 |
| inr | `mount` | 32 | 100.0 | 194 | 291 | 16 | 0/160 |

##### commit on macos-laptop-a (run A)

| System | Variant | p50 ms | min ms | max ms | peak RSS p50 MiB | failures/samples |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| git | `commit_path` | 89.9 | 87.1 | 92.7 | 18 | 0/5 |
| git | `commit_scan` | 162 | 161 | 163 | 18 | 0/5 |
| git | `commit_scan_push` | 239 | 235 | 240 | 14 | 0/5 |
| inr | `commit_full` | 1,512 | 1,496 | 1,527 | 154 | 0/5 |
| inr | `commit_sparse` | 95.1 | 94.6 | 95.4 | 38 | 0/5 |

##### land on macos-laptop-a (runs A / B)

| System | Variant | K | agent p50 ms | agent p95 ms | batch p50 ms | peak RSS p50 MiB | failures/samples | landed per batch |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| git | `push_rebase` | 1 | 139 / 140 | 144 / 143 | 170 / 171 | 19 / 19 | 0/5 / 0/5 | 1.0/1 / 1.0/1 |
| git | `push_rebase` | 8 | 20,478 / 16,240 | 33,274 / 20,379 | 28,174 / 19,744 | 28 / 28 | 0/40 / 0/40 | 8.0/8 / 8.0/8 |
| git | `push_rebase` | 16 | 112,417 / 115,565 | 142,413 / 146,539 | 141,810 / 141,513 | 29 / 29 | 0/80 / 0/80 | 16.0/16 / 16.0/16 |
| git | `push_rebase` | 32 | 526,348 / 583,354 | 698,947 / 760,394 | 683,873 / 727,512 | 29 / 29 | 0/160 / 0/160 | 32.0/32 / 32.0/32 |
| inr | `serve_land` | 1 | 91.2 / 91.1 | 96.8 / 92.0 | 122 / 122 | 29 / 29 | 0/5 / 0/5 | 1.0/1 / 1.0/1 |
| inr | `serve_land` | 8 | 526 / 449 | 580 / 542 | 610 / 550 | 57 / 57 | 0/40 / 0/40 | 8.0/8 / 8.0/8 |
| inr | `serve_land` | 16 | 937 / 913 | 1,192 / 1,262 | 1,097 / 1,067 | 59 / 58 | 0/80 / 0/80 | 16.0/16 / 16.0/16 |
| inr | `serve_land` | 32 | 3,030 / 2,843 | 5,094 / 5,442 | 3,525 / 3,478 | 59 / 58 | 0/160 / 0/160 | 32.0/32 / 32.0/32 |

##### git versus inr on macos-laptop-a (git p50 divided by inr p50; above 1 means inr is faster)

| Pair | What | K | Runs | git p50 ms | inr p50 ms | agent ratio | batch ratio |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `clone_full` vs `checkout_full` | full working copy | 1 | A | 3,619 | 4,887 | 0.74 | 0.74 |
| `clone_full` vs `checkout_full` | full working copy | 8 | A | 17,710 | 29,051 | 0.61 | 0.61 |
| `clone_full` vs `checkout_full` | full working copy | 16 | A | 57,452 | 73,400 | 0.78 | 0.78 |
| `clone_full` vs `checkout_full` | full working copy | 32 | A | 236,354 | skipped | skipped | skipped |
| `clone_sparse` vs `checkout_sparse` | one service directory | 1 | A | 276 | 101 | 2.74 | 2.34 |
| `clone_sparse` vs `checkout_sparse` | one service directory | 8 | A | 671 | 513 | 1.31 | 1.30 |
| `clone_sparse` vs `checkout_sparse` | one service directory | 16 | A | 1,680 | 1,543 | 1.09 | 1.08 |
| `clone_sparse` vs `checkout_sparse` | one service directory | 32 | A | 5,667 | 5,079 | 1.12 | 1.11 |
| `worktree_add` vs `mount` | cheapest working copy each side | 1 | A | 3,173 | 34.9 | 91.05 | 48.43 |
| `worktree_add` vs `mount` | cheapest working copy each side | 8 | A | 16,779 | 53.3 | 314.61 | 182.18 |
| `worktree_add` vs `mount` | cheapest working copy each side | 16 | A | 41,811 | 63.4 | 659.75 | 272.61 |
| `worktree_add` vs `mount` | cheapest working copy each side | 32 | A | 237,652 | 100.0 | 2376.71 | 818.02 |
| `clone_full` vs `mount` | full clone vs virtual mount | 1 | A | 3,619 | 34.9 | 103.84 | 55.17 |
| `clone_full` vs `mount` | full clone vs virtual mount | 8 | A | 17,710 | 53.3 | 332.07 | 193.00 |
| `clone_full` vs `mount` | full clone vs virtual mount | 16 | A | 57,452 | 63.4 | 906.57 | 374.50 |
| `clone_full` vs `mount` | full clone vs virtual mount | 32 | A | 236,354 | 100.0 | 2363.73 | 813.41 |
| `push_rebase` vs `serve_land` | K concurrent single-file landings | 1 | A / B | 139 / 140 | 91.2 / 91.1 | 1.53 / 1.54 | 1.40 / 1.40 |
| `push_rebase` vs `serve_land` | K concurrent single-file landings | 8 | A / B | 20,478 / 16,240 | 526 / 449 | 38.94 / 36.15 | 46.17 / 35.88 |
| `push_rebase` vs `serve_land` | K concurrent single-file landings | 16 | A / B | 112,417 / 115,565 | 937 / 913 | 119.94 / 126.62 | 129.28 / 132.59 |
| `push_rebase` vs `serve_land` | K concurrent single-file landings | 32 | A / B | 526,348 / 583,354 | 3,030 / 2,843 | 173.68 / 205.19 | 193.99 / 209.20 |

### 7.4 Run-to-run agreement, skipped cells and failed agents

Each host ran its workloads twice, so the second run is a repeat check on the first. Across the two shared Linux hosts the repeat is loose: about half of the comparable cells on `linux-worker-a` and under a quarter on `linux-worker-b` agree within 10%, and single cells moved by up to a factor of 3.1 (`linux-worker-a`, `git/clone_full` at `K=8`, 11.3 s in run A and 3.6 s in run B). `linux-worker-c` repeated to within 3%, and the laptop's `land` cells to within 26%. Every ratio in the section 7.1 table keeps its direction, above or below 1, in every run that measured it.

#### Run-to-run agreement

For every cell measured in two consecutive runs of one host at one inr source revision, the difference of the per-agent p50 is |ln(second/first)|, expressed below as a percentage: 10% means the two runs' medians differ by a factor of 1.10 in one direction or the other. Runs at different inr source revisions are not compared.

| Host | inr revision | Runs | Cells compared | Median difference | Largest difference | Cells within 10% |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| linux-worker-a | c15d5e5558bf | A vs B | 35 | 8.3% | 215% (`git/clone_full` K=8) | 18/35 |
| linux-worker-b | c15d5e5558bf | A vs B | 35 | 18.9% | 91% (`git/clone_sparse` K=8) | 8/35 |
| linux-worker-c | c15d5e5558bf | A vs B | 6 | 1.8% | 3% (`git/clone_full` K=32) | 6/6 |
| macos-laptop-a | c15d5e5558bf | A vs B | 8 | 6.6% | 26% (`git/push_rebase` K=8) | 5/8 |

#### Skipped cells (memory-fit guard)

Before each measured batch at `K` above 1 the guard predicts memory as `K` times the largest peak RSS seen so far for that variant and skips the rest of the cell when the prediction exceeds 90% of the memory available to the process (section 3.4). It only ever skipped `inr/checkout_full`, whose agents need about 433 MiB each, apart from two trials of one `serve_land` cell. Full-checkout rows at `K` of 16 or more therefore exist only for `linux-worker-a` run B at `K=16`, `macos-laptop-a` at `K=16` and `linux-worker-c` at `K=32`. Whether a cell ran also depended on the memory free at that moment: `linux-worker-a` skipped `K=16` in run A with 5.0 GiB available and ran it in run B, when more memory was free (7.9 GiB at the `K=32` check).

| Host | Run | Cell | K | trials measured | trials skipped | peak RSS basis MiB | predicted K x peak MiB | available MiB |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| linux-worker-a | A | `inr/serve_land` | 32 | 3 | 2 | 59 | 1873 | 1724 |
| linux-worker-a | A | `inr/checkout_full` | 16 | 0 | 5 | 433 | 6921 | 5118 |
| linux-worker-a | A | `inr/checkout_full` | 32 | 0 | 5 | 433 | 13843 | 5137 |
| linux-worker-a | B | `inr/checkout_full` | 32 | 0 | 5 | 432 | 13830 | 8138 |
| linux-worker-b | A | `inr/checkout_full` | 16 | 0 | 5 | 435 | 6954 | 4632 |
| linux-worker-b | A | `inr/checkout_full` | 32 | 0 | 5 | 435 | 13909 | 4632 |
| linux-worker-b | B | `inr/checkout_full` | 16 | 0 | 5 | 435 | 6954 | 4628 |
| linux-worker-b | B | `inr/checkout_full` | 32 | 0 | 5 | 435 | 13907 | 4629 |
| macos-laptop-a | A | `inr/checkout_full` | 32 | 0 | 5 | 493 | 15787 | 9809 |

#### Failed agents

Only Git's `worktree_add` produced failed agents, all with exit code 128, and only at `K` of 16 or more. Failed agents are excluded from the latency and memory statistics and counted here. The `run.log` of the affected sets contains `fatal: failed to read .git/worktrees/<agent>/commondir` and `fatal: '<work>/prov-git-worktree_add/<agent>' is not a working tree`. The cause was not isolated in this campaign, so the section 7.3 `worktree_add` rows describe the successful agents of those batches, and a failed batch leaves fewer than `K` working copies.

| Host | Run | Cell | K | failures/samples | exit codes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| linux-worker-a | A | `git/worktree_add` | 32 | 1/160 | 128 x1 |
| linux-worker-a | B | `git/worktree_add` | 32 | 2/160 | 128 x2 |
| linux-worker-c | B | `git/worktree_add` | 32 | 3/160 | 128 x3 |
| macos-laptop-a | A | `git/worktree_add` | 16 | 8/80 | 128 x8 |
| macos-laptop-a | A | `git/worktree_add` | 32 | 3/160 | 128 x3 |

### 7.5 What these results do and do not show

What they support:

- On this corpus and these four machines, `inr` provisions a virtual workspace (`mount`) or one service directory (`checkout_sparse`) much faster than Git provisions an equivalent working copy, and the gap widens with `K`. The exception is `checkout_sparse` on the laptop, where the gap narrows from 2.7 times at `K=1` to about 1.1 times at `K` of 16 and 32.
- Landing `K` concurrent single-file changes through one `inr serve` is slower than a single Git push at `K=1` on the Linux hosts, faster at `K=1` on the laptop, and faster at every `K` of 8 or more on every host that ran `land`. Every landing batch in every set delivered all `K` changes (`landed per batch` equals `K` throughout).
- A full working copy is the case where `inr` loses. `checkout_full` is slower than `git clone` in 12 of the 14 comparable cells, needs about eight to ten times the memory per process, and is the cell the memory-fit guard skipped (apart from two trials of one `serve_land` cell). Every `inr` commit and landing command also uses more memory per process than its Git counterpart (section 7.1). Recording a change after a full checkout (`commit_full`) is roughly ten times slower than Git's `commit_scan`.

What they do not show:

- They are not a statement about other corpora. The repository is synthetic: 50,000 files of about 2 KiB in 50 service directories, on local disks, with a `file://` Git origin and a loopback `inr serve`. Real repositories, network storage and a Git server with its own landing queue would change the Git baseline in particular. `push_rebase` is a retry loop with no queue, so its `K=32` times describe that loop, not Git hosting in general.
- `mount` defers blob writes, so `mount` against `worktree_add` or `clone_full` compares provisioning cost, not equal work.
- Two runs per host on non-dedicated machines do not bound the noise. `linux-worker-b` in particular moved by about 19% at the median between its two runs, and the laptop's load average ended above 100.
- The 9 skipped rows and the 5 failed-agent rows above are part of the result: the full-checkout comparison at `K` of 16 or more rests on four host-runs, and the Git `worktree_add` timings at large `K` are for the agents that succeeded.

To regenerate the tables in sections 7.2 to 7.4 from the committed sets, run the renderer over the eight run directories in the order of section 7.2. The section 7.1 table repeats the `K=1` and `K=32` agent ratios of the per-host pair tables.

```bash
python3 -I benchmarks/report-tables.py \
  benchmarks/results/20261021T023424Z-n50000 benchmarks/results/20261021T032119Z-n50000 \
  benchmarks/results/20261021T022647Z-n50000 benchmarks/results/20261021T032742Z-n50000 \
  benchmarks/results/20261021T022252Z-n50000 benchmarks/results/20261021T024201Z-n50000 \
  benchmarks/results/20261021T022321Z-n50000 benchmarks/results/20261021T074706Z-n50000
```

and check any set with `python3 -I benchmarks/verify-run.py benchmarks/results/<run-id>`.
