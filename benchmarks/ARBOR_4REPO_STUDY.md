# Velenza Arbor Stack: 4-Codebase Empirical Run & Side-by-Side Comparison

> [!IMPORTANT]
> **Live Measurement Summary (`linux-worker-b`, Linux x86\_64)**
> All 4 repositories in the Velenza Arbor Stack — [`velenza-inarch`](https://github.com/velenzaboc/velenza-inarch/blob/v0.1.0/README.md) (Rust, Layer 0), [`velenza-cambium`](https://github.com/velenzaboc/velenza-cambium/blob/v0.1.0/README.md) (Go, Layer 1), [`velenza-canon`](https://github.com/velenzaboc/velenza-canon/blob/v0.1.0/README.md) (Go, Layer 2), and [`velenza-trellis`](https://github.com/velenzaboc/velenza-trellis/blob/v0.1.0/README.md) (Go, Layer 3), totaling **737 source files, 252,722 lines of code, and 11.03 MB** — were ingested, analyzed, traced, and governed through the unified `inr` umbrella CLI and compared head-to-head against traditional `git`, `go vet`, `grep`, and unverified task tracking.

---

## Reproducibility, Raw Dataset & Verification

Every measurement in this study is reproducible from a fresh clone of `velenzaboc/velenza-inarch` using only standard toolchains (`cargo`, `go`, `git`, `python3`):

```bash
# 1. Deterministically verify the committed 4-repository JSON dataset (80 invariants):
python3 -I benchmarks/bench-arbor-4repos.py \
  --verify benchmarks/arbor_4repo_results.json

# 2. Re-run the complete 6-stage empirical study from scratch
#    (automatically clones velenza-cambium, velenza-canon, and velenza-trellis from GitHub
#     if not already present in a sibling directory):
python3 -I benchmarks/bench-arbor-4repos.py \
  --output benchmarks/arbor_4repo_results.json
```

* **Benchmark Runner & Verifier**: [`benchmarks/bench-arbor-4repos.py`](bench-arbor-4repos.py)
* **Raw Structured Dataset**: [`benchmarks/arbor_4repo_results.json`](arbor_4repo_results.json)
* **Release Commit Coordinates (`v0.1.0`)**:
  * `velenzaboc/velenza-inarch`: `c15d5e5558bf29103d21102c4c63a77038818c90`
  * `velenzaboc/velenza-cambium`: `817fd2886dd0643199d2bb9822b5a673079a6c32`
  * `velenzaboc/velenza-canon`: `0c66ce44b94d34e14272825801c846d9a3ff7b54`
  * `velenzaboc/velenza-trellis`: `5b92c93a122a8878b758eabffde8fa9f9deebe33`

---

## 0. Corpus Under Test (The 4 Arbor Codebases)

| Repository | Arbor Layer | Language | Tracked Files | Lines of Code | Source Size | `v0.1.0` Commit |
| :--- | :--- | :--- | ---: | ---: | ---: | :--- |
| [`velenza-inarch`](https://github.com/velenzaboc/velenza-inarch/blob/v0.1.0/crates/inarch-cli/src/lib.rs) | **Layer 0** — Bonsai VCS & Virtual Mount | Rust | 85 | 42,738 | 1.65 MB | `c15d5e5` |
| [`velenza-cambium`](https://github.com/velenzaboc/velenza-cambium/blob/v0.1.0/main.go) | **Layer 1** — CPG / SSA / VTA Hazard Graph | Go | 61 | 17,159 | 0.64 MB | `817fd28` |
| [`velenza-canon`](https://github.com/velenzaboc/velenza-canon/blob/v0.1.0/main.go) | **Layer 2** — Normative Spec & Traceability Graph | Go | 454 | 148,962 | 6.95 MB | `0c66ce4` |
| [`velenza-trellis`](https://github.com/velenzaboc/velenza-trellis/blob/v0.1.0/main.go) | **Layer 3** — Multi-Agent Execution & Worklink DAG | Go | 137 | 43,863 | 1.79 MB | `5b92c93` |
| **Total Stack** | **Layers 0–3 (`inr stack --json`)** | **Rust + Go** | **737** | **252,722** | **11.03 MB** | **All `v0.1.0` Green** |

---

## 1. Layer 0 (`velenza-inarch` / `inr`) vs. Traditional `git`

### 1A. Repository Ingest & Sparse / On-Demand Hydration

Traditional `git clone` / `git checkout` materializes every file in the tree into a working directory before an agent can read or edit a single file. `velenza-inarch` (`inr`) supports both **prefix-scoped sparse checkout** (`inr checkout --sparse <prefix>`) and **lazy single-file hydration** (`inr mount --hydrate <path>`):

| Codebase | `git init+add+commit` | `inr init+commit` | `git clone` Full Tree (ms / bytes written) | `inr mount --hydrate` Target File (ms / bytes written) | Hydration Speedup | Disk Write Reduction |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| **`velenza-inarch`** | 57.41 ms | **40.43 ms** (1.42x) | 23.47 ms / 1,647,198 B (85 files) | **4.37 ms / 48,495 B** (1 file) | **5.37x faster** | **97.1% fewer bytes** |
| **`velenza-cambium`** | 30.86 ms | **18.41 ms** (1.68x) | 16.46 ms / 644,425 B (61 files) | **3.95 ms / 65,086 B** (1 file) | **4.17x faster** | **89.9% fewer bytes** |
| **`velenza-canon`** | 220.97 ms | **198.55 ms** (1.11x) | 74.34 ms / 6,952,316 B (454 files) | **4.76 ms / 2,349 B** (1 file) | **15.62x faster** | **99.97% fewer bytes** |
| **`velenza-trellis`** | 59.93 ms | **43.03 ms** (1.39x) | 25.85 ms / 1,789,781 B (137 files) | **3.86 ms / 1,854 B** (1 file) | **6.70x faster** | **99.90% fewer bytes** |

---

### 1B. Zero-Checkout Agent Read + Edit + Land (`inr mcp-stdio` vs. `git clone + commit + push`)

When an AI agent needs to read a file and land a change, `git` requires cloning a worktree, modifying the file on disk, staging, committing, and pushing. With `inr mcp-stdio` (`inarch_read_file` + `inarch_commit_files`), the agent reads and lands directly against the content-addressed Bonsai store with **zero working-tree bytes on disk**:

| Codebase | Traditional `git clone + edit + commit + push` | `git` Worktree Disk Footprint | `inr mcp-stdio` (`inarch_read_file` + `inarch_commit_files`) | `inr` Worktree Disk Footprint | Latency Speedup |
| :--- | ---: | ---: | ---: | ---: | ---: |
| **`velenza-inarch`** | 70.55 ms | 2,173,737 B (2.17 MB) | **3.98 ms** | **0 B** | **17.7x faster** |
| **`velenza-cambium`** | 54.73 ms | 929,821 B (0.93 MB) | **5.02 ms** | **0 B** | **10.9x faster** |
| **`velenza-canon`** | 274.13 ms | 8,961,323 B (8.96 MB) | **2.31 ms** | **0 B** | **118.7x faster** |
| **`velenza-trellis`** | 67.98 ms | 2,389,120 B (2.39 MB) | **2.10 ms** | **0 B** | **32.4x faster** |

---

### 1C. Multi-Agent Concurrency: 16-Agent Disjoint Swarm & 8-Agent Same-File 3-Way Line Merge

We ran two concurrent agent swarm tests on each real codebase:
1. **16-Agent Disjoint File Swarm**: 16 concurrent agents fork from the same base revision and simultaneously land new files onto `main`.
2. **8-Agent Same-File 3-Way Merge Swarm**: 8 concurrent agents fork from the same base revision of the repo's primary entrypoint (`crates/inarch-engine/src/lib.rs` in `velenza-inarch`, `main.go` in the 3 Go repos), each editing a distinct non-overlapping line region of the *same file*, and land concurrently.

| Codebase | `git push` 16-Agent Swarm (Landed / Rejected) | `inr` 16-Agent Disjoint Swarm (Landed / Wall Time / CAS Retries) | `inr` 8-Agent **Same-File** 3-Way Line Merge (Landed / Target File / Wall Time) |
| :--- | :--- | :--- | :--- |
| **`velenza-inarch`** | **1 / 16 landed** (15 failed `non-fast-forward`) | **16 / 16 landed (100%)** in `77.84 ms` (40 CAS rebases) | **8 / 8 landed (100%)** on `crates/inarch-engine/src/lib.rs` (1,315 LOC) in `743.15 ms` |
| **`velenza-cambium`** | **1 / 16 landed** (15 failed `non-fast-forward`) | **16 / 16 landed (100%)** in `113.71 ms` (48 CAS rebases) | **8 / 8 landed (100%)** on `main.go` (2,033 LOC) in `802.10 ms` |
| **`velenza-canon`** | **1 / 16 landed** (15 failed `non-fast-forward`) | **16 / 16 landed (100%)** in `42.73 ms` (36 CAS rebases) | **8 / 8 landed (100%)** on `main.go` (75 LOC) in `127.05 ms` |
| **`velenza-trellis`** | **1 / 16 landed** (15 failed `non-fast-forward`) | **16 / 16 landed (100%)** in `78.26 ms` (39 CAS rebases) | **8 / 8 landed (100%)** on `main.go` (76 LOC) in `119.62 ms` |

---

## 2. Layer 1 (`velenza-cambium` / `inr cambium`) vs. `go vet` & Text Search

### 2A. Whole-Program CPG / SSA / VTA Graph Extraction on `.inarch`-Native Repositories

Running `velenza-cambium` directly against the `.inarch`-initialized repositories (without `.git` directories, via [`cambium_arbor.go`](https://github.com/velenzaboc/velenza-cambium/blob/v0.1.0/cambium_arbor.go#L196-L253)) extracted the full Code Property Graph (AST + SSA + VTA call graph + lock/IO/goroutine/map dataflow edges), while `inr verify-codebase` verified the Rust workspace (`velenza-inarch`):

| Codebase | Analysis Engine | Symbols Extracted | CPG / SSA / VTA Edges | Call Edges (`CALLS`) | Lock Edges (`ACQUIRES_LOCK` / `CALLS_UNDER_LOCK`) | I/O Sinks (`IO_SINK`) | Baseline Hazards Detected | Analysis Time |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **`velenza-inarch`** | `inr verify-codebase` (Rust) | 86 files / Fsnode DAG | 100% Merkle Verified | — | — | — | 0 | **91.12 ms** |
| **`velenza-cambium`** | `inr cambium hazards --analyze` | **932** (`349` funcs, `33` methods, `86` types) | **8,562** | 2,597 | 13 / 22 | 195 | **9** (`3 LOCK_ACROSS_IO`, `3 SPAWNS_UNRECOVERED_GO`, `2 DETACHES_CONTEXT`, `1 TIMER_IN_LOOP`) | **3,613.88 ms** |
| **`velenza-canon`** | `inr cambium hazards --analyze` | **9,595** (`3,504` funcs, `442` methods, `723` types) | **87,507** | 22,440 | 18 / 43 | 508 | **125** (`3 LOCK_ACROSS_IO`, `13 SPAWNS_UNRECOVERED_GO`, `102 UNBOUNDED_MAP`, `4 UNBOUNDED_SHIFT`, `2 DETACHES_CONTEXT`, `1 TIMER_IN_LOOP`) | **6,409.09 ms** |
| **`velenza-trellis`** | `inr cambium hazards --analyze` | **2,807** (`854` funcs, `303` methods, `266` types) | **22,252** | 5,768 | 5 / 20 | 206 | **30** (`3 LOCK_ACROSS_IO`, `6 TXN_CLOSURE_OUTER_MUTATION`, `5 SPAWNS_UNRECOVERED_GO`, `15 UNBOUNDED_MAP`, `1 DETACHES_CONTEXT`) | **3,830.91 ms** |

Real existing hazards surfaced by `inr cambium hazards --analyze` across the 3 Go repositories include:
- **`velenza-cambium`**: `[HIGH] LOCK_ACROSS_IO` in `initializeGoogleCredentials (credentials.go:54)` — holds a mutex lock across a 4-hop call chain reaching `sink:io:net/http.Client.Do`.
- **`velenza-canon`**: `[HIGH] LOCK_ACROSS_IO` in `SpannerSubstrateAdapter.Close (substrate.go:306)` — holds a lock across `sink:io:cloud.google.com/go/spanner.Client.Close`.
- **`velenza-trellis`**: `[HIGH] LOCK_ACROSS_IO` in `SpannerSubstrateAdapter.getClient (substrate.go:205)` — holds a lock across `sink:io:cloud.google.com/go/spanner.NewClient`, plus `6` `TXN_CLOSURE_OUTER_MUTATION` hazards where Spanner `ReadWriteTransaction` closures mutate outer-scope variables that can corrupt state on transaction retry.

### 2B. Differential Hazard Probe: `go vet ./...` vs. `inr cambium hazards --analyze`

When we injected a valid, cleanly compiling Go file (`arbor_injected_hazards_probe.go`) containing 6 real concurrency/resource bugs into each of the 3 Go repositories:
- **`go vet ./...` result**: Exit code `0`, **0 findings** across all 3 repositories.
- **`inr cambium hazards --analyze` result**: Caught **all 6/6 injected hazards** with exact SSA dataflow & call-chain proofs in all 3 repositories:
  1. `[HIGH] MAP_ESCAPE_UNDER_LOCK` (`ArborProbeCache.UnsafeMapSnapshot`, line 15): returns internal `map[string]string` field `ArborProbeCache.data` under `RLock` without cloning.
  2. `[HIGH] LOCK_ACROSS_IO` (`ArborProbeCache.ProcessFilesInLoop`, line 22): holds `c.mu.Lock()` across `sink:io:os.Open`.
  3. `[MEDIUM] DEFER_IN_LOOP` (`ArborProbeCache.ProcessFilesInLoop`, line 22): executes `defer c.mu.Unlock()` and `defer f.Close()` inside a loop cycle.
  4. `[MEDIUM] DETACHES_CONTEXT` (`ArborProbeCache.HandleRequestAsync`, line 34): drops request `ctx` for `context.Background()` without timeout or deadline.
  5. `[MEDIUM] SPAWNS_UNRECOVERED_GO` (`ArborProbeCache.HandleRequestAsync`, line 34): spawns background goroutine mutating shared state without panic recovery `defer`.
  6. `[MEDIUM] UNBOUNDED_MAP` (`ArborProbeCache.HandleRequestAsync`, line 11): map field `ArborProbeCache.data` has insertion paths and `0` deletion/eviction paths.

---

## 3. Layer 2 (`velenza-canon` / `inr canon trace-code`) vs. Unchecked Markdown Docs

Traditional `grep` or prose Markdown documentation cannot enforce that every normative specification clause is implemented in code or that `//spec:` annotations in code point to real, non-deleted specification sections.

We ran `inr canon trace-code --fail-on-dangling --fail-on-uncovered` across source files from all 4 repositories (`velenza-inarch/lib.rs`, `velenza-cambium/hazards.go`, `velenza-canon/canon_arbor.go`, `velenza-trellis/fg_validator_runner.go`) against `ARBOR_STACK_INTEGRITY_v1.ood.json` (`DOC-ARBOR-STACK-001`):

| Check | Traditional `grep` / Markdown Docs | `inr canon trace-code` (Clean 4-Repo State) | `inr canon trace-code` (Simulated Spec Drift) |
| :--- | :--- | :--- | :--- |
| **Execution Time** | Manual inspection | **16.01 ms** (`exit_code = 0`) | **14.67 ms** (`exit_code = 1`) |
| **Normative Section Coverage** | Unverified | **4 / 4 sections covered** (`L0`–`L3`) | **4 / 5 covered** — immediately flagged uncovered section `DOC-ARBOR-STACK-001#L4_unimplemented_requirement` |
| **Dangling Code Annotations** | Silent rot when spec clauses change | **0 dangling annotations** | Caught `DOC-ARBOR-STACK-001#L99_nonexistent_clause` at `velenza-inarch/dangling_ref.rs:1` |
| **VOLT Capability Anchors** | Unindexed comments | Indexed **4 `//volt:` anchors** (`arbor.l0.workspace_base`, `arbor.l1.hazards`, `arbor.l2.trace_code`, `arbor.l3.fg_validator`) | Preserved & reported in structured JSON |

---

## 4. Layer 3 (`velenza-trellis` / `inr trellis`) vs. Unverified Issue Trackers

Traditional issue trackers (GitHub Issues, Jira, Linear) allow agents or humans to mark a task `"done"` without cryptographic proof that tests passed, without checking whether the claimed commit SHA is actually reachable on `origin/main`, and without preventing two agents from colliding on the same active lane/worktree.

Running `velenza-trellis` (`inr trellis arbor-info` in **18.29 ms** and `fg-validator-runner` in **3.04 ms**) against a 15-lane multi-agent fleet snapshot and 3 mutated governance-violation snapshots demonstrated deterministic fail-closed enforcement:

| Fleet Governance Scenario | Traditional Issue Tracker | `velenza-trellis` (`fg-validator-runner`) Verdict | Exact Invariant Enforced |
| :--- | :--- | :--- | :--- |
| **1. Valid 15-Lane Fleet Snapshot** | Marks tasks "Done" on trust | **`PASSED` (`true`) in 3.04 ms** | Verified 15 active lanes, SHA-256 snapshot content hashes, unique worktree bindings, dependency direction, and terminal validation proofs |
| **2. Task Marked `done` Without Validation Proof** | Allowed silently | **`FAILED` (`overall_passed: false`)** | `terminal_proof.acceptance` caught `1` unproved terminal task (`terminal_proof_passed: false`) |
| **3. Broken Dependency Direction + Unpushed Commit SHA** | Allowed silently | **`FAILED` (`overall_passed: false`)** | Caught `L4` dependency direction violation (`dep_integrity_passed: false`) AND classified commit `abcdef01...` as `"not_reachable"` (`reason: "commit_not_in_origin_main"`) |
| **4. Two Agents Bound to Same Active Lane (`MVP-ACTIVATE-01`)** | Silent worktree collision & overwrite | **`FAILED` (`overall_passed: false`)** | `roster.passed: false` — flagged `multiple_valid_bindings` on lane activation `MVP-ACTIVATE-01` |
