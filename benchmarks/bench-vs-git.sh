#!/usr/bin/env bash
# benchmarks/bench-vs-git.sh — Reproducible, publishable Git vs Velenza Inarch (`inr`) comparison.
#
# What it measures (every number is end-to-end CLI wall-clock, separate OS processes, same corpus):
#
#   provision  K agents provision a working copy of an N-file repository at the same moment.
#              git:  worktree_add | clone_full (file:// transport) | clone_sparse (partial clone + cone sparse-checkout)
#              inr:  checkout_full | checkout_sparse (--prefix) | mount (virtual workspace, zero blob writes)
#   commit     one agent records a single-file change inside an N-file working copy.
#              git:  commit_path (add <file> + commit) | commit_scan (add -A + commit) | commit_scan_push (+ push to origin)
#              inr:  commit_full (scan N files, land) | commit_sparse (scan the sparse slice, land)
#   land       K agents land disjoint single-file changes onto the same branch concurrently.
#              git:  push_rebase (commit, push, on rejection `pull --rebase` and retry)
#              inr:  serve_land (`inr commit` from K client processes through one loopback `inr serve`)
#              Agent a edits services/svc-<a-1>/mod_0.rs, so every agent owns a distinct service directory
#              and a distinct sparse slice; --svc-dirs must therefore be >= the largest K (default 50).
#
# Every workload records per-agent latency, exit code, peak RSS of the agent's process tree, batch wall
# time (first start to last finish), disk bytes, and for `land` how many of the K changes verifiably
# reached the branch head. Each agent is one child process timed by benchmarks/measure.py.
#
# Memory-fit guard: before every batch with K > 1 (that is, before every measured trial) the script
# predicts K x (largest peak RSS seen so far for that system/variant) and skips the rest of the cell when
# that exceeds 90% of the memory available to this process (MemAvailable, further bounded by the cgroup
# memory limit headroom on Linux). A skipped cell is listed in metadata.json (skipped_cells, with
# trials_measured and trials_skipped) and summary.md instead of producing OOM-killed or thrashing samples;
# a cell stopped after some trials keeps the measured ones. K levels therefore run in ascending order.
# --no-memory-guard disables the check.
#
# Outputs, all under <output-dir>/<run-id>/ and all free of hostnames, user names, absolute paths
# and private addresses (asserted before exit):
#   metadata.json     host, toolchain and corpus telemetry, skipped cells
#   raw_trials.csv    one row per (workload, system, variant, k, trial, agent); trial 0 = warm-up
#   raw_batches.csv   one row per (workload, system, variant, k, trial) batch
#   aggregate.csv     min / p50 / mean / p95 / p99 / max latency and peak RSS per (workload, system, variant, k)
#                     over the successful (exit 0) non-warm-up samples; failures are counted separately
#   results.json      metadata + aggregate + raw, machine-readable
#   summary.md        tables, git/inr p50 ratios, failures and skipped cells
#   run.log           this script's log (paths redacted)
#   inr-bench/        the built-in `inr bench` suite on the same N and K list (unless --skip-inr-bench)
#
# Requirements: bash >= 5, coreutils, awk, python3 (standard library only, for measure.py), git >= 2.25,
# and an `inr` binary (or --build with cargo).
# Linux (telemetry from /proc, lscpu, findmnt) and macOS (sysctl, vm_stat, pmset, mount) are supported;
# on macOS the script re-executes itself through Homebrew's bash when the login bash is 3.2.
#
# Usage:
#   benchmarks/bench-vs-git.sh [--files 50000] [--concurrency 1,8,16,32] [--trials 5] [--warmup 1]
#                              [--host-label linux-worker] [--output-dir benchmarks/results]
#                              [--inr /path/to/inr | --build] [--source-rev <sha>] [--work-dir <dir>]
#                              [--file-bytes 2048] [--min-free-gb 20] [--keep-work] [--skip-inr-bench]
#                              [--workloads provision,commit,land] [--run-id <id>] [--svc-dirs 50]
#                              [--no-memory-guard]
set -euo pipefail

# bash >= 5 is required (EPOCHREALTIME, mapfile). macOS ships 3.2: re-execute through Homebrew's bash when present.
if (( BASH_VERSINFO[0] < 5 )); then
  for candidate in /opt/homebrew/bin/bash /usr/local/bin/bash; do
    if [[ -x "$candidate" && -z "${BENCH_REEXEC:-}" ]]; then BENCH_REEXEC=1 exec "$candidate" "$0" "$@"; fi
  done
  printf 'bench-vs-git.sh needs bash >= 5 (found %s)\n' "$BASH_VERSION" >&2
  exit 2
fi

# Internal per-agent mode for provision git/clone_sparse: partial clone + cone sparse-checkout as one process.
if [[ "${1:-}" == "--internal-git-sparse" ]]; then
  git -c core.fsmonitor=false -c feature.manyFiles=true clone -q --filter=blob:none --no-checkout "$2" "$3"
  git -C "$3" config core.fsmonitor false
  git -C "$3" config feature.manyFiles true
  git -C "$3" sparse-checkout set --cone "$4"
  git -C "$3" checkout -q main
  exit 0
fi

FILES=50000
CONCURRENCY="1,8,16,32"
TRIALS=5
WARMUP=1
HOST_LABEL="linux-worker"
OUTPUT_DIR="benchmarks/results"
INR=""
BUILD=0
SOURCE_REV=""
WORK_DIR=""
FILE_BYTES=2048
MIN_FREE_GB=20
KEEP_WORK=0
SKIP_INR_BENCH=0
WORKLOADS="provision,commit,land"
RUN_ID=""
SVC_DIRS=50
MEMORY_GUARD=1
MAX_PUSH_ATTEMPTS=500

usage() { sed -n '2,54p' "$0" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --files) FILES="$2"; shift 2 ;;
    --concurrency) CONCURRENCY="$2"; shift 2 ;;
    --trials) TRIALS="$2"; shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --host-label) HOST_LABEL="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --inr) INR="$2"; shift 2 ;;
    --build) BUILD=1; shift ;;
    --source-rev) SOURCE_REV="$2"; shift 2 ;;
    --work-dir) WORK_DIR="$2"; shift 2 ;;
    --file-bytes) FILE_BYTES="$2"; shift 2 ;;
    --min-free-gb) MIN_FREE_GB="$2"; shift 2 ;;
    --keep-work) KEEP_WORK=1; shift ;;
    --skip-inr-bench) SKIP_INR_BENCH=1; shift ;;
    --workloads) WORKLOADS="$2"; shift 2 ;;
    --run-id) RUN_ID="$2"; shift 2 ;;
    --svc-dirs) SVC_DIRS="$2"; shift 2 ;;
    --no-memory-guard) MEMORY_GUARD=0; shift ;;
    -h|--help) usage ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
[[ -n "$RUN_ID" ]] || RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-n${FILES}"
STARTED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------------------------
# Isolation: the benchmark never reads the operator's git identity, global git config, or inr config.
# ---------------------------------------------------------------------------------------------
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=bench GIT_AUTHOR_EMAIL=bench@example.com
export GIT_COMMITTER_NAME=bench GIT_COMMITTER_EMAIL=bench@example.com
export GIT_TERMINAL_PROMPT=0 LC_ALL=C
export INARCH_AUTHOR=bench@example.com INARCH_LOG_BACKEND=none
unset INARCH_REMOTE_URL INARCH_AUTH_TOKEN INARCH_REPO_ID INARCH_STORE_DIR INARCH_CONFIG \
      INARCH_TIER1_CACHE_DIR INARCH_TIER2_CACHE_DIR INARCH_BLOB_BACKEND INARCH_META_BACKEND \
      INARCH_JIT_SIGNING_KEY INARCH_GCP_CREDENTIALS_FILE INARCH_GCP_CREDENTIALS INARCH_JIT_LEASE_FILE \
      XDG_CACHE_HOME
ORIG_HOME="${HOME:-}"
# toolchain versions are read before HOME is redirected (rustup resolves toolchains through HOME)
RUSTC_VERSION="$(rustc --version 2>/dev/null || echo unavailable)"
CARGO_VERSION="$(cargo --version 2>/dev/null || echo unavailable)"

if [[ -z "$WORK_DIR" ]]; then
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/inarch-bench-vs-git.XXXXXX")"
else
  mkdir -p "$WORK_DIR"
  WORK_DIR="$(cd "$WORK_DIR" && pwd -P)"
fi
WORK="$WORK_DIR"
# inr resolves its user-global config and tier caches through HOME; point both at the scratch tree
mkdir -p "$WORK/bench-home"
export HOME="$WORK/bench-home" INARCH_USER_CONFIG="$WORK/bench-home/no-user-config.toml"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
OUT="$OUTPUT_DIR/$RUN_ID"
mkdir -p "$OUT"
LOG="$OUT/run.log"
: >"$LOG"

SERVER_PID=""
cleanup() {
  local rc=$?
  if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; fi
  if [[ "$KEEP_WORK" -eq 0 ]]; then rm -rf "$WORK"; fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$LOG" >&2; }
die() { log "ERROR: $*"; exit 1; }

now_us() {
  if [[ -n "${EPOCHREALTIME:-}" ]]; then
    local t="${EPOCHREALTIME/./}"
    printf '%s\n' "$((10#$t))"
  else
    printf '%s\n' "$(( $(date +%s%N) / 1000 ))"
  fi
}

# ---------------------------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------------------------
command -v git >/dev/null || die "git is required"
command -v awk >/dev/null || die "awk is required"
command -v python3 >/dev/null || die "python3 is required (benchmarks/measure.py times each agent and records its peak RSS)"
MEASURE="$SCRIPT_DIR/measure.py"
[[ -f "$MEASURE" ]] || die "missing $MEASURE"
PYTHON_VERSION="$(python3 --version 2>&1)"
if [[ "$BUILD" -eq 1 ]]; then
  command -v cargo >/dev/null || die "--build requires cargo on PATH"
  log "building inr (cargo build --release -p inarch-cli)"
  cargo build --release -p inarch-cli --manifest-path "$REPO_ROOT/Cargo.toml" >>"$LOG" 2>&1
  INR="$REPO_ROOT/target/release/inr"
fi
if [[ -z "$INR" ]]; then
  if [[ -x "$REPO_ROOT/target/release/inr" ]]; then INR="$REPO_ROOT/target/release/inr"
  elif command -v inr >/dev/null; then INR="$(command -v inr)"
  else die "no inr binary: pass --inr <path> or --build"; fi
fi
INR="$(cd "$(dirname "$INR")" && pwd -P)/$(basename "$INR")"
[[ -x "$INR" ]] || die "inr binary is not executable"
if [[ -z "$SOURCE_REV" ]] && git -C "$REPO_ROOT" rev-parse HEAD >/dev/null 2>&1; then
  SOURCE_REV="$(git -C "$REPO_ROOT" rev-parse HEAD)"
fi

IFS=',' read -r -a K_LIST <<<"$CONCURRENCY"
K_MAX=1
for k in "${K_LIST[@]}"; do [[ "$k" =~ ^[0-9]+$ && "$k" -ge 1 ]] || die "bad concurrency value: $k"; (( k > K_MAX )) && K_MAX=$k; done
# K runs in ascending order so the memory-fit guard can use the peak RSS observed at smaller K
mapfile -t K_LIST < <(printf '%s\n' "${K_LIST[@]}" | sort -n -u)
CONCURRENCY="$(IFS=','; printf '%s' "${K_LIST[*]}")"
(( FILES >= 100 )) || die "--files must be >= 100"
(( SVC_DIRS >= 2 && SVC_DIRS <= FILES )) || die "--svc-dirs must be between 2 and --files"
if [[ ",$WORKLOADS," == *,land,* ]] && (( SVC_DIRS < K_MAX )); then
  die "land needs one service directory per agent: --svc-dirs ($SVC_DIRS) must be >= the largest K ($K_MAX)"
fi

free_kb() { df -Pk "$1" | awk 'NR==2 {print $4}'; }
FREE_KB_START="$(free_kb "$WORK")"
if (( FREE_KB_START / 1048576 < MIN_FREE_GB )); then
  die "need at least ${MIN_FREE_GB} GiB free under the work directory (have $((FREE_KB_START / 1048576)) GiB); lower --min-free-gb only if you know the K_MAX clone footprint fits"
fi

# ---------------------------------------------------------------------------------------------
# Result files
# ---------------------------------------------------------------------------------------------
RAW="$OUT/raw_trials.csv"
BATCHES="$OUT/raw_batches.csv"
AGG="$OUT/aggregate.csv"
printf 'run_id,workload,system,variant,k,trial,agent,latency_us,exit_code,disk_bytes,max_rss_kb,extra,warmup\n' >"$RAW"
printf 'run_id,workload,system,variant,k,trial,batch_wall_us,disk_bytes,agents_ok,agents_failed,extra,warmup\n' >"$BATCHES"

record_raw() { # workload system variant k trial agent latency_us rc disk_bytes max_rss_kb extra warmup
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$RUN_ID" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}" "${12}" >>"$RAW"
}
record_batch() { # workload system variant k trial wall_us disk_bytes ok failed extra warmup
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$RUN_ID" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}" >>"$BATCHES"
}

# timed <result_file> [-] -- cmd...   one child process, timed by measure.py from spawn to exit;
# the result file receives "<us> <rc> <max_rss_kb>"; the child's stdout is discarded, stderr goes to the log
timed() {
  local result="$1"; shift
  [[ "${1:-}" == "-" ]] && shift
  [[ "${1:-}" == "--" ]] && shift
  python3 "$MEASURE" "$result" -- "$@" 2>>"$LOG"
}

# read_result <file> -> sets us, rc, rss (a missing file means the agent subshell died before timing)
read_result() {
  us=0; rc=99; rss=0
  if [[ -f "$1" ]]; then read -r us rc rss <"$1" || true; fi
  [[ -n "$us" ]] || us=0; [[ -n "$rc" ]] || rc=99; [[ -n "$rss" ]] || rss=0
}

# ---------------------------------------------------------------------------------------------
# Memory-fit guard: K concurrent agents of a variant need roughly K x the variant's peak RSS.
# ---------------------------------------------------------------------------------------------
declare -A RSS_PEAK=()   # "system/variant" -> largest peak RSS (KiB) of a successful agent so far
declare -A SKIPPED_SEEN=()
SKIPPED_CELLS=()         # JSON objects for metadata.json
SKIPPED_ROWS=()          # workload,system,variant,k,predicted_mib,available_mib,basis_mib for summary.md
note_rss() { # system variant rc rss_kb
  [[ "$3" == "0" ]] || return 0
  local key="$1/$2"
  if (( ${RSS_PEAK[$key]:-0} < $4 )); then RSS_PEAK[$key]="$4"; fi
}
cgroup_mem_limit_kb() { # Linux cgroup v2: smallest memory.max on the path from this process's cgroup to the root; empty when unlimited
  local path best="" d v
  [[ -r /proc/self/cgroup ]] || return 0
  path="$(awk -F: 'NR==1 {print $3}' /proc/self/cgroup)"
  while :; do
    d="/sys/fs/cgroup$path"
    if [[ -r "$d/memory.max" ]]; then
      v="$(cat "$d/memory.max")"
      if [[ "$v" =~ ^[0-9]+$ ]] && { [[ -z "$best" ]] || (( v / 1024 < best )); }; then best=$((v / 1024)); fi
    fi
    [[ "$path" == "/" || -z "$path" ]] && break
    path="${path%/*}"; [[ -n "$path" ]] || path="/"
  done
  printf '%s\n' "$best"
}
cgroup_limited_dir() { # Linux cgroup v2: this process's nearest ancestor cgroup with a numeric memory.max; empty when none
  local path d v
  [[ -r /proc/self/cgroup ]] || return 0
  path="$(awk -F: 'NR==1 {print $3}' /proc/self/cgroup)"
  while :; do
    d="/sys/fs/cgroup$path"
    if [[ -r "$d/memory.max" ]]; then
      v="$(cat "$d/memory.max")"
      if [[ "$v" =~ ^[0-9]+$ ]]; then printf '%s\n' "$d"; return 0; fi
    fi
    [[ "$path" == "/" || -z "$path" ]] && break
    path="${path%/*}"; [[ -n "$path" ]] || path="/"
  done
}
cgroup_mem_current_kb() { # memory.current of the limiting cgroup (charged anonymous memory, kernel memory and page cache)
  local d; d="$(cgroup_limited_dir)"
  [[ -n "$d" && -r "$d/memory.current" ]] || return 0
  awk '{print int($1 / 1024)}' "$d/memory.current"
}
cgroup_mem_reclaimable_kb() { # clean, non-shmem page cache charged to the limiting cgroup: the kernel reclaims it before it kills, so it is headroom
  local d; d="$(cgroup_limited_dir)"
  [[ -n "$d" && -r "$d/memory.stat" ]] || return 0
  awk '$1 == "file" {f = $2} $1 == "shmem" {s = $2} $1 == "file_dirty" {dr = $2} END {r = f - s - dr; if (r < 0) r = 0; print int(r / 1024)}' "$d/memory.stat"
}
# Memory this process tree can still take before the kernel kills or swaps it.
# Linux: MemAvailable, bounded by the limiting cgroup's headroom (memory.max - memory.current) PLUS the clean,
#   non-shmem page cache charged to that cgroup. memory.current includes the page cache of every file the benchmark
#   itself writes (32 full clones are about 6.4 GiB of cache); without the reclaimable term that cache would count as
#   consumed memory and the guard would skip cells that fit easily. MemAvailable makes the same correction host-wide.
# macOS: physical memory minus wired, compressor-occupied and anonymous pages; free, speculative, purgeable and
#   file-backed pages are all reclaimable.
mem_available_kb() {
  local avail=0 limit cur recl
  if [[ -r /proc/meminfo ]]; then
    avail="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
    limit="$(cgroup_mem_limit_kb)"
    if [[ -n "$limit" ]]; then
      cur="$(cgroup_mem_current_kb)"; [[ -n "$cur" ]] || cur=0
      recl="$(cgroup_mem_reclaimable_kb)"; [[ -n "$recl" ]] || recl=0
      if (( limit - cur + recl < avail )); then avail=$((limit - cur + recl)); fi
    fi
  elif command -v vm_stat >/dev/null 2>&1; then
    avail="$(macos_available_kb)"
  fi
  (( avail > 0 )) || avail=0
  printf '%s\n' "$avail"
}
macos_available_kb() {
  vm_stat | awk -v ps="$(sysctl -n hw.pagesize)" -v total="$(sysctl -n hw.memsize)" \
    '/^Pages wired down:|^Pages occupied by compressor:|^Anonymous pages:/ { gsub(/\./, "", $NF); used += $NF }
     END { print int((total - used * ps) / 1024) }'
}
# memory_fits <workload> <system> <variant> <k> <measured_trials> -> 0 when the next batch may run; 1 when the
# rest of the cell is skipped. The skip is recorded once, with the number of measured trials completed before it.
memory_fits() {
  local workload="$1" system="$2" variant="$3" k="$4" measured="$5" key="$2/$3" cell="$1/$2/$3/$4" peak predicted avail
  [[ -n "${SKIPPED_SEEN[$cell]:-}" ]] && return 1
  peak="${RSS_PEAK[$key]:-0}"
  (( MEMORY_GUARD == 1 && k > 1 && peak > 0 )) || return 0
  predicted=$((peak * k)); avail="$(mem_available_kb)"
  if (( avail > 0 && predicted * 10 > avail * 9 )); then
    SKIPPED_SEEN[$cell]=1
    SKIPPED_CELLS+=("{\"workload\":\"$workload\",\"system\":\"$system\",\"variant\":\"$variant\",\"k\":$k,\"trials_measured\":$measured,\"trials_skipped\":$((TRIALS - measured)),\"predicted_peak_rss_kb\":$predicted,\"available_kb\":$avail,\"peak_rss_kb_basis\":$peak}")
    SKIPPED_ROWS+=("$workload,$system,$variant,$k,$measured,$((TRIALS - measured)),$((predicted / 1024)),$((avail / 1024)),$((peak / 1024))")
    log "SKIP $workload $system/$variant k=$k after $measured of $TRIALS measured trials: predicted peak RSS $((predicted / 1024)) MiB (k x $((peak / 1024)) MiB) exceeds 90% of the $((avail / 1024)) MiB available to this process"
    return 1
  fi
  return 0
}

du_bytes() { # sum of allocated bytes for the given paths
  local kb=0 p
  for p in "$@"; do [[ -e "$p" ]] && kb=$(( kb + $(du -sk "$p" | awk '{print $1}') )); done
  printf '%s\n' "$((kb * 1024))"
}

# agent a (1-based) owns service directory (a-1) mod SVC_DIRS; with SVC_DIRS >= K every agent's slice is disjoint
prefix_for() { printf 'services/svc-%02d\n' "$(( ($1 - 1) % SVC_DIRS ))"; }
file_for_agent() { printf 'services/svc-%02d/mod_%d.rs\n' "$(( ($1 - 1) % SVC_DIRS ))" "$(( ($1 - 1) / SVC_DIRS ))"; }

# ---------------------------------------------------------------------------------------------
# Corpus: N deterministic Rust-like source files across SVC_DIRS service directories, each padded
# to about FILE_BYTES bytes so the tree has a realistic small-source-file footprint.
# ---------------------------------------------------------------------------------------------
CORPUS="$WORK/corpus"
log "run_id=$RUN_ID files=$FILES file_bytes=$FILE_BYTES concurrency=$CONCURRENCY trials=$TRIALS warmup=$WARMUP host_label=$HOST_LABEL"
log "generating corpus"
for ((s = 0; s < SVC_DIRS; s++)); do mkdir -p "$CORPUS/services/svc-$(printf '%02d' "$s")"; done
awk -v n="$FILES" -v svc="$SVC_DIRS" -v pad="$FILE_BYTES" -v root="$CORPUS" 'BEGIN {
  for (i = 0; i < n; i++) {
    s = i % svc; idx = int(i / svc)
    file = sprintf("%s/services/svc-%02d/mod_%d.rs", root, s, idx)
    body = sprintf("//! Synthetic service module svc-%02d file %d\npub fn compute_%d(x: u64) -> u64 {\n    x.wrapping_mul(6364136223846793005).wrapping_add(%d)\n}\n", s, idx, idx, i)
    printf "%s", body > file
    written = length(body); j = 0
    line = sprintf("// filler %08d %08d %-40s\n", i, 0, "deterministic-padding"); step = length(line)
    while (written + step <= pad) { line = sprintf("// filler %08d %08d %-40s\n", i, j, "deterministic-padding"); printf "%s", line > file; written += step; j++ }
    close(file)
  }
}'
CORPUS_BYTES="$(du_bytes "$CORPUS")"
CORPUS_FILES="$(find "$CORPUS" -type f | wc -l | awk '{print $1}')"
(( CORPUS_FILES == FILES )) || die "corpus has $CORPUS_FILES files, expected $FILES"

# ---------------------------------------------------------------------------------------------
# Git baseline: one repository with the corpus committed, packed, served as a bare origin over file://
# ---------------------------------------------------------------------------------------------
GIT_BASE="$WORK/git-base"
ORIGIN="$WORK/origin.git"
log "preparing git baseline"
git init -q -b main "$GIT_BASE"
git -C "$GIT_BASE" config core.fsmonitor false
git -C "$GIT_BASE" config feature.manyFiles true
cp -R "$CORPUS/." "$GIT_BASE/"
git -C "$GIT_BASE" add -A
# gc.auto=0: with $FILES loose objects the commit would otherwise spawn a detached `gc --auto`, which deletes
# loose objects while `git clone` below is still copying them (observed on macOS as "failed to copy file ...
# No such file or directory") and would leave the worktree_add base packed or loose depending on timing.
git -C "$GIT_BASE" -c gc.auto=0 commit -q -m "corpus: $FILES files"
git -C "$GIT_BASE" gc -q --prune=now
git clone -q --bare "$GIT_BASE" "$ORIGIN"
git -C "$ORIGIN" config uploadpack.allowFilter true
git -C "$ORIGIN" config uploadpack.allowAnySHA1InWant true
git -C "$ORIGIN" gc -q --prune=now
git -C "$GIT_BASE" remote add origin "file://$ORIGIN"
ORIGIN_URL="file://$ORIGIN"
GIT_PACK_BYTES="$(du_bytes "$ORIGIN")"

# ---------------------------------------------------------------------------------------------
# inr baseline: a local store (W1/W2) and a server store (W3), both seeded with the same corpus.
# Config files are produced by `inr init` with the store paths given through the environment.
# ---------------------------------------------------------------------------------------------
log "preparing inr stores"
INARCH_STORE_DIR="$WORK/store-local" "$INR" init "$WORK/cfg-local" >>"$LOG" 2>&1
LOCAL_CFG="$WORK/cfg-local/.inarch/config.toml"
INARCH_STORE_DIR="$WORK/store-server" INARCH_AUTH_TOKEN="bench-admin-token" \
  INARCH_JIT_SIGNING_KEY="bench-only-jit-signing-seed-not-a-secret" "$INR" init "$WORK/cfg-server" >>"$LOG" 2>&1
SERVER_CFG="$WORK/cfg-server/.inarch/config.toml"
( cd "$WORK" && INARCH_CONFIG="$LOCAL_CFG" "$INR" commit -m "corpus: $FILES files" "$CORPUS" >>"$LOG" 2>&1 )
( cd "$WORK" && INARCH_CONFIG="$SERVER_CFG" "$INR" commit -m "corpus: $FILES files" "$CORPUS" >>"$LOG" 2>&1 )
INR_STORE_BYTES="$(du_bytes "$WORK/store-local")"
inr_local() { ( cd "$WORK" && INARCH_CONFIG="$LOCAL_CFG" "$INR" "$@" ); }
inr_server_store() { ( cd "$WORK" && INARCH_CONFIG="$SERVER_CFG" "$INR" "$@" ); }

# ---------------------------------------------------------------------------------------------
# Telemetry (neutral: no hostname, no user, no absolute paths, no addresses)
# ---------------------------------------------------------------------------------------------
OS_NAME="$(uname -s)"; KERNEL="$(uname -r)"; ARCH="$(uname -m)"
read_first() { [[ -r "$1" ]] && head -n 1 "$1" || true; }
sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
loadavg_now() { # "1min 5min 15min"
  if [[ -r /proc/loadavg ]]; then awk '{print $1" "$2" "$3}' /proc/loadavg
  elif command -v sysctl >/dev/null 2>&1; then sysctl -n vm.loadavg 2>/dev/null | tr -d '{}' | awk '{print $1" "$2" "$3}'
  else echo unknown; fi
}
fs_type_of() { # filesystem type of the mount holding a path
  local mp
  if command -v findmnt >/dev/null 2>&1; then findmnt -no FSTYPE -T "$1" 2>/dev/null && return 0; fi
  if [[ "$OS_NAME" == "Darwin" ]]; then
    mp="$(df -P "$1" | awk 'NR==2 {print $NF}')"
    mount | awk -v mp="$mp" '$3 == mp { t = $4; gsub(/[(),]/, "", t); print t; exit }'
    return 0
  fi
  echo unknown
}
case "$OS_NAME" in
  Linux)
    OS_PRETTY="$(awk -F= '/^PRETTY_NAME=/ { gsub(/"/, "", $2); print $2; exit }' /etc/os-release 2>/dev/null || true)"
    CPU_MODEL="$(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null || true)"
    CPU_CORES="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN)"
    CPU_PHYSICAL="$(lscpu 2>/dev/null | awk -F: '/^Core\(s\) per socket/ {c=$2+0} /^Socket\(s\)/ {s=$2+0} END { if (c && s) print c*s; else print "unknown" }')"
    CPU_GOVERNOR="$(read_first /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
    MEM_TOTAL_KB="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
    MEM_AVAIL_KB="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
    POWER_SOURCE="n/a"; LOW_POWER_MODE="n/a"
    ;;
  Darwin)
    OS_PRETTY="$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))"
    CPU_MODEL="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)"
    CPU_CORES="$(sysctl -n hw.logicalcpu)"
    CPU_PHYSICAL="$(sysctl -n hw.physicalcpu)"
    perf_p="$(sysctl -n hw.perflevel0.physicalcpu 2>/dev/null || true)"; perf_e="$(sysctl -n hw.perflevel1.physicalcpu 2>/dev/null || true)"
    if [[ -n "$perf_p" && -n "$perf_e" ]]; then CPU_MODEL="$CPU_MODEL (${perf_p} performance + ${perf_e} efficiency cores)"; fi
    CPU_GOVERNOR="n/a"
    MEM_TOTAL_KB="$(( $(sysctl -n hw.memsize) / 1024 ))"
    MEM_AVAIL_KB="$(macos_available_kb)"
    POWER_SOURCE="$(pmset -g batt 2>/dev/null | awk 'NR==1 { gsub(/^Now drawing from /, ""); gsub(/\047/, ""); print; exit }')"
    LOW_POWER_MODE="$(pmset -g 2>/dev/null | awk '/lowpowermode/ { print $2; exit }')"
    ;;
  *)
    OS_PRETTY=""; CPU_MODEL=""; CPU_CORES="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"; CPU_PHYSICAL="unknown"
    CPU_GOVERNOR="unknown"; MEM_TOTAL_KB=0; MEM_AVAIL_KB=0; POWER_SOURCE="n/a"; LOW_POWER_MODE="n/a"
    ;;
esac
[[ -n "$CPU_MODEL" ]] || CPU_MODEL="$ARCH"
[[ -n "$OS_PRETTY" ]] || OS_PRETTY="$OS_NAME $KERNEL"
[[ -n "${CPU_PHYSICAL:-}" ]] || CPU_PHYSICAL="unknown"
[[ -n "$POWER_SOURCE" ]] || POWER_SOURCE="unknown"
[[ -n "$LOW_POWER_MODE" ]] || LOW_POWER_MODE="unknown"
[[ -n "${MEM_TOTAL_KB:-}" ]] || MEM_TOTAL_KB=0
[[ -n "${MEM_AVAIL_KB:-}" ]] || MEM_AVAIL_KB=0
FS_TYPE="$(fs_type_of "$WORK")"; [[ -n "$FS_TYPE" ]] || FS_TYPE=unknown
LOADAVG_START="$(loadavg_now)"
GIT_VERSION="$(git --version | awk '{print $3}')"
AWK_VERSION="$( (awk --version 2>/dev/null || awk -W version 2>/dev/null || true) | head -n 1)"
INR_SHA256="$(sha256_of "$INR")"
INR_BYTES="$(wc -c <"$INR" | awk '{print $1}')"
SCRIPT_SHA256="$(sha256_of "${BASH_SOURCE[0]}")"
MEASURE_SHA256="$(sha256_of "$MEASURE")"
CGROUP_LIMIT_KB="$(cgroup_mem_limit_kb)"; [[ -n "$CGROUP_LIMIT_KB" ]] || CGROUP_LIMIT_KB=0
MEM_AVAIL_PROCESS_KB="$(mem_available_kb)"

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/}"
  printf '%s' "$s"
}

write_metadata() {
  local finished="$1" loadavg_end="$2" k_json
  k_json="$(printf '%s' "$CONCURRENCY" | awk -F, 'BEGIN{ORS=""} {printf "["; for (i=1;i<=NF;i++) printf "%s%s", (i>1?",":""), $i; printf "]"}')"
  cat >"$OUT/metadata.json" <<EOF
{
  "schema": "velenza-inarch-bench-vs-git/1",
  "run_id": "$(json_escape "$RUN_ID")",
  "started_utc": "$STARTED_UTC",
  "finished_utc": "$finished",
  "host_label": "$(json_escape "$HOST_LABEL")",
  "host": {
    "os": "$(json_escape "$OS_NAME")",
    "os_release": "$(json_escape "$OS_PRETTY")",
    "kernel": "$(json_escape "$KERNEL")",
    "arch": "$(json_escape "$ARCH")",
    "cpu_model": "$(json_escape "$CPU_MODEL")",
    "cpu_logical_cores": "$(json_escape "$CPU_CORES")",
    "cpu_physical_cores": "$(json_escape "$CPU_PHYSICAL")",
    "cpu_governor": "$(json_escape "${CPU_GOVERNOR:-unknown}")",
    "power_source": "$(json_escape "$POWER_SOURCE")",
    "low_power_mode": "$(json_escape "$LOW_POWER_MODE")",
    "mem_total_kb": ${MEM_TOTAL_KB:-0},
    "mem_available_kb_at_start": ${MEM_AVAIL_KB:-0},
    "mem_cgroup_limit_kb": ${CGROUP_LIMIT_KB:-0},
    "mem_available_to_process_kb_at_start": ${MEM_AVAIL_PROCESS_KB:-0},
    "work_fs_type": "$(json_escape "$FS_TYPE")",
    "work_fs_free_kb_at_start": ${FREE_KB_START:-0},
    "loadavg_1_5_15_at_start": "$(json_escape "$LOADAVG_START")",
    "loadavg_1_5_15_at_end": "$(json_escape "$loadavg_end")"
  },
  "toolchain": {
    "git_version": "$(json_escape "$GIT_VERSION")",
    "inr_source_rev": "$(json_escape "${SOURCE_REV:-unknown}")",
    "inr_binary_sha256": "$(json_escape "$INR_SHA256")",
    "inr_binary_bytes": ${INR_BYTES:-0},
    "inr_build": "cargo build --release -p inarch-cli",
    "bench_script_sha256": "$(json_escape "$SCRIPT_SHA256")",
    "measure_script_sha256": "$(json_escape "$MEASURE_SHA256")",
    "rustc_version": "$(json_escape "$RUSTC_VERSION")",
    "cargo_version": "$(json_escape "$CARGO_VERSION")",
    "bash_version": "$(json_escape "$BASH_VERSION")",
    "awk_version": "$(json_escape "$AWK_VERSION")",
    "python_version": "$(json_escape "$PYTHON_VERSION")"
  },
  "corpus": {
    "files": $FILES,
    "service_dirs": $SVC_DIRS,
    "file_bytes_target": $FILE_BYTES,
    "corpus_bytes_on_disk": $CORPUS_BYTES,
    "git_bare_origin_bytes": $GIT_PACK_BYTES,
    "inr_local_store_bytes": $INR_STORE_BYTES,
    "layout": "services/svc-NN/mod_I.rs, file i -> svc (i mod $SVC_DIRS), index floor(i / $SVC_DIRS); same naming scheme as the inr bench synthetic corpus, $SVC_DIRS service directories, deterministic comment padding to file_bytes_target"
  },
  "design": {
    "concurrency_levels": $k_json,
    "trials": $TRIALS,
    "warmup_trials": $WARMUP,
    "workloads": "$(json_escape "$WORKLOADS")",
    "timing": "wall-clock microseconds around each agent process from spawn to exit, taken by benchmarks/measure.py (Python perf_counter_ns around Popen/wait); batch_wall = first agent start to last agent exit (bash EPOCHREALTIME)",
    "memory": "max_rss_kb = ru_maxrss of the largest process in the agent's reaped process tree (getrusage RUSAGE_CHILDREN), KiB",
    "percentiles": "nearest-rank over the successful (exit 0) non-warm-up agent samples of a (workload, system, variant, k) group; failures counted separately and excluded from latency and RSS statistics",
    "memory_guard": "$( (( MEMORY_GUARD == 1 )) && printf 'before every batch with k > 1 (each measured trial): skip the rest of the cell when k x (largest successful peak RSS seen so far for the system/variant) > 90%% of memory available to this process (Linux: MemAvailable bounded by cgroup memory.max - memory.current + clean non-shmem page cache charged to the cgroup; macOS: physical memory - wired - compressor - anonymous pages); skipped cells listed in skipped_cells with trials_measured and trials_skipped; a cell stopped after some measured trials keeps them' || printf 'disabled (--no-memory-guard)')",
    "k_order": "concurrency levels run in ascending order",
    "git_isolation": "GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null, fixed bench identity, core.fsmonitor=false and feature.manyFiles=true enabled on Git working copies for large-tree fairness, bare origin over file:// with uploadpack.allowFilter; the worktree_add base repository and the bare origin are packed in the foreground (gc --prune=now) before any measurement; provisioning destinations removed between trials",
    "inr_isolation": "config from inr init with INARCH_* overrides, local fs blob+meta backends, no configured tier cache directories (local-mode processes keep in-memory tiers only), log backend none; land goes through one loopback inr serve (admin bearer token) because the local fs metadata store serialises CAS inside one process only; the land clients run in remote mode, where inr keeps its default on-disk tier-1 blob cache under the redirected HOME inside the scratch tree, shared by the K agents",
    "land_verification": "after each batch every agent's file is read back from the branch head (git cat-file / inr cat) and counted in agents_ok",
    "land_isolation": "agent a edits services/svc-<a-1>/mod_0.rs; each inr agent works in a sparse checkout of only its own service directory where .inarch/workspace_state.toml records the workspace base changeset, and inr commit diffs against that persisted base revision and rebases onto the current branch head in O(delta) via land_patch",
    "git_push_retry": "on a rejected push: git pull --rebase origin main, then push again, up to $MAX_PUSH_ATTEMPTS attempts; attempts recorded in extra"
  },
  "skipped_cells": [$(IFS=','; printf '%s' "${SKIPPED_CELLS[*]}")]
}
EOF
}

# ---------------------------------------------------------------------------------------------
# Workload: provision
# ---------------------------------------------------------------------------------------------
provision_cmd() { # system variant agent dest -> prints the command words
  local system="$1" variant="$2" agent="$3" dest="$4" prefix
  prefix="$(prefix_for "$agent")"
  case "$system/$variant" in
    git/worktree_add)  printf '%s\n' git -C "$GIT_BASE" worktree add -q --detach "$dest" main ;;
    git/clone_full)    printf '%s\n' git -c core.fsmonitor=false -c feature.manyFiles=true clone -q "$ORIGIN_URL" "$dest" ;;
    git/clone_sparse)  printf '%s\n' bash "$SCRIPT_DIR/bench-vs-git.sh" --internal-git-sparse "$ORIGIN_URL" "$dest" "$prefix" ;;
    inr/checkout_full) printf '%s\n' "$INR" checkout main "$dest" ;;
    inr/checkout_sparse) printf '%s\n' "$INR" checkout main "$dest" --prefix "$prefix" ;;
    inr/mount)         printf '%s\n' "$INR" mount main "$dest" ;;
    *) die "unknown provision variant $system/$variant" ;;
  esac
}

run_provision_batch() { # system variant k trial warmup
  local system="$1" variant="$2" k="$3" trial="$4" warm="$5"
  local base="$WORK/prov-$system-$variant" dests=() pids=() a t0 t1 ok=0 failed=0 total_bytes
  rm -rf "$base"; mkdir -p "$base"
  for ((a = 1; a <= k; a++)); do dests+=("$base/agent-$a"); done
  t0="$(now_us)"
  for ((a = 1; a <= k; a++)); do
    (
      mapfile -t cmd < <(provision_cmd "$system" "$variant" "$a" "${dests[a-1]}")
      cd "$WORK" && INARCH_CONFIG="$LOCAL_CFG" timed "$base/agent-$a.result" - -- "${cmd[@]}"
    ) &
    pids+=("$!")
  done
  for p in "${pids[@]}"; do wait "$p" || true; done
  t1="$(now_us)"
  total_bytes="$(du_bytes "${dests[@]}")"
  for ((a = 1; a <= k; a++)); do
    read_result "$base/agent-$a.result"
    if [[ "$rc" == "0" ]]; then ok=$((ok + 1)); else failed=$((failed + 1)); fi
    note_rss "$system" "$variant" "$rc" "$rss"
    record_raw provision "$system" "$variant" "$k" "$trial" "$a" "$us" "$rc" "$(du_bytes "${dests[a-1]}")" "$rss" "prefix=$(prefix_for "$a")" "$warm"
  done
  record_batch provision "$system" "$variant" "$k" "$trial" "$((t1 - t0))" "$total_bytes" "$ok" "$failed" "" "$warm"
  if [[ "$variant" == "worktree_add" ]]; then
    for ((a = 1; a <= k; a++)); do git -C "$GIT_BASE" worktree remove --force "${dests[a-1]}" >>"$LOG" 2>&1 || true; done
    git -C "$GIT_BASE" worktree prune >>"$LOG" 2>&1 || true
  fi
  rm -rf "$base"
  log "provision $system/$variant k=$k trial=$trial warmup=$warm ok=$ok failed=$failed batch_wall_ms=$(( (t1 - t0) / 1000 ))"
}

workload_provision() {
  local variants=("git/worktree_add" "git/clone_full" "git/clone_sparse" "inr/checkout_full" "inr/checkout_sparse" "inr/mount")
  local v system variant k t
  for v in "${variants[@]}"; do
    system="${v%%/*}"; variant="${v##*/}"
    for ((t = 1; t <= WARMUP; t++)); do run_provision_batch "$system" "$variant" "${K_LIST[0]}" 0 1; done
    for k in "${K_LIST[@]}"; do
      for ((t = 1; t <= TRIALS; t++)); do
        memory_fits provision "$system" "$variant" "$k" "$((t - 1))" || break
        run_provision_batch "$system" "$variant" "$k" "$t" 0
      done
    done
  done
}

# ---------------------------------------------------------------------------------------------
# Workload: commit (single agent, single-file change inside an N-file working copy)
# ---------------------------------------------------------------------------------------------
append_line() { printf '// %s\n' "$2" >>"$1"; }

workload_commit() {
  local gitwc="$WORK/w2-git" full="$WORK/w2-inr-full" sparse="$WORK/w2-inr-sparse" t warm res us rc rss
  log "preparing commit working copies"
  git -c core.fsmonitor=false -c feature.manyFiles=true clone -q "$ORIGIN_URL" "$gitwc"
  git -C "$gitwc" config core.fsmonitor false
  git -C "$gitwc" config feature.manyFiles true
  inr_local checkout main "$full" >>"$LOG" 2>&1
  inr_local checkout main "$sparse" --prefix services/svc-00 >>"$LOG" 2>&1
  res="$WORK/w2.result"
  for ((t = 0; t <= TRIALS; t++)); do
    warm=0; (( t == 0 )) && warm=1
    (( t == 0 && WARMUP == 0 )) && continue
    local f_path="services/svc-00/mod_$((t * 3)).rs" f_scan="services/svc-00/mod_$((t * 3 + 1)).rs" f_push="services/svc-00/mod_$((t * 3 + 2)).rs"
    local f_full="services/svc-01/mod_$((t * 3)).rs" f_sparse="services/svc-00/mod_$((t * 3 + 1)).rs"

    append_line "$gitwc/$f_path" "commit trial $t path"
    rm -f "$res"
    ( cd "$gitwc" && timed "$res" - -- bash -c 'git add "$1" && git commit -q -m "$2"' _ "$f_path" "commit_path trial $t" )
    read_result "$res"; record_raw commit git commit_path 1 "$t" 1 "$us" "$rc" 0 "$rss" "files=$FILES" "$warm"

    append_line "$gitwc/$f_scan" "commit trial $t scan"
    rm -f "$res"
    ( cd "$gitwc" && timed "$res" - -- bash -c 'git add -A && git commit -q -m "$1"' _ "commit_scan trial $t" )
    read_result "$res"; record_raw commit git commit_scan 1 "$t" 1 "$us" "$rc" 0 "$rss" "files=$FILES" "$warm"

    append_line "$gitwc/$f_push" "commit trial $t push"
    rm -f "$res"
    ( cd "$gitwc" && timed "$res" - -- bash -c 'git add -A && git commit -q -m "$1" && git push -q origin HEAD:main' _ "commit_scan_push trial $t" )
    read_result "$res"; record_raw commit git commit_scan_push 1 "$t" 1 "$us" "$rc" 0 "$rss" "files=$FILES" "$warm"

    append_line "$full/$f_full" "commit trial $t full"
    rm -f "$res"
    ( cd "$WORK" && INARCH_CONFIG="$LOCAL_CFG" timed "$res" - -- "$INR" commit -m "commit_full trial $t" "$full" )
    read_result "$res"; record_raw commit inr commit_full 1 "$t" 1 "$us" "$rc" 0 "$rss" "files_scanned=$FILES" "$warm"

    append_line "$sparse/$f_sparse" "commit trial $t sparse"
    rm -f "$res"
    ( cd "$WORK" && INARCH_CONFIG="$LOCAL_CFG" timed "$res" - -- "$INR" commit -m "commit_sparse trial $t" "$sparse" )
    read_result "$res"; record_raw commit inr commit_sparse 1 "$t" 1 "$us" "$rc" 0 "$rss" "files_scanned=$((FILES / SVC_DIRS))" "$warm"
    # keep the full working copy in step with the branch head so the next full scan sees only its own edit
    append_line "$full/$f_sparse" "commit trial $t sparse"
    log "commit trial=$t warmup=$warm done"
  done
  rm -rf "$gitwc" "$full" "$sparse"
}

# ---------------------------------------------------------------------------------------------
# Workload: land (K agents land disjoint single-file changes concurrently onto one branch)
# ---------------------------------------------------------------------------------------------
pick_port() {
  local p
  for ((p = 17400 + RANDOM % 2000; p < 65000; p++)); do
    if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then printf '%s\n' "$p"; return 0; fi
  done
  return 1
}

# The git agent is one `bash -c` child running commit, push and the pull --rebase retry loop, so it is
# timed and RSS-measured by measure.py exactly like the single `inr commit` process on the other side.
git_agent_land() { # clone_dir file message attempts_file
  local dir="$1" file="$2" msg="$3" out="$4" attempts=0
  git -C "$dir" commit -q -am "$msg"
  while :; do
    attempts=$((attempts + 1))
    if git -C "$dir" push -q origin HEAD:main 2>/dev/null; then printf '%s\n' "$attempts" >"$out"; return 0; fi
    (( attempts < MAX_PUSH_ATTEMPTS )) || { printf '%s\n' "$attempts" >"$out"; return 1; }
    git -C "$dir" pull -q --rebase origin main 2>/dev/null || true
  done
}
export -f git_agent_land
export MAX_PUSH_ATTEMPTS

run_land_batch() { # k trial warmup
  local k="$1" trial="$2" warm="$3" a pids=() t0 t1 ok failed us rc rss attempts file marker landed
  local measured=$(( trial > 0 ? trial - 1 : 0 ))   # measured trials of this cell completed before this batch
  for ((a = 1; a <= k; a++)); do rm -f "$WORK/w3-git/agent-$a.result" "$WORK/w3-git/agent-$a.attempts" "$WORK/w3-inr/agent-$a.result"; done
  # ---- git ----
  if memory_fits land git push_rebase "$k" "$measured"; then
    for ((a = 1; a <= k; a++)); do
      git -C "$WORK/w3-git/agent-$a" fetch -q origin main && git -C "$WORK/w3-git/agent-$a" reset -q --hard origin/main
    done
    ok=0; failed=0; pids=()
    t0="$(now_us)"
    for ((a = 1; a <= k; a++)); do
      (
        file="$(file_for_agent "$a")"; marker="land trial $trial agent $a"
        append_line "$WORK/w3-git/agent-$a/$file" "$marker"
        timed "$WORK/w3-git/agent-$a.result" - -- bash -c 'git_agent_land "$@"' _ "$WORK/w3-git/agent-$a" "$file" "$marker" "$WORK/w3-git/agent-$a.attempts"
      ) &
      pids+=("$!")
    done
    for p in "${pids[@]}"; do wait "$p" || true; done
    t1="$(now_us)"
    landed=0
    for ((a = 1; a <= k; a++)); do
      file="$(file_for_agent "$a")"; marker="land trial $trial agent $a"
      if git -C "$ORIGIN" cat-file -p "main:$file" 2>/dev/null | tail -n 1 | grep -qF "$marker"; then landed=$((landed + 1)); fi
      read_result "$WORK/w3-git/agent-$a.result"
      attempts="$(read_first "$WORK/w3-git/agent-$a.attempts")"; [[ -n "$attempts" ]] || attempts=0
      if [[ "$rc" == "0" ]]; then ok=$((ok + 1)); else failed=$((failed + 1)); fi
      note_rss git push_rebase "$rc" "$rss"
      record_raw land git push_rebase "$k" "$trial" "$a" "$us" "$rc" 0 "$rss" "attempts=$attempts" "$warm"
    done
    record_batch land git push_rebase "$k" "$trial" "$((t1 - t0))" "$(du_bytes "$ORIGIN")" "$landed" "$((k - landed))" "push_ok=$ok" "$warm"
    log "land git/push_rebase k=$k trial=$trial warmup=$warm landed=$landed/$k batch_wall_ms=$(( (t1 - t0) / 1000 ))"
  fi

  # ---- inr ----
  if memory_fits land inr serve_land "$k" "$measured"; then
    ok=0; failed=0; pids=()
    t0="$(now_us)"
    for ((a = 1; a <= k; a++)); do
      (
        file="$(file_for_agent "$a")"; marker="land trial $trial agent $a"
        append_line "$WORK/w3-inr/agent-$a/$file" "$marker"
        cd "$WORK" && INARCH_CONFIG="$SERVER_CFG" INARCH_REMOTE_URL="$SERVER_URL" \
          timed "$WORK/w3-inr/agent-$a.result" - -- "$INR" commit -m "$marker" "$WORK/w3-inr/agent-$a"
      ) &
      pids+=("$!")
    done
    for p in "${pids[@]}"; do wait "$p" || true; done
    t1="$(now_us)"
    landed=0
    for ((a = 1; a <= k; a++)); do
      file="$(file_for_agent "$a")"; marker="land trial $trial agent $a"
      if inr_server_store cat main "$file" 2>/dev/null | tail -n 1 | grep -qF "$marker"; then landed=$((landed + 1)); fi
      read_result "$WORK/w3-inr/agent-$a.result"
      if [[ "$rc" == "0" ]]; then ok=$((ok + 1)); else failed=$((failed + 1)); fi
      note_rss inr serve_land "$rc" "$rss"
      record_raw land inr serve_land "$k" "$trial" "$a" "$us" "$rc" 0 "$rss" "files_scanned=$((FILES / SVC_DIRS))" "$warm"
    done
    record_batch land inr serve_land "$k" "$trial" "$((t1 - t0))" "$(du_bytes "$WORK/store-server")" "$landed" "$((k - landed))" "commit_ok=$ok" "$warm"
    log "land inr/serve_land k=$k trial=$trial warmup=$warm landed=$landed/$k batch_wall_ms=$(( (t1 - t0) / 1000 ))"
    # refresh the inr sparse working copies to the new head (untimed; the git side does the same with fetch + reset)
    for ((a = 1; a <= k; a++)); do
      rm -rf "$WORK/w3-inr/agent-$a"
      inr_server_store checkout main "$WORK/w3-inr/agent-$a" --prefix "$(prefix_for "$a")" >>"$LOG" 2>&1
    done
  fi
}

workload_land() {
  local a k t port
  log "preparing $K_MAX git clones and $K_MAX inr sparse working copies for land"
  mkdir -p "$WORK/w3-git" "$WORK/w3-inr"
  for ((a = 1; a <= K_MAX; a++)); do
    (
      git -c core.fsmonitor=false -c feature.manyFiles=true clone -q "$ORIGIN_URL" "$WORK/w3-git/agent-$a"
      git -C "$WORK/w3-git/agent-$a" config core.fsmonitor false
      git -C "$WORK/w3-git/agent-$a" config feature.manyFiles true
    ) &
  done
  wait
  for ((a = 1; a <= K_MAX; a++)); do
    inr_server_store checkout main "$WORK/w3-inr/agent-$a" --prefix "$(prefix_for "$a")" >>"$LOG" 2>&1
  done
  port="$(pick_port)" || die "no free loopback port"
  SERVER_URL="http://127.0.0.1:$port"
  ( cd "$WORK" && INARCH_CONFIG="$SERVER_CFG" exec "$INR" serve --listen "127.0.0.1:$port" >>"$LOG" 2>&1 ) &
  SERVER_PID="$!"
  for ((t = 0; t < 100; t++)); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then break; fi
    sleep 0.1
  done
  (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null || die "inr serve did not come up"
  log "inr serve listening on loopback port $port"
  for ((t = 1; t <= WARMUP; t++)); do run_land_batch "${K_LIST[0]}" 0 1; done
  for k in "${K_LIST[@]}"; do
    for ((t = 1; t <= TRIALS; t++)); do run_land_batch "$k" "$t" 0; done
  done
  kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; SERVER_PID=""
  rm -rf "$WORK/w3-git" "$WORK/w3-inr"
}

# ---------------------------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------------------------
# Latency and RSS statistics are computed over the successful (exit 0) non-warm-up samples of a cell;
# `samples` counts every non-warm-up sample and `failures` the non-zero exits, so nothing is hidden.
aggregate() {
  printf 'workload,system,variant,k,samples,failures,min_ms,p50_ms,mean_ms,p95_ms,p99_ms,max_ms,max_rss_kb_p50,max_rss_kb_max,batch_wall_p50_ms,batch_wall_mean_ms,disk_bytes_mean,agents_ok_mean,trials\n' >"$AGG"
  local groups g workload system variant k
  groups="$(awk -F, 'NR>1 && $13=="0" {print $2","$3","$4","$5}' "$RAW" | sort -u)"
  while IFS= read -r g; do
    [[ -n "$g" ]] || continue
    IFS=',' read -r workload system variant k <<<"$g"
    awk -F, -v w="$workload" -v s="$system" -v v="$variant" -v k="$k" 'NR>1 && $13=="0" && $2==w && $3==s && $4==v && $5==k {print $8, $9, $11}' "$RAW" \
      | sort -n | awk -v w="$workload" -v s="$system" -v v="$variant" -v k="$k" -v bfile="$BATCHES" '
        { n++; if ($2 == "0") { m++; lat[m] = $1; sum += $1; rss[m] = $3 + 0 } else fail++ }
        function pct(arr, cnt, p,   r) { r = int((p * cnt + 99) / 100); if (r < 1) r = 1; if (r > cnt) r = cnt; return arr[r] }
        function isort(arr, cnt,   i, j, x) { for (i = 2; i <= cnt; i++) { x = arr[i]; j = i - 1; while (j >= 1 && arr[j] > x) { arr[j+1] = arr[j]; j-- } arr[j+1] = x } }
        END {
          if (n == 0) exit
          isort(rss, m)   # lat[] is already sorted: the input is sorted numerically on latency
          bn = 0; bsum = 0; dsum = 0; oksum = 0
          while ((getline line < bfile) > 0) {
            split(line, f, ",")
            if (f[2] == w && f[3] == s && f[4] == v && f[5] == k && f[12] == "0") { bn++; bw[bn] = f[7] + 0; bsum += f[7]; dsum += f[8]; oksum += f[9] }
          }
          close(bfile)
          isort(bw, bn)
          bp50 = (bn > 0) ? pct(bw, bn, 50) / 1000.0 : 0
          printf "%s,%s,%s,%s,%d,%d,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%d,%d,%.3f,%.3f,%.0f,%.3f,%d\n", w, s, v, k, n, fail + 0,
            (m > 0 ? lat[1] / 1000.0 : 0), (m > 0 ? pct(lat, m, 50) / 1000.0 : 0), (m > 0 ? sum / m / 1000.0 : 0),
            (m > 0 ? pct(lat, m, 95) / 1000.0 : 0), (m > 0 ? pct(lat, m, 99) / 1000.0 : 0), (m > 0 ? lat[m] / 1000.0 : 0),
            (m > 0 ? pct(rss, m, 50) : 0), (m > 0 ? rss[m] : 0),
            bp50, (bn > 0 ? bsum / bn / 1000.0 : 0), (bn > 0 ? dsum / bn : 0), (bn > 0 ? oksum / bn : 0), bn
        }' >>"$AGG"
  done <<<"$groups"
}

csv_to_json_array() { # file -> JSON array of objects, numeric fields unquoted
  awk -F, 'NR==1 { for (i = 1; i <= NF; i++) h[i] = $i; n = NF; printf "["; next }
    { printf "%s{", (NR > 2 ? "," : "")
      for (i = 1; i <= n; i++) {
        val = $i; printf "%s\"%s\":", (i > 1 ? "," : ""), h[i]
        if (val ~ /^-?[0-9]+(\.[0-9]+)?$/) printf "%s", val; else { gsub(/\\/, "\\\\", val); gsub(/"/, "\\\"", val); printf "\"%s\"", val }
      }
      printf "}" }
    END { printf "]" }' "$1"
}

write_results_json() {
  {
    printf '{"metadata":'; cat "$OUT/metadata.json"
    printf ',"aggregate":'; csv_to_json_array "$AGG"
    printf ',"raw_batches":'; csv_to_json_array "$BATCHES"
    printf ',"raw_trials":'; csv_to_json_array "$RAW"
    printf '}\n'
  } >"$OUT/results.json"
}

agg_value() { # workload system variant k column_name
  awk -F, -v w="$1" -v s="$2" -v v="$3" -v k="$4" -v c="$5" 'NR==1 { for (i = 1; i <= NF; i++) if ($i == c) col = i; next } $1==w && $2==s && $3==v && $4==k { print $col; exit }' "$AGG"
}

write_summary_md() {
  local md="$OUT/summary.md" k g a b c w gs gv is iv
  {
    printf '# Git vs Velenza Inarch (`inr`) — N=%s files, K in {%s}\n\n' "$FILES" "$CONCURRENCY"
    printf 'Run `%s` on host label `%s`, %s to %s UTC. Generated by `benchmarks/bench-vs-git.sh`; raw per-trial data in `raw_trials.csv` and `raw_batches.csv`, machine-readable bundle in `results.json`.\n\n' "$RUN_ID" "$HOST_LABEL" "$STARTED_UTC" "$FINISHED_UTC"
    printf '## Host and toolchain\n\n| Field | Value |\n| :--- | :--- |\n'
    printf '| OS / kernel / arch | %s; kernel %s; %s |\n' "$OS_PRETTY" "$KERNEL" "$ARCH"
    printf '| CPU | %s (%s logical / %s physical cores, governor %s) |\n' "$CPU_MODEL" "$CPU_CORES" "$CPU_PHYSICAL" "${CPU_GOVERNOR:-unknown}"
    printf '| Power | source %s, low power mode %s |\n' "$POWER_SOURCE" "$LOW_POWER_MODE"
    printf '| Memory | %s MiB total, %s MiB available at start; cgroup memory limit %s; %s MiB available to this process at start |\n' "$((MEM_TOTAL_KB / 1024))" "$((MEM_AVAIL_KB / 1024))" "$( (( CGROUP_LIMIT_KB > 0 )) && printf '%s MiB' "$((CGROUP_LIMIT_KB / 1024))" || printf 'none')" "$((MEM_AVAIL_PROCESS_KB / 1024))"
    printf '| Work filesystem | %s, %s GiB free at start |\n' "$FS_TYPE" "$((FREE_KB_START / 1048576))"
    printf '| Load average (1/5/15) | start %s, end %s |\n' "$LOADAVG_START" "$LOADAVG_END"
    printf '| git | %s |\n' "$GIT_VERSION"
    printf '| inr | source %s, binary sha256 %s, %s |\n' "${SOURCE_REV:-unknown}" "$INR_SHA256" "$RUSTC_VERSION"
    printf '| Script | bench-vs-git.sh sha256 %s; measure.py sha256 %s; %s |\n' "$SCRIPT_SHA256" "$MEASURE_SHA256" "$PYTHON_VERSION"
    printf '| Corpus | %s files in %s service directories, %s MiB on disk; bare git origin %s MiB; inr local store %s MiB |\n' "$FILES" "$SVC_DIRS" "$((CORPUS_BYTES / 1048576))" "$((GIT_PACK_BYTES / 1048576))" "$((INR_STORE_BYTES / 1048576))"
    printf '| Design | %s measured trials per cell; %s warm-up batch(es) per variant at K=%s, recorded with warmup=1; nearest-rank percentiles over the successful per-agent samples; failures counted separately; warm-up excluded from aggregates but kept in raw data; memory-fit guard %s |\n\n' "$TRIALS" "$WARMUP" "${K_LIST[0]}" "$( (( MEMORY_GUARD == 1 )) && printf 'on' || printf 'off')"
    printf '## Per-agent latency (ms), peak RSS (KiB) and batch wall (ms)\n\n'
    printf '| Workload | System | Variant | K | n | fail | min | p50 | mean | p95 | p99 | max | rss p50 | rss max | batch p50 | batch mean | disk bytes mean | agents ok |\n'
    printf '| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n'
    awk -F, 'NR>1 { printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18 }' "$AGG"
    printf '\n## Failures (non-zero exit codes; excluded from the latency and RSS statistics above)\n\n'
    if awk -F, 'NR>1 && $13=="0" && $9!="0" { found = 1 } END { exit !found }' "$RAW"; then
      printf '| Workload | System | Variant | K | exit code | count |\n| :--- | :--- | :--- | ---: | ---: | ---: |\n'
      awk -F, 'NR>1 && $13=="0" && $9!="0" { c[$2 "," $3 "," $4 "," $5 "," $9]++ } END { for (key in c) { split(key, f, ","); printf "| %s | %s | %s | %s | %s | %d |\n", f[1], f[2], f[3], f[4], f[5], c[key] } }' "$RAW" | sort
    else
      printf 'none\n'
    fi
    printf '\n## Skipped cells (memory-fit guard)\n\n'
    if (( ${#SKIPPED_ROWS[@]} > 0 )); then
      printf '| Workload | System | Variant | K | trials measured | trials skipped | predicted peak RSS MiB (K x basis) | available MiB | basis: largest peak RSS MiB |\n| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |\n'
      local row
      for row in "${SKIPPED_ROWS[@]}"; do
        IFS=',' read -r w gs gv k m s a b c <<<"$row"
        printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' "$w" "$gs" "$gv" "$k" "$m" "$s" "$a" "$b" "$c"
      done
    else
      printf 'none\n'
    fi
    printf '\n## Ratios (git p50 / inr p50 per agent; > 1 means inr is faster)\n\n| Workload | Comparison | K | git p50 ms | inr p50 ms | ratio |\n| :--- | :--- | ---: | ---: | ---: | ---: |\n'
    local pairs=("provision git clone_full inr checkout_full" "provision git clone_sparse inr checkout_sparse" "provision git worktree_add inr mount" "provision git clone_full inr mount" "land git push_rebase inr serve_land")
    for g in "${pairs[@]}"; do
      read -r w gs gv is iv <<<"$g"
      for k in "${K_LIST[@]}"; do
        a="$(agg_value "$w" "$gs" "$gv" "$k" p50_ms)"; b="$(agg_value "$w" "$is" "$iv" "$k" p50_ms)"
        [[ -n "$a" && -n "$b" ]] || continue
        printf '| %s | %s/%s vs %s/%s | %s | %s | %s | %s |\n' "$w" "$gs" "$gv" "$is" "$iv" "$k" "$a" "$b" "$(awk -v a="$a" -v b="$b" 'BEGIN { if (b > 0) printf "%.2f", a / b; else print "n/a" }')"
      done
    done
    for g in "commit git commit_scan_push inr commit_full" "commit git commit_path inr commit_sparse" "commit git commit_scan inr commit_full"; do
      read -r w gs gv is iv <<<"$g"
      a="$(agg_value "$w" "$gs" "$gv" 1 p50_ms)"; b="$(agg_value "$w" "$is" "$iv" 1 p50_ms)"
      [[ -n "$a" && -n "$b" ]] || continue
      printf '| %s | %s/%s vs %s/%s | 1 | %s | %s | %s |\n' "$w" "$gs" "$gv" "$is" "$iv" "$a" "$b" "$(awk -v a="$a" -v b="$b" 'BEGIN { if (b > 0) printf "%.2f", a / b; else print "n/a" }')"
    done
    printf '\n## Batch wall ratios (git batch p50 / inr batch p50; time until the last of K agents finished)\n\n| Workload | Comparison | K | git ms | inr ms | ratio |\n| :--- | :--- | ---: | ---: | ---: | ---: |\n'
    for g in "${pairs[@]}"; do
      read -r w gs gv is iv <<<"$g"
      for k in "${K_LIST[@]}"; do
        a="$(agg_value "$w" "$gs" "$gv" "$k" batch_wall_p50_ms)"; b="$(agg_value "$w" "$is" "$iv" "$k" batch_wall_p50_ms)"
        [[ -n "$a" && -n "$b" ]] || continue
        printf '| %s | %s/%s vs %s/%s | %s | %s | %s | %s |\n' "$w" "$gs" "$gv" "$is" "$iv" "$k" "$a" "$b" "$(awk -v a="$a" -v b="$b" 'BEGIN { if (b > 0) printf "%.2f", a / b; else print "n/a" }')"
      done
    done
    printf '\n## Reading the numbers\n\n'
    printf -- '- Every sample is one OS process from spawn to exit, so it includes process start-up, config discovery and store open for `inr` and the equivalent start-up for `git`. The git `land` agent is a `bash -c` child running commit, push and the rebase retry loop.\n'
    printf -- '- Peak RSS is the resident-set high-water mark of the largest process in the agent'"'"'s process tree (KiB). Latency and RSS statistics cover successful samples only; the fail column and the Failures section carry the rest.\n'
    printf -- '- `provision` destinations are deleted between trials; the git bare origin is packed once; page cache is warm after the warm-up trial for both systems.\n'
    printf -- '- `land` agents_ok counts changes that were read back from the branch head after the batch. A value below K is a lost update and is reported, not hidden.\n'
    printf -- '- `inr` land traffic crosses one loopback HTTP server (same machine), git pushes go to a bare repository on the same filesystem. Neither side pays real network latency.\n'
    printf -- '- Nothing in this directory identifies the machine beyond the host label and the hardware fields above.\n'
  } >"$md"
}

# ---------------------------------------------------------------------------------------------
# Sterility gate: no hostname, user name, home directory, absolute work path or private address
# may appear in any output file. The scan is byte-level and fails the run.
# ---------------------------------------------------------------------------------------------
sterilize_outputs() { # redact the few absolute paths this run knows about from every text output
  local f tmp
  while IFS= read -r f; do
    tmp="$f.redacted"
    sed -e "s#$WORK#<work>#g" -e "s#$OUT#<out>#g" -e "s#$OUTPUT_DIR#<out>#g" -e "s#$REPO_ROOT#<repo>#g" -e "s#${ORIG_HOME:-/nonexistent}#<home>#g" "$f" >"$tmp"
    mv "$tmp" "$f"
  done < <(find "$OUT" -type f \( -name '*.csv' -o -name '*.json' -o -name '*.md' -o -name '*.log' -o -name '*.txt' \))
}

check_sterile() { # dir -> 0 when clean, 1 when any file carries an identifying byte sequence (violations logged)
  local dir="$1" bad=0 f tok
  local tokens=()
  tokens+=("$(id -un 2>/dev/null || true)")
  tokens+=("$(uname -n 2>/dev/null || true)")
  tokens+=("${ORIG_HOME:-}")
  tokens+=("$WORK")
  [[ -d "$dir" ]] || return 0
  while IFS= read -r f; do
    if grep -qE '/(Users|Volumes|home)/[A-Za-z0-9]|C:\\Users\\[A-Za-z0-9]|C:/Users/[A-Za-z0-9]' "$f"; then log "sterility violation (workstation path) in ${f#$OUT/}"; bad=1; fi
    if grep -qE '(^|[^0-9A-Za-z.])(100\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})' "$f"; then log "sterility violation (private address) in ${f#$OUT/}"; bad=1; fi
    for tok in "${tokens[@]}"; do
      [[ -n "$tok" && ${#tok} -ge 3 ]] || continue
      if grep -qiwF -- "$tok" "$f"; then log "sterility violation (identifying token) in ${f#$OUT/}"; bad=1; fi
    done
  done < <(find "$dir" -type f)
  return "$bad"
}

assert_sterile() {
  check_sterile "$1" || die "output is not sterile; refusing to leave it in place as a releasable result"
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------
main() {
  local w
  IFS=',' read -r -a wl <<<"$WORKLOADS"
  for w in "${wl[@]}"; do
    case "$w" in
      provision) workload_provision ;;
      commit) workload_commit ;;
      land) workload_land ;;
      *) die "unknown workload $w" ;;
    esac
  done
  LOADAVG_END="$(loadavg_now)"
  FINISHED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  aggregate
  write_metadata "$FINISHED_UTC" "$LOADAVG_END"
  write_results_json
  write_summary_md
  if [[ "$SKIP_INR_BENCH" -eq 0 ]]; then
    log "running the built-in inr bench suite (files=$FILES concurrency=$CONCURRENCY trials=$TRIALS)"
    mkdir -p "$OUT/inr-bench"
    ( cd "$WORK" && INARCH_CONFIG="$LOCAL_CFG" TMPDIR="$WORK" "$INR" bench --files "$FILES" --concurrency "$CONCURRENCY" --trials "$TRIALS" --host "$HOST_LABEL" --corpus "synthetic-n$FILES" --output-dir "$OUT/inr-bench" >>"$LOG" 2>&1 ) || log "inr bench exited non-zero (see run.log)"
  fi
  sterilize_outputs
  # the built-in suite's files are a secondary artifact: drop them rather than fail the primary results
  if ! check_sterile "$OUT/inr-bench"; then
    rm -rf "$OUT/inr-bench"
    log "inr-bench output removed: it carried an identifying byte sequence (see violations above)"
  fi
  assert_sterile "$OUT"
  log "done: results in ${OUT#$OUTPUT_DIR/}"
  printf '%s\n' "$OUT"
}

main
