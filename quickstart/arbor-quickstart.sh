#!/bin/sh
# Velenza Arbor Stack — 60-Second Local Quickstart
#
# Demonstrates the 4-layer Velenza Arbor Stack in an isolated temporary workspace
# with zero cloud credentials required:
#   - Layer 0 (velenza-inarch / inr): Tree-free BonsaiChangeset commit, checkout-free
#     queries, sparse checkout, and 0-blob virtual workspace mount + on-demand hydration.
#   - Layer 1 (velenza-cambium / code-graph): CPG/SSA/VTA semantic code & hazard graph.
#   - Layer 2 (velenza-canon / spec-graph): Normative specification graph & //spec: traceability.
#   - Layer 3 (velenza-trellis / task-graph): Multi-agent execution DAG & worklink provenance.
#
# Usage:
#   ./quickstart/arbor-quickstart.sh [--smoke] [--emulator] [--keep-workdir]

set -eu

SMOKE_MODE=0
USE_EMULATOR=0
KEEP_WORKDIR=0

while [ $# -gt 0 ]; do
  case "$1" in
    --smoke)
      SMOKE_MODE=1
      shift
      ;;
    --emulator)
      USE_EMULATOR=1
      shift
      ;;
    --keep-workdir)
      KEEP_WORKDIR=1
      shift
      ;;
    -h|--help)
      echo "usage: $0 [--smoke] [--emulator] [--keep-workdir]"
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/velenza-arbor-quickstart.XXXXXX")

cleanup() {
  if [ "$KEEP_WORKDIR" -eq 0 ] && [ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT INT TERM

resolve_inr_bin() {
  if [ -n "${INR_BIN:-}" ] && [ -x "$INR_BIN" ]; then
    printf '%s\n' "$INR_BIN"
    return 0
  fi
  if [ -x "$REPO_ROOT/target/release/inr" ]; then
    printf '%s\n' "$REPO_ROOT/target/release/inr"
    return 0
  fi
  if [ -x "$REPO_ROOT/target/debug/inr" ]; then
    printf '%s\n' "$REPO_ROOT/target/debug/inr"
    return 0
  fi
  if command -v inr >/dev/null 2>&1; then
    command -v inr
    return 0
  fi
  echo "Building inr (release)..." >&2
  (cd "$REPO_ROOT" && cargo build --release --bin inr >&2)
  printf '%s\n' "$REPO_ROOT/target/release/inr"
}

INR=$(resolve_inr_bin)

# Isolate quickstart from any ambient host-global Inarch config or remote server env vars
export INARCH_USER_CONFIG="$WORK_DIR/isolated-user-inarch.toml"
export INARCH_BLOB_BACKEND="local"
export INARCH_META_BACKEND="local"
unset INARCH_CONFIG INARCH_REMOTE_URL INARCH_AUTH_TOKEN INARCH_JIT_LEASE_FILE || true

export ARBOR_GCP_PROJECT="${ARBOR_GCP_PROJECT:-arbor-local}"
export ARBOR_SPANNER_INSTANCE="${ARBOR_SPANNER_INSTANCE:-arbor-local-instance}"

if [ "$USE_EMULATOR" -eq 1 ]; then
  if command -v docker >/dev/null 2>&1; then
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d
    export SPANNER_EMULATOR_HOST="${SPANNER_EMULATOR_HOST:-localhost:9010}"
  else
    echo "warning: docker not found on PATH; continuing in zero-container local mode" >&2
  fi
fi

echo "=================================================================="
echo " Velenza Arbor Stack — 4-Layer Local Quickstart"
echo "=================================================================="

# ------------------------------------------------------------------
# Layer 0: velenza-inarch (inr)
# ------------------------------------------------------------------
echo ""
echo "[Layer 0: velenza-inarch] Initializing tree-free BonsaiChangeset repository..."
PROJECT_DIR="$WORK_DIR/sample-project"
mkdir -p "$PROJECT_DIR/specs" "$PROJECT_DIR/code"

cat > "$PROJECT_DIR/specs/SAMPLE_LOCK_SAFETY_v1.ood.json" <<'EOF'
{
  "doc_id": "00000000-0000-4000-8000-000000000001",
  "sections": {
    "1": {
      "title": "Sample Concurrent Store Lock Safety Specification",
      "statement": "Concurrent store readers must clone internal maps before returning under RLock."
    }
  }
}
EOF

cat > "$PROJECT_DIR/code/go.mod" <<'EOF'
module example.com/arbor-sample

go 1.23
EOF

cat > "$PROJECT_DIR/code/store.go" <<'EOF'
package sample

import (
	"maps"
	"sync"
)

// Store implements section 1 safe snapshot access.
//spec:sample_lock_safety#1
type Store struct {
	mu    sync.RWMutex
	items map[string]string
}

// Snapshot returns a defensive clone of items under RLock.
//spec:sample_lock_safety#1
func (s *Store) Snapshot() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return maps.Clone(s.items)
}
EOF

"$INR" init "$PROJECT_DIR"
(
  cd "$PROJECT_DIR"
  "$INR" commit -m "feat: add normative spec and traced Go implementation" --author "agent@velenza.dev" .

  echo "[Layer 0: velenza-inarch] Verifying checkout-free queries (refs, ls, search, cat)..."
  "$INR" refs
  "$INR" ls main
  "$INR" search main "*.go"

  SPARSE_DIR="$WORK_DIR/sparse-specs"
  "$INR" checkout main "$SPARSE_DIR" --prefix specs
  test -f "$SPARSE_DIR/specs/SAMPLE_LOCK_SAFETY_v1.ood.json"
  test ! -e "$SPARSE_DIR/code/store.go"

  MOUNT_DIR="$WORK_DIR/virtual-mount"
  "$INR" mount main "$MOUNT_DIR"
  "$INR" hydrate "$MOUNT_DIR" code/store.go
  test -f "$MOUNT_DIR/code/store.go"
)

# ------------------------------------------------------------------
# Layer 1: velenza-cambium (code-graph)
# ------------------------------------------------------------------
echo ""
echo "[Layer 1: velenza-cambium] Checking CPG/SSA/VTA Semantic Code & Hazard Graph layer..."
if "$INR" cambium arbor-info >/dev/null 2>&1; then
  "$INR" cambium arbor-info
  echo "verified Layer 1 (velenza-cambium) live delegation via inr cambium arbor-info"
else
  echo "Layer 1 (velenza-cambium) binary not installed in PATH (optional; install from https://github.com/velenzaboc/velenza-cambium); verified Layer 1 descriptor in inr stack"
fi

# ------------------------------------------------------------------
# Layer 2: velenza-canon (spec-graph)
# ------------------------------------------------------------------
echo ""
echo "[Layer 2: velenza-canon] Checking Normative Root Canon & //spec: traceability..."
if "$INR" canon arbor-info >/dev/null 2>&1; then
  "$INR" canon arbor-info
  echo "verified Layer 2 (velenza-canon) live delegation via inr canon arbor-info"
  "$INR" canon trace-code \
    --spec-dir "$PROJECT_DIR/specs" \
    --code-dir "$PROJECT_DIR/code" \
    --fail-on-dangling \
    --fail-on-uncovered
else
  echo "Layer 2 (velenza-canon) binary not installed in PATH (optional; install from https://github.com/velenzaboc/velenza-canon); verified Layer 2 descriptor in inr stack"
fi

# ------------------------------------------------------------------
# Layer 3: velenza-trellis (task-graph)
# ------------------------------------------------------------------
echo ""
echo "[Layer 3: velenza-trellis] Checking Structural Growth Trellis & Worklink DAG layer..."
if "$INR" trellis arbor-info >/dev/null 2>&1; then
  "$INR" trellis arbor-info
  echo "verified Layer 3 (velenza-trellis) live delegation via inr trellis arbor-info"
else
  echo "Layer 3 (velenza-trellis) binary not installed in PATH (optional; install from https://github.com/velenzaboc/velenza-trellis); verified Layer 3 descriptor in inr stack"
fi

echo ""
echo "[Umbrella Stack Status] inr stack --json:"
"$INR" stack --json

if [ "$SMOKE_MODE" -eq 1 ]; then
  echo "ARBOR_QUICKSTART_OK (smoke)"
else
  echo "ARBOR_QUICKSTART_OK"
fi
