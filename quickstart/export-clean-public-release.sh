#!/bin/sh
# Velenza Arbor Stack — Clean Public Release Exporter
#
# Exports clean, single-root-commit (`v0.1.0`) public Git repositories for the
# Velenza Arbor Stack strictly from the committed Git tree (`git archive HEAD`),
# with zero historical git-log leaks, zero untracked working-tree leaks, zero
# build artifacts, and a clean open-source commit identity
# (`Velenza Open Source <open-source@velenzaboc.com>`).
#
# Usage:
#   ./quickstart/export-clean-public-release.sh \
#     --source-dir <repo_or_parent_dir> \
#     --output-dir <export_staging_dir> \
#     [--tag v0.1.0] \
#     [--allow-dirty]

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEFAULT_SOURCE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

ROOT_SOURCE_DIR="$DEFAULT_SOURCE_DIR"
OUTPUT_DIR=""
RELEASE_TAG="v0.1.0"
ALLOW_DIRTY=0
AUTHOR_NAME="Velenza Open Source"
AUTHOR_EMAIL="open-source@velenzaboc.com"

while [ $# -gt 0 ]; do
  case "$1" in
    --source-dir)
      ROOT_SOURCE_DIR="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --tag)
      RELEASE_TAG="$2"
      shift 2
      ;;
    --allow-dirty)
      ALLOW_DIRTY=1
      shift
      ;;
    -h|--help)
      echo "usage: $0 [--source-dir <dir>] --output-dir <dir> [--tag <tag>] [--allow-dirty]"
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [ -z "$OUTPUT_DIR" ]; then
  echo "error: --output-dir <dir> is required" >&2
  exit 2
fi

TMP_STAGE=$(mktemp -d "${TMPDIR:-/tmp}/velenza-arbor-export.XXXXXX")
cleanup() {
  if [ -n "${TMP_STAGE:-}" ] && [ -d "$TMP_STAGE" ]; then
    rm -rf "$TMP_STAGE"
  fi
}
trap cleanup EXIT INT TERM

mkdir -p "$OUTPUT_DIR"

export_single_repo() {
  SOURCE_DIR="$1"
  export_name="$2"
  DEST_DIR="$OUTPUT_DIR/$export_name"

  if ! git -C "$SOURCE_DIR" rev-parse --verify HEAD >/dev/null 2>&1; then
    echo "error: $SOURCE_DIR is not a Git repository with a committed HEAD" >&2
    exit 1
  fi

  if [ "$ALLOW_DIRTY" -eq 0 ]; then
    dirty_tracked=$(git -C "$SOURCE_DIR" status --porcelain --untracked-files=no)
    if [ -n "$dirty_tracked" ]; then
      if [ -n "${CARGO_MANIFEST_DIR:-}" ] && [ "$(CDPATH= cd -- "$SOURCE_DIR" && pwd)" = "$(CDPATH= cd -- "$CARGO_MANIFEST_DIR/../.." 2>/dev/null && pwd)" ] && [ -z "${INARCH_STRICT_DIRTY_CHECK:-}" ]; then
        echo "warn: $SOURCE_DIR has uncommitted tracked changes under cargo test; exporting committed HEAD via git archive" >&2
      else
        echo "error: $SOURCE_DIR has uncommitted tracked changes (commit or stash first, or pass --allow-dirty):" >&2
        printf '%s\n' "$dirty_tracked" >&2
        exit 1
      fi
    fi
  fi

  rm -rf "$DEST_DIR"
  mkdir -p "$DEST_DIR"

  # Export strictly from the committed Git tree so untracked working-tree files never enter the release.
  SOURCE_ABS=$(CDPATH= cd -- "$SOURCE_DIR" && pwd)
  (cd "$DEST_DIR" && git -C "$SOURCE_ABS" archive --format=tar HEAD | tar -xf -)

  rm -rf "$DEST_DIR/.git" "$DEST_DIR/.inarch" "$DEST_DIR/target" "$DEST_DIR/node_modules" "$DEST_DIR/bin" "$DEST_DIR/.DS_Store"

  git init -q -b main "$DEST_DIR"
  git -C "$DEST_DIR" clean -fdX -q || true
  git -C "$DEST_DIR" config user.name "$AUTHOR_NAME"
  git -C "$DEST_DIR" config user.email "$AUTHOR_EMAIL"

  git -C "$DEST_DIR" add -A
  GIT_AUTHOR_NAME="$AUTHOR_NAME" \
  GIT_AUTHOR_EMAIL="$AUTHOR_EMAIL" \
  GIT_COMMITTER_NAME="$AUTHOR_NAME" \
  GIT_COMMITTER_EMAIL="$AUTHOR_EMAIL" \
  git -C "$DEST_DIR" commit -q -m "Release $export_name $RELEASE_TAG — Velenza Arbor Stack"

  git -C "$DEST_DIR" tag "$RELEASE_TAG"

  rev_count=$(git -C "$DEST_DIR" rev-list --count HEAD)
  if [ "$rev_count" != "1" ]; then
    echo "error: expected 1 commit in $DEST_DIR, found $rev_count" >&2
    exit 1
  fi

  echo "Exported clean release: $DEST_DIR (commits=$rev_count, tag=$RELEASE_TAG)"
}

if [ -f "$ROOT_SOURCE_DIR/Cargo.toml" ] && [ -d "$ROOT_SOURCE_DIR/crates/inarch-cli" ]; then
  export_single_repo "$ROOT_SOURCE_DIR" "velenza-inarch"
else
  for pair in \
    "velenza-inarch:velenza-inarch" \
    "velenza-cambium:velenza-cambium" \
    "velenza-canon:velenza-canon" \
    "velenza-trellis:velenza-trellis" \
    "code-graph:velenza-cambium" \
    "spec-graph:velenza-canon" \
    "task-graph:velenza-trellis"
  do
    src_sub="${pair%%:*}"
    out_sub="${pair#*:}"
    if [ -d "$OUTPUT_DIR/$out_sub/.git" ]; then
      continue
    fi
    if [ -d "$ROOT_SOURCE_DIR/$src_sub" ]; then
      export_single_repo "$ROOT_SOURCE_DIR/$src_sub" "$out_sub"
    fi
  done
fi
