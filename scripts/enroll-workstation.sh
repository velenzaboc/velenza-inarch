#!/usr/bin/env bash
# Velenza Inarch Workstation Onboarding Script (`scripts/enroll-workstation.sh`)
#
# Enrolls a workstation's service-account OIDC identity in the central Velenza Inarch
# server (`ScionPrincipals`), configures `~/.config/velenza-inarch/inarch.toml` on
# the target workstation over SSH (or locally), and verifies authentication via
# `inr whoami`.
#
# Usage:
#   ./scripts/enroll-workstation.sh \
#     --server http://velenza-inarch.internal:7331 \
#     --host dev-workstation-01 \
#     --email workstation-01@example-project.iam.gserviceaccount.com \
#     --sa-key-path /path/on/target/to/service_account.json \
#     [--ssh user@dev-workstation-01] \
#     [--kind workstation|admin] \
#     [--repos "*"] \
#     [--ops "read,land"] \
#     [--write-prefixes "*"]

set -euo pipefail

SERVER_URL="${INARCH_REMOTE_URL:-}"
HOST_NAME=""
EMAIL=""
SSH_TARGET=""
SA_KEY_PATH=""
KIND="workstation"
REPOS="*"
OPS="read,land"
WRITE_PREFIXES="*"
INARCH_BIN="${INARCH_BIN:-inr}"
ADMIN_CONFIG="${INARCH_CONFIG:-$HOME/.config/velenza-inarch/inarch.toml}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)
      SERVER_URL="$2"
      shift 2
      ;;
    --host)
      HOST_NAME="$2"
      shift 2
      ;;
    --email)
      EMAIL="$2"
      shift 2
      ;;
    --ssh)
      SSH_TARGET="$2"
      shift 2
      ;;
    --sa-key-path)
      SA_KEY_PATH="$2"
      shift 2
      ;;
    --kind)
      KIND="$2"
      shift 2
      ;;
    --repos)
      REPOS="$2"
      shift 2
      ;;
    --ops)
      OPS="$2"
      shift 2
      ;;
    --write-prefixes)
      WRITE_PREFIXES="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$SERVER_URL" || -z "$HOST_NAME" || -z "$EMAIL" || -z "$SA_KEY_PATH" ]]; then
  echo "Usage: $0 --server <url> --host <hostname> --email <service-account-email> --sa-key-path <path> [--ssh <user@host>] [--kind workstation|admin] [--repos '*'] [--ops 'read,land']" >&2
  exit 1
fi

echo "==> [1/3] Enrolling principal '$EMAIL' (host=$HOST_NAME, kind=$KIND) on $SERVER_URL..."
"$INARCH_BIN" --config "$ADMIN_CONFIG" principal enroll "$EMAIL" \
  --kind "$KIND" \
  --host "$HOST_NAME" \
  --repos "$REPOS" \
  --ops "$OPS" \
  --write-prefixes "$WRITE_PREFIXES"

echo "==> [2/3] Writing ~/.config/velenza-inarch/inarch.toml for $HOST_NAME..."
if [[ -n "$SSH_TARGET" ]]; then
  ssh "$SSH_TARGET" "mkdir -p ~/.config/velenza-inarch && cat > ~/.config/velenza-inarch/inarch.toml <<EOF
remote_url = \"$SERVER_URL\"
gcp_credentials_file = \"$SA_KEY_PATH\"
EOF
chmod 600 ~/.config/velenza-inarch/inarch.toml"
  echo "==> [3/3] Verifying remote OIDC authentication from $SSH_TARGET..."
  ssh "$SSH_TARGET" "inr --config ~/.config/velenza-inarch/inarch.toml whoami"
else
  mkdir -p "$HOME/.config/velenza-inarch"
  cat > "$HOME/.config/velenza-inarch/inarch.toml" <<EOF
remote_url = "$SERVER_URL"
gcp_credentials_file = "$SA_KEY_PATH"
EOF
  chmod 600 "$HOME/.config/velenza-inarch/inarch.toml"
  echo "==> [3/3] Verifying local OIDC authentication..."
  "$INARCH_BIN" --config "$HOME/.config/velenza-inarch/inarch.toml" whoami
fi

echo "==> Workstation '$HOST_NAME' ($EMAIL) successfully enrolled and verified."
