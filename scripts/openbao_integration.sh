#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TLS_DIR="$ROOT_DIR/deploy/podman/dev-state/tls"
TOKEN_FILE=""

cleanup() {
  if [ -n "$TOKEN_FILE" ] && [ -f "$TOKEN_FILE" ]; then
    rm -f "$TOKEN_FILE"
  fi
  "$ROOT_DIR/scripts/openbao_dev.sh" down >/dev/null 2>&1 || true
}

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required" >&2
    exit 1
  fi
}

wait_for_tls() {
  count=0
  while [ "$count" -lt 60 ]; do
    if curl --cacert "$TLS_DIR/dev-ca.crt" -sS https://127.0.0.1:9940/v1/sys/health >/dev/null 2>&1; then
      return 0
    fi
    count=$((count + 1))
    sleep 1
  done
  echo "OpenBao did not become reachable on https://127.0.0.1:9940" >&2
  return 1
}

parse_init_field() {
  field="$1"
  FIELD="$field" python3 -c 'import json, os, sys; data = json.load(sys.stdin); value = data[os.environ["FIELD"]]; print(value[0] if isinstance(value, list) else value)'
}

require curl
require podman
require python3

trap cleanup EXIT INT TERM

"$ROOT_DIR/scripts/openbao_dev.sh" clean >/dev/null 2>&1 || true
"$ROOT_DIR/scripts/openbao_dev.sh" up
wait_for_tls

INIT_JSON=$(podman exec openbao_rust_crate_dev bao operator init -address=https://127.0.0.1:8200 -ca-cert=/openbao/tls/dev-ca.crt -key-shares=1 -key-threshold=1 -format=json)
UNSEAL_KEY=$(printf '%s' "$INIT_JSON" | parse_init_field unseal_keys_b64)
ROOT_TOKEN=$(printf '%s' "$INIT_JSON" | parse_init_field root_token)
unset INIT_JSON

podman exec openbao_rust_crate_dev bao operator unseal -address=https://127.0.0.1:8200 -ca-cert=/openbao/tls/dev-ca.crt "$UNSEAL_KEY" >/dev/null
unset UNSEAL_KEY

TOKEN_FILE=$(mktemp "${TMPDIR:-/tmp}/openbao-token.XXXXXX")
chmod 600 "$TOKEN_FILE"
printf '%s' "$ROOT_TOKEN" > "$TOKEN_FILE"
unset ROOT_TOKEN

OPENBAO_INTEGRATION=1 \
BAO_ADDR=https://127.0.0.1:9940 \
BAO_CACERT="$TLS_DIR/dev-ca.crt" \
BAO_TOKEN_FILE="$TOKEN_FILE" \
cargo test --test openbao_integration --all-features -- --test-threads=1
