#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PODMAN_DIR="$ROOT_DIR/deploy/podman"
STATE_DIR="$PODMAN_DIR/dev-state"
TLS_DIR="$STATE_DIR/tls"
COMPOSE_FILE="$PODMAN_DIR/compose.dev.yml"
OPENBAO_IMAGE="docker.io/openbao/openbao:2.5.5@sha256:e59b4c73cfce6875363d25548222819433c6ce0af9c6d3ec9ede220e905723f9"
DATA_VOLUME="openbao-rust-crate_openbao_data"

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required" >&2
    exit 1
  fi
}

prepare_tls_for_container() {
  chmod 750 "$STATE_DIR" "$TLS_DIR"
  chmod 600 "$TLS_DIR/dev-ca.key"
  chmod 640 "$TLS_DIR/openbao.key"
  chmod 644 "$TLS_DIR/dev-ca.crt" "$TLS_DIR/openbao.crt"
  if [ -f "$TLS_DIR/dev-ca.srl" ]; then
    chmod 644 "$TLS_DIR/dev-ca.srl"
  fi
}

prepare_data_volume() {
  require podman
  if ! podman volume inspect "$DATA_VOLUME" >/dev/null 2>&1; then
    podman volume create "$DATA_VOLUME" >/dev/null
  fi
  podman run --rm --user 0:0 --entrypoint chown -v "$DATA_VOLUME:/openbao/data" "$OPENBAO_IMAGE" -R 100:100 /openbao/data >/dev/null
}

generate_tls() {
  require openssl
  mkdir -p "$TLS_DIR"
  chmod 755 "$STATE_DIR"
  chmod 755 "$TLS_DIR"

  if [ ! -f "$TLS_DIR/dev-ca.key" ] || [ ! -f "$TLS_DIR/dev-ca.crt" ]; then
    openssl req \
      -x509 \
      -newkey rsa:4096 \
      -sha256 \
      -days 30 \
      -nodes \
      -keyout "$TLS_DIR/dev-ca.key" \
      -out "$TLS_DIR/dev-ca.crt" \
      -subj "/CN=OpenBao Rust Crate Dev CA" \
      -addext "basicConstraints = critical, CA:true" \
      -addext "keyUsage = critical, keyCertSign, cRLSign" \
      -addext "subjectKeyIdentifier = hash"
    chmod 600 "$TLS_DIR/dev-ca.key"
    chmod 644 "$TLS_DIR/dev-ca.crt"
  fi

  if [ ! -f "$TLS_DIR/openbao.key" ] || [ ! -f "$TLS_DIR/openbao.crt" ]; then
    openssl req \
      -newkey rsa:4096 \
      -sha256 \
      -nodes \
      -keyout "$TLS_DIR/openbao.key" \
      -out "$TLS_DIR/openbao.csr" \
      -subj "/CN=127.0.0.1"

    EXT_FILE="$TLS_DIR/openbao.ext"
    {
      echo "subjectAltName = DNS:localhost,IP:127.0.0.1"
      echo "extendedKeyUsage = serverAuth"
      echo "keyUsage = critical, digitalSignature, keyEncipherment"
    } > "$EXT_FILE"

    openssl x509 \
      -req \
      -in "$TLS_DIR/openbao.csr" \
      -CA "$TLS_DIR/dev-ca.crt" \
      -CAkey "$TLS_DIR/dev-ca.key" \
      -CAcreateserial \
      -out "$TLS_DIR/openbao.crt" \
      -days 30 \
      -sha256 \
      -extfile "$EXT_FILE"

    rm -f "$TLS_DIR/openbao.csr" "$EXT_FILE"
    chmod 600 "$TLS_DIR/openbao.key"
    chmod 644 "$TLS_DIR/openbao.crt"
  fi

  chmod 755 "$TLS_DIR"
  chmod 600 "$TLS_DIR/dev-ca.key" "$TLS_DIR/openbao.key"
  chmod 644 "$TLS_DIR/dev-ca.crt" "$TLS_DIR/openbao.crt"
  if [ -f "$TLS_DIR/dev-ca.srl" ]; then
    chmod 644 "$TLS_DIR/dev-ca.srl"
  fi
  prepare_tls_for_container
}

compose() {
  require podman
  cd "$PODMAN_DIR"
  podman compose -p openbao-rust-crate -f "$COMPOSE_FILE" "$@"
}

case "${1:-help}" in
  prepare)
    generate_tls
    prepare_data_volume
    echo "OpenBao dev assets prepared."
    echo "BAO_CACERT=$TLS_DIR/dev-ca.crt"
    ;;
  up)
    generate_tls
    compose pull
    prepare_data_volume
    compose up -d
    echo "BAO_ADDR=https://127.0.0.1:9940"
    echo "BAO_CACERT=$TLS_DIR/dev-ca.crt"
    ;;
  down)
    compose down
    ;;
  logs)
    compose logs -f openbao
    ;;
  status)
    require podman
    podman exec openbao_rust_crate_dev bao status -address=https://127.0.0.1:8200 -ca-cert=/openbao/tls/dev-ca.crt
    ;;
  clean)
    compose down -v
    require podman
    podman volume rm -f "$DATA_VOLUME" >/dev/null 2>&1 || true
    rm -rf "$STATE_DIR"
    ;;
  *)
    echo "usage: $0 {prepare|up|down|logs|status|clean}" >&2
    exit 2
    ;;
esac
