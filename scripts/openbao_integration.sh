#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

case "$#" in
  0)
    version=2.5.5
    ;;
  1)
    version=$1
    ;;
  *)
    echo "usage: $0 [exact-inventory-version]" >&2
    exit 2
    ;;
esac

exec python3 "$ROOT_DIR/scripts/openbao_test_harness.py" --version "$version"
