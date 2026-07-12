#!/usr/bin/env sh
set -eu

grep -q '^version = "2.0.2"$' Cargo.toml
grep -q 'openbao = { path = "..", version = "=2.0.2"' fuzz/Cargo.toml
grep -q 'openbao = { path = "../../..", version = "=2.0.2"' \
  tests/fixtures/reqwest-native-unification/Cargo.toml
scripts/checks.sh
python3 -B scripts/openbao_core_matrix.py --verify
python3 -B scripts/generate_openbao_version_contracts.py --verify
scripts/generate-sbom.sh

echo "release 2.0 gate complete"
echo "Require a green all-release GitHub compatibility workflow and exact-commit pentest before tagging."
