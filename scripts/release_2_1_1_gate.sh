#!/usr/bin/env sh
set -eu

grep -q '^version = "2.1.1"$' Cargo.toml
grep -q 'sanitization = { version = "2.0.3"' Cargo.toml
grep -q 'openbao = { path = "..", version = "=2.1.1"' fuzz/Cargo.toml
grep -q 'openbao = { path = "../../..", version = "=2.1.1"' \
  tests/fixtures/reqwest-native-unification/Cargo.toml
grep -q 'Version: 2.1.1' release-notes/RELEASE_NOTES_2.1.1.md
grep -q '2.1.1 - 2026-07-21' CHANGELOG.md
scripts/checks.sh
python3 -B scripts/openbao_core_matrix.py --verify
python3 -B scripts/generate_openbao_version_contracts.py --verify
scripts/generate-sbom.sh

echo "release 2.1.1 gate complete"
echo "Require green GitHub CI, CodeQL, the all-release compatibility workflow, and exact-commit pentests before tagging."
