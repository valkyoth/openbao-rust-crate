#!/usr/bin/env sh
set -eu

grep -q '^version = "2.1.4"$' Cargo.toml
grep -q 'futures-core = { version = "0.3.34"' Cargo.toml
grep -q 'openbao = { path = "..", version = "=2.1.4"' fuzz/Cargo.toml
grep -q 'openbao = { path = "../../..", version = "=2.1.4"' \
  tests/fixtures/reqwest-native-unification/Cargo.toml
grep -q 'Version: 2.1.4' release-notes/RELEASE_NOTES_2.1.4.md
grep -q '2.1.4 - 2026-08-19' CHANGELOG.md
grep -q '"version": "2.6.2"' compat/releases.lock.json
grep -q '"version":"2.6.2"' compat/image-signatures.lock.json
grep -q '"version": "2.6.2"' compat/core-flow-results.json
grep -q '| `2.6.2` | 689 | 594 | 93 | 2 |' \
  docs/OPENBAO_VERSION_SUPPORT_MATRIX.md
scripts/checks.sh
python3 -B scripts/openbao_core_matrix.py --verify
python3 -B scripts/generate_openbao_version_contracts.py --verify
scripts/generate-sbom.sh

echo "release 2.1.4 gate complete"
echo "Require green GitHub CI, CodeQL, the all-release compatibility workflow, and exact-commit pentests before tagging."
