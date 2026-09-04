#!/usr/bin/env sh
set -eu

grep -q '^version = "2.1.5"$' Cargo.toml
grep -q 'base64-ng = { version = "2.0.3"' Cargo.toml
grep -q 'sanitization = { version = "2.0.4"' Cargo.toml
grep -q 'rustix = { version = "1.1.4"' Cargo.toml
grep -q 'windows-sys = { version = "0.61.2"' Cargo.toml
grep -q 'channel = "1.98.1"' rust-toolchain.toml
grep -q 'openbao = { path = "..", version = "=2.1.5"' fuzz/Cargo.toml
grep -q 'openbao = { path = "../../..", version = "=2.1.5"' \
  tests/fixtures/reqwest-native-unification/Cargo.toml
grep -q 'Version: 2.1.5' release-notes/RELEASE_NOTES_2.1.5.md
grep -q '2.1.5 - 2026-09-04' CHANGELOG.md
grep -q 'taiki-e/install-action v2.87.4' .github/workflows/ci.yml
grep -q 'uses: taiki-e/install-action@e67fa11c4b9316fa714ddf0abed07a0c3143b95b' \
  .github/workflows/ci.yml
grep -q 'rustup toolchain install 1.98.1' \
  .github/workflows/openbao-compatibility.yml
grep -q '"version": "2.6.2"' compat/releases.lock.json
grep -q '"version":"2.6.2"' compat/image-signatures.lock.json
grep -q '"version": "2.6.2"' compat/core-flow-results.json
grep -q '| `2.6.2` | 689 | 594 | 93 | 2 |' \
  docs/OPENBAO_VERSION_SUPPORT_MATRIX.md

if grep -q 'with_nonce("request-nonce")' tests/http_client.rs; then
  echo "hard-coded OIDC request nonce fixture remains" >&2
  exit 1
fi
if grep -Eq '(cassandra|influx|valkey)-password' src/secrets/database.rs; then
  echo "hard-coded database password fixture remains" >&2
  exit 1
fi
if grep -Eq '\{(blocked|rejected|signing):\?\}' tests/openbao_integration.rs; then
  echo "secret-bearing integration result remains in diagnostics" >&2
  exit 1
fi

scripts/checks.sh
python3 -B scripts/openbao_core_matrix.py --verify
python3 -B scripts/generate_openbao_version_contracts.py --verify
scripts/generate-sbom.sh

echo "release 2.1.5 gate complete"
echo "Require green GitHub CI, CodeQL, the all-release compatibility workflow, and exact-commit pentests before tagging."
