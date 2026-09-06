#!/usr/bin/env sh
set -eu

grep -q '^version = "2.1.6"$' Cargo.toml
grep -q '^bytes = "1.12.1"$' Cargo.toml
grep -q '^monitor-stream = \["sys", "dep:futures-core", "reqwest/stream"\]$' Cargo.toml
grep -q '^raft-stream = \["sys", "dep:futures-core", "reqwest/stream"\]$' Cargo.toml
grep -q 'openbao = { path = "..", version = "=2.1.6"' fuzz/Cargo.toml
grep -q 'openbao = { path = "../../..", version = "=2.1.6"' \
  tests/fixtures/reqwest-native-unification/Cargo.toml
grep -q 'Version: 2.1.6' release-notes/RELEASE_NOTES_2.1.6.md
grep -q '2.1.6 - 2026-09-06' CHANGELOG.md
grep -q 'taiki-e/install-action v2.87.6' .github/workflows/ci.yml
grep -q 'uses: taiki-e/install-action@7b8d4719ee4aaa279bdf55df38dacb9ebfe12a6c' \
  .github/workflows/ci.yml
grep -q 'Bytes::from_owner(self)' src/client.rs
grep -q 'sanitization::wipe::vec(&mut self.bytes)' src/client.rs
grep -q 'sanitize_response_chunk_if_unique' src/client.rs
grep -q 'sanitize_response_chunk_if_unique' src/sys.rs
grep -q 'transit-sensitive-buffer-regression' tests/openbao_integration.rs
grep -q 'pawalyze-record-binding' tests/openbao_integration.rs
grep -q 'key_version = Some(1)' tests/openbao_integration.rs
grep -q 'wrong-record-binding' tests/openbao_integration.rs

if grep -Eq 'Vec::from\(&encoded\[\.\.\]\)\.into\(\)|Vec::from\(bytes\)\)\.into\(\)|body\.to_vec\(\)\.into\(\)' src/client.rs; then
  echo "ordinary sensitive HTTP body copy remains" >&2
  exit 1
fi

if grep -Eq 'normal non-sanitizing (reqwest|HTTP) body|ordinary Vec owned by the HTTP request' \
  README.md SECURITY.md docs/SECURITY_MODEL.md src/lib.rs src/secrets/transit.rs; then
  echo "stale sensitive HTTP body residual documentation remains" >&2
  exit 1
fi

cargo test --locked --lib --all-features sanitizing_body
cargo test --locked --lib --all-features response_chunk_cleanup
scripts/checks.sh
python3 -B scripts/openbao_core_matrix.py --verify
python3 -B scripts/generate_openbao_version_contracts.py --verify
scripts/generate-sbom.sh

echo "release 2.1.6 gate complete"
echo "Require green GitHub CI, CodeQL, the all-release compatibility workflow, exact OpenBao 2.6.2 TLS integration, and exact-commit pentests before tagging."
