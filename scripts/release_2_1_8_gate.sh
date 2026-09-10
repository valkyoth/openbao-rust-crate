#!/usr/bin/env sh
set -eu

grep -q '^version = "2.1.8"$' Cargo.toml
grep -q '^base64-ng = { version = "2.0.4"' Cargo.toml
grep -q '^reqwest = { version = "0.13.5"' Cargo.toml
grep -q 'taiki-e/install-action v2.87.9' .github/workflows/ci.yml
grep -q 'uses: taiki-e/install-action@c3ec0de9ae7f1019cea21aa96aa0a895b9552063' \
  .github/workflows/ci.yml
grep -Fq '{ name = "base64", version = "0.22" }' deny.toml
grep -q '^secrecy = { package = "sanitization-secrecy", version = "2.1.0", default-features = false, features = \["serde"\] }$' Cargo.toml
grep -q '^sanitization = { version = "2.1.0", default-features = false, features = \["alloc"\] }$' Cargo.toml
grep -q 'openbao = { path = "..", version = "=2.1.8"' fuzz/Cargo.toml
grep -q 'openbao = { path = "../../..", version = "=2.1.8"' \
  tests/fixtures/reqwest-native-unification/Cargo.toml
grep -q 'Version: 2.1.8' release-notes/RELEASE_NOTES_2.1.8.md
grep -q '2.1.8 - 2026-09-10' CHANGELOG.md
grep -q 'transit_batch_result_debug_redacts_item_errors' src/secrets/transit.rs
grep -q 'typed_transit_encrypt_retains_sanitizing_body_owner' src/client.rs
grep -q 'cancelling_response_after_received_chunk_drops_accumulator' src/client.rs
grep -q 'transit_decrypt_parser_edges_remain_secret_free' tests/http_client.rs
grep -q 'transit_chunked_response_limit_is_enforced_without_content_length' tests/http_client.rs
grep -q 'typed_transit_tracing_excludes_secret_material' tests/tracing_secrets.rs
grep -q "serde_json's private ordinary scratch buffer" docs/SECURITY_MODEL.md

if grep -q '^name = "secrecy"$' Cargo.lock fuzz/Cargo.lock \
  tests/fixtures/reqwest-native-unification/Cargo.lock; then
  echo "upstream secrecy package remains in a release lockfile" >&2
  exit 1
fi

require_package_version() {
  lockfile=$1
  package=$2
  version=$3
  awk -v package="$package" -v version="$version" '
    /^\[\[package\]\]$/ { in_package = 0 }
    $0 == "name = \"" package "\"" { in_package = 1 }
    in_package && $0 == "version = \"" version "\"" { found = 1 }
    END { exit found ? 0 : 1 }
  ' "$lockfile"
}

for lockfile in Cargo.lock fuzz/Cargo.lock tests/fixtures/reqwest-native-unification/Cargo.lock; do
  require_package_version "$lockfile" sanitization 2.1.0
  require_package_version "$lockfile" sanitization-secrecy 2.1.0
  require_package_version "$lockfile" reqwest 0.13.5
done
for lockfile in Cargo.lock fuzz/Cargo.lock; do
  require_package_version "$lockfile" base64-ng 2.0.4
done

cargo test --locked --all-features --test tracing_secrets
cargo test --locked --all-features --test http_client transit_
cargo clippy --locked --no-default-features --features rustls-tls -- -D warnings
scripts/checks.sh
python3 -B scripts/openbao_core_matrix.py --verify
python3 -B scripts/generate_openbao_version_contracts.py --verify
scripts/generate-sbom.sh

echo "release 2.1.8 gate complete"
echo "Require green GitHub CI, CodeQL, the all-release compatibility workflow, exact OpenBao 2.6.2 TLS integration, and exact-commit pentests before tagging."
