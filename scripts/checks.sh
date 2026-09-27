#!/usr/bin/env sh
set -eu

echo "checks: latest versions"
scripts/check_latest_crates.sh

echo "checks: formatting"
cargo fmt --all --check

echo "checks: release metadata"
test -f docs/PANIC_POLICY.md
grep -q 'No production exception is currently approved' docs/PANIC_POLICY.md
scripts/validate-release-metadata.sh

echo "checks: Rust 1.90.0 MSRV"
cargo +1.90.0 check --locked --all-targets --all-features

echo "checks: OpenBao release lock"
/usr/bin/python3 -E -s -S -B scripts/validate_openbao_release_lock.py
/usr/bin/python3 -E -s -S -B scripts/validate_openbao_release_lock.py --self-test

echo "checks: OpenBao API snapshots"
/usr/bin/python3 -E -s -S -B scripts/openbao_api_snapshots.py --verify
/usr/bin/python3 -E -s -S -B scripts/openbao_api_snapshots.py --self-test

echo "checks: staged OpenBao 2.7.0 source inventory"
/usr/bin/python3 -E -s -S -B scripts/openbao_2_7_source_inventory.py --verify
/usr/bin/python3 -E -s -S -B scripts/openbao_2_7_source_inventory.py --self-test

echo "checks: staged OpenBao 2.7.0 API evidence"
/usr/bin/python3 -E -s -S -B scripts/openbao_2_7_api.py --verify
/usr/bin/python3 -E -s -S -B scripts/openbao_2_7_api.py --self-test
/usr/bin/python3 -E -s -S -B scripts/test_openbao_evidence.py

echo "checks: staged OpenBao 2.7 external-plugin availability and local fixture"
/usr/bin/python3 -E -s -S -B scripts/openbao_2_7_plugins.py
/usr/bin/python3 -E -s -S -B scripts/openbao_2_7_plugins.py --verify-tls
/usr/bin/python3 -E -s -S -B scripts/test_openbao_2_7_plugins.py
/usr/bin/python3 -E -s -S -B scripts/test_openbao_2_7_tls.py

echo "checks: historical OpenBao 2.6.0 onboarding evidence"
/usr/bin/python3 -E -s -S -B scripts/openbao_onboarding_api.py --verify
/usr/bin/python3 -E -s -S -B scripts/openbao_onboarding_api.py --self-test

echo "checks: OpenBao 2.5.5 contract matrix"
/usr/bin/python3 -E -s -S -B scripts/generate_openbao_contract_matrix.py --verify
/usr/bin/python3 -E -s -S -B scripts/generate_openbao_contract_matrix.py --self-test

echo "checks: OpenBao capability registry"
/usr/bin/python3 -E -s -S -B scripts/generate_openbao_capability_registry.py --verify
/usr/bin/python3 -E -s -S -B scripts/generate_openbao_capability_registry.py --self-test

echo "checks: versioned OpenBao response fixtures"
/usr/bin/python3 -E -s -S -B scripts/generate_openbao_response_fixtures.py --verify
/usr/bin/python3 -E -s -S -B scripts/generate_openbao_response_fixtures.py --self-test

echo "checks: complete OpenBao version contracts"
/usr/bin/python3 -E -s -S -B scripts/generate_openbao_version_contracts.py --verify
/usr/bin/python3 -E -s -S -B scripts/generate_openbao_version_contracts.py --self-test

echo "checks: version-locked OpenBao integration harness"
/usr/bin/python3 -E -s -S -B scripts/openbao_test_harness.py --self-test

echo "checks: historical OpenBao core-flow evidence"
/usr/bin/python3 -E -s -S -B scripts/openbao_core_matrix.py --verify
/usr/bin/python3 -E -s -S -B scripts/openbao_core_matrix.py --self-test

echo "checks: OpenBao compatibility CI controller"
/usr/bin/python3 -E -s -S -B scripts/openbao_ci_matrix.py self-test

echo "checks: compatibility fuzz targets"
cargo check --manifest-path fuzz/Cargo.toml --locked --bins

echo "checks: clippy default"
cargo clippy --all-targets -- -D warnings

echo "checks: clippy unauthenticated workflows without operator operations"
cargo clippy --all-targets \
  --features unauthenticated-workflows,unauthenticated-workflows-acknowledged \
  -- -D warnings

echo "checks: clippy all features"
cargo clippy --all-targets --all-features -- -D warnings

echo "checks: clippy client-only feature set"
cargo clippy --no-default-features --features rustls-tls -- -D warnings

echo "checks: reqwest TLS feature unification"
cargo run --manifest-path tests/fixtures/reqwest-native-unification/Cargo.toml --locked

echo "checks: tests default"
cargo test --all-targets

echo "checks: tests all features"
cargo test --all-targets --all-features

echo "checks: doctests"
cargo test --doc --all-features

echo "checks: docs"
cargo doc --no-deps --all-features

echo "checks: package"
package_files="$(cargo package --locked --allow-dirty --list)"
for forbidden in \
  '.github/' \
  'compat/' \
  'deploy/' \
  'kani/' \
  'release-notes/' \
  'scripts/' \
  'CONTRIBUTING.md' \
  'deny.toml' \
  'rust-toolchain.toml' \
  'docs/' \
  'tests/http_client.rs' \
  'tests/serde_fixtures.rs' \
  'tests/fixtures/' \
  'tests/openbao_integration.rs' \
  'tests/version_contract.rs'
do
  if printf '%s\n' "$package_files" | grep -F -q "$forbidden"; then
    echo "repository-only path entered crates.io package: $forbidden" >&2
    exit 1
  fi
done
cargo package --locked --allow-dirty
package_version="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml | head -n 1)"
package_archive="target/package/openbao-${package_version}.crate"
package_bytes="$(wc -c < "$package_archive")"
if [ "$package_bytes" -gt 524288 ]; then
  echo "crates.io package exceeds 512 KiB compressed limit: $package_bytes bytes" >&2
  exit 1
fi
echo "checks: package archive $package_bytes bytes"
echo "checks: packaged public-API smoke tests"
cargo test --manifest-path "target/package/openbao-${package_version}/Cargo.toml" \
  --locked --test package_smoke --all-features
echo "checks: packaged examples"
cargo check --manifest-path "target/package/openbao-${package_version}/Cargo.toml" \
  --locked --examples --all-features

echo "checks: dependency policy"
cargo deny check
cargo deny --manifest-path tests/fixtures/reqwest-native-unification/Cargo.toml \
  --config deny.toml check
cargo deny --manifest-path fuzz/Cargo.toml --config deny.toml check

echo "checks: RustSec advisories"
rustsec_db="${OPENBAO_RUSTSEC_DB:-}"
rustsec_db_cleanup=
if [ -z "$rustsec_db" ]; then
  rustsec_db="$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/openbao-rustsec.XXXXXX")"
  rustsec_db_cleanup="$rustsec_db"
  cleanup_rustsec_db() {
    if [ -n "$rustsec_db_cleanup" ]; then
      rm -rf -- "$rustsec_db_cleanup"
      rustsec_db_cleanup=
    fi
  }
  trap cleanup_rustsec_db EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
fi
cargo audit --db "$rustsec_db"
cargo audit --db "$rustsec_db" \
  --file tests/fixtures/reqwest-native-unification/Cargo.lock
cargo audit --db "$rustsec_db" --file fuzz/Cargo.lock

echo "checks: Kani"
scripts/check_kani.sh

echo "checks: ok"
