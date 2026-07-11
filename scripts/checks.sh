#!/usr/bin/env sh
set -eu

echo "checks: latest versions"
scripts/check_latest_crates.sh

echo "checks: formatting"
cargo fmt --all --check

echo "checks: release metadata"
scripts/validate-release-metadata.sh

echo "checks: Rust 1.90.0 MSRV"
cargo +1.90.0 check --locked --all-targets --all-features

echo "checks: OpenBao release lock"
python3 scripts/validate_openbao_release_lock.py
python3 scripts/validate_openbao_release_lock.py --self-test

echo "checks: OpenBao API snapshots"
python3 scripts/openbao_api_snapshots.py --verify
python3 scripts/openbao_api_snapshots.py --self-test

echo "checks: OpenBao 2.5.5 contract matrix"
python3 scripts/generate_openbao_contract_matrix.py --verify
python3 scripts/generate_openbao_contract_matrix.py --self-test

echo "checks: OpenBao capability registry"
python3 -B scripts/generate_openbao_capability_registry.py --verify
python3 -B scripts/generate_openbao_capability_registry.py --self-test

echo "checks: versioned OpenBao response fixtures"
python3 -B scripts/generate_openbao_response_fixtures.py --verify
python3 -B scripts/generate_openbao_response_fixtures.py --self-test

echo "checks: complete OpenBao version contracts"
python3 -B scripts/generate_openbao_version_contracts.py --verify
python3 -B scripts/generate_openbao_version_contracts.py --self-test

echo "checks: version-locked OpenBao integration harness"
python3 scripts/openbao_test_harness.py --self-test

echo "checks: historical OpenBao core-flow evidence"
python3 scripts/openbao_core_matrix.py --verify
python3 scripts/openbao_core_matrix.py --self-test

echo "checks: OpenBao compatibility CI controller"
python3 -B scripts/openbao_ci_matrix.py self-test

echo "checks: clippy default"
cargo clippy --all-targets -- -D warnings

echo "checks: clippy all features"
cargo clippy --all-targets --all-features -- -D warnings

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
cargo package --locked --allow-dirty

echo "checks: dependency policy"
cargo deny check
cargo deny --manifest-path tests/fixtures/reqwest-native-unification/Cargo.toml \
  --config deny.toml check

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

echo "checks: Kani"
scripts/check_kani.sh

echo "checks: ok"
