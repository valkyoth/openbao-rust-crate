#!/usr/bin/env sh
set -eu

echo "checks: latest versions"
scripts/check_latest_crates.sh

echo "checks: formatting"
cargo fmt --all --check

echo "checks: release metadata"
scripts/validate-release-metadata.sh

echo "checks: OpenBao release lock"
python3 scripts/validate_openbao_release_lock.py
python3 scripts/validate_openbao_release_lock.py --self-test

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
rustsec_db="${OPENBAO_RUSTSEC_DB:-/tmp/openbao-rust-crate-advisory-db}"
cargo audit --db "$rustsec_db"
cargo audit --db "$rustsec_db" \
  --file tests/fixtures/reqwest-native-unification/Cargo.lock

echo "checks: Kani"
scripts/check_kani.sh

echo "checks: ok"
