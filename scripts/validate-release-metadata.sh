#!/usr/bin/env sh
set -eu

check_file() {
  if [ ! -f "$1" ]; then
    echo "missing required release metadata file: $1" >&2
    exit 1
  fi
}

check_grep() {
  pattern="$1"
  file="$2"
  if ! grep -q "$pattern" "$file"; then
    echo "missing required release metadata pattern in $file: $pattern" >&2
    exit 1
  fi
}

check_file Cargo.toml
check_file README.md
check_file CHANGELOG.md
check_file SECURITY.md
check_file CONTRIBUTING.md
check_file LICENSE-APACHE
check_file LICENSE-MIT
check_file deny.toml
check_file compat/README.md
check_file compat/releases.lock.json
check_file compat/releases.lock.sha256
check_file compat/image-signatures.lock.json
check_file compat/image-signatures.lock.sha256
check_file compat/api-snapshots.lock.json
check_file compat/api-snapshots.lock.sha256
check_file compat/api-contracts/2.5.5-tagged-contract.json
check_file compat/core-flow-results.json
check_file compat/core-flow-results.sha256
check_file rust-toolchain.toml
check_file docs/RELEASE_PLAN.md
check_file docs/OPENBAO_API_COVERAGE.md
check_file docs/OPENBAO_2_5_ENDPOINT_MATRIX.md
check_file docs/openbao-2.5-contract-matrix.json
check_file docs/openbao-2.5-endpoint-matrix.csv
check_file docs/API_STABILITY_AUDIT.md
check_file docs/MIGRATION_GUIDE.md
check_file kani/README.md
check_file release-notes/RELEASE_NOTES_0.1.0.md
check_file release-notes/RELEASE_NOTES_0.2.0.md
check_file release-notes/RELEASE_NOTES_0.3.0.md
check_file release-notes/RELEASE_NOTES_0.4.0.md
check_file release-notes/RELEASE_NOTES_0.5.0.md
check_file release-notes/RELEASE_NOTES_0.6.0.md
check_file release-notes/RELEASE_NOTES_0.7.0.md
check_file release-notes/RELEASE_NOTES_0.8.0.md
check_file release-notes/RELEASE_NOTES_0.9.0.md
check_file release-notes/RELEASE_NOTES_0.10.0.md
check_file release-notes/RELEASE_NOTES_0.11.0.md
check_file release-notes/RELEASE_NOTES_0.12.0.md
check_file release-notes/RELEASE_NOTES_0.13.0.md
check_file release-notes/RELEASE_NOTES_0.14.0.md
check_file release-notes/RELEASE_NOTES_0.15.0.md
check_file release-notes/RELEASE_NOTES_1.0.0.md
check_file release-notes/RELEASE_NOTES_1.0.1.md
check_file release-notes/RELEASE_NOTES_1.0.2.md
check_file release-notes/RELEASE_NOTES_1.1.0.md
check_file release-notes/RELEASE_NOTES_1.1.1.md
check_file release-notes/RELEASE_NOTES_1.1.2.md
check_file scripts/release_0_6_gate.sh
check_file scripts/release_0_7_gate.sh
check_file scripts/release_0_8_gate.sh
check_file scripts/release_0_9_gate.sh
check_file scripts/release_0_10_gate.sh
check_file scripts/release_0_11_gate.sh
check_file scripts/release_0_12_gate.sh
check_file scripts/release_0_13_gate.sh
check_file scripts/release_0_14_gate.sh
check_file scripts/release_0_15_gate.sh
check_file scripts/release_1_0_gate.sh
check_file scripts/check_kani.sh
check_file scripts/validate_openbao_release_lock.py
check_file scripts/openbao_api_snapshots.py
check_file scripts/generate_openbao_contract_matrix.py
check_file scripts/openbao_test_harness.py
check_file scripts/openbao_core_matrix.py
check_file scripts/openbao_ci_matrix.py
check_file .github/workflows/ci.yml
check_file .github/workflows/openbao-compatibility.yml

check_grep 'name = "openbao"' Cargo.toml
check_grep 'version = "2.0.0"' Cargo.toml
check_grep 'edition = "2024"' Cargo.toml
check_grep 'rust-version = "1.90"' Cargo.toml
check_grep '"scripts/\*.py"' Cargo.toml
check_grep '"scripts/\*.sh"' Cargo.toml
check_grep 'channel = "1.97.0"' rust-toolchain.toml
check_grep 'rustup toolchain install 1.90.0' scripts/ci_install_rust.sh
check_grep 'cargo +1.90.0 check --locked --all-targets --all-features' scripts/checks.sh
check_grep 'generate_openbao_contract_matrix.py --verify' scripts/checks.sh
check_grep 'generate_openbao_contract_matrix.py --self-test' scripts/checks.sh
check_grep 'openbao_test_harness.py --self-test' scripts/checks.sh
check_grep 'openbao_core_matrix.py --verify' scripts/checks.sh
check_grep 'openbao_core_matrix.py --self-test' scripts/checks.sh
check_grep 'openbao_ci_matrix.py self-test' scripts/checks.sh
check_grep 'pull_request:' .github/workflows/openbao-compatibility.yml
check_grep 'schedule:' .github/workflows/openbao-compatibility.yml
check_grep 'workflow_dispatch:' .github/workflows/openbao-compatibility.yml
check_grep 'persist-credentials: false' .github/workflows/openbao-compatibility.yml
check_grep 'openbao_ci_matrix.py aggregate' .github/workflows/openbao-compatibility.yml
check_grep 'Unique documented rows: `644`' docs/OPENBAO_2_5_ENDPOINT_MATRIX.md
check_grep 'oidc-get-callback-acknowledged = \["jwt-auth"\]' Cargo.toml
check_grep 'license = "MIT OR Apache-2.0"' Cargo.toml
check_grep 'unsafe_code = "forbid"' Cargo.toml
check_grep '0.1.0 - Secure Core And KV v2' docs/RELEASE_PLAN.md
check_grep '0.2.0 - Token, KV Completeness, And Mount Management' docs/RELEASE_PLAN.md
check_grep '0.3.0 - Transit And Audit' docs/RELEASE_PLAN.md
check_grep '0.4.0 - PKI, Kubernetes Auth, TLS Cert Auth' docs/RELEASE_PLAN.md
check_grep '0.5.0 - Database, JWT/OIDC, Userpass' docs/RELEASE_PLAN.md
check_grep '0.6.0 - SSH, TOTP, Production Init/Unseal Safety' docs/RELEASE_PLAN.md
check_grep '0.7.0 - Remaining Secret Engines And Identity' docs/RELEASE_PLAN.md
check_grep '0.8.0 - Remaining Auth And System Backend' docs/RELEASE_PLAN.md
check_grep '0.9.0 - API Stabilization Candidate' docs/RELEASE_PLAN.md
check_grep '0.10.0 - Identity And Auth Completion' docs/RELEASE_PLAN.md
check_grep '0.11.0 - Transit Advanced Key Management' docs/RELEASE_PLAN.md
check_grep '0.12.0 - PKI Tier 1 Multi-Issuer And Authority Lifecycle' docs/RELEASE_PLAN.md
check_grep '0.13.0 - PKI Specialized Flows' docs/RELEASE_PLAN.md
check_grep '0.14.0 - System Backend Completion' docs/RELEASE_PLAN.md
check_grep '0.15.0 - Endpoint Closure And Stable Candidate' docs/RELEASE_PLAN.md
check_grep '1.0.0 - First Stable Release' docs/RELEASE_PLAN.md
check_grep '1.0.1 - Patch Hardening' docs/RELEASE_PLAN.md
check_grep '1.0.2 - Dependency And Documentation Maintenance' docs/RELEASE_PLAN.md
check_grep '1.1.0 - Sanitization Secret Buffer Migration' docs/RELEASE_PLAN.md
check_grep '1.1.1 - Security Dependency Refresh' docs/RELEASE_PLAN.md
check_grep '1.1.2 - Rust 1.96.1 Toolchain And Dependency Refresh' docs/RELEASE_PLAN.md
check_grep '2.0.0 - Multi-Version OpenBao Compatibility' docs/RELEASE_PLAN.md
check_grep 'Release date: 2026-06-04' release-notes/RELEASE_NOTES_0.12.0.md
check_grep 'Release date: 2026-06-04' release-notes/RELEASE_NOTES_0.13.0.md
check_grep 'Release date: 2026-06-04' release-notes/RELEASE_NOTES_1.0.0.md
check_grep 'Release date: 2026-06-09' release-notes/RELEASE_NOTES_1.0.1.md
check_grep 'Release date: 2026-06-10' release-notes/RELEASE_NOTES_1.0.2.md
check_grep 'Release date: 2026-06-24' release-notes/RELEASE_NOTES_1.1.0.md
check_grep 'Release date: 2026-06-24' release-notes/RELEASE_NOTES_1.1.1.md
check_grep 'Release date: 2026-07-04' release-notes/RELEASE_NOTES_1.1.2.md
check_grep 'Audit status:' docs/API_STABILITY_AUDIT.md
check_grep 'From `vaultrs`' docs/MIGRATION_GUIDE.md

if git grep -l "base64-ng contributors" -- ':!scripts/validate-release-metadata.sh' >/dev/null 2>&1; then
  echo "stale copied license metadata found" >&2
  exit 1
fi

if sed -n '/^default = \[/,/^\]/p' Cargo.toml | grep -q 'sensitive-http-test-only'; then
  echo "test-only sensitive HTTP feature must not be in default features" >&2
  exit 1
fi

if sed -n '/^default = \[/,/^\]/p' Cargo.toml | grep -q 'radius-auth'; then
  echo "legacy RADIUS auth feature must not be in default features" >&2
  exit 1
fi

if sed -n '/^default = \[/,/^\]/p' Cargo.toml | grep -q 'oidc-get-callback-acknowledged'; then
  echo "OIDC GET callback acknowledgment must not be in default features" >&2
  exit 1
fi

if grep -q '"scripts/\*\*"' Cargo.toml; then
  echo "recursive scripts package include can admit generated bytecode" >&2
  exit 1
fi

private_key_pattern='-----BEGIN ((RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----'
if git grep -n -E -- "$private_key_pattern" -- ':!scripts/validate-release-metadata.sh' >/dev/null 2>&1; then
  echo "private key material found in tracked files" >&2
  git grep -n -E -- "$private_key_pattern" -- ':!scripts/validate-release-metadata.sh' >&2
  exit 1
fi

echo "release metadata ok"
