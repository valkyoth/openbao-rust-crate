#!/usr/bin/env sh
set -eu

test -f Cargo.toml
test -f README.md
test -f CHANGELOG.md
test -f SECURITY.md
test -f CONTRIBUTING.md
test -f LICENSE-APACHE
test -f LICENSE-MIT
test -f deny.toml
test -f rust-toolchain.toml
test -f docs/RELEASE_PLAN.md
test -f docs/OPENBAO_API_COVERAGE.md
test -f release-notes/RELEASE_NOTES_0.1.0.md
test -f release-notes/RELEASE_NOTES_0.2.0.md
test -f release-notes/RELEASE_NOTES_0.3.0.md
test -f release-notes/RELEASE_NOTES_0.4.0.md
test -f .github/workflows/ci.yml

grep -q 'name = "openbao"' Cargo.toml
grep -q 'version = "0.4.0"' Cargo.toml
grep -q 'edition = "2024"' Cargo.toml
grep -q 'rust-version = "1.95"' Cargo.toml
grep -q 'license = "MIT OR Apache-2.0"' Cargo.toml
grep -q 'unsafe_code = "forbid"' Cargo.toml
grep -q '0.1.0 - Secure Core And KV v2' docs/RELEASE_PLAN.md
grep -q '0.2.0 - Token, KV Completeness, And Mount Management' docs/RELEASE_PLAN.md
grep -q '0.3.0 - Transit And Audit' docs/RELEASE_PLAN.md
grep -q '0.4.0 - PKI, Kubernetes Auth, TLS Cert Auth' docs/RELEASE_PLAN.md
grep -q '1.0.0 - First Stable Release' docs/RELEASE_PLAN.md
grep -q 'Pentest report:' release-notes/RELEASE_NOTES_0.4.0.md

if git grep -l "base64-ng contributors" -- ':!scripts/validate-release-metadata.sh' >/dev/null 2>&1; then
  echo "stale copied license metadata found" >&2
  exit 1
fi

echo "release metadata ok"
