#!/usr/bin/env sh
set -eu

grep -q '^version = "2.1.7"$' Cargo.toml
grep -q '^secrecy = { package = "sanitization-secrecy", version = "2.1.0", default-features = false, features = \["serde"\] }$' Cargo.toml
grep -q '^sanitization = { version = "2.1.0", default-features = false, features = \["alloc"\] }$' Cargo.toml
grep -q 'openbao = { path = "..", version = "=2.1.7"' fuzz/Cargo.toml
grep -q 'openbao = { path = "../../..", version = "=2.1.7"' \
  tests/fixtures/reqwest-native-unification/Cargo.toml
grep -q 'Version: 2.1.7' release-notes/RELEASE_NOTES_2.1.7.md
grep -q '2.1.7 - 2026-09-06' CHANGELOG.md
grep -q 'pub use secrecy as sanitization_secrecy;' src/lib.rs
grep -q 'packaged_secret_string_uses_sanitization_secrecy' tests/package_smoke.rs
grep -q 'taiki-e/install-action v2.87.7' .github/workflows/ci.yml
grep -q 'uses: taiki-e/install-action@84f5ac3124727fb3d284d4d22ee9ab3654fd09a6' \
  .github/workflows/ci.yml

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
done

cargo test --locked --test package_smoke packaged_secret_string_uses_sanitization_secrecy
scripts/checks.sh
python3 -B scripts/openbao_core_matrix.py --verify
python3 -B scripts/generate_openbao_version_contracts.py --verify
scripts/generate-sbom.sh

echo "release 2.1.7 gate complete"
echo "Require green GitHub CI, CodeQL, the all-release compatibility workflow, exact OpenBao 2.6.2 TLS integration, and exact-commit pentests before tagging."
