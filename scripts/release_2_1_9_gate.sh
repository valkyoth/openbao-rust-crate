#!/usr/bin/env sh
set -eu

grep -q '^version = "2.1.9"$' Cargo.toml
grep -q 'version = "=2.1.9"' fuzz/Cargo.toml
grep -q 'version = "=2.1.9"' tests/fixtures/reqwest-native-unification/Cargo.toml
grep -q 'Version: 2.1.9' release-notes/RELEASE_NOTES_2.1.9.md
grep -q '"version": "2.6.3"' compat/releases.lock.json
grep -q '"version": "2.6.3"' compat/core-flow-results.json
grep -q 'raw_uncompressed_write_rejects_every_older_profile_before_transport' tests/http_client.rs
grep -q 'canonical-userpass-acl' tests/openbao_integration.rs
scripts/checks.sh
python3 -B scripts/openbao_core_matrix.py --verify
python3 -B scripts/generate_openbao_version_contracts.py --verify
scripts/generate-sbom.sh

echo "release 2.1.9 gate complete"
echo "Require exact-commit pentests, green GitHub CI, CodeQL, and all-release compatibility CI before tagging."
