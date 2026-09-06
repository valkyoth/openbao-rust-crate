#!/usr/bin/env sh
set -eu

scripts/release_1_0_gate.sh

grep -q '1.0.0 - First Stable Release' docs/RELEASE_PLAN.md
grep -q '1.1.0 - Sanitization Secret Buffer Migration' docs/RELEASE_PLAN.md
grep -q '1.1.1 - Security Dependency Refresh' docs/RELEASE_PLAN.md
grep -q '1.1.2 - Rust 1.96.1 Toolchain And Dependency Refresh' docs/RELEASE_PLAN.md
grep -q 'Version: 1.1.2' release-notes/RELEASE_NOTES_1.1.2.md
grep -q 'version = "2.1.6"' Cargo.toml
grep -q '2.0.0 - Multi-Version OpenBao Compatibility' docs/RELEASE_PLAN.md
grep -q '2.0.1 - Compatibility Documentation Correction' docs/RELEASE_PLAN.md
grep -q 'Version: 2.0.0' release-notes/RELEASE_NOTES_2.0.0.md
grep -q 'Version: 2.0.1' release-notes/RELEASE_NOTES_2.0.1.md
grep -q '2.0.2 - Focused crates.io Source Package' docs/RELEASE_PLAN.md
grep -q 'Version: 2.0.2' release-notes/RELEASE_NOTES_2.0.2.md
grep -q '2.1.0 - OpenBao 2.6.0 Compatibility' docs/RELEASE_PLAN.md
grep -q 'Version: 2.1.0' release-notes/RELEASE_NOTES_2.1.0.md
grep -q '2.1.1 - Security Dependency And Memory-Lock Correction' docs/RELEASE_PLAN.md
grep -q 'Version: 2.1.1' release-notes/RELEASE_NOTES_2.1.1.md
grep -q '2.1.2 - OpenBao 2.6.1 Compatibility' docs/RELEASE_PLAN.md
grep -q 'Version: 2.1.2' release-notes/RELEASE_NOTES_2.1.2.md
grep -q '2.1.3 - Dependency And CI Tooling Maintenance' docs/RELEASE_PLAN.md
grep -q 'Version: 2.1.3' release-notes/RELEASE_NOTES_2.1.3.md
grep -q '2.1.4 - OpenBao 2.6.2 Compatibility' docs/RELEASE_PLAN.md
grep -q 'Version: 2.1.4' release-notes/RELEASE_NOTES_2.1.4.md
grep -q '2.1.5 - Dependency, Toolchain, And Static-Analysis Maintenance' docs/RELEASE_PLAN.md
grep -q 'Version: 2.1.5' release-notes/RELEASE_NOTES_2.1.5.md
grep -q '2.1.6 - Secret-Bearing HTTP Buffer Hardening' docs/RELEASE_PLAN.md
grep -q 'Version: 2.1.6' release-notes/RELEASE_NOTES_2.1.6.md
echo "stable release gate complete"
