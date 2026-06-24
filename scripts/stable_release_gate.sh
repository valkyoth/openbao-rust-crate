#!/usr/bin/env sh
set -eu

scripts/release_1_0_gate.sh

grep -q '1.0.0 - First Stable Release' docs/RELEASE_PLAN.md
grep -q '1.1.0 - Sanitization Secret Buffer Migration' docs/RELEASE_PLAN.md
grep -q '1.1.1 - Security Dependency Refresh' docs/RELEASE_PLAN.md
grep -q 'Version: 1.1.1' release-notes/RELEASE_NOTES_1.1.1.md
echo "stable release gate complete"
