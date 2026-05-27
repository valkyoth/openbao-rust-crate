#!/usr/bin/env sh
set -eu

scripts/release_0_1_gate.sh

grep -q '1.0.0 - First Stable Release' docs/RELEASE_PLAN.md
echo "stable gate scaffold complete"
echo "For 1.0.0, replace this scaffold with the full 1.0 release gate from docs/RELEASE_PLAN.md."
