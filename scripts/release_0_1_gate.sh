#!/usr/bin/env sh
set -eu

scripts/checks.sh
scripts/generate-sbom.sh

echo "release 0.1 gate complete"
echo "Do not tag unless pentest report status is reviewed and recorded."
