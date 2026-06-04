#!/usr/bin/env sh
set -eu

scripts/checks.sh
if [ "${OPENBAO_SKIP_INTEGRATION:-0}" = "1" ]; then
  echo "checks: OpenBao integration skipped by OPENBAO_SKIP_INTEGRATION=1"
else
  echo "checks: OpenBao integration"
  scripts/openbao_integration.sh
fi
scripts/generate-sbom.sh

echo "release 0.12 gate complete"
echo "Do not tag unless pentest report status is reviewed and recorded."
