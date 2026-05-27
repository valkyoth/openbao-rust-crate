#!/usr/bin/env sh
set -eu

mkdir -p target/sbom
cargo sbom --output-format cyclone_dx_json_1_5 > target/sbom/openbao.cdx.json
test -s target/sbom/openbao.cdx.json
echo "SBOM written to target/sbom/openbao.cdx.json"
