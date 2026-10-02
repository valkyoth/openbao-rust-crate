#!/usr/bin/python3 -EsSB
"""Retain exact 2.6.4 capture and require unchanged 2.6.3 runtime contracts."""

import argparse
import copy
from pathlib import Path

import openbao_2_6_4 as patch

base = patch.base
OUTPUT = patch.OUTPUT
PREDECESSOR = patch.ROOT / "compat/api-snapshots/2.6.3/openapi.json"
PREDECESSOR_SHA256 = "2e03c8864113c0f72c61735a72517c2a9b21e0e8b5b9a42a1dd0d0fc8262f67a"
ARTIFACTS = {
    "openapi.json": ("openapi.json", "227895760956ca5bf71bbc508c7a66351ab2da6487b43b726600b8e801aece2d", base.MAX_OPENAPI_BYTES),
    "patch-tls.json": ("report.json", "bbcf6bd4709d3f6c3947a1b9b3c40f5cb56203659251a3a182156a4bd2e8213a", 64 * 1024),
}


def checked(data, digest, limit):
    patch.pinned(data, digest)
    value = base.parse_json(data, limit)
    patch.require(base.canonical_json(value) == data)
    return value


def compare_contracts(api, before):
    patch.require(before["version"] == "2.6.3" and api["version"] == patch.VERSION)
    for field in ("mounts", "path_count", "operation_count", "schema_count"):
        patch.require(api[field] == before[field])
    document = copy.deepcopy(before["document"])
    patch.require(document["info"]["version"] == "2.6.3")
    document["info"]["version"] = patch.VERSION
    patch.require(api["document"] == document)


def validate(artifacts):
    patch.verify_source()
    patch.verify_image()
    patch.require(set(artifacts) == set(ARTIFACTS))
    values = {name: checked(artifacts[name], digest, limit)
              for name, (_, digest, limit) in ARTIFACTS.items()}
    api, report = values["openapi.json"], values["patch-tls.json"]
    patch.require(api == patch.normalize_api(api["document"], api["mounts"]))
    before = checked(base.read_regular_file(PREDECESSOR, base.MAX_OPENAPI_BYTES),
                     PREDECESSOR_SHA256, base.MAX_OPENAPI_BYTES)
    compare_contracts(api, before)
    patch.require(report == {
        "schema": "openbao-patch-capture/v1", "version": patch.VERSION,
        "image_linux_amd64_digest": patch.AMD64, "image_index_digest": patch.INDEX,
        "inputs": patch.input_hashes(), "openapi_sha256": base.sha256(artifacts["openapi.json"]),
        "scope": "server-fixture-only-not-sdk-integration", "routable": False, "checks": patch.CHECKS,
    })
    return values


def verify():
    return validate({name: base.read_regular_file(OUTPUT / name, limit)
                     for name, (_, _, limit) in ARTIFACTS.items()})


def retain(directory):
    artifacts = {name: base.read_regular_file(directory / source, limit)
                 for name, (source, _, limit) in ARTIFACTS.items()}
    validate(artifacts)
    for name, data in artifacts.items():
        base.write_immutable(OUTPUT / name, data)
    verify()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retain", type=Path)
    args = parser.parse_args()
    try:
        if args.retain:
            retain(args.retain)
        else:
            verify()
    except (patch.harness.HarnessError, base.SnapshotError, OSError, ValueError, KeyError, TypeError):
        print("2.6.4 capture verification failed; no promotion")
        return 1
    print("2.6.4 TLS/API capture verified; exact 2.6.3 contracts preserved; SDK verification remains separate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
