#!/usr/bin/python3 -EsSB
"""Retain and verify the initial 2.7.1 capture; this is not profile promotion."""

import argparse
from pathlib import Path

import openbao_2_7_1 as patch

base = patch.base
OUTPUT = patch.ROOT / "compat/onboarding/2.7.1"
ARTIFACTS = {
    "initial-openapi.json": ("openapi.json", "5091c881b5a2e925331227cb4ee6b6c679ba2b5a7c13704e362c03cb41513af5", base.MAX_OPENAPI_BYTES),
    "initial-patch-tls.json": ("report.json", "11568421a6127d725dceed01d7b79f4060f9c1845ba8d173f96dc33195c922dc", 64 * 1024),
}


def checked(data, digest, limit):
    patch.require(base.sha256(data) == digest)
    value = base.parse_json(data, limit)
    patch.require(base.canonical_json(value) == data)
    return value


def validate(artifacts):
    patch.verify_source()
    patch.require(set(artifacts) == set(ARTIFACTS))
    values = {name: checked(artifacts[name], digest, limit)
              for name, (_, digest, limit) in ARTIFACTS.items()}
    api = values["initial-openapi.json"]
    report = values["initial-patch-tls.json"]
    expected_mounts = [{"kind": "secret", "path": path, "type": kind} for path, kind, _ in patch.SECRET_MOUNTS]
    expected_mounts += [{"kind": "auth", "path": path, "type": kind} for path, kind in patch.AUTH_MOUNTS]
    patch.require(api["mounts"] == expected_mounts)
    patch.require(api == patch.normalize_api(api["document"], expected_mounts))
    patch.require(report == {
        "schema": "openbao-patch-capture/v1", "version": patch.VERSION,
        "image_linux_amd64_digest": patch.AMD64, "image_index_digest": patch.INDEX,
        "inputs": patch.input_hashes(), "openapi_sha256": base.sha256(artifacts["initial-openapi.json"]),
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
        print("Initial 2.7.1 capture verification failed; no promotion")
        return 1
    print("Initial 2.7.1 TLS/API capture verified; raw-storage scope and SDK integration remain pending")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
