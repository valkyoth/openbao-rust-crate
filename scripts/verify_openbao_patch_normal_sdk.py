#!/usr/bin/python3 -EsSB
"""Require exact current normal-build SDK evidence, including the packaged README."""

import argparse
from pathlib import Path

import openbao_2_6_5_sdk as legacy
import openbao_2_7_2_sdk_advanced as modern
import verify_openbao_2_6_5_sdk as legacy_evidence

base, harness = legacy.base, legacy.harness
FIXTURES = {"2.6.5": legacy, "2.7.2": modern}
# Report and sealed executable identities, independently retained for each patch.
PINS = {
    "2.6.5": ("6e6a539596c111b9ff4d5129f100f419eba4ebaf5d7e05100cd87c05cc03455e",
              "982c24f70614c97f2609b0eb492a17a09960225ca2a78d796b68f7e8c1200880"),
    "2.7.2": ("1b8e424047bcec331fd891defbf0539d056b43e5f8e97c645e22902b350565f2",
              "ff2a02283d9caf85643a9edc22030ef2df67eaa590bfa766ebcfe2dba98d8726"),
}


def output(version):
    name = "sdk-normal-tls-v4.json" if version == "2.6.5" else "sdk-advanced-normal-tls-v4.json"
    return legacy.patch.ROOT / "compat/onboarding" / version / name


def expected(version, binary_digest):
    fixture = FIXTURES[version]
    common = {**fixture.execution.EXECUTION_ASSURANCE, **fixture.normal_sdk.verify(),
              "version": version, "inputs": fixture.input_hashes(normal=True),
              "test_binary_sha256": binary_digest, "features": fixture.FEATURES,
              "image_linux_amd64_digest": fixture.patch.AMD64,
              "image_index_digest": fixture.patch.INDEX, "outcome": "passed"}
    if version == "2.6.5":
        return {**common, "schema": "openbao-patch-sdk-tls/v1", "test": fixture.TEST,
                "checks": legacy_evidence.CHECKS}
    return {**common, "schema": "openbao-patch-sdk-advanced-tls/v1", "tests": fixture.TESTS,
            "checks": fixture.CHECKS, "backup_decryption_verified": False,
            "synthetic_indices": "test-only-never-observable-cancellation-and-timeout"}


def validate(version, data):
    legacy.patch.require(version in FIXTURES and version in PINS)
    pin = PINS[version]
    legacy.patch.require(pin is not None)
    report_digest, binary_digest = pin
    legacy.patch.require(base.sha256(data) == report_digest)
    report = base.parse_json(data, 128 * 1024)
    required = expected(version, binary_digest)
    legacy.patch.require(data == base.canonical_json(report)
                         and data == base.canonical_json(required))
    return report


def verify(version):
    return validate(version, base.read_regular_file(output(version), 128 * 1024))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", choices=FIXTURES)
    parser.add_argument("--retain", type=Path)
    args = parser.parse_args()
    if args.retain and not args.version:
        parser.error("--retain requires --version")
    try:
        if args.retain:
            data = base.read_regular_file(args.retain, 128 * 1024)
            validate(args.version, data)
            base.write_immutable(output(args.version), data)
        for version in ([args.version] if args.version else FIXTURES):
            verify(version)
    except (harness.HarnessError, base.SnapshotError, legacy.candidate.registry.RegistryError,
            OSError, ValueError, KeyError, TypeError):
        print("Final normal-build SDK evidence missing or invalid; release gate blocked")
        return 1
    print("Normal-build SDK TLS evidence verified; every input including README matches exactly; release approval remains separate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
