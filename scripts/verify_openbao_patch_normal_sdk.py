#!/usr/bin/python3 -EsSB
"""Require exact current normal-build SDK evidence, including the packaged README."""

import argparse
from pathlib import Path

import openbao_2_6_4_sdk as legacy
import openbao_2_7_1_sdk_advanced as modern
import verify_openbao_2_6_4_sdk as legacy_candidate

base, harness = legacy.base, legacy.harness
FIXTURES = {"2.6.4": legacy, "2.7.1": modern}
# Report and sealed executable identities, independently retained for each patch.
PINS = {
    "2.6.4": ("68eb8e6c2b46b47ab125c15915db6fce0d37eb3bd51b011beb074c8068c27ab0",
              "5a06107ca97841051c763685670f9dd727ffceca937441c50ac366d4fbbac9dc"),
    "2.7.1": ("a9a38df7b789a373143fa3af107c2443fe2c774595c98a0ed398e7d3520767c5",
              "4666c528dae8f070ba2ab847b4f8d7c72b2ce4c14c8e2e3a476ad3f9950c48bd"),
}


def output(version):
    return legacy.patch.ROOT / "compat/onboarding" / version / "sdk-normal-tls-v9.json"


def expected(version, binary_digest):
    fixture = FIXTURES[version]
    common = {**fixture.execution.EXECUTION_ASSURANCE, **fixture.normal_sdk.verify(),
              "version": version, "inputs": fixture.input_hashes(normal=True),
              "test_binary_sha256": binary_digest, "features": fixture.FEATURES,
              "image_linux_amd64_digest": fixture.patch.AMD64,
              "image_index_digest": fixture.patch.INDEX, "outcome": "passed"}
    if version == "2.6.4":
        return {**common, "schema": "openbao-patch-sdk-tls/v1", "test": fixture.TEST,
                "checks": legacy_candidate.CHECKS}
    return {**common, "schema": "openbao-patch-sdk-advanced-tls/v1", "tests": fixture.TESTS,
            "checks": fixture.CHECKS, "backup_decryption_verified": False,
            "synthetic_indices": "test-only-never-observable-cancellation-and-timeout"}


def validate(version, data):
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
