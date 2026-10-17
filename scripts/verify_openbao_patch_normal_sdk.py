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
    "2.6.4": ("17c3d02590ef787372ea9d0b6ae34fb3ba994b78e7dede713b76727d1f38c95f",
              "df72dcc6a7688856805a19fa04144cbff9560feefcf7c893987dba624a2b6aea"),
    "2.7.1": ("6fb0316d5c1e854f9f07bc192f9b9b2c1c9dfd18b2bc9cb34c5425dfc5383369",
              "9ce991f37ec875234d72f40388b0acb7a79670e91e7749d7351e405c0ca0ae52"),
}


def output(version):
    return legacy.patch.ROOT / "compat/onboarding" / version / "sdk-normal-tls-v7.json"


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
