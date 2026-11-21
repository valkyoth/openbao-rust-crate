#!/usr/bin/python3 -EsSB
"""Require exact current normal-build SDK evidence, including the packaged README."""

import argparse
from pathlib import Path

import openbao_2_6_5_sdk as legacy
import openbao_2_7_1_sdk_advanced as patch_271
import openbao_2_7_2_sdk_advanced as modern
import verify_openbao_2_6_5_sdk as legacy_evidence

base, harness = legacy.base, legacy.harness
FIXTURES = {"2.6.5": legacy, "2.7.1": patch_271, "2.7.2": modern}
# Report and sealed executable identities, independently retained for each patch.
PINS = {
    "2.7.1": ("1d07c71315320a5963ca5d3a1e141f20da82cfe34b669e2c3728c86f774ce489",
              "dd85c167da0b0b0b9d38abae9cf20f77987c4cd8274cc55754bb236d1cee9b09"),
    "2.6.5": ("e9615e55204179ce60e5c1fa3a783cddbf917d7416c02c4030239c3df01d5172",
              "f9c7bc0d58e338700fdd5a82724f627eaa308536be81a11721bf46f846da9f11"),
    "2.7.2": ("769dde0bf31b206b562f3834ad28e34dc6835129f7dd20b3189aa251d729a9d4",
              "ef22e0309cf695099e0080008fb4bac4e97a9f0685ad32647ca2f9d4365c03c7"),
}


def output(version):
    name = {"2.6.5": "sdk-normal-tls-v5.json", "2.7.1": "sdk-advanced-normal-tls-v2.json",
            "2.7.2": "sdk-advanced-normal-tls-v6.json"}[version]
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
