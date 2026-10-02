#!/usr/bin/python3 -EsSB
"""Require normal-build SDK evidence, with one pinned post-capture README correction."""

import argparse
from pathlib import Path

import openbao_2_6_4_sdk as legacy
import openbao_2_7_1_sdk_advanced as modern
import verify_openbao_2_6_4_sdk as legacy_candidate

base, harness = legacy.base, legacy.harness
FIXTURES = {"2.6.4": legacy, "2.7.1": modern}
# Report and sealed executable identities, independently retained for each patch.
PINS = {
    "2.6.4": ("bd5d855ff99869fcaecfced5872efd0ee3830b0aa0be0f9259ddded6603e3fb7",
              "5738f7805803d14e59c1e29ad2cc69df90de84ece20ad86c47b865340a62388f"),
    "2.7.1": ("a1a3ff1a5730485a3b30deb4187961e6567de75dfc22278dd6661a8cf398a2f7",
              "d5b1bb8c584f4e361327546b8b4d684c85ea45a3dca16dd0fc01cf214398c8df"),
}
CAPTURED_README_SHA256 = "89b30c6b2421d8a5c6689b16837df1739f8006a3c2be3c99c7f9a1c182d84444"
REVIEWED_README_SHA256 = "f4decde17a056f779de87dd222a0c904c84a8ebcf2ff3f701257b77d0141aa76"
CAPTURED_README = legacy.patch.ROOT / "compat/onboarding/2.7.1/sdk-capture-readme-v3.md"


def output(version):
    return legacy.patch.ROOT / "compat/onboarding" / version / "sdk-normal-tls-v3.json"


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
    captured_inputs = report.get("inputs")
    legacy.patch.require(isinstance(captured_inputs, dict))
    captured_readme = captured_inputs.get("README.md")
    if required["inputs"].get("README.md") != captured_readme:
        # Only the reviewed status/link correction is allowed. No executable
        # input changes, generic Markdown exclusion or rewritten report hashes.
        legacy.patch.require(captured_readme == CAPTURED_README_SHA256
                             and required["inputs"].get("README.md") == REVIEWED_README_SHA256
                             and base.sha256(base.read_regular_file(CAPTURED_README, 128 * 1024)) == CAPTURED_README_SHA256)
        required["inputs"]["README.md"] = CAPTURED_README_SHA256
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
    print("Normal-build SDK TLS evidence verified; executable inputs current, exact README-only correction separately reviewed; release approval remains separate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
