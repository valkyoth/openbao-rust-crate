#!/usr/bin/python3 -EsSB
"""Retain the exact patch SDK result; candidate evidence is not promotion."""

import argparse
from pathlib import Path

import openbao_2_7_1_sdk as fixture
import verify_openbao_2_7_1 as initial

OUTPUT = initial.OUTPUT / "sdk-candidate-tls.json"
EXPECTED_SHA256 = "6506b4c1b34caed30434163da54936b63f1ae4851e48993592e86b444d46e585"
TEST_BINARY_SHA256 = "207d5ff9a6819aae7eb4c0de1e191e380465e1e65216375b7866d34cc9497b9f"
HISTORICAL_INPUTS_SHA256 = "37976e3feaee420905b006d18cc6f902c7c96be8e264cecd90fa4f741f153049"
HISTORICAL_GENERATED_SHA256 = "7abf8c20b0e74fb37eab2189bc52588c33359443c869625d6eb6aca18bb10b92"
HISTORICAL_REGISTRY_SHA256 = "d3441baaa64d511a3644388437d4441cefc08323050cc2cae52014378a5473d6"


def validate(data, *, historical=False):
    report = initial.checked(data, EXPECTED_SHA256, 128 * 1024)
    if historical:
        # This mode authenticates the archived bytes, not current SDK sources.
        # CI separately requires the source-current advanced SDK report.
        inputs = report.get("inputs")
        fixture.patch.require(fixture.base.sha256(fixture.base.canonical_json(inputs)) == HISTORICAL_INPUTS_SHA256)
        generated = HISTORICAL_GENERATED_SHA256
    else:
        inputs = fixture.input_hashes()
        fixture.patch.require(report.get("inputs") == inputs)
        generated = fixture.base.sha256(
            fixture.candidate.registry.rust_output(fixture.candidate.verify(), verification_candidate=True))
    expected = {**fixture.execution.EXECUTION_ASSURANCE,
                "schema": "openbao-patch-sdk-tls/v1", "version": fixture.patch.VERSION,
                "inputs": inputs, "test_binary_sha256": TEST_BINARY_SHA256,
                "test": fixture.TEST, "features": fixture.FEATURES,
                "candidate_registry_sha256": HISTORICAL_REGISTRY_SHA256 if historical else fixture.candidate.EXPECTED_SHA256,
                "candidate_generated_rust_sha256": generated,
                "source_scope": "repository-inputs-with-explicit-generated-candidate-override",
                "image_linux_amd64_digest": fixture.patch.AMD64,
                "image_index_digest": fixture.patch.INDEX,
                "scope": "public-sdk-strict-disposable-candidate-build", "outcome": "passed", "routable": False,
                "checks": ["exact-version", "tls13", "tls-rejections", "resource-limits", "network-isolation",
                           "strict-sdk-profile", "approle-login", "expired-secret-id-denied-without-tidy",
                           "transit-encrypt-decrypt", "transit-version-selection", "associated-data-binding", "cleanup"]}
    if not historical:
        expected["checks"] = fixture.CHECKS
    fixture.patch.require(report == expected)
    return report


def verify(*, historical=False):
    return validate(fixture.base.read_regular_file(OUTPUT, 128 * 1024), historical=historical)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retain", type=Path)
    parser.add_argument("--historical", action="store_true", help="verify archived integrity only, not current release evidence")
    args = parser.parse_args()
    try:
        if args.retain:
            data = fixture.base.read_regular_file(args.retain, 128 * 1024)
            validate(data, historical=args.historical)
            fixture.base.write_immutable(OUTPUT, data)
        verify(historical=args.historical)
    except (fixture.harness.HarnessError, fixture.base.SnapshotError, fixture.candidate.registry.RegistryError,
            OSError, ValueError, KeyError, TypeError):
        print("2.7.1 SDK evidence failed verification; no compatibility promotion")
        return 1
    if args.historical:
        print("Historical 2.7.1 SDK artifact verified; NOT current-source evidence or release approval")
    else:
        print("2.7.1 strict candidate SDK evidence verified; backup and multi-node gates remain separate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
