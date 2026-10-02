#!/usr/bin/python3 -EsSB
"""Verify source-current public SDK patch evidence without promoting routing."""

import argparse
from pathlib import Path

import openbao_2_7_1_sdk_advanced as fixture
import verify_openbao_2_7_1 as initial

OUTPUT = initial.OUTPUT / "sdk-advanced-candidate-tls-v2.json"
EXPECTED_SHA256 = "ab0e3a80466da2e5fafaf04084a3c598812f7ab4670d3fc366c6175f3687215b"
TEST_BINARY_SHA256 = "fb8de36a1d0bf386757d58e395d9b0b1501c6b427e7b76a76cc1c1a90695cdce"
HISTORICAL_INPUTS_SHA256 = "baf799f8663e10fafaee1e29129988e86ae0381b9f7270386eddef06bcfe917e"
HISTORICAL_GENERATED_SHA256 = "7abf8c20b0e74fb37eab2189bc52588c33359443c869625d6eb6aca18bb10b92"


def validate(data, *, historical=False):
    report = initial.checked(data, EXPECTED_SHA256, 128 * 1024)
    if historical:
        inputs = report.get("inputs")
        fixture.patch.require(fixture.base.sha256(fixture.base.canonical_json(inputs)) == HISTORICAL_INPUTS_SHA256)
        generated = HISTORICAL_GENERATED_SHA256
    else:
        inputs = fixture.input_hashes()
        fixture.patch.require(report.get("inputs") == inputs)
        generated = fixture.base.sha256(
            fixture.candidate.registry.rust_output(fixture.candidate.verify(), verification_candidate=True))
    expected = {
        **fixture.execution.EXECUTION_ASSURANCE,
        "schema": "openbao-patch-sdk-advanced-tls/v1", "version": fixture.patch.VERSION,
        "inputs": inputs, "test_binary_sha256": TEST_BINARY_SHA256,
        "tests": fixture.TESTS, "features": fixture.FEATURES, "checks": fixture.CHECKS,
        "candidate_registry_sha256": fixture.candidate.EXPECTED_SHA256,
        "candidate_generated_rust_sha256": generated,
        "source_scope": "repository-inputs-with-explicit-generated-candidate-override",
        "scope": "public-sdk-strict-disposable-candidate-build",
        "image_linux_amd64_digest": fixture.patch.AMD64, "image_index_digest": fixture.patch.INDEX,
        "routable": False, "outcome": "passed", "backup_decryption_verified": False,
        "synthetic_indices": "test-only-never-observable-cancellation-and-timeout",
    }
    fixture.patch.require(fixture.base.canonical_json(report) == fixture.base.canonical_json(expected))
    return report


def verify(*, historical=False):
    return validate(fixture.base.read_regular_file(OUTPUT, 128 * 1024), historical=historical)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retain", type=Path)
    parser.add_argument("--historical", action="store_true", help="archive integrity only, never current release assurance")
    args = parser.parse_args()
    try:
        if args.retain:
            data = fixture.base.read_regular_file(args.retain, 128 * 1024)
            validate(data, historical=args.historical)
            fixture.base.write_immutable(OUTPUT, data)
        verify(historical=args.historical)
    except (fixture.harness.HarnessError, fixture.base.SnapshotError, fixture.candidate.registry.RegistryError,
            OSError, ValueError, KeyError, TypeError):
        print("2.7.1 advanced SDK evidence failed verification; no compatibility promotion")
        return 1
    print("Historical 2.7.1 advanced candidate verified; NOT current release evidence" if args.historical
          else "2.7.1 source-current advanced candidate verified; NOT final normal-build evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
