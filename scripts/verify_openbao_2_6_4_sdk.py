#!/usr/bin/python3 -EsSB
"""Retain source-current 2.6.4 public SDK evidence, without profile promotion."""

import argparse
from pathlib import Path

import openbao_2_6_4_sdk as fixture
import verify_openbao_2_6_4 as initial

OUTPUT = initial.OUTPUT / "sdk-candidate-tls-v2.json"
EXPECTED_SHA256 = "1772b5be49dc02e3fe706a24c469cf846cae897da04ee6eb57ec162bc6319f57"
TEST_BINARY_SHA256 = "11416012204333139024a3b777e6e7583c986b994e4b1d91fcca97145ffe11c0"
HISTORICAL_INPUTS_SHA256 = "30fd148fd0c77b1637c65bd9b3a6f410203e3f466b605c36869efc7b8d79f118"
HISTORICAL_GENERATED_SHA256 = "abf01048c62cdafad04c4becf76391fec067e7b7ba3ec0ca4df10a70c826472d"
CHECKS = ["exact-version", "tls13", "tls-rejections", "resource-limits", "network-isolation",
          "strict-sdk-profile", "approle-login", "expired-secret-id-denied-without-tidy",
          "transit-encrypt-decrypt", "transit-version-selection", "associated-data-binding",
          "kv1-roundtrip", "kv2-write-patch-read", "token-lookup", "wrapping-one-use",
          "ldap-auth-mapping", "kerberos-group-mapping", "radius-user-mapping",
          "ldap-dynamic-role-administration", "cleanup"]


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
    expected = {**fixture.execution.EXECUTION_ASSURANCE,
                "schema": "openbao-patch-sdk-tls/v1", "version": fixture.patch.VERSION,
                "inputs": inputs, "test_binary_sha256": TEST_BINARY_SHA256,
                "test": fixture.TEST, "features": fixture.FEATURES,
                "candidate_registry_sha256": fixture.candidate.EXPECTED_SHA256,
                "candidate_generated_rust_sha256": generated,
                "source_scope": "repository-inputs-with-explicit-generated-candidate-override",
                "image_linux_amd64_digest": fixture.patch.AMD64,
                "image_index_digest": fixture.patch.INDEX,
                "scope": "public-sdk-strict-disposable-candidate-build", "outcome": "passed",
                "routable": False, "checks": CHECKS}
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
        print("2.6.4 SDK evidence failed verification; no compatibility promotion")
        return 1
    print("Historical 2.6.4 candidate verified; NOT current release evidence" if args.historical
          else "2.6.4 source-current candidate verified; NOT final normal-build evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
