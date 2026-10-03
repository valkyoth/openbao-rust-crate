#!/usr/bin/python3 -EsSB
"""Verify immutable local validation of the supplemental 2.2.2 CI runner."""

import openbao_current_ci as fixture

ROOT = fixture.ROOT / "compat/ci/2.2.2"
BINARY_SHA256 = "562cb81576c058156e1f0cf5f22a9f9eaa452bf4219a75d0ab0f13e96a72f5db"
PINS = {
    "2.6.4": "33cffbf753b6bf90e20876b86a1748a5cabc9037a5f37bea5268f707c05d0bb5",
    "2.7.0": "98280734251959ecb5fc9cc038c0ee7ad8209b8c8313faf63f2f8fcbc78c7632",
    "2.7.1": "d2d5cf7720049065d37abc1e2694982d6e62ebe15241d177e8ffe3178f88c209",
}


def validate(version, data):
    fixture.require(version in PINS and fixture.base.sha256(data) == PINS[version])
    report = fixture.base.parse_json(data, 128 * 1024)
    expected = {
        "schema": "openbao-current-ci/v1", "version": version, "outcome": "passed",
        "image_linux_amd64_digest": fixture.RELEASES[version].AMD64,
        "test_binary_sha256": BINARY_SHA256, "inputs": fixture.input_hashes(),
        "build_provenance": "local-trusted-builder-not-attested", "tls": "TLSv1.3",
        "executable_storage": "sealed-memfd", "cleanup": "passed",
        "scope": "eight-public-sdk-core-operations-not-full-endpoint-or-advanced-coverage",
        "attestation": {"schema": "openbao-core-flow-attestation/v1", "version": version,
                        "executed": list(fixture.OPERATIONS),
                        "skipped": list(fixture.harness.OPENBAO_2_6_OPERATION_IDS)},
    }
    fixture.require(data == fixture.base.canonical_json(report)
                    and data == fixture.base.canonical_json(expected))
    return report


def verify(version):
    return validate(version, fixture.base.read_regular_file(ROOT / f"{version}-v2.json", 128 * 1024))


def main():
    try:
        fixture.require(set(PINS) == set(fixture.VERSIONS))
        for version in fixture.VERSIONS:
            verify(version)
    except (fixture.harness.HarnessError, fixture.base.SnapshotError, OSError, ValueError, KeyError, TypeError):
        print("Retained current-profile CI evidence missing or invalid")
        return 1
    print("Three local CI-runner TLS/SDK reports verified; GitHub execution approval remains separate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
