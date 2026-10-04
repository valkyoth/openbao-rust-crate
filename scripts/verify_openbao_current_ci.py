#!/usr/bin/python3 -EsSB
"""Verify immutable local validation of the supplemental 2.2.3 CI runner."""

import openbao_current_ci as fixture

ROOT = fixture.ROOT / "compat/ci/2.2.3"
BINARY_SHA256 = "d6d2b6f7d00e3f31db94545ecb23768bfff8818bcc9cf67835437e91cbc82c9a"
PINS = {
    "2.6.4": "444298ae06bd5efaa295f27f1c69f8758c3068b425b33e33a51315260070c9a9",
    "2.7.0": "de40e0163c9fa6375d4fb8fbd1e642d74a86f0aa74d4d7dffde8ce72f2254a06",
    "2.7.1": "5ca2da380615b81af0e7802db5862e0557aefa28fa088ad08801be93f9da22f8",
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
