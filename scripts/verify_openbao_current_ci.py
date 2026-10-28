#!/usr/bin/python3 -EsSB
"""Verify immutable local validation of the supplemental 2.2.5 CI runner."""

import openbao_current_ci as fixture

ROOT = fixture.ROOT / "compat/ci/2.2.5/v2"
BINARY_SHA256 = "43af4a573e836ff92c89da3c2ae2537e7df57fe6305081ca51f762f6fd4ceb2d"
PINS = {
    "2.6.4": "d2a3cbfd7aa3137d600fa7f765040540099a52b4e099fd6a8c57d2c9e8b67d06",
    "2.6.5": "f86829d6bd982b532514903f9da0b92c24cee85c7ffe77f657e9013c6f39fb22",
    "2.7.0": "9b764641bf4845901c5a6c6ad7d72a096e4022ce5d8562bdd89a5bca3827673f",
    "2.7.1": "e2734aa0845faecd994a3fc827d32685c238ecaf73a39c77415d06a751d6f44c",
    "2.7.2": "089e706c19d0427f12c57a6255b087fff9916e5a65657d6d55740bdbb5c142f7",
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
    return validate(version, fixture.base.read_regular_file(ROOT / f"{version}.json", 128 * 1024))


def main():
    try:
        fixture.require(set(PINS) == set(fixture.VERSIONS))
        for version in fixture.VERSIONS:
            verify(version)
    except (fixture.harness.HarnessError, fixture.base.SnapshotError, OSError, ValueError, KeyError, TypeError):
        print("Retained current-profile CI evidence missing or invalid")
        return 1
    print("Five local CI-runner TLS/SDK reports verified; GitHub execution approval remains separate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
