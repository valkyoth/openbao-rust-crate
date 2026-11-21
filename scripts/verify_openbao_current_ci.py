#!/usr/bin/python3 -EsSB
"""Verify retained local evidence from the supplemental current-profile CI runner."""

import openbao_current_ci as fixture

ROOT = fixture.ROOT / "compat/ci/2.2.6"
BINARY_SHA256 = "606afb4480e07d1335dd5933fdd013bcf339febc3a4cda0ee95a5ea6be7a6279"
PINS = {
    "2.6.6": "1c84b599f9c286dfee09abbf361f3a33489aaef5325b7eb861f54419f6de33b9",
    "2.7.3": "ac953f9add719b654051dea40c6d9a995414826bc6a205a682b02800ccdfd086",
    "2.6.4": "55e3458e22c23c0e96280a28a1a9f93b1bdc1259649cbd4179f2a422d3aecf7c",
    "2.6.5": "68fa3e1d8fa9a13a1d2caf80c21c09fc0b35d9e79cd8e8999fdeba792f55ccab",
    "2.7.0": "daa16159fffc80620776c94cc85e67635e425d10e92af583597cb202a1cea96b",
    "2.7.1": "abde2752444f37d9ed993c5d89d6ec58cd75ef333b45bb578bbf8cd47e7aa4ce",
    "2.7.2": "f7f0abb490100924e868e698dd29d7e95a8215d1ed067b8b4e8a2d364b2eec34",
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
    print(f"{len(PINS)} local CI-runner TLS/SDK reports verified; GitHub execution approval remains separate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
