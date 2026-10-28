#!/usr/bin/python3 -EsSB
"""Verify immutable local validation of the supplemental 2.2.5 CI runner."""

import openbao_current_ci as fixture

ROOT = fixture.ROOT / "compat/ci/2.2.5/v3"
BINARY_SHA256 = "43af4a573e836ff92c89da3c2ae2537e7df57fe6305081ca51f762f6fd4ceb2d"
PINS = {
    "2.6.4": "227b2acc7f936ff9f952d5255d5985c41b4a06afe057a16727f24d90fb2734f9",
    "2.6.5": "80e92935f5bbc0e0cb97d08c569fe8b4e5ed9ba2a0e03df581d6031596c91fe6",
    "2.7.0": "bef7bd94e875fe93c60c9bd3b79b0e28c922117abb0cdb6ccbb32f313d8dbf22",
    "2.7.1": "36265be82618d158311e0753a6c849a065a781a59f2dbe6955c5734384425e51",
    "2.7.2": "3d8963fc7d1b5487c050862bbf29ff729a82b4eb02569177ca213a1cc5a73942",
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
