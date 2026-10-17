#!/usr/bin/python3 -EsSB
"""Verify immutable local validation of the supplemental 2.2.4 CI runner."""

import openbao_current_ci as fixture

ROOT = fixture.ROOT / "compat/ci/2.2.4"
BINARY_SHA256 = "e6862dbd6c3ba1cae32c00839fc1149a24a923ecd83fa3c54a90d8c48b7aefee"
PINS = {
    "2.6.4": "0f41d2d66239aeb96765281527ba3bbdbd674ee83a52315ca5559319d5605941",
    "2.7.0": "4c5a7ee9aa75b1251d834881d523fd8ddb56e561783f7012c748e6563030cf2d",
    "2.7.1": "9ddf7a50e32cc8c30498041aa98f1da1e01f9c1252940dc607509f258f52e8cd",
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
    print("Three local CI-runner TLS/SDK reports verified; GitHub execution approval remains separate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
