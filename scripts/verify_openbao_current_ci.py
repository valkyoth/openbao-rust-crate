#!/usr/bin/python3 -EsSB
"""Verify immutable local validation of the supplemental 2.2.3 CI runner."""

import openbao_current_ci as fixture

ROOT = fixture.ROOT / "compat/ci/2.2.3"
BINARY_SHA256 = "da8127e07d2700ee0666aba01a8bfaf4f22598e52cc2bf44d0dad336a482cdc0"
PINS = {
    "2.6.4": "cf967597cb639092606efdf20fdd014cef8fc06592cd4a6001160f9c5bc84839",
    "2.7.0": "0b27ed8863d65b4611ffb429f55973e8ffb72f42e2d1e076772d1dbc4bf5868c",
    "2.7.1": "5fdb9e99907f3c80cf64de1460f5b64d3ce87f6e486ec5e93694cb99933d323f",
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
    return validate(version, fixture.base.read_regular_file(ROOT / f"{version}-v3.json", 128 * 1024))


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
