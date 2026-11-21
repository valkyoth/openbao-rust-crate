#!/usr/bin/python3 -EsSB
"""Verify retained local evidence from the supplemental current-profile CI runner."""

import openbao_current_ci as fixture

ROOT = fixture.ROOT / "compat/ci/2.2.6"
BINARY_SHA256 = "606afb4480e07d1335dd5933fdd013bcf339febc3a4cda0ee95a5ea6be7a6279"
PINS = {
    "2.6.6": "49f63c2be8cf1c6d4b44c42bfb38d5a0c5d2eaf3b5c59dce4cd28aedd048ceae",
    "2.7.3": "330c38118c4d72d67554e96f7ef65cdca131e0ff44947e1dfd3f60a09c182c3c",
    "2.6.4": "04c7c49243a6eef457e3bef4a8dbc9a6944dacf28526810acc2d0480c6fdde7f",
    "2.6.5": "f788e09e57656a33d63fbb8d36e3d12a55fcdaafc8eedc7ed55732c0e8ce1eeb",
    "2.7.0": "d4b46fd397ace35326701f47f11b02514a3b751209864532a346bc8e5b4a64e9",
    "2.7.1": "2ee17bb35fa4a55af159297ebd6962a809ee4a261addf786060f44a7ebafdaf7",
    "2.7.2": "ee12c904aaa231ec6cd81ea110d42e56cce9b095afd1dd763e01a8bae659f3fc",
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
