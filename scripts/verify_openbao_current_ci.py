#!/usr/bin/python3 -EsSB
"""Verify retained local evidence from the supplemental current-profile CI runner."""

import openbao_current_ci as fixture

ROOT = fixture.ROOT / "compat/ci/2.2.6"
BINARY_SHA256 = "606afb4480e07d1335dd5933fdd013bcf339febc3a4cda0ee95a5ea6be7a6279"
PINS = {
    "2.6.6": "58302f64e04fb58a56d2f7f8cbe6b622a52dc44a7ec77cbbae2c632290a34e7e",
    "2.7.3": "aca393d8ed1a81e5d01b5041b9caf0f384123827400628461af6ad9b6297ccc8",
    "2.6.4": "fb00f070c25a1e7e9716794d801aa451f06c0b7251544384464f071102701dfc",
    "2.6.5": "27705489aab35049dbeeca5819e76053eeb30248ef735797b3c484fee0eaf148",
    "2.7.0": "da6f93778761ae398a7eb302735419bc927affb0b189665ba1ca0e817442cd79",
    "2.7.1": "6285a5d7c863ee88d7b2d7cfeccd5c53e53f1f211b63fb01262be64dc2404d5d",
    "2.7.2": "5a3d42527a1e2b889b84e999b7535469c65e79e2f54aee8d15aad6fb9001ffe9",
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
