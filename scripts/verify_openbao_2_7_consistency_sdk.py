#!/usr/bin/python3 -EsSB
"""Verify retained staged SDK TLS evidence, not public promotion or controlled lag."""

import argparse

import openbao_2_7_consistency_sdk as fixture

snapshots = fixture.server.snapshots
RESULT = fixture.ROOT / "compat/onboarding/2.7.0/consistency-sdk-tls-v13.json"
EXPECTED_SHA256 = "95e8e14187672fe260721d1d54eeaacda64c789105836e173b0b05b1fcb86340"
TEST_BINARY_SHA256 = "0e776adfd7c95b7c2186462c4ef2c0fec8b0b6d93faddb94984628c1481c7862"


def validate_report(report):
    expected = {**fixture.EXECUTION_ASSURANCE, "schema": "openbao-consistency-sdk-tls/v1", "version": fixture.server.fixture.VERSION,
                "inputs": fixture.input_hashes(), "test_binary_sha256": TEST_BINARY_SHA256,
                "test": fixture.TEST, "outcome": "passed",
                "image_linux_amd64_digest": fixture.server.staged.AMD64, "routable": False,
                "scope": "sdk-production-transport-beneath-profile-gate", "controlled_replication_lag_verified": False}
    fixture.server.require(snapshots.canonical_json(report) == snapshots.canonical_json(expected))


def verify():
    data = snapshots.read_regular_file(RESULT, 64 * 1024)
    if snapshots.sha256(data) != EXPECTED_SHA256:
        raise snapshots.SnapshotError("SDK consistency evidence digest changed")
    report = snapshots.parse_json(data, 64 * 1024)
    if snapshots.canonical_json(report) != data:
        raise snapshots.SnapshotError("SDK consistency evidence is not canonical")
    validate_report(report)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (fixture.server.harness.HarnessError, snapshots.SnapshotError, OSError, ValueError):
        print("SDK consistency evidence verification failed")
        return 1
    print("SDK TLS baseline evidence verified; controlled lag has a separate report; no release-approval claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
