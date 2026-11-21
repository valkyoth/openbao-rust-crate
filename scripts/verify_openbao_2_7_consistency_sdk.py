#!/usr/bin/python3 -EsSB
"""Verify retained staged SDK TLS evidence, not public promotion or controlled lag."""

import argparse

import openbao_2_7_consistency_sdk as fixture

snapshots = fixture.server.snapshots
RESULT = fixture.ROOT / "compat/onboarding/2.7.0/consistency-sdk-tls-v13.json"
EXPECTED_SHA256 = "4e12c984c163c53ac1a478f1ccc8eacb8fddff86379de7c182cc5fb09702ab7c"
TEST_BINARY_SHA256 = "ef22e0309cf695099e0080008fb4bac4e97a9f0685ad32647ca2f9d4365c03c7"


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
