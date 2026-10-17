#!/usr/bin/python3 -EsSB
"""Verify public SDK backup evidence without claiming strict profile promotion."""

import argparse

import openbao_2_7_backup_sdk as fixture

snapshots = fixture.snapshots
RESULT = fixture.ROOT / "compat/onboarding/2.7.0/backup-sdk-tls-v10.json"
EXPECTED_SHA256 = "30d0fff65c34108f6c3f429ce05858fa6dccb2b023a67976301d38f5824ea946"
TEST_BINARY_SHA256 = "4666c528dae8f070ba2ab847b4f8d7c72b2ce4c14c8e2e3a476ad3f9950c48bd"


def verify():
    data = snapshots.read_regular_file(RESULT, 64 * 1024)
    if snapshots.sha256(data) != EXPECTED_SHA256:
        raise snapshots.SnapshotError("SDK backup evidence digest changed")
    report = snapshots.parse_json(data, 64 * 1024)
    if snapshots.canonical_json(report) != data:
        raise snapshots.SnapshotError("SDK backup evidence is not canonical")
    fixture.validate_report(report, TEST_BINARY_SHA256)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (fixture.recovery.harness.HarnessError, snapshots.SnapshotError, OSError, ValueError):
        print("SDK backup evidence verification failed")
        return 1
    print("Public SDK backup evidence verified in unverified mode; strict profile and decryption not claimed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
