#!/usr/bin/python3 -EsSB
"""Verify public SDK backup evidence without claiming strict profile promotion."""

import argparse

import openbao_2_7_backup_sdk as fixture

snapshots = fixture.snapshots
RESULT = fixture.ROOT / "compat/onboarding/2.7.0/backup-sdk-tls.json"
EXPECTED_SHA256 = "3514b588bbd9dba861376a5fc2f92e0846bc2f79ddc4f0b75b0542dfadc3afb4"
TEST_BINARY_SHA256 = "8d2ec1ccc97c019731ddf2d4f5edbda2254e31aaf152d6b7b7aa269f40e7f0e1"


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
