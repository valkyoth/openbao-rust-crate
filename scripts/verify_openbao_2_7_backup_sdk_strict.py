#!/usr/bin/python3 -EsSB
"""Verify retained exact-profile backup evidence from the normal SDK build."""

import argparse

import openbao_2_7_backup_sdk as fixture

RESULT = fixture.ROOT / "compat/onboarding/2.7.0/backup-sdk-strict-tls-v13.json"
EXPECTED_SHA256 = "19b86a90143abd3a2c7bb5d8ae36467f22d7859c342eef30edef0ed0513f74b5"
TEST_BINARY_SHA256 = "ef22e0309cf695099e0080008fb4bac4e97a9f0685ad32647ca2f9d4365c03c7"


def verify():
    data = fixture.snapshots.read_regular_file(RESULT, 64 * 1024)
    if fixture.snapshots.sha256(data) != EXPECTED_SHA256:
        raise fixture.snapshots.SnapshotError("strict SDK backup evidence digest changed")
    report = fixture.snapshots.parse_json(data, 64 * 1024)
    if fixture.snapshots.canonical_json(report) != data:
        raise fixture.snapshots.SnapshotError("strict SDK backup evidence is not canonical")
    fixture.validate_report(report, TEST_BINARY_SHA256, strict=True)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (fixture.recovery.harness.HarnessError, fixture.snapshots.SnapshotError,
            OSError, ValueError):
        print("Strict normal-build SDK backup evidence verification failed")
        return 1
    print("Strict normal-build SDK backup TLS evidence verified; decryption not claimed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
