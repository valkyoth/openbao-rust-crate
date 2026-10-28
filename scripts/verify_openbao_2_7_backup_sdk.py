#!/usr/bin/python3 -EsSB
"""Verify public SDK backup evidence without claiming strict profile promotion."""

import argparse

import openbao_2_7_backup_sdk as fixture

snapshots = fixture.snapshots
RESULT = fixture.ROOT / "compat/onboarding/2.7.0/backup-sdk-tls-v11.json"
EXPECTED_SHA256 = "2ae0cb22af2c5f29b0bb6a057dfa1b6c74e11b024544cca66bd844e115616e94"
TEST_BINARY_SHA256 = "182f9f63233333c9f99098d6aa3170603bd39c00375eae93b05253cf2f9591dc"


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
