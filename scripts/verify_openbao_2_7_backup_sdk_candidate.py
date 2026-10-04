#!/usr/bin/python3 -EsSB
"""Verify strict live backup evidence for the disposable candidate build only."""

import argparse

import openbao_2_7_backup_sdk as fixture

RESULT = fixture.ROOT / "compat/onboarding/2.7.0/backup-sdk-strict-candidate-tls-v7.json"
EXPECTED_SHA256 = "d920db41e6a160de79ef8f4c3d72c7af27b29232ff428531767a0271385ce021"
TEST_BINARY_SHA256 = "fa9e57cf58f5d21b3d15e2f09fcb70b39c15d25805c45112c3b802c3041583eb"


def verify():
    data = fixture.snapshots.read_regular_file(RESULT, 64 * 1024)
    if fixture.snapshots.sha256(data) != EXPECTED_SHA256:
        raise fixture.snapshots.SnapshotError("strict candidate backup evidence digest changed")
    report = fixture.snapshots.parse_json(data, 64 * 1024)
    if fixture.snapshots.canonical_json(report) != data:
        raise fixture.snapshots.SnapshotError("strict candidate backup evidence is not canonical")
    fixture.validate_report(report, TEST_BINARY_SHA256, True)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (fixture.recovery.harness.HarnessError, fixture.snapshots.SnapshotError,
            OSError, ValueError):
        print("Strict candidate backup evidence verification failed")
        return 1
    print("Strict candidate SDK backup TLS evidence verified; public promotion and decryption not claimed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
