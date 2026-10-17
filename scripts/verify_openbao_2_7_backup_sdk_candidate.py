#!/usr/bin/python3 -EsSB
"""Verify strict live backup evidence for the disposable candidate build only."""

import argparse

import openbao_2_7_backup_sdk as fixture

RESULT = fixture.ROOT / "compat/onboarding/2.7.0/backup-sdk-strict-candidate-tls-v10.json"
EXPECTED_SHA256 = "59ba2e2a98da3ebb4f5d122b774014fd0552a5ec509532074af2a57322cb846c"
TEST_BINARY_SHA256 = "e995a1f4704ef04df91a9e2cd81e0e2a6a45250bb4602cb5a7b7dbe80ba05e32"


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
