#!/usr/bin/python3 -EsSB
"""Verify strict live backup evidence for the disposable candidate build only."""

import argparse

import openbao_2_7_backup_sdk as fixture

RESULT = fixture.ROOT / "compat/onboarding/2.7.0/backup-sdk-strict-candidate-tls.json"
EXPECTED_SHA256 = "a26882f6ce5f32df22488833264c5c2b79c56340b5bea0d5c91fab63f2f81c6d"
TEST_BINARY_SHA256 = "2e81d8e9d83d184e8d7e5eacd5fc8647cc6a21e079a24c56bbf61d5fb963179d"


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
