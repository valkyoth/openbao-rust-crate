#!/usr/bin/python3 -EsSB
"""Verify staged MFA enrollment evidence without claiming erasure or promotion."""

import argparse

import openbao_2_7_mfa_totp as fixture

snapshots = fixture.snapshots
RESULT = fixture.ROOT / "compat/onboarding/2.7.0/mfa-totp-tls.json"
EXPECTED_SHA256 = "006b5ed1ac04b30772f0623b13fdbe0a67f29c3bae28c0f9f0aa2d3990285a05"


def verify():
    data = snapshots.read_regular_file(RESULT, 64 * 1024)
    if snapshots.sha256(data) != EXPECTED_SHA256:
        raise snapshots.SnapshotError("MFA enrollment evidence digest changed")
    report = snapshots.parse_json(data, 64 * 1024)
    if snapshots.canonical_json(report) != data:
        raise snapshots.SnapshotError("MFA enrollment evidence is not canonical")
    fixture.validate_report(report)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (fixture.harness.HarnessError, snapshots.SnapshotError, OSError, ValueError):
        print("MFA enrollment evidence verification failed")
        return 1
    print("MFA enrollment server evidence verified; erasure not claimed; public profile remains blocked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
