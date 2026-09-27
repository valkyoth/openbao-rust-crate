#!/usr/bin/python3 -EsSB
"""Verify control-group compatibility evidence, including its known security failure."""

import argparse
from pathlib import Path

import openbao_2_7_control_groups as fixture
import openbao_api_snapshots as snapshots

ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "compat/onboarding/2.7.0/control-group-tls.json"
EXPECTED_SHA256 = "4c01c11d4635ffd0b979064c7186f048e5b2672b4d896eb491f531017032630d"


def verify():
    data = snapshots.read_regular_file(RESULT, 64 * 1024)
    if snapshots.sha256(data) != EXPECTED_SHA256:
        raise snapshots.SnapshotError("control-group evidence digest changed")
    report = snapshots.parse_json(data, 64 * 1024)
    if snapshots.canonical_json(report) != data:
        raise snapshots.SnapshotError("control-group evidence is not canonical")
    fixture.validate_report(report, fixture.input_hashes())
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (fixture.harness.HarnessError, snapshots.SnapshotError, OSError, ValueError):
        print("Control-group evidence verification failed")
        return 1
    print("Control-group compatibility evidence verified; known server replay failure remains; SDK profile not promoted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
