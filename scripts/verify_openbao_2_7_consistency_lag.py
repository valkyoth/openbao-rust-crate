#!/usr/bin/python3 -EsSB
"""Verify controlled-lag server evidence without promoting SDK claims."""

import argparse

import openbao_2_7_consistency_lag as fixture

snapshots = fixture.server.snapshots
RESULT = fixture.server.ROOT / "compat/onboarding/2.7.0/consistency-lag-tls.json"
EXPECTED_SHA256 = "af5b88decaf9dc4eb40c8da38f4886d416aa3daa78d644bde149646352434808"


def validate_report(report):
    expected = {"schema": "openbao-consistency-controlled-lag/v1", "version": fixture.server.fixture.VERSION,
                "inputs": fixture.input_hashes(), "outcome": "passed", "checks": fixture.CHECKS,
                "image_linux_amd64_digest": fixture.server.staged.AMD64, "routable": False,
                "scope": "controlled-lag-server-protocol-only", "sdk_controlled_lag_verified": False,
                "expiry_listener_wait_ms": 250, "recovery_listener_wait_ms": 10000}
    fixture.server.require(snapshots.canonical_json(report) == snapshots.canonical_json(expected))


def verify():
    data = snapshots.read_regular_file(RESULT, 64 * 1024)
    if snapshots.sha256(data) != EXPECTED_SHA256:
        raise snapshots.SnapshotError("controlled-lag evidence digest changed")
    report = snapshots.parse_json(data, 64 * 1024)
    if snapshots.canonical_json(report) != data:
        raise snapshots.SnapshotError("controlled-lag evidence is not canonical")
    validate_report(report)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (fixture.server.harness.HarnessError, snapshots.SnapshotError, OSError, ValueError):
        print("Controlled-lag evidence verification failed")
        return 1
    print("Controlled-lag server evidence verified; SDK lag has a separate report; profile remains blocked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
