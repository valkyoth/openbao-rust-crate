#!/usr/bin/python3 -EsSB
"""Verify staged workflow CAS evidence without lifting either SDK security block."""

import argparse

import openbao_2_7_workflow_cas as fixture

snapshots = fixture.snapshots
RESULT = fixture.ROOT / "compat/onboarding/2.7.0/workflow-cas-tls.json"
EXPECTED_SHA256 = "14c430f1b0203a52eba00bb26c2ca7879017f85b1e92f229721e0acedb558980"


def validate_report(report):
    expected = {"schema": "openbao-workflow-cas-tls/v1", "version": fixture.fixture.VERSION,
                "inputs": fixture.input_hashes(), "image_linux_amd64_digest": fixture.staged.AMD64,
                "outcome": "passed", "scope": "server-fixture-only-not-sdk-integration",
                "tls": "TLSv1.3", "checks": fixture.CHECKS, "prefix_listing_verified": False,
                "sdk_cas_enabled": False, "routable": False}
    if snapshots.canonical_json(report) != snapshots.canonical_json(expected):
        raise snapshots.SnapshotError("workflow CAS evidence scope or inputs changed")


def verify():
    data = snapshots.read_regular_file(RESULT, 64 * 1024)
    if snapshots.sha256(data) != EXPECTED_SHA256:
        raise snapshots.SnapshotError("workflow CAS evidence digest changed")
    report = snapshots.parse_json(data, 64 * 1024)
    if snapshots.canonical_json(report) != data:
        raise snapshots.SnapshotError("workflow CAS evidence is not canonical")
    validate_report(report)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (snapshots.SnapshotError, OSError, ValueError):
        print("Workflow CAS evidence verification failed")
        return 1
    print("Workflow CAS server evidence verified; SDK blocks and profile promotion unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
