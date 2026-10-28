#!/usr/bin/python3 -EsSB
"""Verify coordinated SDK lag evidence without claiming public profile promotion."""

import argparse

import openbao_2_7_consistency_sdk_lag as fixture

snapshots = fixture.server.snapshots
RESULT = fixture.server.ROOT / "compat/onboarding/2.7.0/consistency-sdk-lag-tls-v11.json"
EXPECTED_SHA256 = "8bafa1c4ac976cdad189cde21df336aea65c6c43c3cccf23392b8306d83d8be9"
TEST_BINARY_SHA256 = "182f9f63233333c9f99098d6aa3170603bd39c00375eae93b05253cf2f9591dc"


def validate_report(report):
    expected = {**fixture.sdk.EXECUTION_ASSURANCE, "schema": "openbao-consistency-sdk-lag-tls/v2", "version": fixture.server.fixture.VERSION,
                "inputs": fixture.input_hashes(), "test_binary_sha256": TEST_BINARY_SHA256,
                "test": fixture.TEST, "outcome": "passed",
                "image_linux_amd64_digest": fixture.server.staged.AMD64, "routable": False,
                "scope": "sdk-controlled-lag-beneath-profile-gate",
                "checks": ["stale-read", "real-index-429", "rejected-write-no-mutation",
                           "foreign-namespace-index-no-dispatch", "cancel-after-upstream-transmission",
                           "timeout-after-upstream-transmission", "no-retry", "await-recovery",
                           "independent-cluster-preflight-no-authenticated-dispatch", "cleanup"]}
    fixture.server.require(snapshots.canonical_json(report) == snapshots.canonical_json(expected))


def verify():
    data = snapshots.read_regular_file(RESULT, 64 * 1024)
    if snapshots.sha256(data) != EXPECTED_SHA256:
        raise snapshots.SnapshotError("SDK lag evidence digest changed")
    report = snapshots.parse_json(data, 64 * 1024)
    if snapshots.canonical_json(report) != data:
        raise snapshots.SnapshotError("SDK lag evidence is not canonical")
    validate_report(report)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        verify()
    except (fixture.server.harness.HarnessError, snapshots.SnapshotError, OSError, ValueError):
        print("SDK lag evidence verification failed")
        return 1
    print("Coordinated SDK lag evidence verified; no release-approval claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
