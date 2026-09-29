#!/usr/bin/python3 -EsSB
"""Verify public SDK PGP backup decoding in unverified mode, not profile promotion."""

import argparse
import os
from pathlib import Path
import pwd
import signal
import subprocess
import tempfile

import openbao_2_7_recovery_backup as recovery
import openbao_2_7_consistency_sdk as sdk

TEST = "sys::backup_live::public_rotation_backup_tls"
ROOT = recovery.ROOT
snapshots = recovery.snapshots


def input_hashes():
    paths = {*recovery.INPUTS, *sdk.INPUTS, "scripts/openbao_2_7_backup_sdk.py",
             *(str(path.relative_to(ROOT)) for path in (ROOT / "src").rglob("*.rs"))}
    return {path: snapshots.sha256(snapshots.read_regular_file(ROOT / path, 2 * 1024 * 1024))
            for path in sorted(paths)}


def report_for(inputs, binary):
    return {"schema": "openbao-backup-sdk-tls/v1", "version": recovery.fixture.VERSION,
            "inputs": inputs, "test_binary_sha256": binary, "test": TEST,
            "image_linux_amd64_digest": recovery.staged.AMD64,
            "scope": "public-sdk-unverified-mode", "outcome": "passed",
            "checks": [*recovery.CHECKS, "sdk-grouped-backup-read", "sdk-singleton-backup-read",
                       "sdk-hex-base64-equivalence"],
            "backup_decryption_verified": False, "strict_profile_verified": False,
            "routable": False}


def validate_report(report, binary):
    recovery.require(snapshots.canonical_json(report) == snapshots.canonical_json(report_for(input_hashes(), binary)))


def run(binary):
    recovery.require(os.geteuid() == 0)
    uid, gid = int(os.environ.get("SUDO_UID", "0")), int(os.environ.get("SUDO_GID", "0"))
    recovery.require(uid > 0 and gid > 0 and pwd.getpwuid(uid).pw_gid == gid)
    digest = sdk.binary_hash(binary, uid)
    inputs = input_hashes()
    calls = 0

    def observe(address, ca, token):
        nonlocal calls
        recovery.require(calls == 0)
        print("Backup SDK fixture: running unprivileged public SDK test", flush=True)
        sdk.run_test(binary, uid, gid, [address] * 3, ca, token, test=TEST)
        calls += 1

    # The established server harness owns setup and cleanup, including callback failures.
    result = recovery.run(backup_observer=observe)
    recovery.validate_report(result)
    recovery.require(calls == 1 and inputs == input_hashes() and digest == sdk.binary_hash(binary, uid))
    return report_for(inputs, digest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-binary", required=True, type=Path)
    args = parser.parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, recovery.harness.interrupted)
    try:
        result = run(args.test_binary)
        with tempfile.NamedTemporaryFile(prefix="openbao-270-backup-sdk-result-", suffix=".json", delete=False) as output:
            output.write(snapshots.canonical_json(result))
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            print(f"Backup SDK fixture passed; result: {output.name}")
        return 0
    except (recovery.harness.HarnessError, snapshots.SnapshotError, OSError, ValueError,
            KeyError, TypeError, subprocess.SubprocessError):
        print("Backup SDK fixture failed; no profile promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
