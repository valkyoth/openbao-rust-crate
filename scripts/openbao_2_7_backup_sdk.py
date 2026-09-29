#!/usr/bin/python3 -EsSB
"""Verify public SDK PGP backup decoding with explicit build and policy scope."""

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
STRICT_TEST = "sys::backup_live::public_rotation_backup_strict_tls"
ROOT = recovery.ROOT
snapshots = recovery.snapshots


def input_hashes(strict_candidate=False):
    paths = {*recovery.INPUTS, *sdk.INPUTS, "scripts/openbao_2_7_backup_sdk.py",
             *(str(path.relative_to(ROOT)) for path in (ROOT / "src").rglob("*.rs"))}
    if strict_candidate:
        paths.update({"scripts/check_openbao_2_7_candidate_sdk.py",
                      "docs/OPENBAO_REQUEST_FIELD_COMPATIBILITY.md",
                      "compat/onboarding/2.7.0/control-group-policy.hcl",
                      "tests/fixtures/tls_test_ca.pem", "tests/fixtures/tls_test_ca.crl.pem",
                      "scripts/generate_openbao_2_7_candidate.py",
                      "scripts/generate_openbao_capability_registry.py",
                      "compat/onboarding/2.7.0/candidate-capability-registry.json"})
    return {path: snapshots.sha256(snapshots.read_regular_file(ROOT / path, 2 * 1024 * 1024))
            for path in sorted(paths)}


def report_for(inputs, binary, strict_candidate=False, strict=False):
    recovery.require(not (strict_candidate and strict))
    report = {**sdk.EXECUTION_ASSURANCE, "schema": "openbao-backup-sdk-tls/v1", "version": recovery.fixture.VERSION,
            "inputs": inputs, "test_binary_sha256": binary, "test": TEST,
            "image_linux_amd64_digest": recovery.staged.AMD64,
            "scope": "public-sdk-unverified-mode", "outcome": "passed",
            "checks": [*recovery.CHECKS, "sdk-grouped-backup-read", "sdk-singleton-backup-read",
                       "sdk-hex-base64-equivalence"],
            "backup_decryption_verified": False, "strict_profile_verified": False,
            "routable": False}
    if strict_candidate:
        import generate_openbao_2_7_candidate as candidate
        verified = candidate.verify()
        report.update({"schema": "openbao-backup-sdk-strict-candidate-tls/v1",
                       "scope": "public-sdk-strict-disposable-candidate-build",
                       "test": STRICT_TEST, "strict_profile_verified": True,
                       "candidate_registry_sha256": candidate.EXPECTED_SHA256,
                       "candidate_generated_rust_sha256": snapshots.sha256(
                           candidate.registry.rust_output(verified, verification_candidate=True)),
                       "source_scope": "repository-inputs-with-explicit-generated-candidate-override"})
    if strict:
        report.update({"schema": "openbao-backup-sdk-strict-tls/v1",
                       "scope": "public-sdk-strict-normal-build",
                       "test": STRICT_TEST, "strict_profile_verified": True,
                       "routable": True, "source_scope": "unmodified-repository-inputs"})
    return report


def validate_report(report, binary, strict_candidate=False, strict=False):
    recovery.require(snapshots.canonical_json(report) == snapshots.canonical_json(
        report_for(input_hashes(strict_candidate), binary, strict_candidate, strict)))


@sdk.frozen_runner
def run(binary, strict_candidate=False, strict=False):
    recovery.require(not (strict_candidate and strict))
    recovery.require(os.geteuid() == 0)
    uid, gid = int(os.environ.get("SUDO_UID", "0")), int(os.environ.get("SUDO_GID", "0"))
    recovery.require(uid > 0 and gid > 0 and pwd.getpwuid(uid).pw_gid == gid)
    digest = sdk.binary_hash(binary, uid, candidate=strict_candidate)
    inputs = input_hashes(strict_candidate)
    if strict_candidate:
        # Verify the candidate inputs before creating resources, not just when reporting.
        report_for(inputs, digest, True)
    calls = 0

    def observe(address, ca, token):
        nonlocal calls
        recovery.require(calls == 0)
        print("Backup SDK fixture: running unprivileged public SDK test", flush=True)
        sdk.run_test(binary, uid, gid, [address] * 3, ca, token,
                     test=STRICT_TEST if strict_candidate or strict else TEST)
        calls += 1

    # The established server harness owns setup and cleanup, including callback failures.
    result = recovery.run(backup_observer=observe)
    recovery.validate_report(result)
    recovery.require(calls == 1 and inputs == input_hashes(strict_candidate)
                     and digest == sdk.binary_hash(binary, uid, candidate=strict_candidate))
    return report_for(inputs, digest, strict_candidate, strict)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-binary", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--strict-candidate", action="store_true")
    mode.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, recovery.harness.interrupted)
    try:
        result = run(args.test_binary, args.strict_candidate, args.strict)
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
