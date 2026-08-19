#!/usr/bin/env python3
"""Generate and verify exact-release OpenBao core-flow evidence."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from openbao_api_snapshots import SnapshotError, parse_json, read_regular_file
from openbao_test_harness import (
    CORE_OPERATION_IDS,
    HarnessError,
    IntegrationTestFailure,
    VersionMismatch,
    run_integration,
)
from validate_openbao_release_lock import (
    EXPECTED_LOCK_SHA256,
    LockValidationError,
    validate_lock_files,
)

ROOT = Path(__file__).resolve().parents[1]
RESULTS_PATH = ROOT / "compat/core-flow-results.json"
CHECKSUM_PATH = ROOT / "compat/core-flow-results.sha256"
HISTORICAL_RESULTS_PATH = ROOT / "compat/core-flow-history/through-2.5.5.json"
HISTORICAL_CHECKSUM_PATH = ROOT / "compat/core-flow-history/through-2.5.5.sha256"
HARNESS_PATH = ROOT / "scripts/openbao_test_harness.py"
TEST_PATH = ROOT / "tests/openbao_integration.rs"
EXPECTED_RESULTS_SHA256 = "07bfd4f811686888cd737480d74855dbebe9fc3c7a5e6d978b54113dfa1c9a97"
HISTORICAL_RESULTS_SHA256 = "d7aa0b1f07d535ae8b762587ae8221cefb073ff5acba12fec3d7d5b03e1e3d8c"
MAX_RESULTS_BYTES = 512 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
FAILURE_CLASSES = {
    "crate-defect",
    "expected-server-difference",
    "security-policy-block",
    "infrastructure-problem",
}
SKIP_REASONS = {
    "server-operation-unavailable": "expected-server-difference",
    "crate-security-policy-block": "security-policy-block",
}
FAILURE_REASONS = {
    "core-flow-test-failed": "crate-defect",
    "server-version-mismatch": "infrastructure-problem",
    "harness-infrastructure-failed": "infrastructure-problem",
}
SAFE_VALUE = re.compile(r"[A-Za-z0-9_./:+ -]{1,256}", re.ASCII)


class MatrixError(RuntimeError):
    """Historical core-flow evidence is invalid."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def source_hash(path: Path) -> str:
    try:
        return sha256(read_regular_file(path, MAX_SOURCE_BYTES))
    except (OSError, SnapshotError) as error:
        raise MatrixError("core-flow evidence source is missing or unsafe") from error


def failure_record(release: dict[str, Any], error: BaseException) -> dict[str, Any]:
    if isinstance(error, IntegrationTestFailure):
        classification = "crate-defect"
        reason = "core-flow-test-failed"
    elif isinstance(error, VersionMismatch):
        classification = "infrastructure-problem"
        reason = "server-version-mismatch"
    else:
        classification = "infrastructure-problem"
        reason = "harness-infrastructure-failed"
    return {
        "version": release["version"],
        "image_linux_amd64_digest": release["image"]["linux_amd64_digest"],
        "reported_version": None,
        "compatibility_status": "unverified",
        "outcome": "failed",
        "test_count": 0,
        "operations": [],
        "failure_class": classification,
        "failure_reason_code": reason,
    }


def build_matrix() -> dict[str, Any]:
    try:
        inventory = validate_lock_files()
    except LockValidationError as error:
        raise MatrixError("immutable release inventory validation failed") from error
    records = inventory["records"]
    results: list[dict[str, Any]] = []
    for release in records:
        version = release["version"]
        print(f"OpenBao core matrix: testing locked {version}", flush=True)
        try:
            result = run_integration(version)
        except (HarnessError, OSError) as error:
            result = failure_record(release, error)
            diagnostic = (
                str(error)
                if isinstance(error, HarnessError)
                else "local operating system failure"
            )
            print(
                f"OpenBao core matrix: locked {version} failed "
                f"({result['failure_reason_code']}): {diagnostic}",
                flush=True,
            )
        results.append(result)
    passed = sum(record["outcome"] == "passed" for record in results)
    failed = sum(record["outcome"] == "failed" for record in results)
    matrix = {
        "schema": "openbao-core-flow-results/v1",
        "generator_version": 1,
        "release_inventory_sha256": EXPECTED_LOCK_SHA256,
        "harness_sha256": source_hash(HARNESS_PATH),
        "test_definition_sha256": source_hash(TEST_PATH),
        "scope": {
            "compatibility_status": "tested-subset",
            "claim": "only the listed core SDK operations were executed",
            "operation_ids": list(CORE_OPERATION_IDS),
        },
        "summary": {
            "release_count": len(results),
            "passed": passed,
            "failed": failed,
            "skipped_operations": sum(
                operation["status"] == "skipped"
                for record in results
                for operation in record["operations"]
            ),
        },
        "records": results,
    }
    validate_matrix(matrix, inventory, require_all_passed=False)
    return matrix


def validate_safe_strings(value: Any) -> None:
    if isinstance(value, str):
        if SAFE_VALUE.fullmatch(value) is None:
            raise MatrixError("core-flow evidence contains an unsafe string")
    elif isinstance(value, list):
        for item in value:
            validate_safe_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or SAFE_VALUE.fullmatch(key) is None:
                raise MatrixError("core-flow evidence contains an unsafe field")
            validate_safe_strings(item)
    elif value is not None and not isinstance(value, (bool, int)):
        raise MatrixError("core-flow evidence contains an unsupported value")


def validate_matrix(
    matrix: dict[str, Any],
    inventory: dict[str, Any],
    *,
    require_all_passed: bool,
) -> None:
    if set(matrix) != {
        "schema",
        "generator_version",
        "release_inventory_sha256",
        "harness_sha256",
        "test_definition_sha256",
        "scope",
        "summary",
        "records",
    }:
        raise MatrixError("core-flow evidence top-level fields are invalid")
    if (
        matrix["schema"] != "openbao-core-flow-results/v1"
        or matrix["generator_version"] != 1
        or matrix["release_inventory_sha256"] != EXPECTED_LOCK_SHA256
        or matrix["harness_sha256"] != source_hash(HARNESS_PATH)
        or matrix["test_definition_sha256"] != source_hash(TEST_PATH)
        or matrix["scope"]
        != {
            "compatibility_status": "tested-subset",
            "claim": "only the listed core SDK operations were executed",
            "operation_ids": list(CORE_OPERATION_IDS),
        }
    ):
        raise MatrixError("core-flow evidence metadata is invalid")
    records = matrix["records"]
    inventory_records = inventory["records"]
    if not isinstance(records, list) or len(records) != len(inventory_records):
        raise MatrixError("core-flow evidence does not cover the exact inventory")
    passed = 0
    failed = 0
    skipped = 0
    for record, release in zip(records, inventory_records, strict=True):
        if set(record) != {
            "version",
            "image_linux_amd64_digest",
            "reported_version",
            "compatibility_status",
            "outcome",
            "test_count",
            "operations",
            "failure_class",
            "failure_reason_code",
        }:
            raise MatrixError("core-flow release result fields are invalid")
        if (
            record["version"] != release["version"]
            or record["image_linux_amd64_digest"]
            != release["image"]["linux_amd64_digest"]
            or record["outcome"] not in {"passed", "failed"}
            or not isinstance(record["test_count"], int)
            or record["test_count"] < 0
            or not isinstance(record["operations"], list)
        ):
            raise MatrixError("core-flow release result identity is invalid")
        if record["outcome"] == "failed":
            failed += 1
            reason = record["failure_reason_code"]
            classification = record["failure_class"]
            if (
                record["compatibility_status"] != "unverified"
                or record["reported_version"] is not None
                or record["test_count"] != 0
                or record["operations"] != []
                or reason not in FAILURE_REASONS
                or classification not in FAILURE_CLASSES
                or classification != FAILURE_REASONS[reason]
            ):
                raise MatrixError("failed core-flow result is contradictory")
            continue
        passed += 1
        if (
            record["reported_version"] != record["version"]
            or record["compatibility_status"] != "tested-subset"
            or record["test_count"] < 1
            or record["failure_class"] is not None
            or record["failure_reason_code"] is not None
            or len(record["operations"]) != len(CORE_OPERATION_IDS)
        ):
            raise MatrixError("passing core-flow result is incomplete")
        operation_ids: list[str] = []
        passed_operations = 0
        for operation in record["operations"]:
            if set(operation) != {"id", "status", "reason_code", "classification"}:
                raise MatrixError("core-flow operation result fields are invalid")
            operation_id = operation["id"]
            operation_ids.append(operation_id)
            if operation["status"] == "passed":
                passed_operations += 1
                if operation["reason_code"] is not None or operation["classification"] is not None:
                    raise MatrixError("passing operation has a failure classification")
            elif operation["status"] == "skipped":
                skipped += 1
                reason = operation["reason_code"]
                if (
                    reason not in SKIP_REASONS
                    or operation["classification"] != SKIP_REASONS[reason]
                ):
                    raise MatrixError("skipped operation lacks a stable reason code")
            else:
                raise MatrixError("core-flow operation status is invalid")
            should_skip = (
                record["version"] not in {"2.6.0", "2.6.1", "2.6.2"}
                and operation_id in CORE_OPERATION_IDS[8:]
            )
            if (operation["status"] == "skipped") != should_skip:
                raise MatrixError("core-flow operation status contradicts the exact profile")
        if operation_ids != list(CORE_OPERATION_IDS):
            raise MatrixError("core-flow operations are missing, duplicated, or reordered")
        if passed_operations == 0:
            raise MatrixError("all-skipped core-flow result is forbidden")
    expected_summary = {
        "release_count": len(records),
        "passed": passed,
        "failed": failed,
        "skipped_operations": skipped,
    }
    if matrix["summary"] != expected_summary:
        raise MatrixError("core-flow evidence summary is inconsistent")
    if require_all_passed and (failed != 0 or passed != len(records)):
        raise MatrixError("committed core-flow evidence contains a failed release")
    validate_safe_strings(matrix)


def atomic_write(path: Path, data: bytes) -> None:
    if path.is_symlink() or path.parent.is_symlink():
        raise MatrixError("core-flow evidence output must not be a symbolic link")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def immutable_write(path: Path, data: bytes, maximum: int) -> None:
    if path.exists() or path.is_symlink():
        try:
            existing = read_regular_file(path, maximum)
        except (OSError, SnapshotError) as error:
            raise MatrixError("existing core-flow evidence is unsafe") from error
        if existing != data:
            raise MatrixError("immutable core-flow evidence would change")
        return
    atomic_write(path, data)


def capture() -> None:
    validate_historical_results()
    matrix = build_matrix()
    try:
        inventory = validate_lock_files()
    except LockValidationError as error:
        raise MatrixError("immutable release inventory validation failed") from error
    validate_matrix(matrix, inventory, require_all_passed=True)
    data = canonical_json(matrix)
    digest = sha256(data)
    current = read_regular_file(RESULTS_PATH, MAX_RESULTS_BYTES)
    if sha256(current) not in {
        HISTORICAL_RESULTS_SHA256,
        EXPECTED_RESULTS_SHA256,
        digest,
    }:
        raise MatrixError("active core-flow evidence has an unknown predecessor")
    atomic_write(RESULTS_PATH, data)
    atomic_write(
        CHECKSUM_PATH,
        f"{digest}  core-flow-results.json\n".encode(),
    )
    print(f"OpenBao core matrix: {len(matrix['records'])} exact releases passed")


def load_results() -> tuple[dict[str, Any], bytes]:
    validate_historical_results()
    try:
        data = read_regular_file(RESULTS_PATH, MAX_RESULTS_BYTES)
        checksum = read_regular_file(CHECKSUM_PATH, 256)
    except (OSError, SnapshotError) as error:
        raise MatrixError("core-flow evidence is missing or unsafe") from error
    if sha256(data) != EXPECTED_RESULTS_SHA256:
        raise MatrixError("core-flow evidence checksum does not match its validator anchor")
    expected_sidecar = f"{EXPECTED_RESULTS_SHA256}  core-flow-results.json\n".encode()
    if checksum != expected_sidecar:
        raise MatrixError("core-flow evidence sidecar checksum is invalid")
    try:
        value = parse_json(data, MAX_RESULTS_BYTES)
    except SnapshotError as error:
        raise MatrixError("core-flow evidence is malformed JSON") from error
    return value, data


def validate_historical_results() -> None:
    try:
        data = read_regular_file(HISTORICAL_RESULTS_PATH, MAX_RESULTS_BYTES)
        checksum = read_regular_file(HISTORICAL_CHECKSUM_PATH, 256)
    except (OSError, SnapshotError) as error:
        raise MatrixError("historical core-flow evidence is missing or unsafe") from error
    if sha256(data) != HISTORICAL_RESULTS_SHA256:
        raise MatrixError("historical core-flow evidence digest changed")
    expected = f"{HISTORICAL_RESULTS_SHA256}  through-2.5.5.json\n".encode()
    if checksum != expected:
        raise MatrixError("historical core-flow evidence sidecar changed")


def verify() -> None:
    matrix, _ = load_results()
    try:
        inventory = validate_lock_files()
    except LockValidationError as error:
        raise MatrixError("immutable release inventory validation failed") from error
    validate_matrix(matrix, inventory, require_all_passed=True)
    print(f"OpenBao core matrix: {len(matrix['records'])} exact releases verified")


def expect_rejected(label: str, operation: Any) -> None:
    try:
        operation()
    except MatrixError:
        return
    raise MatrixError(f"core-flow self-test accepted {label}")


def self_test() -> None:
    matrix, _ = load_results()
    try:
        inventory = validate_lock_files()
    except LockValidationError as error:
        raise MatrixError("immutable release inventory validation failed") from error
    validate_matrix(matrix, inventory, require_all_passed=True)
    mutations: list[tuple[str, dict[str, Any]]] = []
    missing_release = copy.deepcopy(matrix)
    missing_release["records"].pop()
    mutations.append(("a missing release", missing_release))
    zero_tests = copy.deepcopy(matrix)
    zero_tests["records"][0]["test_count"] = 0
    mutations.append(("a zero-test pass", zero_tests))
    duplicate_operation = copy.deepcopy(matrix)
    duplicate_operation["records"][0]["operations"][1] = copy.deepcopy(
        duplicate_operation["records"][0]["operations"][0]
    )
    mutations.append(("a duplicated operation", duplicate_operation))
    all_skipped = copy.deepcopy(matrix)
    for operation in all_skipped["records"][0]["operations"]:
        operation["status"] = "skipped"
        operation["reason_code"] = "server-operation-unavailable"
        operation["classification"] = "expected-server-difference"
    mutations.append(("an all-skipped pass", all_skipped))
    unknown_reason = copy.deepcopy(matrix)
    unknown_reason["records"][0]["operations"][0]["status"] = "skipped"
    unknown_reason["records"][0]["operations"][0]["reason_code"] = "ignore-failure"
    unknown_reason["records"][0]["operations"][0]["classification"] = "expected-server-difference"
    mutations.append(("an unknown skip reason", unknown_reason))
    for label, mutation in mutations:
        expect_rejected(
            label,
            lambda mutation=mutation: validate_matrix(
                mutation, inventory, require_all_passed=True
            ),
        )
    expect_rejected(
        "an unsafe report value",
        lambda: validate_safe_strings({"value": "line one\nline two"}),
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--capture", action="store_true")
    action.add_argument("--verify", action="store_true")
    action.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.capture:
            capture()
        elif arguments.self_test:
            self_test()
            print("OpenBao core matrix self-tests: ok")
        else:
            verify()
        return 0
    except (MatrixError, HarnessError, OSError) as error:
        print(f"OpenBao core matrix failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
