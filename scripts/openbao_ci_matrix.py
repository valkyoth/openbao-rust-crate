#!/usr/bin/env python3
"""Plan, execute, and aggregate the version-locked OpenBao CI matrix."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

from openbao_api_snapshots import SnapshotError, parse_json, read_regular_file
from openbao_core_matrix import (
    FAILURE_REASONS,
    failure_record,
    source_hash,
    validate_safe_strings,
)
from openbao_test_harness import (
    CORE_OPERATION_IDS,
    HarnessError,
    IntegrationTestFailure,
    run_integration,
)
from validate_openbao_release_lock import (
    EXPECTED_LOCK_SHA256,
    LockValidationError,
    validate_lock_files,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github/workflows/openbao-compatibility.yml"
HARNESS_PATH = ROOT / "scripts/openbao_test_harness.py"
TEST_PATH = ROOT / "tests/openbao_integration.rs"
ARTIFACT_ROOT = ROOT / "ci-artifacts"
RUN_REPORT_PATH = ARTIFACT_ROOT / "openbao-result.json"
DOWNLOAD_ROOT = ARTIFACT_ROOT / "downloaded"
AGGREGATE_REPORT_PATH = ARTIFACT_ROOT / "openbao-compatibility-report.json"
EXPECTED_WORKFLOW_SHA256 = "9f20e2e8bef2715c2569f3821a989e6343364f9e3e06f7c2711882b33f448138"
MAX_REPORT_BYTES = 128 * 1024
MAX_WORKFLOW_BYTES = 128 * 1024
MAX_ARTIFACT_DIRECTORIES = 64
RUN_SCHEMA = "openbao-ci-core-flow-result/v1"
AGGREGATE_SCHEMA = "openbao-ci-compatibility-report/v1"
JOB_RESULTS = {"success", "failure", "cancelled", "skipped"}
DOWNLOAD_RESULTS = {"success", "failure", "cancelled", "skipped"}
COMPATIBILITY_FAILURE_CLASSES = {
    "crate-defect",
    "expected-server-difference",
    "security-policy-block",
}
INFRASTRUCTURE_FAILURE_CLASS = "infrastructure-problem"
CI_INFRASTRUCTURE_REASON = "ci-result-missing-or-invalid"


class CiMatrixError(RuntimeError):
    """The OpenBao CI matrix or its evidence is invalid."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def inventory() -> dict[str, Any]:
    try:
        return validate_lock_files()
    except LockValidationError as error:
        raise CiMatrixError("immutable release inventory validation failed") from error


def parse_version(version: str) -> tuple[int, int, int]:
    parts = version.split(".")
    if (
        len(parts) != 3
        or any(not part.isascii() or not part.isdigit() for part in parts)
        or any(part != str(int(part)) for part in parts)
    ):
        raise CiMatrixError("release inventory contains a non-canonical version")
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


def profile_versions(profile: str, document: dict[str, Any] | None = None) -> list[str]:
    if profile not in {"representative", "all"}:
        raise CiMatrixError("CI matrix profile is invalid")
    release_inventory = inventory() if document is None else document
    versions = [record["version"] for record in release_inventory["records"]]
    if not versions:
        raise CiMatrixError("CI matrix cannot contain zero releases")
    if profile == "all":
        return versions

    latest_by_minor: dict[tuple[int, int], str] = {}
    for version in versions:
        major, minor, _ = parse_version(version)
        latest_by_minor[(major, minor)] = version
    selected = [versions[0]]
    for version in latest_by_minor.values():
        if version not in selected:
            selected.append(version)
    if len(selected) < 2:
        raise CiMatrixError("representative CI matrix is unexpectedly small")
    return selected


def profile_for_event(event: str) -> str:
    if event == "pull_request":
        return "representative"
    if event in {"schedule", "workflow_dispatch", "push"}:
        return "all"
    raise CiMatrixError("GitHub event is not authorized for the compatibility matrix")


def matrix_json(versions: list[str]) -> str:
    if not versions:
        raise CiMatrixError("CI matrix cannot contain zero releases")
    return json.dumps(
        {"include": [{"version": version} for version in versions]},
        ensure_ascii=True,
        separators=(",", ":"),
    )


def append_github_output(path: Path, data: bytes) -> None:
    if len(data) > 64 * 1024 or b"\0" in data:
        raise CiMatrixError("GitHub output is malformed or oversized")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    if no_follow is None or non_block is None:
        raise CiMatrixError("secure GitHub output writes are unavailable")
    flags = os.O_WRONLY | os.O_APPEND | no_follow | non_block | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CiMatrixError("GitHub output cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o022 != 0
            or metadata.st_size > 1024 * 1024
        ):
            raise CiMatrixError("GitHub output is not a private regular file")
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise CiMatrixError("GitHub output write made no progress")
            written += count
    finally:
        os.close(descriptor)


def write_plan(event: str, output: Path) -> None:
    profile = profile_for_event(event)
    versions = profile_versions(profile)
    payload = (
        f"profile={profile}\n"
        f"release_count={len(versions)}\n"
        f"matrix={matrix_json(versions)}\n"
    ).encode()
    append_github_output(output, payload)
    print(f"OpenBao CI matrix: selected {len(versions)} locked releases")


def report_metadata() -> dict[str, Any]:
    return {
        "release_inventory_sha256": EXPECTED_LOCK_SHA256,
        "harness_sha256": source_hash(HARNESS_PATH),
        "test_definition_sha256": source_hash(TEST_PATH),
    }


def validate_operation(operation: dict[str, Any]) -> None:
    if set(operation) != {"id", "status", "reason_code", "classification"}:
        raise CiMatrixError("CI operation result fields are invalid")
    if operation["status"] == "passed":
        if operation["reason_code"] is not None or operation["classification"] is not None:
            raise CiMatrixError("passing CI operation carries a failure classification")
    elif operation["status"] == "skipped":
        if (
            operation["reason_code"] != "server-operation-unavailable"
            or operation["classification"] != "expected-server-difference"
        ):
            raise CiMatrixError("skipped CI operation lacks its stable classification")
    else:
        raise CiMatrixError("CI core-flow operation status is invalid")


def validate_result_record(
    record: dict[str, Any], release: dict[str, Any], *, allow_ci_reason: bool = False
) -> None:
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
        raise CiMatrixError("CI release result fields are invalid")
    if (
        record["version"] != release["version"]
        or record["image_linux_amd64_digest"] != release["image"]["linux_amd64_digest"]
        or record["outcome"] not in {"passed", "failed"}
        or type(record["test_count"]) is not int
        or not isinstance(record["operations"], list)
    ):
        raise CiMatrixError("CI release result identity is invalid")
    if record["outcome"] == "passed":
        if (
            record["reported_version"] != release["version"]
            or record["compatibility_status"] != "tested-subset"
            or record["test_count"] < 1
            or record["failure_class"] is not None
            or record["failure_reason_code"] is not None
            or [operation.get("id") for operation in record["operations"]]
            != list(CORE_OPERATION_IDS)
        ):
            raise CiMatrixError("passing CI result is incomplete")
        for operation in record["operations"]:
            if not isinstance(operation, dict):
                raise CiMatrixError("CI operation result is not an object")
            validate_operation(operation)
            should_skip = (
                release["version"] not in {"2.6.0", "2.6.1"}
                and operation["id"] in CORE_OPERATION_IDS[8:]
            )
            if (operation["status"] == "skipped") != should_skip:
                raise CiMatrixError("CI operation status contradicts the exact profile")
    else:
        allowed_reasons = dict(FAILURE_REASONS)
        if allow_ci_reason:
            allowed_reasons[CI_INFRASTRUCTURE_REASON] = INFRASTRUCTURE_FAILURE_CLASS
        reason = record["failure_reason_code"]
        if (
            record["reported_version"] is not None
            or record["compatibility_status"] != "unverified"
            or record["test_count"] != 0
            or record["operations"] != []
            or reason not in allowed_reasons
            or record["failure_class"] != allowed_reasons[reason]
        ):
            raise CiMatrixError("failed CI result is contradictory")
    validate_safe_strings(record)


def run_report(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": RUN_SCHEMA,
        "generator_version": 1,
        **report_metadata(),
        "result": record,
    }


def validate_run_report(
    report: dict[str, Any], release: dict[str, Any], *, allow_ci_reason: bool = False
) -> None:
    if set(report) != {
        "schema",
        "generator_version",
        "release_inventory_sha256",
        "harness_sha256",
        "test_definition_sha256",
        "result",
    }:
        raise CiMatrixError("CI run report fields are invalid")
    if (
        report["schema"] != RUN_SCHEMA
        or type(report["generator_version"]) is not int
        or report["generator_version"] != 1
        or {key: report[key] for key in report_metadata()} != report_metadata()
        or not isinstance(report["result"], dict)
    ):
        raise CiMatrixError("CI run report metadata is invalid")
    validate_result_record(report["result"], release, allow_ci_reason=allow_ci_reason)


def ensure_new_artifact_root(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except OSError as error:
        raise CiMatrixError("CI artifact directory already exists or is unsafe") from error
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o022 != 0
    ):
        raise CiMatrixError("CI artifact directory is not privately owned")


def ensure_artifact_parent(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise CiMatrixError("CI artifact parent cannot be created safely") from error
    descriptor = open_directory(path)
    os.close(descriptor)


def open_directory(path: Path) -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or non_block is None or directory_flag is None:
        raise CiMatrixError("secure directory access is unavailable")
    flags = os.O_RDONLY | no_follow | non_block | directory_flag | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CiMatrixError("CI directory cannot be opened safely") from error
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o022 != 0
    ):
        os.close(descriptor)
        raise CiMatrixError("CI directory is not a privately owned directory")
    return descriptor


def write_new_regular_file(path: Path, data: bytes) -> None:
    if len(data) > MAX_REPORT_BYTES:
        raise CiMatrixError("CI report exceeds its byte limit")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise CiMatrixError("secure CI report creation is unavailable")
    if path.name in {"", ".", ".."} or "/" in path.name or "\0" in path.name:
        raise CiMatrixError("CI report filename is unsafe")
    parent_descriptor = open_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_descriptor)
    except OSError as error:
        os.close(parent_descriptor)
        raise CiMatrixError("CI report cannot be created safely") from error
    try:
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise CiMatrixError("CI report write made no progress")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)


def release_for_version(document: dict[str, Any], version: str) -> dict[str, Any]:
    matches = [record for record in document["records"] if record["version"] == version]
    if len(matches) != 1:
        raise CiMatrixError("CI version is not an exact release inventory entry")
    return matches[0]


def run_one(version: str) -> int:
    document = inventory()
    release = release_for_version(document, version)
    try:
        record = run_integration(version)
    except (HarnessError, OSError) as error:
        record = failure_record(release, error)
    report = run_report(record)
    validate_run_report(report, release)
    ensure_new_artifact_root(ARTIFACT_ROOT)
    write_new_regular_file(RUN_REPORT_PATH, canonical_json(report))
    if record["outcome"] == "passed":
        print(f"OpenBao CI matrix: locked {version} passed")
        return 0
    print(f"OpenBao CI matrix: locked {version} failed with classified evidence", file=sys.stderr)
    if record["failure_class"] == INFRASTRUCTURE_FAILURE_CLASS:
        return 20
    return 10


def synthetic_infrastructure_record(release: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": release["version"],
        "image_linux_amd64_digest": release["image"]["linux_amd64_digest"],
        "reported_version": None,
        "compatibility_status": "unverified",
        "outcome": "failed",
        "test_count": 0,
        "operations": [],
        "failure_class": INFRASTRUCTURE_FAILURE_CLASS,
        "failure_reason_code": CI_INFRASTRUCTURE_REASON,
    }


def downloaded_directory_entries(descriptor: int) -> set[str]:
    entries: set[str] = set()
    try:
        with os.scandir(descriptor) as iterator:
            for entry in iterator:
                if len(entries) >= MAX_ARTIFACT_DIRECTORIES:
                    raise CiMatrixError("downloaded artifact count exceeds its limit")
                metadata = entry.stat(follow_symlinks=False)
                if entry.name in entries or not stat.S_ISDIR(metadata.st_mode):
                    raise CiMatrixError("downloaded artifact directory is unsafe")
                entries.add(entry.name)
    except OSError as error:
        raise CiMatrixError("downloaded artifact directory cannot be inspected") from error
    return entries


def read_descriptor(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > maximum:
        raise CiMatrixError("CI artifact report exceeds its byte limit")
    return data


def read_run_report(
    root_descriptor: int, directory: str, release: dict[str, Any]
) -> dict[str, Any]:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    non_block = getattr(os, "O_NONBLOCK", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or non_block is None or directory_flag is None:
        raise CiMatrixError("secure artifact reads are unavailable")
    directory_flags = (
        os.O_RDONLY
        | no_follow
        | non_block
        | directory_flag
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        directory_descriptor = os.open(directory, directory_flags, dir_fd=root_descriptor)
    except OSError as error:
        raise CiMatrixError("CI artifact directory is missing") from error
    try:
        metadata = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o022 != 0
        ):
            raise CiMatrixError("CI artifact directory is not privately owned")
        entries: list[str] = []
        with os.scandir(directory_descriptor) as iterator:
            for entry in iterator:
                if len(entries) >= 2:
                    raise CiMatrixError("CI artifact contains too many entries")
                entry_metadata = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(entry_metadata.st_mode):
                    raise CiMatrixError("CI artifact contains an unsafe entry")
                entries.append(entry.name)
        if entries != ["openbao-result.json"]:
            raise CiMatrixError("CI artifact does not contain exactly one result")
        file_flags = os.O_RDONLY | no_follow | non_block | getattr(os, "O_CLOEXEC", 0)
        try:
            file_descriptor = os.open(
                "openbao-result.json", file_flags, dir_fd=directory_descriptor
            )
        except OSError as error:
            raise CiMatrixError("CI artifact report cannot be opened safely") from error
        try:
            file_metadata = os.fstat(file_descriptor)
            if (
                not stat.S_ISREG(file_metadata.st_mode)
                or file_metadata.st_nlink != 1
                or file_metadata.st_uid != os.getuid()
                or file_metadata.st_mode & 0o022 != 0
                or file_metadata.st_size > MAX_REPORT_BYTES
            ):
                raise CiMatrixError("CI artifact report is not a bounded regular file")
            data = read_descriptor(file_descriptor, MAX_REPORT_BYTES)
        finally:
            os.close(file_descriptor)
    finally:
        os.close(directory_descriptor)
    try:
        report = parse_json(data, MAX_REPORT_BYTES)
    except SnapshotError as error:
        raise CiMatrixError("downloaded CI result is malformed") from error
    validate_run_report(report, release)
    return report


def aggregate(
    profile: str,
    matrix_job_result: str,
    download_result: str,
    *,
    download_root: Path = DOWNLOAD_ROOT,
    output_path: Path = AGGREGATE_REPORT_PATH,
) -> int:
    if matrix_job_result not in JOB_RESULTS or download_result not in DOWNLOAD_RESULTS:
        raise CiMatrixError("GitHub job outcome is invalid")
    ensure_artifact_parent(output_path.parent)
    document = inventory()
    versions = profile_versions(profile, document)
    expected_directories = {f"openbao-core-{version}" for version in versions}
    root_descriptor: int | None = None
    try:
        root_descriptor = open_directory(download_root)
        actual_directories = downloaded_directory_entries(root_descriptor)
        artifact_set_valid = actual_directories == expected_directories
    except CiMatrixError:
        actual_directories = set()
        artifact_set_valid = False

    records: list[dict[str, Any]] = []
    received = 0
    for version in versions:
        release = release_for_version(document, version)
        directory = f"openbao-core-{version}"
        try:
            if directory not in actual_directories or root_descriptor is None:
                raise CiMatrixError("expected CI artifact is missing")
            report = read_run_report(root_descriptor, directory, release)
            record = report["result"]
            received += 1
        except (CiMatrixError, OSError):
            artifact_set_valid = False
            record = synthetic_infrastructure_record(release)
        records.append(record)
    if root_descriptor is not None:
        os.close(root_descriptor)

    compatibility_failed = sum(
        record["outcome"] == "failed"
        and record["failure_class"] in COMPATIBILITY_FAILURE_CLASSES
        for record in records
    )
    infrastructure_failed = sum(
        record["outcome"] == "failed"
        and record["failure_class"] == INFRASTRUCTURE_FAILURE_CLASS
        for record in records
    )
    passed = sum(record["outcome"] == "passed" for record in records)
    has_infrastructure_failure = (
        infrastructure_failed > 0
        or not artifact_set_valid
        or download_result != "success"
    )
    expected_job_result = "success" if passed == len(records) else "failure"
    if matrix_job_result != expected_job_result:
        has_infrastructure_failure = True

    if has_infrastructure_failure:
        outcome = "infrastructure-failed"
        exit_code = 20
    elif compatibility_failed:
        outcome = "compatibility-failed"
        exit_code = 10
    else:
        outcome = "passed"
        exit_code = 0

    report = {
        "schema": AGGREGATE_SCHEMA,
        "generator_version": 1,
        **report_metadata(),
        "profile": profile,
        "expected_versions": versions,
        "matrix_job_result": matrix_job_result,
        "download_result": download_result,
        "artifact_set_valid": artifact_set_valid,
        "outcome": outcome,
        "summary": {
            "expected": len(versions),
            "received": received,
            "passed": passed,
            "compatibility_failed": compatibility_failed,
            "infrastructure_failed": infrastructure_failed,
        },
        "records": records,
    }
    validate_aggregate_report(report, document)
    write_new_regular_file(output_path, canonical_json(report))
    print(f"OpenBao CI matrix: aggregate outcome {outcome}")
    return exit_code


def validate_aggregate_report(report: dict[str, Any], document: dict[str, Any]) -> None:
    if set(report) != {
        "schema",
        "generator_version",
        "release_inventory_sha256",
        "harness_sha256",
        "test_definition_sha256",
        "profile",
        "expected_versions",
        "matrix_job_result",
        "download_result",
        "artifact_set_valid",
        "outcome",
        "summary",
        "records",
    }:
        raise CiMatrixError("aggregate CI report fields are invalid")
    versions = profile_versions(report["profile"], document)
    if (
        report["schema"] != AGGREGATE_SCHEMA
        or type(report["generator_version"]) is not int
        or report["generator_version"] != 1
        or {key: report[key] for key in report_metadata()} != report_metadata()
        or report["expected_versions"] != versions
        or report["matrix_job_result"] not in JOB_RESULTS
        or report["download_result"] not in DOWNLOAD_RESULTS
        or not isinstance(report["artifact_set_valid"], bool)
        or report["outcome"]
        not in {"passed", "compatibility-failed", "infrastructure-failed"}
        or not isinstance(report["records"], list)
        or len(report["records"]) != len(versions)
    ):
        raise CiMatrixError("aggregate CI report metadata is invalid")
    passed = compatibility_failed = infrastructure_failed = 0
    received = 0
    for version, record in zip(versions, report["records"], strict=True):
        release = release_for_version(document, version)
        validate_result_record(record, release, allow_ci_reason=True)
        if record["failure_reason_code"] != CI_INFRASTRUCTURE_REASON:
            received += 1
        if record["outcome"] == "passed":
            passed += 1
        elif record["failure_class"] == INFRASTRUCTURE_FAILURE_CLASS:
            infrastructure_failed += 1
        else:
            compatibility_failed += 1
    expected_summary = {
        "expected": len(versions),
        "received": received,
        "passed": passed,
        "compatibility_failed": compatibility_failed,
        "infrastructure_failed": infrastructure_failed,
    }
    if (
        report["summary"] != expected_summary
        or not isinstance(report["summary"], dict)
        or any(type(value) is not int for value in report["summary"].values())
    ):
        raise CiMatrixError("aggregate CI report summary is inconsistent")
    has_infrastructure_failure = (
        infrastructure_failed > 0
        or not report["artifact_set_valid"]
        or report["download_result"] != "success"
    )
    expected_job_result = "success" if passed == len(versions) else "failure"
    if report["matrix_job_result"] != expected_job_result:
        has_infrastructure_failure = True
    if has_infrastructure_failure:
        expected_outcome = "infrastructure-failed"
    elif compatibility_failed:
        expected_outcome = "compatibility-failed"
    else:
        expected_outcome = "passed"
    if report["outcome"] != expected_outcome:
        raise CiMatrixError("aggregate CI report outcome is contradictory")
    validate_safe_strings(report)


def validate_workflow() -> None:
    try:
        data = read_regular_file(WORKFLOW_PATH, MAX_WORKFLOW_BYTES)
    except (OSError, SnapshotError) as error:
        raise CiMatrixError("compatibility workflow is missing or unsafe") from error
    if sha256(data) != EXPECTED_WORKFLOW_SHA256:
        raise CiMatrixError("compatibility workflow does not match its reviewed hash")
    forbidden = (
        b"pull_request_target",
        b"secrets.",
        b"actions/cache",
        b"Swatinem/rust-cache",
    )
    if any(value in data for value in forbidden):
        raise CiMatrixError("compatibility workflow contains a forbidden security pattern")
    required = (
        b"permissions:\n  contents: read",
        b"persist-credentials: false",
        b"python3 -B scripts/openbao_ci_matrix.py plan",
        b"python3 -B scripts/openbao_ci_matrix.py run",
        b"python3 -B scripts/openbao_ci_matrix.py aggregate",
        b"retention-days: 14",
        b"id: download\n        continue-on-error: true",
    )
    if any(value not in data for value in required):
        raise CiMatrixError("compatibility workflow is missing a security invariant")
    if data.count(b"continue-on-error: true") != 1:
        raise CiMatrixError("only artifact download may continue after failure")


def expect_rejected(label: str, operation: Any) -> None:
    try:
        operation()
    except (CiMatrixError, OSError):
        return
    raise CiMatrixError(f"CI matrix self-test accepted {label}")


def self_test() -> None:
    document = inventory()
    expected_representatives = [
        "2.0.0",
        "2.0.3",
        "2.1.1",
        "2.2.2",
        "2.3.2",
        "2.4.4",
        "2.5.5",
        "2.6.1",
    ]
    if profile_versions("representative", document) != expected_representatives:
        raise CiMatrixError("representative CI profile is not the reviewed release set")
    if len(profile_versions("all", document)) != 23:
        raise CiMatrixError("all-release CI profile is incomplete")
    for version in ("", "2.5", "v2.5.5", "2.05.5", "2.5.5;echo"):
        expect_rejected(
            "an unsafe or unknown matrix version",
            lambda version=version: release_for_version(document, version),
        )
    for event in ("pull_request_target", "issue", "repository_dispatch", "push;echo"):
        expect_rejected(event, lambda event=event: profile_for_event(event))

    with tempfile.TemporaryDirectory(prefix="openbao-ci-matrix-self-test-") as directory:
        root = Path(directory)
        output = root / "github-output"
        output.write_bytes(b"")
        append_github_output(output, b"matrix={}\n")
        if output.read_bytes() != b"matrix={}\n":
            raise CiMatrixError("GitHub output self-test did not append exact bytes")
        symlink = root / "github-output-link"
        symlink.symlink_to(output)
        expect_rejected("symbolic-link GitHub output", lambda: append_github_output(symlink, b"x=1\n"))
        fifo = root / "github-output-fifo"
        os.mkfifo(fifo)
        expect_rejected("FIFO GitHub output", lambda: append_github_output(fifo, b"x=1\n"))

        release = document["records"][0]
        record = synthetic_infrastructure_record(release)
        report = run_report(record)
        validate_run_report(report, release, allow_ci_reason=True)
        zero_test = copy.deepcopy(report)
        zero_test["result"]["outcome"] = "passed"
        zero_test["result"]["reported_version"] = release["version"]
        zero_test["result"]["compatibility_status"] = "tested-subset"
        zero_test["result"]["failure_class"] = None
        zero_test["result"]["failure_reason_code"] = None
        expect_rejected("zero-test passing report", lambda: validate_run_report(zero_test, release))
        boolean_test_count = copy.deepcopy(report)
        boolean_test_count["result"]["test_count"] = True
        expect_rejected(
            "boolean test count",
            lambda: validate_run_report(boolean_test_count, release, allow_ci_reason=True),
        )
        leaked = copy.deepcopy(report)
        leaked["result"]["failure_reason_code"] = "line one\nline two"
        expect_rejected("control characters in a report", lambda: validate_run_report(leaked, release, allow_ci_reason=True))

        download = root / "downloaded"
        download.mkdir()
        aggregate_output = root / "aggregate.json"
        code = aggregate(
            "representative",
            "failure",
            "failure",
            download_root=download,
            output_path=aggregate_output,
        )
        if code != 20:
            raise CiMatrixError("missing artifacts were not classified as infrastructure failure")
        parsed = parse_json(aggregate_output.read_bytes(), MAX_REPORT_BYTES)
        if parsed.get("outcome") != "infrastructure-failed":
            raise CiMatrixError("aggregate self-test produced a false-green report")

        successful_download = root / "successful-download"
        successful_download.mkdir()
        for version in expected_representatives:
            release = release_for_version(document, version)
            passed_record = {
                "version": version,
                "image_linux_amd64_digest": release["image"]["linux_amd64_digest"],
                "reported_version": version,
                "compatibility_status": "tested-subset",
                "outcome": "passed",
                "test_count": 1,
                "operations": [
                    {
                        "id": operation,
                        "status": (
                            "skipped"
                            if version not in {"2.6.0", "2.6.1"}
                            and operation in CORE_OPERATION_IDS[8:]
                            else "passed"
                        ),
                        "reason_code": (
                            "server-operation-unavailable"
                            if version not in {"2.6.0", "2.6.1"}
                            and operation in CORE_OPERATION_IDS[8:]
                            else None
                        ),
                        "classification": (
                            "expected-server-difference"
                            if version not in {"2.6.0", "2.6.1"}
                            and operation in CORE_OPERATION_IDS[8:]
                            else None
                        ),
                    }
                    for operation in CORE_OPERATION_IDS
                ],
                "failure_class": None,
                "failure_reason_code": None,
            }
            artifact = successful_download / f"openbao-core-{version}"
            artifact.mkdir()
            (artifact / "openbao-result.json").write_bytes(
                canonical_json(run_report(passed_record))
            )
        success_output = root / "successful-aggregate.json"
        if (
            aggregate(
                "representative",
                "success",
                "success",
                download_root=successful_download,
                output_path=success_output,
            )
            != 0
        ):
            raise CiMatrixError("complete passing artifacts did not produce success")
        success_report = parse_json(success_output.read_bytes(), MAX_REPORT_BYTES)
        if success_report.get("outcome") != "passed":
            raise CiMatrixError("passing aggregate self-test produced a false failure")
        contradictory = copy.deepcopy(success_report)
        contradictory["outcome"] = "compatibility-failed"
        expect_rejected(
            "contradictory aggregate outcome",
            lambda: validate_aggregate_report(contradictory, document),
        )

        contradiction_output = root / "job-contradiction.json"
        if (
            aggregate(
                "representative",
                "failure",
                "success",
                download_root=successful_download,
                output_path=contradiction_output,
            )
            != 20
        ):
            raise CiMatrixError("job/report contradiction did not fail as infrastructure")

        compatibility_download = root / "compatibility-download"
        compatibility_download.mkdir()
        for entry in successful_download.iterdir():
            copied = compatibility_download / entry.name
            copied.mkdir()
            source = parse_json(
                (entry / "openbao-result.json").read_bytes(), MAX_REPORT_BYTES
            )
            if entry.name == "openbao-core-2.0.0":
                source["result"] = failure_record(
                    release_for_version(document, "2.0.0"),
                    IntegrationTestFailure("classified test failure"),
                )
            (copied / "openbao-result.json").write_bytes(canonical_json(source))
        compatibility_output = root / "compatibility-aggregate.json"
        if (
            aggregate(
                "representative",
                "failure",
                "success",
                download_root=compatibility_download,
                output_path=compatibility_output,
            )
            != 10
        ):
            raise CiMatrixError("core-flow failure was not classified as compatibility failure")

        unexpected = successful_download / "unexpected-artifact"
        unexpected.mkdir()
        extra_output = root / "extra-aggregate.json"
        if (
            aggregate(
                "representative",
                "success",
                "success",
                download_root=successful_download,
                output_path=extra_output,
            )
            != 20
        ):
            raise CiMatrixError("unexpected artifact did not fail as infrastructure")
    validate_workflow()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    plan = subcommands.add_parser("plan")
    plan.add_argument("--event", required=True)
    plan.add_argument("--github-output", type=Path, required=True)
    run = subcommands.add_parser("run")
    run.add_argument("--version", required=True)
    aggregate_parser = subcommands.add_parser("aggregate")
    aggregate_parser.add_argument("--profile", required=True)
    aggregate_parser.add_argument("--matrix-job-result", required=True)
    aggregate_parser.add_argument("--download-result", required=True)
    subcommands.add_parser("self-test")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.command == "plan":
            write_plan(arguments.event, arguments.github_output)
            return 0
        if arguments.command == "run":
            return run_one(arguments.version)
        if arguments.command == "aggregate":
            return aggregate(
                arguments.profile,
                arguments.matrix_job_result,
                arguments.download_result,
            )
        self_test()
        print("OpenBao CI matrix self-tests: ok")
        return 0
    except (CiMatrixError, HarnessError, SnapshotError, OSError) as error:
        print(f"OpenBao CI matrix failed: {error}", file=sys.stderr)
        return 20


if __name__ == "__main__":
    raise SystemExit(main())
