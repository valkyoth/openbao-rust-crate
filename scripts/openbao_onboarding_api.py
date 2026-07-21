#!/usr/bin/env python3
"""Generate and verify preserved OpenBao 2.6.0 onboarding API evidence."""

from __future__ import annotations

import argparse
import copy
import subprocess
import sys
from pathlib import Path
from typing import Any

import openbao_api_snapshots as snapshots
import validate_openbao_release_lock as releases

ROOT = Path(__file__).resolve().parents[1]
ONBOARDING_ROOT = ROOT / "compat" / "onboarding" / "2.6.0"
LOCK_PATH = ONBOARDING_ROOT / "api-evidence.lock.json"
CHECKSUM_PATH = ONBOARDING_ROOT / "api-evidence.lock.sha256"
OBSERVED_ON = "2026-07-17"
VERSION = "2.6.0"
PREDECESSOR = "2.5.5"
SOURCE_COMMIT = "03e3a243b6f07d17c60ce0a182adee7cf4c424eb"
RENDERED_LINE = "2.6.x-current"
RENDERED_ROOTS = ("/api-docs/auth/", "/api-docs/secret/", "/api-docs/system/")
EXPECTED_LOCK_SHA256 = "4f1a16777ef9c74bd6e5e131c9fa501121ea0d18e01ee490aed44d36dd7f0f6e"
EXPECTED_ACTIVE_SNAPSHOT_LOCK_SHA256 = (
    "440fbaef87506b3b463689892abb9c0c741e2382676e3c92c4e21fa8cd2a3af6"
)
MAX_REVIEWED_DISCREPANCIES = 32

ARTIFACT_PATHS = {
    "predecessor_openapi_v2": "compat/onboarding/2.6.0/predecessor-2.5.5-openapi-v2.json",
    "documentation": "compat/onboarding/2.6.0/documentation.json",
    "openapi": "compat/onboarding/2.6.0/openapi.json",
    "diff_from_2_5_5": "compat/onboarding/2.6.0/2.5.5--2.6.0.json",
    "rendered_cross_check": "compat/onboarding/2.6.0/rendered-api-cross-check.json",
    "reviewed_discrepancies": "compat/onboarding/2.6.0/reviewed-discrepancies.json",
}


class OnboardingError(ValueError):
    """Staged API evidence could not be generated or verified safely."""


def load_release_evidence() -> tuple[dict[str, Any], bytes]:
    try:
        releases.validate_lock_files()
    except releases.LockValidationError as error:
        raise OnboardingError("release evidence validation failed") from error
    data = snapshots.read_regular_file(releases.ONBOARDING_LOCK_PATH, snapshots.MAX_LOCK_BYTES)
    if snapshots.sha256(data) != releases.EXPECTED_ONBOARDING_LOCK_SHA256:
        raise OnboardingError("onboarding release evidence identity changed")
    document = snapshots.parse_json(data, snapshots.MAX_LOCK_BYTES)
    try:
        releases.validate_onboarding_document(document)
    except releases.LockValidationError as error:
        raise OnboardingError("onboarding release evidence shape changed") from error
    return document, data


def active_predecessor() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bytes, bytes]:
    active = snapshots.verify()
    records = active["records"]
    if not isinstance(records, list):
        raise OnboardingError("active API evidence records changed")
    matches = [record for record in records if record.get("version") == PREDECESSOR]
    if len(matches) != 1:
        raise OnboardingError("active API evidence predecessor changed")
    record = matches[0]
    documentation_data = snapshots.read_regular_file(
        snapshots.require_repo_path(record["documentation"]["path"]),
        snapshots.MAX_SNAPSHOT_BYTES,
    )
    openapi_data = snapshots.read_regular_file(
        snapshots.require_repo_path(record["openapi"]["path"]),
        snapshots.MAX_OPENAPI_BYTES,
    )
    if (
        snapshots.sha256(documentation_data) != record["documentation"]["sha256"]
        or snapshots.sha256(openapi_data) != record["openapi"]["sha256"]
    ):
        raise OnboardingError("active predecessor artifact identity changed")
    return (
        record,
        snapshots.parse_json(documentation_data, snapshots.MAX_SNAPSHOT_BYTES),
        snapshots.parse_json(openapi_data, snapshots.MAX_OPENAPI_BYTES),
        documentation_data,
        openapi_data,
    )


def active_predecessor_release() -> dict[str, Any]:
    records = snapshots.release_records()
    matches = [record for record in records if record.get("version") == PREDECESSOR]
    if len(matches) != 1:
        raise OnboardingError("active release predecessor changed")
    return matches[0]


def reviewed_discrepancies() -> dict[str, Any]:
    return {
        "schema": "openbao-reviewed-api-discrepancies/v1",
        "version": VERSION,
        "source_commit_sha1": SOURCE_COMMIT,
        "items": [
            {
                "id": "jwt-cel-role-path-pluralization",
                "area": "jwt-cel",
                "classification": "tagged-docs-vs-runtime-route",
                "tagged_documentation": "website/content/api-docs/auth/jwt.mdx:636-824",
                "runtime_source": "builtin/credential/jwt/path_cel_role.go:39,117",
                "reviewed_finding": "Tagged docs use /auth/jwt/cel/roles while the registered storage routes use cel/role.",
            },
            {
                "id": "jwt-kubernetes-provider-discovery-conflict",
                "area": "jwt-kubernetes-provider",
                "classification": "guide-vs-runtime-validation",
                "tagged_documentation": "website/content/api-docs/auth/jwt.mdx:20-46",
                "runtime_source": "builtin/credential/jwt/provider_kubernetes.go:38-45",
                "reviewed_finding": "The generic JWT config docs present oidc_discovery_url with provider_config, but the Kubernetes provider rejects OIDC discovery settings.",
            },
            {
                "id": "workflow-unauthenticated-route-conditional",
                "area": "workflows",
                "classification": "configuration-dependent-runtime-route",
                "tagged_documentation": "website/content/api-docs/system/workflows.mdx",
                "runtime_source": "vault/workflow_store.go:308-326; vault/core.go:955",
                "reviewed_finding": "Unauthenticated workflow execution is configuration-dependent and is not represented by the default runtime OpenAPI capture.",
            },
            {
                "id": "list-scan-openapi-method-collapse",
                "area": "method-reporting",
                "classification": "nonstandard-method-openapi-loss",
                "tagged_documentation": "website/content/api-docs/system/namespaces.mdx:9-23",
                "runtime_source": "vault/logical_system_namespaces.go:268-317,571-580",
                "reviewed_finding": "LIST and SCAN share logical routes, while OpenAPI only has standard HTTP operation keys and cannot preserve both method identities directly.",
            },
        ],
    }


def artifact_record(path_text: str, data: bytes, **metadata: int) -> dict[str, Any]:
    return {"path": path_text, "sha256": snapshots.sha256(data), "bytes": len(data), **metadata}


def load_or_capture_rendered() -> tuple[dict[str, Any], bytes]:
    path = ROOT / ARTIFACT_PATHS["rendered_cross_check"]
    if path.exists() or path.is_symlink():
        data = snapshots.read_regular_file(path, snapshots.MAX_SNAPSHOT_BYTES)
        document = snapshots.parse_json(data, snapshots.MAX_SNAPSHOT_BYTES)
        snapshots.validate_rendered_snapshot(
            document,
            data,
            RENDERED_LINE,
            observed_on=OBSERVED_ON,
        )
        return document, data
    document = snapshots.capture_rendered_cross_check(
        RENDERED_LINE,
        RENDERED_ROOTS,
        observed_on=OBSERVED_ON,
    )
    data = snapshots.canonical_json(document)
    snapshots.write_immutable(path, data)
    return document, data


def generate(source_repository: str) -> None:
    repository = snapshots.validate_source_repository(source_repository)
    release, release_data = load_release_evidence()
    predecessor, predecessor_docs, predecessor_openapi, predecessor_docs_data, predecessor_openapi_data = (
        active_predecessor()
    )
    predecessor_release = active_predecessor_release()
    if release["version"] != VERSION or release["source"]["peeled_commit_sha1"] != SOURCE_COMMIT:
        raise OnboardingError("onboarding release identity changed")

    documentation = snapshots.extract_documentation(repository, release)
    documentation_data = snapshots.canonical_json(documentation)
    openapi = snapshots.capture_openapi(release)
    openapi_data = snapshots.canonical_json(openapi)
    predecessor_openapi_v2 = snapshots.capture_openapi(predecessor_release)
    predecessor_openapi_v2_data = snapshots.canonical_json(predecessor_openapi_v2)
    snapshots.write_immutable(
        ROOT / ARTIFACT_PATHS["predecessor_openapi_v2"],
        predecessor_openapi_v2_data,
    )
    snapshots.write_immutable(ROOT / ARTIFACT_PATHS["documentation"], documentation_data)
    snapshots.write_immutable(ROOT / ARTIFACT_PATHS["openapi"], openapi_data)

    diff = snapshots.build_diff(
        PREDECESSOR,
        predecessor_docs,
        predecessor_openapi_v2,
        VERSION,
        documentation,
        openapi,
        {
            "documentation": snapshots.sha256(predecessor_docs_data),
            "openapi": snapshots.sha256(predecessor_openapi_v2_data),
        },
        {
            "documentation": snapshots.sha256(documentation_data),
            "openapi": snapshots.sha256(openapi_data),
        },
    )
    diff_data = snapshots.canonical_json(diff)
    snapshots.write_immutable(ROOT / ARTIFACT_PATHS["diff_from_2_5_5"], diff_data)

    rendered, rendered_data = load_or_capture_rendered()
    discrepancies = reviewed_discrepancies()
    discrepancies_data = snapshots.canonical_json(discrepancies)
    snapshots.write_immutable(ROOT / ARTIFACT_PATHS["reviewed_discrepancies"], discrepancies_data)

    tagged_operations = set(snapshots.operation_index(documentation))
    rendered_operations = {
        f"{operation['method']} {operation['path']}" for operation in rendered["operations"]
    }
    lock = {
        "schema": "openbao-onboarding-api-evidence-lock/v1",
        "generator_version": snapshots.GENERATOR_VERSION,
        "observed_on": OBSERVED_ON,
        "version": VERSION,
        "release_evidence": {
            "path": "compat/onboarding/2.6.0/release-evidence.json",
            "sha256": snapshots.sha256(release_data),
        },
        "active_snapshot_lock_sha256": snapshots.EXPECTED_SNAPSHOT_LOCK_SHA256,
        "predecessor": {
            "version": PREDECESSOR,
            "active_documentation_sha256": predecessor["documentation"]["sha256"],
            "active_openapi_v1_sha256": predecessor["openapi"]["sha256"],
        },
        "artifacts": {
            "predecessor_openapi_v2": artifact_record(
                ARTIFACT_PATHS["predecessor_openapi_v2"],
                predecessor_openapi_v2_data,
                path_count=predecessor_openapi_v2["path_count"],
                operation_count=predecessor_openapi_v2["operation_count"],
                schema_count=predecessor_openapi_v2["schema_count"],
            ),
            "documentation": artifact_record(
                ARTIFACT_PATHS["documentation"],
                documentation_data,
                file_count=len(documentation["files"]),
                operation_count=len(documentation["operations"]),
            ),
            "openapi": artifact_record(
                ARTIFACT_PATHS["openapi"],
                openapi_data,
                path_count=openapi["path_count"],
                operation_count=openapi["operation_count"],
                schema_count=openapi["schema_count"],
            ),
            "diff_from_2_5_5": artifact_record(
                ARTIFACT_PATHS["diff_from_2_5_5"], diff_data, change_count=diff["change_count"]
            ),
            "rendered_cross_check": artifact_record(
                ARTIFACT_PATHS["rendered_cross_check"],
                rendered_data,
                page_count=len(rendered["pages"]),
                operation_count=len(rendered["operations"]),
                tagged_only_operation_count=len(tagged_operations - rendered_operations),
                rendered_only_operation_count=len(rendered_operations - tagged_operations),
            ),
            "reviewed_discrepancies": artifact_record(
                ARTIFACT_PATHS["reviewed_discrepancies"],
                discrepancies_data,
                item_count=len(discrepancies["items"]),
            ),
        },
    }
    lock_data = snapshots.canonical_json(lock)
    snapshots.write_immutable(LOCK_PATH, lock_data)
    snapshots.write_immutable(
        CHECKSUM_PATH,
        f"{snapshots.sha256(lock_data)}  api-evidence.lock.json\n".encode(),
    )
    print("generated OpenBao 2.6.0 onboarding API evidence")


def require_artifact_record(
    value: Any, name: str, metadata: set[str]
) -> dict[str, Any]:
    record = snapshots.require_keys(value, {"path", "sha256", "bytes", *metadata}, name)
    if record["path"] != ARTIFACT_PATHS[name]:
        raise OnboardingError(f"{name} path changed")
    snapshots.require_hash(record["sha256"], f"{name} digest")
    snapshots.require_nonnegative_int(record["bytes"], f"{name} size")
    for key in metadata:
        snapshots.require_nonnegative_int(record[key], f"{name} {key}")
    return record


def verify_artifact(record: dict[str, Any], maximum: int) -> tuple[dict[str, Any], bytes]:
    data = snapshots.read_regular_file(
        snapshots.require_repo_path(record["path"]), maximum
    )
    if len(data) != record["bytes"] or snapshots.sha256(data) != record["sha256"]:
        raise OnboardingError("onboarding artifact size or digest changed")
    return snapshots.parse_json(data, maximum), data


def validate_lock_document(lock: dict[str, Any], lock_data: bytes) -> None:
    snapshots.require_keys(
        lock,
        {
            "schema",
            "generator_version",
            "observed_on",
            "version",
            "release_evidence",
            "active_snapshot_lock_sha256",
            "predecessor",
            "artifacts",
        },
        "onboarding API evidence lock",
    )
    if (
        lock["schema"] != "openbao-onboarding-api-evidence-lock/v1"
        or lock["generator_version"] != snapshots.GENERATOR_VERSION
        or lock["observed_on"] != OBSERVED_ON
        or lock["version"] != VERSION
        or lock["active_snapshot_lock_sha256"] != EXPECTED_ACTIVE_SNAPSHOT_LOCK_SHA256
        or snapshots.canonical_json(lock) != lock_data
    ):
        raise OnboardingError("onboarding API evidence lock metadata changed")
    release = snapshots.require_keys(lock["release_evidence"], {"path", "sha256"}, "release evidence")
    if (
        release["path"] != "compat/onboarding/2.6.0/release-evidence.json"
        or release["sha256"] != releases.EXPECTED_ONBOARDING_LOCK_SHA256
    ):
        raise OnboardingError("onboarding release evidence binding changed")
    predecessor = snapshots.require_keys(
        lock["predecessor"],
        {"version", "active_documentation_sha256", "active_openapi_v1_sha256"},
        "onboarding predecessor",
    )
    if predecessor["version"] != PREDECESSOR:
        raise OnboardingError("onboarding predecessor version changed")
    snapshots.require_hash(
        predecessor["active_documentation_sha256"], "active predecessor documentation"
    )
    snapshots.require_hash(
        predecessor["active_openapi_v1_sha256"], "active predecessor OpenAPI"
    )
    artifacts = snapshots.require_keys(lock["artifacts"], set(ARTIFACT_PATHS), "onboarding artifacts")
    require_artifact_record(
        artifacts["predecessor_openapi_v2"],
        "predecessor_openapi_v2",
        {"path_count", "operation_count", "schema_count"},
    )
    require_artifact_record(artifacts["documentation"], "documentation", {"file_count", "operation_count"})
    require_artifact_record(
        artifacts["openapi"], "openapi", {"path_count", "operation_count", "schema_count"}
    )
    require_artifact_record(artifacts["diff_from_2_5_5"], "diff_from_2_5_5", {"change_count"})
    require_artifact_record(
        artifacts["rendered_cross_check"],
        "rendered_cross_check",
        {
            "page_count",
            "operation_count",
            "tagged_only_operation_count",
            "rendered_only_operation_count",
        },
    )
    require_artifact_record(
        artifacts["reviewed_discrepancies"], "reviewed_discrepancies", {"item_count"}
    )


def validate_discrepancies(document: dict[str, Any], data: bytes) -> None:
    expected = reviewed_discrepancies()
    if document != expected or snapshots.canonical_json(document) != data:
        raise OnboardingError("reviewed API discrepancies changed")
    items = document["items"]
    if not isinstance(items, list) or not items or len(items) > MAX_REVIEWED_DISCREPANCIES:
        raise OnboardingError("reviewed API discrepancy count is outside its bound")


def verify() -> dict[str, Any]:
    release, release_data = load_release_evidence()
    predecessor, _, _, _, _ = active_predecessor()
    lock_data = snapshots.read_regular_file(LOCK_PATH, snapshots.MAX_LOCK_BYTES)
    if snapshots.sha256(lock_data) != EXPECTED_LOCK_SHA256:
        raise OnboardingError("onboarding API evidence lock does not match its validator anchor")
    checksum = snapshots.read_regular_file(CHECKSUM_PATH, 256)
    if checksum != f"{EXPECTED_LOCK_SHA256}  api-evidence.lock.json\n".encode():
        raise OnboardingError("onboarding API evidence checksum sidecar changed")
    lock = snapshots.parse_json(lock_data, snapshots.MAX_LOCK_BYTES)
    validate_lock_document(lock, lock_data)
    if lock["release_evidence"]["sha256"] != snapshots.sha256(release_data):
        raise OnboardingError("onboarding release evidence content changed")
    if (
        lock["predecessor"]["active_documentation_sha256"]
        != predecessor["documentation"]["sha256"]
        or lock["predecessor"]["active_openapi_v1_sha256"]
        != predecessor["openapi"]["sha256"]
    ):
        raise OnboardingError("active predecessor binding changed")

    artifacts = lock["artifacts"]
    predecessor_openapi_v2, predecessor_openapi_v2_data = verify_artifact(
        artifacts["predecessor_openapi_v2"], snapshots.MAX_OPENAPI_BYTES
    )
    documentation, documentation_data = verify_artifact(
        artifacts["documentation"], snapshots.MAX_SNAPSHOT_BYTES
    )
    openapi, openapi_data = verify_artifact(artifacts["openapi"], snapshots.MAX_OPENAPI_BYTES)
    diff, diff_data = verify_artifact(artifacts["diff_from_2_5_5"], snapshots.MAX_SNAPSHOT_BYTES)
    rendered, rendered_data = verify_artifact(
        artifacts["rendered_cross_check"], snapshots.MAX_SNAPSHOT_BYTES
    )
    discrepancies, discrepancies_data = verify_artifact(
        artifacts["reviewed_discrepancies"], snapshots.MAX_SNAPSHOT_BYTES
    )

    snapshot_record = {
        "version": VERSION,
        "source_commit_sha1": SOURCE_COMMIT,
        "image_index_digest": openapi["image_index_digest"],
        "image_linux_amd64_digest": openapi["image_linux_amd64_digest"],
    }
    snapshots.validate_documentation_snapshot(
        documentation, documentation_data, VERSION, SOURCE_COMMIT
    )
    snapshots.validate_openapi_snapshot(
        openapi,
        openapi_data,
        snapshot_record,
        expected_schema="openbao-normalized-openapi/v2",
    )
    predecessor_release = active_predecessor_release()
    predecessor_snapshot_record = {
        "version": PREDECESSOR,
        "source_commit_sha1": predecessor_release["source"]["peeled_commit_sha1"],
        "image_index_digest": predecessor_release["image"]["index_digest"],
        "image_linux_amd64_digest": predecessor_release["image"]["linux_amd64_digest"],
    }
    snapshots.validate_openapi_snapshot(
        predecessor_openapi_v2,
        predecessor_openapi_v2_data,
        predecessor_snapshot_record,
        expected_schema="openbao-normalized-openapi/v2",
    )
    snapshots.validate_diff_snapshot(diff, diff_data, PREDECESSOR, VERSION)
    snapshots.validate_rendered_snapshot(
        rendered, rendered_data, RENDERED_LINE, observed_on=OBSERVED_ON
    )
    validate_discrepancies(discrepancies, discrepancies_data)

    if (
        documentation["source_commit_sha1"] != release["source"]["peeled_commit_sha1"]
        or openapi["image_index_digest"] != release["image"]["index_digest"]
        or openapi["image_linux_amd64_digest"]
        != release["image"]["linux_amd64_digest"]
    ):
        raise OnboardingError("onboarding API artifacts differ from release evidence")
    if rendered["roots"] != list(RENDERED_ROOTS) or any(
        not any(page["path"].startswith(root) for root in RENDERED_ROOTS)
        for page in rendered["pages"]
    ):
        raise OnboardingError("rendered documentation roots changed")

    if (
        artifacts["documentation"]["file_count"] != len(documentation["files"])
        or artifacts["documentation"]["operation_count"] != len(documentation["operations"])
        or artifacts["openapi"]["path_count"] != openapi["path_count"]
        or artifacts["openapi"]["operation_count"] != openapi["operation_count"]
        or artifacts["openapi"]["schema_count"] != openapi["schema_count"]
        or artifacts["predecessor_openapi_v2"]["path_count"]
        != predecessor_openapi_v2["path_count"]
        or artifacts["predecessor_openapi_v2"]["operation_count"]
        != predecessor_openapi_v2["operation_count"]
        or artifacts["predecessor_openapi_v2"]["schema_count"]
        != predecessor_openapi_v2["schema_count"]
        or artifacts["diff_from_2_5_5"]["change_count"] != diff["change_count"]
        or artifacts["rendered_cross_check"]["page_count"] != len(rendered["pages"])
        or artifacts["rendered_cross_check"]["operation_count"] != len(rendered["operations"])
        or artifacts["reviewed_discrepancies"]["item_count"] != len(discrepancies["items"])
    ):
        raise OnboardingError("onboarding API evidence counts changed")
    if diff["from_snapshot_sha256"] != {
        "documentation": predecessor["documentation"]["sha256"],
        "openapi": artifacts["predecessor_openapi_v2"]["sha256"],
    } or diff["to_snapshot_sha256"] != {
        "documentation": artifacts["documentation"]["sha256"],
        "openapi": artifacts["openapi"]["sha256"],
    }:
        raise OnboardingError("onboarding API diff bindings changed")
    tagged = set(snapshots.operation_index(documentation))
    rendered_operations = {
        f"{operation['method']} {operation['path']}" for operation in rendered["operations"]
    }
    if (
        artifacts["rendered_cross_check"]["tagged_only_operation_count"]
        != len(tagged - rendered_operations)
        or artifacts["rendered_cross_check"]["rendered_only_operation_count"]
        != len(rendered_operations - tagged)
    ):
        raise OnboardingError("rendered documentation comparison counts changed")
    return lock


def expect_rejected(label: str, operation: Any) -> None:
    try:
        operation()
    except (OnboardingError, snapshots.SnapshotError):
        return
    raise OnboardingError(f"onboarding self-test did not reject {label}")


def self_test() -> None:
    lock = verify()
    lock_data = snapshots.canonical_json(lock)
    traversal = copy.deepcopy(lock)
    traversal["artifacts"]["documentation"]["path"] = "../documentation.json"
    expect_rejected(
        "artifact path traversal",
        lambda: validate_lock_document(traversal, snapshots.canonical_json(traversal)),
    )
    predecessor = copy.deepcopy(lock)
    predecessor["predecessor"]["version"] = "2.5.4"
    expect_rejected(
        "predecessor downgrade",
        lambda: validate_lock_document(predecessor, snapshots.canonical_json(predecessor)),
    )
    release = copy.deepcopy(lock)
    release["release_evidence"]["sha256"] = "0" * 64
    expect_rejected(
        "release evidence substitution",
        lambda: validate_lock_document(release, snapshots.canonical_json(release)),
    )
    noncanonical = lock_data.replace(b'"artifacts":', b'"artifacts" :', 1)
    expect_rejected(
        "noncanonical lock",
        lambda: validate_lock_document(snapshots.parse_json(noncanonical, snapshots.MAX_LOCK_BYTES), noncanonical),
    )
    discrepancy = reviewed_discrepancies()
    discrepancy["items"][0]["classification"] = "unreviewed"
    discrepancy_data = snapshots.canonical_json(discrepancy)
    expect_rejected(
        "reviewed discrepancy drift",
        lambda: validate_discrepancies(discrepancy, discrepancy_data),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--generate", action="store_true")
    action.add_argument("--verify", action="store_true")
    action.add_argument("--self-test", action="store_true")
    parser.add_argument("--source-repository")
    arguments = parser.parse_args()
    try:
        if arguments.generate:
            if not arguments.source_repository:
                raise OnboardingError("--generate requires --source-repository")
            generate(arguments.source_repository)
        elif arguments.verify:
            verify()
            print("OpenBao 2.6.0 onboarding API evidence: verified")
        else:
            self_test()
            print("OpenBao 2.6.0 onboarding API evidence self-tests: ok")
        return 0
    except (OSError, OnboardingError, snapshots.SnapshotError, subprocess.SubprocessError) as error:
        print(f"OpenBao onboarding API operation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
