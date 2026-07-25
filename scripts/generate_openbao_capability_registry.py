#!/usr/bin/env python3
"""Generate and verify the exact-release OpenBao capability registry."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from generate_openbao_contract_matrix import (
    DOCUMENTATION_PATH_CORRECTIONS,
    EXPECTED_OUTPUT_SHA256 as CONTRACT_OUTPUT_HASHES,
    verify as verify_contract_matrix,
)
from openbao_api_snapshots import (
    EXPECTED_SNAPSHOT_LOCK_SHA256,
    SnapshotError,
    parse_json,
    read_regular_file,
    verify as verify_api_snapshots,
)
from validate_openbao_release_lock import (
    EXPECTED_LOCK_SHA256,
    LockValidationError,
    validate_lock_files,
)
from openbao_onboarding_api import (
    EXPECTED_LOCK_SHA256 as ONBOARDING_API_LOCK_SHA256,
    OnboardingError,
    verify as verify_onboarding_api,
)

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "docs/openbao-2.5-contract-matrix.json"
REGISTRY_PATH = ROOT / "compat/capability-registry.json"
STAGED_REGISTRY_PATH = ROOT / "compat/onboarding/2.6.0/capability-registry.json"
RUST_PATH = ROOT / "src/generated/openbao_capabilities.rs"
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_OPERATIONS = 2048
MAX_PATH_BYTES = 4096
EXPECTED_OPERATION_COUNT = 691
EXPECTED_STAGED_OPERATION_COUNT = 690
EXPECTED_REGISTRY_SHA256 = "2f2f0e4fc64e31745e94fc072c2a48c0032c5cc1d98d6cc9901c79ac14e55e96"
EXPECTED_STAGED_REGISTRY_SHA256 = "397f94126d3756d51cd779bbbef91aa8f993287f85561d4330a3734902f2a87e"
EXPECTED_RUST_SHA256 = "d5eef1c1ee2f6de055c95332651e8356e779cda818f3b054595162c3290b6d09"
HISTORICAL_VERSIONS = (
    "2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.1.0", "2.1.1", "2.2.0",
    "2.2.1", "2.2.2", "2.3.1", "2.3.2", "2.4.0", "2.4.1", "2.4.3",
    "2.4.4", "2.5.0", "2.5.1", "2.5.2", "2.5.3", "2.5.4", "2.5.5",
)
STAGED_VERSION = "2.6.0"
EXPECTED_VERSIONS = (*HISTORICAL_VERSIONS, STAGED_VERSION, "2.6.1")
EXPECTED_STAGED_VERSIONS = (*HISTORICAL_VERSIONS, STAGED_VERSION)

# These routes are present in the locked OpenAPI documents but are absent from
# the tagged MDX operation extraction because their surrounding documentation
# combines several methods under one heading.
OPENAPI_OPERATION_SUPPLEMENTS = {
    ("GET", "/identity/oidc/.well-known/keys"): (
        "get",
        "/identity/oidc/.well-known/keys",
    ),
    ("POST", "/ssh/issuer/:issuer_ref"): (
        "post",
        "/{ssh_mount_path}/issuer/{issuer_ref}",
    ),
}
METHODS = ("ACME", "DELETE", "GET", "HEAD", "LIST", "PATCH", "POST", "PUT", "SCAN")
MULTI_SEGMENT_PLACEHOLDERS = frozenset({"path", "prefix"})
SINGLE_SEGMENT_PLACEHOLDERS = frozenset(
    {
        "algorithm", "alias-identifier", "bytes", "destination", "hash_algorithm",
        "id", "issuer_name", "issuer_ref", "key_id", "key_ref", "key_type",
        "method_id", "migration_id", "mount_accessor", "name", "role", "role_name",
        "secret-mount-path", "serial", "set_name", "source", "type", "username",
        "version", "version-number",
    }
)
PLACEHOLDER_NAME = re.compile(r":([A-Za-z0-9_-]{1,128})", re.ASCII)
DISPOSITIONS = {
    "typed": "typed",
    "typed-gated": "typed-gated",
}
HISTORICAL_SECURITY_BLOCKED = frozenset()
HISTORICAL_DISPOSITIONS = {
    ("GET", "/sys/internal/ui/feature-flags"): "typed-gated",
}

# Candidate-only operations stay out of the public generated operation table
# until their typed implementation commit lands. Root-token generation is the
# exception: Commit 03 adds its reviewed route variants for the existing
# operator ceremony API, so those four operations are already typed-gated.
STAGED_DISPOSITIONS = {
    ("DELETE", "/auth/jwt/cel/role/:name"): "typed",
    ("GET", "/auth/jwt/cel/role/:name"): "typed",
    ("LIST", "/auth/jwt/cel/role"): "typed",
    ("PATCH", "/auth/jwt/cel/role/:name"): "typed",
    ("POST", "/auth/jwt/cel/login"): "typed",
    ("POST", "/auth/jwt/cel/role/:name"): "typed",
    ("DELETE", "/sys/generate-root-token/attempt"): "typed-gated",
    ("GET", "/sys/generate-root-token/attempt"): "typed-gated",
    ("POST", "/sys/generate-root-token/attempt"): "typed-gated",
    ("POST", "/sys/generate-root-token/update"): "typed-gated",
    ("DELETE", "/sys/namespaces/:path/delete-sealed"): "typed-gated",
    ("GET", "/sys/namespaces/:path/seal-status"): "typed",
    ("POST", "/sys/namespaces/:path/seal"): "typed-gated",
    ("POST", "/sys/namespaces/:path/unseal"): "typed-gated",
    ("DELETE", "/sys/workflows/manage/:path"): "typed",
    ("GET", "/sys/workflows/manage/:path"): "typed",
    ("LIST", "/sys/workflows/manage"): "typed",
    ("LIST", "/sys/workflows/manage/:prefix"): "security-blocked",
    ("POST", "/sys/workflows/execute/:path"): "typed",
    ("POST", "/sys/workflows/manage/:path"): "typed",
    ("POST", "/sys/workflows/trace/:path"): "typed-gated",
    ("POST", "/sys/workflows/unauthed-execute/:path"): "typed-gated",
    ("SCAN", "/sys/workflows/manage"): "typed",
    ("SCAN", "/sys/workflows/manage/:prefix"): "security-blocked",
    ("PATCH", "/sys/policies/acl/:name"): "typed",
}
SECURITY_BLOCKED = frozenset(
    f"{method} {path}"
    for (method, path), disposition in STAGED_DISPOSITIONS.items()
    if disposition == "security-blocked"
)
PROFILE_SECURITY_BLOCKED = frozenset(
    {
        ("PATCH", "/auth/jwt/cel/role/:name", "2.6.0"),
    }
)
PENDING_DISPOSITIONS = {
    "pending-typed",
    "pending-typed-gated",
    "pending-security-blocked",
}
CANDIDATE_PATH_CORRECTIONS = {
    "/auth/jwt/cel/roles": "/auth/jwt/cel/role",
    "/auth/jwt/cel/roles/:name": "/auth/jwt/cel/role/:name",
}
CANDIDATE_METHOD_CORRECTIONS = {
    ("PUT", "/sys/namespaces/:path/seal"): ("POST", "/sys/namespaces/:path/seal"),
    ("PUT", "/sys/namespaces/:path/unseal"): ("POST", "/sys/namespaces/:path/unseal"),
}
CANDIDATE_OPERATION_SUPPLEMENTS = {
    ("SCAN", "/sys/workflows/manage"),
    ("SCAN", "/sys/workflows/manage/:prefix"),
}
CANDIDATE_OPENAPI_SUPPLEMENTS = {
    ("GET", "/identity/oidc/.well-known/keys"),
    ("GET", "/sys/rotate/(root|recovery)/backup"),
    ("POST", "/ssh/issuer/:issuer_ref"),
    ("POST", "/sys/rotate/(root|recovery)/update"),
    ("POST", "/sys/rotate/root"),
}
ROOT_GENERATION_ENDPOINTS = {
    "sys.generate-root.cancel": (
        ("DELETE", "/sys/generate-root/attempt"),
        ("DELETE", "/sys/generate-root-token/attempt"),
    ),
    "sys.generate-root.start": (
        ("POST", "/sys/generate-root/attempt"),
        ("POST", "/sys/generate-root-token/attempt"),
    ),
    "sys.generate-root.status": (
        ("GET", "/sys/generate-root/attempt"),
        ("GET", "/sys/generate-root-token/attempt"),
    ),
    "sys.generate-root.update": (
        ("POST", "/sys/generate-root/update"),
        ("POST", "/sys/generate-root-token/update"),
    ),
}
SAFE_ID = re.compile(r"openbao\.[a-z0-9._-]{1,112}\.[0-9a-f]{16}", re.ASCII)


class RegistryError(RuntimeError):
    """Capability evidence or generated output is invalid."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def load_json(path: Path, maximum: int = MAX_INPUT_BYTES) -> dict[str, Any]:
    try:
        value = parse_json(read_regular_file(path, maximum), maximum)
    except (OSError, SnapshotError) as error:
        raise RegistryError("capability registry input is missing or unsafe") from error
    if not isinstance(value, dict):
        raise RegistryError("capability registry input must be an object")
    return value


def operation_key(method: str, path: str) -> str:
    return f"{method} {path}"


def validate_operation(method: Any, path: Any) -> tuple[str, str]:
    if method not in METHODS or not isinstance(path, str):
        raise RegistryError("capability operation method or path is invalid")
    encoded = path.encode("ascii", "strict")
    if (
        not path.startswith("/")
        or not encoded
        or len(encoded) > MAX_PATH_BYTES
        or any(byte < 0x20 or byte == 0x7F for byte in encoded)
    ):
        raise RegistryError("capability path template is unsafe")
    placeholders = set(PLACEHOLDER_NAME.findall(path))
    if placeholders - MULTI_SEGMENT_PLACEHOLDERS - SINGLE_SEGMENT_PLACEHOLDERS:
        raise RegistryError("capability placeholder semantics require explicit review")
    if ":*" in path:
        raise RegistryError("capability path uses unsupported catch-all syntax")
    return method, path


def stable_id(method: str, path: str) -> str:
    identity = operation_key(method, path)
    slug = re.sub(r"[^a-z0-9]+", ".", identity.lower()).strip(".")
    slug = slug[:96].rstrip(".") or "operation"
    digest = sha256(identity.encode())[:16]
    value = f"openbao.{slug}.{digest}"
    if SAFE_ID.fullmatch(value) is None:
        raise RegistryError("generated capability identifier is invalid")
    return value


def matrix_operations(matrix: dict[str, Any]) -> dict[tuple[str, str], str]:
    if matrix.get("schema") != "openbao-api-contract-matrix/v1" or matrix.get("version") != "2.5.5":
        raise RegistryError("current contract matrix identity is invalid")
    result: dict[tuple[str, str], str] = {}
    for row in matrix.get("operations", []):
        path = row.get("path")
        status = row.get("legacy_matrix", {}).get("status")
        if status not in DISPOSITIONS or not isinstance(row.get("methods"), list):
            raise RegistryError("current contract operation disposition is invalid")
        for method in row["methods"]:
            key = validate_operation(method, path)
            if key in result:
                raise RegistryError("current contract operation is duplicated")
            result[key] = DISPOSITIONS[status]
    blocked = {operation_key(*key) for key, value in result.items() if value == "security-blocked"}
    if blocked != HISTORICAL_SECURITY_BLOCKED:
        raise RegistryError("security-blocked operation policy changed without code review")
    return result


def documented_operations(document: dict[str, Any], version: str) -> set[tuple[str, str]]:
    if (
        document.get("schema") != "openbao-tagged-api-documentation/v1"
        or document.get("version") != version
    ):
        raise RegistryError("tagged documentation snapshot identity is invalid")
    result: set[tuple[str, str]] = set()
    for operation in document.get("operations", []):
        path = operation.get("path")
        path = DOCUMENTATION_PATH_CORRECTIONS.get(path, path)
        key = validate_operation(operation.get("method"), path)
        result.add(key)
    return result


def candidate_documented_operations(
    document: dict[str, Any], version: str = STAGED_VERSION,
) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """Return reviewed 2.6 routes and the subset corrected from tagged docs."""
    tagged = documented_operations(document, version)
    result: set[tuple[str, str]] = set()
    corrected: set[tuple[str, str]] = set()
    for method, path in tagged:
        candidate = (method, CANDIDATE_PATH_CORRECTIONS.get(path, path))
        candidate = CANDIDATE_METHOD_CORRECTIONS.get(candidate, candidate)
        validate_operation(*candidate)
        result.add(candidate)
        if candidate != (method, path):
            corrected.add(candidate)
    result.update(CANDIDATE_OPERATION_SUPPLEMENTS)
    return result, corrected


def supplemented_openapi_operations(
    document: dict[str, Any], version: str
) -> set[tuple[str, str]]:
    if (
        document.get("schema") != "openbao-normalized-openapi/v1"
        or document.get("version") != version
        or not isinstance(document.get("document", {}).get("paths"), dict)
    ):
        raise RegistryError("locked OpenAPI snapshot identity is invalid")
    paths = document["document"]["paths"]
    result: set[tuple[str, str]] = set()
    for key, (openapi_method, openapi_path) in OPENAPI_OPERATION_SUPPLEMENTS.items():
        operation = paths.get(openapi_path, {}).get(openapi_method)
        if isinstance(operation, dict):
            result.add(key)
    return result


def compress_ranges(
    versions: list[str],
    states: list[tuple[str, str]],
) -> list[dict[str, str]]:
    if len(versions) != len(states) or not versions:
        raise RegistryError("capability profile state count is invalid")
    ranges: list[dict[str, str]] = []
    start = 0
    for index in range(1, len(states) + 1):
        if index != len(states) and states[index] == states[start]:
            continue
        availability, evidence = states[start]
        ranges.append(
            {
                "minimum": versions[start],
                "maximum": versions[index - 1],
                "availability": availability,
                "evidence": evidence,
            }
        )
        start = index
    return ranges


def state_for_version(
    operation: dict[str, Any], version: str
) -> tuple[str, str]:
    selected = version_tuple(version)
    for item in operation["ranges"]:
        if version_tuple(item["minimum"]) <= selected <= version_tuple(item["maximum"]):
            return item["availability"], item["evidence"]
    raise RegistryError("capability operation has no state for an exact profile")


def root_generation_endpoints() -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    for endpoint_id, routes in sorted(ROOT_GENERATION_ENDPOINTS.items()):
        legacy, current = routes
        endpoints.append(
            {
                "id": endpoint_id,
                "variants": [
                    {
                        "operation_id": stable_id(*legacy),
                        "minimum": HISTORICAL_VERSIONS[0],
                        "maximum": HISTORICAL_VERSIONS[-1],
                    },
                    {
                        "operation_id": stable_id(*current),
                        "minimum": STAGED_VERSION,
                        "maximum": EXPECTED_VERSIONS[-1],
                    },
                ],
            }
        )
    return endpoints


def build_registry() -> dict[str, Any]:
    try:
        releases = validate_lock_files()
        snapshot_lock = verify_api_snapshots()
        verify_contract_matrix()
    except (LockValidationError, SnapshotError) as error:
        raise RegistryError("anchored compatibility evidence failed validation") from error
    matrix_bytes = read_regular_file(MATRIX_PATH, MAX_INPUT_BYTES)
    expected_matrix_hash = CONTRACT_OUTPUT_HASHES["docs/openbao-2.5-contract-matrix.json"]
    if sha256(matrix_bytes) != expected_matrix_hash:
        raise RegistryError("current contract matrix checksum is not anchored")
    matrix = parse_json(matrix_bytes, MAX_INPUT_BYTES)
    current = matrix_operations(matrix)
    for key in OPENAPI_OPERATION_SUPPLEMENTS:
        current[key] = "typed"
    for key in HISTORICAL_DISPOSITIONS:
        if key in current:
            raise RegistryError("historical capability unexpectedly re-entered the current contract")
    versions = [record["version"] for record in releases["records"]]
    if [record["version"] for record in snapshot_lock["records"]] != versions:
        raise RegistryError("snapshot and release inventories are misaligned")

    by_version: dict[str, set[tuple[str, str]]] = {}
    tagged_by_version: dict[str, set[tuple[str, str]]] = {}
    openapi_by_version: dict[str, set[tuple[str, str]]] = {}
    for record in snapshot_lock["records"]:
        version = record["version"]
        documentation_path = ROOT / record["documentation"]["path"]
        openapi_path = ROOT / record["openapi"]["path"]
        if version_tuple(version) >= version_tuple(STAGED_VERSION):
            tagged, corrected = candidate_documented_operations(
                load_json(documentation_path), version
            )
            openapi = CANDIDATE_OPENAPI_SUPPLEMENTS | corrected
        else:
            tagged = documented_operations(load_json(documentation_path), version)
            openapi = supplemented_openapi_operations(load_json(openapi_path), version)
        tagged_by_version[version] = tagged
        openapi_by_version[version] = openapi
        by_version[version] = tagged | openapi
    current_tagged = tagged_by_version["2.5.5"].copy()
    by_version["2.5.5"].update(current)
    all_operations = set().union(*by_version.values())
    if len(all_operations) != EXPECTED_OPERATION_COUNT:
        raise RegistryError("capability operation count changed")

    operations: list[dict[str, Any]] = []
    for method, path in all_operations:
        disposition = current.get(
            (method, path),
            STAGED_DISPOSITIONS.get(
                (method, path), HISTORICAL_DISPOSITIONS.get((method, path), "unlinked")
            ),
        )
        if operation_key(method, path) in SECURITY_BLOCKED:
            disposition = "security-blocked"
        states: list[tuple[str, str]] = []
        for version in versions:
            if (method, path) not in by_version[version]:
                states.append(("unavailable", "none"))
            elif (
                (method, path) in openapi_by_version[version]
                and (method, path) not in tagged_by_version[version]
            ):
                states.append(("documented", "locked-openapi"))
            elif version == "2.5.5" and (method, path) not in current_tagged:
                states.append(("documented", "corrected-2.5.5-contract"))
            else:
                states.append(("documented", "tagged-documentation"))
            if (
                method,
                path,
                version,
            ) in PROFILE_SECURITY_BLOCKED:
                availability, evidence = states[-1]
                if availability != "documented":
                    raise RegistryError(
                        "profile security block targets an undocumented route"
                    )
                states[-1] = ("security-blocked", evidence)
        operations.append(
            {
                "id": stable_id(method, path),
                "method": method,
                "path_template": path,
                "disposition": disposition,
                "ranges": compress_ranges(versions, states),
            }
        )
    operations.sort(key=lambda value: value["id"])
    registry = {
        "schema": "openbao-capability-registry/v1",
        "generator_version": 1,
        "release_inventory_sha256": EXPECTED_LOCK_SHA256,
        "api_snapshot_lock_sha256": EXPECTED_SNAPSHOT_LOCK_SHA256,
        "contract_matrix_sha256": expected_matrix_hash,
        "versions": versions,
        "summary": {
            "operation_count": len(operations),
            "profile_count": len(versions),
            "dispositions": dict(sorted(Counter(item["disposition"] for item in operations).items())),
        },
        "logical_endpoints": root_generation_endpoints(),
        "operations": operations,
    }
    validate_registry(registry)
    return registry


def build_staged_registry(active: dict[str, Any] | None = None) -> dict[str, Any]:
    active = build_registry() if active is None else active
    try:
        onboarding_lock = verify_onboarding_api()
    except OnboardingError as error:
        raise RegistryError("staged 2.6 API evidence failed validation") from error
    documentation_record = onboarding_lock.get("artifacts", {}).get("documentation")
    if not isinstance(documentation_record, dict):
        raise RegistryError("staged documentation record is missing")
    documentation = load_json(ROOT / documentation_record.get("path", ""))
    candidate_routes, corrected_routes = candidate_documented_operations(documentation)
    candidate_routes.update(CANDIDATE_OPENAPI_SUPPLEMENTS)

    active_by_route = {
        (item["method"], item["path_template"]): item for item in active["operations"]
    }
    candidate_only = candidate_routes - set(active_by_route)
    if candidate_only != set(STAGED_DISPOSITIONS):
        raise RegistryError("staged operation inventory changed without disposition review")

    operations: list[dict[str, Any]] = []
    all_routes = set(active_by_route) | candidate_routes
    for method, path in all_routes:
        active_operation = active_by_route.get((method, path))
        if active_operation is None:
            states = [("unavailable", "none")] * len(EXPECTED_VERSIONS)
            disposition = STAGED_DISPOSITIONS[(method, path)]
        else:
            states = [
                state_for_version(active_operation, version) for version in EXPECTED_VERSIONS
            ]
            disposition = active_operation["disposition"]
        if (method, path) in corrected_routes:
            candidate_state = ("documented", "locked-openapi")
        elif (method, path) in candidate_routes:
            candidate_state = (
                "documented",
                "locked-openapi"
                if (method, path) in CANDIDATE_OPENAPI_SUPPLEMENTS
                else "tagged-documentation",
            )
        else:
            candidate_state = ("unavailable", "none")
        states.append(candidate_state)
        operations.append(
            {
                "id": stable_id(method, path),
                "method": method,
                "path_template": path,
                "disposition": disposition,
                "ranges": compress_ranges(list(EXPECTED_STAGED_VERSIONS), states),
            }
        )
    operations.sort(key=lambda value: value["id"])
    registry = {
        "schema": "openbao-staged-capability-registry/v1",
        "generator_version": 1,
        "active_registry_sha256": EXPECTED_REGISTRY_SHA256,
        "onboarding_api_evidence_lock_sha256": ONBOARDING_API_LOCK_SHA256,
        "versions": list(EXPECTED_STAGED_VERSIONS),
        "summary": {
            "operation_count": len(operations),
            "profile_count": len(EXPECTED_STAGED_VERSIONS),
            "public_operation_count": sum(
                item["disposition"] not in PENDING_DISPOSITIONS for item in operations
            ),
            "pending_operation_count": sum(
                item["disposition"] in PENDING_DISPOSITIONS for item in operations
            ),
            "dispositions": dict(
                sorted(Counter(item["disposition"] for item in operations).items())
            ),
        },
        "logical_endpoints": root_generation_endpoints(),
        "operations": operations,
    }
    validate_staged_registry(registry, active)
    return registry


def historical_projection(
    staged: dict[str, Any], active: dict[str, Any]
) -> dict[str, Any]:
    staged_by_id = {item["id"]: item for item in staged["operations"]}
    projected_operations: list[dict[str, Any]] = []
    for active_operation in active["operations"]:
        candidate = staged_by_id.get(active_operation["id"])
        if candidate is None:
            raise RegistryError("staged registry removed a historical operation identity")
        states = [state_for_version(candidate, version) for version in EXPECTED_VERSIONS]
        projected_operations.append(
            {
                "id": candidate["id"],
                "method": candidate["method"],
                "path_template": candidate["path_template"],
                "disposition": candidate["disposition"],
                "ranges": compress_ranges(list(EXPECTED_VERSIONS), states),
            }
        )
    projection = copy.deepcopy(active)
    projection["operations"] = projected_operations
    projection["summary"] = {
        "operation_count": len(projected_operations),
        "profile_count": len(EXPECTED_VERSIONS),
        "dispositions": dict(
            sorted(Counter(item["disposition"] for item in projected_operations).items())
        ),
    }
    return projection


def version_tuple(value: str) -> tuple[int, int, int]:
    parts = value.split(".")
    if len(parts) != 3 or any(not part.isdigit() or (len(part) > 1 and part.startswith("0")) for part in parts):
        raise RegistryError("capability profile version is invalid")
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


def validate_registry(registry: dict[str, Any]) -> None:
    required = {
        "schema",
        "generator_version",
        "release_inventory_sha256",
        "api_snapshot_lock_sha256",
        "contract_matrix_sha256",
        "versions",
        "summary",
        "logical_endpoints",
        "operations",
    }
    if (
        set(registry) != required
        or registry.get("schema") != "openbao-capability-registry/v1"
        or registry.get("generator_version") != 1
        or registry.get("release_inventory_sha256") != EXPECTED_LOCK_SHA256
        or registry.get("api_snapshot_lock_sha256") != EXPECTED_SNAPSHOT_LOCK_SHA256
        or registry.get("contract_matrix_sha256")
        != CONTRACT_OUTPUT_HASHES["docs/openbao-2.5-contract-matrix.json"]
    ):
        raise RegistryError("capability registry metadata is invalid")
    versions = registry["versions"]
    operations = registry["operations"]
    if (
        not isinstance(versions, list)
        or not versions
        or tuple(versions) != EXPECTED_VERSIONS
        or not isinstance(operations, list)
        or not operations
        or len(operations) > MAX_OPERATIONS
    ):
        raise RegistryError("capability registry collections are invalid")
    version_index = {version: index for index, version in enumerate(versions)}
    ids: list[str] = []
    routes: set[tuple[str, str]] = set()
    for operation in operations:
        if set(operation) != {"id", "method", "path_template", "disposition", "ranges"}:
            raise RegistryError("capability operation fields are invalid")
        method, path = validate_operation(operation["method"], operation["path_template"])
        identifier = operation["id"]
        if identifier != stable_id(method, path) or operation["disposition"] not in {
            "typed", "typed-gated", "security-blocked"
        }:
            raise RegistryError("capability operation identity or disposition is invalid")
        if (method, path) in routes:
            raise RegistryError("capability operation route is duplicated")
        routes.add((method, path))
        ids.append(identifier)
        ranges = operation["ranges"]
        if not isinstance(ranges, list) or not ranges:
            raise RegistryError("capability operation has no profile ranges")
        expected_start = 0
        previous_state: tuple[str, str] | None = None
        latest_available = False
        ever_available = False
        for item in ranges:
            if set(item) != {"minimum", "maximum", "availability", "evidence"}:
                raise RegistryError("capability range fields are invalid")
            minimum = version_index.get(item["minimum"])
            maximum = version_index.get(item["maximum"])
            state = (item["availability"], item["evidence"])
            if (
                minimum != expected_start
                or maximum is None
                or maximum < minimum
                or state not in {
                    ("unavailable", "none"),
                    ("documented", "tagged-documentation"),
                    ("documented", "locked-openapi"),
                    ("documented", "corrected-2.5.5-contract"),
                    ("security-blocked", "tagged-documentation"),
                    ("security-blocked", "locked-openapi"),
                }
                or state == previous_state
            ):
                raise RegistryError("capability ranges overlap, contain gaps, or contradict evidence")
            expected_start = maximum + 1
            previous_state = state
            ever_available |= state[0] in {"documented", "security-blocked"}
            if maximum == len(versions) - 1:
                latest_available = state[0] in {"documented", "security-blocked"}
        if expected_start != len(versions):
            raise RegistryError("capability ranges do not cover every exact profile")
        historical_disposition = HISTORICAL_DISPOSITIONS.get((method, path))
        if operation["disposition"] in {"typed", "typed-gated"} and not ever_available:
            raise RegistryError("typed capability is unavailable in every profile")
        if historical_disposition is not None and latest_available:
            raise RegistryError("historical-only capability is unexpectedly current")
        key = operation_key(method, path)
        if (key in SECURITY_BLOCKED) != (operation["disposition"] == "security-blocked"):
            raise RegistryError("security-blocked capability disposition was downgraded")
    if ids != sorted(set(ids)):
        raise RegistryError("capability identifiers are duplicated or unordered")
    if any(item["disposition"] == "unlinked" for item in operations):
        raise RegistryError("capability registry contains an unexplained historical operation")
    summary = registry["summary"]
    expected_counts = dict(sorted(Counter(item["disposition"] for item in operations).items()))
    if summary != {
        "operation_count": len(operations),
        "profile_count": len(versions),
        "dispositions": expected_counts,
    }:
        raise RegistryError("capability registry summary is inconsistent")

    operation_ids = set(ids)
    endpoints = registry["logical_endpoints"]
    if not isinstance(endpoints, list) or len(endpoints) != len(ROOT_GENERATION_ENDPOINTS):
        raise RegistryError("logical endpoint inventory is invalid")
    endpoint_ids: list[str] = []
    for endpoint in endpoints:
        if set(endpoint) != {"id", "variants"} or not isinstance(endpoint["variants"], list):
            raise RegistryError("logical endpoint fields are invalid")
        endpoint_ids.append(endpoint["id"])
        expected_minimum = EXPECTED_VERSIONS[0]
        for variant in endpoint["variants"]:
            if set(variant) != {"operation_id", "minimum", "maximum"}:
                raise RegistryError("logical endpoint variant fields are invalid")
            minimum = version_index.get(variant["minimum"])
            maximum = version_index.get(variant["maximum"])
            if (
                variant["operation_id"] not in operation_ids
                or minimum is None
                or maximum is None
                or minimum > maximum
                or variant["minimum"] != expected_minimum
            ):
                raise RegistryError("logical endpoint variants overlap or contain a gap")
            expected_minimum = (
                EXPECTED_VERSIONS[maximum + 1]
                if maximum + 1 < len(EXPECTED_VERSIONS)
                else ""
            )
        if expected_minimum:
            raise RegistryError("logical endpoint variants do not cover every profile")
    if endpoint_ids != sorted(set(endpoint_ids)):
        raise RegistryError("logical endpoint identifiers are invalid")


def validate_staged_registry(
    registry: dict[str, Any], active: dict[str, Any]
) -> None:
    required = {
        "schema",
        "generator_version",
        "active_registry_sha256",
        "onboarding_api_evidence_lock_sha256",
        "versions",
        "summary",
        "logical_endpoints",
        "operations",
    }
    if (
        set(registry) != required
        or registry.get("schema") != "openbao-staged-capability-registry/v1"
        or registry.get("generator_version") != 1
        or registry.get("active_registry_sha256") != EXPECTED_REGISTRY_SHA256
        or registry.get("onboarding_api_evidence_lock_sha256")
        != ONBOARDING_API_LOCK_SHA256
        or tuple(registry.get("versions", ())) != EXPECTED_STAGED_VERSIONS
    ):
        raise RegistryError("staged capability registry metadata is invalid")
    operations = registry.get("operations")
    if not isinstance(operations, list) or len(operations) != EXPECTED_STAGED_OPERATION_COUNT:
        raise RegistryError("staged capability operation count changed")
    version_index = {
        version: index for index, version in enumerate(EXPECTED_STAGED_VERSIONS)
    }
    identifiers: list[str] = []
    routes: set[tuple[str, str]] = set()
    allowed_dispositions = {
        "typed",
        "typed-gated",
        "security-blocked",
        *PENDING_DISPOSITIONS,
    }
    allowed_states = {
        ("unavailable", "none"),
        ("documented", "tagged-documentation"),
        ("documented", "locked-openapi"),
        ("documented", "corrected-2.5.5-contract"),
    }
    for operation in operations:
        if set(operation) != {"id", "method", "path_template", "disposition", "ranges"}:
            raise RegistryError("staged capability operation fields are invalid")
        method, path = validate_operation(operation["method"], operation["path_template"])
        identifier = operation["id"]
        disposition = operation["disposition"]
        if identifier != stable_id(method, path) or disposition not in allowed_dispositions:
            raise RegistryError("staged capability identity or disposition is invalid")
        if (method, path) in routes:
            raise RegistryError("staged capability route is duplicated")
        routes.add((method, path))
        identifiers.append(identifier)
        ranges = operation["ranges"]
        if not isinstance(ranges, list) or not ranges:
            raise RegistryError("staged capability has no profile ranges")
        expected_start = 0
        previous_state: tuple[str, str] | None = None
        for item in ranges:
            if set(item) != {"minimum", "maximum", "availability", "evidence"}:
                raise RegistryError("staged capability range fields are invalid")
            minimum = version_index.get(item["minimum"])
            maximum = version_index.get(item["maximum"])
            state = (item["availability"], item["evidence"])
            if (
                minimum != expected_start
                or maximum is None
                or maximum < minimum
                or state not in allowed_states
                or state == previous_state
            ):
                raise RegistryError("staged capability ranges overlap or contain gaps")
            expected_start = maximum + 1
            previous_state = state
        if expected_start != len(EXPECTED_STAGED_VERSIONS):
            raise RegistryError("staged capability does not cover every exact profile")
        candidate_state = state_for_version(operation, STAGED_VERSION)
        if disposition in PENDING_DISPOSITIONS:
            if candidate_state[0] != "documented" or any(
                state_for_version(operation, version)[0] != "unavailable"
                for version in EXPECTED_VERSIONS
            ):
                raise RegistryError("pending capability escaped the candidate profile")
        elif candidate_state[0] == "documented" and disposition not in {
            "typed",
            "typed-gated",
            "security-blocked",
        }:
            raise RegistryError("documented candidate capability is unresolved")
    if identifiers != sorted(set(identifiers)):
        raise RegistryError("staged capability identifiers are duplicated or unordered")

    summary = registry.get("summary")
    counts = dict(sorted(Counter(item["disposition"] for item in operations).items()))
    expected_summary = {
        "operation_count": len(operations),
        "profile_count": len(EXPECTED_STAGED_VERSIONS),
        "public_operation_count": sum(
            item["disposition"] not in PENDING_DISPOSITIONS for item in operations
        ),
        "pending_operation_count": sum(
            item["disposition"] in PENDING_DISPOSITIONS for item in operations
        ),
        "dispositions": counts,
    }
    if summary != expected_summary:
        raise RegistryError("staged capability summary is inconsistent")

    operation_ids = set(identifiers)
    endpoints = registry.get("logical_endpoints")
    if not isinstance(endpoints, list) or len(endpoints) != len(ROOT_GENERATION_ENDPOINTS):
        raise RegistryError("staged logical endpoint inventory is invalid")
    endpoint_ids: list[str] = []
    for endpoint in endpoints:
        if set(endpoint) != {"id", "variants"} or not isinstance(endpoint["variants"], list):
            raise RegistryError("staged logical endpoint fields are invalid")
        endpoint_ids.append(endpoint["id"])
        variants = endpoint["variants"]
        if len(variants) != 2:
            raise RegistryError("staged root-generation endpoint variant count changed")
        expected_minimum = EXPECTED_STAGED_VERSIONS[0]
        for variant in variants:
            if set(variant) != {"operation_id", "minimum", "maximum"}:
                raise RegistryError("staged endpoint variant fields are invalid")
            if variant["operation_id"] not in operation_ids:
                raise RegistryError("staged endpoint references an unknown operation")
            minimum = version_index.get(variant["minimum"])
            maximum = version_index.get(variant["maximum"])
            if (
                minimum is None
                or maximum is None
                or minimum > maximum
                or variant["minimum"] != expected_minimum
            ):
                raise RegistryError("staged endpoint variants overlap or contain a gap")
            expected_minimum = (
                EXPECTED_STAGED_VERSIONS[maximum + 1]
                if maximum + 1 < len(EXPECTED_STAGED_VERSIONS)
                else ""
            )
        if expected_minimum:
            raise RegistryError("staged endpoint variants do not cover every profile")
    if endpoint_ids != sorted(set(endpoint_ids)):
        raise RegistryError("staged logical endpoint identifiers are invalid")

    projection = historical_projection(registry, active)
    if canonical_json(projection) != canonical_json(active):
        raise RegistryError("staged registry mutated a historical capability cell")
    if sha256(canonical_json(projection)) != EXPECTED_REGISTRY_SHA256:
        raise RegistryError("historical capability projection checksum changed")


def rust_string(value: str) -> str:
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise RegistryError("generated Rust string contains a control character")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def rust_version(value: str) -> str:
    major, minor, patch = version_tuple(value)
    return f"OpenBaoVersion::new({major}, {minor}, {patch})"


def rust_output(registry: dict[str, Any]) -> bytes:
    registry_versions = tuple(registry["versions"])
    if registry_versions[: len(EXPECTED_VERSIONS)] != EXPECTED_VERSIONS:
        raise RegistryError(
            "generated capability profiles do not preserve the routable inventory"
        )
    method_names = {value: value.title() for value in METHODS}
    disposition_names = {
        "typed": "Typed",
        "typed-gated": "TypedGated",
        "security-blocked": "SecurityBlocked",
    }
    evidence_names = {
        "none": "None",
        "tagged-documentation": "TaggedDocumentation",
        "locked-openapi": "LockedOpenApi",
        "corrected-2.5.5-contract": "CorrectedCurrentContract",
    }
    lines = [
        "// @generated by scripts/generate_openbao_capability_registry.py; do not edit.",
        "",
        "pub(super) const GENERATED_PROFILE_VERSIONS: &[OpenBaoVersion] = &[",
    ]
    for version in registry["versions"]:
        lines.append(f"    {rust_version(version)},")
    lines.extend(
        [
            "];",
            "",
            "// Only fully promoted profiles may drive compatibility policy or dispatch.",
            "pub(super) const GENERATED_ROUTABLE_PROFILE_VERSIONS: &[OpenBaoVersion] = &[",
        ]
    )
    for version in EXPECTED_VERSIONS:
        lines.append(f"    {rust_version(version)},")
    lines.extend(["];", "", "pub(super) static GENERATED_OPERATIONS: &[OpenBaoOperation] = &["])
    for operation in registry["operations"]:
        if operation["disposition"] in PENDING_DISPOSITIONS:
            continue
        lines.extend(
            [
                "    OpenBaoOperation::generated(",
                f"        {rust_string(operation['id'])},",
                f"        OpenBaoHttpMethod::{method_names[operation['method']]},",
                f"        {rust_string(operation['path_template'])},",
                f"        OpenBaoOperationDisposition::{disposition_names[operation['disposition']]},",
                "        &[",
            ]
        )
        for item in operation["ranges"]:
            lines.extend(
                [
                    "            OpenBaoCapabilityRange::generated(",
                    f"                {rust_version(item['minimum'])},",
                    f"                {rust_version(item['maximum'])},",
                    f"                OpenBaoCapabilityEvidence::{evidence_names[item['evidence']]},",
                    f"                {str(item['availability'] == 'security-blocked').lower()},",
                    "            ),",
                ]
            )
        lines.extend(["        ],", "    ),"])
    lines.extend(["];", ""])
    for endpoint in registry.get("logical_endpoints", []):
        constant = "GENERATED_" + endpoint["id"].upper().replace(".", "_").replace("-", "_")
        lines.extend(
            [
                "#[allow(dead_code)] // Consumed by the following system-compatibility commit.",
                f"pub(crate) const {constant}: OpenBaoEndpointSpec = OpenBaoEndpointSpec::new(",
                f"    {rust_string(endpoint['id'])},",
                "    &[",
            ]
        )
        for variant in endpoint["variants"]:
            lines.extend(
                [
                    "        OpenBaoEndpointVariant::new(",
                    f"            {rust_string(variant['operation_id'])},",
                    f"            {rust_version(variant['minimum'])},",
                    f"            {rust_version(variant['maximum'])},",
                    "        ),",
                ]
            )
        lines.extend(["    ],", ");", ""])
    return "\n".join(lines).encode()


def outputs() -> dict[Path, bytes]:
    active = build_registry()
    return {
        REGISTRY_PATH: canonical_json(active),
        RUST_PATH: rust_output(active),
    }


def atomic_write(path: Path, data: bytes) -> None:
    if (
        len(data) > MAX_OUTPUT_BYTES
        or path.is_symlink()
        or any(parent.is_symlink() for parent in path.parents if parent != ROOT.parent)
    ):
        raise RegistryError("capability output path or size is unsafe")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def verify_outputs() -> None:
    generated = outputs()
    expected_hashes = {
        REGISTRY_PATH: EXPECTED_REGISTRY_SHA256,
        RUST_PATH: EXPECTED_RUST_SHA256,
    }
    for path, expected in generated.items():
        if sha256(expected) != expected_hashes[path]:
            raise RegistryError("generated capability output checksum is not anchored")
        try:
            actual = read_regular_file(path, MAX_OUTPUT_BYTES)
        except (OSError, SnapshotError) as error:
            raise RegistryError("generated capability output is missing or unsafe") from error
        if actual != expected:
            raise RegistryError("generated capability output is stale")
    try:
        staged = read_regular_file(STAGED_REGISTRY_PATH, MAX_OUTPUT_BYTES)
    except (OSError, SnapshotError) as error:
        raise RegistryError("historical candidate registry is missing or unsafe") from error
    if sha256(staged) != EXPECTED_STAGED_REGISTRY_SHA256:
        raise RegistryError("historical candidate registry checksum changed")


def self_test() -> None:
    verify_outputs()
    registry = build_registry()

    def expect_rejected(label: str, value: dict[str, Any]) -> None:
        try:
            validate_registry(value)
        except RegistryError:
            return
        raise RegistryError(f"capability self-test accepted {label}")

    duplicate = copy.deepcopy(registry)
    duplicate["operations"][1]["id"] = duplicate["operations"][0]["id"]
    duplicate["operations"].sort(key=lambda value: value["id"])
    expect_rejected("a duplicate operation identifier", duplicate)

    if SECURITY_BLOCKED:
        blocked = copy.deepcopy(registry)
        blocked_operation = next(
            item for item in blocked["operations"] if item["disposition"] == "security-blocked"
        )
        blocked_operation["disposition"] = "typed"
        expect_rejected("a security-policy downgrade", blocked)

    gap = copy.deepcopy(registry)
    ranged = next(item for item in gap["operations"] if len(item["ranges"]) > 1)
    ranged["ranges"][1]["minimum"] = ranged["ranges"][0]["minimum"]
    expect_rejected("a capability range gap or overlap", gap)

    injection = copy.deepcopy(registry)
    injection["operations"][0]["path_template"] += "\nunsafe"
    expect_rejected("a generated-code control character", injection)

    unknown_placeholder = copy.deepcopy(registry)
    unknown_placeholder["operations"][0]["path_template"] += "/:future-semantics"
    expect_rejected("an unreviewed placeholder semantic", unknown_placeholder)

    if canonical_json(build_registry()) != canonical_json(registry) or rust_output(build_registry()) != rust_output(registry):
        raise RegistryError("capability generation is not deterministic")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--generate", action="store_true")
    action.add_argument("--verify", action="store_true")
    action.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.generate:
            generated = outputs()
            expected_hashes = {
                REGISTRY_PATH: EXPECTED_REGISTRY_SHA256,
                RUST_PATH: EXPECTED_RUST_SHA256,
            }
            for path, data in generated.items():
                if sha256(data) != expected_hashes[path]:
                    raise RegistryError("refusing to write unanchored capability output")
                atomic_write(path, data)
            print(
                "OpenBao capability registry: wrote "
                f"{EXPECTED_OPERATION_COUNT} active operations"
            )
        elif arguments.verify:
            verify_outputs()
            print(
                "OpenBao capability registry: "
                f"{EXPECTED_OPERATION_COUNT} active operations verified"
            )
        else:
            self_test()
            print("OpenBao capability registry self-tests: ok")
        return 0
    except (
        RegistryError,
        OnboardingError,
        SnapshotError,
        OSError,
        UnicodeError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
    ) as error:
        print(f"OpenBao capability registry failed: {error}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
