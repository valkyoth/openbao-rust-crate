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

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "docs/openbao-2.5-contract-matrix.json"
REGISTRY_PATH = ROOT / "compat/capability-registry.json"
RUST_PATH = ROOT / "src/generated/openbao_capabilities.rs"
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_OPERATIONS = 2048
MAX_PATH_BYTES = 4096
EXPECTED_OPERATION_COUNT = 664
EXPECTED_REGISTRY_SHA256 = "e6670a40565a8e231935ade1985bacbe1595abc40c88c98f7730b648ca4d6880"
EXPECTED_RUST_SHA256 = "11bfb52ab54302cc145cc8fd15501c24073827fd29296b55edf9ce4ddf4d11ce"
EXPECTED_VERSIONS = (
    "2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.1.0", "2.1.1", "2.2.0",
    "2.2.1", "2.2.2", "2.3.1", "2.3.2", "2.4.0", "2.4.1", "2.4.3",
    "2.4.4", "2.5.0", "2.5.1", "2.5.2", "2.5.3", "2.5.4", "2.5.5",
)
METHODS = ("ACME", "DELETE", "GET", "HEAD", "LIST", "PATCH", "POST", "PUT", "SCAN")
DISPOSITIONS = {
    "typed": "typed",
    "typed-gated": "typed-gated",
    "external": "external",
    "partial": "partial",
    "omitted": "omitted",
    "rejected": "security-blocked",
}
SECURITY_BLOCKED = frozenset()
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
    if blocked != SECURITY_BLOCKED:
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
        key = validate_operation(operation.get("method"), operation.get("path"))
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
    versions = [record["version"] for record in releases["records"]]
    if [record["version"] for record in snapshot_lock["records"]] != versions:
        raise RegistryError("snapshot and release inventories are misaligned")

    by_version: dict[str, set[tuple[str, str]]] = {}
    for record in snapshot_lock["records"]:
        version = record["version"]
        path = ROOT / record["documentation"]["path"]
        by_version[version] = documented_operations(load_json(path), version)
    current_tagged = by_version["2.5.5"].copy()
    by_version["2.5.5"].update(current)
    all_operations = set().union(*by_version.values())
    if len(all_operations) != EXPECTED_OPERATION_COUNT:
        raise RegistryError("capability operation count changed")

    operations: list[dict[str, Any]] = []
    for method, path in all_operations:
        disposition = current.get((method, path), "unlinked")
        if operation_key(method, path) in SECURITY_BLOCKED:
            disposition = "security-blocked"
        states: list[tuple[str, str]] = []
        for version in versions:
            if (method, path) not in by_version[version]:
                states.append(("unavailable", "none"))
            elif version == "2.5.5" and (method, path) not in current_tagged:
                states.append(("documented", "corrected-2.5.5-contract"))
            else:
                states.append(("documented", "tagged-documentation"))
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
        "operations": operations,
    }
    validate_registry(registry)
    return registry


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
            "typed",
            "typed-gated",
            "external",
            "partial",
            "omitted",
            "security-blocked",
            "unlinked",
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
                    ("documented", "corrected-2.5.5-contract"),
                }
                or state == previous_state
            ):
                raise RegistryError("capability ranges overlap, contain gaps, or contradict evidence")
            expected_start = maximum + 1
            previous_state = state
            if maximum == len(versions) - 1:
                latest_available = state[0] == "documented"
        if expected_start != len(versions):
            raise RegistryError("capability ranges do not cover every exact profile")
        if operation["disposition"] in {"typed", "typed-gated"} and not latest_available:
            raise RegistryError("typed capability is unavailable in the current profile")
        key = operation_key(method, path)
        if (key in SECURITY_BLOCKED) != (operation["disposition"] == "security-blocked"):
            raise RegistryError("security-blocked capability disposition was downgraded")
    if ids != sorted(set(ids)):
        raise RegistryError("capability identifiers are duplicated or unordered")
    summary = registry["summary"]
    expected_counts = dict(sorted(Counter(item["disposition"] for item in operations).items()))
    if summary != {
        "operation_count": len(operations),
        "profile_count": len(versions),
        "dispositions": expected_counts,
    }:
        raise RegistryError("capability registry summary is inconsistent")


def rust_string(value: str) -> str:
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise RegistryError("generated Rust string contains a control character")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def rust_version(value: str) -> str:
    major, minor, patch = version_tuple(value)
    return f"OpenBaoVersion::new({major}, {minor}, {patch})"


def rust_output(registry: dict[str, Any]) -> bytes:
    method_names = {value: value.title() for value in METHODS}
    disposition_names = {
        "typed": "LegacyTypedClaim",
        "typed-gated": "LegacyTypedGatedClaim",
        "external": "ExternalBoundary",
        "partial": "PartialLegacyClaim",
        "omitted": "OmittedLegacyClaim",
        "security-blocked": "SecurityBlocked",
        "unlinked": "UnlinkedHistorical",
    }
    evidence_names = {
        "none": "None",
        "tagged-documentation": "TaggedDocumentation",
        "corrected-2.5.5-contract": "CorrectedCurrentContract",
    }
    lines = [
        "// @generated by scripts/generate_openbao_capability_registry.py; do not edit.",
        "",
        "pub(super) const GENERATED_PROFILE_VERSIONS: &[OpenBaoVersion] = &[",
    ]
    for version in registry["versions"]:
        lines.append(f"    {rust_version(version)},")
    lines.extend(["];", "", "pub(super) static GENERATED_OPERATIONS: &[OpenBaoOperation] = &["])
    for operation in registry["operations"]:
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
                    "            ),",
                ]
            )
        lines.extend(["        ],", "    ),"])
    lines.extend(["];", ""])
    return "\n".join(lines).encode()


def outputs() -> dict[Path, bytes]:
    registry = build_registry()
    return {REGISTRY_PATH: canonical_json(registry), RUST_PATH: rust_output(registry)}


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
    expected_hashes = {REGISTRY_PATH: EXPECTED_REGISTRY_SHA256, RUST_PATH: EXPECTED_RUST_SHA256}
    for path, expected in generated.items():
        if sha256(expected) != expected_hashes[path]:
            raise RegistryError("generated capability output checksum is not anchored")
        try:
            actual = read_regular_file(path, MAX_OUTPUT_BYTES)
        except (OSError, SnapshotError) as error:
            raise RegistryError("generated capability output is missing or unsafe") from error
        if actual != expected:
            raise RegistryError("generated capability output is stale")


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
            expected_hashes = {REGISTRY_PATH: EXPECTED_REGISTRY_SHA256, RUST_PATH: EXPECTED_RUST_SHA256}
            for path, data in generated.items():
                if sha256(data) != expected_hashes[path]:
                    raise RegistryError("refusing to write unanchored capability output")
                atomic_write(path, data)
            print(f"OpenBao capability registry: wrote {EXPECTED_OPERATION_COUNT} operations")
        elif arguments.verify:
            verify_outputs()
            print(f"OpenBao capability registry: {EXPECTED_OPERATION_COUNT} operations verified")
        else:
            self_test()
            print("OpenBao capability registry self-tests: ok")
        return 0
    except (
        RegistryError,
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
