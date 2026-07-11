#!/usr/bin/env python3
"""Generate the complete per-release OpenBao compatibility evidence matrix."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import stat
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from generate_openbao_capability_registry import (
    REGISTRY_PATH,
    verify_outputs as verify_capability_registry,
)
from generate_openbao_response_fixtures import generate as generate_response_fixtures
from openbao_api_snapshots import (
    SnapshotError,
    deterministic_byte_mutations,
    parse_json,
    read_regular_file,
)
from openbao_core_matrix import load_results, verify as verify_core_results
from openbao_test_harness import CORE_OPERATION_IDS

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "compat/version-contract-matrix.json"
MARKDOWN_PATH = ROOT / "docs/OPENBAO_VERSION_SUPPORT_MATRIX.md"
REQUEST_RULES_PATH = ROOT / "src/request_compatibility.rs"
RESPONSE_TEST_PATH = ROOT / "tests/serde_fixtures.rs"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
EXPECTED_MATRIX_SHA256 = "6f6914633d5c207b2de5d204e1f275d3cf7730426f0ca7b69f34e42b3b62326d"
EXPECTED_MARKDOWN_SHA256 = "692789c72c2e924bef5307afd32a1420deb3252e92789e9e745761b8744abfac"
ALLOWED_DISPOSITIONS = {"typed", "typed-gated", "security-blocked"}
ALLOWED_AVAILABILITY = {"documented", "unavailable"}
FORBIDDEN_STATES = {"planned", "decision", "partial", "raw", "external", "rejected", "unlinked"}
RESPONSE_FAMILIES = ("pki-certificate", "pki-role", "plugin", "policy", "quota")
EXPECTED_SCOPE = {
    "destructive_test_isolation": "fresh ephemeral OpenBao server per exact profile",
    "external_services_proven": [],
    "external_services_scope": "no external database, directory, cloud, OIDC, MFA, DNS, or broker service was exercised",
    "live_claim": "eight representative built-in core flows per exact profile",
    "response_claim": "five representative public response families per exact profile",
}


class ContractError(RuntimeError):
    """Version contract evidence is incomplete or contradictory."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()


def load_object(path: Path, maximum: int = MAX_INPUT_BYTES) -> tuple[dict[str, Any], bytes]:
    try:
        data = read_regular_file(path, maximum)
        value = parse_json(data, maximum)
    except (OSError, SnapshotError) as error:
        raise ContractError("version contract input is missing or unsafe") from error
    if not isinstance(value, dict):
        raise ContractError("version contract input must be an object")
    return value, data


def state_for(
    operation: dict[str, Any], version: str, version_index: dict[str, int]
) -> tuple[str, str]:
    selected = version_index[version]
    for item in operation["ranges"]:
        minimum = version_index.get(item["minimum"])
        maximum = version_index.get(item["maximum"])
        if minimum is None or maximum is None:
            raise ContractError("capability range references an unknown locked release")
        if minimum <= selected <= maximum:
            return item["availability"], item["evidence"]
    raise ContractError("capability operation has no state for a locked release")


def percent_basis_points(numerator: int, denominator: int) -> int:
    if denominator <= 0 or numerator < 0 or numerator > denominator:
        raise ContractError("compatibility percentage inputs are invalid")
    return numerator * 10_000 // denominator


def build_matrix() -> dict[str, Any]:
    verify_capability_registry()
    verify_core_results()
    registry, registry_bytes = load_object(REGISTRY_PATH)
    fixture_bytes = generate_response_fixtures()
    fixtures = parse_json(fixture_bytes, MAX_INPUT_BYTES)
    core, core_bytes = load_results()
    request_bytes = read_regular_file(REQUEST_RULES_PATH, MAX_INPUT_BYTES)
    response_test_bytes = read_regular_file(RESPONSE_TEST_PATH, MAX_INPUT_BYTES)

    versions = registry.get("versions")
    operations = registry.get("operations")
    if (
        registry.get("schema") != "openbao-capability-registry/v1"
        or not isinstance(versions, list)
        or not isinstance(operations, list)
        or len(versions) != 21
        or len(operations) != 666
    ):
        raise ContractError("capability registry shape is invalid")
    if any(operation.get("disposition") not in ALLOWED_DISPOSITIONS for operation in operations):
        raise ContractError("capability registry contains an unresolved disposition")
    version_index = {version: index for index, version in enumerate(versions)}

    fixture_profiles = fixtures.get("profiles") if isinstance(fixtures, dict) else None
    core_records = core.get("records")
    if not isinstance(fixture_profiles, list) or not isinstance(core_records, list):
        raise ContractError("profile evidence collections are invalid")
    fixtures_by_version = {item.get("version"): item for item in fixture_profiles}
    core_by_version = {item.get("version"): item for item in core_records}
    if set(fixtures_by_version) != set(versions) or set(core_by_version) != set(versions):
        raise ContractError("profile evidence does not cover the locked release inventory")

    operation_records = [
        {
            "disposition": operation["disposition"],
            "id": operation["id"],
            "method": operation["method"],
            "path_template": operation["path_template"],
        }
        for operation in operations
    ]
    profiles = []
    total_documented = 0
    total_resolved = 0
    for version in versions:
        core_record = core_by_version[version]
        fixture_profile = fixtures_by_version[version]
        if (
            core_record.get("outcome") != "passed"
            or core_record.get("compatibility_status") != "tested-subset"
            or fixture_profile.get("openapi_sha256") is None
        ):
            raise ContractError("profile evidence is not a passing exact-release record")
        live_operations = core_record.get("operations")
        if (
            not isinstance(live_operations, list)
            or not live_operations
            or any(item.get("status") != "passed" for item in live_operations)
        ):
            raise ContractError("representative live evidence is incomplete or skipped")

        cells = []
        counts: Counter[str] = Counter()
        for operation in operations:
            availability, endpoint_evidence = state_for(operation, version, version_index)
            if availability not in ALLOWED_AVAILABILITY:
                raise ContractError("operation/profile availability is unresolved")
            if availability == "unavailable":
                implementation = "not-applicable"
                request_evidence = "not-applicable-route-unavailable"
            else:
                implementation = operation["disposition"]
                request_evidence = {
                    "tagged-documentation": "tagged-contract-fields",
                    "locked-openapi": "locked-openapi-schema",
                    "corrected-2.5.5-contract": "reviewed-current-contract",
                }.get(endpoint_evidence)
                if request_evidence is None:
                    raise ContractError("documented route lacks request contract evidence")
                counts[implementation] += 1
                total_documented += 1
                total_resolved += 1
            counts[availability] += 1
            cells.append(
                {
                    "availability": availability,
                    "endpoint_evidence": endpoint_evidence,
                    "implementation": implementation,
                    "live_evidence": "representative-profile-core-flow-only",
                    "request_shape_evidence": request_evidence,
                    "response_fixture_evidence": "representative-profile-serde-fixtures-only",
                }
            )

        documented = counts["documented"]
        resolved = counts["typed"] + counts["typed-gated"] + counts["security-blocked"]
        if documented != resolved:
            raise ContractError("profile contains an unexplained documented operation")
        profiles.append(
            {
                "cells": cells,
                "live_evidence": {
                    "claim": "representative core flows only; not every endpoint",
                    "operation_ids": [item["id"] for item in live_operations],
                    "status": "passed",
                },
                "response_fixture_evidence": {
                    "claim": "reviewed response families only; not every endpoint",
                    "families": list(RESPONSE_FAMILIES),
                    "openapi_sha256": fixture_profile["openapi_sha256"],
                    "status": "passed",
                },
                "summary": {
                    "classified_coverage_basis_points": percent_basis_points(resolved, documented),
                    "documented": documented,
                    "security_blocked": counts["security-blocked"],
                    "typed": counts["typed"],
                    "typed_gated": counts["typed-gated"],
                    "unavailable": counts["unavailable"],
                },
                "version": version,
            }
        )

    cell_count = len(versions) * len(operations)
    matrix = {
        "evidence_sources": {
            "capability_registry_sha256": sha256(registry_bytes),
            "core_flow_results_sha256": sha256(core_bytes),
            "request_compatibility_sha256": sha256(request_bytes),
            "response_fixture_manifest_sha256": sha256(fixture_bytes),
            "response_fixture_tests_sha256": sha256(response_test_bytes),
        },
        "operations": operation_records,
        "profiles": profiles,
        "scope": EXPECTED_SCOPE,
        "schema": "openbao-version-contract-matrix/v1",
        "summary": {
            "cell_count": cell_count,
            "classified_cell_coverage_basis_points": percent_basis_points(cell_count, cell_count),
            "documented_cell_count": total_documented,
            "operation_count": len(operations),
            "profile_count": len(versions),
            "resolved_documented_cell_count": total_resolved,
        },
    }
    validate_matrix(matrix, versions)
    return matrix


def validate_matrix(matrix: dict[str, Any], expected_versions: list[str]) -> None:
    if set(matrix) != {"evidence_sources", "operations", "profiles", "scope", "schema", "summary"}:
        raise ContractError("version contract top-level fields are invalid")
    if matrix["schema"] != "openbao-version-contract-matrix/v1":
        raise ContractError("version contract schema is invalid")
    if matrix["scope"] != EXPECTED_SCOPE:
        raise ContractError("version contract evidence boundary changed")
    evidence_sources = matrix["evidence_sources"]
    if (
        not isinstance(evidence_sources, dict)
        or set(evidence_sources)
        != {
            "capability_registry_sha256", "core_flow_results_sha256",
            "request_compatibility_sha256", "response_fixture_manifest_sha256",
            "response_fixture_tests_sha256",
        }
        or any(
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in evidence_sources.values()
        )
    ):
        raise ContractError("version contract evidence source identities are invalid")
    operations = matrix["operations"]
    profiles = matrix["profiles"]
    if not isinstance(operations, list) or len(operations) != 666:
        raise ContractError("version contract operation count is invalid")
    if not isinstance(profiles, list) or [item.get("version") for item in profiles] != expected_versions:
        raise ContractError("version contract profile order is invalid")
    identifiers = [item.get("id") for item in operations]
    if identifiers != sorted(set(identifiers)):
        raise ContractError("version contract operation identities are invalid")
    for operation in operations:
        if set(operation) != {"disposition", "id", "method", "path_template"}:
            raise ContractError("version contract operation fields are invalid")
        if operation["disposition"] not in ALLOWED_DISPOSITIONS:
            raise ContractError("version contract operation is unresolved")
    documented_cells = 0
    resolved_cells = 0
    for profile in profiles:
        cells = profile.get("cells")
        if not isinstance(cells, list) or len(cells) != len(operations):
            raise ContractError("version contract profile has a missing operation cell")
        counts: Counter[str] = Counter()
        for operation, cell in zip(operations, cells, strict=True):
            if set(cell) != {
                "availability", "endpoint_evidence", "implementation", "live_evidence",
                "request_shape_evidence", "response_fixture_evidence",
            }:
                raise ContractError("version contract cell fields are invalid")
            if any(value in FORBIDDEN_STATES for value in cell.values() if isinstance(value, str)):
                raise ContractError("version contract cell contains a forbidden state")
            if cell["live_evidence"] != "representative-profile-core-flow-only" or cell["response_fixture_evidence"] != "representative-profile-serde-fixtures-only":
                raise ContractError("operation cell overstates representative evidence")
            if cell["availability"] == "documented":
                documented_cells += 1
                counts["documented"] += 1
                if cell["implementation"] != operation["disposition"]:
                    raise ContractError("documented operation disposition is contradictory")
                if cell["request_shape_evidence"] == "not-applicable-route-unavailable":
                    raise ContractError("documented operation lacks request evidence")
                if cell["endpoint_evidence"] == "none":
                    raise ContractError("documented operation lacks endpoint evidence")
                counts[cell["implementation"]] += 1
                resolved_cells += 1
            elif cell["availability"] == "unavailable":
                counts["unavailable"] += 1
                if cell["implementation"] != "not-applicable" or cell["request_shape_evidence"] != "not-applicable-route-unavailable":
                    raise ContractError("unavailable operation cell is contradictory")
                if cell["endpoint_evidence"] != "none":
                    raise ContractError("unavailable operation claims positive endpoint evidence")
            else:
                raise ContractError("version contract availability is invalid")
        summary = profile.get("summary")
        expected_summary = {
            "classified_coverage_basis_points": 10_000,
            "documented": counts["documented"],
            "security_blocked": counts["security-blocked"],
            "typed": counts["typed"],
            "typed_gated": counts["typed-gated"],
            "unavailable": counts["unavailable"],
        }
        if summary != expected_summary:
            raise ContractError("profile coverage is incomplete")
        live = profile.get("live_evidence")
        response = profile.get("response_fixture_evidence")
        if live != {
            "claim": "representative core flows only; not every endpoint",
            "operation_ids": list(CORE_OPERATION_IDS),
            "status": "passed",
        }:
            raise ContractError("profile live evidence is incomplete or overstated")
        if (
            not isinstance(response, dict)
            or response.get("claim") != "reviewed response families only; not every endpoint"
            or response.get("families") != list(RESPONSE_FAMILIES)
            or response.get("status") != "passed"
            or not isinstance(response.get("openapi_sha256"), str)
            or len(response["openapi_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in response["openapi_sha256"])
        ):
            raise ContractError("profile representative evidence is not passing")
    summary = matrix["summary"]
    expected_cells = len(operations) * len(profiles)
    if summary != {
        "cell_count": expected_cells,
        "classified_cell_coverage_basis_points": 10_000,
        "documented_cell_count": documented_cells,
        "operation_count": len(operations),
        "profile_count": len(profiles),
        "resolved_documented_cell_count": resolved_cells,
    }:
        raise ContractError("version contract aggregate summary is inconsistent")
    if documented_cells != resolved_cells:
        raise ContractError("version contract has unresolved documented cells")


def markdown(matrix: dict[str, Any]) -> bytes:
    lines = [
        "# OpenBao Version Support Matrix",
        "",
        "This table is generated from committed compatibility evidence. `100.00%` means",
        "every documented operation for that exact profile is classified as typed,",
        "typed-gated, or security-blocked. It does not mean every operation was exercised",
        "live. Live tests cover eight representative built-in core flows; serde fixtures",
        "cover five representative response families.",
        "",
        "| OpenBao | Documented operations | Typed | Typed-gated | Security-blocked | Unavailable inventory operations | Classified coverage | Live core flows | Response fixture families |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for profile in matrix["profiles"]:
        summary = profile["summary"]
        lines.append(
            f"| `{profile['version']}` | {summary['documented']} | {summary['typed']} | "
            f"{summary['typed_gated']} | {summary['security_blocked']} | {summary['unavailable']} | "
            f"{summary['classified_coverage_basis_points'] / 100:.2f}% | "
            f"{len(profile['live_evidence']['operation_ids'])} | "
            f"{len(profile['response_fixture_evidence']['families'])} |"
        )
    lines.extend(
        [
            "",
            "## Evidence Boundary",
            "",
            "- Endpoint presence and request-shape evidence comes from exact tagged",
            "  documentation, locked normalized OpenAPI, and reviewed current-contract",
            "  corrections.",
            "- Destructive live tests run only against a fresh ephemeral OpenBao server for",
            "  the selected exact release.",
            "- No external database, directory, cloud, OIDC, MFA, DNS, or message-broker",
            "  service is exercised by the historical core matrix.",
            "- The complete machine-readable operation/profile cells are in",
            "  `compat/version-contract-matrix.json`.",
            "- Compatibility evidence is not a security endorsement of an old OpenBao",
            "  release. Deploy the newest reviewed patch whenever possible.",
            "",
        ]
    )
    return "\n".join(lines).encode()


def outputs() -> dict[Path, bytes]:
    matrix = build_matrix()
    return {MATRIX_PATH: canonical_json(matrix), MARKDOWN_PATH: markdown(matrix)}


def atomic_write(path: Path, data: bytes) -> None:
    if (
        len(data) > MAX_OUTPUT_BYTES
        or path.is_symlink()
        or any(parent.is_symlink() for parent in path.parents if parent != ROOT.parent)
    ):
        raise ContractError("version contract output path or size is unsafe")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not stat.S_ISREG(path.lstat().st_mode):
        raise ContractError("version contract output is not a regular file")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def expected_hashes() -> dict[Path, str]:
    return {MATRIX_PATH: EXPECTED_MATRIX_SHA256, MARKDOWN_PATH: EXPECTED_MARKDOWN_SHA256}


def verify_outputs() -> None:
    for path, expected in outputs().items():
        if sha256(expected) != expected_hashes()[path]:
            raise ContractError("generated version contract checksum is not anchored")
        if read_regular_file(path, MAX_OUTPUT_BYTES) != expected:
            raise ContractError("generated version contract output is stale")


def self_test() -> None:
    generated = build_matrix()
    versions = [profile["version"] for profile in generated["profiles"]]

    def rejected(label: str, mutation: dict[str, Any]) -> None:
        try:
            validate_matrix(mutation, versions)
        except ContractError:
            return
        raise ContractError(f"version contract self-test accepted {label}")

    missing = copy.deepcopy(generated)
    missing["profiles"][0]["cells"].pop()
    rejected("a missing operation/profile cell", missing)
    false_green = copy.deepcopy(generated)
    false_green["profiles"][0]["live_evidence"]["status"] = "passed-with-skips"
    rejected("a false-green live status", false_green)
    unresolved = copy.deepcopy(generated)
    unresolved["operations"][0]["disposition"] = "planned"
    rejected("an unresolved operation", unresolved)
    contradictory = copy.deepcopy(generated)
    contradictory["profiles"][0]["cells"][0]["availability"] = "unavailable"
    rejected("a contradictory availability cell", contradictory)
    forged_percentage = copy.deepcopy(generated)
    forged_percentage["profiles"][0]["summary"]["typed"] += 1
    rejected("a forged profile percentage input", forged_percentage)
    overstated_scope = copy.deepcopy(generated)
    overstated_scope["scope"]["external_services_proven"] = ["database"]
    rejected("an overstated external-service claim", overstated_scope)

    encoded = canonical_json(generated)
    parsed_mutations = 0
    rejected_mutations = 0
    # The full matrix is multi-megabyte. Sixteen evenly distributed mutations
    # exercise bounded decoding without turning every release gate into an
    # unbounded parser benchmark.
    for mutation in deterministic_byte_mutations(encoded, 16):
        try:
            candidate = parse_json(mutation, MAX_OUTPUT_BYTES)
        except SnapshotError:
            rejected_mutations += 1
            continue
        parsed_mutations += 1
        try:
            validate_matrix(candidate, versions)
        except (ContractError, KeyError, TypeError, ValueError):
            rejected_mutations += 1
            continue
        if candidate != generated:
            # A structurally valid mutation still fails the externally anchored
            # byte-for-byte verification performed by verify_outputs().
            if sha256(mutation) == EXPECTED_MATRIX_SHA256:
                raise ContractError("mutated version contract matched the anchored digest")
            rejected_mutations += 1
    if parsed_mutations == 0 or rejected_mutations == 0:
        raise ContractError("version contract mutation corpus was ineffective")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true")
    action.add_argument("--verify", action="store_true")
    action.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.self_test:
            self_test()
            print("OpenBao version contracts self-tests: ok")
        elif arguments.verify:
            verify_outputs()
            print("OpenBao version contracts: 13,986 cells verified")
        else:
            generated = outputs()
            for path, data in generated.items():
                if sha256(data) != expected_hashes()[path]:
                    raise ContractError("refusing to write an unanchored version contract")
                atomic_write(path, data)
            print("OpenBao version contracts: wrote 13,986 cells")
        return 0
    except (ContractError, SnapshotError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"OpenBao version contracts failed: {error}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
