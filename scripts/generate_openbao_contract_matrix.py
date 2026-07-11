#!/usr/bin/env python3
"""Capture, generate, and verify the exact OpenBao 2.5.5 contract backlog."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import io
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from openbao_api_snapshots import (
    SnapshotError,
    read_regular_file,
    run_bounded,
    validate_text,
)

ROOT = Path(__file__).resolve().parents[1]
TAGGED_SNAPSHOT = ROOT / "compat/api-snapshots/2.5.5/documentation.json"
OPENAPI_SNAPSHOT = ROOT / "compat/api-snapshots/2.5.5/openapi.json"
LEGACY_MATRIX = ROOT / "docs/openbao-2.5-endpoint-matrix.csv"
EVIDENCE_PATH = ROOT / "compat/api-contracts/2.5.5-tagged-contract.json"
MATRIX_JSON = ROOT / "docs/openbao-2.5-contract-matrix.json"
MATRIX_CSV = ROOT / "docs/openbao-2.5-endpoint-matrix.csv"
MATRIX_MD = ROOT / "docs/OPENBAO_2_5_ENDPOINT_MATRIX.md"

SOURCE_COMMIT = "028992583c693c4de6350b8aa52ff85e30375a99"
EXPECTED_DOC_FILES = 115
EXPECTED_RAW_ROWS = 651
EXPECTED_ROWS = 644
EXPECTED_EXPANDED_OPERATIONS = 663
EXPECTED_TAGGED_SNAPSHOT_SHA256 = "511d18f9bf894cba50c857c247cf3a22b8fd3529144039f27c3552209557be63"
EXPECTED_OPENAPI_SNAPSHOT_SHA256 = "e959918796dd3b67b1ecd3562841e949d1db35af278d3519622cc690b0c696d4"
EXPECTED_EVIDENCE_SHA256 = "1813d10fb9fdc0df7231035d391d5af288f0ba443ed105cb3816e7269557eab4"
EXPECTED_OUTPUT_SHA256 = {
    "docs/openbao-2.5-contract-matrix.json": "18b388265de2a834198f979c48d33919adee0d70232d452c659d5e99a269584e",
    "docs/openbao-2.5-endpoint-matrix.csv": "80706c4ceb7263ad85c8dcf592f2e96b62229efa29e0cc3cb8582c9156188072",
    "docs/OPENBAO_2_5_ENDPOINT_MATRIX.md": "742238404d61215d46cf8ff90067997d6d1e045cc2afc9067a49cd1636a2bfd7",
}
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_FIELDS = 8_192
MAX_TEXT_BYTES = 4_096
METHOD_ORDER = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "LIST", "SCAN", "ACME")
HTTP_METHODS = {"GET": "get", "HEAD": "head", "POST": "post", "PUT": "put", "PATCH": "patch", "DELETE": "delete"}
METHOD_ROW = re.compile(
    r"^\s*\|\s*`((?:GET|HEAD|POST|PUT|PATCH|DELETE|LIST|SCAN|ACME)(?:/(?:GET|HEAD|POST|PUT|PATCH|DELETE|LIST|SCAN|ACME))*)`\s*\|\s*`([^`]{1,4096})`",
    re.ASCII,
)
HEADING = re.compile(r"^(#{2,6})\s+(.{1,512}?)\s*$")
FIELD_ROW = re.compile(r"^\s*[-*]\s+`([^`]{1,256})`\s+`\(([^`]{1,512})\)`")
INCLUDE_ROW = re.compile(r"^\s*@include\s+['\"]([^'\"]{1,256})['\"]\s*$", re.ASCII)
OPTIONAL_SEGMENT = re.compile(r"\(/:([A-Za-z0-9_-]{1,128})\)")
PLACEHOLDER = re.compile(r"^(?::[^/]+|\{[^/]+\}|\([^/]+\))$")

# These two tagged PKI rows are authored relative to the PKI mount even though
# their leading slash makes them appear absolute. The exact OpenAPI and live
# route use the mounted `/pki/certs/...` form.
DOCUMENTATION_PATH_CORRECTIONS = {
    "/certs/revocation-queue": "/pki/certs/revocation-queue",
    "/certs/revoked": "/pki/certs/revoked",
}

# Confirmed operation gaps from the source audit. Previous non-strict rows are
# also gaps; everything else remains unverified until a helper and test are
# linked explicitly in a later compatibility commit.
CONFIRMED_FALSE_TYPED = frozenset(
    line.strip()
    for line in """
""".splitlines()
    if line.strip()
)

SYSTEM_DISPOSITION_OVERRIDES = {
    "HEAD /sys/health": "typed",
    "LIST /sys/config/ui/headers": "typed-gated",
    "DELETE /sys/config/ui/headers/:name": "typed-gated",
    "GET /sys/config/ui/headers/:name": "typed-gated",
    "POST /sys/config/ui/headers/:name": "typed-gated",
    "GET /sys/internal/counters/entities": "typed-gated",
    "GET /sys/internal/counters/tokens": "typed-gated",
    "GET /sys/internal/inspect/request/root": "typed-gated",
    "GET /sys/internal/inspect/router/accessor": "typed-gated",
    "GET /sys/internal/inspect/router/root": "typed-gated",
    "GET /sys/internal/inspect/router/storage": "typed-gated",
    "GET /sys/internal/inspect/router/uuid": "typed-gated",
    "GET /sys/monitor": "omitted",
}

AUTH_DISPOSITION_OVERRIDES = {
    "GET /auth/token/lookup-self": "typed",
    "GET/POST /identity/oidc/provider/:name/authorize": "typed",
    "POST /identity/oidc/provider/:name/token": "typed",
    "POST /identity/oidc/provider/:name/userinfo": "typed",
}

SECRET_DISPOSITION_OVERRIDES = {
    "SCAN /secret/:path": "typed",
    "GET /:secret-mount-path/subkeys/:path": "typed",
    "SCAN /:secret-mount-path/metadata/:path": "typed",
    "LIST /:secret-mount-path/detailed-metadata/:path": "typed",
    "SCAN /:secret-mount-path/detailed-metadata/:path": "typed",
    "GET /ssh/public_key": "typed",
    "GET /ssh/issuer/:issuer_ref/public_key": "typed",
}

PKI_DISPOSITION_OVERRIDES = {
    "ACME /pki/acme/directory": "typed-gated",
    "ACME /pki/issuer/:issuer_ref/acme/directory": "typed-gated",
    "ACME /pki/issuer/:issuer_ref/roles/:role/acme/directory": "typed-gated",
    "ACME /pki/roles/:role/acme/directory": "typed-gated",
    "GET /pki/ca": "typed",
    "GET /pki/ca/pem": "typed",
    "GET /pki/ca_chain": "typed",
    "GET /pki/cert/:serial/raw": "typed",
    "GET /pki/cert/:serial/raw/pem": "typed",
    "GET /pki/cert/ca": "typed",
    "GET /pki/cert/ca_chain": "typed",
    "GET /pki/cert/crl": "typed",
    "GET /pki/cert/delta-crl": "typed",
    "GET /pki/crl": "typed",
    "GET /pki/crl/delta": "typed",
    "GET /pki/crl/delta/pem": "typed",
    "GET /pki/crl/pem": "typed",
    "GET /pki/crl/rotate": "typed",
    "GET /pki/crl/rotate-delta": "typed",
    "GET /pki/issuer/:issuer_ref/crl": "typed",
    "GET /pki/issuer/:issuer_ref/crl/delta": "typed",
    "GET /pki/issuer/:issuer_ref/crl/delta/der": "typed",
    "GET /pki/issuer/:issuer_ref/crl/delta/pem": "typed",
    "GET /pki/issuer/:issuer_ref/crl/der": "typed",
    "GET /pki/issuer/:issuer_ref/crl/pem": "typed",
    "GET /pki/issuer/:issuer_ref/der": "typed",
    "GET /pki/issuer/:issuer_ref/json": "typed",
    "GET /pki/issuer/:issuer_ref/pem": "typed",
    "GET /pki/ocsp/<base 64+URL encoded ocsp DER request>": "typed",
    "POST /pki/ocsp": "typed",
}


class ContractError(RuntimeError):
    """Contract evidence or generated matrix is invalid."""


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path, maximum: int = MAX_INPUT_BYTES) -> dict[str, Any]:
    try:
        value = json.loads(read_regular_file(path, maximum))
    except (OSError, ValueError, SnapshotError) as error:
        raise ContractError("contract input is unreadable or malformed") from error
    if not isinstance(value, dict):
        raise ContractError("contract input must be a JSON object")
    return value


def require_hash(path: Path, expected: str, maximum: int = MAX_INPUT_BYTES) -> bytes:
    try:
        data = read_regular_file(path, maximum)
    except (OSError, SnapshotError) as error:
        raise ContractError("anchored contract input is missing or unsafe") from error
    if sha256(data) != expected:
        raise ContractError("anchored contract input checksum mismatch")
    return data


def git_bytes(repository: Path, arguments: list[str], maximum: int) -> bytes:
    try:
        _, output = run_bounded(
            ["git", "-C", str(repository), *arguments], maximum, timeout=60
        )
    except SnapshotError as error:
        raise ContractError("exact tagged source could not be read") from error
    return output


def normalize_path(path: str) -> tuple[str, str]:
    path = path.strip().replace("\\|", "|")
    validate_text(path, "contract path", MAX_TEXT_BYTES)
    style = "absolute"
    if not path.startswith("/"):
        path = "/" + path
        style = "relative-normalized"
    return path, style


def expand_includes(lines: list[str], partials: dict[str, str]) -> list[str]:
    expanded: list[str] = []
    for line in lines:
        match = INCLUDE_ROW.match(line)
        if match is None:
            expanded.append(line)
            continue
        name = match.group(1)
        if "/" in name or name not in partials:
            raise ContractError("documentation include is unresolved")
        expanded.extend(partials[name].splitlines())
    return expanded


def json_field_paths(value: Any, prefix: str = "") -> set[str]:
    fields: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractError("sample response contains a non-string key")
            path = f"{prefix}.{key}" if prefix else key
            fields.add(path)
            fields.update(json_field_paths(item, path))
    elif isinstance(value, list) and value:
        fields.update(json_field_paths(value[0], f"{prefix}[]"))
    return fields


def sample_response_fields(lines: list[str]) -> tuple[list[str], list[str]]:
    fields: set[str] = set()
    errors: list[str] = []
    section = ""
    in_json = False
    buffer: list[str] = []
    for line in lines:
        heading = HEADING.match(line)
        if heading is not None:
            section = heading.group(2).strip().lower()
        if not in_json and line.strip().lower() == "```json" and "response" in section:
            in_json = True
            buffer = []
            continue
        if in_json and line.strip() == "```":
            in_json = False
            try:
                parsed = json.loads("\n".join(buffer))
                fields.update(json_field_paths(parsed))
            except (ValueError, ContractError):
                errors.append("sample-response-json-requires-manual-review")
            continue
        if in_json:
            if sum(len(item.encode()) for item in buffer) > 256 * 1024:
                raise ContractError("sample response exceeds its byte limit")
            buffer.append(line)
    if in_json:
        errors.append("unterminated-sample-response-json")
    return sorted(fields), sorted(set(errors))


def parse_block(source: str, lines: list[str], partials: dict[str, str]) -> list[dict[str, Any]]:
    if not lines:
        return []
    heading_match = HEADING.match(lines[0])
    if heading_match is None or len(heading_match.group(1)) != 2:
        return []
    heading = validate_text(heading_match.group(2).strip(), "operation heading", 512)
    expanded = expand_includes(lines, partials)
    section = "body"
    parameters: list[dict[str, str]] = []
    endpoint_rows: list[tuple[list[str], str, str]] = []
    for line in expanded[1:]:
        heading_row = HEADING.match(line)
        if heading_row is not None:
            section = heading_row.group(2).strip().lower().replace(" ", "-")[:128]
            continue
        field = FIELD_ROW.match(line)
        if field is not None:
            if len(parameters) >= MAX_FIELDS:
                raise ContractError("documented parameter count exceeds its limit")
            parameters.append(
                {
                    "name": validate_text(field.group(1).strip(), "parameter name", 256),
                    "section": section,
                    "signature": validate_text(field.group(2).strip(), "parameter signature", 512),
                }
            )
        endpoint = METHOD_ROW.match(line)
        if endpoint is None:
            continue
        methods = endpoint.group(1).split("/")
        if len(methods) != len(set(methods)) or any(method not in METHOD_ORDER for method in methods):
            raise ContractError("documented method group is invalid")
        path, style = normalize_path(endpoint.group(2))
        endpoint_rows.append((methods, path, style))
    response_fields, response_errors = sample_response_fields(expanded)
    return [
        {
            "heading": heading,
            "methods": methods,
            "parameters": copy.deepcopy(parameters),
            "path": path,
            "path_style": style,
            "sample_response_fields": response_fields,
            "sample_response_review": response_errors,
            "source": source,
        }
        for methods, path, style in endpoint_rows
    ]


def parse_document(source: str, text: str, partials: dict[str, str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    block: list[str] = []
    preamble: list[str] = []
    title = source.rsplit("/", 1)[-1].removesuffix(".mdx")
    found_section = False
    for line in text.splitlines():
        if line.startswith("# "):
            title = line.removeprefix("# ").strip()
        if line.startswith("## "):
            if not found_section and any(METHOD_ROW.match(item) for item in preamble):
                rows.extend(parse_block(source, [f"## {title}", *preamble], partials))
            found_section = True
            rows.extend(parse_block(source, block, partials))
            block = [line]
        elif block:
            block.append(line)
        elif not found_section:
            preamble.append(line)
    if not found_section and any(METHOD_ROW.match(item) for item in preamble):
        rows.extend(parse_block(source, [f"## {title}", *preamble], partials))
    rows.extend(parse_block(source, block, partials))
    return rows


def legacy_index() -> dict[tuple[tuple[str, ...], str], dict[str, str]]:
    if EVIDENCE_PATH.exists() or EVIDENCE_PATH.is_symlink():
        require_hash(EVIDENCE_PATH, EXPECTED_EVIDENCE_SHA256)
        evidence = load_json(EVIDENCE_PATH)
        result = {
            (tuple(row["methods"]), row["path"]): copy.deepcopy(row["legacy_matrix"])
            for row in evidence.get("operations", [])
        }
        if len(result) != EXPECTED_ROWS:
            raise ContractError("anchored legacy classification inventory changed")
        return result
    try:
        raw = read_regular_file(LEGACY_MATRIX, 4 * 1024 * 1024).decode("utf-8")
    except (OSError, UnicodeDecodeError, SnapshotError) as error:
        raise ContractError("legacy identity matrix is unreadable") from error
    result: dict[tuple[tuple[str, ...], str], dict[str, str]] = {}
    for row in csv.DictReader(io.StringIO(raw)):
        try:
            methods = tuple(row["method"].split("/"))
            path, _ = normalize_path(row["path"])
        except (KeyError, AttributeError) as error:
            raise ContractError("legacy identity matrix schema changed") from error
        key = (methods, path)
        if key in result:
            raise ContractError("legacy identity matrix contains a duplicate row")
        result[key] = {"status": row["status"], "note": row["note"]}
    if len(result) != 643:
        raise ContractError("legacy identity matrix row count changed")
    return result


def capture_source(repository: Path) -> dict[str, Any]:
    commit = git_bytes(repository, ["rev-parse", "HEAD"], 128).decode().strip()
    if commit != SOURCE_COMMIT:
        raise ContractError("source repository is not the locked OpenBao 2.5.5 commit")
    require_hash(TAGGED_SNAPSHOT, EXPECTED_TAGGED_SNAPSHOT_SHA256)
    snapshot = load_json(TAGGED_SNAPSHOT)
    expected_files = {item["path"]: item for item in snapshot.get("files", [])}
    if len(expected_files) != EXPECTED_DOC_FILES:
        raise ContractError("tagged snapshot file inventory changed")
    tree = git_bytes(
        repository,
        ["ls-tree", "-r", "--name-only", SOURCE_COMMIT, "website/content/api-docs"],
        512 * 1024,
    ).decode()
    paths = [line for line in tree.splitlines() if line.endswith(".mdx")]
    if paths != sorted(expected_files):
        raise ContractError("tagged source files do not match the anchored snapshot")

    partial_names: set[str] = set()
    texts: dict[str, str] = {}
    files: list[dict[str, Any]] = []
    for path in paths:
        blob = git_bytes(repository, ["show", f"{SOURCE_COMMIT}:{path}"], 2 * 1024 * 1024)
        record = expected_files[path]
        object_id = git_bytes(
            repository, ["rev-parse", f"{SOURCE_COMMIT}:{path}"], 128
        ).decode().strip()
        if (
            len(blob) != record["bytes"]
            or sha256(blob) != record["sha256"]
            or object_id != record["blob_sha1"]
        ):
            raise ContractError("tagged source blob does not match anchored evidence")
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ContractError("tagged source is not UTF-8") from error
        texts[path] = text
        for line in text.splitlines():
            include = INCLUDE_ROW.match(line)
            if include is not None:
                partial_names.add(include.group(1))
        files.append(copy.deepcopy(record))

    partials: dict[str, str] = {}
    partial_records: list[dict[str, Any]] = []
    for name in sorted(partial_names):
        if "/" in name:
            raise ContractError("documentation include path is unsafe")
        path = f"website/content/partials/{name}"
        blob = git_bytes(repository, ["show", f"{SOURCE_COMMIT}:{path}"], 512 * 1024)
        try:
            partials[name] = blob.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ContractError("documentation partial is not UTF-8") from error
        partial_records.append(
            {
                "bytes": len(blob),
                "path": path,
                "sha256": sha256(blob),
            }
        )

    raw_rows: list[dict[str, Any]] = []
    for path in paths:
        raw_rows.extend(parse_document(path, texts[path], partials))
    if len(raw_rows) != EXPECTED_RAW_ROWS:
        raise ContractError("tagged documentation raw operation count changed")

    grouped: dict[tuple[tuple[str, ...], str], dict[str, Any]] = {}
    for row in raw_rows:
        key = (tuple(row["methods"]), row["path"])
        record = grouped.setdefault(
            key,
            {
                "methods": row["methods"],
                "path": row["path"],
                "variants": [],
            },
        )
        variant = {key: value for key, value in row.items() if key not in ("methods", "path")}
        if variant not in record["variants"]:
            record["variants"].append(variant)
    operations = sorted(grouped.values(), key=lambda item: (item["path"], item["methods"]))
    if len(operations) != EXPECTED_ROWS:
        raise ContractError("tagged documentation unique row count changed")
    expanded = {(method, row["path"]) for row in operations for method in row["methods"]}
    if len(expanded) != EXPECTED_EXPANDED_OPERATIONS:
        raise ContractError("tagged documentation expanded operation count changed")

    legacy = legacy_index()
    for row in operations:
        key = (tuple(row["methods"]), row["path"])
        prior = legacy.get(key)
        row["legacy_matrix"] = (
            prior
            if prior is not None
            else {"status": "omitted", "note": "The legacy matrix omitted this tagged row."}
        )

    return {
        "schema": "openbao-tagged-contract-evidence/v1",
        "version": "2.5.5",
        "source_commit_sha1": SOURCE_COMMIT,
        "files": files,
        "partials": partial_records,
        "raw_documented_rows": len(raw_rows),
        "unique_documented_rows": len(operations),
        "expanded_operations": len(expanded),
        "operations": operations,
    }


def path_variants(path: str) -> list[str]:
    base = path.split("?", 1)[0]
    variants = {base}
    while True:
        changed = False
        for value in list(variants):
            match = OPTIONAL_SEGMENT.search(value)
            if match is None:
                continue
            variants.remove(value)
            variants.add(value[: match.start()] + value[match.end() :])
            variants.add(value[: match.start()] + "/:" + match.group(1) + value[match.end() :])
            changed = True
        if not changed:
            break
    return sorted(variants)


def path_segments(path: str) -> list[str]:
    stripped = path.strip("/")
    return [] if not stripped else stripped.split("/")


def normalized_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def path_score(documented: str, candidate: str, source: str) -> int | None:
    left = path_segments(documented)
    right = path_segments(candidate)
    if len(left) != len(right):
        return None
    source_tokens = {normalized_token(item) for item in source.removesuffix(".mdx").split("/")}
    score = 0
    for expected, actual in zip(left, right):
        expected_var = PLACEHOLDER.match(expected) is not None
        actual_var = PLACEHOLDER.match(actual) is not None
        if expected == actual:
            score += 100
        elif expected_var and actual_var:
            score += 20
        elif actual_var:
            variable = normalized_token(actual)
            token = normalized_token(expected)
            if token and token in variable:
                score += 80
            elif any(item and item in variable for item in source_tokens):
                score += 60
            else:
                score += 5
        elif expected_var:
            score += 10
        else:
            return None
    return score


def method_operation(method: str, path_item: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    if method in HTTP_METHODS:
        key = HTTP_METHODS[method]
        value = path_item.get(key)
        return (key, value) if isinstance(value, dict) else None
    if method in ("LIST", "SCAN"):
        value = path_item.get("get")
        if not isinstance(value, dict):
            return None
        names = {
            item.get("name")
            for item in value.get("parameters", [])
            if isinstance(item, dict)
        }
        expected = "list" if method == "LIST" else "scan"
        if expected not in names:
            return None
        return "get", value
    return None


def resolve_schema(
    schema: Any,
    schemas: dict[str, Any],
    prefix: str = "",
    seen: frozenset[str] = frozenset(),
    depth: int = 0,
) -> tuple[list[dict[str, Any]], list[str]]:
    if depth > 16:
        return [], ["schema-depth-limit"]
    if not isinstance(schema, dict):
        return [], ["non-object-schema"]
    reference = schema.get("$ref")
    if isinstance(reference, str):
        marker = "#/components/schemas/"
        if not reference.startswith(marker):
            return [], ["external-schema-reference"]
        name = reference.removeprefix(marker)
        if name in seen or name not in schemas:
            return [], ["cyclic-or-missing-schema-reference"]
        return resolve_schema(schemas[name], schemas, prefix, seen | {name}, depth + 1)
    fields: list[dict[str, Any]] = []
    review: list[str] = []
    for composition in ("allOf", "oneOf", "anyOf"):
        values = schema.get(composition)
        if isinstance(values, list):
            for value in values:
                nested, nested_review = resolve_schema(value, schemas, prefix, seen, depth + 1)
                fields.extend(nested)
                review.extend(nested_review)
    properties = schema.get("properties")
    required = set(schema.get("required", [])) if isinstance(schema.get("required"), list) else set()
    if isinstance(properties, dict):
        for name, value in sorted(properties.items()):
            if not isinstance(name, str) or not isinstance(value, dict):
                review.append("malformed-schema-property")
                continue
            path = f"{prefix}.{name}" if prefix else name
            fields.append(
                {
                    "path": path,
                    "required": name in required,
                    "schema": {
                        key: copy.deepcopy(value[key])
                        for key in ("type", "format", "enum", "default", "deprecated")
                        if key in value
                    },
                    "coverage": "unverified",
                    "crate_field": None,
                    "secret_classification": "unreviewed",
                }
            )
            nested, nested_review = resolve_schema(value, schemas, path, seen, depth + 1)
            fields.extend(nested)
            review.extend(nested_review)
    items = schema.get("items")
    if isinstance(items, dict):
        nested, nested_review = resolve_schema(items, schemas, prefix + "[]", seen, depth + 1)
        fields.extend(nested)
        review.extend(nested_review)
    unique = {item["path"]: item for item in fields}
    if len(unique) > MAX_FIELDS:
        raise ContractError("OpenAPI schema field count exceeds its limit")
    return [unique[key] for key in sorted(unique)], sorted(set(review))


def openapi_contract(
    method: str,
    path: str,
    source: str,
    paths: dict[str, Any],
    schemas: dict[str, Any],
) -> dict[str, Any]:
    candidates: list[tuple[int, str, str, dict[str, Any], dict[str, Any]]] = []
    for candidate_path, path_item in paths.items():
        if not isinstance(candidate_path, str) or not isinstance(path_item, dict):
            continue
        operation_pair = method_operation(method, path_item)
        if operation_pair is None:
            continue
        operation_method, operation = operation_pair
        scores = [path_score(variant, candidate_path, source) for variant in path_variants(path)]
        scores = [score for score in scores if score is not None]
        if scores:
            candidates.append((max(scores), candidate_path, operation_method, operation, path_item))
    if not candidates:
        return {"match": "absent", "candidates": []}
    best = max(item[0] for item in candidates)
    selected = [item for item in candidates if item[0] == best]
    if len(selected) != 1:
        return {
            "match": "ambiguous",
            "candidates": [item[1] for item in sorted(selected, key=lambda item: item[1])],
        }
    _, matched_path, operation_method, operation, path_item = selected[0]
    parameters = []
    for parameter in [*path_item.get("parameters", []), *operation.get("parameters", [])]:
        if not isinstance(parameter, dict):
            continue
        parameters.append(
            {
                "name": parameter.get("name"),
                "in": parameter.get("in"),
                "required": parameter.get("required", False),
                "schema": copy.deepcopy(parameter.get("schema", {})),
                "coverage": "unverified",
                "crate_field": None,
                "secret_classification": "unreviewed",
            }
        )
    request_fields: list[dict[str, Any]] = []
    response_fields: list[dict[str, Any]] = []
    schema_review: list[str] = []
    request_media: set[str] = set()
    response_media: set[str] = set()
    request_schemas: set[str] = set()
    response_schemas: set[str] = set()
    request_body = operation.get("requestBody", {})
    if isinstance(request_body, dict):
        for media, value in request_body.get("content", {}).items():
            if not isinstance(media, str) or not isinstance(value, dict):
                continue
            request_media.add(media)
            schema = value.get("schema", {})
            reference = schema.get("$ref") if isinstance(schema, dict) else None
            if isinstance(reference, str):
                request_schemas.add(reference.rsplit("/", 1)[-1])
            fields, review = resolve_schema(schema, schemas)
            request_fields.extend(fields)
            schema_review.extend(review)
    responses = operation.get("responses", {})
    if isinstance(responses, dict):
        for response in responses.values():
            if not isinstance(response, dict):
                continue
            for media, value in response.get("content", {}).items():
                if not isinstance(media, str) or not isinstance(value, dict):
                    continue
                response_media.add(media)
                schema = value.get("schema", {})
                reference = schema.get("$ref") if isinstance(schema, dict) else None
                if isinstance(reference, str):
                    response_schemas.add(reference.rsplit("/", 1)[-1])
                fields, review = resolve_schema(schema, schemas)
                response_fields.extend(fields)
                schema_review.extend(review)
    request_fields = list({item["path"]: item for item in request_fields}.values())
    response_fields = list({item["path"]: item for item in response_fields}.values())
    return {
        "match": "exact-pattern",
        "path": matched_path,
        "http_method": operation_method.upper(),
        "operation_id": operation.get("operationId"),
        "parameters": sorted(parameters, key=lambda item: (str(item["in"]), str(item["name"]))),
        "request_media_types": sorted(request_media),
        "response_media_types": sorted(response_media),
        "request_schemas": sorted(request_schemas),
        "response_schemas": sorted(response_schemas),
        "request_fields": sorted(request_fields, key=lambda item: item["path"]),
        "response_fields": sorted(response_fields, key=lambda item: item["path"]),
        "schema_review": sorted(set(schema_review)),
        "unauthenticated": bool(path_item.get("x-vault-unauthenticated", False)),
        "sudo": bool(path_item.get("x-vault-sudo", False)),
    }


def operation_key(methods: list[str], path: str) -> str:
    return f"{'/'.join(methods)} {path}"


def area_for(variants: list[dict[str, Any]]) -> str:
    sources = {item["source"] for item in variants}
    areas = set()
    for source in sources:
        marker = "website/content/api-docs/"
        rest = source.removeprefix(marker)
        areas.add(rest.split("/", 1)[0])
    return next(iter(areas)) if len(areas) == 1 else "mixed"


def build_matrix(evidence: dict[str, Any], openapi: dict[str, Any]) -> dict[str, Any]:
    validate_evidence(evidence)
    document = openapi.get("document")
    if not isinstance(document, dict):
        raise ContractError("OpenAPI snapshot document is missing")
    paths = document.get("paths")
    schemas = document.get("components", {}).get("schemas")
    if not isinstance(paths, dict) or not isinstance(schemas, dict):
        raise ContractError("OpenAPI snapshot contract maps are missing")
    rows: list[dict[str, Any]] = []
    for source_row in evidence["operations"]:
        methods = source_row["methods"]
        path = DOCUMENTATION_PATH_CORRECTIONS.get(source_row["path"], source_row["path"])
        variants = source_row["variants"]
        source = variants[0]["source"]
        openapi_methods = [openapi_contract(method, path, source, paths, schemas) for method in methods]
        documented_parameters: dict[tuple[str, str, str], dict[str, Any]] = {}
        response_fields: set[str] = set()
        response_review: set[str] = set()
        for variant in variants:
            for field in variant["parameters"]:
                key = (field["section"], field["name"], field["signature"])
                documented_parameters[key] = {
                    **field,
                    "coverage": "unverified",
                    "crate_field": None,
                    "secret_classification": "unreviewed",
                }
            response_fields.update(variant["sample_response_fields"])
            response_review.update(variant["sample_response_review"])
        expanded = {f"{method} {path}" for method in methods}
        prior = dict(source_row["legacy_matrix"])
        key = operation_key(methods, path)
        override = SYSTEM_DISPOSITION_OVERRIDES.get(key)
        if override is None:
            override = AUTH_DISPOSITION_OVERRIDES.get(key)
        if override is None:
            override = SECRET_DISPOSITION_OVERRIDES.get(key)
        if override is None:
            override = PKI_DISPOSITION_OVERRIDES.get(key)
        if override is not None:
            prior = {
                "status": override,
                "note": "Reviewed during version-aware endpoint migration.",
            }
        confirmed = (
            prior["status"] in {"partial", "raw", "external", "rejected", "planned", "decision", "omitted"}
            or bool(expanded & CONFIRMED_FALSE_TYPED)
        )
        rows.append(
            {
                "operation_key": operation_key(methods, path),
                "area": area_for(variants),
                "version": "2.5.5",
                "source_commit_sha1": SOURCE_COMMIT,
                "methods": methods,
                "path": path,
                "review_status": "confirmed-gap" if confirmed else "unverified",
                "legacy_matrix": prior,
                "documentation": {
                    "variants": variants,
                    "parameters": [documented_parameters[key] for key in sorted(documented_parameters)],
                    "sample_response_fields": [
                        {
                            "path": value,
                            "coverage": "unverified",
                            "crate_field": None,
                            "secret_classification": "unreviewed",
                        }
                        for value in sorted(response_fields)
                    ],
                    "response_review": sorted(response_review),
                },
                "openapi": openapi_methods,
                "crate": {
                    "endpoint_id": None,
                    "public_helper": None,
                    "request_type": None,
                    "response_type": None,
                    "feature_gate": None,
                    "secret_review": "required",
                    "transport_review": "required",
                },
                "security": {
                    "internal": path.startswith("/sys/internal/") or path.startswith("/sys/inspect/"),
                    "operator_review": "required",
                    "authentication_review": "required",
                    "secret_review": "required",
                },
                "tests": {
                    "unit": [],
                    "fixture": [],
                    "mock_http": [],
                    "openapi": [
                        value["operation_id"]
                        for value in openapi_methods
                        if value.get("match") == "exact-pattern" and value.get("operation_id")
                    ],
                    "live": [],
                },
            }
        )
    matrix = {
        "schema": "openbao-api-contract-matrix/v1",
        "version": "2.5.5",
        "source_commit_sha1": SOURCE_COMMIT,
        "policy": {
            "typed_requires_helper_and_test_evidence": True,
            "final_allowed_statuses": ["typed", "typed-gated"],
            "current_backlog_statuses": ["unverified", "confirmed-gap"],
            "page_level_inference_forbidden": True,
        },
        "documented_rows": len(rows),
        "expanded_operations": sum(len(item["methods"]) for item in rows),
        "operations": rows,
    }
    validate_matrix(matrix)
    return matrix


def validate_evidence(value: dict[str, Any]) -> None:
    if (
        value.get("schema") != "openbao-tagged-contract-evidence/v1"
        or value.get("source_commit_sha1") != SOURCE_COMMIT
        or value.get("raw_documented_rows") != EXPECTED_RAW_ROWS
        or value.get("unique_documented_rows") != EXPECTED_ROWS
        or value.get("expanded_operations") != EXPECTED_EXPANDED_OPERATIONS
        or len(value.get("files", [])) != EXPECTED_DOC_FILES
        or len(value.get("operations", [])) != EXPECTED_ROWS
    ):
        raise ContractError("tagged contract evidence metadata is invalid")
    expanded: set[tuple[str, str]] = set()
    keys: set[str] = set()
    for row in value["operations"]:
        methods = row.get("methods")
        path = row.get("path")
        variants = row.get("variants")
        if (
            not isinstance(methods, list)
            or not methods
            or any(method not in METHOD_ORDER for method in methods)
            or not isinstance(path, str)
            or not isinstance(variants, list)
            or not variants
        ):
            raise ContractError("tagged contract evidence row is malformed")
        key = operation_key(methods, path)
        if key in keys:
            raise ContractError("tagged contract evidence contains a duplicate row")
        keys.add(key)
        for method in methods:
            identity = (method, path)
            if identity in expanded:
                raise ContractError("tagged contract evidence contains an expanded collision")
            expanded.add(identity)
    if len(expanded) != EXPECTED_EXPANDED_OPERATIONS:
        raise ContractError("tagged contract expanded operation count is invalid")


def all_contract_fields(row: dict[str, Any]) -> list[dict[str, Any]]:
    fields = [*row["documentation"]["parameters"], *row["documentation"]["sample_response_fields"]]
    for operation in row["openapi"]:
        fields.extend(operation.get("parameters", []))
        fields.extend(operation.get("request_fields", []))
        fields.extend(operation.get("response_fields", []))
    return fields


def validate_matrix(value: dict[str, Any]) -> None:
    if (
        value.get("schema") != "openbao-api-contract-matrix/v1"
        or value.get("documented_rows") != EXPECTED_ROWS
        or value.get("expanded_operations") != EXPECTED_EXPANDED_OPERATIONS
        or len(value.get("operations", [])) != EXPECTED_ROWS
    ):
        raise ContractError("generated contract matrix metadata is invalid")
    keys: set[str] = set()
    expanded: set[tuple[str, str]] = set()
    for row in value["operations"]:
        key = row.get("operation_key")
        methods = row.get("methods")
        path = row.get("path")
        status = row.get("review_status")
        documentation = row.get("documentation")
        openapi = row.get("openapi")
        crate = row.get("crate")
        security = row.get("security")
        tests = row.get("tests")
        if (
            row.get("source_commit_sha1") != SOURCE_COMMIT
            or not isinstance(methods, list)
            or not methods
            or len(methods) != len(set(methods))
            or any(method not in METHOD_ORDER for method in methods)
            or not isinstance(path, str)
            or normalize_path(path)[0] != path
            or not isinstance(documentation, dict)
            or not isinstance(documentation.get("variants"), list)
            or not documentation["variants"]
            or not isinstance(openapi, list)
            or len(openapi) != len(methods)
            or not isinstance(crate, dict)
            or not isinstance(security, dict)
            or not isinstance(tests, dict)
        ):
            raise ContractError("generated matrix operation structure is invalid")
        for variant in documentation["variants"]:
            if (
                not isinstance(variant, dict)
                or not isinstance(variant.get("source"), str)
                or not variant["source"].startswith("website/content/api-docs/")
            ):
                raise ContractError("generated matrix source evidence is invalid")
        if (
            not isinstance(crate.get("transport_review"), str)
            or not crate["transport_review"]
            or not isinstance(crate.get("secret_review"), str)
            or not crate["secret_review"]
            or not isinstance(security.get("internal"), bool)
            or any(
                not isinstance(security.get(name), str) or not security[name]
                for name in (
                    "operator_review",
                    "authentication_review",
                    "secret_review",
                )
            )
        ):
            raise ContractError("generated matrix security or transport review is invalid")
        if set(tests) != {"unit", "fixture", "mock_http", "openapi", "live"} or any(
            not isinstance(tests[name], list) for name in tests
        ):
            raise ContractError("generated matrix test evidence is invalid")
        if not isinstance(key, str) or key in keys or key != operation_key(methods, path):
            raise ContractError("generated matrix operation key is invalid or duplicated")
        keys.add(key)
        if status not in {"unverified", "confirmed-gap", "typed", "typed-gated"}:
            raise ContractError("generated matrix status is invalid")
        for method in methods:
            identity = (method, path)
            if identity in expanded:
                raise ContractError("generated matrix contains an expanded identity collision")
            expanded.add(identity)
        fields = all_contract_fields(row)
        if len(fields) > MAX_FIELDS:
            raise ContractError("generated matrix operation field count exceeds its limit")
        for field in fields:
            if field.get("coverage") not in {"unverified", "covered", "missing"}:
                raise ContractError("contract field lacks an explicit coverage state")
            if field.get("secret_classification") not in {"unreviewed", "public", "sensitive", "secret"}:
                raise ContractError("contract field lacks an explicit secret classification")
        if status in {"typed", "typed-gated"}:
            if not crate.get("endpoint_id") or not crate.get("public_helper"):
                raise ContractError("typed row lacks an explicit public helper")
            if status == "typed-gated" and not crate.get("feature_gate"):
                raise ContractError("typed-gated row lacks an explicit feature gate")
            if crate["transport_review"] == "required" or crate["secret_review"] == "required":
                raise ContractError("typed row has an incomplete crate review")
            if any(security[name] == "required" for name in (
                "operator_review",
                "authentication_review",
                "secret_review",
            )):
                raise ContractError("typed row has an incomplete security review")
            if not any(tests[name] for name in ("unit", "fixture", "mock_http", "live")):
                raise ContractError("typed row lacks test evidence")
            if any(field["coverage"] != "covered" for field in fields):
                raise ContractError("typed row contains an uncovered field")
    if len(expanded) != EXPECTED_EXPANDED_OPERATIONS:
        raise ContractError("generated matrix expanded operation count is invalid")


def csv_bytes(matrix: dict[str, Any]) -> bytes:
    output = io.StringIO(newline="")
    names = [
        "operation_key", "area", "methods", "path", "review_status", "legacy_status",
        "source_files", "documented_parameters", "sample_response_fields", "openapi_matches",
        "openapi_operation_ids", "crate_endpoint_id", "public_helper", "request_type",
        "response_type", "feature_gate", "secret_review", "transport_review", "unit_evidence",
        "fixture_evidence", "mock_http_evidence", "live_evidence",
    ]
    writer = csv.DictWriter(output, fieldnames=names, lineterminator="\n")
    writer.writeheader()
    for row in matrix["operations"]:
        writer.writerow(
            {
                "operation_key": row["operation_key"],
                "area": row["area"],
                "methods": "/".join(row["methods"]),
                "path": row["path"],
                "review_status": row["review_status"],
                "legacy_status": row["legacy_matrix"]["status"],
                "source_files": ";".join(sorted({item["source"] for item in row["documentation"]["variants"]})),
                "documented_parameters": ";".join(item["name"] for item in row["documentation"]["parameters"]),
                "sample_response_fields": ";".join(item["path"] for item in row["documentation"]["sample_response_fields"]),
                "openapi_matches": ";".join(item["match"] for item in row["openapi"]),
                "openapi_operation_ids": ";".join(str(item) for item in row["tests"]["openapi"]),
                "crate_endpoint_id": row["crate"]["endpoint_id"] or "",
                "public_helper": row["crate"]["public_helper"] or "",
                "request_type": row["crate"]["request_type"] or "",
                "response_type": row["crate"]["response_type"] or "",
                "feature_gate": row["crate"]["feature_gate"] or "",
                "secret_review": row["crate"]["secret_review"],
                "transport_review": row["crate"]["transport_review"],
                "unit_evidence": ";".join(row["tests"]["unit"]),
                "fixture_evidence": ";".join(row["tests"]["fixture"]),
                "mock_http_evidence": ";".join(row["tests"]["mock_http"]),
                "live_evidence": ";".join(row["tests"]["live"]),
            }
        )
    return output.getvalue().encode()


def markdown_bytes(matrix: dict[str, Any]) -> bytes:
    counts: dict[str, int] = {}
    areas: dict[str, dict[str, int]] = {}
    openapi_counts: dict[str, int] = {}
    for row in matrix["operations"]:
        status = row["review_status"]
        counts[status] = counts.get(status, 0) + 1
        area = areas.setdefault(row["area"], {})
        area[status] = area.get(status, 0) + 1
        for operation in row["openapi"]:
            match = operation["match"]
            openapi_counts[match] = openapi_counts.get(match, 0) + 1
    lines = [
        "# OpenBao 2.5.5 Exact Contract Matrix",
        "",
        "Generated offline from the exact tagged OpenBao `v2.5.5` source commit",
        f"`{SOURCE_COMMIT}` and the normalized OpenAPI snapshot captured from the",
        "locked `2.5.5` image. The machine-readable source of truth is",
        "`docs/openbao-2.5-contract-matrix.json`; the CSV is a review index.",
        "",
        "## Corrected Inventory",
        "",
        f"- Raw tagged documentation table rows: `{EXPECTED_RAW_ROWS}`.",
        f"- Unique documented rows: `{EXPECTED_ROWS}`.",
        f"- Expanded method/path operations: `{EXPECTED_EXPANDED_OPERATIONS}`.",
        "- The prior 643-row report omitted `HEAD /sys/health`; 644 is the",
        "  corrected tagged-source row count.",
        "",
        "## Status Semantics",
        "",
        "- `unverified`: an earlier typed claim exists, but no exact helper, field,",
        "  security, transport, and test evidence has been linked yet.",
        "- `confirmed-gap`: the row was previously non-strict, was proven falsely",
        "  typed by the full-support audit, or was omitted from the old matrix.",
        "- `typed` and `typed-gated`: final statuses accepted only after a public",
        "  helper, complete field review, secret classification, and test evidence",
        "  are present. No row receives either status in this baseline audit.",
        "",
        "This is an implementation backlog, not a support percentage or a",
        "compatibility certification.",
        "",
        "## Review Summary",
        "",
        "| Status | Rows |",
        "| --- | ---: |",
    ]
    for status in ("unverified", "confirmed-gap", "typed", "typed-gated"):
        lines.append(f"| `{status}` | {counts.get(status, 0)} |")
    lines.extend(["", "## Area Summary", "", "| Area | Rows | Unverified | Confirmed gap |", "| --- | ---: | ---: | ---: |"])
    for area in sorted(areas):
        values = areas[area]
        total = sum(values.values())
        lines.append(f"| `{area}` | {total} | {values.get('unverified', 0)} | {values.get('confirmed-gap', 0)} |")
    lines.extend(["", "## OpenAPI Reconciliation", "", "| Match state | Expanded operations |", "| --- | ---: |"])
    for state in sorted(openapi_counts):
        lines.append(f"| `{state}` | {openapi_counts[state]} |")
    lines.extend(
        [
            "",
            "An absent or ambiguous OpenAPI match is retained as an explicit review",
            "item; it is never converted into typed coverage. Tagged documentation",
            "remains authoritative for inventory identity.",
            "",
            "## Verification",
            "",
            "```sh",
            "python3 scripts/generate_openbao_contract_matrix.py --verify",
            "python3 scripts/generate_openbao_contract_matrix.py --self-test",
            "```",
            "",
        ]
    )
    return "\n".join(lines).encode()


def outputs(matrix: dict[str, Any]) -> dict[Path, bytes]:
    return {
        MATRIX_JSON: canonical_json(matrix),
        MATRIX_CSV: csv_bytes(matrix),
        MATRIX_MD: markdown_bytes(matrix),
    }


def atomic_write(path: Path, data: bytes) -> None:
    if len(data) > MAX_OUTPUT_BYTES:
        raise ContractError("generated contract output exceeds its byte limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != ROOT.parent):
        raise ContractError("generated contract output path is unsafe")
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


def immutable_write(path: Path, data: bytes) -> None:
    if path.exists() or path.is_symlink():
        try:
            existing = read_regular_file(path, MAX_OUTPUT_BYTES)
        except (OSError, SnapshotError) as error:
            raise ContractError("immutable contract evidence is unsafe") from error
        if existing != data:
            raise ContractError("immutable contract evidence would change")
        return
    atomic_write(path, data)


def generate(write: bool) -> dict[Path, bytes]:
    require_hash(EVIDENCE_PATH, EXPECTED_EVIDENCE_SHA256)
    require_hash(OPENAPI_SNAPSHOT, EXPECTED_OPENAPI_SNAPSHOT_SHA256)
    evidence = load_json(EVIDENCE_PATH)
    openapi = load_json(OPENAPI_SNAPSHOT)
    generated = outputs(build_matrix(evidence, openapi))
    for path, data in generated.items():
        relative = path.relative_to(ROOT).as_posix()
        if sha256(data) != EXPECTED_OUTPUT_SHA256.get(relative):
            raise ContractError("generated contract output checksum is not anchored")
    if write:
        for path, data in generated.items():
            atomic_write(path, data)
    return generated


def verify() -> None:
    generated = generate(False)
    for path, expected in generated.items():
        try:
            actual = read_regular_file(path, MAX_OUTPUT_BYTES)
        except (OSError, SnapshotError) as error:
            raise ContractError("generated contract output is missing or unsafe") from error
        if actual != expected:
            raise ContractError(f"generated contract output is stale: {path.relative_to(ROOT)}")


def self_test() -> None:
    verify()

    def expect_rejected(label: str, operation: Any) -> None:
        try:
            operation()
        except (ContractError, SnapshotError):
            return
        raise ContractError(f"self-test accepted {label}")

    matrix = load_json(MATRIX_JSON, MAX_OUTPUT_BYTES)

    unsupported = copy.deepcopy(matrix)
    unsupported["operations"][0]["review_status"] = "typed"
    expect_rejected("an unsupported typed claim", lambda: validate_matrix(unsupported))

    unclassified = copy.deepcopy(matrix)
    fields = all_contract_fields(unclassified["operations"][0])
    if not fields:
        raise ContractError("self-test fixture unexpectedly has no contract fields")
    fields[0].pop("secret_classification", None)
    expect_rejected("an unclassified contract field", lambda: validate_matrix(unclassified))

    duplicate = copy.deepcopy(matrix)
    duplicate["operations"][1] = copy.deepcopy(duplicate["operations"][0])
    expect_rejected("a duplicate operation identity", lambda: validate_matrix(duplicate))

    oversized_properties = {
        "properties": {
            f"field-{index}": {"type": "string"}
            for index in range(MAX_FIELDS + 1)
        }
    }
    expect_rejected(
        "an oversized OpenAPI schema",
        lambda: resolve_schema(oversized_properties, {}),
    )
    _, depth_review = resolve_schema({}, {}, depth=17)
    if depth_review != ["schema-depth-limit"]:
        raise ContractError("self-test did not bound deeply nested OpenAPI schemas")

    if path_score("/auth/jwt/config", "/auth/{ldap_mount_path}/config", "auth/jwt.mdx") >= path_score(
        "/auth/jwt/config", "/auth/{jwt_mount_path}/config", "auth/jwt.mdx"
    ):
        raise ContractError("self-test failed mount-aware OpenAPI matching")
    try:
        normalize_path("/sys/health\nforged")
    except (ContractError, SnapshotError):
        pass
    else:
        raise ContractError("self-test accepted a control character in a path")

    with tempfile.TemporaryDirectory(prefix="openbao-contract-matrix-") as directory:
        root = Path(directory)
        target = root / "target"
        target.write_bytes(b"{}")
        symlink = root / "symlink"
        symlink.symlink_to(target)
        expect_rejected("a symbolic-link input", lambda: load_json(symlink, 128))
        fifo = root / "fifo"
        os.mkfifo(fifo)
        expect_rejected("a FIFO input", lambda: load_json(fifo, 128))
        expect_rejected(
            "tampered anchored evidence",
            lambda: require_hash(target, "0" * 64, 128),
        )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--capture-source", type=Path)
    actions.add_argument("--generate", action="store_true")
    actions.add_argument("--verify", action="store_true")
    actions.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.capture_source is not None:
            immutable_write(EVIDENCE_PATH, canonical_json(capture_source(arguments.capture_source)))
            print(f"captured {EVIDENCE_PATH.relative_to(ROOT)}")
        elif arguments.generate:
            generate(True)
            print("generated exact OpenBao 2.5.5 contract matrix")
        elif arguments.self_test:
            self_test()
            print("OpenBao contract matrix self-tests: ok")
        else:
            verify()
            print(f"OpenBao contract matrix: {EXPECTED_ROWS} exact rows verified")
    except (ContractError, SnapshotError) as error:
        print(f"OpenBao contract matrix error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
