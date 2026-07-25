#!/usr/bin/env python3
"""Generate evidence-backed response fixtures for every locked OpenBao release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from openbao_api_snapshots import SnapshotError, parse_json, read_regular_file, verify

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "compat/api-snapshots.lock.json"
OUTPUT_PATH = ROOT / "tests/fixtures/openbao_response_profiles.json"
MAX_LOCK_BYTES = 256 * 1024
MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_BYTES = 512 * 1024
EXPECTED_VERSIONS = (
    "2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.1.0", "2.1.1", "2.2.0",
    "2.2.1", "2.2.2", "2.3.1", "2.3.2", "2.4.0", "2.4.1", "2.4.3",
    "2.4.4", "2.5.0", "2.5.1", "2.5.2", "2.5.3", "2.5.4", "2.5.5",
    "2.6.0", "2.6.1",
)


class FixtureError(RuntimeError):
    """Locked response fixture evidence is invalid."""


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()


def load_object(path: Path, maximum: int) -> dict[str, Any]:
    try:
        value = parse_json(read_regular_file(path, maximum), maximum)
    except (OSError, SnapshotError) as error:
        raise FixtureError("response fixture input is missing or unsafe") from error
    if not isinstance(value, dict):
        raise FixtureError("response fixture input must be a JSON object")
    return value


def properties(document: dict[str, Any], schema_name: str) -> dict[str, Any]:
    try:
        value = document["document"]["components"]["schemas"][schema_name]["properties"]
    except (KeyError, TypeError) as error:
        raise FixtureError("required OpenAPI response schema is missing") from error
    if not isinstance(value, dict) or len(value) > 256:
        raise FixtureError("OpenAPI response property map is invalid")
    return value


def profile(version: str, digest: str, document: dict[str, Any]) -> dict[str, Any]:
    certificate_schema = properties(document, "PkiIssueWithRoleResponse")
    role_schema = properties(document, "PkiReadRoleResponse")
    policy_schema = properties(document, "PoliciesReadAclPolicyResponse")
    quota_schema = properties(document, "RateLimitQuotasReadResponse")
    plugin_schema = properties(document, "PluginsCatalogReadPluginConfigurationResponse")

    certificate: dict[str, Any] = {
        "certificate": "fixture-certificate",
        "expiration": 2_000_000_000,
        "private_key": "fixture-private-key",
    }
    if "not_before" in certificate_schema:
        certificate["not_before"] = 1_700_000_000

    role: dict[str, Any] = {
        "allowed_domains": ["example.test"],
        "max_ttl": 7200,
        "not_before_duration": 30,
        "ttl": 3600,
    }
    if "allowed_ip_sans_cidr" in role_schema:
        role["allowed_ip_sans_cidr"] = ["192.0.2.0/24"]

    policy: dict[str, Any] = {
        "name": "fixture",
        "rules": 'path "secret/data/fixture" { capabilities = ["read"] }',
    }
    for key, value in (
        ("cas_required", True),
        ("expiration", "2030-01-01T00:00:00Z"),
        ("modified", "2026-01-01T00:00:00Z"),
        ("version", 2),
    ):
        if key in policy_schema:
            policy[key] = value

    quota: dict[str, Any] = {
        "interval": 1,
        "name": "fixture",
        "path": "auth/approle",
        "rate": 10.0,
        "type": "rate-limit",
    }
    if "inheritable" in quota_schema:
        quota["inheritable"] = True

    plugin: dict[str, Any] = {
        "args": ["fixture-secret-argument"],
        "builtin": False,
        "command": "fixture-plugin",
        "env": ["FIXTURE_SECRET=value"],
        "name": "fixture-plugin",
    }
    if "declarative" in plugin_schema:
        plugin["declarative"] = True
    if "oci" in plugin_schema:
        plugin["oci"] = True

    return {
        "openapi_sha256": digest,
        "pki_certificate": certificate,
        "pki_role": role,
        "plugin": plugin,
        "policy": policy,
        "quota": quota,
        "version": version,
    }


def generate() -> bytes:
    verify()
    lock_bytes = read_regular_file(LOCK_PATH, MAX_LOCK_BYTES)
    lock = parse_json(lock_bytes, MAX_LOCK_BYTES)
    if not isinstance(lock, dict) or lock.get("schema") != "openbao-api-snapshot-lock/v1":
        raise FixtureError("OpenBao snapshot lock identity is invalid")
    records = lock.get("records")
    if not isinstance(records, list) or len(records) != len(EXPECTED_VERSIONS):
        raise FixtureError("OpenBao snapshot lock release count is invalid")

    profiles = []
    for expected, record in zip(EXPECTED_VERSIONS, records, strict=True):
        if not isinstance(record, dict) or record.get("version") != expected:
            raise FixtureError("OpenBao snapshot lock release order is invalid")
        openapi = record.get("openapi")
        if not isinstance(openapi, dict):
            raise FixtureError("OpenBao snapshot lock OpenAPI record is invalid")
        relative = openapi.get("path")
        digest = openapi.get("sha256")
        if not isinstance(relative, str) or not isinstance(digest, str):
            raise FixtureError("OpenBao snapshot lock OpenAPI identity is invalid")
        path = ROOT / relative
        document_bytes = read_regular_file(path, MAX_SNAPSHOT_BYTES)
        if hashlib.sha256(document_bytes).hexdigest() != digest:
            raise FixtureError("OpenBao response fixture source digest changed")
        document = parse_json(document_bytes, MAX_SNAPSHOT_BYTES)
        if not isinstance(document, dict) or document.get("version") != expected:
            raise FixtureError("OpenBao response fixture source version is invalid")
        profiles.append(profile(expected, digest, document))

    output = canonical_json({
        "profiles": profiles,
        "schema": "openbao-versioned-response-fixtures/v1",
        "snapshot_lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
    })
    if len(output) > MAX_OUTPUT_BYTES:
        raise FixtureError("generated OpenBao response fixtures exceed the output limit")
    return output


def write_output(data: bytes) -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    if OUTPUT_PATH.exists() and not stat.S_ISREG(OUTPUT_PATH.lstat().st_mode):
        raise FixtureError("response fixture output is not a regular file")
    descriptor, temporary = tempfile.mkstemp(prefix=".response-fixtures.", dir=OUTPUT_PATH.parent)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, OUTPUT_PATH)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def self_test() -> None:
    generated = parse_json(generate(), MAX_OUTPUT_BYTES)
    profiles = generated.get("profiles")
    if not isinstance(profiles, list) or tuple(item.get("version") for item in profiles) != EXPECTED_VERSIONS:
        raise FixtureError("response fixture self-test release coverage failed")
    if "not_before" in profiles[0]["pki_certificate"]:
        raise FixtureError("response fixture self-test accepted pre-2.1 not_before")
    if profiles[4]["pki_certificate"].get("not_before") != 1_700_000_000:
        raise FixtureError("response fixture self-test missed OpenBao 2.1 not_before")
    if "inheritable" in profiles[8]["quota"] or profiles[9]["quota"].get("inheritable") is not True:
        raise FixtureError("response fixture self-test missed OpenBao 2.3.1 quota drift")


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
    elif arguments.write:
        write_output(generate())
    elif read_regular_file(OUTPUT_PATH, MAX_OUTPUT_BYTES) != generate():
        raise FixtureError("generated OpenBao response fixtures are stale")


if __name__ == "__main__":
    main()
