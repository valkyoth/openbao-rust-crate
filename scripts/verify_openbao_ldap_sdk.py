#!/usr/bin/python3 -EsSB
"""Validate exact normal-build LDAP SDK evidence; never approve untested operations."""

import argparse
import re

import openbao_ldap_sdk as sdk
import verify_openbao_ldap_plugins as server

base = sdk.fixture.base
ANCHORS = {
    "2.7.0": "db57f1a4c3f4641db10dadccc16e9f5658f6c9556108705d1237ca7d38304417",
    "2.7.1": "648561a64b996a6076b9d6c31e69f0d39d8c5860b4ed16679f61e841436a8d95",
    "2.7.2": "84ac956f9fa26309894ecafe6268bd9778de6911fc47bcf277859fdb9c2b8542",
}
BINARY = "a6e72c2d3a8ba2aaf97791c7a6d5c3e86f45ed623abfaf9b6eb9d2950ede4c5b"


def validate_operations(schema):
    registry = base.parse_json(base.read_regular_file(
        sdk.fixture.ROOT / "compat/capability-registry.json", 2 * 1024 * 1024), 2 * 1024 * 1024)
    inventory = {row["id"]: row for row in registry["operations"]}
    server.require(len(sdk.OPERATIONS) == 33 and len(set(sdk.OPERATIONS)) == 33)
    paths = {}
    for path, contract in schema["paths"].items():
        if "fixture_ldap" not in path:
            continue
        path = path.replace("{fixture_ldap_auth_mount_path}", "ldap")
        path = path.replace("{fixture_ldap_secrets_mount_path}", "ldap")
        path = re.sub(r"\{[^{}]+\}", "{}", path)
        server.require(path not in paths)
        paths[path] = contract
    for identifier in sdk.OPERATIONS:
        server.require(identifier in inventory)
        row = inventory[identifier]
        server.require(row["disposition"] == "typed" and
                       (row["path_template"].startswith("/auth/ldap/") or
                        row["path_template"].startswith("/ldap/")))
        path = re.sub(r":[A-Za-z0-9_]+", "{}", row["path_template"])
        method = "get" if row["method"] == "LIST" else row["method"].lower()
        server.require(path in paths and method in paths[path])
        if row["method"] == "LIST" or path == "/ldap/static-role":
            parameters = paths[path][method].get("parameters", [])
            server.require(any(parameter.get("name") == "list" and parameter.get("in") == "query"
                               and parameter.get("required") is True
                               and parameter.get("schema", {}).get("enum") == ["true"]
                               for parameter in parameters))


def validate_report(report, version, inputs, schema):
    server.require(version in ANCHORS and isinstance(report, dict))
    identity = {"schema": "openbao-ldap-plugin-sdk/v1",
                "scope": "public-sdk-normal-build", "checks": list(sdk.STAGES),
                "binary_sha256": BINARY, "execution": sdk.execution.EXECUTION_ASSURANCE}
    for key, expected in identity.items():
        server.require(report.get(key) == expected)
    # Check all remaining fields with the same strict identity/schema validator
    # used for server reports. This conversion does not confer server scope on
    # the retained SDK evidence or relax its separate anchor.
    converted = dict(report)
    for key in ("binary_sha256", "execution"):
        del converted[key]
    converted.update(schema="openbao-ldap-plugin-server/v1",
                     scope="server-fixture-only-not-public-sdk-integration",
                     checks=list(sdk.fixture.CHECKS))
    server.validate_report(converted, version, inputs, schema)
    validate_operations(base.parse_json(schema, 2 * 1024 * 1024))


def verify(version):
    server.require(version in ANCHORS)
    root = server.ROOT / version / "sdk-normal-v8"
    raw = base.read_regular_file(root / "report.json", 64 * 1024)
    server.require(base.sha256(raw) == ANCHORS[version])
    report = base.parse_json(raw, 64 * 1024)
    server.require(base.canonical_json(report) == raw)
    schema = base.read_regular_file(root / "runtime-openapi.json", 2 * 1024 * 1024)
    validate_report(report, version, sdk.input_hashes(), schema)
    return report


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        for version in ANCHORS:
            verify(version)
    except (base.SnapshotError, sdk.fixture.harness.HarnessError, OSError, ValueError, KeyError, TypeError):
        print("LDAP normal-build SDK evidence verification failed")
        return 1
    print("LDAP normal-build SDK evidence verified for all three exact servers, including library operations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
