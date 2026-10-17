#!/usr/bin/python3 -EsSB
"""Verify Kerberos candidate history or current normal-build SDK acceptance."""

import argparse
import re

import openbao_kerberos_sdk as sdk
import verify_openbao_kerberos_plugins as server

base = server.base
require = server.require
CANDIDATE_ANCHORS = {
    "2.7.0": "9033ed4fdcef1c0bcfc97afba4fab8ea03b57e920041a6368f7675e196fd38f5",
    "2.7.1": "b307ab3c18bc1c03b70247301b0f33a40b889d9b0df244023ec406c5cbbfccb6",
}
CANDIDATE_BINARY = "9dd4ef188598161e9e87e51ed9e07c75b3c25eccbeeba7a94a402a07f717d0a9"
NORMAL_ANCHORS = {
    "2.7.0": "34ea600dfe712ae037240cb274efe345273c4caecf7babe58660593bcf5c2362",
    "2.7.1": "eed46444f3b84b8c6765004d5d32ab364ccdf227e60fb1bcbb63da4306054289",
}
NORMAL_BINARY = "ca80c574df7f46c8cfee4cde00b93c109b2234e7b79f93a7978d2641997337a4"


def validate_operations(schema):
    registry = base.parse_json(base.read_regular_file(
        sdk.fixture.ldap.ROOT / "compat/capability-registry.json", 2 * 1024 * 1024), 2 * 1024 * 1024)
    inventory = {row["id"]: row for row in registry["operations"]}
    require(len(sdk.OPERATIONS) == len(set(sdk.OPERATIONS)) == 9)
    paths = {}
    for path, contract in schema["paths"].items():
        if not path.startswith("/auth/{fixture_kerberos_mount_path}/"):
            continue
        path = re.sub(r"\{[^{}]+\}", "{}", path.replace("{fixture_kerberos_mount_path}", "kerberos"))
        require(path not in paths)
        paths[path] = contract
    for identifier in sdk.OPERATIONS:
        require(identifier in inventory)
        row = inventory[identifier]
        require(row["disposition"] == "typed" and row["path_template"].startswith("/auth/kerberos/"))
        path = re.sub(r":[A-Za-z0-9_]+", "{}", row["path_template"])
        method = "get" if row["method"] == "LIST" else row["method"].lower()
        require(path in paths and method in paths[path])
        if row["method"] == "LIST":
            require(any(p.get("name") == "list" and p.get("in") == "query"
                        and p.get("required") is True and p.get("schema", {}).get("enum") == ["true"]
                        for p in paths[path][method].get("parameters", [])))


def validate_report(report, version, inputs, schema, *, candidate=False):
    require(isinstance(report, dict))
    expected = {"schema": "openbao-kerberos-plugin-sdk/v1", "checks": list(sdk.STAGES),
                "scope": "public-sdk-candidate-only" if candidate else "public-sdk-normal-build",
                "binary_sha256": CANDIDATE_BINARY if candidate else NORMAL_BINARY,
                "execution": sdk.execution.EXECUTION_ASSURANCE}
    require(expected["binary_sha256"] is not None)
    require(all(report.get(key) == value for key, value in expected.items()))
    converted = dict(report)
    del converted["binary_sha256"]
    del converted["execution"]
    converted.update(schema="openbao-kerberos-plugin-server/v1", checks=list(sdk.fixture.CHECKS),
                     scope="server-fixture-only-not-public-sdk-integration")
    server.validate_report(converted, version, inputs, schema)
    validate_operations(base.parse_json(schema, 2 * 1024 * 1024))


def verify(version, *, candidate=False):
    anchors = CANDIDATE_ANCHORS if candidate else NORMAL_ANCHORS
    require(version in anchors)
    root = server.ROOT / version / ("sdk-candidate" if candidate else "sdk-normal-v4")
    raw = base.read_regular_file(root / "report.json", 64 * 1024)
    require(base.sha256(raw) == anchors[version])
    report = base.parse_json(raw, 64 * 1024)
    require(base.canonical_json(report) == raw)
    schema = base.read_regular_file(root / "runtime-openapi.json", 2 * 1024 * 1024)
    # Candidate captures are independently anchored history, never a current-source release gate.
    inputs = report["inputs"] if candidate else sdk.input_hashes()
    validate_report(report, version, inputs, schema, candidate=candidate)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--candidate-history", action="store_true")
    args = parser.parse_args()
    try:
        for version in server.ANCHORS:
            verify(version, candidate=args.candidate_history)
    except (base.SnapshotError, sdk.fixture.harness.HarnessError, OSError, ValueError, KeyError, TypeError):
        print("Kerberos SDK evidence verification failed")
        return 1
    print("Kerberos candidate history verified; not normal-build acceptance" if args.candidate_history
          else "Kerberos current normal-build SDK evidence verified for both exact servers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
