#!/usr/bin/python3 -EsSB
"""Verify RADIUS candidate history or current normal-build SDK acceptance."""

import argparse
import re

import openbao_radius_sdk as sdk
import verify_openbao_radius_plugins as server

base = server.base
require = server.require
CANDIDATE_ANCHORS = {
    "2.7.0": "b30dc6581706150424dff1d31e68cbaee04be11a8b687d73c9c53feaae058f51",
    "2.7.1": "fe147582ce38f457a50f7012416600c2f36009e663f3b964f6d2fa9f5ca0519a",
}
CANDIDATE_BINARY = "a3d1fda2541adb4d76369ecf4da4897fd99c4914bcf61996fd20cf07533072f7"
NORMAL_ANCHORS = {
    "2.7.0": "19cc2492215ade7c14e882c917d49e661dad305e56f149f7034136075098e805",
    "2.7.1": "7706198e6a15ece530ac00bea47209f7744c2cc2bee29b26be840850455dffd8",
}
NORMAL_BINARY = "609911fc274af2de07ec980e621537685e651e13d4e8c05dd60f5837078587e3"


def validate_operations(schema):
    registry = base.parse_json(base.read_regular_file(
        sdk.fixture.ldap.ROOT / "compat/capability-registry.json", 2 * 1024 * 1024), 2 * 1024 * 1024)
    inventory = {row["id"]: row for row in registry["operations"]}
    require(len(sdk.OPERATIONS) == len(set(sdk.OPERATIONS)) == 6)
    paths = {}
    for path, contract in schema["paths"].items():
        if not path.startswith("/auth/{fixture_radius_mount_path}/"):
            continue
        path = re.sub(r"\{[^{}]+\}", "{}", path.replace("{fixture_radius_mount_path}", "radius"))
        require(path not in paths)
        paths[path] = contract
    for identifier in sdk.OPERATIONS:
        require(identifier in inventory)
        row = inventory[identifier]
        require(row["disposition"] == "typed" and row["path_template"].startswith("/auth/radius/"))
        path = re.sub(r":[A-Za-z0-9_]+", "{}", row["path_template"])
        method = "get" if row["method"] == "LIST" else row["method"].lower()
        require(path in paths and method in paths[path])
        if row["method"] == "LIST":
            require(any(p.get("name") == "list" and p.get("in") == "query"
                        and p.get("required") is True and p.get("schema", {}).get("enum") == ["true"]
                        for p in paths[path][method].get("parameters", [])))


def validate_report(report, version, inputs, schema, *, candidate=False):
    require(isinstance(report, dict))
    expected = {"schema": "openbao-radius-plugin-sdk/v1", "checks": list(sdk.STAGES),
                "scope": "public-sdk-candidate-only" if candidate else "public-sdk-normal-build",
                "binary_sha256": CANDIDATE_BINARY if candidate else NORMAL_BINARY,
                "execution": sdk.execution.EXECUTION_ASSURANCE}
    require(expected["binary_sha256"] is not None)
    require(all(report.get(key) == value for key, value in expected.items()))
    converted = dict(report)
    del converted["binary_sha256"]
    del converted["execution"]
    converted.update(schema="openbao-radius-plugin-server/v1", checks=list(sdk.fixture.CHECKS),
                     scope="server-fixture-only-not-public-sdk-integration")
    server.validate_report(converted, version, inputs, schema)
    validate_operations(base.parse_json(schema, 2 * 1024 * 1024))


def verify(version, *, candidate=False):
    anchors = CANDIDATE_ANCHORS if candidate else NORMAL_ANCHORS
    require(version in anchors)
    root = server.ROOT / version / ("sdk-candidate" if candidate else "sdk-normal-v3")
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
        print("RADIUS SDK evidence verification failed")
        return 1
    print("RADIUS candidate history verified; not normal-build acceptance" if args.candidate_history
          else "RADIUS current normal-build SDK evidence verified for both exact servers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
