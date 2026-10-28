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
CANDIDATE_PLUGINS = {
    "auth-ldap": "18fa83d993c629a969cfa234d48e451921004c36ac8dc6a9fcc37d9e256d8818",
    "auth-radius": "771be7e9ee028d87bdc79412eb66fe330ca1e54e21a50ebe59584e6b8a5aa69b",
    "secrets-ldap": "47292935509894d8b4feb0fc9b6429455da87181a8fc53999eb986128ab8d73a",
}
NORMAL_ANCHORS = {
    "2.7.0": "709fbc4b206eded90cb63374fd7d361184840f2bd4b59b4b4e576e647043b5d3",
    "2.7.1": "6dcfb06fa081c338642ee3f53c3a1d097a99bc1ff80056cf07de14843c7424f3",
    "2.7.2": "6d9ce8c50261bc5fab81b37320fa6570e523c18040e3893c1ec43cda1991e122",
}
NORMAL_BINARY = "a10c97a47dd555cb4d3b37e5a9ac5131eaafa5692cdb029534d398115cf3d197"


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
    if candidate:
        require(report.get("plugins") == CANDIDATE_PLUGINS)
    converted = dict(report)
    del converted["binary_sha256"]
    del converted["execution"]
    converted.update(schema="openbao-radius-plugin-server/v1", checks=list(sdk.fixture.CHECKS),
                     scope="server-fixture-only-not-public-sdk-integration")
    if candidate:
        # The candidate reports are anchored history with prior plugin
        # binaries. Check those identities above, then substitute only while
        # reusing the current strict structural and schema validator.
        converted["plugins"] = {
            row["id"]: row["binary_sha256"]
            for row in sdk.fixture.ldap.artifacts.lock()["plugins"]
            if row["id"] in (*sdk.fixture.ldap.PLUGINS, "auth-radius")
        }
    server.validate_report(converted, version, inputs, schema)
    validate_operations(base.parse_json(schema, 2 * 1024 * 1024))


def verify(version, *, candidate=False):
    anchors = CANDIDATE_ANCHORS if candidate else NORMAL_ANCHORS
    require(version in anchors)
    root = server.ROOT / version / ("sdk-candidate" if candidate else "sdk-normal-v8")
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
        anchors = CANDIDATE_ANCHORS if args.candidate_history else NORMAL_ANCHORS
        for version in anchors:
            verify(version, candidate=args.candidate_history)
    except (base.SnapshotError, sdk.fixture.harness.HarnessError, OSError, ValueError, KeyError, TypeError):
        print("RADIUS SDK evidence verification failed")
        return 1
    print("RADIUS candidate history verified; not normal-build acceptance" if args.candidate_history
          else "RADIUS current normal-build SDK evidence verified for all exact servers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
