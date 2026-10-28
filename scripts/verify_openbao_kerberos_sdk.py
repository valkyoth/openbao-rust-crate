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
CANDIDATE_PLUGINS = {
    "auth-kerberos": "57ac030fea755adf791600eb2b30aa410d2e848ab7ec7bb54cc515cdce4b89ae",
    "auth-ldap": "18fa83d993c629a969cfa234d48e451921004c36ac8dc6a9fcc37d9e256d8818",
    "secrets-ldap": "47292935509894d8b4feb0fc9b6429455da87181a8fc53999eb986128ab8d73a",
}
NORMAL_ANCHORS = {
    "2.7.0": "95b60bdfa72ed86dd36161ceb26fe9bbc6c8e5747fdae94c38b5e529ca5773a7",
    "2.7.1": "ffb81adc599012edeba4121f4d6235bee10fd5cea9b5cfc0536a9cda18adf045",
    "2.7.2": "a36087df385b1f1304032fa49a2174d577953a4a73951d3b5f6fd0a1a350dd1b",
}
NORMAL_BINARY = "eefe9652c7d036048bbcd715b3ab489ab93c988db446207182c626cf7dcf6ff7"


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
    if candidate:
        require(report.get("plugins") == CANDIDATE_PLUGINS)
    converted = dict(report)
    del converted["binary_sha256"]
    del converted["execution"]
    converted.update(schema="openbao-kerberos-plugin-server/v1", checks=list(sdk.fixture.CHECKS),
                     scope="server-fixture-only-not-public-sdk-integration")
    if candidate:
        # The candidate reports are anchored history with the prior LDAP
        # binaries. Their identities are checked above; substitute only while
        # reusing the current strict structural and schema validator.
        converted["plugins"] = {
            row["id"]: row["binary_sha256"]
            for row in sdk.fixture.ldap.artifacts.lock()["plugins"]
            if row["id"] in (*sdk.fixture.ldap.PLUGINS, "auth-kerberos")
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
        print("Kerberos SDK evidence verification failed")
        return 1
    print("Kerberos candidate history verified; not normal-build acceptance" if args.candidate_history
          else "Kerberos current normal-build SDK evidence verified for all exact servers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
