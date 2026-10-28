#!/usr/bin/python3 -EsSB
"""Retain and verify the initial 2.7.2 capture; this is not profile promotion."""

import argparse
import copy
from pathlib import Path

import openbao_2_7_2 as patch

base = patch.base
OUTPUT = patch.ROOT / "compat/onboarding/2.7.2"
PREDECESSOR = patch.ROOT / "compat/onboarding/2.7.1/initial-openapi.json"
PREDECESSOR_SHA256 = "5091c881b5a2e925331227cb4ee6b6c679ba2b5a7c13704e362c03cb41513af5"
ARTIFACTS = {
    "initial-openapi.json": ("openapi.json", "85645ebb985ad278a5a9f3018ad7c20b85ed057078f2cdee0d13d95ac9ed386b", base.MAX_OPENAPI_BYTES),
    "initial-patch-tls.json": ("report.json", "e76d569337358991d0338f18a562fc98951a9d4f46c48b3e2038d859014f4b59", 64 * 1024),
}


def checked(data, digest, limit):
    patch.require(base.sha256(data) == digest)
    value = base.parse_json(data, limit)
    patch.require(base.canonical_json(value) == data)
    return value


def compare_contracts(api, predecessor):
    patch.require(predecessor["version"] == "2.7.1" and api["version"] == patch.VERSION)
    for field in ("mounts", "path_count", "operation_count", "schema_count"):
        patch.require(api[field] == predecessor[field])
    old, new = copy.deepcopy(predecessor["document"]), copy.deepcopy(api["document"])
    patch.require(old["info"]["version"] == "2.7.1")
    new["info"]["version"] = old["info"]["version"]
    schemas = new.get("components", {}).get("schemas", {})
    role = schemas.get("SshWriteRoleRequest", {})
    properties = role.get("properties")
    patch.require(isinstance(properties, dict))
    wildcard = properties.pop("allow_wildcards_in_identity_templates", None)
    patch.require(wildcard == {"default": False, "type": "boolean",
                              "x-vault-displayAttrs": {
                                  "name": "Allow Wildcards in identity templates",
                                  "value": False}})
    get = new.get("paths", {}).get("/sys/workflows/manage", {}).get("get")
    patch.require(isinstance(get, dict))
    patch.require(get["operationId"] == "workflows-list-workflows-manage")
    get["operationId"] = "workflows-scan-workflows-manage"
    get["parameters"] = sorted(get["parameters"], key=lambda item: item["name"])
    response = get.get("responses", {}).get("200", {}).get("content", {}).get(
        "application/json", {}).get("schema")
    patch.require(isinstance(response, dict))
    patch.require(response == {"$ref": "#/components/schemas/WorkflowsListWorkflowsManageResponse"})
    response["$ref"] = "#/components/schemas/WorkflowsScanWorkflowsManageResponse"
    patch.require(old == new)


def validate(artifacts):
    patch.verify_source()
    patch.require(set(artifacts) == set(ARTIFACTS))
    values = {name: checked(artifacts[name], digest, limit)
              for name, (_, digest, limit) in ARTIFACTS.items()}
    api = values["initial-openapi.json"]
    report = values["initial-patch-tls.json"]
    expected_mounts = [{"kind": "secret", "path": path, "type": kind} for path, kind, _ in patch.SECRET_MOUNTS]
    expected_mounts += [{"kind": "auth", "path": path, "type": kind} for path, kind in patch.AUTH_MOUNTS]
    patch.require(api["mounts"] == expected_mounts)
    patch.require(api == patch.normalize_api(api["document"], expected_mounts))
    predecessor = checked(base.read_regular_file(PREDECESSOR, base.MAX_OPENAPI_BYTES),
                          PREDECESSOR_SHA256, base.MAX_OPENAPI_BYTES)
    compare_contracts(api, predecessor)
    patch.require(report == {
        "schema": "openbao-patch-capture/v1", "version": patch.VERSION,
        "image_linux_amd64_digest": patch.AMD64, "image_index_digest": patch.INDEX,
        "inputs": patch.input_hashes(), "openapi_sha256": base.sha256(artifacts["initial-openapi.json"]),
        "scope": "server-fixture-only-not-sdk-integration", "routable": False, "checks": patch.CHECKS,
    })
    return values


def verify():
    return validate({name: base.read_regular_file(OUTPUT / name, limit)
                     for name, (_, _, limit) in ARTIFACTS.items()})


def retain(directory):
    artifacts = {name: base.read_regular_file(directory / source, limit)
                 for name, (source, _, limit) in ARTIFACTS.items()}
    validate(artifacts)
    for name, data in artifacts.items():
        base.write_immutable(OUTPUT / name, data)
    verify()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retain", type=Path)
    args = parser.parse_args()
    try:
        if args.retain:
            retain(args.retain)
        else:
            verify()
    except (patch.harness.HarnessError, base.SnapshotError, OSError, ValueError, KeyError, TypeError):
        print("Initial 2.7.2 capture verification failed; no promotion")
        return 1
    print("Initial 2.7.2 TLS/API capture verified; raw-storage scope and SDK integration remain pending")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
