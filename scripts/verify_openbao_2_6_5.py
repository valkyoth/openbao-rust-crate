#!/usr/bin/python3 -EsSB
"""Retain exact 2.6.5 capture and require unchanged 2.6.4 runtime contracts."""

import argparse
import copy
from pathlib import Path

import openbao_2_6_5 as patch

base = patch.base
OUTPUT = patch.OUTPUT
PREDECESSOR = patch.ROOT / "compat/onboarding/2.6.4/openapi.json"
PREDECESSOR_SHA256 = "227895760956ca5bf71bbc508c7a66351ab2da6487b43b726600b8e801aece2d"
ARTIFACTS = {
    "openapi.json": ("openapi.json", "a1a656ea3bfd46116fe3dbc83a0409c0f7a11d991998b02779a641c1186d8929", base.MAX_OPENAPI_BYTES),
    "patch-tls.json": ("report.json", "6e4c06c222d93d056de14ea4c3d6cb984763886201f89a2ee1fb6cf678891542", 64 * 1024),
}


def checked(data, digest, limit):
    patch.pinned(data, digest)
    value = base.parse_json(data, limit)
    patch.require(base.canonical_json(value) == data)
    return value


def compare_contracts(api, before):
    patch.require(before["version"] == "2.6.4" and api["version"] == patch.VERSION)
    for field in ("mounts", "path_count", "operation_count", "schema_count"):
        patch.require(api[field] == before[field])
    old, new = copy.deepcopy(before["document"]), copy.deepcopy(api["document"])
    patch.require(old["info"]["version"] == "2.6.4")
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
    get = new.get("paths", {}).get("/sys/namespaces", {}).get("get")
    patch.require(isinstance(get, dict))
    patch.require(get["operationId"] == "namespaces-scan-namespaces")
    get["operationId"] = "namespaces-list-namespaces"
    get["parameters"] = sorted(get["parameters"], key=lambda item: item["name"], reverse=True)
    response = get.get("responses", {}).get("200", {}).get("content", {}).get(
        "application/json", {}).get("schema")
    patch.require(isinstance(response, dict))
    patch.require(response == {"$ref": "#/components/schemas/NamespacesScanNamespacesResponse"})
    response["$ref"] = "#/components/schemas/NamespacesListNamespacesResponse"
    patch.require(old == new)


def validate(artifacts):
    patch.verify_source()
    patch.verify_image()
    patch.require(set(artifacts) == set(ARTIFACTS))
    values = {name: checked(artifacts[name], digest, limit)
              for name, (_, digest, limit) in ARTIFACTS.items()}
    api, report = values["openapi.json"], values["patch-tls.json"]
    patch.require(api == patch.normalize_api(api["document"], api["mounts"]))
    before = checked(base.read_regular_file(PREDECESSOR, base.MAX_OPENAPI_BYTES),
                     PREDECESSOR_SHA256, base.MAX_OPENAPI_BYTES)
    compare_contracts(api, before)
    patch.require(report == {
        "schema": "openbao-patch-capture/v1", "version": patch.VERSION,
        "image_linux_amd64_digest": patch.AMD64, "image_index_digest": patch.INDEX,
        "inputs": patch.input_hashes(), "openapi_sha256": base.sha256(artifacts["openapi.json"]),
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
        print("2.6.5 capture verification failed; no promotion")
        return 1
    print("2.6.5 TLS/API capture verified; exact 2.6.4 contracts preserved; SDK verification remains separate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
