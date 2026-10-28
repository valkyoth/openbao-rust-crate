#!/usr/bin/python3 -EsSB
"""Verify exact 2.7.2 regression artifacts and the reviewed API delta."""

import argparse
import copy
from pathlib import Path

import openbao_2_7_2_regressions as runner
import verify_openbao_2_7_1_regressions as predecessor
import verify_openbao_2_7_2 as initial

patch, base = runner.patch, runner.base
OUTPUT = initial.OUTPUT
OPENAPI_SHA256 = "eb4ebb0fea1bcfd682ee7f44d1962150a224cf2744a0ea2ee6f6de3535528fd5"
REPORTS = {
    "api": "74d2a13b850e0a5cfdfb1e559dc0237ff2c33dc8196d03e28723b5e34512cc09",
    "external-keys": "ccf769faa4faaef69dbdc7c174c036713e7a68f7c4739e87cb28f0ff71538d9d",
    "transit": "e92545b73ddd8f82315be758d7b0f0a22bcd6b4a48ab96c18c80cd9ad0e5674f",
    "pki": "c2097aa6703923d8a23cdc4aad2137edd8078fb6500794cf35b98204adce09a8",
    "workflow-cas": "fcee42ac29b1b0e538e19574fe3df19ae0bc2d811653ad367344cd12b5c17156",
    "control-groups": "d58796eaa4109f0b1602c129e4be39debeb0b4f147121017ef852ee44c631f92",
    "system": "cafd49d55dcefefa9027f526d800b7b49dd8203f7286a55927d5c52727683dd9",
    "mfa-totp": "cddf8c50f21fa1aa8b90d65759417217fd9e54510214361b5171f2e5ee36df18",
}
MODULES = {"external-keys": runner.external, "transit": runner.transit, "pki": runner.pki,
           "workflow-cas": runner.workflow, "control-groups": runner.control,
           "system": runner.system, "mfa-totp": runner.mfa}


def compare_api(before, after):
    left, right = copy.deepcopy(before["document"]), copy.deepcopy(after["document"])
    patch.require(left["info"]["version"] == "2.7.1" and right["info"]["version"] == patch.VERSION)
    patch.require(before["mounts"] == after["mounts"])
    right["info"]["version"] = left["info"]["version"]
    properties = right.get("components", {}).get("schemas", {}).get(
        "SshWriteRoleRequest", {}).get("properties")
    patch.require(isinstance(properties, dict))
    wildcard = properties.pop("allow_wildcards_in_identity_templates", None)
    patch.require(wildcard == {"default": False, "type": "boolean",
                              "x-vault-displayAttrs": {
                                  "name": "Allow Wildcards in identity templates",
                                  "value": False}})
    for document in (left, right):
        detailed = document["paths"]["/{kv_v2_mount_path}/detailed-metadata/{path}"]["get"]
        patch.require(detailed["operationId"] in {
            "kv-list-detailed-metadata-path", "kv-scan-detailed-metadata-path"})
        expected_detailed = [
            {"in": "query", "name": kind, "required": True,
             "schema": {"enum": ["true"], "type": "string"}}
            for kind in ("list", "scan")
        ]
        patch.require(sorted(detailed["parameters"], key=lambda item: item["name"])
                      == expected_detailed)
        detailed["operationId"] = "kv-list-detailed-metadata-path"
        detailed["parameters"] = expected_detailed
        for path, operation, schema in (
                ("/sys/namespaces", "namespaces-{}-namespaces", "Namespaces{}NamespacesResponse"),
                ("/sys/workflows/manage", "workflows-{}-workflows-manage",
                 "Workflows{}WorkflowsManageResponse")):
            schemas = document["components"]["schemas"]
            patch.require(schemas[schema.format("List")] == schemas[schema.format("Scan")])
            get = document["paths"][path]["get"]
            selected = next((kind for kind in ("list", "scan")
                             if get["operationId"] == operation.format(kind)), None)
            patch.require(selected is not None)
            response = get["responses"]["200"]["content"]["application/json"]["schema"]
            patch.require(response == {"$ref": "#/components/schemas/" +
                                       schema.format(selected.title())})
            expected = [{"in": "query", "name": kind, "required": True,
                         "schema": {"enum": ["true"], "type": "string"}}
                        for kind in ("list", "scan")]
            patch.require(sorted(get["parameters"], key=lambda item: item["name"]) == expected)
            get["parameters"] = expected
            get["operationId"] = operation.format("list")
            response["$ref"] = "#/components/schemas/" + schema.format("List")
    patch.require(left == right)


def validate_report(suite, data):
    report = initial.checked(data, REPORTS[suite], 128 * 1024)
    expected = {"schema": "openbao-patch-regression/v1", "version": patch.VERSION, "suite": suite,
                "inputs": runner.input_hashes(), "image_linux_amd64_digest": patch.AMD64,
                "image_index_digest": patch.INDEX, "tls": "TLSv1.3",
                "scope": "server-fixture-only-not-sdk-integration", "routable": False,
                "outcome": "passed",
                "harness_checks": ["exact-version", "tls-rejections", "resource-limits",
                                   "network-isolation", "cleanup"]}
    if suite == "api":
        expected.update(checks=["full-builtin-openapi", "raw-storage-enabled", "external-plugins-absent"],
                        openapi_sha256=OPENAPI_SHA256)
    else:
        expected["checks"] = MODULES[suite].CHECKS
    if suite == "control-groups":
        expected.update(server_replay_rejected=False,
                        outcome="completed-with-known-upstream-replay-failure")
    patch.require(base.canonical_json(report) == base.canonical_json(expected))
    return report


def validate_api(data):
    api = initial.checked(data, OPENAPI_SHA256, base.MAX_OPENAPI_BYTES)
    mounts = initial.verify()["initial-openapi.json"]["mounts"]
    patch.require(api == patch.normalize_api(api["document"], mounts))
    # Compare against the immutable predecessor API artifact without requiring
    # unrelated 2.7.1 server reports to match current 2.7.2 source inputs.
    prior = predecessor.initial.checked(
        base.read_regular_file(predecessor.OUTPUT / "openapi.json", base.MAX_OPENAPI_BYTES),
        predecessor.OPENAPI_SHA256,
        base.MAX_OPENAPI_BYTES,
    )
    compare_api(prior, api)
    return api


def verify():
    api = validate_api(base.read_regular_file(OUTPUT / "openapi.json", base.MAX_OPENAPI_BYTES))
    for suite in REPORTS:
        validate_report(suite, base.read_regular_file(OUTPUT / (suite + "-tls.json"), 128 * 1024))
    return api


def retain(suite, result):
    source = result / "report.json" if suite == "api" else result
    data = base.read_regular_file(source, 128 * 1024)
    validate_report(suite, data)
    if suite == "api":
        api = base.read_regular_file(result / "openapi.json", base.MAX_OPENAPI_BYTES)
        validate_api(api)
        base.write_immutable(OUTPUT / "openapi.json", api)
    base.write_immutable(OUTPUT / (suite + "-tls.json"), data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retain", choices=tuple(REPORTS))
    parser.add_argument("--result", type=Path)
    args = parser.parse_args()
    try:
        if args.retain:
            if not args.result:
                parser.error("--retain requires --result (API result uses its directory)")
            retain(args.retain, args.result)
        else:
            verify()
    except (runner.harness.HarnessError, base.SnapshotError, OSError, ValueError, KeyError, TypeError):
        print("2.7.2 regression evidence failed; no promotion")
        return 1
    print("2.7.2 server evidence verified; replay limitation retained; no SDK promotion")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
