#!/usr/bin/python3 -EsSB
"""Verify exact patch-regression artifacts and the reviewed API delta."""

import argparse
import copy
from pathlib import Path

import openbao_2_7_1_regressions as runner
import verify_openbao_2_7_1 as initial
from maintenance_control_evidence import expected_inputs

patch, base = runner.patch, runner.base
OUTPUT = initial.OUTPUT
OPENAPI_SHA256 = "7e7e778beb427a7be13576076f0a68ae1d4db19fc4bc0819df8fb0f8956d90dc"
REFRESH_OPENAPI_SHA256 = "5197838a955d3a7ea188c93595f44aa38999cd04a01ec1e04de1335feb1d025d"
# The immutable candidate registry includes these historical report identities.
REPORTS = {
    "api": "2584a5833089a5b1d99b75eb94f402f8a9253572e3efb12a29514faca08cec55",
    "control-groups": "5731d362fa9a907aad5c304a6ddba0935a4cf0e0b98f5b3d478429a605674d8d",
    "external-keys": "6b7e420082add2f612178e660e751de2814404b9e15174b5144e1774a083ac4f",
    "mfa-totp": "f60afaad5b747fadd5a04635277b932f49d761317964199e3e9fbc79a5929558",
    "pki": "eeb1b4dcb157ef9d629e9dea1add18062ed061864c70e1eaec9dbf9fe05c47ee",
    "system": "7378657bfc58b3658a2831068263f078b03d90f21aeac22b3024fa7f8632c587",
    "transit": "d9995a9cbb0e869d98539ecb7656056f7610660d19e2eb4ea9b5fe7568e10e5a",
    "workflow-cas": "06bc49b04cfa991f73b027906f5cde8ff5980527165eade1c4d05b9ba09874ec",
}
CURRENT_REPORTS = {
    "api": "0f67b4587238d526d2cd3533907b2ba844322fe9aca00fff9b29931c5444e11d",
    "external-keys": "232e28334a3884594a8b27de86ca1bdbb261d7c0c1f935e5f8da00d0a4fac1a4",
    "transit": "88495a95ec057b46f5b0b4ceb71a22256f62e04048addd9c1afa9269b1ababa4",
    "pki": "1b39d27b8098563056f4515c334fa4e4d9171e38f52edd7249508840724843cc",
    "workflow-cas": "17781632fb09ac55a3245bd0ca6302794362f42e56737ad1bcbcedf92a0c2a95",
    "control-groups": "5731d362fa9a907aad5c304a6ddba0935a4cf0e0b98f5b3d478429a605674d8d",
    "system": "eb1821a61146f1eaedf2449a14a8d3e2ac098c1c149a57cd018f9ec94471e57a",
    "mfa-totp": "d08f0d3c0c66edab2cc5fc46f9078007375831142d360c62934d3c82b9c1eeff",
}
MODULES = {"external-keys": runner.external, "transit": runner.transit, "pki": runner.pki,
           "workflow-cas": runner.workflow, "control-groups": runner.control,
           "system": runner.system, "mfa-totp": runner.mfa}


def compare_api(before, after):
    """Only collapse the two reviewed equivalent LIST/SCAN projections."""
    left, right = copy.deepcopy(before["document"]), copy.deepcopy(after["document"])
    patch.require(left["info"]["version"] == "2.7.0" and right["info"]["version"] == patch.VERSION)
    patch.require(before["mounts"] == after["mounts"])
    right["info"]["version"] = left["info"]["version"]
    patch.require(left["components"] == right["components"])
    for doc in (left, right):
        for path, operation, schema in (("/sys/namespaces", "namespaces-{}-namespaces", "Namespaces{}NamespacesResponse"),
                                        ("/sys/workflows/manage", "workflows-{}-workflows-manage", "Workflows{}WorkflowsManageResponse")):
            schemas = doc["components"]["schemas"]
            patch.require(schemas[schema.format("List")] == schemas[schema.format("Scan")])
            get = doc["paths"][path]["get"]
            selected = next((kind for kind in ("list", "scan") if get["operationId"] == operation.format(kind)), None)
            patch.require(selected is not None)
            ref = get["responses"]["200"]["content"]["application/json"]["schema"]
            patch.require(ref == {"$ref": "#/components/schemas/" + schema.format(selected.title())})
            parameters = get["parameters"]
            expected = [{"in": "query", "name": kind, "required": True,
                         "schema": {"enum": ["true"], "type": "string"}} for kind in ("list", "scan")]
            patch.require(sorted(parameters, key=lambda item: item["name"]) == expected)
            get["parameters"] = expected
            get["operationId"] = operation.format("list")
            ref["$ref"] = "#/components/schemas/" + schema.format("List")
        path = "/{kv_v2_mount_path}/detailed-metadata/{path}"
        get = doc["paths"][path]["get"]
        patch.require(get["operationId"] in {
            "kv-list-detailed-metadata-path", "kv-scan-detailed-metadata-path"})
        expected = [{"in": "query", "name": kind, "required": True,
                     "schema": {"enum": ["true"], "type": "string"}}
                    for kind in ("list", "scan")]
        patch.require(sorted(get["parameters"], key=lambda item: item["name"]) == expected)
        get["operationId"] = "kv-list-detailed-metadata-path"
        get["parameters"] = expected
    patch.require(left == right)


def report_path(suite):
    patch.require(suite in REPORTS)
    suffix = "-tls-v2.json" if suite == "control-groups" else "-tls-v3.json"
    return OUTPUT / (suite + suffix)


def validate_report(suite, data):
    report = initial.checked(data, CURRENT_REPORTS[suite], 128 * 1024)
    expected = {"schema": "openbao-patch-regression/v1", "version": patch.VERSION, "suite": suite,
                "inputs": runner.input_hashes(), "image_linux_amd64_digest": patch.AMD64,
                "image_index_digest": patch.INDEX, "tls": "TLSv1.3",
                "scope": "server-fixture-only-not-sdk-integration", "routable": False, "outcome": "passed",
                "harness_checks": ["exact-version", "tls-rejections", "resource-limits", "network-isolation", "cleanup"]}
    if suite == "api":
        expected.update(checks=["full-builtin-openapi", "raw-storage-enabled", "external-plugins-absent"],
                        openapi_sha256=REFRESH_OPENAPI_SHA256)
    else:
        expected["checks"] = MODULES[suite].CHECKS
    if suite == "control-groups":
        expected["inputs"] = expected_inputs(patch.VERSION, base.sha256(data), expected["inputs"])
        expected.update(server_replay_rejected=False, outcome="completed-with-known-upstream-replay-failure")
    patch.require(base.canonical_json(report) == base.canonical_json(expected))
    return report


def validate_api(data, *, refreshed=False):
    api = initial.checked(data, REFRESH_OPENAPI_SHA256 if refreshed else OPENAPI_SHA256, base.MAX_OPENAPI_BYTES)
    mounts = initial.verify()["initial-openapi.json"]["mounts"]
    patch.require(api == patch.normalize_api(api["document"], mounts))
    prior = patch.tls.staged.verify()
    compare_api(base.parse_json(prior["openapi.json"], base.MAX_OPENAPI_BYTES), api)
    return api


def verify():
    api = validate_api(base.read_regular_file(OUTPUT / "openapi.json", base.MAX_OPENAPI_BYTES))
    validate_api(base.read_regular_file(OUTPUT / "openapi-v3.json", base.MAX_OPENAPI_BYTES), refreshed=True)
    for suite in REPORTS:
        validate_report(suite, base.read_regular_file(report_path(suite), 128 * 1024))
    return api


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--retain", choices=tuple(REPORTS))
    parser.add_argument("--result", type=Path)
    args = parser.parse_args()
    try:
        if args.retain:
            if not args.result:
                parser.error("--retain requires --result (API result uses its directory)")
            source = args.result / "report.json" if args.retain == "api" else args.result
            data = base.read_regular_file(source, 128 * 1024)
            validate_report(args.retain, data)
            if args.retain == "api":
                api = base.read_regular_file(args.result / "openapi.json", base.MAX_OPENAPI_BYTES)
                validate_api(api, refreshed=True)
                base.write_immutable(OUTPUT / "openapi-v3.json", api)
            base.write_immutable(report_path(args.retain), data)
        else:
            verify()
    except (runner.harness.HarnessError, base.SnapshotError, OSError, ValueError, KeyError, TypeError):
        print("2.7.1 regression evidence failed; no promotion")
        return 1
    print("2.7.1 server evidence verified; replay limitation retained; no SDK promotion")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
