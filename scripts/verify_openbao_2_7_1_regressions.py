#!/usr/bin/python3 -EsSB
"""Verify exact patch-regression artifacts and the reviewed API delta."""

import argparse
import copy
from pathlib import Path

import openbao_2_7_1_regressions as runner
import verify_openbao_2_7_1 as initial

patch, base = runner.patch, runner.base
OUTPUT = initial.OUTPUT
OPENAPI_SHA256 = "7e7e778beb427a7be13576076f0a68ae1d4db19fc4bc0819df8fb0f8956d90dc"
REPORTS = {
    "api": "2584a5833089a5b1d99b75eb94f402f8a9253572e3efb12a29514faca08cec55",
    "external-keys": "6b7e420082add2f612178e660e751de2814404b9e15174b5144e1774a083ac4f",
    "transit": "d9995a9cbb0e869d98539ecb7656056f7610660d19e2eb4ea9b5fe7568e10e5a",
    "pki": "eeb1b4dcb157ef9d629e9dea1add18062ed061864c70e1eaec9dbf9fe05c47ee",
    "workflow-cas": "06bc49b04cfa991f73b027906f5cde8ff5980527165eade1c4d05b9ba09874ec",
    "control-groups": "5731d362fa9a907aad5c304a6ddba0935a4cf0e0b98f5b3d478429a605674d8d",
    "system": "7378657bfc58b3658a2831068263f078b03d90f21aeac22b3024fa7f8632c587",
    "mfa-totp": "f60afaad5b747fadd5a04635277b932f49d761317964199e3e9fbc79a5929558",
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


def validate_report(suite, data):
    report = initial.checked(data, REPORTS[suite], 128 * 1024)
    expected = {"schema": "openbao-patch-regression/v1", "version": patch.VERSION, "suite": suite,
                "inputs": runner.input_hashes(), "image_linux_amd64_digest": patch.AMD64,
                "image_index_digest": patch.INDEX, "tls": "TLSv1.3",
                "scope": "server-fixture-only-not-sdk-integration", "routable": False, "outcome": "passed",
                "harness_checks": ["exact-version", "tls-rejections", "resource-limits", "network-isolation", "cleanup"]}
    if suite == "api":
        expected.update(checks=["full-builtin-openapi", "raw-storage-enabled", "external-plugins-absent"],
                        openapi_sha256=OPENAPI_SHA256)
    else:
        expected["checks"] = MODULES[suite].CHECKS
    if suite == "control-groups":
        expected.update(server_replay_rejected=False, outcome="completed-with-known-upstream-replay-failure")
    patch.require(base.canonical_json(report) == base.canonical_json(expected))
    return report


def validate_api(data):
    api = initial.checked(data, OPENAPI_SHA256, base.MAX_OPENAPI_BYTES)
    mounts = initial.verify()["initial-openapi.json"]["mounts"]
    patch.require(api == patch.normalize_api(api["document"], mounts))
    prior = patch.tls.staged.verify()
    compare_api(base.parse_json(prior["openapi.json"], base.MAX_OPENAPI_BYTES), api)
    return api


def verify():
    api = validate_api(base.read_regular_file(OUTPUT / "openapi.json", base.MAX_OPENAPI_BYTES))
    for suite in REPORTS:
        validate_report(suite, base.read_regular_file(OUTPUT / (suite + "-tls-v2.json"), 128 * 1024))
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
                validate_api(api)
                base.write_immutable(OUTPUT / "openapi.json", api)
            base.write_immutable(OUTPUT / (args.retain + "-tls-v2.json"), data)
        else:
            verify()
    except (runner.harness.HarnessError, base.SnapshotError, OSError, ValueError, KeyError, TypeError):
        print("2.7.1 regression evidence failed; no promotion")
        return 1
    print("2.7.1 server evidence verified; replay limitation retained; no SDK promotion")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
