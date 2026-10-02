#!/usr/bin/python3 -EsSB
"""Verify exact patch-regression artifacts and the reviewed API delta."""

import argparse
import copy
from pathlib import Path

import openbao_2_7_1_regressions as runner
import verify_openbao_2_7_1 as initial

patch, base = runner.patch, runner.base
OUTPUT = initial.OUTPUT
OPENAPI_SHA256 = "5197838a955d3a7ea188c93595f44aa38999cd04a01ec1e04de1335feb1d025d"
REPORTS = {
    "api": "7ac766d59ac242599068502f3083bf6f14f8c646ffbec34ccbc2bfd0d3337322",
    "external-keys": "c0dd42ed899ec9f048176f63e59dc74e53b17953c3588d7ff459b59d10344ea4",
    "transit": "f46a4c322f889857c839eb36d75bf05b3464778e1f6affdb30fbaee6bf9ec42a",
    "pki": "0d576b27b122f544040ff3dc7ca0bbae6fa616b8d49c92cde4c88a422f542597",
    "workflow-cas": "ede51309d36c144b83c8c075fd2d6697c9fc67b9dd9db21797e0921e5180b9aa",
    "control-groups": "731e1732814d78ffa4db0a4ce62e232bd0ea48a5eb2028a94b3d76f49f10d656",
    "system": "71fc6c71fdc4666d17787476196d8062b293164ef9a0af32fa1925b4a555366e",
    "mfa-totp": "4229d401c5b6df968669ac1579358a70c838c80f036e12c835da379a30a2fb42",
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
