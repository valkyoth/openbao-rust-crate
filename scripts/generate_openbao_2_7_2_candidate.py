#!/usr/bin/python3 -EsSB
"""Stage the reviewed 2.7.2 patch profile without promoting it."""

import argparse
import copy

import generate_openbao_2_7_1_candidate as previous
import verify_openbao_2_7_2_regressions as evidence

registry = previous.registry
OUTPUT = evidence.OUTPUT / "candidate-capability-registry.json"
EXPECTED_SHA256 = "416a2de3e2d93393953439c7883f441ad55c15eaca7d9da0a6ca9c8ee1d0846c"


def load_parent():
    data = registry.read_regular_file(previous.OUTPUT, registry.MAX_OUTPUT_BYTES)
    evidence.patch.require(registry.sha256(data) == previous.EXPECTED_SHA256)
    parent = registry.parse_json(data, registry.MAX_OUTPUT_BYTES)
    evidence.patch.require(registry.canonical_json(parent) == data)
    return parent


def build():
    evidence.verify()
    parent = load_parent()
    result = copy.deepcopy(parent)
    result.update(schema="openbao-patch-candidate-capability-registry/v1",
                  scope="candidate-contracts-not-public-dispatch",
                  predecessor_registry_sha256=previous.EXPECTED_SHA256,
                  patch_openapi_sha256=evidence.OPENAPI_SHA256,
                  patch_documentation_sha256=evidence.patch.DOCUMENTATION_SHA256,
                  patch_report_sha256=dict(evidence.REPORTS))
    result["versions"].append(evidence.patch.VERSION)
    result["routable_versions"] = parent["versions"]
    result["routable"] = False
    for operation in result["operations"]:
        latest = operation["ranges"][-1]
        evidence.patch.require(latest["minimum"] == latest["maximum"] == "2.7.1")
        operation["ranges"].append({**latest, "minimum": evidence.patch.VERSION,
                                    "maximum": evidence.patch.VERSION})
    for endpoint in result["logical_endpoints"]:
        latest = endpoint["variants"][-1]
        evidence.patch.require(latest["minimum"] == latest["maximum"] == "2.7.1")
        endpoint["variants"].append({**latest, "minimum": evidence.patch.VERSION,
                                     "maximum": evidence.patch.VERSION})
    result["summary"] = {"operations": len(result["operations"]),
                         "profile_count": len(result["versions"]), "new_identities": 0}
    return result


def verify():
    expected = build()
    data = registry.read_regular_file(OUTPUT, registry.MAX_OUTPUT_BYTES)
    evidence.patch.require(registry.sha256(data) == EXPECTED_SHA256
                           and data == registry.canonical_json(expected))
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate", action="store_true")
    args = parser.parse_args()
    try:
        if args.generate:
            data = registry.canonical_json(build())
            evidence.patch.require(registry.sha256(data) == EXPECTED_SHA256)
            evidence.base.write_immutable(OUTPUT, data)
        verify()
    except (evidence.runner.harness.HarnessError, registry.RegistryError,
            registry.SnapshotError, OSError, ValueError, KeyError, TypeError):
        print("2.7.2 candidate failed validation; no promotion")
        return 1
    print("2.7.2 candidate verified; historical cells preserved; no normal dispatch promotion")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
