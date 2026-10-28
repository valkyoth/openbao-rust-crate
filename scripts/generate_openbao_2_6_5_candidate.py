#!/usr/bin/python3 -EsSB
"""Stage 2.6.5 from the reviewed 2.6.4 profile without promoting it."""

import argparse
import copy

import generate_openbao_2_6_4_candidate as previous
import verify_openbao_2_6_5 as evidence

registry = previous.registry
OUTPUT = evidence.OUTPUT / "candidate-capability-registry.json"
EXPECTED_SHA256 = "f42b9a6820e2c9ca7c9eee1fb371e26e86b4d25e774fe47151403058a932b359"


def load_parent():
    data = registry.read_regular_file(previous.OUTPUT, registry.MAX_OUTPUT_BYTES)
    evidence.patch.require(registry.sha256(data) == previous.EXPECTED_SHA256)
    parent = registry.parse_json(data, registry.MAX_OUTPUT_BYTES)
    evidence.patch.require(registry.canonical_json(parent) == data)
    return parent


def selected(items, version, *, optional=False):
    number = registry.version_tuple(version)
    matches = [item for item in items if registry.version_tuple(item["minimum"]) <= number
               <= registry.version_tuple(item["maximum"])]
    evidence.patch.require(len(matches) == 1 or (optional and not matches))
    return matches[0] if matches else None


def build():
    evidence.verify()
    parent = load_parent()
    evidence.patch.require(parent["versions"][-2:] == ["2.6.4", "2.7.0"])
    result = copy.deepcopy(parent)
    result.update(schema="openbao-patch-candidate-capability-registry/v1",
                  scope="candidate-contracts-not-public-dispatch",
                  predecessor_registry_sha256=previous.EXPECTED_SHA256,
                  patch_openapi_sha256=evidence.ARTIFACTS["openapi.json"][1],
                  patch_documentation_sha256=evidence.patch.DOCUMENTATION_SHA256,
                  patch_report_sha256=evidence.ARTIFACTS["patch-tls.json"][1])
    result["versions"].insert(-1, evidence.patch.VERSION)
    result["routable_versions"] = parent["versions"]
    result["routable"] = False
    for operation in result["operations"]:
        ranges = operation["ranges"]
        predecessor = selected(ranges, "2.6.4")
        evidence.patch.require(predecessor["minimum"] == predecessor["maximum"] == "2.6.4"
                               and ranges[-1]["minimum"] == "2.7.0")
        ranges.insert(-1, {**predecessor, "minimum": evidence.patch.VERSION,
                           "maximum": evidence.patch.VERSION})
    # Preserve both existing routes and intentional gaps (request inspection
    # is unavailable on 2.6); reject an interval that selects a different route.
    for endpoint in result["logical_endpoints"]:
        evidence.patch.require(selected(endpoint["variants"], "2.6.4", optional=True) ==
                               selected(endpoint["variants"], "2.6.5", optional=True))
    counts = {}
    for operation in result["operations"]:
        state = selected(operation["ranges"], "2.6.5")["availability"]
        counts[state] = counts.get(state, 0) + 1
    result["summary"] = {"candidate_states": counts, "new_identities": 0,
                         "operations": len(result["operations"])}
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
    except (evidence.patch.harness.HarnessError, registry.RegistryError, registry.SnapshotError,
            OSError, ValueError, KeyError, TypeError):
        print("2.6.5 candidate failed validation; no promotion")
        return 1
    print("2.6.5 candidate verified; historical cells preserved; no normal dispatch promotion")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
