#!/usr/bin/python3 -EsSB
"""Combine reviewed 2.6.4/2.7.1 contracts for SDK 2.2.1, without promotion."""

import argparse
import copy

import generate_openbao_2_6_4_candidate as legacy
import generate_openbao_2_7_1_candidate as modern

registry = legacy.registry
require = legacy.evidence.patch.require
OUTPUT = modern.evidence.OUTPUT / "combined-capability-registry.json"
EXPECTED_SHA256 = "71913f4685cf08882bd24b77b9067fbb1e168c4a70b7a5350e068189358f9ade"


def combine(left, right):
    # Each branch has its own API evidence and predecessor. Never infer the
    # 2.6 patch's engine availability from the 2.7 patch's plugin exclusions.
    require(registry.sha256(registry.canonical_json(left)) == legacy.EXPECTED_SHA256)
    require(registry.sha256(registry.canonical_json(right)) == modern.EXPECTED_SHA256)
    historical = [*registry.EXPECTED_VERSIONS, "2.7.0"]
    require(left["versions"] == [*registry.EXPECTED_VERSIONS, "2.6.4", "2.7.0"])
    require(right["versions"] == [*historical, "2.7.1"])
    require(left["routable_versions"] == right["routable_versions"] == historical)
    require(left["routable"] is False and right["routable"] is False)
    result = copy.deepcopy(left)
    for key in ("patch_openapi_sha256", "patch_documentation_sha256", "patch_report_sha256"):
        del result[key]
    result.update(schema="openbao-combined-patch-candidate-registry/v1",
                  patch_registry_sha256={"2.6.4": legacy.EXPECTED_SHA256, "2.7.1": modern.EXPECTED_SHA256})
    result["versions"].append("2.7.1")
    require(len(left["operations"]) == len(right["operations"]) == 707)
    for old, new, target in zip(left["operations"], right["operations"], result["operations"], strict=True):
        require({k: v for k, v in old.items() if k != "ranges"} ==
                {k: v for k, v in new.items() if k != "ranges"})
        for version in historical:
            require(legacy.selected(old["ranges"], version) == legacy.selected(new["ranges"], version))
        extension = legacy.selected(new["ranges"], "2.7.1")
        require(extension["minimum"] == extension["maximum"] == "2.7.1")
        target["ranges"].append(copy.deepcopy(extension))
    require(len(left["logical_endpoints"]) == len(right["logical_endpoints"]))
    for old, new in zip(left["logical_endpoints"], right["logical_endpoints"], strict=True):
        require({k: v for k, v in old.items() if k != "variants"} ==
                {k: v for k, v in new.items() if k != "variants"})
        require(old["variants"] == new["variants"][:-1])
        require(new["variants"][-1]["minimum"] == new["variants"][-1]["maximum"] == "2.7.1")
        require(legacy.selected(old["variants"], "2.6.4", optional=True) ==
                legacy.selected(new["variants"], "2.6.4", optional=True))
    result["logical_endpoints"] = copy.deepcopy(right["logical_endpoints"])
    result["summary"] = {"operations": 707, "profile_count": len(result["versions"]), "new_identities": 0,
                         "patch_states": {"2.6.4": left["summary"]["candidate_states"],
                                          "2.7.1": right["summary"]["candidate_states"]}}
    return result


def build():
    return combine(legacy.verify(), modern.verify())


def verify():
    expected = registry.canonical_json(build())
    data = registry.read_regular_file(OUTPUT, registry.MAX_OUTPUT_BYTES)
    require(registry.sha256(data) == EXPECTED_SHA256 and data == expected)
    return registry.parse_json(data, registry.MAX_OUTPUT_BYTES)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate", action="store_true")
    args = parser.parse_args()
    try:
        if args.generate:
            data = registry.canonical_json(build())
            require(registry.sha256(data) == EXPECTED_SHA256)
            legacy.evidence.base.write_immutable(OUTPUT, data)
        verify()
    except (legacy.evidence.patch.harness.HarnessError, registry.RegistryError, registry.SnapshotError,
            OSError, ValueError, KeyError, TypeError):
        print("Combined patch registry failed; no compatibility promotion")
        return 1
    print("28 profiles reconciled; historical contracts preserved; no normal routing promotion")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
