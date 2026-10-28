#!/usr/bin/python3 -EsSB
"""Reconcile reviewed 2.6.5 and 2.7.2 patch contracts for SDK promotion."""

import argparse
import copy

import generate_openbao_2_6_5_candidate as legacy
import generate_openbao_2_7_2_candidate as modern

registry = legacy.registry
require = legacy.evidence.patch.require
OUTPUT = modern.evidence.OUTPUT / "combined-capability-registry.json"
EXPECTED_SHA256 = "76be4df50299db39e882d6bfe13b9f35164ba329ceb8eefa60a88e46accbbb27"


def selected(items, version, *, optional=False):
    return legacy.selected(items, version, optional=optional)


def combine(left, right):
    require(registry.sha256(registry.canonical_json(left)) == legacy.EXPECTED_SHA256)
    require(registry.sha256(registry.canonical_json(right)) == modern.EXPECTED_SHA256)
    base = [*registry.EXPECTED_VERSIONS]
    left_versions = [*base, "2.6.4", "2.6.5", "2.7.0"]
    right_versions = [*base, "2.7.0", "2.7.1", "2.7.2"]
    require(left["versions"] == left_versions and right["versions"] == right_versions)
    require(left["routable"] is False and right["routable"] is False)

    result = copy.deepcopy(left)
    for key in ("patch_openapi_sha256", "patch_documentation_sha256", "patch_report_sha256"):
        del result[key]
    result.update(schema="openbao-combined-patch-candidate-registry/v2",
                  scope="candidate-contracts-not-public-dispatch",
                  patch_registry_sha256={"2.6.5": legacy.EXPECTED_SHA256,
                                         "2.7.2": modern.EXPECTED_SHA256})
    result["versions"].extend(("2.7.1", "2.7.2"))
    result["routable_versions"] = [*base, "2.6.4", "2.7.0", "2.7.1"]

    require(len(left["operations"]) == len(right["operations"]) == 707)
    for old, new, target in zip(left["operations"], right["operations"], result["operations"], strict=True):
        require({key: value for key, value in old.items() if key != "ranges"} ==
                {key: value for key, value in new.items() if key != "ranges"})
        for version in [*base, "2.7.0"]:
            require(selected(old["ranges"], version) == selected(new["ranges"], version))
        for version in ("2.7.1", "2.7.2"):
            extension = selected(new["ranges"], version)
            require(extension["minimum"] == extension["maximum"] == version)
            target["ranges"].append(copy.deepcopy(extension))

    require(len(left["logical_endpoints"]) == len(right["logical_endpoints"]))
    for old, new, target in zip(left["logical_endpoints"], right["logical_endpoints"],
                                result["logical_endpoints"], strict=True):
        require({key: value for key, value in old.items() if key != "variants"} ==
                {key: value for key, value in new.items() if key != "variants"})
        for version in [*base, "2.7.0"]:
            require(selected(old["variants"], version, optional=True) ==
                    selected(new["variants"], version, optional=True))
        for version in ("2.7.1", "2.7.2"):
            extension = selected(new["variants"], version, optional=True)
            if extension is not None:
                require(extension["minimum"] == extension["maximum"] == version)
                target["variants"].append(copy.deepcopy(extension))

    result["summary"] = {"operations": 707, "profile_count": len(result["versions"]),
                         "new_identities": 0,
                         "patch_states": {"2.6.5": left["summary"]["candidate_states"],
                                          "2.7.2": {"copied_from": "2.7.1"}}}
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
    except (legacy.evidence.patch.harness.HarnessError, registry.RegistryError,
            registry.SnapshotError, OSError, ValueError, KeyError, TypeError):
        print("Combined patch registry failed; no compatibility promotion")
        return 1
    print("30 profiles reconciled; historical contracts preserved; ready for normal routing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
