#!/usr/bin/python3 -EsSB
"""Stage a patch profile from reviewed equal contracts; do not promote main."""

import argparse
import copy

import generate_openbao_2_7_candidate as previous
import verify_openbao_2_7_1_regressions as evidence

registry = previous.registry
OUTPUT = evidence.OUTPUT / "candidate-capability-registry-v2.json"
EXPECTED_SHA256 = "876182f813520e1a51c8bcf3b0a8910c133a0c88f3f9ab7608a691a30e05ffb6"


def build():
    evidence.verify()
    parent = previous.verify()
    docs = evidence.patch.verify_source()
    old_docs = previous.staged.parse(previous.staged.verify()["documentation.json"])
    evidence.patch.require(docs["files"] == old_docs["files"] and docs["operations"] == old_docs["operations"])
    result = copy.deepcopy(parent)
    result.update(schema="openbao-patch-candidate-capability-registry/v1", scope="candidate-contracts-not-public-dispatch",
                  predecessor_registry_sha256=previous.EXPECTED_SHA256, patch_openapi_sha256=evidence.OPENAPI_SHA256,
                  patch_documentation_sha256=evidence.patch.DOCUMENTATION_SHA256,
                  patch_report_sha256=dict(evidence.REPORTS))
    result["versions"].append(evidence.patch.VERSION)
    result["routable_versions"] = parent["versions"]
    for op in result["operations"]:
        latest = op["ranges"][-1]
        evidence.patch.require(latest["minimum"] == "2.7.0" and latest["maximum"] == "2.7.0")
        op["ranges"].append({**latest, "minimum": evidence.patch.VERSION, "maximum": evidence.patch.VERSION})
    for endpoint in result["logical_endpoints"]:
        last = endpoint["variants"][-1]
        evidence.patch.require(last["maximum"] == "2.7.0")
        endpoint["variants"].append({**last, "minimum": evidence.patch.VERSION, "maximum": evidence.patch.VERSION})
    result["summary"]["new_identities"] = 0
    return result


def verify():
    expected = build()
    data = registry.read_regular_file(OUTPUT, registry.MAX_OUTPUT_BYTES)
    evidence.patch.require(registry.sha256(data) == EXPECTED_SHA256 and data == registry.canonical_json(expected))
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
    except (evidence.runner.harness.HarnessError, registry.RegistryError, registry.SnapshotError,
            OSError, ValueError, KeyError, TypeError):
        print("2.7.1 candidate failed validation; no promotion")
        return 1
    print("2.7.1 candidate verified; normal SDK profile remains non-routable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
