#!/usr/bin/python3 -EsSB
"""Normal-build release evidence cannot accept candidate, stale or partial reports."""

from contextlib import ExitStack
import copy
import unittest
from unittest.mock import patch

import verify_openbao_patch_normal_sdk as evidence


class EvidenceTests(unittest.TestCase):
    def test_pre_auth_reports_cannot_satisfy_current_sources(self):
        digests = {
            "2.6.4": "360fc1d8df609867d7b2e0cdce4dd1e5da43914817bf70cc4fe90d8a5e36990d",
            "2.7.1": "afd27fc0409f827449078d4b77ed498615ee9163b7ac436755b0866eb6b2c1dd",
        }
        for version, digest in digests.items():
            fixture = evidence.FIXTURES[version]
            data = evidence.base.read_regular_file(evidence.output(version).with_name("sdk-normal-tls-v2.json"), 128 * 1024)
            self.assertEqual(evidence.base.sha256(data), digest)
            old = evidence.base.parse_json(data, 128 * 1024)
            current = evidence.base.read_regular_file(evidence.output(version), 128 * 1024)
            report = evidence.base.parse_json(current, 128 * 1024)
            released = evidence.base.parse_json(evidence.base.read_regular_file(
                evidence.output(version).with_name("sdk-normal-tls-v3.json"), 128 * 1024), 128 * 1024)
            self.assertEqual(old["inputs"]["Cargo.lock"], released["inputs"]["Cargo.lock"])
            with self.subTest(version=version), \
                 patch.object(fixture.normal_sdk, "verify", return_value=fixture.normal_sdk.verify()):
                with patch.object(evidence, "PINS", {version: (digest, old["test_binary_sha256"])}), \
                     self.assertRaises(evidence.harness.HarnessError):
                    evidence.validate(version, data)
                # Keep the new binary, README and schema, isolating each old
                # auth input so README rejection cannot mask a source bypass.
                for name in ("jwt", "kerberos", "ldap", "mod", "radius"):
                    key = "src/auth/" + name + ".rs"
                    changed = copy.deepcopy(report)
                    self.assertNotEqual(old["inputs"][key], report["inputs"][key])
                    changed["inputs"][key] = old["inputs"][key]
                    altered = evidence.base.canonical_json(changed)
                    with self.subTest(input=key), \
                         patch.object(evidence, "PINS", {version: (evidence.base.sha256(altered), report["test_binary_sha256"])}), \
                         self.assertRaises(evidence.harness.HarnessError):
                        evidence.validate(version, altered)

    def test_pre_dependency_reports_are_preserved_but_not_current(self):
        digests = {
            "2.6.4": "3766ed4490f3ef971d892f7824beed03018c0bf4ec8ab37dcf656c46c26758a6",
            "2.7.1": "9ae2ed0030bac654160f2e49f9d7e9f84705ae06fcad284b9ad486c7f96c68e6",
        }
        for version, digest in digests.items():
            fixture = evidence.FIXTURES[version]
            data = evidence.base.read_regular_file(evidence.output(version).with_name("sdk-normal-tls.json"), 128 * 1024)
            self.assertEqual(evidence.base.sha256(data), digest)
            old = evidence.base.parse_json(data, 128 * 1024)
            current = evidence.base.read_regular_file(evidence.output(version), 128 * 1024)
            report = evidence.base.parse_json(current, 128 * 1024)
            self.assertNotEqual(old["inputs"]["Cargo.lock"], report["inputs"]["Cargo.lock"])
            with self.subTest(version=version), \
                 patch.object(fixture.normal_sdk, "verify", return_value=fixture.normal_sdk.verify()):
                with patch.object(evidence, "PINS", {version: (digest, old["test_binary_sha256"])}), \
                     self.assertRaises(evidence.harness.HarnessError):
                    evidence.validate(version, data)
                # Isolate the lockfile change: even a repinned report using
                # the new binary and accepted README cannot reuse the old lock.
                report["inputs"]["Cargo.lock"] = old["inputs"]["Cargo.lock"]
                altered = evidence.base.canonical_json(report)
                with patch.object(evidence, "PINS", {version: (evidence.base.sha256(altered), report["test_binary_sha256"])}), \
                     self.assertRaises(evidence.harness.HarnessError):
                    evidence.validate(version, altered)

    def test_every_input_including_readme_matches_exactly(self):
        for version, fixture in evidence.FIXTURES.items():
            with self.subTest(version=version):
                data = evidence.base.read_regular_file(evidence.output(version), 128 * 1024)
                report = evidence.base.parse_json(data, 128 * 1024)
                current = fixture.input_hashes(normal=True)
                changed = {name for name in set(current) | set(report["inputs"])
                           if current.get(name) != report["inputs"].get(name)}
                self.assertEqual(changed, set())
                with patch.object(fixture.normal_sdk, "verify", return_value=fixture.normal_sdk.verify()):
                    for name in current:
                        for omit in (False, True):
                            altered = dict(current)
                            if omit:
                                del altered[name]
                            else:
                                altered[name] = "0" * 64
                            with self.subTest(input=name, omit=omit), \
                                 patch.object(fixture, "input_hashes", return_value=altered), \
                                 self.assertRaises(evidence.harness.HarnessError):
                                evidence.validate(version, data)

    def test_2_2_1_captures_are_preserved_and_each_old_metadata_input_is_rejected(self):
        pins = {"2.6.4": "bd5d855ff99869fcaecfced5872efd0ee3830b0aa0be0f9259ddded6603e3fb7",
                "2.7.1": "a1a3ff1a5730485a3b30deb4187961e6567de75dfc22278dd6661a8cf398a2f7"}
        for version, digest in pins.items():
            fixture = evidence.FIXTURES[version]
            data = evidence.base.read_regular_file(evidence.output(version).with_name("sdk-normal-tls-v3.json"), 128 * 1024)
            self.assertEqual(evidence.base.sha256(data), digest)
            old = evidence.base.parse_json(data, 128 * 1024)
            report = evidence.base.parse_json(evidence.base.read_regular_file(evidence.output(version), 128 * 1024), 128 * 1024)
            changed = {key for key in old["inputs"] if old["inputs"][key] != report["inputs"].get(key)}
            self.assertEqual(set(old["inputs"]), set(report["inputs"]))
            self.assertEqual(changed, {"Cargo.toml", "Cargo.lock", "README.md"})
            with patch.object(fixture.normal_sdk, "verify", return_value=fixture.normal_sdk.verify()):
                with patch.object(evidence, "PINS", {version: (digest, old["test_binary_sha256"])}), \
                     self.assertRaises(evidence.harness.HarnessError):
                    evidence.validate(version, data)
                for key in changed:
                    mutated = copy.deepcopy(report)
                    mutated["inputs"][key] = old["inputs"][key]
                    altered = evidence.base.canonical_json(mutated)
                    with self.subTest(version=version, input=key), \
                         patch.object(evidence, "PINS", {version: (evidence.base.sha256(altered), report["test_binary_sha256"])}), \
                         self.assertRaises(evidence.harness.HarnessError):
                        evidence.validate(version, altered)

    def test_both_retained_reports_are_current_normal_builds(self):
        for version in evidence.FIXTURES:
            with self.subTest(version=version):
                report = evidence.verify(version)
                self.assertIs(report["routable"], True)
                self.assertEqual(report["scope"], "public-sdk-strict-normal-build")
                self.assertEqual(report["version"], version)
                self.assertNotIn("candidate_generated_rust_sha256", report)

    def test_retained_reports_cannot_be_swapped_or_replaced_by_candidates(self):
        for version, filename in (("2.6.4", "sdk-candidate-tls-v2.json"),
                                  ("2.7.1", "sdk-advanced-candidate-tls-v2.json")):
            fixture = evidence.FIXTURES[version]
            normal = evidence.base.read_regular_file(evidence.output(version), 128 * 1024)
            candidate = evidence.base.read_regular_file(evidence.output(version).parent / filename, 128 * 1024)
            other = "2.7.1" if version == "2.6.4" else "2.6.4"
            with self.assertRaises(evidence.harness.HarnessError):
                evidence.validate(other, normal)
            pins = {**evidence.PINS, version: (evidence.base.sha256(candidate), evidence.PINS[version][1])}
            with patch.object(evidence, "PINS", pins), \
                 patch.object(fixture.normal_sdk, "verify", return_value={}), \
                 self.assertRaises(evidence.harness.HarnessError):
                evidence.validate(version, candidate)

    def test_missing_pins_block_even_an_otherwise_valid_report(self):
        with patch.object(evidence, "PINS", {"2.6.4": None, "2.7.1": None}):
            for version in evidence.FIXTURES:
                with self.assertRaises(evidence.harness.HarnessError):
                    evidence.validate(version, b"{}\n")

    def test_strict_semantics_independent_of_digest(self):
        for version, fixture in evidence.FIXTURES.items():
            with self.subTest(version=version), ExitStack() as stack:
                proof = {"scope": "public-sdk-strict-normal-build", "routable": True,
                         "source_scope": "repository-normal-build-no-generated-override",
                         "combined_registry_sha256": "a" * 64, "generated_rust_sha256": "b" * 64}
                stack.enter_context(patch.object(fixture.normal_sdk, "verify", return_value=proof))
                inputs = {"src/lib.rs": "c" * 64, "Cargo.lock": "d" * 64}
                hashes = stack.enter_context(patch.object(fixture, "input_hashes", return_value=inputs))
                report = evidence.expected(version, "e" * 64)
                data = evidence.base.canonical_json(report)
                pins = stack.enter_context(patch.object(evidence, "PINS", {version: (evidence.base.sha256(data), "e" * 64)}))
                self.assertEqual(evidence.validate(version, data), report)
                hashes.assert_called_with(normal=True)
                mutations = {"routable": False, "version": "2.7.0", "scope": "public-sdk-strict-disposable-candidate-build",
                             "source_scope": "repository-inputs-with-explicit-generated-candidate-override",
                             "combined_registry_sha256": "0" * 64, "generated_rust_sha256": "0" * 64,
                             "outcome": "failed", "checks": [], "features": "", "inputs": {},
                             "test_binary_sha256": "0" * 64, "executable_storage": "mutable-path",
                             "build_provenance": "attested", "image_index_digest": "sha256:" + "0" * 64}
                mutations["test" if version == "2.6.4" else "tests"] = []
                for key, value in mutations.items():
                    changed = evidence.base.canonical_json({**report, key: value})
                    pins[version] = (evidence.base.sha256(changed), "e" * 64)
                    with self.subTest(key=key), self.assertRaises(evidence.harness.HarnessError):
                        evidence.validate(version, changed)
                for key, value in (("routable", 1), ("candidate_registry_sha256", "a" * 64)):
                    changed = evidence.base.canonical_json({**report, key: value})
                    pins[version] = (evidence.base.sha256(changed), "e" * 64)
                    with self.assertRaises(evidence.harness.HarnessError):
                        evidence.validate(version, changed)
                pins[version] = (evidence.base.sha256(data), "e" * 64)
                for name in inputs:
                    for omit in (False, True):
                        changed = copy.deepcopy(inputs)
                        if omit:
                            changed.pop(name)
                        else:
                            changed[name] = "0" * 64
                        hashes.return_value = changed
                        with self.assertRaises(evidence.harness.HarnessError):
                            evidence.validate(version, data)
                hashes.return_value = inputs
                with self.assertRaises(evidence.harness.HarnessError):
                    evidence.validate(version, data + b" ")


if __name__ == "__main__":
    unittest.main()
