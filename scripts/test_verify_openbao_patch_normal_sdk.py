#!/usr/bin/python3 -EsSB
"""Current normal-build evidence cannot accept stale, candidate, or partial reports."""

import copy
import unittest
from unittest.mock import patch

import verify_openbao_patch_normal_sdk as evidence


class EvidenceTests(unittest.TestCase):
    def test_current_reports_bind_every_input_and_readme(self):
        for version, fixture in evidence.FIXTURES.items():
            with self.subTest(version=version):
                report = evidence.verify(version)
                self.assertTrue(report["routable"])
                self.assertEqual(report["scope"], "public-sdk-strict-normal-build")
                self.assertEqual(report["version"], version)
                self.assertEqual(report["inputs"], fixture.input_hashes(normal=True))
                self.assertIn("README.md", report["inputs"])
                self.assertNotIn("candidate_registry_sha256", report)

    def test_every_current_input_is_required(self):
        for version, fixture in evidence.FIXTURES.items():
            data = evidence.base.read_regular_file(evidence.output(version), 128 * 1024)
            current = fixture.input_hashes(normal=True)
            provenance = fixture.normal_sdk.verify()
            with patch.object(fixture.normal_sdk, "verify", return_value=provenance):
                for name in current:
                    for omit in (False, True):
                        changed = dict(current)
                        if omit:
                            changed.pop(name)
                        else:
                            changed[name] = "0" * 64
                        with self.subTest(version=version, input=name, omit=omit), \
                             patch.object(fixture, "input_hashes", return_value=changed), \
                             self.assertRaises(evidence.harness.HarnessError):
                            evidence.validate(version, data)

    def test_reports_cannot_be_swapped_or_replaced_by_candidates(self):
        pairs = {"2.6.5": "sdk-candidate-tls-v4.json",
                 "2.7.2": "sdk-advanced-candidate-tls-v4.json"}
        for version, candidate_name in pairs.items():
            normal = evidence.base.read_regular_file(evidence.output(version), 128 * 1024)
            candidate = evidence.base.read_regular_file(
                evidence.output(version).with_name(candidate_name), 128 * 1024)
            other = "2.7.2" if version == "2.6.5" else "2.6.5"
            with self.subTest(version=version), self.assertRaises(evidence.harness.HarnessError):
                evidence.validate(other, normal)
            pins = {**evidence.PINS,
                    version: (evidence.base.sha256(candidate), evidence.PINS[version][1])}
            provenance = evidence.FIXTURES[version].normal_sdk.verify()
            with self.subTest(version=version), patch.object(evidence, "PINS", pins), \
                 patch.object(evidence.FIXTURES[version].normal_sdk, "verify",
                              return_value=provenance), \
                 self.assertRaises(evidence.harness.HarnessError):
                evidence.validate(version, candidate)

    def test_semantic_mutations_fail_independently_of_digest(self):
        for version in evidence.FIXTURES:
            fixture = evidence.FIXTURES[version]
            data = evidence.base.read_regular_file(evidence.output(version), 128 * 1024)
            report = evidence.base.parse_json(data, 128 * 1024)
            mutations = {"routable": False,
                         "scope": "public-sdk-strict-disposable-candidate-build",
                         "source_scope": "repository-inputs-with-explicit-generated-candidate-override",
                         "outcome": "failed", "checks": [], "features": "", "inputs": {},
                         "test_binary_sha256": "0" * 64}
            mutations["test" if version == "2.6.5" else "tests"] = []
            provenance = fixture.normal_sdk.verify()
            with patch.object(fixture.normal_sdk, "verify", return_value=provenance):
                for key, value in mutations.items():
                    changed = copy.deepcopy(report)
                    changed[key] = value
                    encoded = evidence.base.canonical_json(changed)
                    pins = {**evidence.PINS,
                            version: (evidence.base.sha256(encoded), report["test_binary_sha256"])}
                    with self.subTest(version=version, key=key), patch.object(evidence, "PINS", pins), \
                         self.assertRaises(evidence.harness.HarnessError):
                        evidence.validate(version, encoded)


if __name__ == "__main__":
    unittest.main()
