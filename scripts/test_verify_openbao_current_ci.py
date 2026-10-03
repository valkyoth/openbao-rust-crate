#!/usr/bin/python3 -EsSB
"""Fail-closed current-profile CI evidence and scope regressions."""

import unittest
from unittest.mock import patch

import verify_openbao_current_ci as evidence


class CurrentCiEvidenceTests(unittest.TestCase):
    def test_all_three_retained_reports(self):
        self.assertEqual(set(evidence.PINS), set(evidence.fixture.VERSIONS))
        for version in evidence.PINS:
            self.assertEqual(evidence.verify(version)["version"], version)

    def test_every_input_must_be_present_and_current(self):
        for version in evidence.PINS:
            data = evidence.fixture.base.read_regular_file(evidence.ROOT / f"{version}-v2.json", 128 * 1024)
            inputs = evidence.fixture.input_hashes()
            for name in inputs:
                for omit in (False, True):
                    changed = dict(inputs)
                    if omit:
                        del changed[name]
                    else:
                        changed[name] = "0" * 64
                    with self.subTest(version=version, input=name, omit=omit), \
                         patch.object(evidence.fixture, "input_hashes", return_value=changed), \
                         self.assertRaises(evidence.fixture.harness.HarnessError):
                        evidence.validate(version, data)

    def test_repinned_reports_cannot_change_scope_identity_or_success(self):
        for version in evidence.PINS:
            report = evidence.verify(version)
            mutations = {"version": "2.7.2", "outcome": "failed", "inputs": {},
                         "image_linux_amd64_digest": "sha256:" + "0" * 64,
                         "test_binary_sha256": "0" * 64, "tls": "TLSv1.2",
                         "executable_storage": "mutable-path", "cleanup": "failed",
                         "build_provenance": "attested", "scope": "all-endpoints", "attestation": {}}
            for name, value in mutations.items():
                changed = evidence.fixture.base.canonical_json({**report, name: value})
                with self.subTest(version=version, field=name), \
                     patch.object(evidence, "PINS", {version: evidence.fixture.base.sha256(changed)}), \
                     self.assertRaises(evidence.fixture.harness.HarnessError):
                    evidence.validate(version, changed)
            for attestation in ({**report["attestation"], "executed": []},
                                {**report["attestation"], "skipped": []}):
                changed = evidence.fixture.base.canonical_json({**report, "attestation": attestation})
                with patch.object(evidence, "PINS", {version: evidence.fixture.base.sha256(changed)}), \
                     self.assertRaises(evidence.fixture.harness.HarnessError):
                    evidence.validate(version, changed)

    def test_unknown_swapped_altered_or_noncanonical_data_is_rejected(self):
        for version in evidence.PINS:
            data = evidence.fixture.base.read_regular_file(evidence.ROOT / f"{version}-v2.json", 128 * 1024)
            with self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate("2.7.2", data)
            for other in set(evidence.PINS) - {version}:
                with self.assertRaises(evidence.fixture.harness.HarnessError):
                    evidence.validate(other, data)
            with self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(version, data + b" ")
            changed = data + b" "
            with patch.object(evidence, "PINS", {version: evidence.fixture.base.sha256(changed)}), \
                 self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(version, changed)

    def test_original_reports_preserved_but_obsolete_workflow_rejected(self):
        original_pins = {
            "2.6.4": "a5125f7c2a5766d3a1cafd1f42025d75fb37f3e82e3b05da862e9b63dbdc4326",
            "2.7.0": "8532fd4006c2c598ffc7dfe0c1e071242f1f1938f46205d8dd0bd7593e998044",
            "2.7.1": "12ff366f741cb25fbf166526d5b21f3032c0307a558953a2e19a771cfc47adb3",
        }
        workflow = ".github/workflows/openbao-current-compatibility.yml"
        for version, digest in original_pins.items():
            data = evidence.fixture.base.read_regular_file(evidence.ROOT / f"{version}.json", 128 * 1024)
            self.assertEqual(evidence.fixture.base.sha256(data), digest)
            old = evidence.fixture.base.parse_json(data, 128 * 1024)
            current = evidence.verify(version)
            changed_inputs = {name for name in set(old["inputs"]) | set(current["inputs"])
                              if old["inputs"].get(name) != current["inputs"].get(name)}
            self.assertEqual(changed_inputs, {workflow})
            with patch.object(evidence, "PINS", original_pins), \
                 self.assertRaises(evidence.fixture.harness.HarnessError):
                evidence.validate(version, data)


if __name__ == "__main__":
    unittest.main()
