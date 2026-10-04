#!/usr/bin/python3 -EsSB
"""The aggregate release gate must not omit a family, version or normal run."""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import check_openbao_plugin_release as gate


class ReleaseTests(unittest.TestCase):
    def test_checkpoint_captures_remain_immutable_and_are_not_current_evidence(self):
        anchors = (
            (gate.ldap, "BINARY", "sdk-normal-checkpoint", (
                "2a3fe998637604afa40bf2f6d59a99987e035aec453b936ac9edbf512b997d03",
                "c686b35e411007db7f98cb2517b8478b346734bdf293b23a6b36e0000803df63")),
            (gate.kerberos, "NORMAL_BINARY", "sdk-normal-checkpoint", (
                "8a5d22b8c04e40182161eee868753c9a8a7861ded5d4ca04dd1a6d6eee2fd38e",
                "e9697b4442dfcace0d52a62a7aed999cd06e99029fc54f59d5418e8f29164c92")),
            (gate.radius, "NORMAL_BINARY", "sdk-normal-checkpoint", (
                "c23ed976b7a4d0b4fa5dad2e27c5c4b505cc6d2034a9a42e3ef029431a27fba8",
                "fced62353990a2c8e1015c6a74d6294e7a92b3bd59bb6fff218ba20e16573720")),
            (gate.ldap, "BINARY", "sdk-normal-pre-tokio", (
                "2a2565bbbc5d6e07b8a9dc830bb02a040786883d663a2aadb7745006882ab39e",
                "70ecbce616c035f4767b8af1406e83b11705855d77034533bb3048728ddd650d")),
            (gate.kerberos, "NORMAL_BINARY", "sdk-normal-pre-tokio", (
                "4c8bc6e020afe5cb634a1bc3d3c82acca6e141ffe9521c26fce7d0df19515aaa",
                "258ae09c5145139438ff8efaacf5301ba74c5d9a86e2e8497876061b7e8d6900")),
            (gate.radius, "NORMAL_BINARY", "sdk-normal-pre-tokio", (
                "fa573dd6fdb07b402771a04de34ed202a2d9d92656af3267311a97cafa9bfa84",
                "774e04879e5d0c04baefcceef33b75bb5c5197d4bfe8bd0dcfbb90886abaa018")),
        )
        for module, binary_field, directory, digests in anchors:
            for version, digest in zip(gate.VERSIONS, digests):
                root = module.server.ROOT / version / directory
                raw = module.base.read_regular_file(root / "report.json", 65536)
                self.assertEqual(module.base.sha256(raw), digest)
                report = module.base.parse_json(raw, 65536)
                schema = module.base.read_regular_file(root / "runtime-openapi.json", 2 * 1024 * 1024)
                # Even restoring the old binary anchor cannot make stale source inputs current.
                with patch.object(module, binary_field, report["binary_sha256"]):
                    module.validate_report(report, version, report["inputs"], schema)
                    with self.assertRaises(module.base.SnapshotError):
                        module.validate_report(report, version, module.sdk.input_hashes(), schema)

    def families(self):
        return tuple((SimpleNamespace(
            sdk=SimpleNamespace(OPERATIONS=tuple(f"{prefix}-{n}" for n in range(count))),
            server=SimpleNamespace(verify=Mock()),
            verify=Mock(return_value={"scope": "public-sdk-normal-build"})), count)
            for prefix, count in (("ldap", 33), ("kerberos", 9), ("radius", 6)))

    def test_all_families_and_both_versions_required(self):
        families = self.families()
        with patch.object(gate, "FAMILIES", families):
            gate.verify()
        for module, _ in families:
            self.assertEqual(module.verify.call_count, 2)
            self.assertEqual(module.server.verify.call_count, 2)
            for version in gate.VERSIONS:
                module.verify.assert_any_call(version)
                module.server.verify.assert_any_call(version)

    def test_failure_in_any_gate_propagates(self):
        for index in range(3):
            for target in ("server", "sdk"):
                families = self.families()
                module = families[index][0]
                verifier = module.server.verify if target == "server" else module.verify
                verifier.side_effect = ValueError("stale evidence")
                with patch.object(gate, "FAMILIES", families), self.assertRaises(ValueError):
                    gate.verify()

    def test_candidate_is_not_release_acceptance(self):
        families = self.families()
        families[2][0].verify.return_value = {"scope": "public-sdk-candidate-only"}
        with patch.object(gate, "FAMILIES", families), self.assertRaises(ValueError):
            gate.verify()

    def test_missing_duplicate_or_overlapping_operations_fail(self):
        for mode in ("missing-family", "duplicate", "overlap", "missing-operation"):
            families = self.families()
            if mode == "missing-family":
                families = families[:-1]
            else:
                ops = list(families[2][0].sdk.OPERATIONS)
                if mode == "duplicate":
                    ops[0] = ops[1]
                elif mode == "overlap":
                    ops[0] = families[0][0].sdk.OPERATIONS[0]
                else:
                    ops.pop()
                families[2][0].sdk.OPERATIONS = tuple(ops)
            with patch.object(gate, "FAMILIES", families), self.assertRaises(ValueError):
                gate.verify()


if __name__ == "__main__":
    unittest.main()
