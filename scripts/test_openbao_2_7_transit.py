#!/usr/bin/python3 -EsSB
"""Offline bounds, negative-control and cleanup tests for the 05b TLS fixture."""

import contextlib
import copy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import openbao_2_7_transit as subject
import verify_openbao_2_7_transit as evidence


class TransitFixtureTests(unittest.TestCase):
    def test_retained_evidence_rejects_scope_input_and_coverage_changes(self):
        report = evidence.verify()
        inputs = subject.input_hashes()
        for key in report:
            changed = copy.deepcopy(report)
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(subject.snapshots.SnapshotError):
                evidence.validate_report(changed, inputs)
        for key, value in (("routable", True), ("routable", 0),
                           ("pkcs11_verified", 0), ("pkcs11_verified", True),
                           ("mldsa_parameters", [44.0, 65, 87]),
                           ("checks", report["checks"][:-1]), ("inputs", {}),
                           ("scope", "sdk-integration"), ("unexpected", "field"),
                           ("image_linux_amd64_digest", "sha256:changed")):
            changed = copy.deepcopy(report)
            changed[key] = value
            with self.subTest(field=key, value=value), self.assertRaises(subject.snapshots.SnapshotError):
                evidence.validate_report(changed, inputs)
        with patch.object(subject, "input_hashes", return_value={}):
            with self.assertRaises(subject.snapshots.SnapshotError):
                evidence.verify()

    def test_retained_evidence_rejects_byte_changes_and_noncanonical_encoding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            data = evidence.RESULT.read_bytes() + b" "
            path.write_bytes(data)
            with patch.object(evidence, "RESULT", path):
                with self.assertRaises(subject.snapshots.SnapshotError):
                    evidence.verify()
                with patch.object(evidence, "EXPECTED_SHA256", subject.snapshots.sha256(data)):
                    with self.assertRaises(subject.snapshots.SnapshotError):
                        evidence.verify()

    def test_binary_and_pem_decoders_reject_malformed_oversized_and_noncanonical(self):
        self.assertEqual(subject.raw(subject.b64(b"test"), 4), b"test")
        self.assertEqual(subject.pem_der("-----BEGIN PUBLIC KEY-----\ndGVzdA==\n-----END PUBLIC KEY-----", "PUBLIC KEY"), b"test")
        for value in (None, 1, "!", "Zg", "Zh==", "Zg==\n", "A" * (subject.fixture.MAX_BODY + 1)):
            with self.assertRaises(subject.harness.HarnessError):
                subject.raw(value)
        with self.assertRaises(subject.harness.HarnessError):
            subject.raw("Zg==", 2)
        # A certificate label exercises wrong-type rejection without a private-key marker.
        for pem in ("", "-----BEGIN CERTIFICATE-----\nZg==\n-----END CERTIFICATE-----",
                    "-----BEGIN PUBLIC KEY-----\n!\n-----END PUBLIC KEY-----"):
            with self.assertRaises(subject.harness.HarnessError):
                subject.pem_der(pem, "PUBLIC KEY")

    def test_mu_is_bounded_and_binds_both_message_and_public_key(self):
        # Test the standard-library prehash wiring; live sign/verify is the crypto oracle.
        for public_size, _ in subject.PARAMETERS.values():
            public, message = b"p" * public_size, b"synthetic"
            expected = subject.hashlib.shake_256(subject.hashlib.shake_256(public).digest(64) + b"\0\0" + message).digest(64)
            mu = subject.compute_mu(public, message)
            self.assertEqual(mu, expected)
            self.assertEqual(len(mu), 64)
            self.assertNotEqual(mu, subject.compute_mu(b"q" * public_size, message))
            self.assertNotEqual(mu, subject.compute_mu(public, message + b"wrong"))
        for public, message in ((b"p", b"x"), (b"p" * 1312, b"x" * 4097), (None, b"x")):
            with self.assertRaises(subject.harness.HarnessError):
                subject.compute_mu(public, message)

    def test_tampering_preserves_format_version_and_length_but_changes_bytes(self):
        for _, size in subject.PARAMETERS.values():
            signature = "vault:v1:" + subject.b64(b"s" * size)
            tampered = subject.tamper(signature, 1, size)
            changed = subject.signature_bytes(tampered, 1, size)
            self.assertEqual(sum(a != b for a, b in zip(changed, b"s" * size)), 1)
            for value in (signature.replace("v1:", "v2:"), "vault:v1:!", "vault:v1:" + subject.b64(b"s")):
                with self.assertRaises(subject.harness.HarnessError):
                    subject.signature_bytes(value, 1, size)

    def test_error_checks_require_specific_semantics_and_failure_status(self):
        subject.require_error(400, {"errors": ["expected restriction"]}, "expected restriction")
        for status, body in ((200, {"errors": ["expected restriction"]}),
                             (400, {"errors": ["permission denied"]}), (500, {"errors": [1]}),
                             (404, {"errors": ["expected restriction"]}), (400, {})):
            with self.assertRaises(subject.harness.HarnessError):
                subject.require_error(status, body, "expected restriction")

    def test_sign_verify_helpers_fail_on_wrong_version_signature_and_boolean(self):
        probe = subject.Probe("https://localhost", Path("ca"), "synthetic")
        signature = "vault:v1:" + subject.b64(b"s" * 2420)
        for result in ({"signature": signature, "key_version": 2},
                       {"signature": signature, "key_version": True},
                       {"signature": "vault:v1:!", "key_version": 1}, {}):
            with patch.object(probe, "data", return_value=result), self.assertRaises(subject.harness.HarnessError):
                probe.sign("fixture", "key", b"x", 1, 2420)
        for result in ({"valid": False}, {"valid": 1}, {"valid": "true"}, {}):
            with patch.object(probe, "data", return_value=result), self.assertRaises(subject.harness.HarnessError):
                probe.verify("fixture", "key", b"x", signature)
        with patch.object(probe, "data", return_value={"valid": True}):
            probe.verify("fixture", "key", b"x", signature)

    def test_probe_transport_uses_shared_bounded_tls_and_rejects_bad_envelopes(self):
        probe = subject.Probe("https://localhost", Path("ca"), "synthetic")
        with patch.object(subject.external, "request", return_value=(200, {"data": {"valid": True}})) as request:
            probe.verify("fixture", "key", b"x", "synthetic-signature")
            self.assertEqual(request.call_args.args[4], "/v1/fixture/verify/key")
            self.assertEqual(request.call_args.args[5]["input"], "eA==")
        for body in ({}, {"data": []}, {"data": None}, []):
            with patch.object(subject.external, "request", return_value=(200, body)), self.assertRaises(subject.harness.HarnessError):
                probe.data("GET", "fixture/keys/key")

    def test_inputs_bind_reused_harness_and_all_probes(self):
        hashes = subject.input_hashes()
        for name in ("scripts/openbao_2_7_transit.py", "scripts/openbao_2_7_external_keys.py",
                     "scripts/openbao_2_7_tls.py", "scripts/openbao_test_harness.py"):
            self.assertIn(name, hashes)
        self.assertEqual(len(hashes), len(subject.INPUTS))
        self.assertTrue(all(len(value) == 64 for value in hashes.values()))

    def test_run_cleans_resources_on_failure_and_never_promotes_sdk(self):
        for failure in (None, "network", "container", "health", "probe", "cleanup", "files", "changed-inputs"):
            removed, commands = [], []

            def command(*args, **kwargs):
                commands.append(args[0])
                self.assertNotIn("CONTAINER_HOST", kwargs["environment"])
                if (failure == "network" and len(commands) == 1) or (failure == "container" and len(commands) == 2):
                    raise subject.harness.HarnessError("synthetic-private-detail")
                return b"{}"

            def remove(podman, kind, name, owner, environment):
                removed.append(kind)
                self.assertTrue(name.endswith(owner))
                if failure == "cleanup":
                    raise subject.harness.HarnessError("synthetic-private-detail")

            def fail_at(stage):
                if failure == stage:
                    raise subject.harness.HarnessError("synthetic-private-detail")

            with contextlib.ExitStack() as stack:
                def mock(obj, name, **kwargs): return stack.enter_context(patch.object(obj, name, **kwargs))
                mock(subject.staged, "verify")
                mock(subject.staged, "verify_image_signature")
                mock(subject.external.evidence_tools, "protected_path", side_effect=lambda path: path)
                mock(subject.harness, "generate_tls", side_effect=lambda root, *args: (root / "tls", root / "ca"))
                mock(subject.harness, "write_server_config", side_effect=lambda root, *args: root / "config")
                mock(subject.harness, "inspect_image", return_value="pinned-fixture")
                mock(subject.harness, "run_bounded", side_effect=command)
                mock(subject.snapshots, "validate_container_resource_config")
                mock(subject.fixture, "verify_network")
                mock(subject.harness, "parse_port", return_value=18200)
                mock(subject.fixture, "wait_for_health", side_effect=lambda *args: fail_at("health"))
                mock(subject.fixture, "probe_tls")
                mock(subject.harness, "initialize_and_unseal", return_value="synthetic")
                mock(subject, "probe", side_effect=lambda *args: fail_at("probe"))
                mock(subject.harness, "remove_owned_resource", side_effect=remove)
                mock(subject.harness, "cleanup_private_files", return_value=failure != "files")
                mock(subject, "input_hashes", side_effect=[{}, {"changed": "hash"}] if failure == "changed-inputs" else [{}, {}])
                with contextlib.redirect_stdout(io.StringIO()):
                    if failure:
                        with self.assertRaises(subject.harness.HarnessError): subject.run()
                    else:
                        result = subject.run()
                        self.assertIs(result["routable"], False)
                        self.assertIs(result["pkcs11_verified"], False)
                        self.assertEqual(result["checks"], subject.CHECKS)
                        self.assertEqual(result["mldsa_parameters"], [44, 65, 87])
            self.assertEqual(removed, ["network"] if failure == "network" else ["container", "network"])

    def test_main_redacts_errors_and_writes_no_success_on_failure(self):
        for error in (subject.harness.HarnessError("synthetic-private-detail"), KeyError("synthetic-private-detail")):
            output = io.StringIO()
            with patch.object(subject, "run", side_effect=error), \
                 patch.object(subject.tempfile, "NamedTemporaryFile") as write, \
                 patch("sys.argv", ["fixture"]), contextlib.redirect_stdout(output):
                self.assertEqual(subject.main(), 1)
            write.assert_not_called()
            self.assertNotIn("synthetic-private-detail", output.getvalue())


if __name__ == "__main__":
    unittest.main()
