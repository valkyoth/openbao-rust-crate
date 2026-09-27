#!/usr/bin/python3 -EsSB
"""Offline cleanup and security boundaries for the staged PKI fixture."""

import contextlib
import copy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import openbao_2_7_pki as subject
import verify_openbao_2_7_pki as evidence


class PkiFixtureTests(unittest.TestCase):
    def test_evidence_rejects_missing_extra_changed_and_wrong_typed_fields(self):
        report = evidence.verify()
        inputs = subject.input_hashes()
        for key in report:
            changed = copy.deepcopy(report)
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(subject.snapshots.SnapshotError):
                evidence.validate_report(changed, inputs)
        for key, value in (("routable", True), ("routable", 0), ("pkcs11_verified", 0),
                           ("pkcs11_verified", True), ("mldsa_parameters", [44.0, 65, 87]),
                           ("checks", report["checks"][:-1]), ("inputs", {}),
                           ("scope", "sdk-integration"), ("unexpected", "field"),
                           ("image_linux_amd64_digest", "sha256:changed")):
            changed = copy.deepcopy(report)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(subject.snapshots.SnapshotError):
                evidence.validate_report(changed, inputs)
        with patch.object(subject, "input_hashes", return_value={}):
            with self.assertRaises(subject.snapshots.SnapshotError):
                evidence.verify()

    def test_evidence_rejects_changed_bytes_even_if_json_equivalent(self):
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

    def test_kms_policy_grants_only_exact_provider_operations(self):
        # Keep this expected policy independent of the builder: private export,
        # broad prefixes and extra capabilities must fail this regression.
        self.assertEqual(subject.kms_provider_policy().splitlines(), [
            'path "auth/token/lookup-self" { capabilities = ["read"] }',
            'path "pki-source/keys/signer" { capabilities = ["read"] }',
            'path "pki-source/export/public-key/signer/latest" { capabilities = ["read"] }',
            'path "pki-source/sign/signer" { capabilities = ["update"] }',
            'path "pki-source/verify/signer" { capabilities = ["update"] }',
        ])

    def test_trailing_dot_requires_exact_idna_rejection(self):
        probe = Mock()
        expected = {'errors': ['idna: invalid label "leaf.fixture.test."']}
        for parameter in (44, 65, 87):
            probe.request.return_value = (400, expected)
            subject.probe_trailing_dot(probe, "fixture", parameter)
            self.assertEqual(probe.request.call_args.args, ("POST", "fixture/issue/leaf", {
                "common_name": "leaf.fixture.test.", "ttl": "10m",
                "key_type": "mldsa", "key_bits": parameter}))
        for status, response in ((200, expected), (500, expected), (403, expected),
                                 (400, {}), (400, []), (400, {'errors': [None]}),
                                 (400, {'errors': ['permission denied']}),
                                 (400, {'errors': ['common name not allowed by this role']}),
                                 (400, {'errors': ['idna: invalid label "other.test."']}),
                                 (400, {'errors': expected['errors'] + ['unrelated']})):
            with self.subTest(status=status, response=response):
                probe.request.return_value = (status, response)
                with self.assertRaises(subject.harness.HarnessError):
                    subject.probe_trailing_dot(probe, "fixture", 44)

    def test_role_write_uses_documented_200_and_verifies_readback(self):
        probe = Mock()
        probe.data.return_value = {"key_type": "any", "allowed_domains": ["fixture.test"], "use_pss": False}
        subject.role(probe, "fixture", use_pss=False)
        self.assertEqual(probe.call.call_args.args[-1], 200)
        probe.data.assert_called_once_with("GET", "fixture/roles/leaf")
        for value in (True, 0, None):
            probe.data.return_value["use_pss"] = value
            with self.assertRaises(subject.harness.HarnessError):
                subject.role(probe, "fixture", use_pss=False)

    def test_ocsp_transport_is_bounded_unauthenticated_and_uses_tls_harness(self):
        probe = Mock(address="https://127.0.0.1:18200", ca="fixture-ca")
        for size, media, accepted in ((5, "application/ocsp-response", True),
                                      (subject.crypto.LIMIT + 1, "application/ocsp-response", False),
                                      (5, "application/json", False)):
            response = Mock(status=500)
            response.read.return_value = b"x" * size
            response.headers.get_content_type.return_value = media
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            opener = Mock()
            opener.open.return_value = response
            with patch.object(subject.fixture, "context", return_value=None) as tls, \
                 patch.object(subject.urllib.request, "build_opener", return_value=opener) as build:
                if accepted:
                    self.assertEqual(subject.ocsp_response(probe, "fixture", b"request"), (500, b"xxxxx"))
                else:
                    with self.assertRaises(subject.harness.HarnessError):
                        subject.ocsp_response(probe, "fixture", b"request")
                tls.assert_called_once_with("fixture-ca")
                self.assertTrue(any(isinstance(arg, subject.harness.RejectRedirect) for arg in build.call_args.args))
                outgoing = opener.open.call_args.args[0]
                self.assertIsNone(outgoing.get_header("X-vault-token"))
                self.assertEqual(opener.open.call_args.kwargs["timeout"], 5)
                response.read.assert_called_once_with(subject.crypto.LIMIT + 1)
        for body in (b"", b"x" * 2048, None):
            with self.assertRaises(subject.harness.HarnessError):
                subject.ocsp_response(probe, "fixture", body)

    def test_ocsp_requires_exact_unsupported_response(self):
        verifier = Mock()
        verifier.store.return_value = "/tmp/fixture"
        for status, body, accepted in ((500, bytes.fromhex("30030a0102"), True),
                                      (400, bytes.fromhex("30030a0101"), False),
                                      (401, bytes.fromhex("30030a0106"), False),
                                      (500, b"unrelated failure", False),
                                      (200, bytes.fromhex("30030a0102"), False)):
            with patch.object(subject.snapshots, "read_regular_file", return_value=b"request"), \
                 patch.object(subject, "ocsp_response", return_value=(status, body)):
                if accepted:
                    subject.probe_ocsp(Mock(), verifier, "fixture", "issuer", "certificate", True)
                else:
                    with self.assertRaises(subject.harness.HarnessError):
                        subject.probe_ocsp(Mock(), verifier, "fixture", "issuer", "certificate", True)

    def test_inputs_bind_all_imported_probes(self):
        hashes = subject.input_hashes()
        self.assertEqual(len(hashes), len(subject.INPUTS))
        for name in ("openbao_2_7_pki.py", "openbao_2_7_pki_crypto.py", "openbao_2_7_transit.py",
                     "openbao_2_7_external_keys.py", "openbao_2_7_tls.py", "openbao_test_harness.py"):
            self.assertIn("scripts/" + name, hashes)

    def test_failure_cleanup_and_no_promotion(self):
        for failure in (None, "network", "container", "health", "probe", "cleanup", "scratch", "files", "inputs"):
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

            with self.subTest(failure=failure), contextlib.ExitStack() as stack:
                def mock(obj, name, **kwargs):
                    return stack.enter_context(patch.object(obj, name, **kwargs))
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
                wipe = mock(subject.crypto.Crypto, "cleanup", side_effect=lambda: fail_at("scratch"))
                mock(subject.harness, "cleanup_private_files", return_value=failure != "files")
                mock(subject, "input_hashes", side_effect=[{}, {"changed": "hash"}] if failure == "inputs" else [{}, {}])
                with contextlib.redirect_stdout(io.StringIO()):
                    if failure:
                        with self.assertRaises(subject.harness.HarnessError):
                            subject.run()
                    else:
                        report = subject.run()
                        self.assertIs(report["routable"], False)
                        self.assertIs(report["pkcs11_verified"], False)
                        self.assertEqual(report["scope"], "server-fixture-only-not-sdk-integration")
                        self.assertEqual(report["mldsa_parameters"], [44, 65, 87])
                wipe.assert_called_once()
            self.assertEqual(removed, ["network"] if failure == "network" else ["container", "network"])

    def test_main_never_emits_secret_exception_or_success_on_failure(self):
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
