#!/usr/bin/python3 -EsSB
"""Offline regressions for exact-version patch capture and negative controls."""

import copy
import io
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import openbao_2_7_1 as fixture


class PatchEvidenceTests(unittest.TestCase):
    def test_capture_output_works_outside_repository(self):
        output = fixture.write_capture_output(b'{"document":{}}\n', {"routable": False})
        try:
            self.assertEqual(output.parent, Path("/tmp"))
            self.assertEqual((output / "openapi.json").read_bytes(), b'{"document":{}}\n')
            self.assertEqual((output / "report.json").read_bytes(), b'{"routable":false}\n')
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o755)
            for path in output.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        finally:
            shutil.rmtree(output)

    def test_failed_output_is_not_retained(self):
        output = Path(tempfile.mkdtemp(prefix="openbao-271-output-test-"))
        try:
            with patch.object(fixture.tempfile, "mkdtemp", return_value=str(output)), \
                 patch.object(fixture.os, "fsync", side_effect=OSError("disposable-marker")), \
                 self.assertRaises(OSError):
                fixture.write_capture_output(b"{}", {"routable": False})
            self.assertFalse(output.exists())
        finally:
            if output.exists():
                shutil.rmtree(output)

    def test_diagnostics_never_interpolate_errors_or_causes(self):
        for kind in (OSError, ValueError, KeyError, fixture.harness.HarnessError, fixture.base.SnapshotError):
            error = kind("disposable-marker")
            error.__cause__ = ValueError("another-marker")
            self.assertEqual(fixture.failure_category(error), "unclassified")
        self.assertEqual(fixture.failure_category(fixture.base.SnapshotError(
            "evidence command failed without exposing its output")), "verification-command-failed")

    def test_signature_failure_stops_before_server_preparation(self):
        output = io.StringIO()
        with patch.object(fixture.os, "geteuid", return_value=0), \
             patch.object(fixture, "input_hashes", return_value={}), \
             patch.object(fixture, "verify_signature", side_effect=fixture.base.SnapshotError("denied")), \
             patch.object(fixture.harness, "generate_tls") as prepare, \
             redirect_stdout(output), self.assertRaises(fixture.base.SnapshotError):
            fixture.capture()
        prepare.assert_not_called()
        self.assertEqual(output.getvalue(), "2.7.1 fixture: verifying signed image\n")

    def test_source_evidence_is_anchored(self):
        data = fixture.base.read_regular_file(fixture.DOCUMENTATION_PATH, fixture.base.MAX_SNAPSHOT_BYTES)
        fixture.validate_documentation(data)
        for altered in (data + b" ", data[:-1], b"{}"):
            with self.assertRaises(fixture.harness.HarnessError):
                fixture.validate_documentation(altered)

    def signature(self):
        return [{"critical": {"image": {"docker-manifest-digest": fixture.INDEX},
                              "type": "https://sigstore.dev/cosign/sign/v1"}}]

    def test_signature_requires_exact_claim(self):
        fixture.validate_signature(fixture.base.canonical_json(self.signature()))
        for value in ([], [{}], [None], self.signature() * 33):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(fixture.harness.HarnessError):
                    fixture.validate_signature(fixture.base.canonical_json(value))
        changed = self.signature()
        changed[0]["critical"]["image"]["docker-manifest-digest"] = fixture.tls.staged.INDEX
        with self.assertRaises(fixture.harness.HarnessError):
            fixture.validate_signature(fixture.base.canonical_json(changed))

    def test_signature_verification_has_no_bypass(self):
        with patch.object(fixture.base, "run_bounded", return_value=(0, fixture.base.canonical_json(self.signature()))) as run:
            fixture.verify_signature()
        argv = run.call_args.args[0]
        self.assertEqual(argv, ["cosign", "verify", "--certificate-identity", fixture.IDENTITY,
                               "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
                               "docker.io/openbao/openbao@" + fixture.INDEX])

    def test_plugin_exclusions_do_not_remove_other_mounts(self):
        self.assertEqual(len(fixture.SECRET_MOUNTS), len(fixture.base.SECRET_MOUNTS) - 1)
        self.assertEqual(len(fixture.AUTH_MOUNTS), len(fixture.base.AUTH_MOUNTS) - 3)
        self.assertNotIn("ldap", {row[1] for row in fixture.SECRET_MOUNTS})
        self.assertFalse({row[1] for row in fixture.AUTH_MOUNTS} & {"ldap", "radius", "kerberos"})

    def test_sanitization_requires_positive_listener_control(self):
        valid = {"data": {"listeners": [{"config": {"address": "0.0.0.0:8200",
                                                   "tls_acme_eab_key_id": fixture.EAB_KEY_ID}}]}}
        fixture.check_sanitized(valid, "disposable-marker")
        invalid = [{}, {"data": {}}, {"data": {"listeners": []}},
                   {"data": {"listeners": [{"config": {}}]}}]
        leaked_key = copy.deepcopy(valid)
        leaked_key["data"]["listeners"][0]["config"]["tls_acme_eab_mac_key"] = ""
        leaked_value = copy.deepcopy(valid)
        leaked_value["unexpected"] = "disposable-marker"
        for response in [*invalid, leaked_key, leaked_value]:
            with self.assertRaises(fixture.harness.HarnessError) as error:
                fixture.check_sanitized(response, "disposable-marker")
            self.assertNotIn("disposable-marker", str(error.exception))

    def test_config_supplies_eab_pair_without_enabling_acme(self):
        with tempfile.TemporaryDirectory() as directory:
            config, marker = fixture.prepare_config(Path(directory))
            data = config.read_bytes()
            self.assertEqual(len(marker), 64)
            self.assertEqual(data.count(b'tls_acme_eab_key_id = "' + fixture.EAB_KEY_ID.encode() + b'"'), 1)
            self.assertEqual(data.count(b'tls_acme_eab_mac_key = "' + marker.encode() + b'"'), 1)
            self.assertIn(b'tls_min_version = "tls13"', data)
            self.assertIn(b'tls_cert_file = "/openbao/tls/server.crt"', data)
            self.assertIn(b'tls_key_file = "/openbao/tls/server.key"', data)
            self.assertNotIn(b'tls_acme_ca_directory', data)
            self.assertNotIn(b'tls_acme_enable', data)
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o640)

    def document(self):
        return {"openapi": "3.0.2", "info": {"version": fixture.VERSION},
                         "paths": {"/sys/health": {"get": {"responses": {"200": {"description": "ok"}}}}},
                         "components": {"schemas": {}}}

    def test_normalization_requires_exact_version(self):
        result = fixture.normalize_api(self.document(), [])
        self.assertEqual(result["version"], fixture.VERSION)
        self.assertEqual(result["operation_count"], 1)
        self.assertEqual(result["image_index_digest"], fixture.INDEX)
        for version in ("2.7.0", "2.7.2", "2.7.1+unreviewed", None):
            doc = self.document()
            doc["info"]["version"] = version
            with self.assertRaises(fixture.harness.HarnessError):
                fixture.normalize_api(doc, [])

    def test_empty_api_fails_closed(self):
        doc = self.document()
        doc["paths"] = {}
        with self.assertRaises(fixture.harness.HarnessError):
            fixture.normalize_api(doc, [])

    def test_cli_envelope_is_not_the_http_contract(self):
        for response in ({"data": self.document()}, {}, None, [], {"errors": ["denied"]}):
            with self.assertRaises(fixture.harness.HarnessError):
                fixture.normalize_api(response, [])

    def test_capture_mounts_then_normalizes_raw_http_document(self):
        count = len(fixture.SECRET_MOUNTS) + len(fixture.AUTH_MOUNTS)
        with patch.object(fixture, "call", side_effect=[{}] * count + [self.document()]) as call, \
             redirect_stdout(io.StringIO()):
            result = fixture.capture_api("https://127.0.0.1", None, "disposable-token")
        self.assertEqual(len(result["mounts"]), count)
        self.assertEqual(result["document"]["info"]["version"], fixture.VERSION)
        self.assertEqual(call.call_args.args[3:],
                         ("POST", "/v1/sys/internal/specs/openapi", {"generic_mount_paths": True}))
        self.assertEqual(call.call_args.kwargs, {"openapi": True})
        self.assertEqual(call.call_args_list[0].args[-1], {"type": "kv", "options": {"version": "1"}})
        self.assertEqual(call.call_args_list[1].args[-1], {"type": "kv", "options": {"version": "2"}})

    def test_malformed_api_still_fails_closed(self):
        for key, value in (("openapi", "2.0"), ("info", {}), ("paths", []), ("components", {})):
            document = self.document()
            document[key] = value
            with self.assertRaises(fixture.harness.HarnessError):
                fixture.normalize_api(document, [])

    def test_expired_login_success_cannot_count_as_denial(self):
        responses = [
            {"data": {"listeners": [{"config": {"tls_acme_eab_key_id": fixture.EAB_KEY_ID}}]}}, {}, {},
            {"data": {"role_id": "disposable-role"}},
            {"data": {"secret_id": "disposable-id"}},
            {"auth": {"client_token": "disposable-token"}},
            {"auth": {"client_token": "disposable-token"}},
        ]
        for status, response in ((200, {"auth": {"client_token": "disposable-token"}}),
                                 (403, {"errors": ["permission denied"]}),
                                 (500, {"errors": ["invalid role or secret ID"]})):
            with patch.object(fixture, "call", side_effect=copy.deepcopy(responses)), \
                 patch.object(fixture, "request", return_value=(status, response)), \
                 patch.object(fixture.time, "sleep"), redirect_stdout(io.StringIO()), \
                 self.assertRaises(fixture.harness.HarnessError):
                fixture.patch_probes("https://127.0.0.1", None, "disposable", "marker")

    def test_nonroot_capture_fails_before_commands(self):
        with patch.object(fixture.os, "geteuid", return_value=1000), \
             patch.object(fixture, "verify_signature") as verify, \
             self.assertRaises(fixture.harness.HarnessError):
            fixture.capture()
        verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
