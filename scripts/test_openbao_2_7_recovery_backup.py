#!/usr/bin/python3 -EsSB
"""Offline adversarial tests for disposable raw backup evidence."""

import base64
import contextlib
import copy
import io
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import openbao_2_7_recovery_backup as subject
import verify_openbao_2_7_recovery_backup as retained


class RecoveryBackupTests(unittest.TestCase):
    def test_retained_digest_and_canonical_encoding(self):
        retained.verify()
        with patch.object(retained, "EXPECTED_SHA256", "0" * 64):
            with self.assertRaises(subject.snapshots.SnapshotError):
                retained.verify()
        data = subject.snapshots.read_regular_file(retained.RESULT, 65536)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_bytes(data + b" ")
            with patch.object(retained, "RESULT", path):
                with self.assertRaises(subject.snapshots.SnapshotError):
                    retained.verify()
                with patch.object(retained, "EXPECTED_SHA256", subject.snapshots.sha256(data + b" ")):
                    with self.assertRaises(subject.snapshots.SnapshotError):
                        retained.verify()

    def test_static_seal_is_private_file_not_inline_or_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tls = root / "tls"
            tls.mkdir(mode=0o750)
            config = subject.configure_static_seal(root, tls)
            key = tls / "fixture-seal.key"
            self.assertEqual(key.stat().st_size, 32)
            self.assertEqual(key.stat().st_mode & 0o777, 0o640)
            contents = config.read_text()
            self.assertIn('file:///openbao/tls/fixture-seal.key', contents)
            self.assertNotIn('env://', contents)
            self.assertEqual(config.stat().st_mode & 0o777, 0o640)

    def test_initialization_requires_recovery_share_and_unsealed_state(self):
        for sealed in (False, True):
            with patch.object(subject.harness, "https_json", side_effect=[
                {"root_token": "fixture-token", "recovery_keys_base64": ["fixture-share"]},
                {"sealed": sealed},
            ]) as request:
                if sealed:
                    with self.assertRaises(subject.harness.HarnessError):
                        subject.initialize("address", Path("ca"))
                else:
                    subject.initialize("address", Path("ca"))
                self.assertEqual(request.call_args_list[0].args[4],
                                 {"recovery_shares": 1, "recovery_threshold": 1})
                self.assertEqual(request.call_args_list[1].args[2:4], ("GET", "/v1/sys/seal-status"))

    def test_report_rejects_changed_claims_and_inputs(self):
        report = subject.report_for(subject.input_hashes())
        subject.validate_report(report)
        for field in report:
            changed = dict(report)
            del changed[field]
            with self.assertRaises(subject.harness.HarnessError): subject.validate_report(changed)
        for field in ("routable", "unseal_backup_verified", "upgrade_verified", "backup_decryption_verified"):
            for value in (True, 0):
                with self.assertRaises(subject.harness.HarnessError):
                    subject.validate_report(dict(report, **{field: value}))
        for field, value in (("scope", "sdk-integration"), ("checks", []), ("outcome", "failed"), ("extra", True)):
            with self.assertRaises(subject.harness.HarnessError):
                subject.validate_report(dict(report, **{field: value}))
        for path in report["inputs"]:
            for omit in (True, False):
                changed = copy.deepcopy(report)
                if omit: del changed["inputs"][path]
                else: changed["inputs"][path] = "0" * 64
                with self.assertRaises(subject.harness.HarnessError): subject.validate_report(changed)

    def test_backup_exact_envelope_and_bounds(self):
        good = {"Nonce": "fixture-nonce", "Keys": {"fixture-fingerprint": ["ab"]}}
        subject.backup_matches(json.dumps(good), "fixture-nonce", "fixture-fingerprint", "ab")
        for value in (json.dumps(dict(good, Nonce="other")), json.dumps(dict(good, Keys={})),
                      json.dumps(dict(good, extra=True)), "x" * 65537, None):
            with self.assertRaises(subject.harness.HarnessError):
                subject.backup_matches(value, "fixture-nonce", "fixture-fingerprint", "ab")

    def test_protected_requires_exact_path_status_and_cause(self):
        path = "core/keyring"
        subject.protected(400, {"errors": [f'cannot access "{path}"']}, path)
        for status, errors in ((200, [f'cannot access "{path}"']), (500, [f'cannot access "{path}"']),
                               (400, ["permission denied"]), (400, ['cannot access "other"'])):
            with self.assertRaises(subject.harness.HarnessError):
                subject.protected(status, {"errors": errors}, path)

    def test_probe_rejects_wrong_backup_layer_missing_deletion_and_acl_bypass(self):
        for defect in (None, "wrong-backup", "wrong-base64", "wrong-dedicated", "not-deleted",
                       "acl-bypass", "protected-readable"):
            exists = False
            value = json.dumps({"Nonce": "fixture-nonce", "Keys": {"a" * 40: ["abcd"]}})
            def request(address, ca, token, method, path, payload=None, wrap=False):
                nonlocal exists
                if token == "fixture-restricted":
                    return (200, {"data": {"value": value}}) if defect == "acl-bypass" else (
                        403, {"errors": ["permission denied"]})
                if path == "sys/rotate/recovery/init":
                    self.assertEqual(method, "POST")
                    self.assertEqual(token, "fixture-root")
                    self.assertIs(payload["backup"], True)
                    self.assertEqual(len(payload["pgp_keys"]), 1)
                    return 200, {"data": {"nonce": "fixture-nonce", "started": True, "backup": True}}
                if path == "sys/rotate/recovery/update":
                    self.assertEqual(method, "POST")
                    self.assertEqual(token, "fixture-root")
                    exists = True
                    return 200, {"data": {"complete": True, "backup": True,
                                 "pgp_fingerprints": ["a" * 40], "keys": ["abcd"]}}
                if path == subject.RAW:
                    if not exists: return 404, {}
                    return 200, {"data": {"value": "{}" if defect == "wrong-backup" else value}}
                if path == subject.RAW + "?encoding=base64":
                    encoded = base64.b64encode((value if defect != "wrong-base64" else "{}").encode()).decode()
                    return 200, {"data": {"value": encoded}}
                if path == "sys/rotate/recovery/backup":
                    if method == "DELETE":
                        if defect != "not-deleted": exists = False
                        return 204, {}
                    return 200, {"data": {"nonce": "fixture-nonce",
                                         "keys": {} if defect == "wrong-dedicated" else {"a" * 40: ["abcd"]}}}
                if path == "sys/policies/acl/fixture-raw-deny": return 204, {}
                if path == "auth/token/create":
                    self.assertEqual(payload["policies"], ["fixture-raw-deny"])
                    return 200, {"auth": {"policies": ["fixture-raw-deny"], "client_token": "fixture-restricted"}}
                self.assertTrue(path.startswith("sys/raw/core/"))
                if defect == "protected-readable": return 200, {"data": {"value": "unexpected"}}
                return 400, {"errors": [f'cannot access "{path.removeprefix("sys/raw/")}"']}
            with patch.object(subject.system, "request", side_effect=request), contextlib.redirect_stdout(io.StringIO()):
                if defect:
                    with self.assertRaises(subject.harness.HarnessError):
                        subject.probe("address", Path("ca"), "fixture-root", "fixture-share")
                else:
                    observed = []
                    def observer(address, ca, token):
                        self.assertTrue(exists)
                        self.assertEqual((address, ca, token), ("address", Path("ca"), "fixture-root"))
                        observed.append(True)
                    subject.probe("address", Path("ca"), "fixture-root", "fixture-share", observer)
                    self.assertEqual(observed, [True])
                    self.assertFalse(exists)

    def test_partial_setup_probe_and_cleanup_failures_never_emit_report(self):
        for fail_at in ("network", "container", "probe", "cleanup", "seal-cleanup"):
            removed = []
            with contextlib.ExitStack() as stack:
                def mock(obj, name, **kwargs):
                    return stack.enter_context(patch.object(obj, name, **kwargs))
                mock(subject.os, "geteuid", return_value=0)
                mock(subject.staged, "verify")
                mock(subject.staged, "verify_image_signature")
                mock(subject.transport.evidence_tools, "protected_path", side_effect=lambda path: path)
                mock(subject.harness, "generate_tls", side_effect=lambda root, *args: (root / "tls", root / "ca"))
                mock(subject, "configure_static_seal", side_effect=lambda root, tls: root / "config.hcl")
                sanitize = mock(subject.harness, "sanitize_file", return_value=fail_at != "seal-cleanup")
                mock(subject.harness, "inspect_image", return_value="image")
                def run(command, **kwargs):
                    if (fail_at == "network" and "create" in command
                            or fail_at == "container" and "run" in command):
                        raise subject.harness.HarnessError("synthetic-private-detail")
                    return b"{}"
                mock(subject.harness, "run_bounded", side_effect=run)
                mock(subject.snapshots, "validate_container_resource_config")
                mock(subject.fixture, "verify_network")
                mock(subject.harness, "parse_port", return_value=18200)
                mock(subject.fixture, "wait_for_health")
                mock(subject.fixture, "probe_tls")
                mock(subject, "initialize", return_value=("fixture-token", "fixture-share"))
                mock(subject, "probe", side_effect=subject.harness.HarnessError("synthetic-private-detail")
                     if fail_at == "probe" else None)
                mock(subject.harness, "remove_owned_resource", side_effect=lambda p, kind, *args: removed.append(kind))
                mock(subject.harness, "cleanup_private_files", return_value=fail_at != "cleanup")
                output = mock(subject.tempfile, "NamedTemporaryFile")
                stack.enter_context(patch("sys.argv", ["fixture"]))
                with contextlib.redirect_stdout(io.StringIO()) as messages:
                    self.assertEqual(subject.main(), 1)
                output.assert_not_called()
                sanitize.assert_called_once()
                self.assertEqual(sanitize.call_args.args[0].name, "fixture-seal.key")
                self.assertNotIn("synthetic-private-detail", messages.getvalue())
            self.assertEqual(removed, ["network"] if fail_at == "network" else ["container", "network"])


if __name__ == "__main__":
    unittest.main()
