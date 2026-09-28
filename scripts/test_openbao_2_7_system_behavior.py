#!/usr/bin/python3 -EsSB
"""Offline adversarial tests for staged system behavior evidence."""

import contextlib
import copy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import openbao_2_7_system_behavior as subject
import verify_openbao_2_7_system_behavior as retained


class SystemBehaviorTests(unittest.TestCase):
    def test_retained_evidence_digest_and_canonical_encoding(self):
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

    def test_report_rejects_changed_claims_and_source_inputs(self):
        original = subject.report_for(subject.input_hashes())
        subject.validate_report(original)
        for field in original:
            changed = dict(original)
            del changed[field]
            with self.assertRaises(subject.harness.HarnessError):
                subject.validate_report(changed)
        for field, value in (("routable", 0), ("routable", True), ("outcome", "failed"),
                             ("scope", "sdk-integration"), ("checks", []), ("tls", "TLSv1.2"),
                             ("version", "2.6.3"), ("extra", True)):
            with self.assertRaises(subject.harness.HarnessError):
                subject.validate_report(dict(original, **{field: value}))
        for path in original["inputs"]:
            for omitted in (True, False):
                changed = copy.deepcopy(original)
                if omitted:
                    del changed["inputs"][path]
                else:
                    changed["inputs"][path] = "0" * 64
                with self.assertRaises(subject.harness.HarnessError):
                    subject.validate_report(changed)

    def test_config_requires_all_fields_and_actual_booleans(self):
        data = dict.fromkeys(subject.CONFIG_FIELDS, False)
        subject.config_state({"data": data})
        for field in subject.CONFIG_FIELDS:
            for value in (None, True, 0, "", "false"):
                with self.assertRaises(subject.harness.HarnessError):
                    subject.config_state({"data": dict(data, **{field: value})})
            missing = dict(data)
            del missing[field]
            with self.assertRaises(subject.harness.HarnessError):
                subject.config_state({"data": missing})

    def test_denial_requires_exact_status_and_cause(self):
        subject.denied(403, {"errors": ["permission denied"]}, "permission denied")
        for status, response in ((500, {"errors": ["permission denied"]}),
                                 (403, {"errors": ["unrelated"]}), (403, {}),
                                 (403, {"errors": ["permission denied", "unrelated"]}),
                                 (200, {"errors": ["permission denied"]})):
            with self.assertRaises(subject.harness.HarnessError):
                subject.denied(status, response, "permission denied")

    def test_probe_detects_revocation_and_unwrap_defects(self):
        for defect in (None, "positive-unwrap", "missing-accessor", "retained-accessor",
                       "unwrap-after-revoke", "reuse-after-revoke", "unrelated-error",
                       "swapped-denial"):
            tokens, revoked = {}, set()
            def request(address, ca, token, method, path, payload=None, wrap=False):
                if path == "sys/config/state/sanitized":
                    return 200, {"data": dict.fromkeys(subject.CONFIG_FIELDS, False)}
                if path == "sys/wrapping/wrap":
                    self.assertTrue(wrap)
                    key = "fixture-" + str(len(tokens))
                    tokens[key] = payload
                    return 200, {"wrap_info": {"token": key, "accessor": key + "-accessor"}}
                if path == "auth/token/lookup-accessor":
                    key = payload["accessor"].removesuffix("-accessor")
                    if (key in revoked and defect != "retained-accessor") or defect == "missing-accessor":
                        return 400, {"errors": ["invalid accessor"]}
                    return 200, {"data": {"accessor": payload["accessor"]}}
                if token in revoked:
                    if defect == "unwrap-after-revoke" and path == "sys/wrapping/unwrap":
                        return 200, {"data": tokens[token]}
                    if defect == "reuse-after-revoke" and path == "auth/token/revoke-self":
                        return 204, {}
                    if path == "sys/wrapping/unwrap" and defect != "swapped-denial":
                        return 400, {"errors": ["unrelated" if defect == "unrelated-error"
                                               else "wrapping token is not valid or does not exist"]}
                    return 403, {"errors": ["unrelated" if defect == "unrelated-error" else "permission denied"]}
                if path == "sys/wrapping/unwrap":
                    return 200, {"data": {} if defect == "positive-unwrap" else tokens[token]}
                self.assertEqual(path, "auth/token/revoke-self")
                revoked.add(token)
                return 204, {}
            with patch.object(subject, "request", side_effect=request), contextlib.redirect_stdout(io.StringIO()):
                if defect:
                    with self.assertRaises(subject.harness.HarnessError):
                        subject.probe("address", Path("ca"), "fixture-root")
                else:
                    subject.probe("address", Path("ca"), "fixture-root")

    def test_wrapping_denial_is_not_interchangeable_with_permission_denial(self):
        message = "wrapping token is not valid or does not exist"
        subject.denied(400, {"errors": [message]}, message)
        for status, errors in ((403, [message]), (400, ["permission denied"]),
                               (403, ["permission denied"]), (400, [message, "unrelated"]),
                               (500, [message]), (200, [message])):
            with self.assertRaises(subject.harness.HarnessError):
                subject.denied(status, {"errors": errors}, message)
        with self.assertRaises(subject.harness.HarnessError):
            subject.denied(400, {"errors": [message]}, "permission denied")

    def test_transport_bounds_redaction_and_no_retry(self):
        for data, content_type in ((b"x" * (subject.fixture.MAX_BODY + 1), "application/json"),
                                   (b"{}", "text/plain")):
            response = MagicMock()
            response.__enter__.return_value = response
            response.read.return_value = data
            response.headers.get_content_type.return_value = content_type
            opener = MagicMock()
            opener.open.return_value = response
            with patch.object(subject.fixture, "context"), patch.object(
                    subject.urllib.request, "build_opener", return_value=opener):
                with self.assertRaises(subject.harness.HarnessError):
                    subject.request("https://localhost", Path("ca"), "fixture-token", "GET", "test")
            opener.open.assert_called_once()
            response.read.assert_called_once_with(subject.fixture.MAX_BODY + 1)
            response.__exit__.assert_called_once()
        with patch.object(subject.urllib.request, "build_opener") as build:
            for token in ("", "bad\r\nheader", "x" * 8193):
                with self.assertRaises(subject.harness.HarnessError):
                    subject.request("https://localhost", Path("ca"), token, "GET", "test")
            build.assert_not_called()

    def test_partial_setup_probe_and_cleanup_failures_never_emit_report(self):
        for fail_at in ("network", "container", "probe", "cleanup"):
            removed = []
            with contextlib.ExitStack() as stack:
                def mock(obj, name, **kwargs):
                    return stack.enter_context(patch.object(obj, name, **kwargs))
                mock(subject.os, "geteuid", return_value=0)
                mock(subject.staged, "verify")
                mock(subject.staged, "verify_image_signature")
                mock(subject.transport.evidence_tools, "protected_path", side_effect=lambda path: path)
                mock(subject.harness, "generate_tls", side_effect=lambda root, *args: (root / "tls", root / "ca"))
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
                mock(subject.harness, "initialize_and_unseal", return_value="fixture-token")
                mock(subject, "probe", side_effect=subject.harness.HarnessError("synthetic-private-detail")
                     if fail_at == "probe" else None)
                mock(subject.harness, "remove_owned_resource", side_effect=lambda p, kind, *args: removed.append(kind))
                mock(subject.harness, "cleanup_private_files", return_value=fail_at != "cleanup")
                output = mock(subject.tempfile, "NamedTemporaryFile")
                stack.enter_context(patch("sys.argv", ["fixture"]))
                with contextlib.redirect_stdout(io.StringIO()) as messages:
                    self.assertEqual(subject.main(), 1)
                output.assert_not_called()
                self.assertNotIn("synthetic-private-detail", messages.getvalue())
            self.assertEqual(removed, ["network"] if fail_at == "network" else ["container", "network"])


if __name__ == "__main__":
    unittest.main()
