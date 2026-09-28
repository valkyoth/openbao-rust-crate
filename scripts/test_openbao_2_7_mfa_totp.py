#!/usr/bin/python3 -EsSB
"""Adversarial offline tests for the staged MFA enrollment fixture."""

import base64
import contextlib
import copy
import io
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse
import uuid

import openbao_2_7_mfa_totp as subject
import verify_openbao_2_7_mfa_totp as retained


def enrollment_response(entity, secret=None):
    secret = secret or base64.b32encode(secrets.token_bytes(20)).decode()
    query = urllib.parse.urlencode({"issuer": subject.ISSUER, "secret": secret,
                                   "algorithm": "SHA256", "digits": "6", "period": "30"})
    # Synthetic PNG header only: the fixture does not claim QR decoding.
    image = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR" + (200).to_bytes(4, "big") * 2 + bytes(9)
    return {"data": {"url": "otpauth://totp/" + subject.ISSUER + ":" + entity + "?" + query,
                     "barcode": base64.b64encode(image).decode()}}


def duplicate_response():
    return {"warnings": [f'Entity already has a secret for MFA method "{subject.METHOD_NAME}"']}


class MfaTotpTests(unittest.TestCase):
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

    def test_report_rejects_changed_claims_and_inputs(self):
        original = subject.report_for(subject.input_hashes())
        subject.validate_report(original)
        for field in original:
            changed = dict(original)
            del changed[field]
            with self.assertRaises(subject.harness.HarnessError):
                subject.validate_report(changed)
        for field in ("routable", "storage_erasure_verified", "qr_decode_verified", "login_enforcement_verified"):
            for value in (0, True):
                with self.assertRaises(subject.harness.HarnessError):
                    subject.validate_report(dict(original, **{field: value}))
        for field, value in (("scope", "sdk-integration"), ("checks", []), ("outcome", "failed"),
                             ("tls", "TLSv1.2"), ("extra", True)):
            with self.assertRaises(subject.harness.HarnessError):
                subject.validate_report(dict(original, **{field: value}))
        for path in original["inputs"]:
            for omit in (True, False):
                changed = copy.deepcopy(original)
                if omit: del changed["inputs"][path]
                else: changed["inputs"][path] = "0" * 64
                with self.assertRaises(subject.harness.HarnessError):
                    subject.validate_report(changed)

    def test_enrollment_rejects_malformed_secret_metadata(self):
        entity = str(uuid.uuid4())
        response = enrollment_response(entity)
        subject.enrollment(response, entity)
        mutations = [
            {"url": response["data"]["url"].replace("otpauth:", "https:")},
            {"url": response["data"]["url"] + "&secret=unexpected"},
            {"url": response["data"]["url"].replace("SHA256", "SHA1")},
            {"url": response["data"]["url"].replace(entity, str(uuid.uuid4()))},
            {"url": "x" * 8193}, {"url": None}, {"barcode": ""},
            {"barcode": "!"}, {"barcode": "x" * 65537},
            {"barcode": base64.b64encode(bytes(33)).decode()},
        ]
        for mutation in mutations:
            with self.assertRaises((subject.harness.HarnessError, ValueError)):
                subject.enrollment({"data": dict(response["data"], **mutation)}, entity)

    def test_duplicate_requires_warning_without_secret(self):
        subject.duplicate(duplicate_response())
        for response in ({}, {"warnings": ["unrelated"]},
                         dict(duplicate_response(), data={"url": "unexpected"})):
            with self.assertRaises(subject.harness.HarnessError):
                subject.duplicate(response)

    def test_identifiers_cannot_inject_paths(self):
        subject.identifier(str(uuid.uuid4()))
        for value in ("../method", "", None, "x" * 36, str(uuid.uuid4()).upper()):
            with self.assertRaises(subject.harness.HarnessError):
                subject.identifier(value)

    def test_probe_detects_missing_removal_reuse_and_wrong_entity(self):
        for defect in (None, "no-removal", "same-secret", "remove-control", "acl-allowed",
                       "acl-wrong-error", "inherited-root", "extra-default", "missing-policy"):
            method, entities, entries = str(uuid.uuid4()), [], {}
            old_secret = base64.b32encode(secrets.token_bytes(20)).decode()
            def request(address, ca, token, operation, path, payload=None, wrap=False):
                if token == "fixture-restricted":
                    if defect == "acl-allowed": return 204, {}
                    return 403, {"errors": ["unrelated" if defect == "acl-wrong-error" else "permission denied"]}
                if path == subject.BASE: return 200, {"data": {"method_id": method}}
                if path == "identity/entity":
                    entity = str(uuid.uuid4())
                    entities.append(entity)
                    return 200, {"data": {"id": entity}}
                if path == "auth/token/create":
                    self.assertEqual(payload["policies"], [subject.DENY_POLICY])
                    self.assertIs(payload["no_default_policy"], True)
                    policies = {"inherited-root": ["root"],
                                "extra-default": [subject.DENY_POLICY, "default"],
                                "missing-policy": []}.get(defect, [subject.DENY_POLICY])
                    return 200, {"auth": {"client_token": "fixture-restricted", "policies": policies}}
                if path == "sys/policies/acl/" + subject.DENY_POLICY:
                    self.assertEqual(operation, "POST")
                    self.assertEqual(payload, {"policy": 'path "*" { capabilities = ["deny"] }'})
                    return 204, {}
                if path.endswith("/admin-generate"):
                    entity = payload["entity_id"]
                    self.assertEqual(payload["method_id"], method)
                    if entity in entries: return 200, duplicate_response()
                    entries[entity] = True
                    return 200, enrollment_response(entity, old_secret if defect == "same-secret" else None)
                if path.endswith("/admin-destroy"):
                    if defect != "no-removal":
                        entries.pop(payload["entity_id"], None)
                    if defect == "remove-control": entries.clear()
                    return 204, {}
                self.assertEqual(operation, "DELETE")
                return 204, {}
            with patch.object(subject.system, "request", side_effect=request), contextlib.redirect_stdout(io.StringIO()):
                if defect:
                    with self.assertRaises(subject.harness.HarnessError):
                        subject.probe("address", Path("ca"), "fixture-root")
                else:
                    subject.probe("address", Path("ca"), "fixture-root")
                    self.assertEqual(entries, {})

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
