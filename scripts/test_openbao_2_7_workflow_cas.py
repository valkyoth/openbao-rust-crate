#!/usr/bin/python3 -EsSB
"""Offline failure, state-integrity and cleanup tests for the workflow CAS fixture."""

import contextlib
import copy
import io
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import openbao_2_7_workflow_cas as subject
import verify_openbao_2_7_workflow_cas as retained


class WorkflowCasTests(unittest.TestCase):
    def test_retained_evidence_rejects_changed_claims_and_input_omissions(self):
        original = retained.verify()
        for field, value in (("version", "2.6.3"), ("outcome", "failed"), ("checks", []),
                             ("scope", "sdk-integration"), ("tls", "TLSv1.2"),
                             ("image_linux_amd64_digest", "sha256:" + "0" * 64),
                             ("routable", True), ("routable", 0),
                             ("sdk_cas_enabled", True), ("sdk_cas_enabled", 0),
                             ("prefix_listing_verified", True), ("prefix_listing_verified", 0)):
            with self.assertRaises(subject.snapshots.SnapshotError):
                retained.validate_report(dict(original, **{field: value}))
        for field in original:
            changed = dict(original)
            del changed[field]
            with self.assertRaises(subject.snapshots.SnapshotError): retained.validate_report(changed)
        with self.assertRaises(subject.snapshots.SnapshotError):
            retained.validate_report(dict(original, extra="unexpected"))
        for path in original["inputs"]:
            for omit in (True, False):
                changed = copy.deepcopy(original)
                if omit: del changed["inputs"][path]
                else: changed["inputs"][path] = "0" * 64
                with self.assertRaises(subject.snapshots.SnapshotError): retained.validate_report(changed)

    def test_retained_bytes_and_independent_pin_are_enforced(self):
        with patch.object(retained, "EXPECTED_SHA256", "0" * 64):
            with self.assertRaises(subject.snapshots.SnapshotError): retained.verify()
        data = subject.snapshots.read_regular_file(retained.RESULT, 65536)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_bytes(data + b" ")
            with patch.object(retained, "RESULT", path):
                with self.assertRaises(subject.snapshots.SnapshotError): retained.verify()
                with patch.object(retained, "EXPECTED_SHA256", subject.snapshots.sha256(data + b" ")):
                    with self.assertRaises(subject.snapshots.SnapshotError): retained.verify()

    def test_rejection_requires_exact_error_and_status(self):
        message = "check-and-set parameter required for this call"
        subject.require_error(400, {"errors": [message]}, message)
        for status, response in ((200, {"errors": [message]}), (500, {"errors": [message]}),
                                 (400, {"errors": ["permission denied"]}), (400, {})):
            with self.assertRaises(subject.harness.HarnessError): subject.require_error(status, response, message)

    def test_state_checks_all_written_fields_and_strict_version_type(self):
        data = {"version": 1, "description": "initial", "workflow": subject.WORKFLOW,
                "cas_required": True, "allow_unauthenticated": False}
        subject.state({"data": data}, 1, "initial", True)
        for key, value in (("version", True), ("version", 2), ("description", "changed"),
                           ("workflow", "changed"), ("cas_required", False), ("allow_unauthenticated", True)):
            with self.assertRaises(subject.harness.HarnessError):
                subject.state({"data": dict(data, **{key: value})}, 1, "initial", True)

    def test_probe_detects_ignored_cas_mutation_and_multiple_winners(self):
        for defect in (None, "ignore-cas", "mutate-on-rejection", "race-accepts-stale"):
            entries, lock = {}, threading.Lock()
            def request(address, ca, token, method, path, body=None):
                with lock:
                    existing = entries.get(path)
                    if method == "GET": return (200, {"data": dict(existing)}) if existing else (404, {})
                    if method == "DELETE":
                        entries.pop(path, None)
                        return 204, {}
                    self.assertEqual(method, "POST")
                    cas = body.get("cas")
                    error = None
                    if cas is None and (body["cas_required"] or existing and existing["cas_required"]):
                        error = "check-and-set parameter required for this call"
                    elif cas == -1 and existing:
                        error = "check-and-set parameter set to -1 on existing entry"
                    elif cas is not None and cas != -1 and not existing:
                        error = "check-and-set parameter set greater than 1 on non-existent entry"
                    elif cas is not None and cas != -1 and cas != existing["version"]:
                        error = "check-and-set parameter did not match the current version"
                    if defect == "ignore-cas" or defect == "race-accepts-stale" and body["description"].startswith("writer-"):
                        error = None
                    if error:
                        if defect == "mutate-on-rejection" and existing: existing["description"] = "changed"
                        return 400, {"errors": [error]}
                    entries[path] = {key: value for key, value in body.items() if key != "cas"}
                    entries[path]["version"] = existing["version"] + 1 if existing else 1
                    return 200, {"data": dict(entries[path])}
            with patch.object(subject.transport, "request", side_effect=request), contextlib.redirect_stdout(io.StringIO()):
                if defect:
                    with self.assertRaises(subject.harness.HarnessError): subject.probe("address", Path("ca"), "fixture-token")
                else:
                    subject.probe("address", Path("ca"), "fixture-token")
                    self.assertEqual(entries, {})

    def test_partial_setup_and_probe_failure_cleanup_without_success_report(self):
        for fail_at in ("network", "container", "probe"):
            removed = []
            with contextlib.ExitStack() as stack:
                def mock(obj, name, **kwargs): return stack.enter_context(patch.object(obj, name, **kwargs))
                mock(subject.os, "geteuid", return_value=0)
                mock(subject.staged, "verify")
                mock(subject.staged, "verify_image_signature")
                mock(subject.transport.evidence_tools, "protected_path", side_effect=lambda path: path)
                mock(subject.harness, "generate_tls", side_effect=lambda root, *args: (root / "tls", root / "ca"))
                mock(subject.harness, "inspect_image", return_value="image")
                def run(command, **kwargs):
                    if fail_at == "network" and "create" in command or fail_at == "container" and "run" in command:
                        raise subject.harness.HarnessError("synthetic-private-detail")
                    return b"{}"
                mock(subject.harness, "run_bounded", side_effect=run)
                mock(subject.snapshots, "validate_container_resource_config")
                mock(subject.fixture, "verify_network")
                mock(subject.harness, "parse_port", return_value=18200)
                mock(subject.fixture, "wait_for_health")
                mock(subject.fixture, "probe_tls")
                mock(subject.harness, "initialize_and_unseal", return_value="fixture-token")
                mock(subject, "probe", side_effect=subject.harness.HarnessError("synthetic-private-detail"))
                mock(subject.harness, "remove_owned_resource", side_effect=lambda p, kind, *args: removed.append(kind))
                mock(subject.harness, "cleanup_private_files", return_value=True)
                output = mock(subject.tempfile, "NamedTemporaryFile")
                stack.enter_context(patch("sys.argv", ["fixture"]))
                with contextlib.redirect_stdout(io.StringIO()) as messages:
                    self.assertEqual(subject.main(), 1)
                output.assert_not_called()
                self.assertNotIn("synthetic-private-detail", messages.getvalue())
            self.assertEqual(removed, ["network"] if fail_at == "network" else ["container", "network"])

    def test_inputs_bind_server_transport_and_sdk_source_without_promotion(self):
        inputs = subject.input_hashes()
        for path in ("scripts/openbao_2_7_workflow_cas.py", "scripts/openbao_2_7_external_keys.py", "src/sys.rs"):
            self.assertIn(path, inputs)
        self.assertNotIn("cas", subject.payload("omitted"))
        self.assertEqual(subject.payload("zero", 0)["cas"], 0)


if __name__ == "__main__":
    unittest.main()
