#!/usr/bin/python3 -EsSB
"""Offline controls for staged control-group TLS evidence (not live evidence)."""

import contextlib
import io
from pathlib import Path
import unittest
from unittest.mock import patch

import openbao_2_7_control_groups as subject
import verify_openbao_2_7_control_groups as evidence


class ControlGroupFixtureTests(unittest.TestCase):
    def test_lifecycle_continues_with_secure_and_known_failure_versions(self):
        for secure in (True, False):
            version = 2 if secure else 3
            def stored(value, number):
                return {"data": {"value": value}, "metadata": {"version": number}}
            def call(method, path, *args, **kwargs):
                if path == "sys/namespaces/fixture-peer":
                    return {"data": {"id": "peer123"}}
                if path == "sys/wrapping/unwrap":
                    return next(responses)
                return {}
            responses = iter([{"data": {"version": 2}}, {"data": stored("changed", version)}])
            denied = {"errors": ["wrapping token is not valid or does not exist"]}
            with patch.object(subject, "Probe") as create, \
                 patch.object(subject.secrets, "token_urlsafe", side_effect=["initial", "changed", "final"]), \
                 patch.object(subject.time, "sleep"), patch.object(subject, "cancelled_unwrap") as cancel, \
                 contextlib.redirect_stdout(io.StringIO()):
                p = create.return_value
                p.user.side_effect = [("requester", "id1"), ("first", "id2"), ("second", "id3"), ("outsider", "id4"), ("peer", "id5")]
                p.call.side_effect = call
                p.deferred.return_value = ("wrapped", "accessor")
                p.review.side_effect = [
                    {"approved": False, "authorizations": [], "request_operation": "update",
                     "request_path": "fixture-kv/data/record", "request_data": {"data": {"value": "changed"}},
                     "request_entity": {"ID": "id1"}},
                    {"authorizations": []}, {"authorizations": []}, {"approved": True}]
                p.request.side_effect = [
                    (403, {"errors": ["permission denied"]}),
                    (500, {"errors": ["token owner cannot be approver"]}),
                    (400, denied) if secure else (200, {"data": {"version": 3}}),
                    (400, denied), (500, {"errors": ["cannot lookup token in different namespace"]}),
                    (400, denied)]
                p.value.side_effect = [stored("initial", 1), stored("initial", 1), stored("changed", 2),
                                       stored("changed", version), stored("changed", version), stored("final", version + 1)]
                self.assertIs(subject.probe("address", Path("ca"), "root", secure), secure)
                cancel.assert_called_once()
                self.assertEqual(p.request.call_count, 6)
                report = subject.report_for({}, secure)
                subject.validate_report(report, {})
                self.assertEqual(report["security_checks"]["server-replay-rejection"], "passed" if secure else "known-upstream-failure")

    def test_retained_evidence_rejects_digest_and_input_changes(self):
        report = evidence.verify()
        self.assertEqual(report["security_checks"]["server-replay-rejection"], "known-upstream-failure")
        self.assertNotIn("replay-denied", report["checks"])
        with patch.object(evidence.snapshots, "read_regular_file", return_value=b"{}"), \
             self.assertRaises(subject.snapshots.SnapshotError):
            evidence.verify()
        with patch.object(subject, "input_hashes", return_value={}), \
             self.assertRaises(subject.harness.HarnessError):
            evidence.verify()

    def test_entity_ids_require_exact_created_namespace(self):
        identifier = "00000000-0000-4000-8000-000000000001"
        subject.validate_entity_id(identifier)
        subject.validate_entity_id(identifier + ".peer123", "peer123")
        for value, namespace in ((identifier, "peer123"), (identifier + ".other", "peer123"),
                                 (identifier + ".peer123.extra", "peer123"),
                                 (identifier + ".peer123", None), (None, None),
                                 ("invalid", None), (identifier + ".", ""),
                                 (identifier + ".peer123", "peer\n123")):
            with self.assertRaises(subject.harness.HarnessError):
                subject.validate_entity_id(value, namespace)

    def test_known_replay_exception_is_exact_and_strict_mode_still_fails(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIs(subject.classify_known_replay(200, {"data": {"version": 3}}, 3, False), False)
            for strict in (True, False):
                self.assertIs(subject.classify_known_replay(400, {"errors": ["wrapping token is not valid or does not exist"]}, 2, strict), True)
            with self.assertRaises(subject.harness.HarnessError):
                subject.classify_known_replay(200, {"data": {"version": 3}}, 3, True)
            for status, body, version in ((400, {}, 2), (500, {}, 3),
                                          (200, {}, 3), (200, {"data": {"version": "3"}}, 3),
                                          (200, {"data": {"version": 3}}, 2),
                                          (200, {"data": {"version": 4}}, 4)):
                with self.assertRaises(subject.harness.HarnessError):
                    subject.classify_known_replay(status, body, version, False)
            with patch.object(subject.fixture, "VERSION", "2.7.1"), \
                 self.assertRaises(subject.harness.HarnessError):
                subject.classify_known_replay(200, {"data": {"version": 3}}, 3, False)

    def test_replay_success_never_passes_and_diagnostics_do_not_expose_body(self):
        denial = {"errors": ["wrapping token is not valid or does not exist"]}
        subject.reject_replay(400, denial, 2)
        for version in (None, True, "2", 1, 3):
            with self.assertRaises(subject.harness.HarnessError):
                subject.reject_replay(400, denial, version)
        for version, label in ((2, "unexpected-success"), (3, "write-version-advanced")):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), self.assertRaises(subject.harness.HarnessError):
                subject.reject_replay(200, {"data": "synthetic-private-payload"}, version)
            self.assertIn("replay diagnostic=" + label, output.getvalue())
            self.assertNotIn("synthetic-private-payload", output.getvalue())

    def test_review_uses_tagged_entity_shape_and_secret_free_mismatch_labels(self):
        entity, value = "synthetic-private-entity", "synthetic-private-value"
        review = {"approved": False, "authorizations": [], "request_operation": "update",
                  "request_path": "fixture-kv/data/record",
                  "request_data": {"data": {"value": value}}, "request_entity": {"ID": entity}}
        subject.initial_review(review, entity, value)
        mutations = [(field, None) for field in review]
        mutations.extend((("approved", True), ("approved", 0),
                          ("authorizations", [{"entity_id": entity}]),
                          ("request_operation", "read"), ("request_path", value),
                          ("request_data", {"data": {"value": "different"}}),
                          ("request_entity", {"id": entity})))
        for field, replacement in mutations:
            output = io.StringIO()
            with self.subTest(field=field), contextlib.redirect_stdout(output), \
                 self.assertRaises(subject.harness.HarnessError) as failure:
                subject.initial_review(dict(review, **{field: replacement}), entity, value)
            self.assertIn("Control-group fixture: review mismatch=", output.getvalue())
            for marker in (entity, value):
                self.assertNotIn(marker, output.getvalue())
                self.assertNotIn(marker, str(failure.exception))

    def test_denials_require_exact_status_and_error(self):
        for status, message in ((403, "permission denied"), (500, "token owner cannot be approver"),
                                (500, "cannot lookup token in different namespace"),
                                (400, "invalid accessor"), (400, "wrapping token is not valid or does not exist")):
            subject.denied(status, {"errors": [message]}, message)
            subject.denied(status, {"errors": [f"1 error occurred:\n\t* {message}\n\n"]}, message)
            for bad_status, body in ((200, {"errors": [message]}), (True, {"errors": [message]}),
                                     (404, {"errors": [message]}), (status, {}),
                                     (status, {"errors": ["unrelated"]}), (status, {"errors": [message, "extra"]}),
                                     (status, {"errors": [f"2 errors occurred:\n\t* {message}\n\t* unrelated\n\n"]}),
                                     (status, {"errors": [f"prefix {message}"]})):
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(subject.harness.HarnessError):
                    subject.denied(bad_status, body, message)

    def test_report_rejects_changes_and_missing_fields(self):
        inputs = subject.input_hashes()
        report = subject.report_for(inputs)
        subject.validate_report(report, inputs)
        for field in report:
            changed = dict(report)
            del changed[field]
            with self.assertRaises(subject.harness.HarnessError):
                subject.validate_report(changed, inputs)
        for field, value in (("routable", True), ("routable", 0), ("inputs", {}),
                             ("checks", report["checks"][:-1]), ("outcome", "failed"),
                             ("outcome", "passed"), ("security_checks", {}),
                             ("security_checks", {"server-replay-rejection": "passed"}),
                             ("version", "2.6.3"), ("scope", "sdk-integration"), ("tls", "TLSv1.2")):
            with self.assertRaises(subject.harness.HarnessError):
                subject.validate_report(dict(report, **{field: value}), inputs)
        with self.assertRaises(subject.harness.HarnessError):
            subject.validate_report(dict(report, unexpected="field"), inputs)

    def test_credential_controls_and_size(self):
        for value in (None, "", "a\rb", "a\nb", "a b", "\u00e9", "x" * 8193):
            with self.assertRaises(subject.harness.HarnessError):
                subject.credential(value)
        subject.credential("x" * 8192)

    def test_request_preserves_namespace_and_transport_controls(self):
        class Response:
            status = 204
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, maximum):
                self.maximum = maximum
                return b""
        response = Response()
        with patch.object(subject.fixture, "context", return_value=None), \
             patch.object(subject.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = response
            subject.request("https://127.0.0.1:1234", Path("ca"), "fixture-credential", "POST",
                            "sys/control-group/request", {"accessor": "fixture-accessor"}, "fixture-peer")
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(build.call_args.args[1], subject.harness.RejectRedirect)
        request = build.return_value.open.call_args.args[0]
        self.assertEqual(request.get_header("X-vault-namespace"), "fixture-peer")
        self.assertNotIn("fixture-accessor", request.full_url)
        self.assertEqual(response.maximum, subject.fixture.MAX_BODY + 1)
        self.assertEqual(build.return_value.open.call_args.kwargs["timeout"], 5)

    def test_cancel_sends_once_and_closes_without_receiving(self):
        probe = subject.Probe("https://127.0.0.1:1234", Path("ca"), "fixture-root")
        with patch.object(subject.fixture, "context", return_value=None), \
             patch.object(subject.http.client, "HTTPSConnection") as create:
            subject.cancelled_unwrap(probe, "fixture-requester", "fixture-wrapped")
        create.return_value.request.assert_called_once()
        create.return_value.getresponse.assert_not_called()
        create.return_value.close.assert_called_once()
        with patch.object(subject.fixture, "context", return_value=None), \
             patch.object(subject.http.client, "HTTPSConnection") as create:
            create.return_value.request.side_effect = OSError("synthetic-private-error")
            with self.assertRaises(OSError):
                subject.cancelled_unwrap(probe, "fixture-requester", "fixture-wrapped")
            create.return_value.close.assert_called_once()

    def test_response_limits_and_media_type_fail_closed(self):
        class Headers:
            def __init__(self, media): self.media = media
            def get_content_type(self): return self.media
        class Response:
            status = 200
            def __init__(self, data, media):
                self.data, self.headers, self.closed = data, Headers(media), False
            def __enter__(self): return self
            def __exit__(self, *args): self.closed = True
            def read(self, maximum): return self.data[:maximum]
        for data, media in ((b"x" * (subject.fixture.MAX_BODY + 1), "application/json"),
                            (b"{}", "text/plain"), (b"invalid", "application/json"),
                            (b'{"x":1,"x":2}', "application/json")):
            response = Response(data, media)
            with patch.object(subject.fixture, "context", return_value=None), \
                 patch.object(subject.urllib.request, "build_opener") as build:
                build.return_value.open.return_value = response
                with self.assertRaises((subject.harness.HarnessError, subject.snapshots.SnapshotError)):
                    subject.request("https://127.0.0.1:1234", Path("ca"), "", "GET", "example")
            self.assertTrue(response.closed)

    def test_main_failure_is_secret_free_and_has_no_report(self):
        output = io.StringIO()
        with patch.object(subject, "run", side_effect=subject.harness.HarnessError("synthetic-private-error")), \
             patch.object(subject.tempfile, "NamedTemporaryFile") as write, \
             patch("sys.argv", ["fixture"]), contextlib.redirect_stdout(output):
            self.assertEqual(subject.main(), 1)
        write.assert_not_called()
        self.assertNotIn("synthetic-private-error", output.getvalue())

    def test_cleanup_runs_after_failed_probe_and_blocks_success_on_failure(self):
        for failed_probe, failed_cleanup in ((True, False), (False, True), (False, False)):
            with contextlib.ExitStack() as stack:
                for name in ("verify", "verify_image_signature"):
                    stack.enter_context(patch.object(subject.staged, name))
                stack.enter_context(patch.object(subject.evidence_tools, "protected_path", side_effect=lambda path: path))
                stack.enter_context(patch.object(subject.harness, "generate_tls", return_value=(Path("tls"), Path("ca"))))
                stack.enter_context(patch.object(subject.harness, "write_server_config", return_value=Path("config")))
                stack.enter_context(patch.object(subject.harness, "inspect_image", return_value="sha256:" + "0" * 64))
                stack.enter_context(patch.object(subject.harness, "run_bounded", return_value=b"{}"))
                stack.enter_context(patch.object(subject.harness, "parse_port", return_value=1234))
                stack.enter_context(patch.object(subject.harness, "initialize_and_unseal", return_value="fixture-root"))
                stack.enter_context(patch.object(subject.snapshots, "validate_container_resource_config"))
                for name in ("verify_network", "wait_for_health", "probe_tls"):
                    stack.enter_context(patch.object(subject.fixture, name))
                remove = stack.enter_context(patch.object(subject.harness, "remove_owned_resource"))
                stack.enter_context(patch.object(subject.harness, "cleanup_private_files", return_value=True))
                if failed_cleanup:
                    remove.side_effect = subject.harness.HarnessError("cleanup failed")
                stack.enter_context(patch.object(subject, "probe", return_value=False, side_effect=subject.harness.HarnessError("probe failed") if failed_probe else None))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                if failed_probe or failed_cleanup:
                    with self.assertRaises(subject.harness.HarnessError):
                        subject.run()
                else:
                    subject.validate_report(subject.run(), subject.input_hashes())
                self.assertEqual([call.args[1] for call in remove.call_args_list], ["container", "network"])


if __name__ == "__main__":
    unittest.main()
