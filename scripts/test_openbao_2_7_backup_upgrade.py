#!/usr/bin/python3 -EsSB
"""Offline failure and scope tests for the bounded backup upgrade fixture."""

import contextlib
import base64
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import openbao_2_7_backup_upgrade as subject
import verify_openbao_2_7_backup_upgrade as retained


class BackupUpgradeTests(unittest.TestCase):
    def test_retained_digest_canonical_encoding_and_scope(self):
        retained.verify()
        data = subject.snapshots.read_regular_file(retained.RESULT, 65536)
        changed = json.loads(data)
        changed["general_upgrade_verified"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            for modified in (data + b" ", subject.snapshots.canonical_json(changed)):
                path.write_bytes(modified)
                with patch.object(retained, "RESULT", path):
                    with self.assertRaises(subject.snapshots.SnapshotError): retained.verify()
                    with patch.object(retained, "EXPECTED_SHA256", subject.snapshots.sha256(modified)):
                        with self.assertRaises((subject.snapshots.SnapshotError, subject.harness.HarnessError)):
                            retained.verify()

    def test_raft_initialization_is_single_bounded_write_without_immediate_seal_assertion(self):
        response = {"root_token": "fixture-token", "recovery_keys_base64": ["fixture-share"]}
        with patch.object(subject.raft, "request", return_value=(200, response, None, None)) as request:
            self.assertEqual(subject.initialize("address", Path("ca")), ("fixture-token", "fixture-share"))
            request.assert_called_once_with("address", Path("ca"), "", "PUT", "/v1/sys/init",
                                            {"recovery_shares": 1, "recovery_threshold": 1}, timeout=30)
        for result in ((500, {}, None, None), (200, dict(response, recovery_keys_base64=[]), None, None)):
            with patch.object(subject.raft, "request", return_value=result) as request:
                with self.assertRaises(subject.harness.HarnessError):
                    subject.initialize("address", Path("ca"))
                self.assertEqual(request.call_count, 1)
        with patch.object(subject.raft, "request", side_effect=TimeoutError) as request:
            with self.assertRaises(TimeoutError): subject.initialize("address", Path("ca"))
            self.assertEqual(request.call_count, 1)

    def test_network_failure_is_not_bypassed_by_startup_diagnostics(self):
        with contextlib.ExitStack() as stack:
            def mock(obj, name, **kwargs):
                return stack.enter_context(patch.object(obj, name, **kwargs))
            mock(subject.harness, "run_bounded", return_value=b"{}")
            mock(subject.snapshots, "validate_container_resource_config")
            mock(subject.fixture, "verify_network",
                 side_effect=subject.harness.HarnessError("synthetic-private-detail"))
            diagnostic = mock(subject.fixture, "startup_diagnostic")
            health = mock(subject.harness, "wait_for_exact_version")
            with contextlib.redirect_stdout(io.StringIO()) as messages:
                with self.assertRaises(subject.harness.HarnessError):
                    subject.start("podman", "image", "2.7.0", "container", "network", "owner",
                                  Path("config"), Path("tls"), Path("storage"), Path("ca"), {})
            diagnostic.assert_called_once_with("podman", "container", {})
            health.assert_not_called()
            self.assertNotIn("synthetic-private-detail", messages.getvalue())

    def test_startup_diagnostics_preserve_failure_and_do_not_print_exception(self):
        with contextlib.ExitStack() as stack:
            def mock(obj, name, **kwargs):
                return stack.enter_context(patch.object(obj, name, **kwargs))
            mock(subject.harness, "run_bounded", return_value=b"{}")
            mock(subject.snapshots, "validate_container_resource_config")
            mock(subject.fixture, "verify_network")
            mock(subject.harness, "parse_port", return_value=18200)
            mock(subject.harness, "wait_for_exact_version",
                 side_effect=subject.harness.HarnessError("synthetic-private-detail"))
            diagnostics = mock(subject.fixture, "startup_diagnostic")
            tls = mock(subject.fixture, "probe_tls")
            with contextlib.redirect_stdout(io.StringIO()) as messages:
                with self.assertRaises(subject.harness.HarnessError):
                    subject.start("podman", "image", "2.7.0", "container", "network", "owner",
                                  Path("config"), Path("tls"), Path("storage"), Path("ca"), {})
            diagnostics.assert_called_once_with("podman", "container", {})
            tls.assert_not_called()
            self.assertNotIn("synthetic-private-detail", messages.getvalue())
            self.assertIn("waiting for exact-version TLS health", messages.getvalue())

    def test_cluster_wait_is_bounded_and_rejects_wrong_version(self):
        sealed = {"version": "2.7.0", "initialized": True, "sealed": True}
        ready = dict(sealed, sealed=False, standby=False, cluster_id="fixture-cluster")
        with patch.object(subject.harness, "https_json", side_effect=[sealed, dict(ready, standby=True), ready]), \
                patch.object(subject.time, "sleep") as sleep:
            self.assertEqual(subject.cluster("address", Path("ca"), "2.7.0"), "fixture-cluster")
            self.assertEqual(sleep.call_count, 2)
            sleep.assert_called_with(0.25)
        with patch.object(subject.harness, "https_json", return_value=sealed) as read, \
                patch.object(subject.time, "sleep"):
            with self.assertRaises(subject.harness.HarnessError):
                subject.cluster("address", Path("ca"), "2.7.0")
            self.assertEqual(read.call_count, 120)
        with patch.object(subject.harness, "https_json", return_value=dict(ready, version="2.6.3")):
            with self.assertRaises(subject.harness.HarnessError):
                subject.cluster("address", Path("ca"), "2.7.0")

    def test_exact_source_image_and_signature_claims(self):
        release = subject.predecessor()
        self.assertEqual(release["version"], "2.6.3")
        good = {"critical": {"image": {"docker-manifest-digest": release["image"]["index_digest"]},
                             "type": "https://sigstore.dev/cosign/sign/v1"}}
        for claims in ([good], [], [dict(good, critical={})], [good] * 33, [None]):
            with patch.object(subject.snapshots, "run_bounded", return_value=(0, json.dumps(claims).encode())) as run:
                if claims == [good]:
                    subject.verify_predecessor_signature(release)
                else:
                    with self.assertRaises(subject.harness.HarnessError):
                        subject.verify_predecessor_signature(release)
                command = run.call_args.args[0]
                self.assertIn(release["image"]["certificate_identity"], command)
                self.assertNotIn("--insecure-ignore-tlog", command)

    def test_scope_and_every_input_are_bound(self):
        report = subject.report_for(subject.input_hashes())
        subject.validate_report(report)
        for field in report:
            changed = copy.deepcopy(report)
            del changed[field]
            with self.assertRaises(subject.harness.HarnessError): subject.validate_report(changed)
        for field in ("routable", "unseal_backup_upgrade_verified", "general_upgrade_verified",
                      "backup_decryption_verified"):
            for value in (True, 0):
                with self.assertRaises(subject.harness.HarnessError):
                    subject.validate_report(dict(report, **{field: value}))
        for name in report["inputs"]:
            changed = copy.deepcopy(report)
            changed["inputs"][name] = "0" * 64
            with self.assertRaises(subject.harness.HarnessError): subject.validate_report(changed)

    def test_configuration_retains_tls_and_file_seal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tls = root / "tls"
            tls.mkdir()
            with patch.object(subject.os, "chown") as chown:
                config, storage = subject.configure(root, tls)
            chown.assert_called_once_with(storage, 100, 0)
            data = config.read_text()
            self.assertIn('storage "raft"', data)
            self.assertIn('node_id = "fixture-upgrade"', data)
            self.assertNotIn('storage "file"', data)
            self.assertNotIn('storage "inmem"', data)
            self.assertIn('tls_min_version = "tls13"', data)
            self.assertIn('file:///openbao/tls/fixture-seal.key', data)
            self.assertEqual(storage.stat().st_mode & 0o777, 0o700)

    def test_creation_does_not_read_or_migrate_source_backup(self):
        responses = [{"data": {"started": True, "backup": True, "nonce": "fixture-nonce"}},
                     {"data": {"complete": True, "backup": True, "pgp_fingerprints": ["a" * 40],
                               "keys": ["abcd"]}}]
        with patch.object(subject, "call", side_effect=responses) as call:
            self.assertEqual(subject.create_backup("address", Path("ca"), "fixture-token", "fixture-share"),
                             ("fixture-nonce", "a" * 40, "abcd"))
        self.assertEqual([c.args[3:5] for c in call.call_args_list],
                         [("POST", "sys/rotate/recovery/init"), ("POST", "sys/rotate/recovery/update")])
        for field, value in (("complete", False), ("backup", False), ("keys", []),
                             ("pgp_fingerprints", ["invalid"])):
            bad = copy.deepcopy(responses)
            bad[1]["data"][field] = value
            with patch.object(subject, "call", side_effect=bad):
                with self.assertRaises(subject.harness.HarnessError):
                    subject.create_backup("address", Path("ca"), "fixture-token", "fixture-share")

    def test_failed_initial_raw_read_does_not_call_migrating_handler(self):
        with patch.object(subject, "call", return_value={"data": {"value": "{}"}}) as call:
            with self.assertRaises(subject.harness.HarnessError):
                subject.verify_backup("address", Path("ca"), "fixture-token", ("n", "f", "ab"))
            call.assert_called_once_with("address", Path("ca"), "fixture-token", "GET",
                                         subject.recovery.RAW + "?encoding=base64")

    def test_target_checks_reject_corruption_and_access_control_failures(self):
        expected = ("fixture-nonce", "a" * 40, "abcd")
        raw = b"\x00\xff\x81fixture-barrier-ciphertext"
        for defect in (None, "backup", "encoding", "changed-storage", "dedicated", "policy", "acl", "protected", "delete"):
            deleted = False
            raw_reads = 0
            def request(address, ca, token, method, path, payload=None):
                nonlocal deleted, raw_reads
                if token == "fixture-restricted":
                    return (200, {}) if defect == "acl" else (403, {"errors": ["permission denied"]})
                if path == subject.recovery.RAW:
                    if deleted and defect != "delete": return 404, {}
                    return 200, {"data": {"value": "fixture-binary-rendering"}}
                if path.endswith("?encoding=base64"):
                    raw_reads += 1
                    value = b"" if defect == "backup" else raw
                    if defect == "changed-storage" and raw_reads == 2: value += b"changed"
                    return 200, {"data": {"value": "invalid%" if defect == "encoding"
                                         else base64.b64encode(value).decode()}}
                if path == "sys/rotate/recovery/backup":
                    if method == "DELETE":
                        deleted = True
                        return 204, {}
                    return 200, {"data": {"nonce": expected[0], "keys": {} if defect == "dedicated"
                                         else {expected[1]: [expected[2]]}}}
                if path.startswith("sys/policies/acl/"): return 204, {}
                if path == "auth/token/create":
                    return 200, {"auth": {"client_token": "fixture-restricted",
                                          "policies": ["root"] if defect == "policy" else ["fixture-upgrade-deny"]}}
                if defect == "protected": return 200, {}
                return 400, {"errors": [f'cannot access "{path.removeprefix("sys/raw/")}"']}
            with patch.object(subject.system, "request", side_effect=request):
                if defect:
                    with self.assertRaises(subject.harness.HarnessError):
                        subject.verify_backup("address", Path("ca"), "fixture-token", expected)
                else:
                    subject.verify_backup("address", Path("ca"), "fixture-token", expected)
                    self.assertTrue(deleted)

    def test_lifecycle_failures_never_emit_success(self):
        for failure in (None, "network", "old-start", "create", "stop", "new-start",
                        "foreign-cluster", "verify", "seal-cleanup", "resource-cleanup"):
            removed = []
            with contextlib.ExitStack() as stack:
                def mock(obj, name, **kwargs):
                    return stack.enter_context(patch.object(obj, name, **kwargs))
                mock(subject.os, "geteuid", return_value=0)
                mock(subject.staged, "verify")
                mock(subject.staged, "verify_image_signature")
                mock(subject, "verify_predecessor_signature")
                mock(subject.recovery.transport.evidence_tools, "protected_path", side_effect=lambda p: p)
                mock(subject.harness, "generate_tls", side_effect=lambda r, *a: (r / "tls", r / "ca"))
                mock(subject, "configure", side_effect=lambda r, t: (r / "config", r / "storage"))
                mock(subject.harness, "inspect_image", return_value="image")
                def command(cmd, **kwargs):
                    if (failure == "network" and "create" in cmd or failure == "stop" and "stop" in cmd):
                        raise subject.harness.HarnessError("private-detail")
                    return b""
                mock(subject.harness, "run_bounded", side_effect=command)
                def start(*args):
                    if failure == ("old-start" if args[2] == "2.6.3" else "new-start"):
                        raise subject.harness.HarnessError("private-detail")
                    return "address"
                mock(subject, "start", side_effect=start)
                mock(subject, "initialize", return_value=("fixture-token", "fixture-share"))
                mock(subject, "cluster", side_effect=["same", "other" if failure == "foreign-cluster" else "same"])
                mock(subject, "create_backup", side_effect=subject.harness.HarnessError("private-detail")
                     if failure == "create" else None, return_value=("n", "f", "ab"))
                mock(subject, "verify_backup", side_effect=subject.harness.HarnessError("private-detail")
                     if failure == "verify" else None)
                def remove(p, kind, *args):
                    removed.append(kind)
                    if failure == "resource-cleanup": raise subject.harness.HarnessError("private-detail")
                mock(subject.harness, "remove_owned_resource", side_effect=remove)
                sanitize = mock(subject.harness, "sanitize_file", return_value=failure != "seal-cleanup")
                mock(subject.harness, "cleanup_private_files", return_value=True)
                if failure is None:
                    with contextlib.redirect_stdout(io.StringIO()): subject.validate_report(subject.run())
                else:
                    output = mock(subject.tempfile, "NamedTemporaryFile")
                    stack.enter_context(patch("sys.argv", ["fixture"]))
                    with contextlib.redirect_stdout(io.StringIO()) as messages:
                        self.assertEqual(subject.main(), 1)
                    output.assert_not_called()
                    self.assertNotIn("private-detail", messages.getvalue())
                sanitize.assert_called_once()
            self.assertEqual(removed[-1], "network")


if __name__ == "__main__":
    unittest.main()
