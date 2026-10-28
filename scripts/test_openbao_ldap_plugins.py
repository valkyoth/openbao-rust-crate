#!/usr/bin/python3 -EsSB
"""Offline directory-image and LDAP fixture trust-boundary regressions."""

import copy
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

import openbao_ldap_directory_image as image
import openbao_ldap_plugins as fixture

ROOT = fixture.ROOT


class DirectoryImageTests(unittest.TestCase):
    def setUp(self):
        root = ROOT / "compat/plugins/ldap-directory"
        self.documents = [(root / name).read_bytes() for name in
                          ("index.json", "manifest.json", "config.json")]
        self.documents = [value.rstrip(b"\n") for value in self.documents]

    def test_retained_observation_is_pinned_and_not_signature_assurance(self):
        result = image.validate(*self.documents)
        self.assertEqual(result["publisher_signature"], "not-available")
        self.assertEqual(result["image"], image.REFERENCE)

    def test_mutations_fail_closed(self):
        for index in range(3):
            documents = list(self.documents)
            documents[index] += b" "
            with self.subTest(index=index), self.assertRaises(fixture.harness.HarnessError):
                image.validate(*documents)

    def test_unsigned_acknowledgement_required_before_any_tool_execution(self):
        for value in (False, None, 1, "true"):
            with patch.object(image.harness, "run_bounded") as run:
                with self.subTest(value=value), self.assertRaises(fixture.harness.HarnessError):
                    image.verify({}, value)
                run.assert_not_called()

    def test_live_metadata_uses_anonymous_raw_digest_requests(self):
        with patch.object(image.tls.evidence_tools, "protected_path", side_effect=lambda p: p), \
                patch.object(image.harness, "run_bounded", side_effect=self.documents) as run:
            result = image.verify({"PATH": "/usr/bin:/bin"}, True)
            self.assertEqual(result["image"], image.REFERENCE)
            for args, _ in run.call_args_list:
                self.assertIn("--no-creds", args[0])
                self.assertIn("--raw", args[0])
                self.assertNotIn("--tls-verify=false", args[0])
                self.assertNotIn(":latest", repr(args[0]))
            self.assertIn("--config", run.call_args_list[-1].args[0])

    def test_structural_identity_checks_are_independent(self):
        documents = [json.loads(value) for value in self.documents]
        changes = ((0, lambda d: d["manifests"].append(copy.deepcopy(d["manifests"][0]))),
                   (1, lambda d: d["config"].update(digest="sha256:" + "0" * 64)),
                   (2, lambda d: d.update(architecture="arm64")),
                   (2, lambda d: d["config"].update(User="root")),
                   (2, lambda d: d["config"]["Labels"].update({"org.opencontainers.image.revision": "other"})))
        for index, change in changes:
            changed = copy.deepcopy(documents)
            change(changed[index])
            with self.subTest(index=index), patch.object(image, "pinned", side_effect=changed):
                with self.assertRaises(fixture.harness.HarnessError):
                    image.validate(b"", b"", b"")


class DirectoryFixtureTests(unittest.TestCase):
    def exercise_startup(self, code, *, timeout=5, maximum=16384, failure=False, setup_failure=False):
        processes = []
        original = fixture.subprocess.Popen

        def spawn(*args, **kwargs):
            process = original(*args, **kwargs)
            processes.append(process)
            return process

        with patch.object(fixture.subprocess, "Popen", side_effect=spawn):
            if setup_failure:
                with patch.object(fixture.os, "set_blocking", side_effect=OSError("setup failure")):
                    with self.assertRaises(OSError):
                        fixture.start_container([sys.executable, "-E", "-s", "-S", "-c", code], {}, timeout=timeout)
            elif failure:
                with self.assertRaises(fixture.harness.HarnessError):
                    fixture.start_container([sys.executable, "-E", "-s", "-S", "-c", code], {},
                                            timeout=timeout, maximum=maximum)
            else:
                fixture.start_container([sys.executable, "-E", "-s", "-S", "-c", code], {}, timeout=timeout)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())
        self.assertTrue(processes[0].stdout.closed)

    def test_startup_success_and_nonzero_exit_reaps_and_closes(self):
        self.exercise_startup("print('a' * 64)")
        self.exercise_startup("import sys; sys.stderr.write('runtime warning\\n'); sys.stderr.flush(); print('a' * 64)")
        with redirect_stderr(io.StringIO()):
            self.exercise_startup("import sys; print('a' * 64); sys.exit(125)", failure=True)

    def test_startup_timeout_overflow_and_setup_failure_reap_and_close(self):
        self.exercise_startup("import time; time.sleep(30)", timeout=0.05, failure=True)
        self.exercise_startup("print('x' * 4096)", maximum=8, failure=True)
        self.exercise_startup("import time; time.sleep(30)", setup_failure=True)

    def test_startup_diagnostics_do_not_reflect_child_output(self):
        captured = io.StringIO()
        with redirect_stderr(captured):
            self.exercise_startup("import sys; sys.stderr.write('permission denied: sentinel-sensitive-value'); sys.exit(125)", failure=True)
        self.assertEqual(captured.getvalue(), "LDAP plugin fixture: startup diagnostic=permission\n")

    def test_command_has_no_privileged_host_network_or_secret_arguments(self):
        command = fixture.directory_command("/usr/bin/podman", image.REFERENCE, "ldap", "owned-server",
                                            "a" * 32, Path("/tmp/private/config"), Path("/tmp/private/tls"))
        self.assertEqual(command[command.index("--network") + 1], "container:owned-server")
        self.assertEqual(command[command.index("--user") + 1], "65532:0")
        self.assertEqual(command[command.index("--cap-drop") + 1], "ALL")
        for flag in ("--read-only", "--no-healthcheck", "--log-driver", "--memory", "--cpus", "--pids-limit"):
            self.assertIn(flag, command)
        for flag in ("--privileged", "--password", "--env", "--publish"):
            self.assertNotIn(flag, command)
        tmpfs = command[command.index("--tmpfs") + 1]
        self.assertIn("mode=0770", tmpfs)
        self.assertNotIn("uid=", tmpfs)
        self.assertNotIn("gid=", tmpfs)
        self.assertIn('umask 077; mkdir /data/db && exec /usr/lib/openldap/slapd "$@"', command)
        # Loopback-only host publication forwards to the container interface,
        # not its loopback address. The isolated directory must listen there.
        self.assertEqual(command[-3:], ["ldaps://0.0.0.0:1636", "-d", "0"])

    def test_configuration_and_seed_are_disposable_not_world_readable(self):
        with tempfile.TemporaryDirectory() as root:
            path = fixture.directory_config(Path(root), "f" * 48)
            value = path.read_text()
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertIn("maxsize 67108864", value)
            self.assertIn("threads 4", value)
            self.assertIn("directory /data/db", value)
            self.assertIn("TLSProtocolMin 3.3", value)
            self.assertIn("by anonymous auth by * none", value)
            self.assertNotIn("ldap://", value)
        for password in ("", "x" * 48, "f" * 49, "f" * 47 + "\n"):
            with self.assertRaises(fixture.harness.HarnessError):
                fixture.directory_config(Path("/unused"), password)

    def test_ldif_seed_uses_separate_bootstrap_and_mutable_manager(self):
        value = fixture.seed({name: "a" * 48 for name in ("manager", "alice", "static")})
        self.assertIn(fixture.MANAGER.encode(), value)
        self.assertNotIn(fixture.ROOT_DN.encode(), value)
        self.assertEqual(value.count(b"userPassword:"), 3)

    def test_inspection_enforces_runtime_isolation(self):
        good = {"State": {"Running": True}, "Config": {
                    "Labels": {fixture.harness.OWNER_LABEL: "owner"}, "User": "65532:0"},
                "ImageName": image.REFERENCE, "BoundingCaps": [],
                "HostConfig": {"Memory": 1024 ** 3, "MemorySwap": 2 * 1024 ** 3,
                               "NanoCpus": 1000000000, "PidsLimit": 256,
                               "ReadonlyRootfs": True, "SecurityOpt": ["no-new-privileges"]}}
        fixture.verify_container(good, "owner", image.REFERENCE, "65532:0")
        for mutate in (lambda d: d["State"].update(Running=False),
                       lambda d: d["Config"].update(User="0"),
                       lambda d: d["Config"]["Labels"].clear(),
                       lambda d: d.update(BoundingCaps=["CAP_SYS_ADMIN"]),
                       lambda d: d["HostConfig"].update(Memory=0),
                       lambda d: d["HostConfig"].update(ReadonlyRootfs=False),
                       lambda d: d["HostConfig"].update(SecurityOpt=[]),
                       lambda d: d.update(ImageName="floating:latest")):
            changed = copy.deepcopy(good)
            mutate(changed)
            with self.assertRaises((fixture.harness.HarnessError, fixture.base.SnapshotError)):
                fixture.verify_container(changed, "owner", image.REFERENCE, "65532:0")
        for caps in (None, []):
            good["BoundingCaps"] = caps
            fixture.verify_container(good, "owner", image.REFERENCE, "65532:0")
        del good["BoundingCaps"]
        with self.assertRaises(fixture.harness.HarnessError):
            fixture.verify_container(good, "owner", image.REFERENCE, "65532:0")

    def test_process_status_requires_all_capability_sets_empty_and_no_new_privileges(self):
        good = (b"Name:\tslapd\nUid:\t65532\t65532\t65532\t65532\n"
                b"CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n"
                b"CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n"
                b"CapAmb:\t0000000000000000\nNoNewPrivs:\t1\n")
        fixture.verify_process_status(good, "65532:0")
        for key in (b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb"):
            for bad in (good.replace(key + b":\t0000000000000000", key + b":\t0000000000000001"),
                        good.replace(key + b":\t0000000000000000\n", b""),
                        good + key + b":\t0000000000000000\n"):
                with self.assertRaises(fixture.harness.HarnessError):
                    fixture.verify_process_status(bad, "65532:0")
        for bad in (good.replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\t0"),
                    good.replace(b"65532", b"0", 1), b"", good * 256):
            with self.assertRaises(fixture.harness.HarnessError):
                fixture.verify_process_status(bad, "65532:0")

    def test_password_is_fd_only_and_cleaned_on_subprocess_failure(self):
        with patch.object(fixture.tls.evidence_tools, "protected_path", side_effect=lambda p: p), \
                patch.object(fixture.harness, "create_secret_fd", return_value=99), \
                patch.object(fixture.harness, "sanitize_secret_fd", return_value=True) as sanitize, \
                patch.object(fixture.subprocess, "run", side_effect=OSError("failed")) as run:
            with self.assertRaises(OSError):
                fixture.ldap_call(Path("/private"), 1234, Path("/private/ca"), fixture.MANAGER, "test-password")
            args, kwargs = run.call_args
            self.assertNotIn("test-password", repr(args))
            self.assertNotIn("test-password", repr(kwargs))
            self.assertEqual(kwargs["pass_fds"], (99,))
            self.assertEqual(kwargs["env"]["LDAPTLS_REQCERT"], "demand")
            sanitize.assert_called_once_with(99)

    def test_failed_password_cleanup_cannot_be_reported_as_success(self):
        with patch.object(fixture.tls.evidence_tools, "protected_path", side_effect=lambda p: p), \
                patch.object(fixture.harness, "create_secret_fd", return_value=99), \
                patch.object(fixture.harness, "sanitize_secret_fd", return_value=False), \
                patch.object(fixture.subprocess, "run") as run:
            run.return_value.returncode = 0
            with self.assertRaises(fixture.harness.HarnessError):
                fixture.ldap_call(Path("/private"), 1234, Path("/private/ca"), fixture.MANAGER, "test-password")

    def test_directory_seeding_explicitly_adds_with_resolved_modify_executable(self):
        with patch.object(fixture.tls.evidence_tools, "protected_path", return_value=Path("/usr/bin/ldapmodify")) as tool, \
                patch.object(fixture.harness, "create_secret_fd", return_value=99), \
                patch.object(fixture.harness, "sanitize_secret_fd", return_value=True), \
                patch.object(fixture.subprocess, "run") as run:
            run.return_value.returncode = 0
            fixture.ldap_call(Path("/private"), 1234, Path("/private/ca"), fixture.ROOT_DN,
                              "test-password", ldif=b"disposable-ldif")
            tool.assert_called_once_with(Path("/usr/bin/ldapmodify"))
            command = run.call_args.args[0]
            self.assertEqual(command[0], "/usr/bin/ldapmodify")
            self.assertIn("-a", command)
            self.assertEqual(run.call_args.kwargs["input"], b"disposable-ldif")
            self.assertNotIn("test-password", repr(command))

    def test_tls_connectivity_failure_is_not_certificate_rejection(self):
        with patch.object(fixture.socket, "create_connection", side_effect=ConnectionRefusedError):
            with self.assertRaises(ConnectionRefusedError):
                fixture.probe_directory_tls(1234, Path("/private/ca"))

    def test_directory_preparation_checks_bootstrap_rejection_tls_seed_and_all_users(self):
        passwords = {key: "test-value" for key in ("bootstrap", "manager", "alice", "static")}
        with patch.object(fixture, "ldap_call") as call, \
                patch.object(fixture, "probe_directory_tls") as tls_probe, redirect_stderr(io.StringIO()):
            fixture.prepare_directory(Path("/private"), 1234, Path("/private/ca"), passwords)
            self.assertEqual(call.call_count, 6)
            self.assertEqual(call.call_args_list[0].args[3], fixture.ROOT_DN)
            self.assertEqual(call.call_args_list[1].kwargs, {"expected": 49})
            self.assertEqual(call.call_args_list[2].kwargs["ldif"], fixture.seed(passwords))
            self.assertEqual([args.args[3] for args in call.call_args_list[3:]],
                             ["cn=" + user + "," + fixture.PEOPLE for user in ("manager", "alice", "static")])
            tls_probe.assert_called_once_with(1234, Path("/private/ca"))

    def test_bind_readiness_timeout_preserves_safe_failure_and_does_not_seed(self):
        with patch.object(fixture, "ldap_call", side_effect=fixture.LdapCommandFailure(255)) as call, \
                patch.object(fixture.time, "monotonic", side_effect=(0, 31)), \
                patch.object(fixture, "probe_directory_tls") as tls_probe, redirect_stderr(io.StringIO()):
            with self.assertRaises(fixture.LdapCommandFailure) as error:
                fixture.prepare_directory(Path("/private"), 1234, Path("/private/ca"), {"bootstrap": "test-value"})
            self.assertEqual(error.exception.diagnostic, "transport-error")
            self.assertEqual(call.call_count, 1)
            tls_probe.assert_not_called()

    def test_mount_identity_mismatch_fails_closed(self):
        digests = {name: "a" * 64 for name in fixture.PLUGINS}
        for actual in ({"running_sha256": "b" * 64, "running_plugin_version": "v0.2.0"},
                       {"running_sha256": "a" * 64, "running_plugin_version": "v9.9.9"}, {}):
            with patch.object(fixture, "api", side_effect=[{}, {}, {
                    "data": {fixture.AUTH_MOUNT + "/": actual}}]):
                with self.assertRaises(fixture.harness.HarnessError):
                    fixture.register("https://127.0.0.1", Path("/ca"), "test-token", digests)

    def test_mounts_require_versioned_catalog_and_verified_running_identity(self):
        digests = {name: "a" * 64 for name in fixture.PLUGINS}
        replies = []
        versions = ("v0.2.0", "v0.1.1")
        for mount, version in zip((fixture.AUTH_MOUNT, fixture.SECRET_MOUNT), versions):
            replies.extend([{}, {}, {"data": {mount + "/": {
                "running_sha256": "a" * 64, "running_plugin_version": version}}}])
        with patch.object(fixture, "api", side_effect=replies) as api:
            fixture.register("https://127.0.0.1", Path("/ca"), "test-token", digests)
            for index, version in zip((0, 3), versions):
                self.assertEqual(api.call_args_list[index].args[-1]["version"], version)
                self.assertEqual(api.call_args_list[index + 1].args[-1]["config"]["plugin_version"], version)

    def test_http_success_cannot_satisfy_a_denial_check(self):
        with patch.object(fixture.tls, "request", return_value=(200, {})):
            with self.assertRaises(fixture.harness.HarnessError):
                fixture.api("https://127.0.0.1", Path("/ca"), "test-token", "GET", "denied", expected=403)

    def test_invalid_directory_data_rejected_before_process(self):
        for dn, password in ((fixture.MANAGER, ""), (fixture.MANAGER, "x" * 513),
                             (fixture.MANAGER, "secret\n"), ("bad\x00", "secret")):
            with patch.object(fixture.subprocess, "run") as run:
                with self.assertRaises(fixture.harness.HarnessError):
                    fixture.ldap_call(Path("/private"), 1234, Path("/private/ca"), dn, password)
                run.assert_not_called()

    def test_fixture_error_does_not_echo_secret(self):
        with self.assertRaises(fixture.harness.HarnessError) as caught:
            fixture.require(False)
        self.assertEqual(str(caught.exception), "LDAP plugin fixture validation failed")

    def test_evidence_inputs_include_execution_and_artifact_boundaries(self):
        inputs = fixture.input_hashes()
        for name in ("scripts/openbao_ldap_plugins.py", "scripts/openbao_ldap_directory_image.py",
                     "scripts/evidence_tools.py", "compat/plugins/artifacts.lock.json"):
            self.assertIn(name, inputs)
        self.assertEqual(set(fixture.PLUGINS), {"auth-ldap", "secrets-ldap"})


if __name__ == "__main__":
    unittest.main()
