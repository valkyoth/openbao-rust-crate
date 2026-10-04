#!/usr/bin/python3 -EsSB
"""Trust boundaries for real KDC fixtures and the signed offline build."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import openbao_kerberos_plugins as fixture
import openbao_kerberos_image as image


class KerberosTests(unittest.TestCase):
    def test_cosign_array_is_required_and_digest_claims_are_exact(self):
        good = {"critical": {"image": {"docker-manifest-digest": image.INDEX}}}
        image.verify_signature_claims(json.dumps([good]).encode())
        for value in (good, [], [None], [{"critical": {"image": {"docker-manifest-digest": "wrong"}}}],
                      [good] * 17):
            with self.assertRaises(fixture.harness.HarnessError):
                image.verify_signature_claims(json.dumps(value).encode())
        with self.assertRaises(fixture.base.SnapshotError):
            image.verify_signature_claims(b'[{"critical":{},"critical":{}}]')

    def test_pinned_package_inventory_is_bounded_and_unique(self):
        rows = image.package_lock()
        self.assertEqual(len(rows), 31)
        self.assertIn("krb5-server-1.22.2-r4.apk", [row["file"] for row in rows])
        self.assertEqual(fixture.input_hashes()[image.APK_INDEX], image.APK_INDEX_SHA256)

    def test_changed_package_lock_fails_before_parsing_or_download(self):
        with patch.object(image.base, "read_regular_file", return_value=b"{}"):
            with self.assertRaises(fixture.harness.HarnessError):
                image.package_lock()

    def test_changed_signed_index_fails_input_capture(self):
        read = fixture.base.read_regular_file
        with patch.object(fixture.base, "read_regular_file", side_effect=lambda path, maximum:
                          b"changed" if str(path).endswith("APKINDEX.tar.gz") else read(path, maximum)):
            with self.assertRaises(fixture.harness.HarnessError):
                fixture.input_hashes()

    def test_download_rejects_wrong_size_digest_and_redirect(self):
        row = {"file": "test.apk", "size": 3, "sha256": image.base.sha256(b"apk")}
        for data in (b"ap", b"apkk", b"bad"):
            response = Mock()
            response.status = 200
            response.read.return_value = data
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            opener = Mock()
            opener.open.return_value = response
            with patch.object(image.urllib.request, "build_opener", return_value=opener):
                with self.assertRaises(fixture.harness.HarnessError):
                    image.fetch_package(row)
                response.read.assert_called_once_with(4)
        with self.assertRaises(fixture.harness.HarnessError):
            image.NoRedirect().redirect_request(None, None, 302, "", {}, "http://untrusted.invalid")

    def test_offline_build_keeps_signature_validation_and_pinned_base(self):
        value = image.containerfile().decode()
        self.assertIn("FROM " + image.REFERENCE, value)
        self.assertIn("--no-network", value)
        self.assertIn("--repository /fixture-packages", value)
        self.assertIn("source=repository,target=/fixture-packages,ro", value)
        self.assertNotIn("--allow-untrusted", value)
        self.assertNotIn("curl", value)

    def test_kdc_has_no_host_network_or_published_ports(self):
        args = fixture.kdc_command("podman", "image", "name", "owned-server", "owner", Path("/private"))
        self.assertEqual(args[args.index("--network") + 1], "container:owned-server")
        self.assertEqual(args[args.index("--user") + 1], "65532:0")
        for option in ("--read-only", "--cap-drop", "ALL", "no-new-privileges", "--memory", "--pids-limit"):
            self.assertIn(option, args)
        self.assertNotIn("--publish", args)
        self.assertNotIn("--privileged", args)
        self.assertIn("/data:rw,noexec,nosuid,nodev,size=64m,mode=0770", args)

    def test_configuration_disables_dns_and_limits_enctypes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = fixture.configuration(Path(temp))
            client = (root / "krb5.conf").read_text()
            server = (root / "kdc.conf").read_text()
            for value in ("dns_lookup_kdc = false", "dns_lookup_realm = false", "rdns = false",
                          "kdc = 127.0.0.1:1188", "aes256-cts-hmac-sha1-96"):
                self.assertIn(value, client)
            self.assertIn("kdc_tcp_listen = 127.0.0.1:1188", server)
            self.assertNotIn("rc4", client + server)
            self.assertNotIn("des3", client + server)
            self.assertEqual((root / "kdc.py").stat().st_mode & 0o777, 0o640)

    def test_ticket_bounds_and_canonical_base64(self):
        self.assertEqual(fixture.encoded_secret(b"YWJj", 4), "YWJj")
        for value in (b"", b"YQ==\n", b"YQ==extra", b"YR==", b"YWJjYQ==", b"secret"):
            with self.subTest(value=value), self.assertRaises((fixture.harness.HarnessError, ValueError)):
                fixture.encoded_secret(value, 4)

    def test_auth_requires_exact_identity_and_policies(self):
        auth = {"client_token": "disposable", "policies": ["base", "group"],
                "metadata": {"user": "alice", "domain": fixture.REALM}}
        fixture.check_auth(auth, "alice", ["group", "base"])
        for value in ({**auth, "policies": ["base", "root"]}, {**auth, "client_token": ""},
                      {**auth, "metadata": {"user": "static", "domain": fixture.REALM}},
                      {**auth, "metadata": {"user": "alice", "domain": "OTHER.INVALID"}}):
            with self.assertRaises(fixture.harness.HarnessError):
                fixture.check_auth(value, "alice", ["base", "group"])

    def test_rejected_login_body_is_never_read(self):
        response = Mock()
        response.status = 401
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        with patch.object(fixture.ldap.tls, "context", return_value=None), \
             patch.object(fixture.urllib.request, "build_opener", return_value=opener):
            self.assertIsNone(fixture.login("https://127.0.0.1:8200", Path("ca"), "ZmFrZQ==", expected=401))
        response.read.assert_not_called()

    def test_extra_plugin_hook_rejects_ambiguous_or_unreviewed_inputs(self):
        with patch.object(fixture.ldap.os, "geteuid", return_value=0):
            for plugins, extra, sdk in ((("unknown",), Mock(), None), (("auth-kerberos",), None, None),
                                        ((), Mock(), None), (("auth-kerberos",), Mock(), Mock())):
                with self.assertRaises(fixture.harness.HarnessError):
                    fixture.ldap.run("2.7.0", True, extra_plugins=plugins, extra_exercise=extra, sdk_exercise=sdk)

    def test_plugin_installer_rejects_duplicates_before_tools_or_network(self):
        with self.assertRaises(fixture.harness.HarnessError):
            fixture.ldap.install_plugins(Path("/unused"), ("auth-kerberos", "auth-kerberos"))


if __name__ == "__main__":
    unittest.main()
