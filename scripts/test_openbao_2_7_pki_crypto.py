#!/usr/bin/python3 -EsSB
"""Real local crypto and fail-closed tests; no OpenBao compatibility claim."""

from pathlib import Path
import tempfile
import contextlib
import io
import unittest
from unittest.mock import patch

import openbao_2_7_pki_crypto as subject


class CryptoTests(unittest.TestCase):
    def test_command_failure_diagnostics_do_not_expose_arguments_or_error(self):
        for arguments, expected in ((('verify', 'synthetic-private-argument'), 'verify'),
                                    (('synthetic-private-operation',), 'unknown')):
            output = io.StringIO()
            with patch.object(subject.harness, "run_bounded", side_effect=subject.harness.HarnessError("synthetic-private-error")), \
                 contextlib.redirect_stdout(output), self.assertRaises(subject.harness.HarnessError):
                self.crypto.command(*arguments)
            self.assertEqual(output.getvalue(), f"PKI fixture: OpenSSL operation failed ({expected})\n")

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.crypto = subject.Crypto(root, "/usr/bin/openssl", {
            "PATH": "/usr/bin:/bin", "HOME": str(root), "LANG": "C.UTF-8"})
        self.addCleanup(self.crypto.cleanup)

    def generate(self, algorithm, pss=False):
        key = self.crypto.command("genpkey", "-algorithm", algorithm)
        keyfile = self.crypto.store(key)
        options = ["-sigopt", "rsa_padding_mode:pss"] if pss else []
        csr = self.crypto.command("req", "-new", "-key", keyfile, "-subj", "/CN=fixture.test", *options)
        cert = self.crypto.command("req", "-new", "-x509", "-key", keyfile,
                                   "-subj", "/CN=fixture.test", "-days", "1", *options)
        return key.decode("ascii"), csr.decode("ascii"), cert.decode("ascii")

    def test_real_mldsa_all_parameters_and_wrong_keys(self):
        for parameter in (44, 65, 87):
            algorithm = f"ML-DSA-{parameter}"
            with self.subTest(parameter=parameter):
                key, csr, cert = self.generate(algorithm)
                self.crypto.certificate(cert, cert, algorithm)
                self.crypto.csr(csr, algorithm)
                self.crypto.key_matches(key, cert)
                self.crypto.key_matches(key, csr, "req")
                other, _, other_cert = self.generate(algorithm)
                with self.assertRaises(subject.harness.HarnessError):
                    self.crypto.key_matches(other, cert)
                with self.assertRaises(subject.harness.HarnessError):
                    self.crypto.certificate(cert, other_cert, algorithm)
                for value, kind in ((cert, "CERTIFICATE"), (csr, "CERTIFICATE REQUEST")):
                    der = bytearray(subject.transit.pem_der(value, kind))
                    der[-1] ^= 1
                    changed = f"-----BEGIN {kind}-----\n{subject.transit.b64(der)}\n-----END {kind}-----\n"
                    with self.assertRaises(subject.harness.HarnessError):
                        if kind == "CERTIFICATE":
                            self.crypto.certificate(changed, cert, algorithm)
                        else:
                            self.crypto.csr(changed, algorithm)

    def test_real_rsa_pss_and_pkcs1_are_distinguished(self):
        for pss, signature in ((False, "sha256WithRSAEncryption"), (True, "rsassaPss")):
            key, csr, cert = self.generate("RSA", pss)
            self.crypto.certificate(cert, cert, signature)
            self.crypto.csr(csr, signature)
            self.crypto.key_matches(key, cert)
            with self.assertRaises(subject.harness.HarnessError):
                self.crypto.certificate(cert, cert, "wrong-algorithm")

    def test_bounds_permissions_and_cleanup(self):
        for value in (None, 1, b"", b"x" * (subject.LIMIT + 1)):
            with self.assertRaises(subject.harness.HarnessError):
                self.crypto.store(value)
        path = Path(self.crypto.store(b"synthetic"))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.crypto.cleanup()
        self.assertEqual(path.read_bytes(), b"\0" * len(b"synthetic"))

    def test_cleanup_attempts_every_file_and_propagates_failure(self):
        self.crypto.store(b"one")
        self.crypto.store(b"two")
        with patch.object(subject.harness, "sanitize_file", side_effect=[False, True]) as wipe:
            with self.assertRaises(subject.harness.HarnessError):
                self.crypto.cleanup()
            self.assertEqual(wipe.call_count, 2)

    def test_commands_are_bounded_no_shell_or_ambient_trust(self):
        with patch.object(subject.harness, "run_bounded", return_value=b"result") as run:
            self.assertEqual(self.crypto.command("version"), b"result")
            self.assertEqual(run.call_args.args[0], ["/usr/bin/openssl", "version"])
            self.assertEqual(run.call_args.kwargs["maximum"], subject.LIMIT)
            self.assertEqual(run.call_args.kwargs["timeout"], 30)
            self.assertNotIn("OPENSSL_CONF", run.call_args.kwargs["environment"])


if __name__ == "__main__":
    unittest.main()
