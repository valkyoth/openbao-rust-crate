#!/usr/bin/python3 -EsSB
"""Bounded OpenSSL verification for the staged PKI fixture, not SDK code."""

import os
from pathlib import Path
import tempfile

import openbao_2_7_transit as transit

harness = transit.harness
LIMIT = 128 * 1024


def require(condition):
    if not condition:
        raise harness.HarnessError("PKI cryptographic contract failed")


class Crypto:
    """Private scratch files; diagnostics never contain certificate/key text."""

    def __init__(self, root, openssl, environment):
        self.root = Path(root)
        self.openssl = openssl
        self.environment = environment
        self.files = []

    def store(self, value):
        require(isinstance(value, (str, bytes)))
        data = value.encode("ascii") if isinstance(value, str) else value
        require(0 < len(data) <= LIMIT)
        with tempfile.NamedTemporaryFile(dir=self.root, prefix="pki-", delete=False) as output:
            path = Path(output.name)
            self.files.append(path)
            os.fchmod(output.fileno(), 0o600)
            output.write(data)
        return str(path)

    def command(self, *arguments):
        try:
            return harness.run_bounded([self.openssl, *arguments], maximum=LIMIT,
                                       timeout=30, environment=self.environment)
        except harness.HarnessError:
            # Only allowlisted operation names, never arguments, paths or stderr.
            operation = arguments[0] if arguments and arguments[0] in (
                "verify", "x509", "req", "pkey", "ocsp", "genpkey", "version") else "unknown"
            print(f"PKI fixture: OpenSSL operation failed ({operation})", flush=True)
            raise

    def certificate(self, pem, issuer, signature):
        transit.pem_der(pem, "CERTIFICATE")
        transit.pem_der(issuer, "CERTIFICATE")
        cert, ca = self.store(pem), self.store(issuer)
        # Disable ambient trust. -check_ss_sig also verifies a root's signature.
        self.command("verify", "-no-CAfile", "-no-CApath", "-no-CAstore",
                     "-trusted", ca, "-check_ss_sig", cert)
        text = self.command("x509", "-in", cert, "-noout", "-text").decode("ascii")
        algorithms = [line.strip().removeprefix("Signature Algorithm: ")
                      for line in text.splitlines() if line.strip().startswith("Signature Algorithm: ")]
        require(algorithms == [signature, signature])
        return text

    def csr(self, pem, signature):
        transit.pem_der(pem, "CERTIFICATE REQUEST")
        path = self.store(pem)
        self.command("req", "-in", path, "-verify", "-noout")
        text = self.command("req", "-in", path, "-noout", "-text").decode("ascii")
        algorithms = [line.strip().removeprefix("Signature Algorithm: ")
                      for line in text.splitlines() if line.strip().startswith("Signature Algorithm: ")]
        require(algorithms == [signature])
        return text

    def key_matches(self, private_key, public_pem, kind="x509"):
        require(kind in ("x509", "req"))
        key, public = self.store(private_key), self.store(public_pem)
        # Compare the actual SubjectPublicKeyInfo, not a textual algorithm label.
        actual = self.command("pkey", "-in", key, "-pubout")
        expected = self.command(kind, "-in", public, "-pubkey", "-noout")
        require(actual == expected)

    def cleanup(self):
        failed = False
        for path in self.files:
            if not harness.sanitize_file(path):
                failed = True
        if failed:
            raise harness.HarnessError("PKI scratch cleanup incomplete")
