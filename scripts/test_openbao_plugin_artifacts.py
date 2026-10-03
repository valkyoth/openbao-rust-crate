#!/usr/bin/python3 -EsSB
"""Artifact trust, bounded decoding and non-promotion regressions."""

import copy
import gzip
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import openbao_api_snapshots as base
import openbao_plugin_artifacts as subject

NAME = "openbao-plugin-auth-radius_linux_amd64_v1"
ELF = b"\x7fELF\x02\x01\x01" + bytes(9) + b"\x02\x00\x3e\x00" + bytes(44)


def archive(entries=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT) as bundle:
        for name, data, kind, mode in entries or [
            ("LICENSE", b"test-only license", tarfile.REGTYPE, 0o644),
            (NAME, ELF, tarfile.REGTYPE, 0o755),
        ]:
            member = tarfile.TarInfo(name)
            member.type, member.mode = kind, mode
            member.size = len(data) if kind == tarfile.REGTYPE else 0
            if kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                member.linkname = "/tmp/never-write-this-path"
            bundle.addfile(member, io.BytesIO(data) if member.size else None)
    return gzip.compress(output.getvalue(), mtime=0)


class ArtifactTests(unittest.TestCase):
    def test_lock_and_key_pins(self):
        document = subject.lock()
        self.assertEqual(tuple(p["id"] for p in document["plugins"]), subject.PLUGINS)
        for field in ("platform", "source_commit", "signing_primary_fingerprint", "plugins"):
            changed = copy.deepcopy(document)
            changed[field] = "changed"
            with patch.object(base, "read_regular_file", return_value=base.canonical_json(changed)):
                with self.assertRaises(base.SnapshotError):
                    subject.lock()
        with patch.object(base, "read_regular_file", return_value=b"wrong key"):
            with self.assertRaises(base.SnapshotError):
                subject.verify_signature(b"archive", b"signature")

    def test_assets_reject_mutation_size_missing_and_extra(self):
        plugin = {"assets": [{"name": "archive", "size": 4, "sha256": base.sha256(b"data")}]}
        subject.check_assets(plugin, {"archive": b"data"})
        for assets in ({}, {"archive": b"Data"}, {"archive": b"data!"},
                       {"archive": b"data", "extra": b""}):
            with self.assertRaises(base.SnapshotError):
                subject.check_assets(plugin, assets)

    def test_url_and_redirect_boundaries(self):
        self.assertTrue(subject.allowed_url(subject.ASSET_BASE + "tag/file"))
        self.assertTrue(subject.allowed_url("https://release-assets.githubusercontent.com/path?token=example"))
        for url in ("http://github.com/file", "https://evil.example/file",
                    "https://github.com.evil.example/file", "https://user@github.com/file",
                    "https://github.com:444/file", "https://github.com/file#fragment"):
            self.assertFalse(subject.allowed_url(url))
            with self.assertRaises(base.SnapshotError):
                subject.AssetRedirect().redirect_request(None, None, 302, "", {}, url)

    def test_download_bounds_and_no_proxy(self):
        class Response:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def geturl(self):
                return "https://github.com/path"
            def read(self, maximum):
                self.maximum = maximum
                return b"excess"
        response = Response()
        with patch.object(subject.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = response
            with self.assertRaises(base.SnapshotError):
                subject.download("https://github.com/path", 4)
            self.assertEqual(response.maximum, 5)
            self.assertEqual(build.call_args.args[0].proxies, {})
            self.assertEqual(build.return_value.open.call_args.kwargs["timeout"], 30)

    def test_checksums_strict_duplicate_and_bounds(self):
        self.assertEqual(subject.checksums(b"a" * 64 + b"  binary\n"), {"binary": "a" * 64})
        for value in (b"", b"a" * 64 + b"  ../binary\n", b"a" * 64 + b" *binary\n",
                      (b"a" * 64 + b"  binary\n") * 2, b"\xff", b"a" * (32 * 1024 + 1)):
            with self.assertRaises((base.SnapshotError, ValueError)):
                subject.checksums(value)

    def test_signature_status_pins_and_weak_digest_rejection(self):
        valid = (f"[GNUPG:] VALIDSIG {subject.SIGNER} 2026-10-02 1790956800 0 4 0 1 8 00 "
                 f"{subject.PRIMARY}\n").encode()
        subject.signature_status(valid)
        for value in (b"", valid + valid, valid.replace(subject.SIGNER.encode(), b"A" * 40),
                      valid.replace(subject.PRIMARY.encode(), b"B" * 40),
                      valid.replace(b" 1 8 00 ", b" 1 2 00 "),
                      valid + b"[GNUPG:] REVKEYSIG rejected\n"):
            with self.assertRaises(base.SnapshotError):
                subject.signature_status(value)

    def test_archive_allows_only_two_regular_members(self):
        self.assertEqual(subject.unpack(archive(), NAME)[NAME], ELF)
        good = [("LICENSE", b"license", tarfile.REGTYPE, 0o644),
                (NAME, ELF, tarfile.REGTYPE, 0o755)]
        for name, kind, mode in (("../escape", tarfile.REGTYPE, 0o644),
                                 ("/tmp/escape", tarfile.REGTYPE, 0o644),
                                 (NAME, tarfile.SYMTYPE, 0o755),
                                 (NAME, tarfile.LNKTYPE, 0o755),
                                 (NAME, tarfile.FIFOTYPE, 0o644),
                                 (NAME, tarfile.CHRTYPE, 0o644),
                                 (NAME, tarfile.DIRTYPE, 0o755),
                                 (NAME, tarfile.REGTYPE, 0o4755),
                                 (NAME, tarfile.REGTYPE, 0o777)):
            entries = good[:1] + [(name, ELF, kind, mode)]
            with self.subTest(name=name, kind=kind, mode=mode), self.assertRaises(base.SnapshotError):
                subject.unpack(archive(entries), NAME)
        for entries in (good[:1], good + good, good + [("extra", b"a", tarfile.REGTYPE, 0o644)]):
            with self.assertRaises(base.SnapshotError):
                subject.unpack(archive(entries), NAME)

    def test_archive_size_elf_and_malformed_rejections(self):
        for limit in ("MAX_ARCHIVE", "MAX_EXPANDED", "MAX_BINARY", "MAX_LICENSE"):
            with patch.object(subject, limit, 1), self.assertRaises(base.SnapshotError):
                subject.unpack(archive(), NAME)
        for binary in (b"", b"not ELF", ELF.replace(b"\x3e\x00", b"\x28\x00"),
                       ELF.replace(b"ELF\x02", b"ELF\x01")):
            with self.assertRaises(base.SnapshotError):
                subject.unpack(archive([("LICENSE", b"license", tarfile.REGTYPE, 0o644),
                                        (NAME, binary, tarfile.REGTYPE, 0o755)]), NAME)
        for value in (b"invalid", archive()[:20]):
            with self.assertRaises((base.SnapshotError, OSError, EOFError, tarfile.TarError)):
                subject.unpack(value, NAME)

    def test_gpg_real_valid_and_tampered_signatures(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            env = {"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": directory}
            def gpg(*args):
                return subprocess.run(["/usr/bin/gpg", "--no-options", "--batch", "--homedir", directory,
                                       *args], check=True, timeout=30, env=env,
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
            gpg("--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key",
                "Disposable Artifact Regression <test@example.invalid>", "ed25519", "sign", "1d")
            fingerprint = next(line.split(":")[9] for line in
                               gpg("--with-colons", "--list-keys").decode().splitlines()
                               if line.startswith("fpr:"))
            key = home / "public.asc"
            key.write_bytes(gpg("--armor", "--export", fingerprint))
            message = home / "message"
            message.write_bytes(b"disposable public test data")
            gpg("--output", str(home / "sig"), "--detach-sign", str(message))
            signature = (home / "sig").read_bytes()
            with patch.object(subject, "KEY", key), patch.object(subject, "KEY_SHA256", base.sha256(key.read_bytes())), \
                 patch.object(subject, "PRIMARY", fingerprint), patch.object(subject, "SIGNER", fingerprint):
                subject.verify_signature(message.read_bytes(), signature)
                for data, sig in ((b"tampered", signature), (message.read_bytes(), b"invalid")):
                    with self.assertRaises(subprocess.CalledProcessError):
                        subject.verify_signature(data, sig)

    def test_no_capture_as_root(self):
        with patch.object(os, "geteuid", return_value=0), patch.object(subject, "download") as fetch:
            with self.assertRaises(base.SnapshotError):
                subject.capture()
            fetch.assert_not_called()

    def test_complete_verification_and_failure_order(self):
        name = NAME + ".tar.gz"
        binary_sha = base.sha256(ELF)
        assets = {name: archive(), name + ".sig": b"test-signature",
                  "checksums-auth-radius.txt":
                  (base.sha256(archive()) + "  " + name + "\n" + binary_sha + "  " + NAME + "\n").encode(),
                  name + ".spdx.sbom.json": base.canonical_json(
                      {"bomFormat": "CycloneDX", "specVersion": "1.7"})}
        plugin = {"id": "auth-radius", "binary_sha256": binary_sha,
                  "assets": [{"name": key, "size": len(value), "sha256": base.sha256(value)}
                             for key, value in assets.items()]}
        with patch.object(subject, "verify_signature") as verify:
            self.assertEqual(subject.verify_plugin(plugin, assets)[NAME], ELF)
            verify.assert_called_once_with(assets[name], assets[name + ".sig"])
        with patch.object(subject, "verify_signature", side_effect=base.SnapshotError("rejected")), \
             patch.object(subject, "unpack") as unpack:
            with self.assertRaises(base.SnapshotError):
                subject.verify_plugin(plugin, assets)
            unpack.assert_not_called()
        for field in ("binary_sha256",):
            changed = copy.deepcopy(plugin)
            changed[field] = "0" * 64
            with patch.object(subject, "verify_signature"), self.assertRaises(base.SnapshotError):
                subject.verify_plugin(changed, assets)
        for bom in ({"bomFormat": "SPDX", "specVersion": "1.7"},
                    {"bomFormat": "CycloneDX", "specVersion": "1.6"}):
            changed_assets = dict(assets)
            changed_assets[name + ".spdx.sbom.json"] = base.canonical_json(bom)
            changed = copy.deepcopy(plugin)
            changed["assets"] = [{"name": key, "size": len(value), "sha256": base.sha256(value)}
                                 for key, value in changed_assets.items()]
            with patch.object(subject, "verify_signature"), self.assertRaises(base.SnapshotError):
                subject.verify_plugin(changed, changed_assets)

    def test_capture_failure_does_not_emit_report_or_execute_plugin(self):
        with patch.object(subject, "download", side_effect=base.SnapshotError("rejected")), \
             patch.object(subject.tempfile, "NamedTemporaryFile") as report, \
             patch.object(subject.subprocess, "run") as execution:
            with self.assertRaises(base.SnapshotError):
                subject.capture()
            report.assert_not_called()
            execution.assert_not_called()


if __name__ == "__main__":
    unittest.main()
