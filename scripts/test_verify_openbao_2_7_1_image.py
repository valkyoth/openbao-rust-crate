#!/usr/bin/python3 -EsSB
"""Image evidence must bind the exact architecture, source and signed index."""

import base64
import copy
import unittest
from unittest.mock import patch

import verify_openbao_2_7_1_image as evidence


class ImageEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = {name: evidence.patch.base.read_regular_file(evidence.initial.OUTPUT / name, evidence.LIMIT)
                         for name in evidence.ARTIFACTS}

    def test_retained_image_chain(self):
        evidence.validate(self.artifacts)

    def test_every_digest_is_enforced(self):
        for name in self.artifacts:
            with self.subTest(name=name), self.assertRaises(evidence.patch.harness.HarnessError):
                evidence.validate({**self.artifacts, name: self.artifacts[name] + b" "})

    def test_source_and_subject_semantics(self):
        def mutate(args):
            for name, value in args:
                artifacts = dict(self.artifacts)
                artifacts[name] = evidence.patch.base.canonical_json(value)
                with self.subTest(name=name), patch.object(evidence, "pinned", side_effect=lambda data, _: data), \
                     self.assertRaises(evidence.patch.harness.HarnessError):
                    evidence.validate(artifacts)

        index = evidence.patch.base.parse_json(self.artifacts["image-index.json"], evidence.LIMIT)
        manifest = evidence.patch.base.parse_json(self.artifacts["image-attestation-manifest.json"], evidence.LIMIT)
        provenance = evidence.patch.base.parse_json(self.artifacts["image-provenance.json"], evidence.LIMIT)
        wrong_image = copy.deepcopy(index)
        next(m for m in wrong_image["manifests"] if m.get("platform") == {"architecture": "amd64", "os": "linux"})["digest"] = "sha256:" + "0" * 64
        duplicate = copy.deepcopy(index)
        duplicate["manifests"].append(duplicate["manifests"][0])
        wrong_subject = copy.deepcopy(manifest)
        wrong_subject["subject"]["digest"] = "sha256:" + "0" * 64
        wrong_source = copy.deepcopy(provenance)
        wrong_source["predicate"]["buildDefinition"]["externalParameters"]["request"]["root"]["request"]["args"]["vcs:revision"] = "0" * 40
        mutate((("image-index.json", wrong_image), ("image-index.json", duplicate),
                ("image-attestation-manifest.json", wrong_subject)))
        # Keep the size descriptor consistent so source validation is exercised.
        artifacts = dict(self.artifacts)
        artifacts["image-provenance.json"] = evidence.patch.base.canonical_json(wrong_source)
        manifest["layers"][0]["size"] = len(artifacts["image-provenance.json"])
        artifacts["image-attestation-manifest.json"] = evidence.patch.base.canonical_json(manifest)
        with patch.object(evidence, "pinned", side_effect=lambda data, _: data), \
             self.assertRaises(evidence.patch.harness.HarnessError):
            evidence.validate(artifacts)

    def test_signature_payload_cannot_name_another_index(self):
        lines = self.artifacts["signature-bundle.json"].splitlines()
        bundle = evidence.patch.base.parse_json(lines[0], evidence.LIMIT)
        payload = evidence.patch.base.parse_json(base64.b64decode(bundle["dsseEnvelope"]["payload"]), evidence.LIMIT)
        payload["subject"][0]["digest"]["sha256"] = "0" * 64
        bundle["dsseEnvelope"]["payload"] = base64.b64encode(evidence.patch.base.canonical_json(payload)).decode("ascii")
        artifacts = {**self.artifacts, "signature-bundle.json": evidence.patch.base.canonical_json(bundle)}
        with patch.object(evidence, "pinned", side_effect=lambda data, _: data), \
             self.assertRaises(evidence.patch.harness.HarnessError):
            evidence.validate(artifacts)


if __name__ == "__main__":
    unittest.main()
