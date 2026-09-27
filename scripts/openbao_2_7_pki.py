#!/usr/bin/python3 -EsSB
"""Staged PKI TLS and certificate verification; never promotes SDK routing."""

import argparse
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile
import urllib.error
import urllib.request

import openbao_2_7_pki_crypto as crypto

transit = crypto.transit
external, fixture, harness, staged, snapshots = (
    transit.external, transit.fixture, transit.harness, transit.staged, transit.snapshots)
ROOT = Path(__file__).resolve().parents[1]
INPUTS = (*transit.INPUTS, "scripts/openbao_2_7_pki_crypto.py", "scripts/openbao_2_7_pki.py")
CHECKS = ["exact-version-tls13", "tls-rejections", "resource-limits", "network-isolation",
          "mldsa-all-parameters", "root-csr-leaf-signatures", "exported-key-matching",
          "standalone-key-import-read", "named-issuer-issue-sign", "existing-key-cross-csr", "root-rotation",
          "rsa-pss-default-and-overrides", "trailing-dot-rejection", "ocsp-rsa-positive-mldsa-unsupported",
          "kms-provider-signing", "grant-denial-and-revocation", "cleanup"]


def input_hashes():
    return {path: snapshots.sha256(snapshots.read_regular_file(ROOT / path, 2 * 1024 * 1024)) for path in INPUTS}


def mount(probe, name, kind="pki"):
    probe.call("POST", "sys/mounts/" + name, {"type": kind}, 204)


def role(probe, name, **options):
    probe.call("POST", name + "/roles/leaf", {"allowed_domains": ["fixture.test"],
        "allow_bare_domains": True, "allow_subdomains": True, "max_ttl": "30m",
        "key_type": "any", **options}, 200)
    read = probe.data("GET", name + "/roles/leaf")
    crypto.require(read.get("key_type") == "any" and read.get("allowed_domains") == ["fixture.test"])
    for field, value in options.items():
        crypto.require(type(read.get(field)) is type(value) and read[field] == value)


def ocsp_response(probe, mount_name, body):
    crypto.require(isinstance(body, bytes) and 0 < len(body) < 2048)
    request = urllib.request.Request(probe.address + f"/v1/{mount_name}/ocsp", data=body,
        headers={"Content-Type": "application/ocsp-request"}, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), harness.RejectRedirect(),
        urllib.request.HTTPSHandler(context=fixture.context(probe.ca)))
    try:
        response = opener.open(request, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        data = response.read(crypto.LIMIT + 1)
        crypto.require(len(data) <= crypto.LIMIT and response.headers.get_content_type() == "application/ocsp-response")
        return response.status, data


def probe_ocsp(probe, verify, name, issuer, certificate, unsupported):
    ca, cert, output = verify.store(issuer), verify.store(certificate), verify.store(b"pending")
    verify.command("ocsp", "-issuer", ca, "-cert", cert, "-no_nonce", "-reqout", output)
    request = snapshots.read_regular_file(Path(output), 2048)
    status, body = ocsp_response(probe, name, request)
    if unsupported:
        # Tagged path_ocsp.go returns HTTP 500 and RFC 6960 internalError.
        # An arbitrary failure (bad request, missing issuer, TLS outage) is not evidence.
        expected = status == 500 and body == bytes.fromhex("30030a0102")
        if not expected:
            print("PKI fixture: OCSP did not return the expected internalError response", flush=True)
        crypto.require(expected)
    else:
        crypto.require(status == 200)
        response = verify.store(body)
        result = verify.command("ocsp", "-respin", response, "-issuer", ca, "-cert", cert,
            "-CAfile", ca, "-no-CApath", "-no-CAstore", "-no_nonce")
        crypto.require((cert + ": good").encode("ascii") in result)


def probe_trailing_dot(probe, name, parameter):
    # cert_util.go converts CN to IDNA before role validation. The pinned
    # x/net v0.58.0 VerifyDNSLength rejects a final dot under Unicode 16+.
    status, response = probe.request("POST", name + "/issue/leaf", {
        "common_name": "leaf.fixture.test.", "ttl": "10m",
        "key_type": "mldsa", "key_bits": parameter})
    crypto.require(status == 400 and isinstance(response, dict)
                   and response.get("errors") == ['idna: invalid label "leaf.fixture.test."'])


def probe_mldsa(probe, verify, parameter):
    name, algorithm = f"pki-{parameter}", f"ML-DSA-{parameter}"
    print(f"PKI fixture: ML-DSA-{parameter} certificates and CSR", flush=True)
    mount(probe, name)
    root = probe.data("POST", name + "/root/generate/exported", {
        "common_name": "fixture.test", "key_type": "mldsa", "key_bits": parameter,
        "ttl": "2h", "format": "pem"})
    cert = root["certificate"]
    print("PKI fixture: verifying root signature and exported key", flush=True)
    verify.certificate(cert, cert, algorithm)
    verify.key_matches(root["private_key"], cert)
    print("PKI fixture: writing and reading role", flush=True)
    role(probe, name)
    print("PKI fixture: issuing named-issuer leaf", flush=True)
    leaf = probe.data("POST", f"{name}/issuer/{root['issuer_id']}/issue/leaf", {
        "common_name": "leaf.fixture.test", "ttl": "10m", "key_type": "mldsa",
        "key_bits": parameter, "format": "pem"})
    print("PKI fixture: verifying leaf signature, algorithm and key", flush=True)
    text = verify.certificate(leaf["certificate"], cert, algorithm)
    crypto.require(f"Public Key Algorithm: {algorithm}" in text)
    verify.key_matches(leaf["private_key"], leaf["certificate"])
    print("PKI fixture: checking unsupported ML-DSA OCSP", flush=True)
    probe_ocsp(probe, verify, name, cert, leaf["certificate"], True)
    print("PKI fixture: checking trailing-dot rejection", flush=True)
    probe_trailing_dot(probe, name, parameter)
    print("PKI fixture: generating and verifying intermediate CSR", flush=True)
    intermediate = probe.data("POST", name + "/intermediate/generate/exported", {
        "common_name": "intermediate.fixture.test", "key_type": "mldsa",
        "key_bits": parameter, "format": "pem"})
    verify.csr(intermediate["csr"], algorithm)
    verify.key_matches(intermediate["private_key"], intermediate["csr"], "req")
    print("PKI fixture: signing and verifying intermediate", flush=True)
    signed = probe.data("POST", f"{name}/issuer/{root['issuer_id']}/sign-intermediate", {
        "csr": intermediate["csr"], "common_name": "intermediate.fixture.test", "ttl": "1h"})
    verify.certificate(signed["certificate"], cert, algorithm)
    print("PKI fixture: signing and verifying CSR as leaf", flush=True)
    signed_leaf = probe.data("POST", f"{name}/issuer/{root['issuer_id']}/sign/leaf", {
        "csr": intermediate["csr"], "common_name": "intermediate.fixture.test", "ttl": "10m"})
    verify.certificate(signed_leaf["certificate"], cert, algorithm)
    print("PKI fixture: cross-sign CSR with existing key", flush=True)
    cross = probe.data("POST", name + "/intermediate/cross-sign", {
        "key_ref": intermediate["key_id"], "common_name": "cross.fixture.test"})
    crypto.require(cross["key_id"] == intermediate["key_id"] and "private_key" not in cross)
    verify.csr(cross["csr"], algorithm)
    verify.key_matches(intermediate["private_key"], cross["csr"], "req")
    print("PKI fixture: standalone key generation, import and read", flush=True)
    standalone = probe.data("POST", name + "/keys/generate/exported", {
        "key_type": "mldsa", "key_bits": parameter})
    crypto.require(standalone.get("key_type") == "mldsa")
    imported_mount = name + "-import"
    mount(probe, imported_mount)
    imported = probe.data("POST", imported_mount + "/keys/import", {"pem_bundle": standalone["private_key"]})
    key_id = imported.get("key_id")
    crypto.require(isinstance(key_id, str) and key_id and imported.get("key_type") == "mldsa")
    read = probe.data("GET", imported_mount + "/key/" + key_id)
    crypto.require(read.get("key_type") == "mldsa" and "private_key" not in read)
    print("PKI fixture: verifying imported key through CSR", flush=True)
    imported_csr = probe.data("POST", imported_mount + "/intermediate/generate/existing", {
        "key_ref": key_id, "common_name": "import.fixture.test"})
    verify.csr(imported_csr["csr"], algorithm)
    verify.key_matches(standalone["private_key"], imported_csr["csr"], "req")
    print("PKI fixture: rotating and verifying root", flush=True)
    rotated = probe.data("POST", name + "/root/rotate/internal", {
        "common_name": "rotated.fixture.test", "key_type": "mldsa", "key_bits": parameter, "ttl": "2h"})
    crypto.require(rotated["key_id"] != root["key_id"] and rotated["issuer_id"] != root["issuer_id"])
    verify.certificate(rotated["certificate"], rotated["certificate"], algorithm)


def probe_rsa(probe, verify):
    print("PKI fixture: RSA-PSS defaults and overrides", flush=True)
    for suffix, options, algorithm in (
        ("default", {}, "sha256WithRSAEncryption"),
        ("false", {"use_pss": False, "signature_bits": 256}, "sha256WithRSAEncryption"),
        ("pss", {"use_pss": True, "signature_bits": 384}, "rsassaPss")):
        name = "pki-rsa-" + suffix
        mount(probe, name)
        root = probe.data("POST", name + "/root/generate/internal", {
            "common_name": "fixture.test", "key_type": "rsa", "key_bits": 2048, "ttl": "2h", **options})
        text = verify.certificate(root["certificate"], root["certificate"], algorithm)
        if suffix == "pss":
            crypto.require("Hash Algorithm: sha384" in text)
        role(probe, name, **options)
        leaf = probe.data("POST", name + "/issue/leaf", {"common_name": "leaf.fixture.test",
            "key_type": "ec", "key_bits": 256, "ttl": "10m"})
        verify.certificate(leaf["certificate"], root["certificate"], algorithm)
        probe_ocsp(probe, verify, name, root["certificate"], leaf["certificate"], False)
        csr = probe.data("POST", name + "/intermediate/generate/internal", {
            "common_name": "intermediate.fixture.test", "key_type": "rsa", "key_bits": 2048, **options})
        verify.csr(csr["csr"], algorithm)


def kms_provider_policy():
    # Pinned kms/transit v2.1.0 ExportPublic uses this exact public export route.
    # No private-key export, wildcard, key mutation or administrative access.
    return ('path "auth/token/lookup-self" { capabilities = ["read"] }\n'
            'path "pki-source/keys/signer" { capabilities = ["read"] }\n'
            'path "pki-source/export/public-key/signer/latest" { capabilities = ["read"] }\n'
            'path "pki-source/sign/signer" { capabilities = ["update"] }\n'
            'path "pki-source/verify/signer" { capabilities = ["update"] }')


def probe_kms(probe, verify):
    print("PKI fixture: KMS signatures and mount grants", flush=True)
    source, target, denied = "pki-source", "pki-kms", "pki-denied"
    mount(probe, source, "transit")
    mount(probe, target)
    mount(probe, denied)
    probe.data("POST", source + "/keys/signer", {"type": "mldsa-44"})
    policy = kms_provider_policy()
    probe.call("POST", "sys/policies/acl/pki-provider", {"policy": policy}, 204)
    auth = probe.call("POST", "auth/token/create", {"policies": ["pki-provider"],
        "no_default_policy": True, "ttl": "5m", "explicit_max_ttl": "5m", "renewable": False})["auth"]
    crypto.require(auth["policies"] == ["pki-provider"] and isinstance(auth["client_token"], str)
                   and auth["client_token"])
    probe.call("GET", "sys/mounts", status=403, credential=auth["client_token"])
    print("PKI fixture: checking provider public export and private-export denial", flush=True)
    probe.call("GET", source + "/export/public-key/signer/latest?format=der", credential=auth["client_token"])
    probe.call("GET", source + "/export/signing-key/signer/latest", status=403, credential=auth["client_token"])
    config = "sys/external-keys/configs/pki-provider"
    probe.call("POST", config, {"plugin": "transit", "address": "https://127.0.0.1:8200",
        "mount_path": source, "token": auth["client_token"],
        "tls_ca_cert_bytes": probe.ca.read_text(encoding="ascii"), "verify": True}, 204)
    key = config + "/keys/signer"
    probe.call("POST", key, {"name": "signer", "version": 1, "verify": True}, 204)
    payload = {"external_key_ref": "pki-provider:signer", "common_name": "fixture.test", "ttl": "2h"}
    print("PKI fixture: checking denied KMS mount", flush=True)
    external.require_grant_denial(*probe.request("POST", denied + "/root/generate/kms", payload))
    probe.call("POST", key + "/grants/" + target, status=204)
    print("PKI fixture: registering standalone KMS key", flush=True)
    registered = probe.data("POST", target + "/keys/generate/kms", {"external_key_ref": "pki-provider:signer"})
    crypto.require(registered.get("external_key_ref") == "pki-provider:signer" and "private_key" not in registered)
    print("PKI fixture: generating and verifying KMS root", flush=True)
    root = probe.data("POST", target + "/root/generate/kms", payload)
    crypto.require("private_key" not in root)
    verify.certificate(root["certificate"], root["certificate"], "ML-DSA-44")
    print("PKI fixture: generating and verifying KMS CSR", flush=True)
    csr = probe.data("POST", target + "/intermediate/generate/kms", {
        "external_key_ref": "pki-provider:signer", "common_name": "intermediate.fixture.test"})
    crypto.require("private_key" not in csr)
    verify.csr(csr["csr"], "ML-DSA-44")
    print("PKI fixture: issuing and verifying KMS leaf", flush=True)
    role(probe, target)
    request = {"common_name": "leaf.fixture.test", "key_type": "ec", "key_bits": 256, "ttl": "10m"}
    leaf = probe.data("POST", target + "/issue/leaf", request)
    verify.certificate(leaf["certificate"], root["certificate"], "ML-DSA-44")
    print("PKI fixture: revoking and restoring KMS grant", flush=True)
    probe.call("DELETE", key + "/grants/" + target, status=204)
    external.require_grant_denial(*probe.request("POST", target + "/issue/leaf", request))
    probe.call("POST", key + "/grants/" + target, status=204)
    restored = probe.data("POST", target + "/issue/leaf", request)
    verify.certificate(restored["certificate"], root["certificate"], "ML-DSA-44")


def probe(address, ca, token, verify):
    client = transit.Probe(address, ca, token)
    for parameter in (44, 65, 87):
        probe_mldsa(client, verify, parameter)
    probe_rsa(client, verify)
    probe_kms(client, verify)


def run():
    inputs = input_hashes()
    print("PKI fixture: verifying signed image", flush=True)
    staged.verify()
    staged.verify_image_signature()
    podman = str(external.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(external.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-270-pki-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    verify = crypto.Crypto(root, openssl, environment)
    owner = secrets.token_hex(16)
    container, network = "openbao-270-pki-" + owner, "openbao-270-pkinet-" + owner
    network_attempted = container_attempted = False
    token = ""
    try:
        tls, ca = harness.generate_tls(root, openssl, environment)
        config = harness.write_server_config(root, fixture.VERSION)
        image = harness.inspect_image(podman, staged.RELEASE, environment)
        network_attempted = True
        harness.run_bounded(fixture.network_command(podman, network, owner), timeout=60, environment=environment)
        container_attempted = True
        harness.run_bounded(fixture.container_command(podman, image, container, network, owner, config, tls),
                            timeout=120, environment=environment)
        limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", container],
                                     maximum=64 * 1024, timeout=30, environment=environment)
        snapshots.validate_container_resource_config(snapshots.parse_json(limits, 64 * 1024))
        fixture.verify_network(podman, network, container, environment)
        port = harness.parse_port(harness.run_bounded([podman, "port", container, "8200/tcp"],
                                  maximum=1024, timeout=30, environment=environment))
        address = f"https://127.0.0.1:{port}"
        fixture.wait_for_health(podman, container, environment, address, ca)
        fixture.probe_tls(port, ca)
        token = harness.initialize_and_unseal(address, ca)
        probe(address, ca, token, verify)
    finally:
        token = ""
        failed = False
        for attempted, kind, name in ((container_attempted, "container", container), (network_attempted, "network", network)):
            if attempted:
                try:
                    harness.remove_owned_resource(podman, kind, name, owner, environment)
                except (harness.HarnessError, OSError):
                    failed = True
        try:
            verify.cleanup()
        except (harness.HarnessError, OSError):
            failed = True
        if not harness.cleanup_private_files(root):
            failed = True
        try:
            shutil.rmtree(root)
        except OSError:
            failed = True
        if failed:
            raise harness.HarnessError("PKI fixture cleanup incomplete")
    if inputs != input_hashes():
        raise harness.HarnessError("PKI fixture inputs changed")
    return {"schema": "openbao-pki-tls/v1", "version": fixture.VERSION,
            "image_linux_amd64_digest": staged.AMD64, "inputs": inputs, "outcome": "passed",
            "scope": "server-fixture-only-not-sdk-integration", "tls": "TLSv1.3", "checks": CHECKS,
            "mldsa_parameters": [44, 65, 87], "pkcs11_verified": False, "routable": False}


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        result = run()
        with tempfile.NamedTemporaryFile(prefix="openbao-270-pki-result-", suffix=".json", delete=False) as output:
            output.write(snapshots.canonical_json(result))
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            print(f"PKI fixture passed; result: {output.name}")
        return 0
    except Exception:
        print("PKI fixture failed; no compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
