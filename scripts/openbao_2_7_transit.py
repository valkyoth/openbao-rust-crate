#!/usr/bin/python3 -EsSB
"""Staged Transit 2.7 TLS crypto contracts; does not promote SDK routing."""

import argparse
import base64
import binascii
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile

import openbao_2_7_external_keys as external

fixture = external.fixture
staged = external.staged
harness = external.harness
snapshots = external.snapshots
ROOT = Path(__file__).resolve().parents[1]
INPUTS = (*external.INPUTS, "scripts/openbao_2_7_transit.py")
PARAMETERS = {44: (1312, 2420), 65: (1952, 3309), 87: (2592, 4627)}
CHECKS = ["exact-version-tls13", "tls-rejections", "resource-limits", "network-isolation",
          "mldsa-all-parameters", "message-empty-tamper-wrong-message", "explicit-older-version",
          "external-mu-positive-and-negative", "batch-controls-and-partial-errors",
          "raw-der-pem-exports", "public-import-and-parameter-mismatch",
          "wrapped-pkcs8-private-import", "version-import-and-post-rotation-rejection",
          "external-reference-rotation", "provider-sign-verify-encrypt-decrypt",
          "external-key-restrictions", "grant-denial-and-revocation", "cleanup"]


def input_hashes():
    return {path: snapshots.sha256(snapshots.read_regular_file(ROOT / path, 2 * 1024 * 1024)) for path in INPUTS}


def require(condition):
    if not condition:
        raise harness.HarnessError("Transit contract assertion failed")


def b64(value):
    return base64.b64encode(value).decode("ascii")


def raw(value, size=None):
    require(isinstance(value, str) and len(value) <= fixture.MAX_BODY)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise harness.HarnessError("invalid fixture base64 response") from error
    require(b64(decoded) == value and (size is None or len(decoded) == size))
    return decoded


def pem_der(value, kind):
    require(isinstance(value, str) and len(value) <= fixture.MAX_BODY)
    lines = value.splitlines()
    require(len(lines) >= 3 and lines[0] == f"-----BEGIN {kind}-----"
            and lines[-1] == f"-----END {kind}-----")
    return raw("".join(lines[1:-1]))


def compute_mu(public_key, message):
    # RFC 9881 Appendix D / FIPS 204: empty context, ordinary (not HashML-DSA) message.
    require(isinstance(public_key, bytes) and len(public_key) in {size[0] for size in PARAMETERS.values()})
    require(isinstance(message, bytes) and len(message) <= 4096)
    return hashlib.shake_256(hashlib.shake_256(public_key).digest(64) + b"\x00\x00" + message).digest(64)


def signature_bytes(signature, version, size):
    require(isinstance(signature, str) and signature.startswith(f"vault:v{version}:"))
    return raw(signature.split(":", 2)[2], size)


def tamper(signature, version, size):
    value = bytearray(signature_bytes(signature, version, size))
    value[len(value) // 2] ^= 1
    return f"vault:v{version}:" + b64(value)


def require_error(status, response, fragment, statuses=(400, 500)):
    errors = response.get("errors") if isinstance(response, dict) else None
    require(status in statuses and isinstance(errors, list) and errors
            and all(isinstance(error, str) for error in errors)
            and any(fragment in error for error in errors))


class Probe:
    def __init__(self, address, ca, token):
        self.address, self.ca, self.token = address, ca, token

    def request(self, method, path, payload=None, credential=None):
        return external.request(self.address, self.ca, self.token if credential is None else credential,
                                method, "/v1/" + path, payload)

    def call(self, method, path, payload=None, status=200, credential=None):
        actual, response = self.request(method, path, payload, credential)
        fixture.require_status(actual, status)
        require(isinstance(response, dict))
        return response

    def data(self, method, path, payload=None):
        result = self.call(method, path, payload).get("data")
        require(isinstance(result, dict))
        return result

    def error(self, method, path, payload, fragment, statuses=(400, 500)):
        require_error(*self.request(method, path, payload), fragment, statuses)

    def sign(self, mount, key, message, version, size, **options):
        result = self.data("POST", f"{mount}/sign/{key}",
                           {"input": b64(message), "key_version": version, **options})
        signature = result.get("signature")
        signature_bytes(signature, version, size)
        require(type(result.get("key_version")) is int and result["key_version"] == version)
        return signature

    def verify(self, mount, key, message, signature, valid=True):
        result = self.data("POST", f"{mount}/verify/{key}", {"input": b64(message), "signature": signature})
        require(result.get("valid") is valid)


def probe_mldsa(probe, parameter):
    mount, key = "fixture-transit", f"mldsa{parameter}"
    public_size, signature_size = PARAMETERS[parameter]
    key_type = f"mldsa-{parameter}"
    message = b"checkpoint-five-synthetic-message"
    print(f"Transit fixture: ML-DSA-{parameter} message and rotation", flush=True)
    info = probe.data("POST", f"{mount}/keys/{key}", {"type": key_type, "exportable": True})
    require(info.get("type") == key_type and info.get("latest_version") == 1)
    read = probe.data("GET", f"{mount}/keys/{key}")
    public = raw(read["keys"]["1"]["public_key"], public_size)
    require(read["keys"]["1"]["name"] == key_type)
    for msg in (message, b""):
        signature = probe.sign(mount, key, msg, 1, signature_size, hash_algorithm="none", prehashed=False)
        probe.verify(mount, key, msg, signature)
        probe.verify(mount, key, msg + b"-wrong", signature, False)
        probe.verify(mount, key, msg, tamper(signature, 1, signature_size), False)
    info = probe.data("POST", f"{mount}/keys/{key}/rotate")
    require(info.get("latest_version") == 2 and set(info.get("keys", {})) == {"1", "2"})
    signature = probe.sign(mount, key, message, 1, signature_size, hash_algorithm="none", prehashed=False)
    probe.verify(mount, key, message, signature)
    current = probe.data("POST", f"{mount}/sign/{key}", {"input": b64(message)})
    signature_bytes(current.get("signature"), 2, signature_size)
    require(current.get("key_version") == 2)

    print(f"Transit fixture: ML-DSA-{parameter} external mu and batches", flush=True)
    mu = compute_mu(public, message)
    mu_signature = probe.sign(mount, key, mu, 1, signature_size, hash_algorithm="mldsa-mu", prehashed=True)
    probe.verify(mount, key, message, mu_signature)
    probe.verify(mount, key, message + b"-wrong", mu_signature, False)
    wrong_mu = compute_mu(public, message + b"-wrong")
    wrong_signature = probe.sign(mount, key, wrong_mu, 1, signature_size, hash_algorithm="mldsa-mu", prehashed=True)
    probe.verify(mount, key, message, wrong_signature, False)
    for value in (mu[:-1], mu + b"x"):
        probe.error("POST", f"{mount}/sign/{key}", {"input": b64(value), "hash_algorithm": "mldsa-mu", "prehashed": True},
                    "external ML-DSA mu must be 64 bytes")
    probe.error("POST", f"{mount}/sign/{key}", {"input": b64(mu), "hash_algorithm": "mldsa-mu", "prehashed": False},
                "requires prehashed=true and a ML-DSA compatible key", (400,))
    probe.error("POST", f"{mount}/verify/{key}", {"input": b64(mu), "signature": mu_signature,
                "hash_algorithm": "mldsa-mu", "prehashed": True}, "does not support verification", (400,))
    for external_mu in (False, True):
        inputs = [mu, compute_mu(public, b"")] if external_mu else [message, b""]
        batch = probe.data("POST", f"{mount}/sign/{key}", {"key_version": 1,
            "prehashed": external_mu, "hash_algorithm": "mldsa-mu" if external_mu else "none",
            "batch_input": [{"input": b64(value)} for value in inputs] + [{"input": "%"}]}).get("batch_results")
        require(isinstance(batch, list) and len(batch) == 3)
        for index, original in enumerate((message, b"")):
            signature_bytes(batch[index].get("signature"), 1, signature_size)
            require(batch[index].get("key_version") == 1 and not batch[index].get("error"))
            probe.verify(mount, key, original, batch[index]["signature"])
        require(isinstance(batch[2].get("error"), str) and "unable to decode input as base64" in batch[2]["error"])
        verify = probe.data("POST", f"{mount}/verify/{key}", {"prehashed": False, "hash_algorithm": "none", "batch_input": [
            {"input": b64(message), "signature": batch[0]["signature"]},
            {"input": b64(b"wrong"), "signature": batch[0]["signature"]},
            {"input": "%", "signature": batch[0]["signature"]}]}).get("batch_results")
        require(isinstance(verify, list) and len(verify) == 3)
        require(verify[0].get("valid") is True and verify[1].get("valid") is False
                and "unable to decode input as base64" in verify[2].get("error", ""))

    print(f"Transit fixture: ML-DSA-{parameter} export and import", flush=True)
    exports = {}
    for kind in ("public-key", "signing-key"):
        values = {}
        for encoding in ("", "raw", "der", "pem"):
            result = probe.data("GET", f"{mount}/export/{kind}/{key}/1?format={encoding}")
            require(result.get("type") == key_type and set(result.get("keys", {})) == {"1"})
            values[encoding] = result["keys"]["1"]
        require(values[""] == values["raw"])
        raw(values["raw"], public_size if kind == "public-key" else 32)
        require(raw(values["der"]) == pem_der(values["pem"], "PUBLIC KEY" if kind == "public-key" else "PRIVATE KEY"))
        exports[kind] = values
    require(raw(exports["public-key"]["raw"]) == public)
    pub_name, private_name = key + "-public", key + "-imported"
    probe.call("POST", f"{mount}/keys/{pub_name}/import", {"type": key_type, "public_key": exports["public-key"]["pem"]}, 204)
    probe.verify(mount, pub_name, message, signature)
    probe.error("POST", f"{mount}/sign/{pub_name}", {"input": b64(message)}, "does not contain a private part")
    mismatch = "mldsa-65" if parameter == 44 else "mldsa-44"
    probe.error("POST", f"{mount}/keys/{key}-mismatch/import", {"type": mismatch, "public_key": exports["public-key"]["pem"]}, "invalid key type")

    wrapped = probe.data("GET", f"{mount}/byok-export/wrapper/{key}/1")["keys"]["1"]
    require(len(raw(wrapped)) > 512)
    probe.call("POST", f"{mount}/keys/{private_name}/import", {"type": key_type, "ciphertext": wrapped, "allow_rotation": True}, 204)
    imported = probe.data("GET", f"{mount}/keys/{private_name}")
    require(imported.get("imported_key") is True and imported.get("imported_key_allow_rotation") is True)
    require(raw(imported["keys"]["1"]["public_key"]) == public)
    copy_signature = probe.sign(mount, private_name, message, 1, signature_size)
    probe.verify(mount, key, message, copy_signature)
    public2 = probe.data("GET", f"{mount}/export/public-key/{key}/2?format=pem")["keys"]["2"]
    probe.call("POST", f"{mount}/keys/{private_name}/import_version", {"public_key": public2}, 204)
    wrapped2 = probe.data("GET", f"{mount}/byok-export/wrapper/{key}/2")["keys"]["2"]
    probe.call("POST", f"{mount}/keys/{private_name}/import_version", {"ciphertext": wrapped2, "version": 2}, 204)
    require(probe.data("GET", f"{mount}/keys/{private_name}").get("latest_version") == 2)
    copy_signature = probe.sign(mount, private_name, message, 2, signature_size)
    probe.verify(mount, key, message, copy_signature)
    require(probe.data("POST", f"{mount}/keys/{private_name}/rotate").get("latest_version") == 3)
    probe.error("POST", f"{mount}/keys/{private_name}/import_version", {"ciphertext": wrapped2}, "can only be used with an imported key")
    return public


def probe_external(probe, publics):
    print("Transit fixture: reference providers and rotation", flush=True)
    source, target, denied = "fixture-transit", "fixture-delegated", "fixture-denied"
    for mount in (target, denied):
        probe.call("POST", "sys/mounts/" + mount, {"type": "transit"}, 204)
    probe.data("POST", source + "/keys/aes", {"type": "aes256-gcm96"})
    probe.data("POST", source + "/keys/aes/rotate")
    policy = 'path "auth/token/lookup-self" { capabilities = ["read"] }\n'
    for key, operations in [("aes", ("encrypt", "decrypt")), *[(f"mldsa{p}", ("sign", "verify")) for p in PARAMETERS]]:
        policy += f'path "{source}/keys/{key}" {{ capabilities = ["read"] }}\n'
        for operation in operations:
            policy += f'path "{source}/{operation}/{key}" {{ capabilities = ["update"] }}\n'
    probe.call("POST", "sys/policies/acl/fixture-transit-provider", {"policy": policy}, 204)
    auth = probe.call("POST", "auth/token/create", {"policies": ["fixture-transit-provider"],
        "no_default_policy": True, "ttl": "5m", "explicit_max_ttl": "5m", "renewable": False}).get("auth")
    require(isinstance(auth, dict) and isinstance(auth.get("client_token"), str) and auth["client_token"]
            and auth.get("policies") == ["fixture-transit-provider"])
    probe.call("GET", "sys/mounts", status=403, credential=auth["client_token"])
    config = "sys/external-keys/configs/transit-provider"
    probe.call("POST", config, {"plugin": "transit", "address": "https://127.0.0.1:8200",
        "mount_path": source, "token": auth["client_token"], "tls_ca_cert_bytes": probe.ca.read_text(encoding="ascii"), "verify": True}, 204)
    for key in ["aes", *[f"mldsa{p}" for p in PARAMETERS]]:
        for version in (1, 2):
            mapping = f"{key}-v{version}"
            path = config + "/keys/" + mapping
            probe.call("POST", path, {"name": key, "version": version, "verify": True}, 204)
            probe.call("POST", path + "/grants/" + target, status=204)
        reference = "transit-provider:" + key + "-v1"
        create = {"type": "external-key", "external_key_ref": reference}
        external.require_grant_denial(*probe.request("POST", f"{denied}/keys/{key}", create))
        info = probe.data("POST", f"{target}/keys/{key}", create)
        require(info.get("type") == "external-key" and info.get("keys") == {"1": reference})
        reference2 = "transit-provider:" + key + "-v2"
        info = probe.data("POST", f"{target}/keys/{key}/rotate", {"external_key_ref": reference2})
        require(info.get("latest_version") == 2 and info.get("keys") == {"1": reference, "2": reference2})
        if key == "aes":
            message, aad = b"synthetic-delegated-plaintext", b"synthetic-binding"
            for version in (1, 2):
                encrypted = probe.data("POST", f"{target}/encrypt/{key}", {"plaintext": b64(message), "associated_data": b64(aad), "key_version": version})
                cipher = encrypted.get("ciphertext")
                require(isinstance(cipher, str) and cipher.startswith(f"vault:v{version}:"))
                require(probe.data("POST", f"{target}/decrypt/{key}", {"ciphertext": cipher, "associated_data": b64(aad)}).get("plaintext") == b64(message))
                probe.error("POST", f"{target}/decrypt/{key}", {"ciphertext": cipher, "associated_data": b64(b"wrong")}, "cipher")
        else:
            parameter = int(key.removeprefix("mldsa"))
            size = PARAMETERS[parameter][1]
            message = b"synthetic-delegated-signature"
            for version in (1, 2):
                signature = probe.sign(target, key, message, version, size)
                probe.verify(target, key, message, signature)
                probe.verify(target, key, b"wrong", signature, False)
                probe.verify(target, key, message, tamper(signature, version, size), False)
            mu_signature = probe.sign(target, key, compute_mu(publics[parameter], message), 1, size, hash_algorithm="mldsa-mu", prehashed=True)
            probe.verify(target, key, message, mu_signature)
        # Revoke only the older mapping: distinguish grant rejection from provider outage.
        probe.call("DELETE", config + f"/keys/{key}-v1/grants/{target}", status=204)
        operation = "encrypt" if key == "aes" else "sign"
        payload = {"plaintext" if key == "aes" else "input": b64(b"synthetic"), "key_version": 1}
        external.require_grant_denial(*probe.request("POST", f"{target}/{operation}/{key}", payload))
        probe.data("POST", f"{target}/{operation}/{key}", {**payload, "key_version": 2})
    print("Transit fixture: external-key restrictions", flush=True)
    create = {"type": "external-key", "external_key_ref": "transit-provider:aes-v2"}
    for field, value, error in [("derived", True, "derivation"), ("convergent_encryption", True, "convergent encryption"),
                                 ("auto_rotate_period", "1h", "cannot enable auto-rotation")]:
        probe.error("POST", f"{target}/keys/forbidden-{field}", {**create, field: value}, error)
    probe.error("POST", f"{target}/keys/forbidden-import/import", {"type": "external-key", "public_key": "synthetic"}, "unknown key type")
    probe.error("GET", f"{target}/export/encryption-key/aes", None, "not exportable")
    # Prove the type restriction separately from the default exportable=false policy.
    probe.data("POST", f"{target}/keys/forbidden-export", {**create, "exportable": True})
    probe.error("GET", f"{target}/export/encryption-key/forbidden-export", None, "unknown key type")
    probe.error("POST", f"{target}/keys/aes/import_version", {"public_key": "synthetic"}, "can only be used with an imported key")


def probe(address, ca, token):
    client = Probe(address, ca, token)
    client.call("POST", "sys/mounts/fixture-transit", {"type": "transit"}, 204)
    wrapping = client.data("GET", "fixture-transit/wrapping_key").get("public_key")
    require(isinstance(wrapping, str) and "PUBLIC KEY" in wrapping)
    client.call("POST", "fixture-transit/keys/wrapper/import", {"type": "rsa-4096", "public_key": wrapping}, 204)
    publics = {parameter: probe_mldsa(client, parameter) for parameter in PARAMETERS}
    probe_external(client, publics)


def run():
    inputs = input_hashes()
    print("Transit fixture: verifying signed image", flush=True)
    staged.verify()
    staged.verify_image_signature()
    podman = str(external.evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(external.evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-270-transit-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root), "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    owner = secrets.token_hex(16)
    container, network = "openbao-270-transit-" + owner, "openbao-270-trnet-" + owner
    network_attempted = container_attempted = False
    token = ""
    try:
        tls, ca = harness.generate_tls(root, openssl, environment)
        config = harness.write_server_config(root, fixture.VERSION)
        image = harness.inspect_image(podman, staged.RELEASE, environment)
        network_attempted = True
        harness.run_bounded(fixture.network_command(podman, network, owner), timeout=60, environment=environment)
        container_attempted = True
        harness.run_bounded(fixture.container_command(podman, image, container, network, owner, config, tls), timeout=120, environment=environment)
        limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", container], maximum=64 * 1024, timeout=30, environment=environment)
        snapshots.validate_container_resource_config(snapshots.parse_json(limits, 64 * 1024))
        fixture.verify_network(podman, network, container, environment)
        port = harness.parse_port(harness.run_bounded([podman, "port", container, "8200/tcp"], maximum=1024, timeout=30, environment=environment))
        address = f"https://127.0.0.1:{port}"
        fixture.wait_for_health(podman, container, environment, address, ca)
        fixture.probe_tls(port, ca)
        token = harness.initialize_and_unseal(address, ca)
        probe(address, ca, token)
    finally:
        token = ""
        failed = False
        for attempted, kind, name in ((container_attempted, "container", container), (network_attempted, "network", network)):
            if attempted:
                try:
                    harness.remove_owned_resource(podman, kind, name, owner, environment)
                except (harness.HarnessError, OSError):
                    failed = True
        if not harness.cleanup_private_files(root):
            failed = True
        try:
            shutil.rmtree(root)
        except OSError:
            failed = True
        if failed:
            raise harness.HarnessError("Transit fixture cleanup incomplete")
    if inputs != input_hashes():
        raise harness.HarnessError("Transit fixture inputs changed")
    return {"schema": "openbao-transit-tls/v1", "version": fixture.VERSION,
            "image_linux_amd64_digest": staged.AMD64, "inputs": inputs, "outcome": "passed",
            "scope": "server-fixture-only-not-sdk-integration", "tls": "TLSv1.3", "checks": CHECKS,
            "mldsa_parameters": list(PARAMETERS), "pkcs11_verified": False, "routable": False}


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        result = run()
        with tempfile.NamedTemporaryFile(prefix="openbao-270-transit-result-", suffix=".json", delete=False) as output:
            output.write(snapshots.canonical_json(result))
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            print(f"Transit fixture passed; result: {output.name}")
        return 0
    except Exception:
        # Provider errors may embed credentials or request data. Never print them.
        print("Transit fixture failed; no compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
