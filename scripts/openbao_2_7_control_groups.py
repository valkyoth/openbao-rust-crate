#!/usr/bin/python3 -EsSB
"""Probe staged control-group enforcement over TLS; never promote SDK routing."""

import argparse
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import evidence_tools
import openbao_2_7_api as staged
import openbao_2_7_tls as fixture
import openbao_api_snapshots as snapshots
import openbao_test_harness as harness

ROOT = Path(__file__).resolve().parents[1]
POLICY = "compat/onboarding/2.7.0/control-group-policy.hcl"
INPUTS = (*fixture.INPUTS, "scripts/openbao_2_7_control_groups.py", POLICY,
          "src/policy.rs", "src/policy/control_groups.rs", "src/sys.rs",
          "src/sys/control_groups.rs", "src/sys/control_groups/execution.rs",
          "src/sys/control_groups/review.rs")
CHECKS = ["exact-version-tls13", "tls-rejections", "resource-limits", "network-isolation",
          "generated-policy", "distinct-identities", "self-approval-denied",
          "nonmember-no-approval", "all-factors-required", "review-metadata",
          "deferred-write", "original-kv2-response", "expiry-denied",
          "peer-namespace-review-denied", "cancel-without-retry", "cleanup"]


def require(condition):
    if not condition:
        raise harness.HarnessError("control-group contract assertion failed")


def input_hashes():
    return {path: snapshots.sha256(snapshots.read_regular_file(ROOT / path, 2 * 1024 * 1024))
            for path in INPUTS}


def report_for(inputs, replay_rejected=False):
    require(type(replay_rejected) is bool)
    return {"schema": "openbao-control-group-tls/v3", "version": fixture.VERSION,
            "image_linux_amd64_digest": staged.AMD64, "inputs": inputs,
            "outcome": "passed" if replay_rejected else "compatible-with-known-upstream-limitation",
            "security_checks": {"server-replay-rejection": "passed" if replay_rejected else "known-upstream-failure"},
            "scope": "server-fixture-only-not-sdk-integration", "tls": "TLSv1.3",
            "checks": CHECKS, "routable": False}


def validate_report(report, inputs):
    require(isinstance(report, dict))
    rejected = report.get("security_checks") == {"server-replay-rejection": "passed"}
    require(report == report_for(inputs, rejected)
            and report.get("routable") is False)


def credential(value):
    require(isinstance(value, str) and 0 < len(value) <= 8192
            and all(0x21 <= ord(char) <= 0x7e for char in value))
    return value


def request(address, ca, token, method, path, payload=None, namespace=None):
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    require(body is None or len(body) <= fixture.MAX_BODY)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = credential(token)
    if namespace is not None:
        require(namespace == "fixture-peer")
        headers["X-Vault-Namespace"] = namespace
    outgoing = urllib.request.Request(address + "/v1/" + path, data=body, method=method, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), harness.RejectRedirect(),
                                        urllib.request.HTTPSHandler(context=fixture.context(ca)))
    try:
        response = opener.open(outgoing, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    except (OSError, urllib.error.URLError) as error:
        raise harness.HarnessError("control-group TLS request failed") from error
    with response:
        status = response.status
        data = response.read(fixture.MAX_BODY + 1)
        require(len(data) <= fixture.MAX_BODY)
        require(not data or response.headers.get_content_type() == "application/json")
    return status, snapshots.parse_json(data, fixture.MAX_BODY) if data else {}


def denied(status, body, message):
    # An unrelated 400/403/500 must never count as evidence of approval denial.
    expected = {"permission denied": 403, "token owner cannot be approver": 500,
                "cannot lookup token in different namespace": 500,
                "invalid accessor": 400, "wrapping token is not valid or does not exist": 400}
    require(message in expected and type(status) is int and isinstance(body, dict))
    fixture.require_status(status, expected[message])
    # request_handling.go wraps ACL denials with go-multierror v1.1.1.
    # Accept only its exact single-cause format, never substring matches or
    # multiple causes which could conceal an unrelated failure.
    require(body.get("errors") in ([message], [f"1 error occurred:\n\t* {message}\n\n"]))


def reject_replay(status, body, persisted_version):
    # Observe state read-only after the single deliberate replay probe. Never
    # count a successful replay as evidence, even if the write did not repeat.
    if status == 200:
        repeated = type(persisted_version) is int and persisted_version > 2
        diagnostic = "write-version-advanced" if repeated else "unexpected-success"
        print("Control-group fixture: replay diagnostic=" + diagnostic, flush=True)
    denied(status, body, "wrapping token is not valid or does not exist")
    require(type(persisted_version) is int and persisted_version == 2)


def classify_known_replay(status, body, persisted_version, strict):
    if strict or status == 400:
        reject_replay(status, body, persisted_version)
        return True
    # This exception is only for the exact pinned 2.7.0 fixture. Unexpected
    # errors or behavior changes require review, not a broader exception.
    require(fixture.VERSION == "2.7.0")
    require(type(status) is int and status == 200 and isinstance(body, dict))
    data = body.get("data")
    require(isinstance(data, dict) and type(data.get("version")) is int
            and data["version"] == 3)
    require(type(persisted_version) is int and persisted_version == 3)
    print("Control-group fixture: server replay rejection FAILED (known upstream limitation)", flush=True)
    return False


def initial_review(review, requester_id, changed):
    require(isinstance(review, dict))
    # logical.Entity uses the uppercase protobuf JSON field ID in the tagged source.
    checks = (
        ("approval", review.get("approved") is False),
        ("authorizations", review.get("authorizations") == []),
        ("operation", review.get("request_operation") == "update"),
        ("path", review.get("request_path") == "fixture-kv/data/record"),
        ("payload", review.get("request_data") == {"data": {"value": changed}}),
        ("entity-ID", isinstance(review.get("request_entity"), dict)
         and review["request_entity"].get("ID") == requester_id),
    )
    for field, valid in checks:
        if not valid:
            print("Control-group fixture: review mismatch=" + field, flush=True)
            require(False)


def validate_entity_id(entity, namespace_id=None):
    require(isinstance(entity, str) and len(entity) <= 256)
    identifier = entity
    if namespace_id is not None:
        require(isinstance(namespace_id, str) and 0 < len(namespace_id) <= 128
                and namespace_id.isascii() and namespace_id.isalnum())
        identifier, separator, suffix = entity.partition(".")
        require(separator == "." and suffix == namespace_id)
    try:
        valid = str(uuid.UUID(identifier)) == identifier
    except ValueError:
        valid = False
    require(valid)


class Probe:
    def __init__(self, address, ca, root):
        self.address, self.ca, self.root = address, ca, root

    def request(self, method, path, payload=None, token=None, namespace=None):
        return request(self.address, self.ca, self.root if token is None else token,
                       method, path, payload, namespace)

    def call(self, method, path, payload=None, status=204, token=None, namespace=None):
        actual, response = self.request(method, path, payload, token, namespace)
        fixture.require_status(actual, status)
        require(isinstance(response, dict))
        return response

    def user(self, name, policies, namespace=None, namespace_id=None):
        require((namespace is None) == (namespace_id is None))
        password = secrets.token_urlsafe(32)
        self.call("POST", "auth/userpass/users/" + name, {"password": password,
                  "token_policies": policies, "token_no_default_policy": True,
                  "token_ttl": "5m", "token_max_ttl": "5m"}, namespace=namespace)
        auth = self.call("POST", "auth/userpass/login/" + name, {"password": password},
                         200, token="", namespace=namespace).get("auth")
        require(isinstance(auth, dict) and set(auth.get("policies", [])) == set(policies))
        token = credential(auth.get("client_token"))
        entity = auth.get("entity_id")
        validate_entity_id(entity, namespace_id)
        return token, entity

    def review(self, accessor, token):
        data = self.call("POST", "sys/control-group/request", {"accessor": accessor},
                         200, token).get("data")
        require(isinstance(data, dict) and type(data.get("approved")) is bool
                and isinstance(data.get("authorizations"), list))
        return data

    def authorize(self, accessor, token, approved):
        data = self.call("POST", "sys/control-group/authorize", {"accessor": accessor},
                         200, token).get("data")
        require(isinstance(data, dict) and data.get("approved") is approved)

    def deferred(self, method, token, payload=None):
        response = self.call(method, "fixture-kv/data/record", payload, 200, token)
        require(response.get("data") is None and isinstance(response.get("wrap_info"), dict))
        info = response["wrap_info"]
        return credential(info.get("token")), credential(info.get("accessor"))

    def value(self):
        data = self.call("GET", "fixture-kv/data/record", status=200).get("data")
        require(isinstance(data, dict) and isinstance(data.get("data"), dict)
                and isinstance(data.get("metadata"), dict))
        return data


def cancelled_unwrap(probe, requester, wrapped):
    # Send once over verified TLS and abandon reception. This establishes no
    # rollback guarantee; observation is read-only and execution is never retried.
    parts = urllib.parse.urlsplit(probe.address)
    require(parts.scheme == "https" and parts.hostname == "127.0.0.1" and parts.port)
    connection = http.client.HTTPSConnection(parts.hostname, parts.port, timeout=5,
                                             context=fixture.context(probe.ca))
    try:
        connection.request("POST", "/v1/sys/wrapping/unwrap",
                           json.dumps({"token": credential(wrapped)}).encode(),
                           {"Content-Type": "application/json", "X-Vault-Token": credential(requester)})
    finally:
        connection.close()


def probe(address, ca, root, strict_replay=False):
    p = Probe(address, ca, root)
    policy = snapshots.read_regular_file(ROOT / POLICY, 16 * 1024).decode("ascii")
    require(policy.count('ttl = "300s"') == 1)
    reviewer = '\n'.join(f'path "sys/control-group/{action}" {{ capabilities = ["update"] }}'
                         for action in ("authorize", "request"))
    reviewer += '\npath "sys/wrapping/unwrap" { capabilities = ["update"] }\n'
    print("Control-group fixture: enabling userpass and KV2", flush=True)
    p.call("POST", "sys/auth/userpass", {"type": "userpass"})
    p.call("POST", "sys/mounts/fixture-kv", {"type": "kv", "options": {"version": "2"}})
    print("Control-group fixture: installing reviewer and generated policies", flush=True)
    p.call("POST", "sys/policies/acl/fixture-reviewer", {"policy": reviewer})
    p.call("POST", "sys/policies/acl/fixture-controlled", {"policy": policy})
    print("Control-group fixture: creating requester identity", flush=True)
    requester, requester_id = p.user("requester", ["fixture-controlled", "fixture-reviewer"])
    print("Control-group fixture: creating first approver identity", flush=True)
    first, first_id = p.user("first", ["fixture-reviewer"])
    print("Control-group fixture: creating second approver identity", flush=True)
    second, second_id = p.user("second", ["fixture-reviewer"])
    print("Control-group fixture: creating nonmember identity", flush=True)
    outsider, outsider_id = p.user("outsider", ["fixture-reviewer"])
    require(len({requester_id, first_id, second_id, outsider_id}) == 4)
    print("Control-group fixture: creating identity groups", flush=True)
    for name, members in (("operators", [requester_id, first_id, second_id]),
                          ("security", [requester_id, second_id])):
        p.call("POST", "identity/group", {"name": name, "type": "internal",
               "member_entity_ids": members}, 200)
    print("Control-group fixture: checking approver least privilege", flush=True)
    denied(*p.request("GET", "sys/mounts", token=first), "permission denied")
    print("Control-group fixture: seeding initial KV2 value", flush=True)
    initial, changed = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    p.call("POST", "fixture-kv/data/record", {"data": {"value": initial}}, 200)
    print("Control-group fixture: creating deferred write", flush=True)
    wrapped, accessor = p.deferred("POST", requester, {"data": {"value": changed}})
    print("Control-group fixture: checking request review metadata", flush=True)
    review = p.review(accessor, first)
    initial_review(review, requester_id, changed)
    print("Control-group fixture: checking self-approval denial", flush=True)
    denied(*p.request("POST", "sys/control-group/authorize", {"accessor": accessor}, requester),
           "token owner cannot be approver")
    require(p.review(accessor, first)["authorizations"] == [])
    print("Control-group fixture: checking nonmember approval", flush=True)
    p.authorize(accessor, outsider, False)
    require(p.review(accessor, first)["authorizations"] == [])
    print("Control-group fixture: checking insufficient first approval", flush=True)
    p.authorize(accessor, first, False)
    require(p.value()["data"] == {"value": initial})
    # Do not redeem this token yet: some failed wrapping operations consume it.
    print("Control-group fixture: checking complete factor thresholds", flush=True)
    p.authorize(accessor, second, True)
    require(p.review(accessor, first)["approved"] is True)
    require(p.value()["data"] == {"value": initial})
    print("Control-group fixture: deferred write and replay rejection", flush=True)
    response = p.call("POST", "sys/wrapping/unwrap", {"token": wrapped}, 200, requester)
    require(response.get("data", {}).get("version") == 2)
    require(p.value()["data"] == {"value": changed})
    replay_status, replay_body = p.request("POST", "sys/wrapping/unwrap", {"token": wrapped}, requester)
    persisted_version = p.value()["metadata"].get("version")
    replay_rejected = classify_known_replay(replay_status, replay_body, persisted_version, strict_replay)
    current_version = 2 if replay_rejected else 3
    require(p.value()["data"] == {"value": changed})
    print("Control-group fixture: original KV2 response and insufficient approval", flush=True)
    wrapped, accessor = p.deferred("GET", requester)
    p.authorize(accessor, first, False)
    denied(*p.request("POST", "sys/wrapping/unwrap", {"token": wrapped}, requester),
           "wrapping token is not valid or does not exist")
    wrapped, accessor = p.deferred("GET", requester)
    p.authorize(accessor, first, False)
    p.authorize(accessor, second, True)
    response = p.call("POST", "sys/wrapping/unwrap", {"token": wrapped}, 200, requester)
    require(response.get("data", {}).get("data") == {"value": changed}
            and response["data"].get("metadata", {}).get("version") == current_version)
    print("Control-group fixture: peer namespace review denial", flush=True)
    print("Control-group fixture: creating peer namespace", flush=True)
    peer_namespace = p.call("POST", "sys/namespaces/fixture-peer", {}, 200).get("data")
    require(isinstance(peer_namespace, dict))
    peer_namespace_id = peer_namespace.get("id")
    require(isinstance(peer_namespace_id, str) and bool(peer_namespace_id))
    print("Control-group fixture: enabling peer userpass and reviewer policy", flush=True)
    p.call("POST", "sys/auth/userpass", {"type": "userpass"}, namespace="fixture-peer")
    p.call("POST", "sys/policies/acl/fixture-reviewer", {"policy": reviewer}, namespace="fixture-peer")
    print("Control-group fixture: creating peer reviewer identity", flush=True)
    peer, _ = p.user("peer", ["fixture-reviewer"], namespace="fixture-peer",
                     namespace_id=peer_namespace_id)
    print("Control-group fixture: checking cross-namespace accessor denial", flush=True)
    _, accessor = p.deferred("GET", requester)
    denied(*p.request("POST", "sys/control-group/request", {"accessor": accessor}, peer, "fixture-peer"),
           "cannot lookup token in different namespace")
    print("Control-group fixture: expiry rejection", flush=True)
    p.call("POST", "sys/policies/acl/fixture-controlled", {"policy": policy.replace('ttl = "300s"', 'ttl = "3s"')})
    wrapped, accessor = p.deferred("GET", requester)
    p.authorize(accessor, first, False)
    p.authorize(accessor, second, True)
    time.sleep(4)
    denied(*p.request("POST", "sys/wrapping/unwrap", {"token": wrapped}, requester),
           "wrapping token is not valid or does not exist")
    p.call("POST", "sys/policies/acl/fixture-controlled", {"policy": policy})
    print("Control-group fixture: cancellation without retry", flush=True)
    final = secrets.token_urlsafe(24)
    wrapped, accessor = p.deferred("POST", requester, {"data": {"value": final}})
    p.authorize(accessor, first, False)
    p.authorize(accessor, second, True)
    cancelled_unwrap(p, requester, wrapped)
    observed = p.value()
    version = observed["metadata"].get("version")
    require(type(version) is int and version in (current_version, current_version + 1)
            and observed["data"] == {"value": final if version == current_version + 1 else changed})
    return replay_rejected


def run(strict_replay=False):
    inputs = input_hashes()
    print("Control-group fixture: verifying signed image", flush=True)
    staged.verify()
    print("Control-group fixture: verifying registry signature", flush=True)
    staged.verify_image_signature()
    print("Control-group fixture: preparing protected tools and TLS", flush=True)
    podman = str(evidence_tools.protected_path(Path("/usr/bin/podman")))
    openssl = str(evidence_tools.protected_path(Path("/usr/bin/openssl")))
    root = Path(tempfile.mkdtemp(prefix="openbao-270-control-", dir="/tmp"))
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(root), "XDG_CONFIG_HOME": str(root),
                   "XDG_CACHE_HOME": str(root), "LANG": "C.UTF-8"}
    run_id = secrets.token_hex(16)
    container, network = "openbao-270-control-" + run_id, "openbao-270-cgnet-" + run_id
    network_attempted = container_attempted = False
    token = ""
    try:
        tls, ca = harness.generate_tls(root, openssl, environment)
        config = harness.write_server_config(root, fixture.VERSION)
        print("Control-group fixture: preparing pinned image", flush=True)
        image = harness.inspect_image(podman, staged.RELEASE, environment)
        print("Control-group fixture: creating isolated network", flush=True)
        network_attempted = True
        harness.run_bounded(fixture.network_command(podman, network, run_id), timeout=60, environment=environment)
        container_attempted = True
        print("Control-group fixture: starting constrained server", flush=True)
        harness.run_bounded(fixture.container_command(podman, image, container, network, run_id, config, tls), timeout=120, environment=environment)
        print("Control-group fixture: verifying limits and loopback port", flush=True)
        limits = harness.run_bounded([podman, "inspect", "--format", "{{json .HostConfig}}", container], maximum=64 * 1024, timeout=30, environment=environment)
        snapshots.validate_container_resource_config(snapshots.parse_json(limits, 64 * 1024))
        fixture.verify_network(podman, network, container, environment)
        port = harness.parse_port(harness.run_bounded([podman, "port", container, "8200/tcp"], maximum=1024, timeout=30, environment=environment))
        address = f"https://127.0.0.1:{port}"
        print("Control-group fixture: waiting for exact-version TLS health", flush=True)
        fixture.wait_for_health(podman, container, environment, address, ca)
        print("Control-group fixture: checking TLS rejection cases", flush=True)
        fixture.probe_tls(port, ca)
        print("Control-group fixture: initializing disposable server", flush=True)
        token = harness.initialize_and_unseal(address, ca)
        print("Control-group fixture: preparing policies and identities", flush=True)
        replay_rejected = probe(address, ca, token, strict_replay)
    finally:
        token = ""
        failed = False
        for attempted, kind, name in ((container_attempted, "container", container), (network_attempted, "network", network)):
            if attempted:
                try:
                    harness.remove_owned_resource(podman, kind, name, run_id, environment)
                except (harness.HarnessError, OSError):
                    failed = True
        if not harness.cleanup_private_files(root):
            failed = True
        try:
            shutil.rmtree(root)
        except OSError:
            failed = True
        if failed:
            raise harness.HarnessError("control-group fixture cleanup incomplete")
    require(inputs == input_hashes())
    return report_for(inputs, replay_rejected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-replay-rejection", action="store_true",
                        help="Require replay rejection; failure emits no report")
    arguments = parser.parse_args()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, harness.interrupted)
    try:
        result = run(arguments.require_replay_rejection)
        with tempfile.NamedTemporaryFile(prefix="openbao-270-control-result-", suffix=".json", delete=False) as output:
            output.write(snapshots.canonical_json(result))
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            label = "replay rejection passed" if result["outcome"] == "passed" else "known server replay failure"
            print(f"Control-group compatibility checks completed ({label}); result: {output.name}")
        return 0
    except (harness.HarnessError, snapshots.SnapshotError, OSError, ValueError, TypeError, KeyError, http.client.HTTPException):
        print("Control-group fixture failed; no compatibility promotion")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
