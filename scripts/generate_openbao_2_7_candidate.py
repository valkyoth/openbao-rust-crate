#!/usr/bin/python3 -EsSB
"""Build a non-routable 2.7 candidate while preserving every historical cell."""

import argparse
import copy
from collections import Counter

import generate_openbao_capability_registry as registry
import openbao_2_7_api as staged
import verify_openbao_2_7_delta_review as delta

RESULT = staged.STAGED / "candidate-capability-registry.json"
EXPECTED_SHA256 = "28dfa6898f34c481dae31aa208bfff0cf56f4c75dfb8528cd5291f7eb38dcdd0"
VERSION = "2.7.0"
EXCLUDED_PREFIXES = ("/auth/ldap/", "/auth/kerberos/", "/auth/radius/", "/ldap/")
CONFIG = "/sys/external-keys/configs/:name"
KEY = CONFIG + "/keys/:key_ref"
GRANT = KEY + "/grants/:path"
EXTERNAL = {
    (method, path): (wire_method, wire_path)
    for methods, path, wire_path in (
        (("LIST",), "/sys/external-keys/configs", "/sys/external-keys/configs"),
        (("GET", "POST", "PATCH", "DELETE"), CONFIG, "/sys/external-keys/configs/{config}"),
        (("LIST",), CONFIG + "/keys", "/sys/external-keys/configs/{config}/keys"),
        (("GET", "POST", "PATCH", "DELETE"), KEY, "/sys/external-keys/configs/{config}/keys/{key}"),
        (("LIST",), KEY + "/grants", "/sys/external-keys/configs/{config}/keys/{key}/grants"),
        (("POST", "DELETE"), GRANT, "/sys/external-keys/configs/{config}/keys/{key}/grants/{mount}"),
    )
    for method in methods
    for wire_method in ("get" if method == "LIST" else method.lower(),)
}
NEW_RUNTIME = {
    **EXTERNAL,
    ("POST", "/sys/control-group/authorize"): ("post", "/sys/control-group/authorize"),
    ("POST", "/sys/control-group/request"): ("post", "/sys/control-group/request"),
    ("GET", "/sys/internal/inspect/request"): ("get", "/sys/internal/inspect/request"),
}
REJECTED_DOCS = {("PATCH", "/ssh/issuer/:issuer_ref"), ("GET", "/sys/internal/inspect/request/root")}


def require(condition, message):
    if not condition:
        raise registry.RegistryError(message)


def normalize(method, path):
    path = registry.DOCUMENTATION_PATH_CORRECTIONS.get(path, path)
    path = registry.CANDIDATE_PATH_CORRECTIONS.get(path, path)
    method, path = registry.CANDIDATE_METHOD_CORRECTIONS.get((method, path), (method, path))
    if path.startswith("/sys/external-keys/"):
        path = path.replace(":config_name", ":name").replace(":key_name", ":key_ref").replace(":mount-path", ":path")
        if method == "PUT": method = "POST"
    return registry.validate_operation(method, path)


def build(active, documentation, openapi):
    require(documentation.get("schema") == "openbao-tagged-api-documentation/v2"
            and documentation.get("version") == VERSION, "candidate documentation identity changed")
    require(openapi.get("schema") == "openbao-normalized-openapi/v2"
            and openapi.get("version") == VERSION, "candidate OpenAPI identity changed")
    require(tuple(active["versions"]) == registry.EXPECTED_VERSIONS, "active profiles changed")
    tagged = {normalize(row["method"], row["path"]) for row in documentation["operations"]}
    paths = openapi["document"]["paths"]
    for (method, _), (wire_method, wire_path) in NEW_RUNTIME.items():
        operation = paths.get(wire_path, {}).get(wire_method)
        require(isinstance(operation, dict), "candidate runtime route missing")
        if method == "LIST":
            require(any(p.get("name") == "list" and p.get("in") == "query"
                        for p in operation.get("parameters", [])), "LIST projection changed")
    require("patch" not in paths["/{ssh_mount_path}/issuer/{issuer_ref}"], "SSH PATCH requires new review")
    require("/sys/internal/inspect/request/root" not in paths, "inspection route requires new review")
    workflow = paths["/sys/workflows/manage"]["get"]
    require({p["name"] for p in workflow["parameters"] if p["in"] == "query"} == {"list", "scan"},
            "workflow LIST/SCAN projection changed")
    require("get" in paths["/identity/oidc/.well-known/keys"], "OIDC keys supplement disappeared")
    documented = (tagged - REJECTED_DOCS) | set(NEW_RUNTIME) | {
        ("GET", "/identity/oidc/.well-known/keys"),
        ("SCAN", "/sys/workflows/manage"), ("SCAN", "/sys/workflows/manage/:prefix"),
    }
    old = {(op["method"], op["path_template"]): op for op in active["operations"]}
    require(documented - set(old) == set(NEW_RUNTIME), "candidate-only identity inventory changed")
    operations = []
    for method, path in sorted(set(old) | documented):
        previous = old.get((method, path))
        if previous is None:
            op = {"id": registry.stable_id(method, path), "method": method, "path_template": path,
                  "disposition": "typed-gated", "ranges": [{"minimum": active["versions"][0],
                  "maximum": active["versions"][-1], "availability": "unavailable", "evidence": "none"}]}
        else:
            op = copy.deepcopy(previous)
        excluded = any(path.startswith(prefix) for prefix in EXCLUDED_PREFIXES)
        if excluded or (method, path) not in documented:
            state, evidence = "unavailable", "none"
        elif op["disposition"] == "security-blocked":
            state, evidence = "security-blocked", "tagged-documentation"
        else:
            state = "documented"
            evidence = "locked-openapi" if (method, path) in NEW_RUNTIME or (method, path) not in tagged else "tagged-documentation"
        op["ranges"].append({"minimum": VERSION, "maximum": VERSION, "availability": state, "evidence": evidence})
        operations.append(op)
    operations.sort(key=lambda op: op["id"])
    endpoints = copy.deepcopy(active["logical_endpoints"])
    for endpoint in endpoints:
        require(endpoint["variants"][-1]["maximum"] == active["versions"][-1], "root-token variant boundary changed")
        endpoint["variants"][-1]["maximum"] = VERSION
    endpoints.append({"id": "sys.internal-request-inspection", "variants": [
        {"operation_id": registry.stable_id("GET", "/sys/internal/inspect/request/root"),
         "minimum": "2.5.5", "maximum": "2.5.5"},
        {"operation_id": registry.stable_id("GET", "/sys/internal/inspect/request"),
         "minimum": VERSION, "maximum": VERSION},
    ]})
    return {"schema": "openbao-2.7-candidate-capability-registry/v1",
            "scope": "candidate-contracts-not-public-dispatch", "routable": False,
            "active_registry_sha256": registry.EXPECTED_REGISTRY_SHA256,
            "staged_api_lock_sha256": staged.EXPECTED_LOCK_SHA256,
            "delta_review_sha256": delta.EXPECTED_SHA256,
            "versions": [*active["versions"], VERSION],
            "routable_versions": active["versions"], "logical_endpoints": endpoints,
            "excluded_prefixes": list(EXCLUDED_PREFIXES),
            "summary": {"operations": len(operations), "new_identities": len(NEW_RUNTIME),
                        "candidate_states": dict(sorted(Counter(op["ranges"][-1]["availability"] for op in operations).items()))},
            "operations": operations}


def inputs():
    registry.verify_historical_registry()
    artifacts = staged.verify()
    delta.verify()
    return (registry.load_json(registry.REGISTRY_PATH), staged.parse(artifacts["documentation.json"]),
            staged.parse(artifacts["openapi.json"]))


def verify():
    expected = build(*inputs())
    actual = registry.read_regular_file(RESULT, registry.MAX_OUTPUT_BYTES)
    require(registry.sha256(actual) == EXPECTED_SHA256, "candidate registry digest changed")
    require(actual == registry.canonical_json(expected), "candidate registry differs from anchored inputs")
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate", action="store_true")
    args = parser.parse_args()
    try:
        if args.generate:
            registry.atomic_write(RESULT, registry.canonical_json(build(*inputs())))
        candidate = verify()
    except (registry.RegistryError, staged.base.SnapshotError, OSError, ValueError, KeyError, TypeError):
        print("Candidate registry validation failed; no profile promotion")
        return 1
    print(f"Candidate registry verified: {candidate['summary']['operations']} identities; public 2.7 remains blocked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
