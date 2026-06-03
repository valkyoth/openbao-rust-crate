#!/usr/bin/env python3
"""Generate the OpenBao 2.5.x endpoint coverage matrix.

The script intentionally uses only the Python standard library. It crawls the
official OpenBao 2.5.x API documentation, extracts rendered Method/Path tables,
and classifies each unique documented row against the crate's current public
surface.
"""

from __future__ import annotations

import collections
import csv
import datetime as dt
import html
import re
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path


DOCS_ROOT = "https://openbao.org"
START_PATHS = (
    "/api-docs/auth/",
    "/api-docs/secret/",
    "/api-docs/system/",
)
OUTPUT_CSV = Path("docs/openbao-2.5-endpoint-matrix.csv")
OUTPUT_MD = Path("docs/OPENBAO_2_5_ENDPOINT_MATRIX.md")
EXCLUDED_DOCS_VERSIONS = ("/next/", "/2.4.x/", "/2.3.x/")
LINK_RE = re.compile(
    r"href=(?:\"|')?(/api-docs/(?:auth|secret|system)/[^\"' >#?]+/)(?:\"|')?"
)
ENDPOINT_RE = re.compile(
    r"<tr><td[^>]*><code>([^<]+)</code><td[^>]*><code>([^<]+)</code>"
)
API_METHODS = {
    "ACME",
    "DELETE",
    "GET",
    "GET/POST",
    "GET/POST/DELETE",
    "LIST",
    "PATCH",
    "POST",
    "PUT",
    "SCAN",
}


@dataclass(frozen=True)
class Endpoint:
    area: str
    page: str
    method: str
    path: str
    status: str
    note: str


def fetch(path: str) -> str:
    with urllib.request.urlopen(f"{DOCS_ROOT}{path}", timeout=30) as response:
        return response.read().decode("utf-8", "replace")


def in_scope(path: str) -> bool:
    if any(version in path for version in EXCLUDED_DOCS_VERSIONS):
        return False
    return any(path.startswith(start) for start in START_PATHS)


def crawl_pages() -> list[tuple[str, str]]:
    seen: set[str] = set()
    pending = list(START_PATHS)
    pages: list[tuple[str, str]] = []

    while pending:
        path = pending.pop(0)
        if path in seen or not in_scope(path):
            continue
        seen.add(path)
        document = fetch(path)
        pages.append((path, document))
        for match in LINK_RE.finditer(document):
            link = match.group(1)
            if link not in seen and link not in pending and in_scope(link):
                pending.append(link)

    return pages


def extract_endpoints(pages: list[tuple[str, str]]) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for page, document in pages:
        for method, path in ENDPOINT_RE.findall(document):
            method = html.unescape(method.strip())
            if method not in API_METHODS:
                continue
            path = html.unescape(path.strip())
            if not path.startswith("/"):
                path = f"/{path}"
            key = (method, path)
            if key in seen:
                continue
            seen.add(key)
            rows.append((page, method, path))
    return rows


def classify(page: str, method: str, path: str) -> tuple[str, str]:
    normalized = path.replace("?list=true", "")

    if page.startswith("/api-docs/auth/"):
        return classify_auth(page, normalized)
    if page.startswith("/api-docs/secret/"):
        return classify_secret(page, method, normalized)
    if page.startswith("/api-docs/system/"):
        return classify_system(page, normalized)
    return ("decision", "Unclassified endpoint row.")


def classify_auth(page: str, path: str) -> tuple[str, str]:
    approle_property_segments = (
        "policies",
        "secret-id-num-uses",
        "secret-id-ttl",
        "token-ttl",
        "token-max-ttl",
        "bind-secret-id",
        "secret-id-bound-cidrs",
        "token-bound-cidrs",
        "period",
    )
    if (
        page == "/api-docs/auth/approle/"
        and "/auth/approle/role/:role_name/" in path
        and any(segment in path for segment in approle_property_segments)
    ):
        return (
            "raw",
            "AppRole delegated per-property endpoint; full role read/write is typed.",
        )

    if page == "/api-docs/auth/token/":
        if path in ("/auth/token/create-orphan", "/auth/token/renew-accessor"):
            return ("decision", "Token endpoint needs a dedicated helper decision.")
        if path == "/auth/token/lookup-self":
            return (
                "partial",
                "Typed helper exists, but uses OpenBao-compatible POST while this row documents GET.",
            )

    return ("typed", "Typed auth helper exists.")


def classify_secret(page: str, method: str, path: str) -> tuple[str, str]:
    fully_typed_prefixes = (
        "/api-docs/secret/cubbyhole/",
        "/api-docs/secret/databases/",
        "/api-docs/secret/kubernetes/",
        "/api-docs/secret/kv/",
        "/api-docs/secret/ldap/",
        "/api-docs/secret/rabbitmq/",
        "/api-docs/secret/totp/",
    )
    if page.startswith(fully_typed_prefixes):
        return ("typed", "Typed secrets-engine helper exists.")

    if page.startswith("/api-docs/secret/identity/"):
        if (
            page == "/api-docs/secret/identity/oidc-provider/"
            and path
            in (
                "/identity/oidc/provider/:name/authorize",
                "/identity/oidc/provider/:name/token",
                "/identity/oidc/provider/:name/userinfo",
            )
        ):
            return (
                "external",
                "OIDC browser protocol flow; use a dedicated OIDC library with the crate's discovery/JWKS helpers.",
            )
        if any(segment in page for segment in ("/mfa", "/oidc-provider", "/tokens")):
            return (
                "decision",
                "Implement in 0.10.0 as Identity OIDC admin/discovery/token/introspection or MFA management.",
            )
        return ("typed", "Typed Identity entity/group/alias/lookup helper exists.")

    if page.startswith("/api-docs/secret/ssh/"):
        if "public_key" in path or "public-key" in path:
            return (
                "external",
                "Unauthenticated text/plain SSH public key reads stay outside the typed JSON client.",
            )
        return ("typed", "Typed SSH helper exists.")

    if page.startswith("/api-docs/secret/transit/"):
        decision_segments = (
            "/import",
            "/import_version",
            "/wrapping_key",
            "/byok-export",
            "/cache-config",
            "/csr",
            "/set-certificate",
            "/soft-delete",
        )
        if path == "/transit/config/keys" or any(segment in path for segment in decision_segments):
            return (
                "decision",
                "Transit advanced key-import/BYOK/config/certificate/soft-delete endpoint is planned for 0.11.0 decision or implementation.",
            )
        return ("typed", "Typed Transit helper exists.")

    if page.startswith("/api-docs/secret/pki/"):
        if method == "ACME" and "/directory" in path:
            return (
                "external",
                "ACME protocol flow is intentionally handled by ACME clients; crate provides directory URL helpers.",
            )
        if "/pki/ocsp" in path:
            return (
                "raw",
                "OCSP is binary ASN.1; use raw byte helpers with a dedicated OCSP encoder/decoder.",
            )
        typed_pki_paths = {
            "/pki/acme/new-eab",
            "/pki/issuer/:issuer_ref/acme/new-eab",
            "/pki/roles/:role/acme/new-eab",
            "/pki/issuer/:issuer_ref/roles/:role/acme/new-eab",
            "/pki/eab",
            "/pki/eab/:key_id",
            "/pki/config/acme",
            "/pki/roles",
            "/pki/roles/:name",
            "/pki/issue/:name",
            "/pki/sign/:name",
            "/pki/root/sign-intermediate",
            "/pki/revoke",
            "/pki/issuers",
            "/pki/certs",
            "/pki/cert/:serial",
            "/pki/keys",
            "/pki/root/generate/:type",
            "/pki/intermediate/generate/:type",
            "/pki/config/ca",
            "/pki/issuers/import/bundle",
            "/pki/issuers/import/cert",
            "/pki/intermediate/set-signed",
            "/pki/issuer/:issuer_ref",
            "/pki/issuer/:issuer_ref/revoke",
            "/pki/key/:key_ref",
            "/pki/keys/import",
            "/pki/config/urls",
            "/pki/config/crl",
            "/pki/crl/rotate",
            "/pki/tidy",
            "/pki/tidy-status",
            "/pki/tidy-cancel",
        }
        if path in typed_pki_paths:
            return ("typed", "Typed PKI helper exists.")
        pki_0_12_paths = {
            "/pki/issuer/:issuer_ref/issue/:name",
            "/pki/issuer/:issuer_ref/sign/:name",
            "/pki/issuer/:issuer_ref/sign-intermediate",
            "/pki/root/sign-self-issued",
            "/pki/issuer/:issuer_ref/sign-self-issued",
            "/pki/root/rotate/:type",
            "/pki/issuers/generate/root/:type",
            "/pki/root/replace",
            "/pki/keys/generate/:type",
            "/pki/issuers/generate/intermediate/:type",
            "/pki/cert/ca",
            "/pki/ca",
            "/pki/ca/pem",
            "/pki/issuer/:issuer_ref/json",
            "/pki/issuer/:issuer_ref/der",
            "/pki/issuer/:issuer_ref/pem",
            "/pki/ca_chain",
            "/pki/cert/ca_chain",
            "/pki/cert/crl",
            "/pki/crl",
            "/pki/crl/pem",
            "/pki/cert/delta-crl",
            "/pki/crl/delta",
            "/pki/crl/delta/pem",
            "/pki/issuer/:issuer_ref/crl",
            "/pki/issuer/:issuer_ref/crl/der",
            "/pki/issuer/:issuer_ref/crl/pem",
            "/pki/issuer/:issuer_ref/crl/delta",
            "/pki/issuer/:issuer_ref/crl/delta/der",
            "/pki/issuer/:issuer_ref/crl/delta/pem",
            "/pki/cert/:serial/raw",
            "/pki/cert/:serial/raw/pem",
            "/pki/config/issuers",
            "/pki/config/keys",
            "/pki/config/cluster",
            "/pki/config/auto-tidy",
            "/pki/crl/rotate-delta",
        }
        if path == "/pki/root" and method == "DELETE":
            return (
                "decision",
                "Implement in 0.12.0 behind operator-ops; deleting a PKI root is destructive.",
            )
        if path in pki_0_12_paths:
            return (
                "decision",
                "Implement in 0.12.0 as advanced issuer/root/config or public PKI read coverage.",
            )
        pki_0_13_paths = {
            "/pki/revoke-with-key",
            "/certs/revoked",
            "/certs/revocation-queue",
            "/pki/certs/detailed?detailed=true",
            "/pki/issuer/:issuer_ref/resign-crls",
            "/pki/issuer/:issuer_ref/sign-revocation-list",
            "/pki/cel/roles",
            "/pki/cel/roles/:name",
            "/pki/cel/issue/:name",
            "/pki/cel/sign/:name",
            "/pki/sign-verbatim(/:name)",
            "/pki/issuer/:issuer_ref/sign-verbatim(/:name)",
            "/pki/intermediate/cross-sign",
        }
        if path in pki_0_13_paths:
            return (
                "decision",
                "Implement in 0.13.0 as specialized PKI revocation, CEL, sign-verbatim, or cross-sign coverage.",
            )
        return (
            "decision",
            "PKI row needs explicit 0.12.0/0.13.0 implementation or boundary classification.",
        )

    return ("decision", "Secret-engine endpoint is not classified yet.")


def classify_system(page: str, path: str) -> tuple[str, str]:
    if page == "/api-docs/system/mfa-validate/":
        return (
            "decision",
            "Implement in 0.10.0; this completes MFA-enforced login flows.",
        )

    if any(
        segment in page
        for segment in (
            "generate-root",
            "generate-recovery-token",
            "decode-token",
            "in-flight-req",
            "internal-counters",
            "inspect",
            "internal-ui-resultant-acl",
            "monitor",
            "policies-password",
            "config-ui",
            "rekey-recovery-key",
        )
    ):
        return ("decision", "System endpoint is planned for 0.14.0 decision or explicit rejection.")

    gated_pages = (
        "raw",
        "pprof",
        "/rekey/",
        "/rotate/",
        "/seal/",
        "/unseal/",
        "/step-down/",
    )
    if any(segment in page for segment in gated_pages):
        return ("typed-gated", "Typed helper exists behind operator-operation gates where needed.")

    return ("typed", "Typed system helper exists.")


def build_matrix(rows: list[tuple[str, str, str]]) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    for page, method, path in rows:
        status, note = classify(page, method, path)
        endpoints.append(
            Endpoint(
                area=page.split("/")[2],
                page=page,
                method=method,
                path=path,
                status=status,
                note=note,
            )
        )
    return endpoints


def percent(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0.0%"
    return f"{(numerator / denominator) * 100:.1f}%"


def write_csv(endpoints: list[Endpoint]) -> None:
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(("area", "method", "path", "status", "doc_page", "note"))
        for endpoint in endpoints:
            writer.writerow(
                (
                    endpoint.area,
                    endpoint.method,
                    endpoint.path,
                    endpoint.status,
                    f"{DOCS_ROOT}{endpoint.page}",
                    endpoint.note,
                )
            )


def write_markdown(endpoints: list[Endpoint]) -> None:
    total = len(endpoints)
    by_status = collections.Counter(endpoint.status for endpoint in endpoints)
    by_area: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    by_page: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    for endpoint in endpoints:
        by_area[endpoint.area][endpoint.status] += 1
        by_page[endpoint.page][endpoint.status] += 1

    covered = by_status["typed"] + by_status["typed-gated"]
    covered_or_partial = covered + by_status["partial"]
    addressed = covered_or_partial + by_status["raw"] + by_status["external"]
    generated = dt.date.today().isoformat()

    lines = [
        "# OpenBao 2.5.x Endpoint Coverage Matrix",
        "",
        f"Generated on {generated} from the official OpenBao 2.5.x API documentation.",
        "The full endpoint row matrix is stored in",
        f"`{OUTPUT_CSV.as_posix()}`.",
        "",
        "Sources:",
        "",
        "- https://openbao.org/api-docs/auth/",
        "- https://openbao.org/api-docs/secret/",
        "- https://openbao.org/api-docs/system/",
        "",
        "## Status Semantics",
        "",
        "- `typed`: a first-class typed helper exists in the crate.",
        "- `typed-gated`: a first-class typed helper exists behind explicit operator feature gates.",
        "- `partial`: a typed helper exists, but the documented row differs in method, variant, or exact endpoint shape.",
        "- `raw`: the crate intentionally relies on `Client::request_json` for this row.",
        "- `external`: the workflow is intentionally delegated to an external protocol/client.",
        "- `decision`: the row needs implementation, rejection, raw-wrapper policy, or external-client policy before `1.0.0`.",
        "",
        "## Summary",
        "",
        f"- Total documented endpoint rows: `{total}`",
        f"- Strict typed coverage: `{covered}/{total}` ({percent(covered, total)})",
        f"- Typed plus partial coverage: `{covered_or_partial}/{total}` ({percent(covered_or_partial, total)})",
        f"- Addressed by typed, partial, raw, or external policy: `{addressed}/{total}` ({percent(addressed, total)})",
        f"- Open decisions before `1.0.0`: `{by_status['decision']}`",
        "",
        "| Status | Count |",
        "| --- | ---: |",
    ]
    for status in ("typed", "typed-gated", "partial", "raw", "external", "decision"):
        lines.append(f"| `{status}` | {by_status[status]} |")

    lines.extend(
        [
            "",
            "## Area Totals",
            "",
            "| Area | Total | Typed | Typed gated | Partial | Raw | External | Decision | Strict % |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for area in ("auth", "secret", "system"):
        counts = by_area[area]
        area_total = sum(counts.values())
        area_covered = counts["typed"] + counts["typed-gated"]
        lines.append(
            f"| `{area}` | {area_total} | {counts['typed']} | {counts['typed-gated']} | "
            f"{counts['partial']} | {counts['raw']} | {counts['external']} | "
            f"{counts['decision']} | {percent(area_covered, area_total)} |"
        )

    lines.extend(
        [
            "",
            "## Pages With Non-Typed Rows",
            "",
            "| Page | Typed | Typed gated | Partial | Raw | External | Decision |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for page in sorted(by_page):
        counts = by_page[page]
        if not any(counts[status] for status in ("partial", "raw", "external", "decision")):
            continue
        lines.append(
            f"| [{page}]({DOCS_ROOT}{page}) | {counts['typed']} | {counts['typed-gated']} | "
            f"{counts['partial']} | {counts['raw']} | {counts['external']} | {counts['decision']} |"
        )

    lines.extend(
        [
            "",
            "## Required Follow-Up",
            "",
            "- Token `create-orphan` and `renew-accessor` need dedicated helper decisions.",
            "- AppRole delegated per-property endpoints need a final raw-vs-typed decision.",
            "- Identity OIDC admin/discovery/token/introspection rows and MFA management are planned for `0.10.0`.",
            "- Named-provider OIDC browser protocol rows (`authorize`, `token`, `userinfo`) are classified as `external` because they belong to a dedicated OIDC client library.",
            "- `sys/mfa/validate` is planned for `0.10.0` because MFA-enforced login flows cannot complete without it.",
            "- Transit import/BYOK, wrapping-key, cache/config, CSR/certificate, and soft-delete rows are planned for `0.11.0`.",
            "- PKI named-issuer, root lifecycle, public CA/CRL/cert reads, and config rows are planned for `0.12.0`; PKI revocation/CRL management, CEL, sign-verbatim, and cross-sign rows are planned for `0.13.0`; OCSP rows are classified as `raw`.",
            "- System generate-root/recovery-token, decode-token, password policies, monitor, internal inspection, resultant ACL, and legacy recovery rekey are planned for `0.14.0`.",
            "- `0.15.0` is the closure release where no endpoint row may remain `decision`.",
            "",
            "Regenerate with:",
            "",
            "```sh",
            "python3 scripts/generate_openbao_endpoint_matrix.py",
            "```",
            "",
        ]
    )
    OUTPUT_MD.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    pages = crawl_pages()
    rows = extract_endpoints(pages)
    endpoints = build_matrix(rows)
    write_csv(endpoints)
    write_markdown(endpoints)
    print(f"Generated {OUTPUT_CSV} and {OUTPUT_MD} from {len(pages)} docs pages.")
    print(f"Endpoint rows: {len(endpoints)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
