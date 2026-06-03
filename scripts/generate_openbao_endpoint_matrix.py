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
    r"<tr><td[^>]*><code>([^<]+)</code><td[^>]*><code>(/[^<]+)</code>"
)


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
            path = html.unescape(path.strip())
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
        if any(segment in page for segment in ("/mfa", "/oidc-provider", "/tokens")):
            return (
                "decision",
                "Identity OIDC/token/MFA management needs pre-1.0 decision.",
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
                "Transit advanced key-import/BYOK/config/certificate/soft-delete endpoint needs pre-1.0 decision.",
            )
        return ("typed", "Typed Transit helper exists.")

    if page.startswith("/api-docs/secret/pki/"):
        if method == "ACME" and "/directory" in path:
            return (
                "external",
                "ACME protocol flow is intentionally handled by ACME clients; crate provides directory URL helpers.",
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
        return (
            "decision",
            "PKI advanced issuer/root/CEL/authority endpoint needs pre-1.0 decision or implementation.",
        )

    return ("decision", "Secret-engine endpoint is not classified yet.")


def classify_system(page: str, path: str) -> tuple[str, str]:
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
            "mfa-validate",
            "monitor",
            "policies-password",
            "config-ui",
            "rekey-recovery-key",
        )
    ):
        return ("decision", "System endpoint needs pre-1.0 decision or explicit rejection.")

    if page.startswith("/api-docs/system/leases/") and "/sys/leases/tidy" in path:
        return ("decision", "Lease tidy needs pre-1.0 decision.")

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
        writer = csv.writer(handle)
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
        "- `decision`: the row needs implementation, rejection, or movement to the optional `0.10.0` buffer before `1.0.0`.",
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
            "- Identity OIDC provider/token and MFA management needs a pre-`1.0.0` decision.",
            "- Transit import/BYOK, wrapping-key, cache/config, CSR/certificate, and soft-delete rows need pre-`1.0.0` decisions.",
            "- PKI advanced issuer/root/CEL/authority rows need implementation or explicit rejection.",
            "- System generate-root/recovery-token, decode-token, password policies, monitor, internal inspection, resultant ACL, MFA validate, legacy recovery rekey, and lease tidy need decisions.",
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
