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
    if page == "/api-docs/auth/token/":
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
        if "/mfa/login-enforcement/" in page:
            return ("typed", "Typed Identity MFA login-enforcement helper exists.")
        if "/mfa/duo/" in page:
            return (
                "typed",
                "Typed Identity MFA Duo helper exists with secret-aware provider credentials.",
            )
        if "/mfa/okta/" in page:
            return (
                "typed",
                "Typed Identity MFA Okta helper exists with secret-aware provider credentials.",
            )
        if "/mfa/pingid/" in page:
            return (
                "typed",
                "Typed Identity MFA PingID helper exists with secret-aware settings-file payload.",
            )
        if "/mfa/totp/" in page:
            return (
                "typed",
                "Typed Identity MFA TOTP helper exists with secret-aware generated QR and URL output.",
            )
        if any(segment in page for segment in ("/oidc-provider", "/tokens")):
            return ("typed", "Typed Identity OIDC helper exists.")
        return ("typed", "Typed Identity entity/group/alias/lookup helper exists.")

    if page.startswith("/api-docs/secret/ssh/"):
        if "public_key" in path or "public-key" in path:
            return (
                "external",
                "Unauthenticated text/plain SSH public key reads stay outside the typed JSON client.",
            )
        return ("typed", "Typed SSH helper exists.")

    if page.startswith("/api-docs/secret/transit/"):
        if path == "/transit/wrapping_key":
            return (
                "typed",
                "Typed Transit wrapping-key helper exists and returns the RSA public key PEM as non-secret String.",
            )
        if path in ("/transit/keys/:name/import", "/transit/keys/:name/import_version"):
            return (
                "typed",
                "Typed Transit import helper exists; accepts pre-wrapped ciphertext as SecretString or public-key-only import material, rejects empty import constructors, and documents that raw private or symmetric key bytes stay outside default endpoint wrappers.",
            )
        if path.startswith("/transit/byok-export/"):
            return (
                "typed",
                "Typed Transit BYOK export helper exists and returns destination-wrapped ciphertext blobs as SecretString with redacted Debug.",
            )
        if path in (
            "/transit/keys/:name/soft-delete",
            "/transit/keys/:name/soft-delete-restore",
        ):
            return (
                "typed",
                "Typed reversible Transit key soft-delete and restore helpers exist.",
            )
        if path in ("/transit/cache-config", "/transit/config/keys"):
            return (
                "typed",
                "Typed Transit cache and global key configuration helpers exist.",
            )
        if path in ("/transit/keys/:name/csr", "/transit/keys/:name/set-certificate"):
            return (
                "typed",
                "Typed Transit CSR generation and certificate install helpers exist; PEM material is public.",
            )
        return ("typed", "Typed Transit helper exists.")

    if page.startswith("/api-docs/secret/pki/"):
        if method == "ACME" and "/directory" in path:
            return (
                "external",
                "ACME protocol flow is intentionally handled by ACME clients; crate provides directory URL and EAB helpers.",
            )
        if "/pki/ocsp" in path:
            return (
                "external",
                "OCSP responder protocol endpoint is handled by OCSP/TLS clients, not this SDK.",
            )
        public_pki_read_paths = {
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
        }
        if path in public_pki_read_paths:
            return (
                "external",
                "Unauthenticated public CA/certificate/CRL endpoint; fetch directly with TLS, CRL, or external HTTP tooling.",
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
            "/pki/config/issuers",
            "/pki/config/keys",
            "/pki/config/crl",
            "/pki/crl/rotate",
            "/pki/tidy",
            "/pki/tidy-status",
            "/pki/tidy-cancel",
            "/pki/issuer/:issuer_ref/issue/:name",
            "/pki/issuer/:issuer_ref/sign/:name",
            "/pki/root/rotate/:type",
            "/pki/issuers/generate/root/:type",
            "/pki/root/replace",
            "/pki/keys/generate/:type",
            "/pki/issuers/generate/intermediate/:type",
            "/pki/revoke-with-key",
            "/pki/config/cluster",
            "/pki/config/auto-tidy",
        }
        if path in typed_pki_paths:
            return ("typed", "Typed PKI helper exists.")
        pki_0_12_paths = set()
        if path == "/pki/root" and method == "DELETE":
            return (
                "typed-gated",
                "Dedicated destructive PKI root deletion helper exists behind operator-operation gates and requires an explicit confirmation type.",
            )
        pki_gated_paths = {
            "/pki/sign-verbatim(/:name)",
            "/pki/issuer/:issuer_ref/sign-verbatim(/:name)",
        }
        if path in pki_gated_paths:
            return (
                "typed-gated",
                "Typed PKI sign-verbatim helper exists behind operator-operation gates.",
            )
        if path in pki_0_12_paths:
            return (
                "planned",
                "Implement in 0.12.0 as PKI Tier 1 multi-issuer, authority lifecycle, config, sign-verbatim, or self-service revocation coverage.",
            )
        pki_0_13_paths = {
            "/pki/issuer/:issuer_ref/sign-intermediate",
            "/certs/revoked",
            "/certs/revocation-queue",
            "/pki/certs/detailed?detailed=true",
            "/pki/issuer/:issuer_ref/resign-crls",
            "/pki/crl/rotate-delta",
            "/pki/cel/roles",
            "/pki/cel/roles/:name",
            "/pki/cel/issue/:name",
            "/pki/cel/sign/:name",
        }
        if path in pki_0_13_paths:
            return (
                "typed",
                "Typed PKI specialized revocation, CEL, named-issuer hierarchy, or delta-CRL helper exists.",
            )
        pki_0_13_gated_paths = {
            "/pki/root/sign-self-issued",
            "/pki/issuer/:issuer_ref/sign-self-issued",
            "/pki/issuer/:issuer_ref/sign-revocation-list",
            "/pki/intermediate/cross-sign",
        }
        if path in pki_0_13_gated_paths:
            return (
                "typed-gated",
                "Typed PKI high-risk hierarchy or revocation-list helper exists behind operator-operation gates.",
            )
        return (
            "decision",
            "PKI row needs explicit implementation or boundary classification before 1.0.0.",
        )

    return ("decision", "Secret-engine endpoint is not classified yet.")


def classify_system(page: str, path: str) -> tuple[str, str]:
    if page == "/api-docs/system/mfa-validate/":
        return (
            "typed",
            "Typed MFA validation helper exists and returns secret-aware auth data.",
        )

    if page == "/api-docs/system/config-ui/":
        return (
            "rejected",
            "Rejected for stable scope: OpenBao removed the embedded UI and the remaining header configuration use case is narrow server administration.",
        )

    if page == "/api-docs/system/monitor/":
        return (
            "rejected",
            "Rejected for current stable scope: sys/monitor is a streaming log endpoint and needs a deliberate streaming API design outside the crate's single-response model.",
        )

    if page == "/api-docs/system/inspect/router/":
        return (
            "rejected",
            "Rejected: router inspection is an internal OpenBao implementation/debug endpoint with no backwards-compatibility guarantee.",
        )

    if page == "/api-docs/system/inspect/request/":
        return (
            "rejected",
            "Rejected: request inspection is underdocumented and either overlaps capability/resultant-ACL helpers or belongs to internal OpenBao debugging.",
        )

    if page in (
        "/api-docs/system/generate-root/",
        "/api-docs/system/generate-recovery-token/",
        "/api-docs/system/decode-token/",
        "/api-docs/system/rekey-recovery-key/",
    ):
        return (
            "typed-gated",
            "Typed operator ceremony helper exists behind operator-ops plus operator-ops-acknowledged.",
        )

    if page == "/api-docs/system/policies-password/":
        return (
            "typed",
            "Typed password policy helpers exist; generated passwords return SecretString.",
        )

    if page == "/api-docs/system/internal-ui-resultant-acl/":
        return (
            "typed",
            "Typed resultant ACL helper exists with an internal-endpoint stability caveat and conservative capability maps.",
        )

    if "in-flight-req" in page:
        return (
            "typed-gated",
            "Typed operator-gated diagnostic helper exists; client token accessors are SecretString and the response map is bounded.",
        )

    if "internal-counters" in page:
        return (
            "rejected",
            "Rejected: internal counter endpoints have no stability guarantee and sys/metrics covers the observability use case.",
        )

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
    addressed = (
        covered_or_partial
        + by_status["raw"]
        + by_status["external"]
        + by_status["rejected"]
    )
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
        "- `rejected`: the endpoint is intentionally not covered by this SDK.",
        "- `planned`: the row has a final pre-`1.0.0` implementation decision but is not implemented yet.",
        "- `decision`: the row needs implementation, rejection, raw-wrapper policy, or external-client policy before `1.0.0`.",
        "",
        "## Summary",
        "",
        f"- Total documented endpoint rows: `{total}`",
        f"- Strict typed coverage: `{covered}/{total}` ({percent(covered, total)})",
        f"- Typed plus partial coverage: `{covered_or_partial}/{total}` ({percent(covered_or_partial, total)})",
        f"- Addressed by typed, partial, raw, external, or rejected policy: `{addressed}/{total}` ({percent(addressed, total)})",
        f"- Planned implementation rows before `1.0.0`: `{by_status['planned']}`",
        f"- Open owner decisions before `1.0.0`: `{by_status['decision']}`",
        "",
        "| Status | Count |",
        "| --- | ---: |",
    ]
    for status in (
        "typed",
        "typed-gated",
        "partial",
        "raw",
        "external",
        "rejected",
        "planned",
        "decision",
    ):
        lines.append(f"| `{status}` | {by_status[status]} |")

    lines.extend(
        [
            "",
            "## Area Totals",
            "",
            "| Area | Total | Typed | Typed gated | Partial | Raw | External | Rejected | Planned | Decision | Strict % |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for area in ("auth", "secret", "system"):
        counts = by_area[area]
        area_total = sum(counts.values())
        area_covered = counts["typed"] + counts["typed-gated"]
        lines.append(
            f"| `{area}` | {area_total} | {counts['typed']} | {counts['typed-gated']} | "
            f"{counts['partial']} | {counts['raw']} | {counts['external']} | "
            f"{counts['rejected']} | {counts['planned']} | {counts['decision']} | {percent(area_covered, area_total)} |"
        )

    lines.extend(
        [
            "",
            "## Pages With Non-Typed Rows",
            "",
            "| Page | Typed | Typed gated | Partial | Raw | External | Rejected | Planned | Decision |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for page in sorted(by_page):
        counts = by_page[page]
        if not any(
            counts[status]
            for status in ("partial", "raw", "external", "rejected", "planned", "decision")
        ):
            continue
        lines.append(
            f"| [{page}]({DOCS_ROOT}{page}) | {counts['typed']} | {counts['typed-gated']} | "
            f"{counts['partial']} | {counts['raw']} | {counts['external']} | {counts['rejected']} | {counts['planned']} | {counts['decision']} |"
        )

    lines.extend(
        [
            "",
            "## Required Follow-Up",
            "",
            "- Identity OIDC token backend config, signing key CRUD/rotate, role CRUD/list, signed token generation, token introspection, discovery metadata, default JWKS reads, OIDC provider/scope/client/assignment admin, named-provider discovery, named-provider JWKS, MFA method management, MFA TOTP generation/admin actions, and MFA login enforcement helpers are implemented in `0.10.0`.",
            "- Named-provider OIDC browser protocol rows (`authorize`, `token`, `userinfo`) are classified as `external` because they belong to a dedicated OIDC client library.",
            "- `sys/mfa/validate` is implemented in `0.10.0` because MFA-enforced login flows cannot complete without it.",
            "- Transit wrapping-key, import/import-version, BYOK export, soft-delete/restore, cache/global config, CSR, and certificate install rows are implemented in `0.11.0`; the optional `transit-import` wrapping helper prepares OpenBao BYOK blobs with AES-KWP/RSA-OAEP behind feature-gated `openssl` and `aes-kw` dependencies.",
            "- PKI default issuer/key config, named-issuer issue/sign, root rotate/replace, standalone key generation, multi-issuer root/intermediate generation, revoke-with-key, cluster config, auto-tidy config, operator-gated sign-verbatim rows, and current-doc struct-field expansion are implemented in `0.12.0`; Tier 2 revocation/CEL/cross-sign/delta-CRL work is implemented in `0.13.0`; unauthenticated public CA/CRL/cert and OCSP protocol reads are classified as `external`.",
            "- System generate-root/recovery-token, decode-token, password policies, resultant ACL, legacy recovery-key rekey, and in-flight request inspection are implemented in `0.14.0`; config-ui, monitor streaming, internal router inspection, request inspection, and internal counters are classified as `rejected`.",
            "- `0.15.0` was the closure release where planned endpoint rows were implemented or intentionally reclassified before `1.0.0`; the `1.x` stable line freezes the addressed endpoint boundary.",
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
