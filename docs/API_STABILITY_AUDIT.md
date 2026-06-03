# API Stability Audit

This document tracks the `0.9.0` audit before the first stable `1.0.0`
release. The goal is to avoid accidental public API commitments while keeping
the crate useful for production trials.

## Status

- Release line: `0.9.0`
- Started: 2026-06-03
- Audit status: in progress
- Stable target: `1.0.0`

## Stabilization Rules

- Public types that expose secret material must continue using `SecretString`
  or an equivalent secret-aware type.
- Public request builders must validate local path, duration, CIDR, header,
  TLS, and size constraints before request dispatch when validation can be done
  without weakening OpenBao server-side policy.
- New public helpers must preserve existing HTTPS, redirect, namespace,
  response-size, decode-sanitization, and bounded-deserialization guarantees.
- Feature additions should remain opt-in when they pull new dependencies,
  background tasks, alternate TLS behavior, or operator-risk APIs.
- Generic ergonomics must not erase secret-specific handling. In particular,
  token accessors, lease IDs, Transit plaintext/ciphertext, PKI private keys,
  raw storage values, and backup/export material must not be converted into
  ordinary loggable strings.

## API Areas

| Area | Current Posture | `0.9.0` Decision Needed |
| --- | --- | --- |
| Client construction | Typestate client, env construction, shared client, strict TLS defaults. | Audit builder names and decide whether any aliases are needed before `1.0`. |
| Error handling | Sanitized API errors and common predicates. | Decide whether additional predicates or structured OpenBao error codes are needed. |
| Retry/backoff | Only readiness polling retries temporary failures. | Implement an explicit retry policy or document deferral with idempotency rules. |
| Token lifecycle | Typed create/lookup/renew/revoke/role/tidy helpers. | Decide token auto-renewal API shape or defer to caller-owned scheduling. |
| Lease lifecycle | Exact lookup/renew/revoke plus prefix revoke/count. | Decide lease tracker API shape or defer to explicit lease handles. |
| Pagination | Endpoint-specific helpers exist where implemented. | Implement a shared abstraction or document why endpoint-specific helpers remain safer. |
| Admin bootstrap | Common service bootstrap and preview are implemented. | Decide PKI role and Identity convergence scope for `1.0`. |
| Identity | Entity/group/alias lifecycle, lookup, and merge are implemented. | Decide OIDC provider and MFA management scope for `1.0`. |
| PKI | Core CA, issuer/key, role, tidy, ACME config/EAB, issue/sign/revoke helpers. | Decide root rotate/replace and named issuer issue/sign scope. |
| Transit | Lifecycle, batch, byte, and signing helpers. | Audit public request constructors and byte-helper feature boundaries. |
| System backend | Broad sys coverage with operator gates. | Audit operator-gated APIs for names, feature gates, and docs before `1.0`. |
| Tracing | Not implemented. | Decide OpenTelemetry/tracing feature shape or defer. |
| HTTP/2 | Not exposed as public configuration. | Decide whether a public transport knob is needed. |
| Fuzz/fixtures | Unit and HTTP mock coverage are broad. | Add or defer fuzz targets and public serde fixtures. |
| Quantum readiness | Advisory roadmap only. | Add a design note without claiming current post-quantum safety. |

## Deferred Work Template

When deferring a feature from `0.9.0`, record:

- user-facing workflow affected;
- why the feature is unsafe, unstable, or too broad for the release;
- whether `Client::request_json` can reach the endpoint safely meanwhile;
- intended `1.0` or post-`1.0` decision;
- security considerations for callers implementing it locally.

## Release Exit Criteria

- All public modules have been reviewed for secret handling, builder
  consistency, feature gates, and semver expectations.
- Migration guide covers `0.1` through `0.9`, `vaultrs`, and bespoke
  `reqwest` wrappers.
- Retry, token auto-renewal, lease tracking, pagination, PKI root/named issuer
  scope, Identity OIDC/MFA scope, tracing, HTTP/2, fuzzing, fixtures, and
  quantum-readiness have explicit decisions in this document or linked docs.
- README examples and docs examples compile.
- The real OpenBao integration gate passes with default features.
- A pentest report for the exact release candidate has been reviewed and
  resolved or recorded before tagging.
