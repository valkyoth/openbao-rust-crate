# API Stability Audit

This document tracks the `0.9.0` audit before the first stable `1.0.0`
release. The goal is to avoid accidental public API commitments while keeping
the crate useful for production trials.

## Status

- Release line: `0.9.0`
- Started: 2026-06-03
- Audit status: decision register started
- Stable target: `1.0.0`
- Planning assumption: `1.0.0` is the final planned feature release. Use
  `0.10.0` only as an optional completion buffer before `1.0.0`; after
  `1.0.0`, assume only `1.0.x` maintenance and security fixes.

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

| Area | Current Posture | `0.9.0` Decision |
| --- | --- | --- |
| Client construction | Typestate client, env construction, shared client, strict TLS defaults. | Audit names in `0.9.0`; no compatibility aliases until a concrete downstream migration issue is found. |
| Error handling | Sanitized API errors and common predicates. | Audit predicates in `0.9.0`; add only value-free helpers that do not expose raw response bodies. |
| Retry/backoff | Only readiness polling retries temporary failures. | Implement an explicit opt-in retry policy in `0.9.0`; default requests remain single-shot to avoid retrying non-idempotent writes. |
| Token lifecycle | Typed create/lookup/renew/revoke/role/tidy helpers. | Do not add background auto-renewal in `0.9.0`; document caller-owned scheduling and consider explicit renewal handles after the retry policy lands. |
| Lease lifecycle | Exact lookup/renew/revoke plus prefix revoke/count. | Do not add a background lease tracker in `0.9.0`; implement or document explicit lease-handle ergonomics without hidden tasks. |
| Pagination | Endpoint-specific helpers exist where implemented. | Implement a shared request/response pagination shape in `0.9.0` for non-secret string lists only; secret accessor lists stay dedicated. |
| Admin bootstrap | Common service bootstrap and preview are implemented. | Implement PKI role and Identity entity/group convergence in `0.9.0` where existing typed reads/writes make comparison safe. |
| Identity | Entity/group/alias lifecycle, lookup, and merge are implemented. | Identity OIDC provider/key/role/token and MFA management must be implemented, rejected, or moved to the optional `0.10.0` buffer before `1.0.0`; no post-`1.0` feature promise. |
| PKI | Core CA, issuer/key, role, tidy, ACME config/EAB, issue/sign/revoke helpers. | Implement or explicitly reject root rotate/replace and named issuer issue/sign helpers in `0.9.0` after checking current OpenBao docs. |
| Transit | Lifecycle, batch, byte, and signing helpers. | Audit constructors and `transit-bytes` boundaries in `0.9.0`; no default dependency growth. |
| System backend | Broad sys coverage with operator gates. | Keep operator-risk APIs gated; audit names and docs in `0.9.0`. |
| Tracing | Not implemented. | Reject default OpenTelemetry dependency growth for `1.0`; decide in `0.9.0` whether a zero-dependency hook is useful, otherwise document no tracing API in stable scope. |
| Seal watcher | Readiness polling and seal status helpers exist. | Defer background seal watchers; document polling patterns because watchers need runtime/back-pressure policy. |
| HTTP/2 | Not exposed as public configuration. | Decide in `0.9.0` whether to expose a transport knob; otherwise document reqwest defaults as the stable policy. |
| Fuzz/fixtures | Unit and HTTP mock coverage are broad. | Add `0.9.0` fuzz targets for path validation, API error decoding, and response envelopes; add serde fixtures for representative public responses. |
| Quantum readiness | Advisory roadmap only. | Add a design note in `0.9.0`; no API may claim post-quantum safety until OpenBao exposes stable primitives. |

## Known Limitations Decision Register

This section resolves the `Known Limitations` sections from the historical
release notes. Historical release notes remain unchanged, but each limitation
must now have an explicit current decision.

| Source | Limitation | Current Decision |
| --- | --- | --- |
| `0.1.0` | KV v2 metadata, token lifecycle, and Transit were incomplete. | Resolved by later releases. No `0.9.0` action. |
| `0.1.0` to `0.5.0` | Exact certificate/public-key pinning was not implemented. | Decide before `1.0.0`; likely reject for stable scope because custom CA roots and root-only trust stores are safer rotation controls. |
| `0.2.0` and `0.3.0` | HTTP/TLS/kernel/device buffers are outside crate zeroization control after handoff to `reqwest`. | Permanent documented boundary. No crate can guarantee zeroization for external transport buffers. |
| `0.3.0` | Transit batch/export/backup/restore were not typed. | Resolved in `0.8.0`. BYOK/import remains tied to current OpenBao docs review in `0.9.0`. |
| `0.3.0` | Plugin OCI initialization and reload-status endpoints were not typed. | Defer; plugin schemas and OCI deployment workflows are operator-specific. Keep `Client::request_json` and documented custom wrapper pattern. |
| `0.3.0` | Production init/unseal/rekey/rotate were planned. | Resolved behind `operator-ops` and `operator-ops-acknowledged`. |
| `0.4.0` | Full ACME account/order/authorization/challenge flows were not implemented. | Intentionally out of scope; use dedicated ACME clients with the directory URL/config helpers. |
| `0.4.0` | `Kv2ServiceConfig` accepts flat string maps. | Intentional. Use typed structs for nested JSON. |
| `0.5.0` | OIDC browser/device flows were not implemented. | Resolved in `0.8.0`. |
| `0.5.0` | Full JOSE/JWKS construction was out of scope. | Still out of scope; use Transit signing helpers with an application JWT/JWK library. |
| `0.6.0` | Raw unauthenticated SSH public-key reads were not typed. | Intentional; use an external HTTP client for unauthenticated text/plain public-key endpoints. |
| `0.6.0` | ACL builder did not cover advanced ACL parameter/wrapping constraints. | Keep direct `PolicyWriteRequest` for advanced policies; do not expand builder until a safe typed representation is designed. |
| `0.7.0` | AppRole delegated per-property endpoints were not typed. | Defer; full role update covers the common case, and delegated single-property ACLs can use `Client::request_json`. |
| `0.7.0` | Custom plugin APIs were not modeled as a generic trait. | Intentional; plugin schemas are deployment-specific. Keep local typed wrappers. |
| `0.7.0` | Bootstrap preview, typed capabilities, list traits, and timestamps were planned. | Resolved in `0.8.0`. |
| `0.7.0` | Broader bootstrap convergence for LDAP/RabbitMQ/Kubernetes secrets/Identity remained planned. | Implement PKI role and Identity entity/group convergence in `0.9.0`; decide before `1.0.0` whether engine-specific convergence is rejected or moved to `0.10.0`. |
| `0.8.0` | Kerberos SPNEGO acquisition is left to platform tooling. | Intentional; the crate accepts the documented base64 token and does not embed Kerberos client stacks. |
| `0.8.0` | Retry, auto-renewal, lease tracking, pagination, Identity OIDC/MFA, PKI root/named issuer, tracing, seal watcher, HTTP/2, and secret wrappers needed decisions. | Decisions are recorded in the API Areas table above and must be reflected in `0.9.0` release notes before tag. |

## Deferred Work Template

When moving a feature out of `0.9.0`, record:

- user-facing workflow affected;
- whether it moves to optional `0.10.0`, lands in `1.0.0`, is rejected for
  stable scope, or is a permanent external boundary;
- why the feature is unsafe, unstable, or too broad for `0.9.0`;
- whether `Client::request_json` can reach the endpoint safely meanwhile;
- intended pre-`1.0` decision point;
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
- No item remains classified as open-ended future work.
