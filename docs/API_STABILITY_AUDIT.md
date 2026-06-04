# API Stability Audit

This document tracks the pre-stable API audit before the first stable `1.0.0`
release. The goal is to avoid accidental public API commitments while keeping
the crate useful for production trials.

## Status

- Release line: `0.15.0`
- Started: 2026-06-03
- Audit status: endpoint-scope closure completed for the `0.15.0` stable
  candidate; the OpenBao `2.5.x` endpoint matrix has zero `planned` and zero
  `decision` rows.
- Stable target: `1.0.0`
- Planning assumption: the endpoint matrix expanded the pre-`1.0` plan through
  `0.15.0`. Use `0.9.0` for stabilization foundations, `0.10.0` through
  `0.14.0` for remaining endpoint families, `0.15.0` for closure, and
  `1.0.0` for the stable freeze. After `1.0.0`, assume only `1.0.x`
  maintenance and security fixes.
- Coverage target: no OpenBao `2.5.x` endpoint row remains classified as
  `planned` or `decision` before `1.0.0`; not every row must become first-class
  typed if a raw, external, partial, gated, or rejected boundary is safer.

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

## Pre-Stable Closure Work

The following items were implementation commitments during the pre-stable audit
and now have current API or documentation coverage:

- explicit opt-in retry/backoff with single-shot requests as the default;
- shared pagination for non-secret string list endpoints only;
- bootstrap convergence for PKI roles and Identity entities/groups;
- representative serde response fixtures for public API responses;
- fuzz targets for path validation, API error decoding, and response envelope
  parsing;
- public API audit covering names, constructors, feature gates, secret
  handling, docs, examples, and semver expectations;
- migration docs from older `openbao` versions, `vaultrs`, and raw `reqwest`
  wrappers;
- advisory quantum-readiness design note without post-quantum safety claims.

## API Areas

| Area | Current Posture | Planned Decision |
| --- | --- | --- |
| Client construction | Typestate client, env construction, shared client, strict TLS defaults. | Reviewed for `0.9.0`; no compatibility aliases are needed before `1.0.0` unless a concrete downstream migration issue is found. |
| Error handling | Sanitized API errors and common predicates. | Reviewed for `0.9.0`; keep helpers value-free and do not expose raw response bodies. |
| Retry/backoff | `RetryPolicy`, `RetryableMethod`, and `Client::request_json_with_retry` provide explicit exponential backoff with bounded jitter for caller-approved idempotent raw JSON requests. Retryable methods are limited to GET, HEAD, and OpenBao LIST. | Keep default typed helpers single-shot to avoid retrying non-idempotent writes by accident. Do not add global/background retry middleware before `1.0.0`. |
| Token lifecycle | Typed create/create-orphan, lookup, accessor lookup/list, renew/renew-accessor, revoke/revoke-accessor, role, tidy helpers, plus `RenewalHint` timing guidance. | Reject background auto-renewal for stable scope. No remaining token endpoint decision rows. |
| AppRole | Login, role CRUD, delegated documented role-property read/write/delete, RoleID, SecretID, SecretID accessor, custom SecretID, and tidy helpers are typed. | No remaining AppRole endpoint decision rows in the OpenBao `2.5.x` matrix. The current docs do not publish delegated paths for `local_secret_ids`, `token_explicit_max_ttl`, `token_num_uses`, or `token_type`; those remain full-role fields unless upstream documents narrow endpoints. |
| Lease lifecycle | Exact lookup/renew/revoke plus prefix revoke/count/tidy and `RenewalHint` timing guidance. | Reject background lease tracking and `LeaseHandle` wrappers for stable scope; applications own renewal loops, renewal-failure policy, and shutdown ordering. |
| Pagination | `ListPageOptions` provides a shared, bounded request shape for non-secret string-list pagination and existing paginated list helpers use it internally. | Keep token accessors, lease IDs, and other secret-bearing list values on dedicated helpers so generic pagination does not erase secret handling. |
| Admin bootstrap | Common service bootstrap and preview now include KV v2/Transit/PKI/database/SSH mount convergence, Transit keys, ACL policies, KV v2 values, PKI/database/SSH/AppRole role convergence, Identity entity/group convergence, and explicit credential issuance. | Reject PKI CA setup, database connection configuration, SSH CA setup, and KV v1 convergence for stable bootstrap scope. |
| Custom plugins | Raw JSON transport and typed wrapper docs exist; `PluginMount`, public path validators, and bounded string-list helpers provide the same safety rails used internally. | Reject generic `Plugin`/`SecretEngine` traits, codegen, and macro approaches for stable scope; plugin schemas are deployment-specific. |
| Identity | Entity/group/alias lifecycle, lookup, merge, OIDC admin/discovery/token/introspection, MFA method/login-enforcement management, and MFA login validation are implemented. | `0.10.0` resolves the Identity OIDC/MFA implementation scope; keep named-provider `/authorize`, `/token`, and `/userinfo` browser protocol flows external. |
| PKI | Core CA, issuer/key, role, tidy, ACME config/EAB, issue/sign/revoke helpers, default issuer/key config, named-issuer issue/sign, root rotate/replace, key generation, revoke-with-key, cluster/auto-tidy config, current-doc role/generation/CRL/tidy fields, revocation/CRL management, CEL roles and CEL issue/sign, named-issuer sign-intermediate, delta CRL rotation, operator-gated sign-verbatim/sign-self-issued/cross-sign/sign-revocation-list helpers, and operator-gated default root deletion with explicit confirmation are typed. | `0.12.0` resolves the Tier 1 PKI multi-issuer and authority lifecycle scope, and `0.13.0` resolves the Tier 2 PKI specialized-flow scope. `DELETE /pki/root` remains resolved as `Pki::delete_root(PkiRootDeletion::confirm())`. Unauthenticated public CA/cert/CRL reads plus OCSP remain external protocol/public-distribution endpoints, and full ACME account/order/authorization/challenge flows stay external. |
| Transit | Lifecycle, batch, byte, signing, wrapping-key, import/import-version, BYOK export, soft-delete/restore, cache/global config, CSR, and certificate-install helpers are implemented. Import wrappers accept pre-wrapped `SecretString` ciphertext or public-key-only import material with non-empty constructors and redacted `Debug`; raw private or symmetric key bytes stay outside default endpoint wrappers. The optional `transit-import` helper performs AES-KWP/RSA-OAEP software wrapping behind feature-gated `openssl` and `aes-kw` dependencies. | Keep the helper documented as an ergonomic software helper with no OpenBao, HSM, FIPS, certification, or post-quantum security claims. |
| System backend | Broad sys coverage with operator gates. Matrix now rejects config-ui, sys/monitor streaming, internal router inspection, internal counters, and internal request inspection; generate-root/recovery-token/decode-token, password policies, resultant ACL, legacy recovery-key rekey, and in-flight request inspection are implemented. | `0.14.0` resolves the remaining system backend endpoint decisions: operator ceremonies stay behind `operator-ops` plus `operator-ops-acknowledged`, password policies/resultant ACL are ungated, and in-flight request inspection uses `SecretString` accessors with bounded maps. |
| Tracing | Optional `tracing` feature instruments the shared HTTP dispatch point with method, validated path, and status only. Paths can contain opaque operational IDs such as lease or entity identifiers, so debug traces are operationally sensitive even though bodies, tokens, and namespaces are not logged. | Reject OpenTelemetry SDK dependencies and custom request hooks for stable scope. Defer W3C `traceparent` propagation past `1.0.0` unless a concrete OpenBao-side correlation use case emerges. |
| Seal watcher | Readiness polling, seal status, runtime-neutral `wait_until_unsealed_with_delay`, and `tokio-helpers`-gated `wait_until_unsealed` helpers exist. | Reject request-level seal back-pressure because retry, queueing, and concurrency policy belong to the application or middleware layer. |
| Response wrapping | Sys wrapping lookup/wrap/unwrap/rewrap helpers exist, and `Client::wrapping` provides `WrappingContext` plus `WrappedResponse<T>` for ordinary typed JSON response wrapping with redacted wrapping tokens. | Per-engine wrapped method duplication is rejected; callers use the wrapping context and keep delivery/recipient policy outside the SDK. |
| ACL policy builder | Narrow typed path-rule builder exists for known OpenBao capabilities, with wrapping-TTL constraints and helper variants for common wrapped-response policies. | Reject `allowed_parameters`, `denied_parameters`, and `required_parameters` generation because correct output requires a full HCL value serializer. |
| HTTP/2 | Default builds are HTTP/1.1-only because reqwest default features are disabled. | Reject a runtime `OpenBaoConfig` knob. Add non-default `http2 = ["reqwest/http2"]`; when enabled, TLS ALPN negotiates HTTP/2 where OpenBao supports it and falls back to HTTP/1.1. Reject HTTP/3 for stable scope. |
| Fuzz/fixtures | Unit and HTTP mock coverage are broad; `0.9.0` adds representative serde fixtures and fuzz targets for path validation, API error decoding, and response envelope parsing. | Keep fixtures and fuzz targets updated when new public response families are added. |
| Quantum readiness | `docs/QUANTUM_READINESS.md` records the advisory-only posture. | No API may claim post-quantum safety until OpenBao exposes stable primitives. |

## Known Limitations Decision Register

This section resolves the `Known Limitations` sections from the historical
release notes. Historical release notes remain unchanged, but each limitation
must now have an explicit current decision.

| Source | Limitation | Current Decision |
| --- | --- | --- |
| `0.1.0` | KV v2 metadata, token lifecycle, and Transit were incomplete. | Resolved by later releases. |
| `0.1.0` to `0.5.0` | Exact certificate/public-key pinning was not implemented. | Rejected for stable scope. Use `OpenBaoConfig::only_root_certificates` or `OPENBAO_CACERT` plus `OPENBAO_TLS_ROOTS_ONLY=true` with an internal CA or self-signed OpenBao certificate. Leaf and SPKI pinning are operationally brittle and `reqwest` has no portable pinning API across TLS backends. |
| `0.2.0` and `0.3.0` | HTTP/TLS/kernel/device buffers are outside crate zeroization control after handoff to `reqwest`. | Permanent documented boundary. No crate can guarantee zeroization for external transport buffers. |
| `0.3.0` | Transit batch/export/backup/restore were not typed. | Resolved in `0.8.0`. BYOK/import HTTP wrappers are resolved in `0.11.0`; default endpoint wrappers accept pre-wrapped `SecretString` ciphertext or public-key-only import material, and raw private or symmetric key bytes stay outside those wrappers. Optional software wrapping is available only behind the non-default `transit-import` feature. |
| `0.3.0` | Plugin OCI initialization and reload-status endpoints were not typed. | Defer; plugin schemas and OCI deployment workflows are operator-specific. Keep `Client::request_json` and documented custom wrapper pattern. |
| `0.3.0` | Production init/unseal/rekey/rotate were planned. | Resolved behind `operator-ops` and `operator-ops-acknowledged`. |
| `0.4.0` | Full ACME account/order/authorization/challenge flows were not implemented. | Intentionally out of scope; use dedicated ACME clients with the directory URL/config helpers. |
| `0.4.0` | `Kv2ServiceConfig` accepts flat string maps. | Intentional. Use typed structs for nested JSON. |
| `0.5.0` | OIDC browser/device flows were not implemented. | Resolved in `0.8.0`. |
| `0.5.0` | Full JOSE/JWKS construction was out of scope. | Still out of scope; use Transit signing helpers with an application JWT/JWK library. |
| `0.6.0` | Raw unauthenticated SSH public-key reads were not typed. | Intentional; use an external HTTP client for unauthenticated text/plain public-key endpoints. |
| `0.6.0` | ACL builder did not cover advanced ACL parameter/wrapping constraints. | Wrapping TTL constraints are resolved in `0.15.0`. Keep direct `PolicyWriteRequest` for parameter constraints because safe generation requires a complete HCL value serializer. |
| `0.7.0` | AppRole delegated per-property endpoints were not typed. | Resolved in `0.9.0` for every documented OpenBao `2.5.x` delegated property row. |
| `0.7.0` | Custom plugin APIs were not modeled as a generic trait. | Intentional; plugin schemas are deployment-specific. Keep local typed wrappers. |
| `0.7.0` | Bootstrap preview, typed capabilities, list traits, and timestamps were planned. | Resolved in `0.8.0`. |
| `0.7.0` | Broader bootstrap convergence for LDAP/RabbitMQ/Kubernetes secrets/Identity remained planned. | PKI role and Identity entity/group convergence landed in `0.9.0`; selective PKI/database/SSH mount and role convergence lands in `0.15.0`; CA setup, connection configuration, and KV v1 convergence remain rejected in the bootstrap layer. |
| `0.8.0` | Kerberos SPNEGO acquisition is left to platform tooling. | Intentional; the crate accepts the documented base64 token and does not embed Kerberos client stacks. |
| `0.8.0` | Retry, auto-renewal, lease tracking, pagination, Identity OIDC/MFA, PKI root/named issuer, tracing, seal watcher, HTTP/2, and secret wrappers needed decisions. | Resolved in the API Areas table above. Background auto-renewal, background lease tracking, request-level seal back-pressure, runtime HTTP/2 knobs, and per-engine wrapped method duplication are rejected for stable scope. |

## Deferred Work Template

When moving a feature out of the stable scope, record:

- user-facing workflow affected;
- whether it is rejected for stable scope, becomes a permanent external
  boundary, or is reserved for a future `1.x` feature discussion;
- why the feature is unsafe, unstable, or too broad for the stable API;
- whether `Client::request_json` can reach the endpoint safely meanwhile;
- intended future decision point, if any;
- security considerations for callers implementing it locally.

## Release Exit Criteria

- All public modules have been reviewed for secret handling, builder
  consistency, feature gates, and semver expectations.
- Migration guide covers `0.1` through `0.15`, `vaultrs`, bespoke `reqwest`
  wrappers, and the pre-stable retry/pagination/bootstrap additions.
- Retry, token auto-renewal, lease tracking, pagination, Identity OIDC/MFA,
  Transit advanced key management, PKI advanced scope, system completion,
  tracing, HTTP/2, fuzzing, fixtures, and quantum-readiness have explicit
  decisions in this document or linked docs.
- Endpoint matrix has zero `planned` or `decision` rows.
- README examples and docs examples compile.
- The real OpenBao integration gate passes with default features.
- A pentest report for the exact release candidate has been reviewed and
  resolved or recorded before tagging.
- No item remains classified as open-ended future work.
