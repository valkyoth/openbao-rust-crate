# API Stability Audit

This document records the historical stable `1.x` API audit, its `2.0.0`
finalization, and the compatible `2.1.x` OpenBao 2.6 extension. The goal is to
make the public API commitments and security boundaries explicit.

## Status

- Release line: `1.x` historical audit; stable `2.1.x`
- Started: 2026-06-03
- Audit status: stable endpoint API frozen at `1.0.0`; `1.0.1` and `1.0.2`
  are compatible maintenance patches, and `1.1.0` is a reviewed
  security-buffer type migration from `zeroize::Zeroizing<Vec<u8>>` to
  `sanitization::SecretVec`. The OpenBao `2.5.x` endpoint matrix has zero
  `planned` and zero `decision` rows.
- Stable target: reached by `1.0.0`.
- Planning assumption: after `1.0.0`, assume stable maintenance, security
  fixes, OpenBao compatibility fixes, documentation corrections, and reviewed
  security-focused minor migrations.
- Major boundary: `2.0.0` combines multi-version OpenBao compatibility with
  intentionally breaking raw-transport, JWT/OIDC secret-metadata, and base-URL
  hardening. See the migration guide before updating from 1.x.
- Final coverage: the compatibility union has 691 logical operation identities
  and 15,893 operation/profile cells. All operations available in supported
  profiles are typed, typed-gated, or security-blocked. The current `2.6.1`
  profile has 689 documented operations: 594 typed, 93 typed-gated, and 2
  security-blocked.
- Evidence boundary: contract and serde evidence is complete; live integration
  coverage is representative rather than an endpoint-by-endpoint execution
  claim.
- Release evidence: signed `v2.0.0` passed GitHub CI, CodeQL, the full
  21-release compatibility workflow, and the exact-commit pentest. `2.0.1`
  corrects release documentation without changing the compatibility contract.
  `2.0.2` narrows the crates.io source package while retaining complete release
  evidence in the corresponding signed Git tag. `2.1.0` adds the exact
  OpenBao `2.6.0` profile and its reviewed API additions without changing the
  21 historical profiles. `2.1.1` updates `sanitization` to `2.0.3` and
  `base64-ng` to `1.3.9`; it also makes a documented compatibility exception
  for the non-default `memory-lock` feature so authenticated clients retain
  tokens in fail-closed locked mapped storage with required random canaries.
  Authentication tokens have a 16 KiB secure default limit, an explicit
  configuration override, and a 1 MiB hard ceiling. Direct mapped-token input
  must report an active OS lock; canaries are not an attacker-resistant
  integrity boundary. `2.1.2` appends exact OpenBao `2.6.1`, typed ACL policy
  PATCH, and acknowledged JWT CEL PATCH after the upstream constraint-
  preservation fix without changing historical profile behavior. It also
  makes a security-driven source correction from ordinary string database-role
  credential maps to `DatabaseCredentialConfig` with `SecretString` values
  because those maps can hold PEM CA private keys.
- OpenBao 2.6 closure: no operation is planned, pending, raw, external, or
  deferred. Of 689 operations documented for exact `2.6.1`, 594 are typed, 93
  are typed-gated, and two are security-blocked because the workflow prefix
  handlers remain unsafe. JWT CEL PATCH is separately blocked only on exact
  `2.6.0`, where the server drops claim constraints.

## Stabilization Rules

- Public types that expose secret material must continue using `SecretString`,
  `SecretVec`, or an equivalent secret-aware type.
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
| Client construction | Typestate client, env construction, shared client, strict TLS defaults, and `2.0.0` opt-in exact/range/automatic/assumed server-version policies with per-client verification caching. Every typed helper uses the immutable operation dispatcher, which selects and validates method/path/query shape before serialization. | Existing constructors remain offline and unverified for migration compatibility; strict verification is recommended. A range probe observes one backend, not a mixed cluster's capability intersection. Assumed and acknowledged-newer reports must never be presented as verified. |
| Error handling | Sanitized API errors and common predicates, including typed unsupported-version and unsupported-capability failures carrying only stable version values and secret-free logical endpoint IDs. | Keep helpers value-free and do not expose raw response bodies, concrete paths, query values, URLs, or credentials. |
| Retry/backoff | `RetryPolicy`, `RetryableMethod`, and `Client::request_json_with_retry` provide explicit exponential backoff with bounded jitter for caller-approved idempotent raw JSON requests. Retryable methods are limited to GET, HEAD, and OpenBao LIST. | Keep default typed helpers single-shot to avoid retrying non-idempotent writes by accident. Do not add global/background retry middleware before `1.0.0`. |
| Token lifecycle | Typed create/create-orphan, lookup, accessor lookup/list, renew/renew-accessor, revoke/revoke-accessor, role, tidy helpers, plus `RenewalHint` timing guidance. | Reject background auto-renewal for stable scope. No remaining token endpoint decision rows. |
| AppRole | Login, role CRUD, delegated documented role-property read/write/delete, RoleID, SecretID, SecretID accessor, custom SecretID, and tidy helpers are typed. | No remaining AppRole endpoint decision rows in the OpenBao `2.5.x` matrix. The current docs do not publish delegated paths for `local_secret_ids`, `token_explicit_max_ttl`, `token_num_uses`, or `token_type`; those remain full-role fields unless upstream documents narrow endpoints. |
| Lease lifecycle | Exact lookup/renew/revoke plus prefix revoke/count/tidy and `RenewalHint` timing guidance. | Reject background lease tracking and `LeaseHandle` wrappers for stable scope; applications own renewal loops, renewal-failure policy, and shutdown ordering. |
| Pagination | `ListPageOptions` provides a shared, bounded request shape for non-secret string-list pagination and existing paginated list helpers use it internally. | Keep token accessors, lease IDs, and other secret-bearing list values on dedicated helpers so generic pagination does not erase secret handling. |
| Admin bootstrap | Common service bootstrap and preview now include KV v2/Transit/PKI/database/SSH mount convergence, Transit keys, ACL policies, KV v2 values, PKI/database/SSH/AppRole role convergence, Identity entity/group convergence, and explicit credential issuance. | Reject PKI CA setup, database connection configuration, SSH CA setup, and KV v1 convergence for stable bootstrap scope. |
| Custom plugins | Raw JSON transport and typed wrapper docs exist; `PluginMount`, public path validators, and bounded string-list helpers provide the same safety rails used internally. | Reject generic `Plugin`/`SecretEngine` traits, codegen, and macro approaches for stable scope; plugin schemas are deployment-specific. |
| Identity | Entity/group/alias lifecycle, lookup, merge, OIDC admin/discovery/token/introspection, MFA method/login-enforcement management, and MFA login validation are implemented. | `0.10.0` resolves the Identity OIDC/MFA implementation scope; keep named-provider `/authorize`, `/token`, and `/userinfo` browser protocol flows external. |
| JWT/OIDC auth | Configuration, ordinary roles, browser/direct/device helpers, and OpenBao 2.6 JWT CEL role/login contracts are typed. CEL source uses `SecretString`; CEL success bodies are decoded from sanitizing storage and failure bodies are discarded because server errors can echo policy source. | Keep CEL role writes and PATCH acknowledgement-gated, exact 2.6.0 CEL PATCH security-blocked, and callback query credentials behind `oidc-get-callback-acknowledged`. |
| PKI | Core CA, issuer/key, role, tidy, ACME administration, issue/sign/revoke, public CA/certificate/CRL reads, raw OCSP transport, authority lifecycle, CEL, and gated destructive/signing operations are typed. | `DELETE /pki/root` requires `PkiRootDeletion::confirm()`. ACME account/order/authorization/challenge state machines remain a dedicated ACME client's responsibility, while all OpenBao HTTP operation identities have typed or typed-gated transport coverage. |
| Transit | Lifecycle, batch, byte, signing, wrapping-key, import/import-version, BYOK export, soft-delete/restore, cache/global config, CSR, and certificate-install helpers are implemented. Import wrappers accept pre-wrapped `SecretString` ciphertext or public-key-only import material with non-empty constructors and redacted `Debug`; raw private or symmetric key bytes stay outside default endpoint wrappers. The optional `transit-import` helper performs AES-KWP/RSA-OAEP software wrapping behind feature-gated `openssl` and `aes-kw` dependencies. | Keep the helper documented as an ergonomic software helper with no OpenBao, HSM, FIPS, certification, or post-quantum security claims. |
| System backend | Version-aware sys coverage includes ACL, lease, auth-mount, rotation, bounded monitor streaming with a 64-chunk per-poll work budget, exact-length `raft-stream` restore helpers, and gated internal diagnostics. | Operator ceremonies stay behind `operator-ops` plus `operator-ops-acknowledged`; unstable internals additionally require `unstable-internal-ops-acknowledged`. Generated-token decoding is local because OpenBao documents no HTTP decode endpoint. |
| Tracing | Optional `tracing` feature instruments the shared HTTP dispatch point with method, validated path, and status only. Paths can contain opaque operational IDs such as lease or entity identifiers, so debug traces are operationally sensitive even though bodies, tokens, and namespaces are not logged. | Reject OpenTelemetry SDK dependencies and custom request hooks for stable scope. Defer W3C `traceparent` propagation past `1.0.0` unless a concrete OpenBao-side correlation use case emerges. |
| Seal watcher | Readiness polling, seal status, runtime-neutral retry-budget helpers, and strict-overall-deadline `tokio-helpers`-gated `wait_ready` and `wait_until_unsealed` helpers exist. | Reject request-level seal back-pressure because retry, queueing, and concurrency policy belong to the application or middleware layer. |
| Response wrapping | Sys wrapping lookup/wrap/unwrap/rewrap helpers exist, and `Client::wrapping` provides `WrappingContext` plus `WrappedResponse<T>` for ordinary typed JSON response wrapping with redacted wrapping tokens. `try_unwrap(&mut self)` preserves local ownership across cancellation and marks successful redemption consumed. | Per-engine wrapped method duplication is rejected; callers use the wrapping context, avoid automatic retry after outcome-unknown failures, and keep delivery/recipient policy outside the SDK. The deprecated consuming `unwrap(self)` remains only for `2.x` compatibility and must be removed in the next semver-major release. |
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
| `0.6.0` | Raw unauthenticated SSH public-key reads were not typed. | Resolved for `2.0.0` through the token-free, bounded `SshPublic` handle. |
| `0.6.0` | ACL builder did not cover advanced ACL parameter/wrapping constraints. | Wrapping TTL constraints are resolved in `0.15.0`. Keep direct `PolicyWriteRequest` for parameter constraints because safe generation requires a complete HCL value serializer. |
| `0.7.0` | AppRole delegated per-property endpoints were not typed. | Resolved in `0.9.0` for every documented OpenBao `2.5.x` delegated property row. |
| `0.7.0` | Custom plugin APIs were not modeled as a generic trait. | Intentional; plugin schemas are deployment-specific. Keep local typed wrappers. |
| `0.7.0` | Bootstrap preview, typed capabilities, list traits, and timestamps were planned. | Resolved in `0.8.0`. |
| `0.7.0` | Broader bootstrap convergence for LDAP/RabbitMQ/Kubernetes secrets/Identity remained planned. | PKI role and Identity entity/group convergence landed in `0.9.0`; selective PKI/database/SSH mount and role convergence lands in `0.15.0`; CA setup, connection configuration, and KV v1 convergence remain rejected in the bootstrap layer. |
| `0.8.0` | Kerberos SPNEGO acquisition is left to platform tooling. | Intentional; the crate accepts the documented base64 token and does not embed Kerberos client stacks. |
| `0.8.0` | Retry, auto-renewal, lease tracking, pagination, Identity OIDC/MFA, PKI root/named issuer, tracing, seal watcher, HTTP/2, and secret wrappers needed decisions. | Resolved in the API Areas table above. Background auto-renewal, background lease tracking, request-level seal back-pressure, runtime HTTP/2 knobs, and per-engine wrapped method duplication are rejected for stable scope. |

## Deferred Work Template

This template records historical scope decisions and future OpenBao onboarding
rules. It does not represent unfinished `2.1.x` or OpenBao `2.6.1` work; the
active exact profile has no deferred operation disposition.

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
