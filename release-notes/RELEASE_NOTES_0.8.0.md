# OpenBao Rust SDK 0.8.0 Release Notes

## Version

- Version: 0.8.0
- Release date: Unreleased
- Git tag: `v0.8.0` planned
- Git commit: tag target for `v0.8.0`
- License: MIT OR Apache-2.0

## Scope

- Stable modules carried from `0.7.0`: client configuration, direct token auth,
  AppRole login and administration, token lifecycle helpers, KV v1/v2, Transit,
  sys health/seal status, loopback-only dev bootstrap, mount/auth mount
  management, response wrapping, ACL policies, capabilities, audit devices,
  exact lease helpers, plugin catalog helpers, environment-based client
  construction, Kubernetes auth, TLS certificate auth, PKI helpers, Userpass
  auth, JWT/OIDC helpers, database secrets helpers, SSH helpers, TOTP helpers,
  Cubbyhole, Kubernetes secrets, RabbitMQ secrets, Identity, LDAP secrets,
  admin bootstrap, production operator APIs behind explicit gates, and optional
  Transit byte helpers.
- New `0.8.0` work currently implemented: LDAP auth login, method
  configuration, group policy mapping, user policy/group mapping, list, read,
  and delete helpers; RADIUS auth login, method configuration, user policy
  mapping, user read/list/delete, paginated user-list helpers; Kerberos auth
  SPNEGO login, service-account/keytab config, Kerberos LDAP config, and group
  policy mapping helpers; JWT/OIDC authorization URL, callback, and
  direct/device poll helpers; token role CRUD, token tidy, and revoke-orphan
  helpers; Transit key config update, rotation, export, backup, restore, trim,
  and batch encrypt/decrypt/rewrap/sign/verify helpers; PKI role merge-patch,
  tidy status, and tidy cancel helpers; Identity entity/group lookup and entity
  merge helpers; system leader status, OpenAPI discovery, internal UI
  namespace/mount discovery, JSON telemetry metrics helpers, HA status, key
  status, host diagnostics, sanitized config state JSON, audited request-header
  config helpers, CORS config helpers, operator-gated active-node step-down,
  and typed capability views for common access checks; system random byte and
  hash tool helpers; runtime logger level helpers and installed version-history listing;
  namespace management helpers; rate-limit quota config and named quota helpers;
  locked-user list/filter/unlock helpers; lease prefix revoke, force prefix
  revoke, and lease count helpers;
  Integrated Storage Raft join/configuration/peer/bootstrap, capped
  snapshot download/restore helpers, and Autopilot JSON helpers; Prometheus
  text metrics output; operator-gated raw storage read/write/list/delete
  helpers; operator-gated pprof diagnostic byte helpers;
  remount/mount-migration start and status helpers; read-only admin bootstrap
  preview with would-create, would-update, and would-issue statuses; advisory
  `FipsPosture` reporting for crate-visible Transit and seal-assumption
  choices; shared `ListEntries` ergonomics for common string list responses;
  optional RFC3339 timestamp parsing helpers behind the `time` feature;
  runtime-neutral `Sys::wait_ready_with_delay` helper; and additional error
  predicates for rate limiting, temporary failures, and permission denial.
- Remaining `0.8.0` planned work: final release-candidate polish after CI
  confirms the pentest and gap-analysis remediation commits.
- Minimum supported Rust: 1.90.0.

## Security Notes

- New auth-method request and response types must keep passwords, shared
  secrets, tokens, accessors, and service credentials in `SecretString` where
  they can cross the public API.
- New list and map response types must use bounded deserializers.
- New request builders must validate OpenBao paths, CIDRs, durations, and JSON
  object strings locally where the crate can do so without weakening upstream
  validation.
- RADIUS shared secrets, login passwords, returned tokens, and token accessors
  are secret-aware and redacted from debug output.
- RADIUS user list responses and login metadata maps are bounded during
  deserialization, and token CIDR/duration fields are validated before request
  dispatch.
- RADIUS configuration documents the protocol's UDP and MD5-based authenticator
  risk so high-assurance deployments can prefer stronger auth methods.
- JWT/OIDC callback and poll helpers keep returned tokens and accessors in
  `SecretString`; query-bearing callback requests are treated as sensitive by
  the HTTP transport path to avoid retaining detailed request URLs in transport
  errors.
- Token roles validate duration and CIDR fields locally, token accessors remain
  secret-aware, and token tidy is documented as an administrative maintenance
  operation.
- LDAP auth bind passwords, client TLS private keys, login passwords, returned
  tokens, and token accessors are secret-aware where applicable and redacted
  from debug output.
- LDAP auth list responses, policy lists, and login metadata maps are bounded
  during deserialization. TLS version, token CIDR/duration, path-name, and
  insecure LDAP TLS settings are validated before request dispatch.
- LDAP auth TLS version fields reject deprecated TLS 1.0 and TLS 1.1 values.
- Kerberos auth keytabs, SPNEGO tokens, LDAP bind passwords, returned tokens,
  and token accessors are secret-aware and redacted from debug output.
- Kerberos group list responses and login metadata maps are bounded during
  deserialization. LDAP TLS version, token CIDR/duration, group-name, and
  insecure LDAP TLS settings are validated before request dispatch.
- Kerberos LDAP TLS version fields reject deprecated TLS 1.0 and TLS 1.1
  values.
- Transit exported key material, backups, batch ciphertext/plaintext/signature
  fields, and restored backup payloads are secret-aware and redacted from debug
  output. Transit batch inputs and server-returned batch result lists are
  bounded.
- PKI tidy status/cancel responses use typed fields, and role merge-patch uses
  JSON Merge Patch content type.
- Identity lookup and merge inputs validate required fields and bound source ID
  lists.
- Metrics support includes JSON output and Prometheus text output. Prometheus
  text uses the private raw-body transport path while preserving HTTPS/token
  enforcement and response-size limits.
- Logger level and version-history responses are bounded during
  deserialization, and logger level writes use a typed allowlist.
- Namespace paths reject trailing slashes, spaces, and reserved namespace names
  before request dispatch. Namespace metadata maps are bounded.
- Rate-limit quota rates must be positive finite numbers, duration fields are
  validated, quota names are single path segments, and exempt paths are bounded.
- Locked-user namespace, mount-accessor, and alias-identifier lists are bounded
  during deserialization. Unlock path parameters must be single path segments.
- Lease prefix revocation validates prefix paths locally, force prefix
  revocation is documented as emergency-only, and lease count maps are bounded.
- Raft join client keys, auto-join metadata, and DR operation tokens are
  secret-aware and redacted from debug output. Raft server lists are bounded,
  peer IDs are validated, Raft join leader addresses and auto-join schemes must
  use HTTPS, and Autopilot duration/integer fields are checked before request
  dispatch.
- Raft snapshots are returned in zeroizing byte buffers and remain capped by
  `OpenBaoConfig::max_response_bytes`. Restore helpers reject empty payloads
  before dispatch and should be used only during an operator-controlled
  recovery ceremony.
- Raw storage helpers are unavailable in default builds and require
  `operator-ops` plus `operator-ops-acknowledged`. Raw values use
  `SecretString`, raw key lists are bounded, and raw storage paths are
  validated before dispatch.
- Pprof helpers are unavailable in default builds and require `operator-ops`
  plus `operator-ops-acknowledged`. Profile payloads are returned in zeroizing
  byte buffers, the configured response-size limit applies, and profiling
  duration/debug query values are validated locally.
- HA node lists are bounded during deserialization, and remount source,
  destination, and migration ID values are validated before request dispatch.
- CORS origin and header lists are bounded during deserialization. CORS writes
  require at least one non-empty origin, reject wildcard origins and control
  characters, and validate configured HTTP header names before request dispatch.
- Audited request-header maps are bounded during deserialization, and request
  header names are validated with HTTP header parsing before request dispatch.
- System tools random byte and hash outputs are secret-aware and redacted from
  debug output. Random byte counts are rejected when zero or above the local
  1 MiB helper limit.
- Internal UI namespace lists and mount maps are bounded during
  deserialization. UI mount detail paths are validated before request dispatch.
- Typed capability views keep the existing raw string lists available and
  preserve unknown future capability names instead of dropping or rejecting
  them.
- Admin bootstrap preview performs read-side comparisons only and never writes
  state or issues credentials. Credential operations are reported as
  `WouldIssue`.
- `FipsPosture` is a best-effort helper over SDK-visible choices only. It does
  not certify OpenBao, cryptographic providers, HSM/KMS use, TLS, operating
  systems, or deployment processes.
- `ListEntries` is limited to regular string lists. Secret accessor lists are
  intentionally excluded because their entries are sensitive.
- Timestamp parse errors intentionally do not echo the provided timestamp value
  so loggable errors stay value-free near secret-bearing response handling.
- `Sys::wait_ready_with_delay` retries temporary transport failures until the
  configured timeout instead of failing on the first connection error.
- `Error::is_permission_denied` is documented as a superset of
  `Error::is_forbidden` because OpenBao can report `permission denied` outside
  HTTP 403 in some policy-check paths.
- Development Podman TLS material is documented as local-only; generated
  `dev-state` files remain ignored and historical development keys are not
  trusted production material.

## Security And Stability Gate

- Gate command: `scripts/release_0_8_gate.sh`
- Result: local release gate passed on 2026-06-02 after pentest remediations.
- Pentest report: local `PENTEST.md` reviewed on 2026-06-02; actionable local
  findings were addressed and the report was deleted before commit. A follow-up
  `PENTEST.md` was reviewed on 2026-06-02 after gap-analysis work; actionable
  local findings were addressed and the report was deleted before commit.
- `cargo audit` result: passed in local release gate.
- `cargo deny check` result: passed in local release gate.
- CodeQL result: pending for this pentest remediation commit.
- Podman OpenBao integration result: passed in local release gate.
- SBOM generation result: passed in local release gate.
- Reproducible package result: passed in local release gate.

## Known Limitations

- Kerberos SPNEGO token acquisition is intentionally left to platform Kerberos
  tooling; the crate accepts the base64-encoded token required by the OpenBao
  HTTP API.
- Token auto-renewal, lease tracking, retry policy/backoff, a shared pagination
  abstraction, Identity OIDC provider/MFA management, PKI root rotate/replace,
  named issuer issue/sign flows, OpenTelemetry tracing, seal-status watching,
  HTTP/2 transport configuration, and application-side secret-struct wrappers
  are planned or require design decisions before stabilization.
