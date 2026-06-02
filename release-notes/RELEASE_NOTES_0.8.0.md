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
  mapping, user read/list/delete, paginated user-list helpers; system leader
  status, OpenAPI discovery, JSON telemetry metrics helpers, and typed
  capability views for common access checks; runtime logger level helpers and
  installed version-history listing; read-only admin bootstrap preview with
  would-create, would-update, and would-issue statuses; advisory
  `FipsPosture` reporting for crate-visible Transit and seal-assumption
  choices; shared `ListEntries` ergonomics for common string list responses;
  optional RFC3339 timestamp parsing helpers behind the `time` feature.
- Remaining `0.8.0` planned work: Kerberos auth coverage; quotas/namespaces
  and additional system backend coverage.
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
- LDAP auth bind passwords, client TLS private keys, login passwords, returned
  tokens, and token accessors are secret-aware where applicable and redacted
  from debug output.
- LDAP auth list responses, policy lists, and login metadata maps are bounded
  during deserialization. TLS version, token CIDR/duration, path-name, and
  insecure LDAP TLS settings are validated before request dispatch.
- Metrics support is intentionally JSON-only in `0.8.0`; Prometheus text
  output is deferred until the crate has an explicit raw-body API.
- Logger level and version-history responses are bounded during
  deserialization, and logger level writes use a typed allowlist.
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

## Security And Stability Gate

- Gate command: `scripts/release_0_8_gate.sh`
- Result: pending.
- Pentest report: pending.
- `cargo audit` result: pending.
- `cargo deny check` result: pending.
- CodeQL result: pending.
- Podman OpenBao integration result: pending.
- SBOM generation result: pending.
- Reproducible package result: pending.

## Known Limitations

- Kerberos API coverage may require careful handling because the current
  OpenBao API navigation links older Kerberos API documentation while the 2.5.x
  auth overview still lists the method.
