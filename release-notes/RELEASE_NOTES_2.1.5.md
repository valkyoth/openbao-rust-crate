# OpenBao Rust SDK 2.1.5 Release Notes

## Version

- Version: 2.1.5
- Release date: 2026-09-04
- Release tag: `v2.1.5`, created only after every release gate passes
- Release commit: bound by the signed `v2.1.5` tag object
- License: MIT OR Apache-2.0

## Summary

`2.1.5` is a source-compatible dependency, toolchain, CI, static-analysis, and
transport-hardening maintenance release. It does not change the public SDK or
any exact OpenBao compatibility profile. All 24 profiles from OpenBao `2.0.0`
through `2.6.2` retain their reviewed routes, request and response field rules,
and security classifications.

## Dependency And Toolchain Updates

- Updated `base64-ng` from `2.0.1` to `2.0.3`.
- Updated `sanitization` from `2.0.3` to `2.0.4`.
- Added target-specific `rustix` and `windows-sys` dependencies for safe,
  race-resistant CA certificate file handling.
- Refreshed the root, fuzz, and TLS-unification fixture lockfiles to current
  compatible dependency versions.
- Updated the primary Rust toolchain from `1.97.1` to `1.98.1`; Rust `1.90.0`
  remains the checked MSRV.
- Updated `taiki-e/install-action` from `2.86.3` to `2.87.4` with an immutable
  commit-SHA pin.
- Confirmed all other direct crates, CI cargo tools, and pinned GitHub Actions
  are current on the release date.

## Static-Analysis Hardening

The maintenance pass resolves all eleven CodeQL alerts open at its start
without query suppressions or alert dismissals:

- database password and protocol nonce fixtures are built at test runtime
  instead of embedding complete values in source; and
- assertions and panic paths no longer format secret-bearing operation results
  or secret-memory errors into diagnostics.

## Backend Transport Hardening

- JWT/OIDC discovery and JWKS endpoints, Kubernetes auth and secrets API
  hosts, and RabbitMQ management endpoints must be absolute HTTPS URLs without
  embedded credentials or fragments.
- LDAP and Kerberos LDAP bind credentials require `ldaps://` or StartTLS and
  verified peer certificates. The LDAP acknowledgement feature cannot weaken
  transport while bind credentials or a client private key are configured.
- Reviewed PostgreSQL, MySQL-family, Cassandra, InfluxDB, and Valkey options
  must prove encrypted TCP transport. `insecure-database-tls-acknowledged` may
  permit encrypted transport without full peer verification, but never
  plaintext transport. Valkey constructors now select TLS explicitly.
- Environment CA certificates are read only from regular files no larger than
  1 MiB. Unix opens are nonblocking and do not follow symlinks; Windows opens
  reject reparse points. Error messages do not disclose the configured path.
- Minimal `kerberos-auth` builds now include the internal client-state helper
  they require instead of relying on another auth feature being enabled.

## Compatibility

No source migration is required. Deployments that configured plaintext or
unverified credential-bearing backend connections must move those services to
TLS; see `docs/MIGRATION_GUIDE.md`. Exact and automatic compatibility selection
continue to support every locked stable OpenBao release from `2.0.0` through
`2.6.2`. The active inventory remains 691 operation identities across 24 exact
profiles and 16,584 operation/profile cells.

## Release Gate

Run `scripts/release_2_1_5_gate.sh`. Tagging additionally requires green
GitHub CI, CodeQL, the all-release compatibility workflow, and clean
independent pentests for the exact release commit.
