# OpenBao Rust SDK 0.5.0 Release Notes

## Version

- Version: 0.5.0
- Release date: Unreleased
- Git tag: `v0.5.0` planned
- Git commit: tag target for `v0.5.0`
- License: MIT OR Apache-2.0

## Scope

- Stable modules carried from `0.4.0`: client configuration, direct token auth,
  AppRole login, token lifecycle helpers, KV v1/v2, Transit, sys health/seal
  status, loopback-only dev bootstrap, mount/auth mount management, response
  wrapping, ACL policies, capabilities, audit devices, exact lease helpers,
  plugin catalog helpers, environment-based client construction, Kubernetes
  auth, TLS certificate auth, and PKI helpers.
- New `0.5.0` work currently implemented: public API dependency re-exports,
  prelude exports, safer constructors/defaults for request types, KV v2
  optional-read ergonomics, `Sys::enable_kv2`, Userpass auth helpers, and
  JWT/OIDC config/role helpers with JWT login.
- Remaining `0.5.0` planned work: database secrets, byte-oriented Transit
  helpers, and Transit signing/JWKS ergonomics.
- Default Cargo features: `approle`, `cert-auth`, `jwt-auth`,
  `kubernetes-auth`, `userpass`, `token`, `kv1`, `kv2`, `pki`, `transit`,
  `sys`, `rustls-tls`.
- Non-default Cargo features: `allow-sha1`, `native-tls`,
  `native-tls-acknowledged`.
- Minimum supported Rust: 1.90.0.
- Rust compatibility evidence: release gate will refresh full test suite and
  clippy on 1.90.0 plus feature checks through 1.96.0 before tagging.
- Tested OpenBao version: latest OpenBao release verified as `v2.5.4` on
  2026-05-30 during 0.5.0 development.

## Security Changes

- Response schema decode errors avoid raw serde value fragments so malformed
  secret-bearing OpenBao responses are not copied into `Error::Decode`.
- Environment CA certificate read/parse errors no longer echo local filesystem
  paths or parser details.
- Auth tokens are validated for header safety during `try_with_token`.
- Credential-bearing or request-body requests are refused over plain HTTP,
  even when numeric loopback HTTP is enabled for non-sensitive development
  probes.
- Sensitive request dispatch uses a separate HTTPS-only `reqwest::Client` path
  outside test binaries.
- Userpass passwords are handled as `SecretString` and redacted from debug
  output.
- JWT login values and OIDC client secrets are handled as `SecretString`;
  `JwtConfig` debug output redacts the OIDC client secret.
- Userpass and JWT/OIDC list responses and login metadata maps are bounded
  during deserialization.
- The KV v2 example avoids printing secret-derived response fields.

## Security And Stability Gate

- Gate command: `scripts/release_0_5_gate.sh`
- Result: in progress for the 0.5.0 development line.
- Pentest report: required before tagging; local `PENTEST.md` must be reviewed,
  remediated where actionable, recorded here, and deleted before commit.
- `cargo audit` result: pending final release gate.
- `cargo deny check` result: pending final release gate.
- CodeQL result: pending final release gate.
- Podman OpenBao integration result: pending final release gate.
- SBOM generation result: pending final release gate.
- Reproducible package result: pending final release gate.

## Known Limitations

- Browser-based OIDC callback/device helper flows are not implemented yet;
  the current JWT/OIDC surface covers config, roles, list/delete, and direct
  JWT login.
- Database secrets, byte-oriented Transit helpers, and Transit signing/JWKS
  ergonomics remain planned for the rest of the 0.5.0 line.
- Exact certificate/public-key pinning is not implemented; use custom CA roots
  and root-only trust stores for private PKI.
