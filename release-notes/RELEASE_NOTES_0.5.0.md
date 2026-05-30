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
  JWT/OIDC config/role helpers with JWT login, and optional byte-oriented
  Transit helpers backed by `base64-ng`, and database secrets helpers for
  connection config, dynamic/static roles, credential reads, and rotations,
  plus typed Transit signing options for RSA signatures and JWS-style ECDSA
  marshaling.
- Remaining `0.5.0` planned work: no functional scope remains before the next
  pentest pass; continue with fixes only unless new findings arrive.
- Default Cargo features: `approle`, `cert-auth`, `jwt-auth`,
  `database`, `kubernetes-auth`, `userpass`, `token`, `kv1`, `kv2`, `pki`,
  `transit`, `sys`, `rustls-tls`.
- Non-default Cargo features: `allow-sha1`, `native-tls`,
  `native-tls-acknowledged`, `transit-bytes`.
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
  outside explicit debug-only numeric-loopback mock tests; the previous
  cargo-test-binary path detection was removed.
- Userpass passwords are handled as `SecretString` and redacted from debug
  output.
- JWT login values and OIDC client secrets are handled as `SecretString`;
  `JwtConfig` debug output redacts the OIDC client secret.
- JWT role leeway fields use typed `JwtLeeway` values so disabling JWT time
  validation requires an explicit `DisableTimeValidation` variant.
- Userpass and JWT/OIDC list responses and login metadata maps are bounded
  during deserialization.
- Database connection passwords, generated credential passwords, generated
  private keys, and lease IDs are handled as secret material and redacted from
  debug output.
- Database connection URLs are treated as secret material because DSNs commonly
  embed credentials.
- Database connection/role/static-role lists, statement lists, CA chains, and
  connection detail maps are bounded during deserialization.
- OpenBao request paths are bounded before URL construction to avoid
  disproportionate allocations from untrusted path inputs.
- Optional Transit byte helpers use `base64-ng` 1.0.5 secret buffer APIs to encode
  raw request bytes and return decoded response bytes in zeroizing buffers.
- Transit sign/verify requests now use typed helpers for RSA signature
  algorithm selection, JWS marshaling, and RSA-PSS salt length instead of
  requiring raw option strings.
- The KV v2 example avoids printing secret-derived response fields.

## Security And Stability Gate

- Gate command: `scripts/release_0_5_gate.sh`
- Result: local gate-equivalent checks passed on 2026-05-30; the initial
  scripted run stopped at `cargo audit` because the sandbox could not create
  the advisory database lock, and the audit step was rerun directly with the
  same lock/update access used by CI.
- Pentest report: reviewed on 2026-05-30; actionable current-tree findings
  were remediated, current tracked files were checked for dev TLS private-key
  material, and local `PENTEST.md` was deleted before commit.
- `cargo audit` result: passed locally on 2026-05-30.
- `cargo deny check` result: passed locally on 2026-05-30; duplicate
  transitive dependency warnings remain informational under the current policy.
- Supply-chain review: `serde_core` and `zmij` crate owners were verified with
  `cargo owner --list` on 2026-05-30; both resolve to David Tolnay / serde-rs
  ownership.
- CodeQL result: pending GitHub run for the final release candidate.
- Podman OpenBao integration result: passed locally on 2026-05-30 against the
  pinned OpenBao dev image on port 9940.
- SBOM generation result: passed locally on 2026-05-30.
- Reproducible package result: `cargo package --locked --allow-dirty` passed
  locally on 2026-05-30.

## Known Limitations

- Browser-based OIDC callback/device helper flows are not implemented yet;
  the current JWT/OIDC surface covers config, roles, list/delete, and direct
  JWT login.
- Full JOSE/JWKS document construction remains out of scope to avoid adding a
  JWT/JWK dependency; use the Transit JWS marshaling helpers with the
  application JWT library.
- Exact certificate/public-key pinning is not implemented; use custom CA roots
  and root-only trust stores for private PKI.
