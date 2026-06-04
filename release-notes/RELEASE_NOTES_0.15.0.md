# OpenBao Rust SDK 0.15.0 Release Notes

## Version

- Version: 0.15.0
- Status: in development
- Git tag: pending
- Git commit: pending
- License: MIT OR Apache-2.0

## Summary

`0.15.0` is the final substantial pre-stable release line before `1.0.0`.
It focuses on stable-scope ergonomics and final closure work rather than new
OpenBao endpoint coverage. The OpenBao `2.5.x` endpoint matrix already records
zero `planned` and zero `decision` rows.

## Added

- Started the `0.15.0` release line.
- Added the `0.15.0` release gate script and metadata checks.
- Added runtime-neutral `Sys::wait_until_unsealed_with_delay` and the
  `tokio-helpers`-gated `Sys::wait_until_unsealed` convenience helper for
  bounded startup and recovery polling.
- Added `Client::wrapping`, `WrappingContext`, and `WrappedResponse<T>` for
  typed response-wrapped JSON requests and typed unwrap of the original
  response shape.
- Added ACL policy-builder wrapping TTL constraints through
  `allow_path_with_wrapping` and helper variants that require response
  wrapping on common KV v2 and Transit paths.
- Added selective AdminBootstrap convergence for PKI, database, and SSH mounts,
  dynamic/static database roles, and SSH roles.
- Updated the migration guide and bootstrap example to show the new `0.15.0`
  stable-candidate helpers.
- Updated the pinned `taiki-e/install-action` CI action to the latest v2 tag
  enforced by the local check script.
- Added rustls-backed static PEM CRL configuration for OpenBao server
  certificate checks when using a root-only trust store.
- Added final pentest hardening for RADIUS user policy validation, Transit
  import wrapping-key validation, token and user-agent header validation,
  retry jitter fallback visibility, Transit batch invariants, and bootstrap
  contention classification.
- Renamed the legacy Transit SHA-1 opt-in to `allow-sha1-acknowledged`, added
  `allow-weak-jitter-fallback-acknowledged`, and rotated CI cache keys on
  toolchain or lockfile changes.

## Remaining Finalization

- Local release-gate validation, external pentest feedback, and GitHub CI must
  pass on the exact release candidate before tagging.
- The final public API, documentation, migration, and stable-scope review must
  remain clean before `1.0.0`.

## Security Notes

- Request-level seal back-pressure remains rejected because retry, queueing,
  and concurrency policy belong to application middleware.
- Unseal polling is bounded and caller-initiated only; the crate does not
  install background seal polling or delay unrelated requests.
- Wrapped response metadata keeps wrapping tokens and accessors in
  `SecretString` and redacts them from `Debug`; delivery and recipient policy
  remain caller-owned.
- ACL parameter-constraint HCL generation remains rejected for typed builder
  scope because correct output requires a full HCL value serializer.
- PKI CA setup, database connection configuration, SSH CA setup, KV v1
  convergence, and ACL parameter-constraint HCL generation remain rejected for
  stable bootstrap/builder scope.
- The deprecated production `Client::with_token` path was removed; use
  `try_with_token` so token header validity is checked at construction time.
- LDAP auth and LDAP secrets-engine config now reject non-ASCII LDAP path names
  and plaintext `ldap://` URLs unless StartTLS or the insecure LDAP
  acknowledgment feature is used. Even with the acknowledgment feature,
  `insecure_tls=true` is rejected when LDAP credentials would cross an
  unverified TLS connection.
- Transit batch requests now expose checked `try_push` builders and a named
  `MAX_TRANSIT_BATCH_ITEMS` limit; methods still reject empty or oversized
  batches before dispatch.
- TLS 1.2 compatibility now has an explicit `tls12-acknowledged` feature and
  build warning. TLS 1.3 remains the default and recommended floor.
- Legacy Transit SHA-1 selection now requires `allow-sha1-acknowledged`.
- Default builds skip retry jitter if OS randomness fails rather than using a
  weak timing-derived fallback.
- AdminBootstrap KV v2 secret values are now bounded at plan construction, and
  secret convergence comparisons use a fixed-iteration comparison over that
  bound instead of variable-length slice comparison.
- Static PEM CRLs can now be enforced for OpenBao server certificates when
  using `only_root_certificates`; callers still own CRL refresh, client rebuild
  timing, and OCSP/automatic revocation-discovery policy.
- RADIUS remains prohibited for classified and new high-assurance deployments
  despite legacy compatibility support; use certificate auth, Kerberos, or LDAP
  over TLS instead.
- `transit-import` remains a software wrapping helper only; classified or
  high-assurance key wrapping must use an HSM or equivalent audited boundary.
  OpenSSL-managed temporary key buffers, swap, crash dumps, and allocator free
  lists remain outside this crate's zeroization control.
- `Error::BootstrapContention` remains a best-effort post-write verification
  signal. It is not a distributed lock; multi-runner bootstrap workflows must
  still use external serialization.

## Security And Stability Gate

- Release gate script: `scripts/release_0_15_gate.sh`
- OpenBao integration command: `scripts/openbao_integration.sh`
- Do not tag `v0.15.0` until local validation, external pentest feedback, and
  GitHub CI are green.
