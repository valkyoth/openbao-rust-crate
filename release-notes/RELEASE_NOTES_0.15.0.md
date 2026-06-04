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

## Security And Stability Gate

- Release gate script: `scripts/release_0_15_gate.sh`
- OpenBao integration command: `scripts/openbao_integration.sh`
- Do not tag `v0.15.0` until local validation, external pentest feedback, and
  GitHub CI are green.
