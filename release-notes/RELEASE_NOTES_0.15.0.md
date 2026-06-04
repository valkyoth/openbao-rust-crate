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

## Planned Scope

- Typed response-wrapping ergonomics with redacted wrapping tokens and typed
  unwrap.
- Selective AdminBootstrap convergence for PKI, database, and SSH mount/role
  workflows.
- ACL policy-builder wrapping TTL constraints and helper variants.
- Final public API, documentation, migration, and stable-scope review before
  `1.0.0`.

## Security Notes

- Request-level seal back-pressure remains rejected because retry, queueing,
  and concurrency policy belong to application middleware.
- Unseal polling is bounded and caller-initiated only; the crate does not
  install background seal polling or delay unrelated requests.
- PKI CA setup, database connection configuration, SSH CA setup, KV v1
  convergence, and ACL parameter-constraint HCL generation remain rejected for
  stable bootstrap/builder scope.

## Security And Stability Gate

- Release gate script: `scripts/release_0_15_gate.sh`
- OpenBao integration command: `scripts/openbao_integration.sh`
- Do not tag `v0.15.0` until local validation, external pentest feedback, and
  GitHub CI are green.
