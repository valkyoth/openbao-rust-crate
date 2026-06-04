# OpenBao Rust SDK 1.0.0 Release Notes

## Version

- Version: 1.0.0
- Release date: 2026-06-04
- Git tag: `v1.0.0`
- Git commit: see the signed `v1.0.0` tag object
- License: MIT OR Apache-2.0

## Summary

`1.0.0` is the first stable release of the `openbao` Rust SDK. It freezes the
public API surface trialed through `0.15.0` and keeps the OpenBao `2.5.x`
endpoint matrix at zero `planned` and zero `decision` rows.

This release does not add a new endpoint family beyond `0.15.0`. It promotes
the stable-candidate API, documentation, security posture, release gates, and
residual-risk register to the stable line.

## Stable Scope

- Strict typed or operator-gated coverage: `597/643` documented OpenBao `2.5.x`
  endpoint rows (`92.8%`).
- Addressed coverage: `643/643` rows (`100.0%`) through typed, gated, partial,
  raw, external, or rejected policy.
- No endpoint row remains `planned` or `decision`.
- Background token renewal, background lease tracking, request-level
  back-pressure, runtime HTTP/2 knobs, OpenTelemetry SDK dependencies, leaf
  certificate pinning, ACL parameter-constraint generation, and per-engine
  wrapped-response method duplication remain rejected for stable scope.

## Documentation

- README install snippets now use `openbao = "1"`.
- README includes a compact crates.io-facing quick-start example.
- Migration guide now includes `0.15` to `1.0` guidance.
- API stability audit records the stable freeze.
- Release plan and API coverage docs now describe the `1.0.0` stable line.

## Security Notes

- HTTPS remains required by default. Plain HTTP requires explicit numeric
  loopback opt-in, and sensitive requests still require HTTPS.
- TLS 1.3 remains the default minimum. TLS 1.2 requires
  `tls12-acknowledged`.
- Production operator APIs remain behind `operator-ops` plus
  `operator-ops-acknowledged`.
- Legacy RADIUS remains behind `radius-auth` plus
  `radius-auth-acknowledged`.
- Software Transit BYOK wrapping remains behind `transit-import` plus
  `transit-import-acknowledged` and is not an HSM, FIPS, certification,
  post-quantum, or security-boundary claim.
- Transport request payloads are zeroized only up to the serialization buffer
  controlled by the crate. `reqwest`, TLS, kernel, device, allocator, swap, and
  crash-dump buffers remain accepted residual risks.
- `AdminBootstrap` remains a convergence helper, not a distributed lock.
  Multi-runner workflows must use external serialization.
- Retry jitter remains non-cryptographic timing only.

## Security And Stability Gate

- Release gate script: `scripts/release_1_0_gate.sh`
- OpenBao integration command: `scripts/openbao_integration.sh`
- Do not tag `v1.0.0` until local validation, external pentest feedback, and
  GitHub CI are green.
