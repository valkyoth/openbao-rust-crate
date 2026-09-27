# openbao 2.1.9

Version: 2.1.9
Release date: 2026-09-27
Status: prepared for pentesting and GitHub validation; not yet tagged

This maintenance release adds exact OpenBao 2.6.3 support while preserving
separate profiles for all 25 selected releases from 2.0.0 onward. OpenBao
2.7.0 support is planned separately for openbao 2.2.0.

## Dependency And Tooling Maintenance

- Retains Rust 1.98.1 as the current stable build toolchain and Rust 1.90 MSRV.
- Updates rand to 0.10.3, rustix to 1.1.5, and taiki-e/install-action to
  2.87.21 with an immutable commit pin.
- Refreshes all maintained lockfiles, including rustls 0.23.45 to address
  RUSTSEC-2026-0285, and rustls-platform-verifier 0.7.1.
- Removes the obsolete base64 0.22 duplicate exception after convergence.

## Compatibility Work

See the [source review and verification scope](../docs/OPENBAO_2_6_3_REVIEW.md).
OpenBao 2.6.3 includes server security fixes, raw-storage creation behavior,
and changes to canonical ACL evaluation and plugin namespace restrictions.
Using this SDK with an older server does not apply those server fixes.

- Adds `Sys::raw_write_uncompressed` without changing existing public structs
  or enum variants. Older profiles reject the new compression value locally.
- Corrects `Sys::raw_read` to decode the actual `data.value` envelope.
- Preserves `RawCompression::None` as the empty-string wire value. On normal
  2.6.3 servers that existing mode creates entries; the new explicit `none`
  value works on updates but returns 400 for creation. The SDK does not retry
  with another value. Recovery-mode creation was not exercised.
- Keeps workflow CAS/prefix-list security blocks and JWT CEL acknowledgements.
- Records 17,275 operation/profile contract cells. The exact 2.6.3 profile
  has 689 documented operations: 594 typed, 93 gated, and two blocked.
- Reruns representative core flows on all 25 versions, plus exact 2.6.3 TLS
  regressions for raw storage, canonical ACL denial, and existing Transit,
  PKI, JWT, and workflow checks. This is not endpoint-by-endpoint live coverage.

## Release Gate

Before publication, complete `scripts/release_2_1_9_gate.sh`, exact 2.6.3 TLS
integration, the all-release compatibility matrix, pentesting, and GitHub CI.
