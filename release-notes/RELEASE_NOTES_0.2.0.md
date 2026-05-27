# OpenBao Rust SDK 0.2.0 Release Notes

## Version

- Version: 0.2.0
- Release date: TBD
- Git tag: `v0.2.0`
- Git commit: TBD
- License: MIT OR Apache-2.0

## Scope

- Stable modules carried from `0.1.0`: client configuration, direct token auth,
  AppRole login, KV v2 core read/write/list/delete, sys health/seal status.
- New `0.2.0` modules started: token lifecycle helpers, KV v1, expanded KV v2
  metadata/version/config operations, sys mount/auth mount management, and
  response wrapping.
- Remaining `0.2.0` work: real OpenBao container integration coverage.
- Default Cargo features: `approle`, `token`, `kv1`, `kv2`, `sys`, `rustls-tls`.
- Minimum supported Rust: 1.95.0.
- Tested OpenBao version: latest release verified before tag.

## Security And Stability Gate

- Gate command: `scripts/release_0_2_gate.sh`
- Result: pending
- Pentest report: pending
- `cargo audit` result: pending
- `cargo deny check` result: pending
- CodeQL result: pending through GitHub default setup
- Podman OpenBao integration result: pending
- SBOM generation result: pending

## Known Limitations

- Real OpenBao integration coverage is not complete yet.
- Exact certificate/public-key pinning is not implemented; use custom CA roots
  and root-only trust stores for private PKI.
