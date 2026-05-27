# OpenBao Rust SDK 0.1.0 Release Notes

## Version

- Version: 0.1.0
- Release date: TBD
- Git tag: `v0.1.0`
- Git commit: TBD
- License: MIT OR Apache-2.0

## Scope

- Stable modules: client configuration, direct token auth, AppRole login, KV v2,
  sys health/seal status.
- Experimental modules: raw JSON request layer.
- Default Cargo features: `approle`, `kv2`, `sys`, `rustls-tls`.
- Minimum supported Rust: 1.95.0.
- Tested OpenBao version: latest release verified before tag.

## Security And Stability Gate

- Gate command: `scripts/release_0_1_gate.sh`
- Result: pending
- Pentest report: pending owner-provided report before tag
- `cargo audit` result: pending
- `cargo deny check` result: pending
- CodeQL result: pending
- Podman OpenBao integration result: pending
- SBOM generation result: pending

## Known Limitations

- KV v2 metadata operations are not complete until `0.2.0`.
- Token lifecycle helpers are not complete until `0.2.0`.
- Transit support starts in `0.3.0`.
