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
- Result: local pre-pentest gate passed on 2026-05-27
- Pentest report: local `PENTEST.md` reviewed on 2026-05-27; report source
  deleted before commit and ignored by `.gitignore`
- `cargo audit` result: passed, no vulnerabilities reported
- `cargo deny check` result: passed with duplicate transitive crate warnings from the all-feature TLS graph
- CodeQL result: pending through GitHub default setup
- Podman OpenBao integration result: pending
- SBOM generation result: passed, generated `target/sbom/openbao.cdx.json`

## Known Limitations

- KV v2 metadata operations are not complete until `0.2.0`.
- Token lifecycle helpers are not complete until `0.2.0`.
- Transit support starts in `0.3.0`.
- Exact certificate/public-key pinning is not implemented; `0.1.0` supports
  custom CA roots and root-only trust stores.
