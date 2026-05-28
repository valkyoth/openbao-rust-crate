# OpenBao Rust SDK 0.3.0 Release Notes

## Version

- Version: 0.3.0
- Release date: TBD
- Git tag: `v0.3.0`
- Git commit: TBD
- License: MIT OR Apache-2.0

## Scope

- Stable modules carried from `0.2.0`: client configuration, direct token auth,
  AppRole login, token lifecycle helpers, KV v1, expanded KV v2 operations,
  sys health/seal status, mount/auth mount management, response wrapping, ACL
  policies, and capabilities.
- New `0.3.0` modules started: sys audit device helpers and safe exact lease
  lookup, renew, and revoke helpers.
- Planned before `0.3.0` tagging: Transit helpers and plugin catalog helpers.
- Default Cargo features: `approle`, `token`, `kv1`, `kv2`, `sys`, `rustls-tls`.
- Minimum supported Rust: 1.95.0.
- Tested OpenBao version: latest release must be verified before tag.

## Security Changes

- Lease IDs are accepted as `SecretString`, validated before JSON submission,
  and redacted from SDK debug output.
- Lease helpers intentionally use the JSON-body lookup, renew, and revoke
  endpoints and do not expose prefix, force, or tidy lease operations.
- Audit device options returned by OpenBao are decoded through a bounded string
  map to avoid disproportionate allocation from compromised servers.
- Audit hash inputs are accepted as `SecretString`.

## Security And Stability Gate

- Gate command: `scripts/release_0_3_gate.sh`
- Result: pending
- Pentest report: required before tagging `v0.3.0`
- `cargo audit` result: pending
- `cargo deny check` result: pending
- CodeQL result: pending through GitHub default setup
- Podman OpenBao integration result: pending
- SBOM generation result: pending

## Known Limitations

- Transit support is still pending in this development snapshot.
- Plugin catalog helpers are still pending in this development snapshot.
- Exact certificate/public-key pinning is not implemented; use custom CA roots
  and root-only trust stores for private PKI.
- After JSON request bodies are handed to `reqwest`, buffers owned by the HTTP
  stack, TLS backend, operating system, or network device are outside this
  crate's zeroization control.
