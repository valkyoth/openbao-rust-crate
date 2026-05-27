# OpenBao Rust SDK 0.2.0 Release Notes

## Version

- Version: 0.2.0
- Release date: 2026-05-27
- Git tag: `v0.2.0`
- Git commit: tag target for `v0.2.0`
- License: MIT OR Apache-2.0

## Scope

- Stable modules carried from `0.1.0`: client configuration, direct token auth,
  AppRole login, KV v2 core read/write/list/delete, sys health/seal status.
- New `0.2.0` modules: token lifecycle helpers, KV v1, expanded KV v2
  metadata/version/config operations, sys mount/auth mount management,
  response wrapping, ACL policies, and capabilities.
- Real OpenBao container integration coverage now exercises the default
  `0.2.0` feature flow against the pinned TLS Podman dev instance.
- Default Cargo features: `approle`, `token`, `kv1`, `kv2`, `sys`, `rustls-tls`.
- Minimum supported Rust: 1.95.0.
- Tested OpenBao version: v2.5.4, verified before tag.

## Security Changes

- JSON request serialization buffers controlled by the crate are zeroized after
  handoff to the HTTP stack.
- Successful JSON responses now require an `application/json` content type.
- Namespace headers are marked sensitive.
- Token TTL responses reject negative values.
- System TTL/config fields use typed duration and lockout structures instead
  of open-ended JSON values.
- Response string lists are bounded for token policies, accessors, policy
  names, KV list keys, mount header lists, capabilities, and response warnings.
- KV v2 internal path helpers validate operation and mount child path segments.
- Response wrapping TTLs are validated before sending.
- `rustls-tls` is wired to the actual `reqwest/rustls` feature; `native-tls`
  remains available only for audited legacy compatibility.

## Security And Stability Gate

- Gate command: `scripts/release_0_2_gate.sh`
- Result: local release gate passed on 2026-05-27 after pentest remediations
- Pentest report: local `PENTEST.md` reviewed on 2026-05-27; all actionable
  findings for `0.2.0` were remediated before tagging, and the local report
  file was deleted to avoid publishing private security details
- `cargo audit` result: passed
- `cargo deny check` result: passed with allowed duplicate-version warnings
- CodeQL result: pending through GitHub default setup
- Podman OpenBao integration result: passed against the pinned TLS dev instance
- SBOM generation result: passed, CycloneDX JSON written under `target/sbom/`

## Known Limitations

- Exact certificate/public-key pinning is not implemented; use custom CA roots
  and root-only trust stores for private PKI.
- After JSON request bodies are handed to `reqwest`, buffers owned by the HTTP
  stack, TLS backend, operating system, or network device are outside this
  crate's zeroization control.
