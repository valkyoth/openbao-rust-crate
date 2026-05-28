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
- New `0.3.0` modules started: Transit helpers, sys audit device helpers,
  safe exact lease lookup, renew, and revoke helpers, and plugin catalog
  helpers.
- Transit helpers cover key create/read/list/delete, encrypt, decrypt, rewrap,
  data key, random, hash, HMAC, sign, and verify endpoints.
- Plugin helpers cover catalog list, type-list, register, read, delete, and
  mounted backend reload endpoints.
- Default Cargo features: `approle`, `token`, `kv1`, `kv2`, `transit`, `sys`,
  `rustls-tls`.
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
- Transit plaintext, ciphertext, data keys, random bytes, hashes, and HMACs
  are represented with `SecretString` where they enter or leave the crate.
- Transit request bodies expose secret material only in internal serialization
  payloads immediately before handoff to the shared HTTP request layer.
- Plugin registration args/env and returned args/env are represented as
  `SecretString`; detailed catalog lists are bounded during deserialization.

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

- Transit batch, import, export, backup, restore, and BYOK endpoints are not
  part of this initial typed Transit slice.
- Plugin OCI initialization and reload status endpoints are not part of this
  initial typed plugin slice.
- Exact certificate/public-key pinning is not implemented; use custom CA roots
  and root-only trust stores for private PKI.
- After JSON request bodies are handed to `reqwest`, buffers owned by the HTTP
  stack, TLS backend, operating system, or network device are outside this
  crate's zeroization control.
