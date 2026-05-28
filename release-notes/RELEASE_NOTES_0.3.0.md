# OpenBao Rust SDK 0.3.0 Release Notes

## Version

- Version: 0.3.0
- Release date: 2026-05-28
- Git tag: `v0.3.0`
- Git commit: tag target for `v0.3.0`
- License: MIT OR Apache-2.0

## Scope

- Stable modules carried from `0.2.0`: client configuration, direct token auth,
  AppRole login, token lifecycle helpers, KV v1, expanded KV v2 operations,
  sys health/seal status, mount/auth mount management, response wrapping, ACL
  policies, and capabilities.
- New `0.3.0` modules started: Transit helpers, sys audit device helpers,
  safe exact lease lookup, renew, and revoke helpers, and plugin catalog
  helpers.
- System helpers now include `/sys/init` status and a loopback-only
  `bootstrap_dev` convenience flow for disposable local development instances.
- Transit helpers cover key create/read/list/delete, encrypt, decrypt, rewrap,
  data key, random, hash, HMAC, sign, and verify endpoints.
- Plugin helpers cover catalog list, type-list, register, read, delete, and
  mounted backend reload endpoints.
- Default Cargo features: `approle`, `token`, `kv1`, `kv2`, `transit`, `sys`,
  `rustls-tls`.
- Minimum supported Rust: 1.95.0.
- Tested OpenBao version: latest OpenBao release verified as `v2.5.4` on
  2026-05-28.

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
- Server-controlled maps for capabilities, mounts, audit devices, KV metadata,
  token metadata, and Transit key versions are bounded during deserialization.
- SHA-1 Transit hashing is deprecated at compile time, and Transit signatures
  and derived public keys are wrapped as `SecretString`.
- Plugin registration SHA-256 digests are validated as 64-character hex before
  requests are sent.
- The legacy `native-tls` feature now requires explicit
  `native-tls-acknowledged` opt-in after audit.
- Token and AppRole login response structs no longer implement `Clone`, which
  avoids accidental extra token/accessor heap copies.
- Residual request-body memory owned by `reqwest`, TLS, the kernel, or devices
  is documented in `SECURITY.md`.
- `bootstrap_dev` refuses non-loopback and already-initialized targets, returns
  root/unseal material as secret values, and is documented as unsuitable for
  production, shared environments, or HSM/KMS-backed auto-unseal deployments.

## Security And Stability Gate

- Gate command: `scripts/release_0_3_gate.sh`
- Result: local release gate passed on 2026-05-28 after pentest remediations.
- Pentest report: local `PENTEST.md` reviewed on 2026-05-28; all actionable
  findings for `0.3.0` were remediated before tagging, and the local report
  was deleted after review.
- `cargo audit` result: passed on 2026-05-28.
- `cargo deny check` result: passed on 2026-05-28 with duplicate dependency
  warnings only.
- CodeQL result: pending through GitHub default setup
- Podman OpenBao integration result: passed on 2026-05-28.
- SBOM generation result: passed on 2026-05-28.

## Known Limitations

- Transit batch, import, export, backup, restore, and BYOK endpoints are not
  part of this initial typed Transit slice.
- Plugin OCI initialization and reload status endpoints are not part of this
  initial typed plugin slice.
- Exact certificate/public-key pinning is not implemented; use custom CA roots
  and root-only trust stores for private PKI.
- Production init, unseal, rekey, and rotate APIs remain planned for a later
  explicitly gated safety surface; `bootstrap_dev` is intentionally limited to
  fresh loopback development instances.
- After JSON request bodies are handed to `reqwest`, buffers owned by the HTTP
  stack, TLS backend, operating system, or network device are outside this
  crate's zeroization control.
