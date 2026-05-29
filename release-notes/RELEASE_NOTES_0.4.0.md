# OpenBao Rust SDK 0.4.0 Release Notes

## Version

- Version: 0.4.0
- Release date: TBD
- Git tag: `v0.4.0`
- Git commit: TBD
- License: MIT OR Apache-2.0

## Scope

- Stable modules carried from `0.3.0`: client configuration, direct token auth,
  AppRole login, token lifecycle helpers, KV v1/v2, Transit, sys health/seal
  status, loopback-only dev bootstrap, mount/auth mount management, response
  wrapping, ACL policies, capabilities, audit devices, exact lease helpers,
  and plugin catalog helpers.
- New `0.4.0` work started: environment-based client construction for
  OpenBao/Vault-compatible address, token, namespace, CA certificate,
  root-only trust, and loopback HTTP opt-in variables.
- Kubernetes auth helpers cover login, auth method config, role
  write/read/list/delete, and secret-aware service account JWT handling.
- TLS certificate auth helpers cover login, auth method config, CA role
  write/read/list/delete, CRL write/read/list/delete, and mutual TLS client
  identity configuration.
- PKI helpers cover URL config, role write/read/list/delete, issue, sign,
  revoke, certificate list, and certificate read.
- Planned remaining `0.4.0` modules: broader PKI authority management and KV
  v2 service config loading.
- Default Cargo features: `approle`, `cert-auth`, `kubernetes-auth`, `token`,
  `kv1`, `kv2`, `pki`, `transit`, `sys`, `rustls-tls`.
- Minimum supported Rust: 1.95.0.
- Tested OpenBao version: latest release must be verified before tag.

## Security Changes

- Environment-based construction preserves secure defaults: HTTPS is still
  required unless an explicit loopback HTTP opt-in variable is set, and
  loopback HTTP remains restricted to numeric loopback hosts.
- Environment token aliases are loaded into `SecretString`.
- Custom CA files can be merged with system roots or used as the only trusted
  roots through explicit root-only trust variables.
- Namespace values from environment variables are path-validated before use.
- Kubernetes service account JWTs and token reviewer JWTs are handled as
  `SecretString` and exposed only in request payloads immediately before the
  shared HTTP request layer.
- Kubernetes role names, mount paths, and login roles are path-validated before
  request construction.
- Kubernetes role lists and login metadata maps are bounded during
  deserialization.
- TLS certificate auth role names, CRL names, mount paths, and login role names
  are path-validated before request construction.
- TLS certificate auth tokens/accessors are represented as `SecretString`,
  role/CRL lists and CRL serial maps are bounded during deserialization, and
  role fields accept both documented comma-delimited strings and arrays.
- Mutual TLS client identities are configured through `OpenBaoConfig` and are
  redacted from debug output as a boolean presence flag only.
- PKI generated private keys are represented as `SecretString` and redacted
  from debug output.
- PKI role lists, certificate lists, CA chains, URL config lists, and role list
  fields are bounded during deserialization.

## Security And Stability Gate

- Gate command: `scripts/release_0_4_gate.sh`
- Result: pending
- Pentest report: required before tagging `v0.4.0`
- `cargo audit` result: pending
- `cargo deny check` result: pending
- CodeQL result: pending through GitHub default setup
- Podman OpenBao integration result: pending
- SBOM generation result: pending

## Known Limitations

- Advanced PKI authority management is not complete yet, including issuer/key
  lifecycle, root/intermediate generation/import, CRL rotation/tidy, and ACME.
- KV service config helpers are not complete yet.
- Exact certificate/public-key pinning is not implemented; use custom CA roots
  and root-only trust stores for private PKI.
