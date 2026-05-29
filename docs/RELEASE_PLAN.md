# Release Plan

This plan starts at `0.1.0` and ends at `1.0.0`, the first stable release.
Every release must be functional enough to publish for external testing. No tag
is cut until the owner provides a pentest report for the exact release commit.

## Standing Release Gates

Every release:

- checks latest Rust and key dependency versions;
- verifies the documented Rust support range for the release;
- runs `cargo fmt --all --check`;
- runs `cargo clippy --all-targets --all-features -- -D warnings`;
- runs `cargo test --all-targets --all-features`;
- runs doctests;
- builds docs with all features;
- runs `cargo audit`;
- runs `cargo deny check`;
- generates an SBOM;
- validates release metadata;
- records pentest report status before tag.

## Downstream Ergonomics Backlog

Read-only review of Mjolni and Pawalyze on 2026-05-28 showed recurring
OpenBao glue that should become first-class crate ergonomics instead of being
reimplemented in applications:

- env-based client construction from `OPENBAO_ADDR`, `BAO_ADDR`, `VAULT_ADDR`,
  token aliases, namespace, and CA/root-only trust settings;
- KV v2 service config loading into `BTreeMap<String, SecretString>` and typed
  structs, with optional fallback behavior for local development;
- optional-feature byte-oriented Transit helpers that base64 encode/decode
  internally for encrypt, decrypt, HMAC, sign, verify, and envelope-key
  wrapping without adding the dependency to default builds;
- Transit signing helpers for JWT/JWKS use cases, including safe extraction of
  raw signature bytes and asymmetric public key metadata;
- idempotent admin bootstrap helpers for mounts, Transit keys, policies, KV
  secret patching, and scoped service-token creation;
- policy builder helpers for common KV v2 and Transit capabilities so projects
  do not assemble ACL HCL with ad hoc strings;
- best-effort FIPS posture helpers that validate crate request options against
  FIPS-oriented allowlists and emit an audit report, without claiming OpenBao,
  the host, TLS backend, or HSM/KMS module is certified;
- quantum-readiness helpers that inventory algorithms and prefer hybrid or
  post-quantum-safe choices when OpenBao exposes stable support;
- migration examples for projects currently using `vaultrs` or bespoke
  `reqwest` wrappers.

## Version Plan

### 0.1.0 - Secure Core And KV v2

Stop condition:

- secure client config exists;
- direct token auth works;
- AppRole login works;
- KV v2 read/write/list/delete works;
- system health and seal status work;
- local TLS OpenBao podman dev instance exists on ports `9940` and `9941`;
- docs explain first-use flows and limitations.

Publishable value:

- users can authenticate and read/write versioned secrets safely.

### 0.2.0 - Token, KV Completeness, And Mount Management

Stop condition:

- token lookup, renew, revoke, create, and accessor lookup helpers;
- KV v1 support;
- KV v2 metadata, undelete, destroy, patch, versions, and config support;
- sys mounts/auth mounts enable, tune, list, disable;
- response wrapping lookup, wrap, unwrap, rewrap;
- ACL policy list/read/write/delete and capability checks for self, token, and
  accessor;
- integration tests cover real OpenBao container flow.

Publishable value:

- users can manage common secret mounts and token lifecycle.

### 0.3.0 - Transit And Audit

Stop condition:

- transit key create/read/list/delete;
- encrypt, decrypt, rewrap, datakey, random, hash, hmac, sign, verify;
- audit device enable/list/disable/hash;
- lease lookup/renew/revoke supported only on non-legacy safe endpoints;
- loopback-only dev bootstrap for fresh local OpenBao instances;
- timing-sensitive docs for transit use cases.

Publishable value:

- users can delegate cryptographic operations to OpenBao.

### 0.4.0 - PKI, Kubernetes Auth, TLS Cert Auth

Stop condition:

- PKI roles, issue, sign, revoke, tidy, CA and CRL endpoints;
- Kubernetes auth login/config/role helpers;
- TLS certificate auth login/config/cert helpers;
- certificate examples and tests avoid writing private keys to logs.
- env-based client construction helper for common `OPENBAO_*`, `BAO_*`, and
  `VAULT_*` deployment variables;
- KV v2 service config loader for maps and typed structs.

Publishable value:

- users can automate certificates, workload auth, and service startup secret
  loading without custom OpenBao glue.

### 0.5.0 - Database, JWT/OIDC, Userpass

Stop condition:

- database engine config, roles, static roles, rotate root, credentials;
- JWT/OIDC role config and JWT login;
- userpass create/update/delete/login;
- byte-oriented Transit convenience helpers for envelope encryption and HMAC
  lookup-token patterns;
- Transit signing/JWKS helpers for RSA and Ed25519 JWT signing workflows;
- examples show short-lived database credentials.

Publishable value:

- users can retrieve dynamic credentials, support common human/machine auth,
  and move application crypto glue onto typed OpenBao helpers.

### 0.6.0 - SSH, TOTP, Production Init/Unseal Safety

Stop condition:

- SSH CA/sign/OTP helpers;
- TOTP key/code/validate helpers;
- idempotent admin bootstrap builder for mounts, Transit keys, ACL policies,
  KV secret patching, and scoped service-token creation;
- ACL policy builder for common KV v2 and Transit permissions;
- production init, unseal, rekey, rotate APIs behind explicit feature and
  warnings;
- tests prove production init/unseal APIs cannot be called accidentally from
  default docs.

Publishable value:

- users can support operational bootstrap, least-privilege service setup, and
  MFA-style workflows.

### 0.7.0 - Remaining Secret Engines And Identity

Stop condition:

- cubbyhole;
- identity entities/groups/aliases;
- Kubernetes secrets engine;
- LDAP secrets engine;
- RabbitMQ secrets engine;
- typed custom plugin API pattern documented.

Publishable value:

- broad OpenBao coverage for plugin-style engines and identity operations.

### 0.8.0 - Remaining Auth And System Backend

Stop condition:

- LDAP, RADIUS, Kerberos auth coverage;
- sys policies, capabilities, plugins catalog/reload, quotas, metrics,
  namespaces, storage, leader, HA status, loggers, locked users, version
  history;
- OpenAPI discovery helper.
- `FipsPosture` helper that can validate supported request builders and typed
  Transit choices against a conservative allowlist, warn on SHA-1, SHA-3,
  Ed25519, ChaCha20/XChaCha20, plaintext backup/exportable keys, convergent
  encryption, weak RSA sizes, and non-HSM/KMS seal assumptions, and produce a
  machine-readable report of what the crate could and could not verify.

Publishable value:

- operators can automate most OpenBao administration tasks and get a
  non-certifying compliance posture report for OpenBao usage.

### 0.9.0 - API Stabilization Candidate

Stop condition:

- public API audit completed;
- feature matrix frozen for `1.0`;
- migration guide from `0.1` through `0.9`;
- migration guide from `vaultrs` and bespoke `reqwest` OpenBao wrappers;
- quantum-readiness design note that tracks OpenBao support, avoids premature
  API promises, and defines how hybrid/post-quantum profiles will be exposed
  once stable upstream primitives exist;
- all docs examples compile;
- real OpenBao integration suite covers supported default features;
- fuzz tests cover path validation, error decoding, and response envelopes.

Publishable value:

- downstream users can trial the near-stable API.

### 1.0.0 - First Stable Release

Stop condition:

- complete documented support for selected stable API surface;
- no known high or critical findings from pentest;
- `cargo audit` clean or documented non-exploitable exceptions;
- `cargo deny check` clean;
- SBOM generated;
- docs.rs build verified;
- semver policy documented;
- security response policy finalized.

Publishable value:

- production-ready stable OpenBao SDK for Rust.
