<p align="center">
  <b>Secure, typed, async Rust SDK for OpenBao.</b><br>
  Memory-safe Rust API. Reviewed dependency surface. Built for audited secret workflows.
</p>

<div align="center">
  <a href="https://openbao.org/">OpenBao</a>
  ·
  <a href="https://docs.rs/openbao">API Documentation</a>
  ·
  <a href="https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/docs/CURRENT_STATUS.md">Current Status</a>
  ·
  <a href="https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/docs/OPENBAO_API_COVERAGE.md">API Coverage</a>
  ·
  <a href="https://github.com/valkyoth/openbao-rust-crate/security">Security</a>
</div>

<br>

<p align="center">
  <img src="https://raw.githubusercontent.com/valkyoth/openbao-rust-crate/v2.1.3/.github/images/openbao_rust_crate.webp" alt="OpenBao Rust crate overview">
</p>

# OpenBao Rust SDK

Secure, typed, async Rust SDK for
[OpenBao](https://openbao.org/). The crate is designed for audited secret
workflows: HTTPS and TLS 1.3 by default, disabled redirects, strict path and
response bounds, secret-aware values, and fail-closed server-version
compatibility.

[API documentation](https://docs.rs/openbao) | [Source](https://github.com/valkyoth/openbao-rust-crate) | [Security](https://github.com/valkyoth/openbao-rust-crate/security) | [Releases](https://github.com/valkyoth/openbao-rust-crate/releases)

The current `2.1.x` line supports every published stable OpenBao release from
`2.0.0` through `2.6.1` through immutable compatibility profiles. Rust `1.97.1`
is the primary checked toolchain and Rust `1.90.0` is the MSRV.

## Install

```toml
[dependencies]
openbao = "2.1.3"
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Default features select the Rustls TLS backend and the primary authentication,
secret-engine, and system APIs. Capabilities with additional security or
dependency costs are opt-in; see [Feature Selection](#feature-selection).

## Quick Start

The environment constructor reads the supported `OPENBAO_*`, `BAO_*`, and
`VAULT_*` aliases. The authenticated variant validates the token before the
first request.

```rust,no_run
use openbao::{Client, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::from_env_with_token()?;
    let health = client.sys().health().await?;
    println!("sealed: {}", health.sealed);
    Ok(())
}
```

Typed secret responses let applications select which fields require secret
storage:

```rust,no_run
use openbao::{Client, Result, SecretString};
use serde::Deserialize;

#[derive(Deserialize)]
struct DatabaseCredentials {
    username: String,
    password: SecretString,
}

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::from_env_with_token()?;
    let secret = client
        .kv2("secret")?
        .read::<DatabaseCredentials>("production/database")
        .await?;

    let _username = secret.data.username;
    let _password = secret.data.password;
    Ok(())
}
```

Do not print or serialize secret values into diagnostics. `SecretString` and
the crate's secret response types redact `Debug`, but exposing a secret remains
an explicit application responsibility.

## OpenBao Version Selection

The `/v1` URL prefix is not an API-version guarantee. Use strict automatic
selection for normal deployments or an exact policy when the server release is
pinned:

```rust,no_run
use openbao::{
    Client, OpenBaoCompatibilityPolicy, OpenBaoConfig, OpenBaoVersion, Result,
};

fn exact_openbao_2_2() -> Result<Client> {
    let policy = OpenBaoCompatibilityPolicy::exact(OpenBaoVersion::new(2, 2, 0))?;
    let config = OpenBaoConfig::new("https://bao.example.com:8200")?
        .compatibility_policy(policy);
    Client::from_config(config)
}
```

The first compatible operation performs a token-free `/sys/health` probe and
caches the selected profile in that client. A mismatch fails before a typed
operation is sent. Rolling ranges verify only the backend that answered the
probe, so mixed clusters still require backend affinity or use of the common
capability intersection.

See the versioned source documentation for the complete policy:

- [server version selection](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/docs/OPENBAO_VERSION_SELECTION.md);
- [tested server matrix](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/docs/OPENBAO_VERSION_SUPPORT_MATRIX.md);
- [response compatibility](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/docs/OPENBAO_RESPONSE_COMPATIBILITY.md).

## Coverage

The typed API includes:

- AppRole, token, certificate, Kubernetes, JWT/OIDC, LDAP, RADIUS, Kerberos,
  and userpass authentication;
- KV v1/v2, Cubbyhole, Kubernetes, RabbitMQ, LDAP, database, Transit, PKI,
  TOTP, and SSH secret engines;
- Identity entities, groups, aliases, OIDC providers, and MFA administration;
- health, readiness, mounts, audit devices, leases, policies, capabilities,
  namespaces, Raft, quotas, plugins, wrapping, metrics, and system tools;
- OpenBao 2.6 workflows, JWT CEL roles, identity-template controls, userpass
  bcrypt hashes, and sealable namespaces; and
- idempotent bootstrap convergence for common application-owned resources.

Destructive operator ceremonies, raw transports, unstable internal endpoints,
credential-bearing URL query flows, and other high-risk operations require
explicit feature acknowledgements. This keeps them unavailable to ordinary
builds while retaining typed support for reviewed operator tooling.

Detailed inventories:

- [current capability status](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/docs/CURRENT_STATUS.md);
- [API coverage](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/docs/OPENBAO_API_COVERAGE.md);
- [custom plugin pattern](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/docs/CUSTOM_PLUGIN_PATTERN.md).

## Feature Selection

Important non-default features include:

| Feature | Purpose |
| --- | --- |
| `http2` | Enable HTTP/2 negotiation through TLS ALPN. |
| `time` | Parse timestamps into `time` crate types. |
| `tokio-helpers` | Add Tokio-backed bounded readiness waits. |
| `tracing` | Emit redacted request spans without an OpenTelemetry SDK dependency. |
| `monitor-stream` | Expose bounded, secret-aware system log streaming. |
| `raft-stream` | Stream large Integrated Storage restore bodies. |
| `transit-bytes` | Add secret byte encode/decode helpers. |
| `transit-import` | Add software Transit BYOK wrapping; also requires `transit-import-acknowledged`. |
| `memory-lock` | Keep the authenticated client's retained token in locked mapped memory; also requires `memory-lock-acknowledged`. |
| `operator-ops` | Expose production operator ceremonies; also requires `operator-ops-acknowledged`. |
| `raw-api` | Expose generic transports; also requires `raw-api-acknowledged`. |
| `unstable-internal-ops` | Expose unstable OpenBao internal endpoints with both operator and unstable acknowledgements. |

Several protocol-specific features have matching `-acknowledged` gates. Cargo
will reject incomplete high-risk feature combinations at compile time. Review
the [complete feature list](https://docs.rs/crate/openbao/latest/features) and
the detailed security model before enabling one.

## Security

Key defaults and controls:

- `unsafe_code = "forbid"` for this crate's own Rust sources; TLS and
  cryptographic dependencies can contain unsafe Rust, FFI, assembly, or native
  code and remain part of the trusted computing base;
- Rustls and TLS 1.3 by default;
- root-only private-CA trust and static CRL support;
- redirects disabled;
- bounded request and response bodies;
- validated paths, headers, CIDRs, durations, and collection sizes;
- redacted API errors, tracing fields, tokens, accessors, and credential types;
- immutable OpenBao compatibility profiles without fallback route probing;
- optional fail-closed locked storage for the retained client token; and
- dependency, RustSec, package, Kani, compatibility, and pentest release gates.

HTTP, TLS, allocator, kernel, and device layers can retain secret copies beyond
the buffers controlled by this crate. Other request and response secrets are
not automatically locked by the `memory-lock` feature. High-assurance users
must review process isolation, core dumps, swap, memory-lock quotas, TLS
termination, and feature selection.

Read [`SECURITY.md`](SECURITY.md) for reporting and baseline policy. The
[detailed security model](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/docs/SECURITY_MODEL.md)
records feature-specific controls, residual risks, and hardened deployment
guidance.

## Examples And Guides

The repository contains compiled examples rather than duplicating dozens of
unchecked Markdown programs:

- [environment client](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/examples/from_env.rs);
- [KV v2](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/examples/kv2.rs);
- [AppRole login](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/examples/approle.rs);
- [exact OpenBao 2.2 profile](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/examples/openbao_2_2.rs);
- [admin bootstrap](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/examples/bootstrap.rs);
- [system administration](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/examples/sys_admin.rs).

Additional repository documentation:

- [migration guide](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/docs/MIGRATION_GUIDE.md);
- [API stability audit](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/docs/API_STABILITY_AUDIT.md);
- [panic policy](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/docs/PANIC_POLICY.md);
- [Kani proofs](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/kani/README.md);
- [release plan](https://github.com/valkyoth/openbao-rust-crate/blob/v2.1.3/docs/RELEASE_PLAN.md).

## Development And Releases

Repository-only compatibility fixtures, integration harnesses, fuzz targets,
formal proofs, release scripts, and historical evidence remain available in
the signed source tag without being copied into the crates.io archive.

From a checkout, run the standard gate with:

```bash
scripts/checks.sh
```

Every release additionally requires version-locked OpenBao integration,
package verification, a reviewed pentest report, and the matching release
gate. Release history is recorded in [`CHANGELOG.md`](CHANGELOG.md) and
[GitHub releases](https://github.com/valkyoth/openbao-rust-crate/releases).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE));
- MIT License ([LICENSE-MIT](LICENSE-MIT)).
