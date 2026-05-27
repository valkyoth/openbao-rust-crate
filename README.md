<p align="center">
  <b>Secure, typed, async Rust SDK for OpenBao.</b><br>
  Memory-safe by default. Minimal dependency surface. Built for audited secret workflows.
</p>

<div align="center">
  <a href="https://openbao.org/">OpenBao</a>
  ·
  <a href="docs/OPENBAO_API_COVERAGE.md">API Coverage</a>
  ·
  <a href="docs/RELEASE_PLAN.md">Release Plan</a>
  ·
  <a href="SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <img src="./.github/images/openbao_rust_crate.webp" alt="OpenBao Rust crate overview">
</p>

# OpenBao Rust SDK

`openbao` is a secure, async Rust SDK for [OpenBao](https://openbao.org/).
The crate name on crates.io is intended to be `openbao`; Rust imports are
lowercase:

```rust
use openbao::Client;
```

The current development target is `0.2.0`: token lifecycle helpers, KV v1, KV v2
metadata/version/config operations, mount management, response wrapping,
policies, capabilities, and real OpenBao integration coverage on top of the
secure `0.1.0` core.

OpenBao Rust SDK is dual-licensed under MIT or Apache-2.0.

## What Works Today

### Client, Transport, And TLS

| Capability | Status | Notes |
| --- | --- | --- |
| Async client | Yes | Built on `reqwest` with a small public API surface. |
| Typestate auth | Yes | Separate unauthenticated and authenticated client states. |
| HTTPS by default | Yes | Plain HTTP is rejected unless loopback HTTP is explicitly enabled. |
| Redirect protection | Yes | Redirect following is disabled to avoid forwarding token headers. |
| TLS floor | Yes | TLS 1.3 minimum by default; audited legacy deployments can explicitly opt down to TLS 1.2. |
| Custom CA roots | Yes | Extra root certificates can be merged with the platform trust store. |
| Root-only trust stores | Yes | System roots can be bypassed by using only configured root certificates. |
| Connection timeout | Yes | 5-second connection timeout by default; caller overrides are bounded at 5 minutes. |
| User agent fingerprinting | Yes | Default user agent omits the exact crate version. |
| Namespace header | Yes | `X-Vault-Namespace` support for namespace-aware deployments. |
| Raw JSON requests | Yes | Escape hatch for endpoints that are not typed yet. |

### Authentication

| Capability | Status | Notes |
| --- | --- | --- |
| Direct token auth | Yes | Tokens are accepted as `secrecy::SecretString`. |
| `X-Vault-Token` | Yes | Default documented OpenBao-compatible token header. |
| Bearer auth | Yes | Optional `Authorization: Bearer` header mode. |
| AppRole login | Yes | Role ID and secret ID are secret-aware; returned token is wrapped in `SecretString`. |
| Token accessor handling | Yes | AppRole token accessors are treated as secret material. |
| Token lifecycle helpers | Yes | Lookup, accessor lookup/list, renew, revoke, revoke-self, and create helpers. |
| Kubernetes auth | Planned | Planned for `0.4.0`. |
| TLS certificate auth | Planned | Planned for `0.4.0`. |
| JWT/OIDC and userpass | Planned | Planned for `0.5.0`. |

### Secret Engines

| Capability | Status | Notes |
| --- | --- | --- |
| KV v2 read | Yes | Typed deserialization into caller-provided structs. |
| KV v2 write | Yes | Typed serialization with zeroized intermediate JSON buffer. |
| KV v2 CAS write | Yes | Optional check-and-set version support. |
| KV v2 patch | Yes | Partial secret updates with documented JSON merge patch content type. |
| KV v2 list | Yes | `LIST` method support for metadata paths. |
| KV v2 delete latest | Yes | Accepts documented `200` and `204` success responses. |
| KV v2 metadata/version APIs | Yes | Version reads, soft delete, undelete, destroy, metadata, and config helpers. |
| KV v1 | Yes | Read, write, delete, and list helpers for non-versioned KV mounts. |
| Transit | Planned | Planned for `0.3.0`. |
| PKI | Planned | Planned for `0.4.0`. |
| Database credentials | Planned | Planned for `0.5.0`. |
| SSH and TOTP | Planned | Planned for `0.6.0`. |
| Identity and remaining engines | Planned | Planned for `0.7.0`. |

### System Backend And Operations

| Capability | Status | Notes |
| --- | --- | --- |
| Health | Yes | Accepts OpenBao health statuses for active, standby, sealed, and uninitialized nodes. |
| Seal status | Yes | Typed `/sys/seal-status` helper. |
| Mount management | Yes | Secret and auth mount enable/list/tune/disable helpers. |
| Response wrapping | Yes | Lookup, wrap, unwrap, and rewrap helpers with secret-aware wrapping tokens. |
| Policies and capabilities | Yes | ACL policy list/read/write/delete plus self/token/accessor capability checks. |
| Audit devices | Planned | Enable/list/disable/hash in `0.3.0`. |
| Lease helpers | Planned | Safe non-legacy lease endpoints in `0.3.0`. |
| Init, unseal, rekey, rotate | Planned | Behind explicit safety documentation in `0.6.0`. |
| Plugins, quotas, metrics, namespaces | Planned | Planned in the `0.8.0` operations line. |

### Security And Release Process

| Capability | Status | Notes |
| --- | --- | --- |
| Unsafe Rust policy | Yes | `unsafe_code = "forbid"`. |
| Secret handling | Yes | Token-bearing APIs use `SecretString`; intermediate auth buffers are zeroized where practical. |
| Path validation | Yes | Rejects traversal, query/fragment injection, empty segments, control characters, and trailing periods. |
| Dependency policy | Yes | `cargo deny` enforces source and license policy. |
| RustSec audit | Yes | `cargo audit` is part of the release gate. |
| CodeQL | Yes | Uses GitHub CodeQL default setup; no advanced workflow is committed. |
| SBOM | Yes | `scripts/generate-sbom.sh` writes CycloneDX JSON. |
| Pentest gate | Yes | Release notes record pentest review status before tagging. |
| Local OpenBao dev stack | Yes | Podman TLS dev instance on `9940` and `9941`. |

See [API Coverage](docs/OPENBAO_API_COVERAGE.md) and
[Release Plan](docs/RELEASE_PLAN.md) for the precise road to `1.0.0`.

## Why OpenBao Rust SDK

- **Security first**: HTTPS by default, no redirects, TLS floor, strict path
  validation, zeroized intermediate auth buffers, and secret-aware types.
- **OpenBao focused**: follows the current OpenBao `/v1` HTTP API and documented
  token header behavior.
- **Small dependency surface**: keeps runtime dependencies narrow and reviewed.
- **Typed where it matters**: safe typed helpers for common workflows, with a raw
  JSON escape hatch while coverage grows.
- **Release discipline**: security checks, SBOM, GitHub CodeQL default setup,
  and pentest review are treated as release inputs, not afterthoughts.

## Quick Start

Add the crate:

```toml
[dependencies]
openbao = "0.2"
secrecy = "0.10.3"
serde = { version = "1.0.228", features = ["derive"] }
tokio = { version = "1.52.3", features = ["macros", "rt-multi-thread"] }
```

Read a KV v2 secret:

```rust,no_run
use openbao::{Client, Result};
use secrecy::SecretString;
use serde::Deserialize;

#[derive(Deserialize)]
struct DbCredentials {
    username: String,
    password: SecretString,
}

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.with_token(token);

    let secret = client
        .kv2("secret")?
        .read::<DbCredentials>("production/database")
        .await?;

    println!("username: {}", secret.data.username);
    let _password = secret.data.password;
    Ok(())
}
```

Authenticate with AppRole:

```rust,no_run
use openbao::{Client, Result};
use secrecy::SecretString;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new("https://bao.example.com:8200")?;
    let role_id = SecretString::from(std::env::var("APPROLE_ROLE_ID").unwrap_or_default());
    let secret_id = SecretString::from(std::env::var("APPROLE_SECRET_ID").unwrap_or_default());

    let (client, login) = client.login_approle(role_id, secret_id).await?;
    let health = client.sys().health().await?;

    let _token_accessor = login.accessor;
    println!("openbao version: {}", health.version);
    Ok(())
}
```

Write an ACL policy and check capabilities:

```rust,no_run
use openbao::{Client, Result};
use openbao::sys::PolicyWriteRequest;
use secrecy::SecretString;

#[tokio::main]
async fn main() -> Result<()> {
    let token = SecretString::from(std::env::var("BAO_TOKEN").unwrap_or_default());
    let client = Client::new("https://bao.example.com:8200")?.with_token(token);

    client
        .sys()
        .write_policy(
            "app-read",
            &PolicyWriteRequest {
                policy: r#"path "secret/data/app" { capabilities = ["read"] }"#.to_owned(),
                expiration: None,
                ttl: None,
                cas: None,
                cas_required: None,
            },
        )
        .await?;

    let capabilities = client.sys().capabilities_self(["secret/data/app"]).await?;
    let _for_path = capabilities.by_path.get("secret/data/app");
    Ok(())
}
```

## Local OpenBao Dev Instance

The local dev stack uses Podman, TLS, a private CA, and loopback-only ports in
the requested `994x` range.

Prepare the rootless Podman volume and TLS assets without starting OpenBao:

```bash
scripts/openbao_dev.sh prepare
```

This project does not require a `/srv` directory tree for local development:
raft data lives in a Podman-managed volume, and TLS material lives in the
ignored `deploy/podman/dev-state/` directory.

```bash
scripts/openbao_dev.sh up
```

Endpoints:

- API: `https://127.0.0.1:9940`
- Cluster: `https://127.0.0.1:9941`
- CA certificate: `deploy/podman/dev-state/tls/dev-ca.crt`

Initialize and unseal OpenBao using `bao operator init` and
`bao operator unseal`, then export `BAO_ADDR=https://127.0.0.1:9940` and
`BAO_CACERT=deploy/podman/dev-state/tls/dev-ca.crt`.

Run the real OpenBao integration flow:

```bash
scripts/openbao_integration.sh
```

The integration script creates a fresh TLS dev instance, initializes and
unseals it, stores the root token in a temporary `0600` file for the test
process, and removes that file when the run exits.

## Release Discipline

Run the normal local checks:

```bash
scripts/checks.sh
```

Run the current release gate:

```bash
scripts/release_0_2_gate.sh
```

Set `OPENBAO_SKIP_INTEGRATION=1` only when Podman is unavailable; release
candidate validation should run the integration gate.

No release tag should be cut unless the matching pentest report status is
reviewed and recorded in the release notes.
