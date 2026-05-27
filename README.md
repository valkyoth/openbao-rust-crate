# OpenBao Rust SDK

`openbao` is a secure, async Rust SDK for [OpenBao](https://openbao.org/).

The crate name on crates.io is intended to be `openbao`; the project and public
branding use `OpenBao`. Rust imports are lowercase:

```rust
use openbao::Client;
```

## Security Posture

- Unsafe Rust is forbidden.
- HTTPS is required by default.
- Loopback HTTP requires explicit opt-in for tests and local-only development.
- Tokens use `secrecy::SecretString` and are redacted from `Debug`.
- Authentication headers are marked sensitive before requests are sent.
- URLs are assembled with structured path segments instead of string
  concatenation.
- Path traversal, query injection, fragment injection, empty segments, and
  OpenBao path parameters ending in `.` are rejected client-side.
- The default token header is the officially documented `X-Vault-Token`.
- `X-Vault-Request: true` is sent on requests, matching OpenBao SDK behavior.
- Dependencies are intentionally small and tracked by `cargo audit`,
  `cargo deny`, CodeQL, Dependabot, and release gates.

## Current Scope

Version `0.1.0` provides a functional first SDK slice:

- secure client configuration;
- direct token auth;
- AppRole login;
- KV v2 read/write/list/delete;
- system health and seal status;
- raw JSON request support for advanced OpenBao APIs.

See [docs/RELEASE_PLAN.md](docs/RELEASE_PLAN.md) for the complete path to
`1.0.0`.

## Install

```toml
[dependencies]
openbao = "0.1"
secrecy = "0.10.3"
serde = { version = "1.0.228", features = ["derive"] }
tokio = { version = "1.52.3", features = ["macros", "rt-multi-thread"] }
```

## Direct Token Example

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
        .kv2("secret")
        .read::<DbCredentials>("production/database")
        .await?;

    println!("username: {}", secret.data.username);
    let _password = secret.data.password;
    Ok(())
}
```

## AppRole Example

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

    println!("token accessor: {}", login.accessor);
    println!("openbao version: {}", health.version);
    Ok(())
}
```

## Local OpenBao Dev Instance

The local dev stack uses Podman, TLS, a private CA, and loopback-only ports in
the requested `994x` range.

```sh
scripts/openbao_dev.sh up
```

Endpoints:

- API: `https://127.0.0.1:9940`
- Cluster: `https://127.0.0.1:9941`
- CA certificate: `deploy/podman/dev-state/tls/dev-ca.crt`

Initialize and unseal OpenBao using `bao operator init` and
`bao operator unseal`, then export `BAO_ADDR=https://127.0.0.1:9940` and
`BAO_CACERT=deploy/podman/dev-state/tls/dev-ca.crt`.

## Release Discipline

Every version is expected to pass:

```sh
scripts/checks.sh
```

Stable releases also require:

```sh
scripts/stable_release_gate.sh
```

No release tag should be cut until the matching pentest report is reviewed and
recorded in the release notes.
