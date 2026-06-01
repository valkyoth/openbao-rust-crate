# Typed Custom Plugin Pattern

OpenBao plugins often expose deployment-specific paths that this crate cannot
know ahead of time. Use `Client::request_json` as the transport primitive, but
wrap it in a small typed module so application code does not pass ad hoc paths,
unredacted secrets, or loosely shaped JSON values around the codebase.

Recommended pattern:

- keep plugin paths in one module;
- pass relative `/v1` paths to `request_json`;
- model request and response bodies with `serde` structs;
- use `openbao::SecretString` for every password, token, key, plaintext, or
  lease-like value;
- hand-write `Debug` for request/response structs that contain secrets;
- bound returned lists before exposing them to application code;
- cover the wrapper with a mock HTTP test that asserts the documented method
  and path.

## Example

```rust,no_run
use core::fmt;

use openbao::{Authenticated, Client, Empty, Error, Method, ResponseEnvelope, Result, SecretString};
use serde::{Deserialize, Serialize};

pub struct ExamplePlugin<'a> {
    client: &'a Client<Authenticated>,
    mount: String,
}

impl<'a> ExamplePlugin<'a> {
    pub fn new(client: &'a Client<Authenticated>, mount: impl Into<String>) -> Result<Self> {
        let mount = mount.into();
        validate_plugin_segment(&mount)?;
        Ok(Self { client, mount })
    }

    pub async fn write_account(&self, name: &str, request: &AccountRequest) -> Result<Empty> {
        validate_plugin_segment(name)?;
        self.client
            .request_json(
                Method::POST,
                &format!("{}/accounts/{}", self.mount, name),
                Some(request),
            )
            .await
    }

    pub async fn credentials(&self, name: &str) -> Result<AccountCredentials> {
        validate_plugin_segment(name)?;
        let envelope: ResponseEnvelope<AccountCredentials> = self
            .client
            .request_json(
                Method::GET,
                &format!("{}/creds/{}", self.mount, name),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }
}

#[derive(Clone, Serialize)]
pub struct AccountRequest {
    pub username: String,
    pub password: SecretString,
}

impl fmt::Debug for AccountRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountRequest")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Deserialize)]
pub struct AccountCredentials {
    pub username: String,
    pub password: SecretString,
}

impl fmt::Debug for AccountCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

fn validate_plugin_segment(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || value.contains('/')
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
        || value == "."
        || value == ".."
        || value.as_bytes().iter().any(u8::is_ascii_control)
    {
        return Err(Error::InvalidPath("invalid custom plugin path segment".into()));
    }
    Ok(())
}
```

The wrapper still uses the crate's authenticated client, TLS policy, namespace
handling, redirect policy, body size limit, decode sanitization, and secret-aware
response envelope. The plugin module adds the endpoint-specific typing and
redaction that the crate cannot infer from arbitrary JSON.

## Test Checklist

- Assert each wrapper method sends the documented HTTP method and `/v1/...`
  path.
- Assert token or namespace headers are present only when expected.
- Assert `Debug` output does not contain any secret field values.
- Add oversized-list decode tests for plugin responses that contain arrays or
  maps controlled by OpenBao or a plugin.
- Prefer deterministic fixture values assembled at runtime in tests when CodeQL
  could mistake names such as operation IDs, nonces, or tokens for real
  credentials.
