# Typed Custom Plugin Pattern

OpenBao plugins often expose deployment-specific paths that this crate cannot
know ahead of time. Use `Client::request_json` as the transport primitive, but
wrap it in a small typed module so application code does not pass ad hoc paths,
unredacted secrets, or loosely shaped JSON values around the codebase.

Recommended pattern:

- keep plugin paths in one module;
- pass relative `/v1` paths to `request_json`;
- use `PluginMount` for mount validation and path construction;
- model request and response bodies with `serde` structs;
- use `openbao::SecretString` for every password, token, key, plaintext, or
  lease-like value;
- hand-write `Debug` for request/response structs that contain secrets;
- use `BoundedStringList` or `deserialize_bounded_string_vec` for returned
  string lists before exposing them to application code;
- cover the wrapper with a mock HTTP test that asserts the documented method
  and path.

Do not build a generic `Plugin` or `SecretEngine` trait around this pattern.
OpenBao plugin schemas are deployment-specific; a trait that only forwards to
`request_json` adds abstraction without adding safety.

## Example

```rust,no_run
use core::fmt;

use openbao::{
    Authenticated, Client, Empty, Method, PluginMount, ResponseEnvelope, Result, SecretString,
    deserialize_bounded_string_vec,
};
use serde::{Deserialize, Serialize};

pub struct ExamplePlugin<'a> {
    handle: PluginMount<'a>,
}

impl<'a> ExamplePlugin<'a> {
    pub fn new(client: &'a Client<Authenticated>, mount: &str) -> Result<Self> {
        Ok(Self {
            handle: PluginMount::new(client, mount)?,
        })
    }

    pub async fn write_account(&self, name: &str, request: &AccountRequest) -> Result<Empty> {
        self.handle
            .client()
            .request_json(
                Method::POST,
                &self.handle.path(&["accounts", name])?,
                Some(request),
            )
            .await
    }

    pub async fn credentials(&self, name: &str) -> Result<AccountCredentials> {
        let envelope: ResponseEnvelope<AccountCredentials> = self
            .handle
            .client()
            .request_json(
                Method::GET,
                &self.handle.path(&["creds", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    pub async fn list_roles(&self) -> Result<RoleList> {
        let envelope: ResponseEnvelope<RoleList> = self
            .handle
            .client()
            .request_json(
                Method::GET,
                &self.handle.path(&["roles"])?,
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

#[derive(Clone, Debug, Deserialize)]
pub struct RoleList {
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub roles: Vec<String>,
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
