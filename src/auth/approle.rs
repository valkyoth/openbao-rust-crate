//! AppRole authentication support.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{Authenticated, Client, Error, Result, Unauthenticated, path::validate_mount_path};

/// Handle for the AppRole auth method at a configured mount.
#[derive(Debug)]
pub struct AppRole<'a> {
    client: &'a Client<Unauthenticated>,
    mount: String,
}

/// Metadata returned after a successful login.
#[derive(Debug, Deserialize)]
pub struct LoginMetadata {
    /// Token accessor. Accessors can revoke or look up token metadata, so they
    /// are treated as secret material.
    pub accessor: SecretString,
    /// Policies attached to the token.
    #[serde(
        default,
        deserialize_with = "crate::response::deserialize_bounded_string_vec"
    )]
    pub policies: Vec<String>,
    /// Token lease duration in seconds.
    #[serde(default)]
    pub lease_duration: u64,
    /// Whether the token is renewable.
    #[serde(default)]
    pub renewable: bool,
}

#[derive(Serialize)]
struct LoginRequest<'a> {
    role_id: &'a str,
    secret_id: &'a str,
}

#[derive(Deserialize)]
struct LoginResponse {
    auth: Option<LoginAuth>,
}

#[derive(Deserialize)]
struct LoginAuth {
    #[serde(deserialize_with = "deserialize_secret")]
    client_token: SecretString,
    #[serde(deserialize_with = "deserialize_secret")]
    accessor: SecretString,
    #[serde(
        default,
        deserialize_with = "crate::response::deserialize_bounded_string_vec"
    )]
    policies: Vec<String>,
    #[serde(default)]
    lease_duration: u64,
    #[serde(default)]
    renewable: bool,
}

impl Client<Unauthenticated> {
    /// Uses the AppRole auth method mounted at `auth/approle`.
    pub fn approle(&self) -> Result<AppRole<'_>> {
        self.approle_at("approle")
    }

    /// Uses the AppRole auth method mounted at `auth/{mount}`.
    pub fn approle_at(&self, mount: impl Into<String>) -> Result<AppRole<'_>> {
        let mount = mount.into();
        let mount = validate_mount_path(&mount)?.join("/");
        Ok(AppRole {
            client: self,
            mount,
        })
    }

    /// Logs in with AppRole at `auth/approle` and returns an authenticated client.
    pub async fn login_approle(
        self,
        role_id: SecretString,
        secret_id: SecretString,
    ) -> Result<(Client<Authenticated>, LoginMetadata)> {
        let response = self
            .approle()?
            .login_response(&role_id, &secret_id)
            .await?
            .auth
            .ok_or(Error::MissingField("auth"))?;
        let (token, metadata) = split_login_auth(response);
        Ok((self.with_token(token), metadata))
    }
}

impl AppRole<'_> {
    /// Logs in and returns token metadata plus an authenticated client.
    pub async fn login(
        self,
        role_id: SecretString,
        secret_id: SecretString,
    ) -> Result<(Client<Authenticated>, LoginMetadata)> {
        let response = self
            .login_response(&role_id, &secret_id)
            .await?
            .auth
            .ok_or(Error::MissingField("auth"))?;
        let (token, metadata) = split_login_auth(response);
        Ok((
            self.client.clone_without_state().with_token(token),
            metadata,
        ))
    }

    async fn login_response(
        &self,
        role_id: &SecretString,
        secret_id: &SecretString,
    ) -> Result<LoginResponse> {
        let request = LoginRequest {
            role_id: role_id.expose_secret(),
            secret_id: secret_id.expose_secret(),
        };
        self.client
            .request_json(
                reqwest::Method::POST,
                &format!("auth/{}/login", self.mount),
                Some(&request),
            )
            .await
    }
}

fn split_login_auth(auth: LoginAuth) -> (SecretString, LoginMetadata) {
    let LoginAuth {
        client_token,
        accessor,
        policies,
        lease_duration,
        renewable,
    } = auth;
    let metadata = LoginMetadata {
        accessor,
        policies,
        lease_duration,
        renewable,
    };
    (client_token, metadata)
}

fn deserialize_secret<'de, D>(deserializer: D) -> core::result::Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    Ok(SecretString::from(value))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::ExposeSecret;

    use super::LoginResponse;

    #[test]
    fn login_auth_deserializes_secrets_into_secret_strings() {
        let response: LoginResponse = serde_json::from_str(
            r#"{"auth":{"client_token":"token-value","accessor":"accessor-value"}}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let auth = response.auth.unwrap_or_else(|| panic!("auth missing"));

        assert_eq!(auth.client_token.expose_secret(), "token-value");
        assert_eq!(auth.accessor.expose_secret(), "accessor-value");
    }

    #[test]
    fn approle_policies_are_bounded() {
        let mut policies = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            policies.push(format!("policy-{index}"));
        }
        let value = serde_json::json!({ "auth": { "client_token": "token", "accessor": "accessor", "policies": policies } });
        let error = match serde_json::from_value::<LoginResponse>(value) {
            Ok(_) => panic!("oversized AppRole policy list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }
}
