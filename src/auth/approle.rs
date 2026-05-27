//! AppRole authentication support.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{Authenticated, Client, Error, Result, Unauthenticated, response::Empty};

/// Handle for the AppRole auth method at a configured mount.
#[derive(Debug)]
pub struct AppRole<'a> {
    client: &'a Client<Unauthenticated>,
    mount: String,
}

/// Non-secret metadata returned after a successful login.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoginMetadata {
    /// Token accessor.
    pub accessor: String,
    /// Policies attached to the token.
    #[serde(default)]
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
    client_token: String,
    accessor: String,
    #[serde(default)]
    policies: Vec<String>,
    #[serde(default)]
    lease_duration: u64,
    #[serde(default)]
    renewable: bool,
}

impl Client<Unauthenticated> {
    /// Uses the AppRole auth method mounted at `auth/approle`.
    pub fn approle(&self) -> AppRole<'_> {
        self.approle_at("approle")
    }

    /// Uses the AppRole auth method mounted at `auth/{mount}`.
    pub fn approle_at(&self, mount: impl Into<String>) -> AppRole<'_> {
        AppRole {
            client: self,
            mount: mount.into(),
        }
    }

    /// Logs in with AppRole at `auth/approle` and returns an authenticated client.
    pub async fn login_approle(
        self,
        role_id: SecretString,
        secret_id: SecretString,
    ) -> Result<(Client<Authenticated>, LoginMetadata)> {
        let response = self
            .approle()
            .login_response(&role_id, &secret_id)
            .await?
            .auth
            .ok_or(Error::MissingField("auth"))?;
        let metadata = LoginMetadata {
            accessor: response.accessor,
            policies: response.policies,
            lease_duration: response.lease_duration,
            renewable: response.renewable,
        };
        Ok((
            self.with_token(SecretString::from(response.client_token)),
            metadata,
        ))
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
        let metadata = LoginMetadata {
            accessor: response.accessor,
            policies: response.policies,
            lease_duration: response.lease_duration,
            renewable: response.renewable,
        };
        Ok((
            self.client
                .clone_without_state()
                .with_token(SecretString::from(response.client_token)),
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

impl Client<Unauthenticated> {
    fn clone_without_state(&self) -> Client<Unauthenticated> {
        Client {
            config: self.config.clone(),
            http: self.http.clone(),
            token: None,
            _state: core::marker::PhantomData,
        }
    }
}

#[allow(dead_code)]
fn _empty_payload() -> Empty {
    Empty {}
}
