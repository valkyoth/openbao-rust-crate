//! Username and password authentication support.

use std::collections::BTreeMap;

use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    Authenticated, Client, Error, Result, Unauthenticated,
    path::validate_mount_path,
    response::{
        Empty, ResponseEnvelope, deserialize_bounded_string_map_or_default,
        deserialize_bounded_string_vec,
    },
};

/// Handle for Userpass auth login at a configured mount.
#[derive(Debug)]
pub struct UserpassAuth<'a> {
    client: &'a Client<Unauthenticated>,
    mount: String,
}

/// Handle for Userpass auth administration at a configured mount.
#[derive(Debug)]
pub struct UserpassAuthAdmin<'a> {
    client: &'a Client<Authenticated>,
    mount: String,
}

/// Userpass user create/update request.
#[derive(Clone, Default)]
pub struct UserpassUserRequest {
    /// Password used for userpass login.
    pub password: SecretString,
    /// Policies attached to generated tokens.
    pub token_policies: Vec<String>,
    /// Token TTL such as `30m`.
    pub token_ttl: Option<String>,
    /// Token max TTL such as `2h`.
    pub token_max_ttl: Option<String>,
    /// Periodic token period.
    pub token_period: Option<String>,
    /// Token explicit max TTL.
    pub token_explicit_max_ttl: Option<String>,
    /// Generated token type.
    pub token_type: Option<String>,
    /// CIDR restrictions for generated tokens.
    pub token_bound_cidrs: Vec<String>,
    /// Number of allowed token uses.
    pub token_num_uses: Option<u64>,
    /// Whether to omit the default policy.
    pub token_no_default_policy: Option<bool>,
}

#[derive(Serialize)]
struct UserpassUserPayload<'a> {
    password: &'a str,
    #[serde(skip_serializing_if = "is_empty_string_slice")]
    token_policies: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    token_ttl: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_max_ttl: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_period: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_explicit_max_ttl: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<&'a str>,
    #[serde(skip_serializing_if = "is_empty_string_slice")]
    token_bound_cidrs: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    token_num_uses: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_no_default_policy: Option<bool>,
}

impl UserpassUserRequest {
    /// Creates a userpass user request with a password.
    pub fn new(password: SecretString) -> Self {
        Self {
            password,
            ..Self::default()
        }
    }

    /// Adds a token policy.
    #[must_use]
    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.token_policies.push(policy.into());
        self
    }

    /// Adds a generated-token CIDR restriction.
    pub fn with_token_bound_cidr(mut self, cidr: impl Into<String>) -> Result<Self> {
        let cidr = cidr.into();
        crate::validation::validate_cidr(&cidr, "userpass token_bound_cidrs")?;
        self.token_bound_cidrs.push(cidr);
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        crate::validation::validate_cidr_list(&self.token_bound_cidrs, "userpass token_bound_cidrs")
    }
}

impl core::fmt::Debug for UserpassUserRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("UserpassUserRequest")
            .field("password", &"<redacted>")
            .field("token_policies", &self.token_policies)
            .field("token_ttl", &self.token_ttl)
            .field("token_max_ttl", &self.token_max_ttl)
            .field("token_period", &self.token_period)
            .field("token_explicit_max_ttl", &self.token_explicit_max_ttl)
            .field("token_type", &self.token_type)
            .field("token_bound_cidrs", &self.token_bound_cidrs)
            .field("token_num_uses", &self.token_num_uses)
            .field("token_no_default_policy", &self.token_no_default_policy)
            .finish()
    }
}

/// Userpass user configuration returned by OpenBao.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct UserpassUserInfo {
    /// Policies attached to generated tokens.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub token_policies: Vec<String>,
    /// Token TTL in seconds, when returned by OpenBao.
    #[serde(default)]
    pub token_ttl: u64,
    /// Token max TTL in seconds, when returned by OpenBao.
    #[serde(default)]
    pub token_max_ttl: u64,
    /// Periodic token period in seconds, when returned by OpenBao.
    #[serde(default)]
    pub token_period: u64,
    /// Token explicit max TTL in seconds, when returned by OpenBao.
    #[serde(default)]
    pub token_explicit_max_ttl: u64,
    /// Generated token type.
    #[serde(default)]
    pub token_type: Option<String>,
    /// CIDR restrictions for generated tokens.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub token_bound_cidrs: Vec<String>,
    /// Number of allowed token uses.
    #[serde(default)]
    pub token_num_uses: u64,
    /// Whether default policy is omitted.
    #[serde(default)]
    pub token_no_default_policy: bool,
}

/// Userpass user list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct UserpassUserList {
    /// User names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

/// Metadata returned after a successful Userpass login.
#[derive(Debug, Deserialize)]
pub struct UserpassLoginMetadata {
    /// Token accessor. Accessors can revoke or look up token metadata, so they
    /// are treated as secret material.
    pub accessor: SecretString,
    /// Policies attached to the token.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub policies: Vec<String>,
    /// Token lease duration in seconds.
    #[serde(default)]
    pub lease_duration: u64,
    /// Whether the token is renewable.
    #[serde(default)]
    pub renewable: bool,
    /// Metadata returned by OpenBao, usually including the username.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct UserpassLoginRequest<'a> {
    password: &'a str,
}

#[derive(Serialize)]
struct UserpassPasswordRequest<'a> {
    password: &'a str,
}

#[derive(Serialize)]
struct UserpassPoliciesRequest<'a> {
    token_policies: &'a [String],
}

#[derive(Deserialize)]
struct UserpassLoginResponse {
    auth: Option<UserpassLoginAuth>,
}

#[derive(Deserialize)]
struct UserpassLoginAuth {
    client_token: SecretString,
    accessor: SecretString,
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    policies: Vec<String>,
    #[serde(default)]
    lease_duration: u64,
    #[serde(default)]
    renewable: bool,
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    metadata: BTreeMap<String, String>,
}

impl Client<Unauthenticated> {
    /// Uses the Userpass auth method mounted at `auth/userpass`.
    pub fn userpass(&self) -> Result<UserpassAuth<'_>> {
        self.userpass_at("userpass")
    }

    /// Uses the Userpass auth method mounted at `auth/{mount}`.
    pub fn userpass_at(&self, mount: impl Into<String>) -> Result<UserpassAuth<'_>> {
        Ok(UserpassAuth {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }

    /// Logs in with Userpass auth at `auth/userpass`.
    pub async fn login_userpass(
        self,
        username: &str,
        password: SecretString,
    ) -> Result<(Client<Authenticated>, UserpassLoginMetadata)> {
        let response = self.userpass()?.login_response(username, &password).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((self.try_with_token(token)?, metadata))
    }
}

impl Client<Authenticated> {
    /// Administers the Userpass auth method mounted at `auth/userpass`.
    pub fn userpass_admin(&self) -> Result<UserpassAuthAdmin<'_>> {
        self.userpass_admin_at("userpass")
    }

    /// Administers the Userpass auth method mounted at `auth/{mount}`.
    pub fn userpass_admin_at(&self, mount: impl Into<String>) -> Result<UserpassAuthAdmin<'_>> {
        Ok(UserpassAuthAdmin {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }
}

impl UserpassAuth<'_> {
    /// Logs in and returns token metadata plus an authenticated client.
    pub async fn login(
        self,
        username: &str,
        password: SecretString,
    ) -> Result<(Client<Authenticated>, UserpassLoginMetadata)> {
        let response = self.login_response(username, &password).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((
            self.client.clone_without_state().try_with_token(token)?,
            metadata,
        ))
    }

    async fn login_response(
        &self,
        username: &str,
        password: &SecretString,
    ) -> Result<UserpassLoginAuth> {
        let username = validate_username(username)?;
        let request = UserpassLoginRequest {
            password: password.expose_secret(),
        };
        let response: UserpassLoginResponse = self
            .client
            .request_json(
                Method::POST,
                &format!("auth/{}/login/{username}", self.mount),
                Some(&request),
            )
            .await?;
        response.auth.ok_or(Error::MissingField("auth"))
    }
}

impl UserpassAuthAdmin<'_> {
    /// Creates or updates a userpass user.
    pub async fn write_user(&self, username: &str, user: &UserpassUserRequest) -> Result<Empty> {
        user.validate()?;
        let username = validate_username(username)?;
        let payload = UserpassUserPayload {
            password: user.password.expose_secret(),
            token_policies: &user.token_policies,
            token_ttl: user.token_ttl.as_deref(),
            token_max_ttl: user.token_max_ttl.as_deref(),
            token_period: user.token_period.as_deref(),
            token_explicit_max_ttl: user.token_explicit_max_ttl.as_deref(),
            token_type: user.token_type.as_deref(),
            token_bound_cidrs: &user.token_bound_cidrs,
            token_num_uses: user.token_num_uses,
            token_no_default_policy: user.token_no_default_policy,
        };
        self.client
            .request_json(
                Method::POST,
                &format!("auth/{}/users/{username}", self.mount),
                Some(&payload),
            )
            .await
    }

    /// Reads a userpass user configuration.
    pub async fn read_user(&self, username: &str) -> Result<UserpassUserInfo> {
        let username = validate_username(username)?;
        let envelope: ResponseEnvelope<UserpassUserInfo> = self
            .client
            .request_json(
                Method::GET,
                &format!("auth/{}/users/{username}", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a userpass user.
    pub async fn delete_user(&self, username: &str) -> Result<Empty> {
        let username = validate_username(username)?;
        self.client
            .request_json_accepting(
                Method::DELETE,
                &format!("auth/{}/users/{username}", self.mount),
                Option::<&Empty>::None,
                &[reqwest::StatusCode::OK, reqwest::StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Updates only a userpass user's password.
    pub async fn update_password(&self, username: &str, password: &SecretString) -> Result<Empty> {
        let username = validate_username(username)?;
        let request = UserpassPasswordRequest {
            password: password.expose_secret(),
        };
        self.client
            .request_json(
                Method::POST,
                &format!("auth/{}/users/{username}/password", self.mount),
                Some(&request),
            )
            .await
    }

    /// Updates only a userpass user's token policies.
    pub async fn update_policies(&self, username: &str, policies: &[String]) -> Result<Empty> {
        let username = validate_username(username)?;
        let request = UserpassPoliciesRequest {
            token_policies: policies,
        };
        self.client
            .request_json(
                Method::POST,
                &format!("auth/{}/users/{username}/policies", self.mount),
                Some(&request),
            )
            .await
    }

    /// Lists userpass user names.
    pub async fn list_users(&self) -> Result<UserpassUserList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<UserpassUserList> = self
            .client
            .request_json(
                method,
                &format!("auth/{}/users", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }
}

fn split_login_auth(auth: UserpassLoginAuth) -> (SecretString, UserpassLoginMetadata) {
    let UserpassLoginAuth {
        client_token,
        accessor,
        policies,
        lease_duration,
        renewable,
        metadata,
    } = auth;
    let metadata = UserpassLoginMetadata {
        accessor,
        policies,
        lease_duration,
        renewable,
        metadata,
    };
    (client_token, metadata)
}

fn is_empty_string_slice(values: &&[String]) -> bool {
    values.is_empty()
}

fn validate_username(username: &str) -> Result<&str> {
    let bytes = username.as_bytes();
    if bytes.is_empty() {
        return Err(Error::InvalidPath(
            "userpass username must not be empty".into(),
        ));
    }
    if bytes[0] == b'-' || bytes[0] == b'.' || bytes[bytes.len() - 1] == b'.' {
        return Err(Error::InvalidPath(
            "userpass username must not begin with '-' or '.', or end with '.'".into(),
        ));
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(Error::InvalidPath(
            "userpass username may only contain ASCII alphanumeric, '_', '-', or '.'".into(),
        ));
    }
    Ok(username)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::{ExposeSecret, SecretString};

    use super::{UserpassLoginResponse, UserpassUserList, UserpassUserRequest, validate_username};

    fn test_secret(parts: &[&str]) -> SecretString {
        SecretString::from(parts.concat())
    }

    #[test]
    fn userpass_login_auth_deserializes_secret_token_fields() {
        let response: UserpassLoginResponse = serde_json::from_str(
            r#"{"auth":{"client_token":"token-value","accessor":"accessor-value","metadata":{"username":"alice"}}}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let auth = response.auth.unwrap_or_else(|| panic!("auth missing"));

        assert_eq!(auth.client_token.expose_secret(), "token-value");
        assert_eq!(auth.accessor.expose_secret(), "accessor-value");
        assert_eq!(
            auth.metadata.get("username").map(String::as_str),
            Some("alice")
        );
    }

    #[test]
    fn userpass_user_list_is_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("user-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<UserpassUserList>(value) {
            Ok(_) => panic!("oversized Userpass user list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn userpass_username_validation_matches_openbao_rules() {
        assert!(validate_username("alice_1").is_ok());
        assert!(validate_username("alice.sre").is_ok());
        assert!(validate_username("").is_err());
        assert!(validate_username("-alice").is_err());
        assert!(validate_username(".alice").is_err());
        assert!(validate_username("alice.").is_err());
        assert!(validate_username("alice/admin").is_err());
        assert!(validate_username("alice?x=1").is_err());
    }

    #[test]
    fn userpass_user_request_debug_redacts_password() {
        let request = UserpassUserRequest::new(test_secret(&["correct", "-", "horse"]));
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("correct-horse"));
    }
}
