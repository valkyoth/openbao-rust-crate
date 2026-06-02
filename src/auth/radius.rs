//! RADIUS authentication support.

use core::fmt;
use std::collections::BTreeMap;

use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    Authenticated, Client, Error, Result, Unauthenticated,
    path::validate_mount_path,
    response::{
        Empty, ResponseEnvelope, deserialize_bounded_string_map_or_default,
        deserialize_bounded_string_vec,
    },
    validation::validate_duration_string,
};

/// Handle for RADIUS auth login at a configured mount.
#[derive(Debug)]
pub struct RadiusAuth<'a> {
    client: &'a Client<Unauthenticated>,
    mount: String,
}

/// Handle for RADIUS auth administration at a configured mount.
#[derive(Debug)]
pub struct RadiusAuthAdmin<'a> {
    client: &'a Client<Authenticated>,
    mount: String,
}

/// RADIUS auth method configuration.
#[derive(Clone, Default)]
pub struct RadiusConfig {
    /// RADIUS server host name or IP address.
    pub host: String,
    /// RADIUS shared secret.
    pub secret: SecretString,
    /// RADIUS UDP port. OpenBao defaults this to 1812.
    pub port: Option<u16>,
    /// Policies granted to users without an explicit user mapping.
    pub unregistered_user_policies: Option<String>,
    /// Backend connection timeout in seconds.
    pub dial_timeout: Option<u64>,
    /// NAS-Port attribute sent to the RADIUS server.
    pub nas_port: Option<u64>,
    /// Policies attached to generated tokens.
    pub token_policies: Vec<String>,
    /// Generated token CIDR restrictions.
    pub token_bound_cidrs: Vec<String>,
    /// Whether generated tokens are bound to the login source IP.
    pub token_strictly_bind_ip: Option<bool>,
    /// Token TTL such as `30m`.
    pub token_ttl: Option<String>,
    /// Token max TTL such as `2h`.
    pub token_max_ttl: Option<String>,
    /// Token explicit max TTL.
    pub token_explicit_max_ttl: Option<String>,
    /// Whether to omit the default policy.
    pub token_no_default_policy: Option<bool>,
    /// Number of allowed token uses.
    pub token_num_uses: Option<u64>,
    /// Periodic token period.
    pub token_period: Option<String>,
    /// Generated token type.
    pub token_type: Option<String>,
}

#[derive(Serialize)]
struct RadiusConfigPayload<'a> {
    host: &'a str,
    secret: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unregistered_user_policies: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dial_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nas_port: Option<u64>,
    #[serde(skip_serializing_if = "is_empty_string_slice")]
    token_policies: &'a [String],
    #[serde(skip_serializing_if = "is_empty_string_slice")]
    token_bound_cidrs: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    token_strictly_bind_ip: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_ttl: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_max_ttl: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_explicit_max_ttl: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_no_default_policy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_num_uses: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_period: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<&'a str>,
}

impl RadiusConfig {
    /// Creates a RADIUS config with the required host and shared secret.
    pub fn new(host: impl Into<String>, secret: SecretString) -> Self {
        Self {
            host: host.into(),
            secret,
            ..Self::default()
        }
    }

    /// Sets the RADIUS UDP port.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Adds a generated-token policy.
    #[must_use]
    pub fn with_token_policy(mut self, policy: impl Into<String>) -> Self {
        self.token_policies.push(policy.into());
        self
    }

    /// Adds a generated-token CIDR restriction.
    pub fn with_token_bound_cidr(mut self, cidr: impl Into<String>) -> Result<Self> {
        let cidr = cidr.into();
        crate::validation::validate_cidr(&cidr, "RADIUS token_bound_cidrs")?;
        self.token_bound_cidrs.push(cidr);
        Ok(self)
    }

    /// Sets generated-token TTL from an OpenBao duration string.
    pub fn with_token_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        validate_radius_duration(&ttl, "RADIUS token_ttl")?;
        self.token_ttl = Some(ttl);
        Ok(self)
    }

    /// Sets generated-token TTL from a Rust duration.
    pub fn with_token_ttl_duration(self, ttl: std::time::Duration) -> Result<Self> {
        self.with_token_ttl(crate::duration_to_bao_string(ttl))
    }

    fn validate(&self) -> Result<()> {
        if self.host.trim().is_empty() {
            return Err(Error::InvalidParameter(
                "RADIUS host must not be empty".into(),
            ));
        }
        crate::validation::validate_cidr_list(&self.token_bound_cidrs, "RADIUS token_bound_cidrs")?;
        if self.token_strictly_bind_ip == Some(true) && !self.token_bound_cidrs.is_empty() {
            return Err(Error::InvalidParameter(
                "RADIUS token_strictly_bind_ip conflicts with token_bound_cidrs".into(),
            ));
        }
        if let Some(ttl) = &self.token_ttl {
            validate_radius_duration(ttl, "RADIUS token_ttl")?;
        }
        if let Some(ttl) = &self.token_max_ttl {
            validate_radius_duration(ttl, "RADIUS token_max_ttl")?;
        }
        if let Some(ttl) = &self.token_explicit_max_ttl {
            validate_radius_duration(ttl, "RADIUS token_explicit_max_ttl")?;
        }
        if let Some(period) = &self.token_period {
            validate_radius_duration(period, "RADIUS token_period")?;
        }
        Ok(())
    }
}

impl fmt::Debug for RadiusConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RadiusConfig")
            .field("host", &self.host)
            .field("secret", &"<redacted>")
            .field("port", &self.port)
            .field(
                "unregistered_user_policies",
                &self.unregistered_user_policies,
            )
            .field("dial_timeout", &self.dial_timeout)
            .field("nas_port", &self.nas_port)
            .field("token_policies", &self.token_policies)
            .field("token_bound_cidrs", &self.token_bound_cidrs)
            .field("token_strictly_bind_ip", &self.token_strictly_bind_ip)
            .field("token_ttl", &self.token_ttl)
            .field("token_max_ttl", &self.token_max_ttl)
            .field("token_explicit_max_ttl", &self.token_explicit_max_ttl)
            .field("token_no_default_policy", &self.token_no_default_policy)
            .field("token_num_uses", &self.token_num_uses)
            .field("token_period", &self.token_period)
            .field("token_type", &self.token_type)
            .finish()
    }
}

/// RADIUS user policy mapping request.
#[derive(Clone, Debug, Default)]
pub struct RadiusUserRequest {
    /// Policies mapped to this RADIUS user.
    pub policies: Vec<String>,
}

impl RadiusUserRequest {
    /// Creates a RADIUS user request with one policy.
    pub fn new(policy: impl Into<String>) -> Self {
        Self {
            policies: vec![policy.into()],
        }
    }

    /// Adds a policy to the RADIUS user mapping.
    #[must_use]
    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.policies.push(policy.into());
        self
    }
}

#[derive(Serialize)]
struct RadiusUserPayload {
    policies: String,
}

/// RADIUS user policy mapping returned by OpenBao.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct RadiusUserInfo {
    /// Comma-separated policy list returned by OpenBao.
    #[serde(default)]
    pub policies: String,
}

/// RADIUS user list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct RadiusUserList {
    /// User names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

/// Metadata returned after a successful RADIUS login.
#[derive(Debug, Deserialize)]
pub struct RadiusLoginMetadata {
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
struct RadiusLoginRequest<'a> {
    password: &'a str,
}

#[derive(Deserialize)]
struct RadiusLoginResponse {
    auth: Option<RadiusLoginAuth>,
}

#[derive(Deserialize)]
struct RadiusLoginAuth {
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
    /// Uses the RADIUS auth method mounted at `auth/radius`.
    pub fn radius(&self) -> Result<RadiusAuth<'_>> {
        self.radius_at("radius")
    }

    /// Uses the RADIUS auth method mounted at `auth/{mount}`.
    pub fn radius_at(&self, mount: impl Into<String>) -> Result<RadiusAuth<'_>> {
        Ok(RadiusAuth {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }

    /// Logs in with RADIUS auth at `auth/radius`.
    pub async fn login_radius(
        self,
        username: &str,
        password: SecretString,
    ) -> Result<(Client<Authenticated>, RadiusLoginMetadata)> {
        let response = self.radius()?.login_response(username, &password).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((self.try_with_token(token)?, metadata))
    }
}

impl Client<Authenticated> {
    /// Administers the RADIUS auth method mounted at `auth/radius`.
    pub fn radius_admin(&self) -> Result<RadiusAuthAdmin<'_>> {
        self.radius_admin_at("radius")
    }

    /// Administers the RADIUS auth method mounted at `auth/{mount}`.
    pub fn radius_admin_at(&self, mount: impl Into<String>) -> Result<RadiusAuthAdmin<'_>> {
        Ok(RadiusAuthAdmin {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }
}

impl RadiusAuth<'_> {
    /// Logs in and returns token metadata plus an authenticated client.
    pub async fn login(
        self,
        username: &str,
        password: SecretString,
    ) -> Result<(Client<Authenticated>, RadiusLoginMetadata)> {
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
    ) -> Result<RadiusLoginAuth> {
        let username = validate_radius_username(username)?;
        let request = RadiusLoginRequest {
            password: password.expose_secret(),
        };
        let response: RadiusLoginResponse = self
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

impl RadiusAuthAdmin<'_> {
    /// Configures the RADIUS auth method.
    pub async fn configure(&self, config: &RadiusConfig) -> Result<Empty> {
        config.validate()?;
        let payload = RadiusConfigPayload {
            host: &config.host,
            secret: config.secret.expose_secret(),
            port: config.port,
            unregistered_user_policies: config.unregistered_user_policies.as_deref(),
            dial_timeout: config.dial_timeout,
            nas_port: config.nas_port,
            token_policies: &config.token_policies,
            token_bound_cidrs: &config.token_bound_cidrs,
            token_strictly_bind_ip: config.token_strictly_bind_ip,
            token_ttl: config.token_ttl.as_deref(),
            token_max_ttl: config.token_max_ttl.as_deref(),
            token_explicit_max_ttl: config.token_explicit_max_ttl.as_deref(),
            token_no_default_policy: config.token_no_default_policy,
            token_num_uses: config.token_num_uses,
            token_period: config.token_period.as_deref(),
            token_type: config.token_type.as_deref(),
        };
        self.client
            .request_json(
                Method::POST,
                &format!("auth/{}/config", self.mount),
                Some(&payload),
            )
            .await
    }

    /// Creates or updates a RADIUS user policy mapping.
    pub async fn write_user(&self, username: &str, user: &RadiusUserRequest) -> Result<Empty> {
        let username = validate_radius_username(username)?;
        let payload = RadiusUserPayload {
            policies: user.policies.join(","),
        };
        self.client
            .request_json(
                Method::POST,
                &format!("auth/{}/users/{username}", self.mount),
                Some(&payload),
            )
            .await
    }

    /// Reads a RADIUS user policy mapping.
    pub async fn read_user(&self, username: &str) -> Result<RadiusUserInfo> {
        let username = validate_radius_username(username)?;
        let envelope: ResponseEnvelope<RadiusUserInfo> = self
            .client
            .request_json(
                Method::GET,
                &format!("auth/{}/users/{username}", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a RADIUS user policy mapping.
    pub async fn delete_user(&self, username: &str) -> Result<Empty> {
        let username = validate_radius_username(username)?;
        self.client
            .request_json_accepting(
                Method::DELETE,
                &format!("auth/{}/users/{username}", self.mount),
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Lists RADIUS user names.
    pub async fn list_users(&self) -> Result<RadiusUserList> {
        self.list_users_page(None, None).await
    }

    /// Lists RADIUS user names with OpenBao pagination query parameters.
    pub async fn list_users_page(
        &self,
        after: Option<&str>,
        limit: Option<u64>,
    ) -> Result<RadiusUserList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let mut query = Vec::new();
        if let Some(after) = after {
            validate_radius_username(after)?;
            query.push(("after", after.to_owned()));
        }
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        let envelope: ResponseEnvelope<RadiusUserList> = self
            .client
            .request_json_query_accepting(
                method,
                &format!("auth/{}/users", self.mount),
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }
}

fn split_login_auth(auth: RadiusLoginAuth) -> (SecretString, RadiusLoginMetadata) {
    let RadiusLoginAuth {
        client_token,
        accessor,
        policies,
        lease_duration,
        renewable,
        metadata,
    } = auth;
    let metadata = RadiusLoginMetadata {
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

fn validate_radius_duration(value: &str, field: &'static str) -> Result<()> {
    if validate_duration_string(value, true) {
        return Ok(());
    }
    Err(Error::InvalidParameter(format!(
        "{field} must be a duration such as 0s, 30s, 5m, or 1h"
    )))
}

fn validate_radius_username(username: &str) -> Result<&str> {
    let bytes = username.as_bytes();
    if bytes.is_empty() {
        return Err(Error::InvalidPath(
            "RADIUS username must not be empty".into(),
        ));
    }
    if bytes[0] == b'-' || bytes[0] == b'.' || bytes[bytes.len() - 1] == b'.' {
        return Err(Error::InvalidPath(
            "RADIUS username must not begin with '-' or '.', or end with '.'".into(),
        ));
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(Error::InvalidPath(
            "RADIUS username may only contain ASCII alphanumeric, '_', '-', or '.'".into(),
        ));
    }
    Ok(username)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::{ExposeSecret, SecretString};

    use super::{
        RadiusConfig, RadiusLoginResponse, RadiusUserList, RadiusUserRequest,
        validate_radius_username,
    };

    fn test_secret(parts: &[&str]) -> SecretString {
        SecretString::from(parts.concat())
    }

    #[test]
    fn radius_login_auth_deserializes_secret_token_fields() {
        let response: RadiusLoginResponse = serde_json::from_str(
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
    fn radius_user_list_is_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("user-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<RadiusUserList>(value) {
            Ok(_) => panic!("oversized RADIUS user list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn radius_username_validation_matches_documented_path_use() {
        assert!(validate_radius_username("alice_1").is_ok());
        assert!(validate_radius_username("alice.sre").is_ok());
        assert!(validate_radius_username("").is_err());
        assert!(validate_radius_username("-alice").is_err());
        assert!(validate_radius_username(".alice").is_err());
        assert!(validate_radius_username("alice.").is_err());
        assert!(validate_radius_username("alice/admin").is_err());
        assert!(validate_radius_username("alice?x=1").is_err());
    }

    #[test]
    fn radius_config_debug_redacts_shared_secret() {
        let config = RadiusConfig::new("radius.example.com", test_secret(&["shared", "-secret"]));
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("shared-secret"));
    }

    #[test]
    fn radius_config_validates_cidr_and_strict_ip_conflict() {
        let config = RadiusConfig::new("radius.example.com", test_secret(&["secret"]))
            .with_token_bound_cidr("10.0.0.0/8")
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(config.validate().is_ok());

        let mut conflicting = config;
        conflicting.token_strictly_bind_ip = Some(true);
        assert!(conflicting.validate().is_err());
    }

    #[test]
    fn radius_user_request_joins_policies() {
        let request = RadiusUserRequest::new("dev").with_policy("prod");
        assert_eq!(request.policies.join(","), "dev,prod");
    }
}
