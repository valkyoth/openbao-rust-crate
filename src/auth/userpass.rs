//! Username and password authentication support.

use std::collections::BTreeMap;

use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    Authenticated, Client, Error, Result, Unauthenticated,
    path::validate_mount_path,
    response::{
        Empty, ListEntries, ResponseEnvelope, deserialize_bounded_string_map_or_default,
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

/// Validated pre-hashed bcrypt credential for OpenBao 2.6 userpass APIs.
///
/// The value is always treated as secret material. Accepted hashes use a
/// modern bcrypt marker and OpenBao's reviewed cost range of 5 through 12.
#[derive(Clone)]
pub struct UserpassPasswordHash(SecretString);

impl UserpassPasswordHash {
    /// Validates and wraps a pre-computed bcrypt hash.
    pub fn bcrypt(hash: SecretString) -> Result<Self> {
        validate_bcrypt_hash(hash.expose_secret())?;
        Ok(Self(hash))
    }

    fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl core::fmt::Debug for UserpassPasswordHash {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("UserpassPasswordHash(<redacted>)")
    }
}

/// Token settings used when creating a userpass user from a bcrypt hash.
#[derive(Clone, Debug, Default)]
pub struct UserpassUserSettings {
    /// Policies attached to generated tokens.
    pub token_policies: Vec<String>,
    /// Deprecated policy field retained for older OpenBao compatibility.
    pub policies: Vec<String>,
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

impl UserpassUserSettings {
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

/// Userpass user creation request containing a pre-hashed bcrypt credential.
#[derive(Clone)]
pub struct UserpassHashedUserRequest {
    /// Validated pre-hashed bcrypt credential.
    pub password_hash: UserpassPasswordHash,
    /// Token settings stored for this user.
    pub settings: UserpassUserSettings,
}

impl UserpassHashedUserRequest {
    /// Creates a hashed user request with default token settings.
    pub fn new(password_hash: UserpassPasswordHash) -> Self {
        Self {
            password_hash,
            settings: UserpassUserSettings::default(),
        }
    }
}

impl core::fmt::Debug for UserpassHashedUserRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("UserpassHashedUserRequest")
            .field("password_hash", &"<redacted>")
            .field("settings", &self.settings)
            .finish()
    }
}

/// Userpass user create/update request.
#[derive(Clone, Default)]
pub struct UserpassUserRequest {
    /// Password used for userpass login.
    pub password: SecretString,
    /// Policies attached to generated tokens.
    pub token_policies: Vec<String>,
    /// Deprecated policy field retained for older OpenBao 2.x compatibility.
    pub policies: Vec<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "is_empty_string_slice")]
    token_policies: &'a [String],
    #[serde(skip_serializing_if = "is_empty_string_slice")]
    policies: &'a [String],
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
        if self.password.expose_secret().is_empty() {
            return Err(Error::InvalidParameter(
                "userpass password must not be empty".into(),
            ));
        }
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

impl ListEntries for UserpassUserList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_hash: Option<&'a str>,
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
            .request_auth_json_internal(
                "userpass",
                &self.mount,
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
            password: Some(user.password.expose_secret()),
            password_hash: None,
            token_policies: &user.token_policies,
            policies: &user.policies,
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
            .request_auth_json_internal(
                "userpass",
                &self.mount,
                Method::POST,
                &format!("auth/{}/users/{username}", self.mount),
                Some(&payload),
            )
            .await
    }

    /// Creates or updates a user using a pre-hashed bcrypt credential.
    ///
    /// This OpenBao 2.6 helper sends only `password_hash`; the distinct request
    /// type makes it impossible to combine that field with plaintext
    /// `password`. The bcrypt hash remains secret and is redacted from debug
    /// output.
    pub async fn write_hashed_user(
        &self,
        username: &str,
        user: &UserpassHashedUserRequest,
    ) -> Result<Empty> {
        user.settings.validate()?;
        self.client
            .validate_versioned_request_fields(&[(
                &crate::request_compatibility::fields::USERPASS_USER_PASSWORD_HASH,
                true,
            )])
            .await?;
        let username = validate_username(username)?;
        let settings = &user.settings;
        let payload = UserpassUserPayload {
            password: None,
            password_hash: Some(user.password_hash.expose_secret()),
            token_policies: &settings.token_policies,
            policies: &settings.policies,
            token_ttl: settings.token_ttl.as_deref(),
            token_max_ttl: settings.token_max_ttl.as_deref(),
            token_period: settings.token_period.as_deref(),
            token_explicit_max_ttl: settings.token_explicit_max_ttl.as_deref(),
            token_type: settings.token_type.as_deref(),
            token_bound_cidrs: &settings.token_bound_cidrs,
            token_num_uses: settings.token_num_uses,
            token_no_default_policy: settings.token_no_default_policy,
        };
        self.client
            .request_auth_json_internal(
                "userpass",
                &self.mount,
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
            .request_auth_json_internal(
                "userpass",
                &self.mount,
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
            .request_auth_json_accepting(
                "userpass",
                &self.mount,
                Method::DELETE,
                &format!("auth/{}/users/{username}", self.mount),
                Option::<&Empty>::None,
                &[reqwest::StatusCode::OK, reqwest::StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Updates only a userpass user's password.
    pub async fn update_password(&self, username: &str, password: &SecretString) -> Result<Empty> {
        if password.expose_secret().is_empty() {
            return Err(Error::InvalidParameter(
                "userpass password must not be empty".into(),
            ));
        }
        let username = validate_username(username)?;
        let request = UserpassPasswordRequest {
            password: Some(password.expose_secret()),
            password_hash: None,
        };
        self.client
            .request_auth_json_internal(
                "userpass",
                &self.mount,
                Method::POST,
                &format!("auth/{}/users/{username}/password", self.mount),
                Some(&request),
            )
            .await
    }

    /// Updates only a user's password using a validated pre-hashed bcrypt value.
    pub async fn update_password_hash(
        &self,
        username: &str,
        password_hash: &UserpassPasswordHash,
    ) -> Result<Empty> {
        self.client
            .validate_versioned_request_fields(&[(
                &crate::request_compatibility::fields::USERPASS_PASSWORD_PASSWORD_HASH,
                true,
            )])
            .await?;
        let username = validate_username(username)?;
        let request = UserpassPasswordRequest {
            password: None,
            password_hash: Some(password_hash.expose_secret()),
        };
        self.client
            .request_auth_json_internal(
                "userpass",
                &self.mount,
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
            .request_auth_json_internal(
                "userpass",
                &self.mount,
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
            .request_auth_json_internal(
                "userpass",
                &self.mount,
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

fn validate_bcrypt_hash(hash: &str) -> Result<()> {
    let bytes = hash.as_bytes();
    let valid_prefix = bytes.len() == 60
        && bytes[0] == b'$'
        && bytes[1] == b'2'
        && matches!(bytes[2], b'a' | b'b' | b'y')
        && bytes[3] == b'$'
        && bytes[4].is_ascii_digit()
        && bytes[5].is_ascii_digit()
        && bytes[6] == b'$';
    if !valid_prefix
        || !bytes[7..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/'))
    {
        return Err(Error::InvalidParameter(
            "userpass password_hash must be a valid bcrypt hash".into(),
        ));
    }
    let cost = u16::from(bytes[4] - b'0') * 10 + u16::from(bytes[5] - b'0');
    if !(5..=12).contains(&cost) {
        return Err(Error::InvalidParameter(
            "userpass bcrypt cost must be between 5 and 12".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::{ExposeSecret, SecretString};

    use super::{
        UserpassHashedUserRequest, UserpassLoginResponse, UserpassPasswordHash, UserpassUserList,
        UserpassUserRequest, validate_bcrypt_hash, validate_username,
    };

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
    fn userpass_bcrypt_hashes_are_validated_and_redacted() {
        let hash_text = format!("$2b$10${}", "A".repeat(53));
        let hash = UserpassPasswordHash::bcrypt(SecretString::from(hash_text.clone()))
            .unwrap_or_else(|error| panic!("{error}"));
        let request = UserpassHashedUserRequest::new(hash.clone());
        assert!(!format!("{hash:?}").contains(&hash_text));
        assert!(!format!("{request:?}").contains(&hash_text));
        assert_eq!(hash.expose_secret(), hash_text);

        assert!(validate_bcrypt_hash(&format!("$2b$04${}", "A".repeat(53))).is_err());
        assert!(validate_bcrypt_hash(&format!("$2b$13${}", "A".repeat(53))).is_err());
        assert!(validate_bcrypt_hash("plaintext-password").is_err());
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
