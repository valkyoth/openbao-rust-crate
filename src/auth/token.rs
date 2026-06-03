//! Token auth method lifecycle helpers.

use std::collections::BTreeMap;

use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    Authenticated, Client, Error, Result,
    response::{
        Empty, ResponseEnvelope, deserialize_bounded_secret_string_vec,
        deserialize_bounded_string_map_or_default, deserialize_bounded_string_vec,
    },
};

/// Handle for the built-in token auth method.
#[derive(Debug)]
pub struct Token<'a> {
    client: &'a Client<Authenticated>,
}

/// Options for creating a child token.
#[derive(Clone, Default, Serialize)]
pub struct TokenCreateRequest {
    /// Policies attached to the token.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    /// Metadata stored with the token.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,
    /// Human-readable display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Requested TTL such as `30m`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Explicit max TTL such as `2h`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explicit_max_ttl: Option<String>,
    /// Periodic token period such as `1h`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<String>,
    /// Maximum number of uses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_uses: Option<u64>,
    /// Whether the token is renewable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renewable: Option<bool>,
    /// Create an orphan token without a parent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_parent: Option<bool>,
    /// Do not attach the default policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_default_policy: Option<bool>,
    /// OpenBao token type, such as `service` or `batch`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

impl TokenCreateRequest {
    /// Sets the policies attached to the created token.
    #[must_use]
    pub fn with_policies<I, P>(mut self, policies: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        self.policies = policies.into_iter().map(Into::into).collect();
        self
    }

    /// Omits OpenBao's default policy from the created token.
    #[must_use]
    pub fn without_default_policy(mut self) -> Self {
        self.no_default_policy = Some(true);
        self
    }

    /// Sets the requested token TTL after validating OpenBao duration syntax.
    pub fn with_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        crate::validation::validate_duration_parameter(&ttl, "token ttl")?;
        self.ttl = Some(ttl);
        Ok(self)
    }

    /// Sets the requested token TTL from a Rust duration.
    pub fn with_ttl_duration(self, ttl: std::time::Duration) -> Result<Self> {
        self.with_ttl(crate::duration_to_bao_string(ttl))
    }

    /// Sets the requested explicit maximum TTL after validating duration syntax.
    pub fn with_explicit_max_ttl(mut self, explicit_max_ttl: impl Into<String>) -> Result<Self> {
        let explicit_max_ttl = explicit_max_ttl.into();
        crate::validation::validate_duration_parameter(
            &explicit_max_ttl,
            "token explicit_max_ttl",
        )?;
        self.explicit_max_ttl = Some(explicit_max_ttl);
        Ok(self)
    }

    /// Sets the requested explicit maximum TTL from a Rust duration.
    pub fn with_explicit_max_ttl_duration(
        self,
        explicit_max_ttl: std::time::Duration,
    ) -> Result<Self> {
        self.with_explicit_max_ttl(crate::duration_to_bao_string(explicit_max_ttl))
    }

    /// Sets the requested periodic token period after validating duration syntax.
    pub fn with_period(mut self, period: impl Into<String>) -> Result<Self> {
        let period = period.into();
        crate::validation::validate_duration_parameter(&period, "token period")?;
        self.period = Some(period);
        Ok(self)
    }

    /// Sets the requested periodic token period from a Rust duration.
    pub fn with_period_duration(self, period: std::time::Duration) -> Result<Self> {
        self.with_period(crate::duration_to_bao_string(period))
    }

    fn validate(&self) -> Result<()> {
        if let Some(ttl) = &self.ttl {
            crate::validation::validate_duration_parameter(ttl, "token ttl")?;
        }
        if let Some(explicit_max_ttl) = &self.explicit_max_ttl {
            crate::validation::validate_duration_parameter(
                explicit_max_ttl,
                "token explicit_max_ttl",
            )?;
        }
        if let Some(period) = &self.period {
            crate::validation::validate_duration_parameter(period, "token period")?;
        }
        Ok(())
    }
}

/// Result of creating or renewing a token.
#[derive(Debug, Deserialize)]
pub struct TokenAuth {
    /// Client token returned by OpenBao.
    pub client_token: SecretString,
    /// Token accessor returned by OpenBao.
    pub accessor: SecretString,
    /// Policies attached to the token.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub policies: Vec<String>,
    /// Token policies attached to the token.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub token_policies: Vec<String>,
    /// Token metadata.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    pub metadata: BTreeMap<String, String>,
    /// Lease duration in seconds.
    #[serde(default)]
    pub lease_duration: u64,
    /// Whether the token is renewable.
    #[serde(default)]
    pub renewable: bool,
    /// Entity identifier, when present.
    #[serde(default)]
    pub entity_id: Option<String>,
    /// Token type, when present.
    #[serde(default)]
    pub token_type: Option<String>,
    /// Whether the token is orphaned.
    #[serde(default)]
    pub orphan: bool,
}

/// Token lookup metadata returned by OpenBao.
#[derive(Clone, Debug, Deserialize)]
pub struct TokenInfo {
    /// Token accessor, treated as secret material.
    #[serde(default)]
    pub accessor: Option<SecretString>,
    /// Token ID, when OpenBao returns one.
    #[serde(default)]
    pub id: Option<SecretString>,
    /// Display name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Entity identifier.
    #[serde(default)]
    pub entity_id: Option<String>,
    /// Creation path.
    #[serde(default)]
    pub path: Option<String>,
    /// Creation time as a Unix timestamp.
    #[serde(default)]
    pub creation_time: Option<u64>,
    /// Creation TTL in seconds.
    #[serde(default)]
    pub creation_ttl: Option<u64>,
    /// Current TTL in seconds.
    #[serde(default)]
    pub ttl: Option<u64>,
    /// Expiration time, when present.
    #[serde(default)]
    pub expire_time: Option<String>,
    /// Explicit max TTL in seconds.
    #[serde(default)]
    pub explicit_max_ttl: Option<u64>,
    /// Number of uses remaining.
    #[serde(default)]
    pub num_uses: Option<u64>,
    /// Whether the token is orphaned.
    #[serde(default)]
    pub orphan: bool,
    /// Whether the token is renewable.
    #[serde(default)]
    pub renewable: bool,
    /// Attached policies.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub policies: Vec<String>,
    /// Identity policies.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub identity_policies: Vec<String>,
    /// Token metadata.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    pub meta: BTreeMap<String, String>,
    /// Token type.
    #[serde(default)]
    pub token_type: Option<String>,
}

/// Token accessor list response.
#[derive(Clone, Debug, Deserialize)]
pub struct TokenAccessorList {
    /// Token accessors. Accessors can revoke tokens, so keep them secret.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub keys: Vec<SecretString>,
}

/// Token role configuration used by `/auth/token/roles/:role_name`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TokenRole {
    /// Policies allowed to be requested when creating tokens through the role.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_policies: Vec<String>,
    /// Policies that cannot be requested through the role.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub disallowed_policies: Vec<String>,
    /// Additional policies always attached to generated tokens.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_policies: Vec<String>,
    /// Whether generated tokens are orphan tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orphan: Option<bool>,
    /// Whether generated tokens are renewable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewable: Option<bool>,
    /// Token path suffix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_suffix: Option<String>,
    /// Allowed entity aliases.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_entity_aliases: Vec<String>,
    /// Token type, such as `service`, `batch`, or `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// Token TTL, such as `30m`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    /// Token maximum TTL, such as `2h`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
    /// Explicit maximum TTL, such as `4h`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_explicit_max_ttl: Option<String>,
    /// Periodic token period.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_period: Option<String>,
    /// Number of uses for generated tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_num_uses: Option<u64>,
    /// Bound CIDRs for generated tokens.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_bound_cidrs: Vec<String>,
}

impl TokenRole {
    /// Sets the allowed policies for this role.
    #[must_use]
    pub fn with_allowed_policies<I, P>(mut self, policies: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        self.allowed_policies = policies.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the token TTL after validating OpenBao duration syntax.
    pub fn with_token_ttl(mut self, token_ttl: impl Into<String>) -> Result<Self> {
        let token_ttl = token_ttl.into();
        crate::validation::validate_duration_parameter(&token_ttl, "token role token_ttl")?;
        self.token_ttl = Some(token_ttl);
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        if let Some(token_ttl) = &self.token_ttl {
            crate::validation::validate_duration_parameter(token_ttl, "token role token_ttl")?;
        }
        if let Some(token_max_ttl) = &self.token_max_ttl {
            crate::validation::validate_duration_parameter(
                token_max_ttl,
                "token role token_max_ttl",
            )?;
        }
        if let Some(token_explicit_max_ttl) = &self.token_explicit_max_ttl {
            crate::validation::validate_duration_parameter(
                token_explicit_max_ttl,
                "token role token_explicit_max_ttl",
            )?;
        }
        if let Some(token_period) = &self.token_period {
            crate::validation::validate_duration_parameter(
                token_period,
                "token role token_period",
            )?;
        }
        crate::validation::validate_cidr_list(&self.token_bound_cidrs, "token role bound CIDR")
    }
}

/// Token role list response.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct TokenRoleList {
    /// Token role names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl crate::response::ListEntries for TokenRoleList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

#[derive(Deserialize)]
struct TokenAuthEnvelope {
    auth: Option<TokenAuth>,
}

#[derive(Serialize)]
struct TokenPayload<'a> {
    token: &'a str,
}

#[derive(Serialize)]
struct AccessorPayload<'a> {
    accessor: &'a str,
}

#[derive(Serialize)]
struct RenewPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    increment: Option<&'a str>,
}

#[derive(Serialize)]
struct RenewAccessorPayload<'a> {
    accessor: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    increment: Option<&'a str>,
}

impl Client<Authenticated> {
    /// Accesses token lifecycle helpers.
    pub fn token(&self) -> Token<'_> {
        Token { client: self }
    }
}

impl Token<'_> {
    /// Creates a child token.
    pub async fn create(&self, request: &TokenCreateRequest) -> Result<TokenAuth> {
        self.create_at(None, request).await
    }

    /// Creates an orphan token through OpenBao's dedicated policy path.
    ///
    /// This is not only a convenience for [`TokenCreateRequest::no_parent`].
    /// OpenBao policies are path-specific, so callers may be granted sudo
    /// capability on `auth/token/create-orphan` without access to
    /// `auth/token/create`.
    pub async fn create_orphan(&self, request: &TokenCreateRequest) -> Result<TokenAuth> {
        request.validate()?;
        let envelope: TokenAuthEnvelope = self
            .client
            .request_json(Method::POST, "auth/token/create-orphan", Some(request))
            .await?;
        envelope.auth.ok_or(Error::MissingField("auth"))
    }

    /// Creates a token using an OpenBao token role.
    pub async fn create_at(
        &self,
        role_name: Option<&str>,
        request: &TokenCreateRequest,
    ) -> Result<TokenAuth> {
        request.validate()?;
        let path = match role_name {
            Some(role_name) => {
                let role_name = crate::path::validate_mount_path(role_name)?.join("/");
                format!("auth/token/create/{role_name}")
            }
            None => "auth/token/create".to_owned(),
        };
        let envelope: TokenAuthEnvelope = self
            .client
            .request_json(Method::POST, &path, Some(request))
            .await?;
        envelope.auth.ok_or(Error::MissingField("auth"))
    }

    /// Looks up the caller's token.
    pub async fn lookup_self(&self) -> Result<TokenInfo> {
        let envelope: ResponseEnvelope<TokenInfo> = self
            .client
            .request_json(
                Method::POST,
                "auth/token/lookup-self",
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Looks up a token value.
    pub async fn lookup(&self, token: &SecretString) -> Result<TokenInfo> {
        let payload = TokenPayload {
            token: token.expose_secret(),
        };
        let envelope: ResponseEnvelope<TokenInfo> = self
            .client
            .request_json(Method::POST, "auth/token/lookup", Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Looks up a token accessor.
    pub async fn lookup_accessor(&self, accessor: &SecretString) -> Result<TokenInfo> {
        let payload = AccessorPayload {
            accessor: accessor.expose_secret(),
        };
        let envelope: ResponseEnvelope<TokenInfo> = self
            .client
            .request_json(Method::POST, "auth/token/lookup-accessor", Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Lists token accessors. This requires tightly controlled sudo capability.
    pub async fn list_accessors(&self) -> Result<TokenAccessorList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<TokenAccessorList> = self
            .client
            .request_json(method, "auth/token/accessors", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Renews the caller's token.
    pub async fn renew_self(&self, increment: Option<&str>) -> Result<TokenAuth> {
        validate_renew_increment(increment)?;
        let payload = RenewPayload {
            token: None,
            increment,
        };
        let envelope: TokenAuthEnvelope = self
            .client
            .request_json(Method::POST, "auth/token/renew-self", Some(&payload))
            .await?;
        envelope.auth.ok_or(Error::MissingField("auth"))
    }

    /// Renews a token value.
    pub async fn renew(&self, token: &SecretString, increment: Option<&str>) -> Result<TokenAuth> {
        validate_renew_increment(increment)?;
        let payload = RenewPayload {
            token: Some(token.expose_secret()),
            increment,
        };
        let envelope: TokenAuthEnvelope = self
            .client
            .request_json(Method::POST, "auth/token/renew", Some(&payload))
            .await?;
        envelope.auth.ok_or(Error::MissingField("auth"))
    }

    /// Renews a token by accessor without holding the token value.
    pub async fn renew_accessor(
        &self,
        accessor: &SecretString,
        increment: Option<&str>,
    ) -> Result<TokenAuth> {
        validate_renew_increment(increment)?;
        let payload = RenewAccessorPayload {
            accessor: accessor.expose_secret(),
            increment,
        };
        let envelope: TokenAuthEnvelope = self
            .client
            .request_json(Method::POST, "auth/token/renew-accessor", Some(&payload))
            .await?;
        envelope.auth.ok_or(Error::MissingField("auth"))
    }

    /// Revokes a token and its child tokens.
    pub async fn revoke(&self, token: &SecretString) -> Result<Empty> {
        let payload = TokenPayload {
            token: token.expose_secret(),
        };
        self.client
            .request_json(Method::POST, "auth/token/revoke", Some(&payload))
            .await
    }

    /// Revokes a token while orphaning its child tokens.
    pub async fn revoke_orphan(&self, token: &SecretString) -> Result<Empty> {
        let payload = TokenPayload {
            token: token.expose_secret(),
        };
        self.client
            .request_json(Method::POST, "auth/token/revoke-orphan", Some(&payload))
            .await
    }

    /// Revokes the caller's token and its child tokens.
    pub async fn revoke_self(&self) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                "auth/token/revoke-self",
                Option::<&Empty>::None,
            )
            .await
    }

    /// Revokes the token associated with an accessor.
    pub async fn revoke_accessor(&self, accessor: &SecretString) -> Result<Empty> {
        let payload = AccessorPayload {
            accessor: accessor.expose_secret(),
        };
        self.client
            .request_json(Method::POST, "auth/token/revoke-accessor", Some(&payload))
            .await
    }

    /// Writes a token role used as a template for token creation.
    pub async fn write_role(&self, role_name: &str, role: &TokenRole) -> Result<Empty> {
        role.validate()?;
        let role_name = crate::path::validate_mount_path(role_name)?.join("/");
        self.client
            .request_json(
                Method::POST,
                &format!("auth/token/roles/{role_name}"),
                Some(role),
            )
            .await
    }

    /// Reads a token role.
    pub async fn read_role(&self, role_name: &str) -> Result<TokenRole> {
        let role_name = crate::path::validate_mount_path(role_name)?.join("/");
        let envelope: ResponseEnvelope<TokenRole> = self
            .client
            .request_json(
                Method::GET,
                &format!("auth/token/roles/{role_name}"),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists token roles.
    pub async fn list_roles(&self) -> Result<TokenRoleList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<TokenRoleList> = self
            .client
            .request_json(method, "auth/token/roles", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a token role.
    pub async fn delete_role(&self, role_name: &str) -> Result<Empty> {
        let role_name = crate::path::validate_mount_path(role_name)?.join("/");
        self.client
            .request_json_accepting(
                Method::DELETE,
                &format!("auth/token/roles/{role_name}"),
                Option::<&Empty>::None,
                &[reqwest::StatusCode::OK, reqwest::StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Triggers OpenBao token-store tidy.
    ///
    /// This is an administrative operation that can be expensive on large token
    /// stores; callers should run it deliberately, not on hot request paths.
    pub async fn tidy(&self) -> Result<Empty> {
        self.client
            .request_json(Method::POST, "auth/token/tidy", Option::<&Empty>::None)
            .await
    }
}

fn validate_renew_increment(increment: Option<&str>) -> Result<()> {
    if let Some(increment) = increment {
        crate::validation::validate_duration_parameter(increment, "token renewal increment")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use crate::response::ResponseEnvelope;

    use super::{TokenAccessorList, TokenCreateRequest, TokenInfo, validate_renew_increment};

    #[test]
    fn token_ttl_rejects_negative_values() {
        let error = match serde_json::from_str::<ResponseEnvelope<TokenInfo>>(
            r#"{"data":{"ttl":-1,"policies":[]}}"#,
        ) {
            Ok(_) => panic!("negative ttl unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("invalid value"));
    }

    #[test]
    fn token_create_duration_fields_are_validated() {
        let request = TokenCreateRequest::default()
            .with_policies(["app-read", "infra-common"])
            .without_default_policy()
            .with_ttl("30m")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(request.policies, ["app-read", "infra-common"]);
        assert_eq!(request.no_default_policy, Some(true));
        assert!(TokenCreateRequest::default().with_ttl("never").is_err());
        assert!(TokenCreateRequest::default().with_ttl("1h\r\nbad").is_err());
        assert!(
            TokenCreateRequest::default()
                .with_explicit_max_ttl("1h")
                .is_ok()
        );
        assert!(TokenCreateRequest::default().with_period("60s").is_ok());
        assert!(validate_renew_increment(Some("30m")).is_ok());
        assert!(validate_renew_increment(Some("1 hour")).is_err());
    }

    #[test]
    fn token_accessor_list_is_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("accessor-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<TokenAccessorList>(value) {
            Ok(_) => panic!("oversized accessor list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }
}
