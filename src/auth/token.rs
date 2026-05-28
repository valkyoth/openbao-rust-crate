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

    /// Creates a token using an OpenBao token role.
    pub async fn create_at(
        &self,
        role_name: Option<&str>,
        request: &TokenCreateRequest,
    ) -> Result<TokenAuth> {
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

    /// Revokes a token and its child tokens.
    pub async fn revoke(&self, token: &SecretString) -> Result<Empty> {
        let payload = TokenPayload {
            token: token.expose_secret(),
        };
        self.client
            .request_json(Method::POST, "auth/token/revoke", Some(&payload))
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
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use crate::response::ResponseEnvelope;

    use super::{TokenAccessorList, TokenInfo};

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
