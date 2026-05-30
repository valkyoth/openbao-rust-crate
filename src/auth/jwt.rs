//! JWT/OIDC authentication support.

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

/// Handle for JWT auth login at a configured mount.
#[derive(Debug)]
pub struct JwtAuth<'a> {
    client: &'a Client<Unauthenticated>,
    mount: String,
}

/// Handle for JWT/OIDC auth administration at a configured mount.
#[derive(Debug)]
pub struct JwtAuthAdmin<'a> {
    client: &'a Client<Authenticated>,
    mount: String,
}

/// JWT/OIDC auth method configuration.
#[derive(Clone, Default, Deserialize)]
pub struct JwtConfig {
    /// OIDC discovery base URL.
    #[serde(default)]
    pub oidc_discovery_url: Option<String>,
    /// PEM CA bundle for the OIDC discovery URL.
    #[serde(default)]
    pub oidc_discovery_ca_pem: Option<String>,
    /// JWKS endpoint URL.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// PEM CA bundle for the JWKS URL.
    #[serde(default)]
    pub jwks_ca_pem: Option<String>,
    /// Static JWT verification public keys.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub jwt_validation_pubkeys: Vec<String>,
    /// Required JWT issuer.
    #[serde(default)]
    pub bound_issuer: Option<String>,
    /// Supported JWT signature algorithms.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub jwt_supported_algs: Vec<String>,
    /// Default role used when the login request omits `role`.
    #[serde(default)]
    pub default_role: Option<String>,
    /// OIDC client identifier.
    #[serde(default)]
    pub oidc_client_id: Option<String>,
    /// OIDC client secret. Treated as secret material and redacted from debug output.
    #[serde(default)]
    pub oidc_client_secret: Option<SecretString>,
    /// OIDC response mode.
    #[serde(default)]
    pub oidc_response_mode: Option<String>,
    /// OIDC response types.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub oidc_response_types: Vec<String>,
    /// Provider-specific string configuration.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    pub provider_config: BTreeMap<String, String>,
    /// Whether namespaces are encoded in OIDC state.
    #[serde(default)]
    pub namespace_in_state: Option<bool>,
}

impl core::fmt::Debug for JwtConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("JwtConfig")
            .field("oidc_discovery_url", &self.oidc_discovery_url)
            .field("oidc_discovery_ca_pem", &self.oidc_discovery_ca_pem)
            .field("jwks_url", &self.jwks_url)
            .field("jwks_ca_pem", &self.jwks_ca_pem)
            .field("jwt_validation_pubkeys", &self.jwt_validation_pubkeys)
            .field("bound_issuer", &self.bound_issuer)
            .field("jwt_supported_algs", &self.jwt_supported_algs)
            .field("default_role", &self.default_role)
            .field("oidc_client_id", &self.oidc_client_id)
            .field(
                "oidc_client_secret",
                &self.oidc_client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("oidc_response_mode", &self.oidc_response_mode)
            .field("oidc_response_types", &self.oidc_response_types)
            .field("provider_config", &self.provider_config)
            .field("namespace_in_state", &self.namespace_in_state)
            .finish()
    }
}

/// JWT/OIDC role configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct JwtRole {
    /// Role type, usually `jwt` or `oidc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_type: Option<String>,
    /// Audiences accepted from the `aud` claim.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bound_audiences: Vec<String>,
    /// Subject accepted from the `sub` claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_subject: Option<String>,
    /// Bound claims matching mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_claims_type: Option<String>,
    /// Claims that must match for login.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub bound_claims: BTreeMap<String, String>,
    /// Claim used to identify the entity alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_claim: Option<String>,
    /// Whether `user_claim` is a JSON pointer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_claim_json_pointer: Option<bool>,
    /// Claim containing groups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups_claim: Option<String>,
    /// Claim mappings copied into alias metadata.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub claim_mappings: BTreeMap<String, String>,
    /// Clock skew leeway such as `60s` or `-1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_skew_leeway: Option<String>,
    /// Expiration leeway such as `150s` or `-1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_leeway: Option<String>,
    /// Not-before leeway such as `150s` or `-1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before_leeway: Option<String>,
    /// OIDC callback URLs permitted for this role.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_redirect_uris: Vec<String>,
    /// OIDC scopes requested by this role.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub oidc_scopes: Vec<String>,
    /// Policies attached to generated tokens.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_policies: Vec<String>,
    /// Token TTL such as `30m`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    /// Token max TTL such as `2h`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
    /// Periodic token period.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_period: Option<String>,
    /// Token explicit max TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_explicit_max_ttl: Option<String>,
    /// Generated token type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// CIDR restrictions for generated tokens.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_bound_cidrs: Vec<String>,
    /// Number of allowed token uses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_num_uses: Option<u64>,
    /// Whether to omit the default policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_no_default_policy: Option<bool>,
}

impl JwtRole {
    /// Creates a JWT role request with the required user claim.
    pub fn new(user_claim: impl Into<String>) -> Self {
        Self {
            user_claim: Some(user_claim.into()),
            ..Self::default()
        }
    }
}

/// JWT/OIDC role list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct JwtRoleList {
    /// Role names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

/// Metadata returned after a successful JWT login.
#[derive(Debug, Deserialize)]
pub struct JwtLoginMetadata {
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
    /// Metadata returned by OpenBao, such as the JWT role.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct JwtConfigPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc_discovery_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc_discovery_ca_pem: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwks_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwks_ca_pem: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    jwt_validation_pubkeys: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bound_issuer: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    jwt_supported_algs: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_role: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc_client_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc_client_secret: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc_response_mode: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    oidc_response_types: Vec<&'a str>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    provider_config: &'a BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace_in_state: Option<bool>,
}

#[derive(Serialize)]
struct JwtLoginRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<&'a str>,
    jwt: &'a str,
}

#[derive(Deserialize)]
struct JwtLoginResponse {
    auth: Option<JwtLoginAuth>,
}

#[derive(Deserialize)]
struct JwtLoginAuth {
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
    /// Uses the JWT/OIDC auth method mounted at `auth/jwt`.
    pub fn jwt(&self) -> Result<JwtAuth<'_>> {
        self.jwt_at("jwt")
    }

    /// Uses the JWT/OIDC auth method mounted at `auth/{mount}`.
    pub fn jwt_at(&self, mount: impl Into<String>) -> Result<JwtAuth<'_>> {
        Ok(JwtAuth {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }

    /// Logs in with JWT auth at `auth/jwt`.
    pub async fn login_jwt(
        self,
        role: Option<&str>,
        jwt: SecretString,
    ) -> Result<(Client<Authenticated>, JwtLoginMetadata)> {
        let response = self.jwt()?.login_response(role, &jwt).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((self.try_with_token(token)?, metadata))
    }
}

impl Client<Authenticated> {
    /// Administers the JWT/OIDC auth method mounted at `auth/jwt`.
    pub fn jwt_admin(&self) -> Result<JwtAuthAdmin<'_>> {
        self.jwt_admin_at("jwt")
    }

    /// Administers the JWT/OIDC auth method mounted at `auth/{mount}`.
    pub fn jwt_admin_at(&self, mount: impl Into<String>) -> Result<JwtAuthAdmin<'_>> {
        Ok(JwtAuthAdmin {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }
}

impl JwtAuth<'_> {
    /// Logs in and returns token metadata plus an authenticated client.
    pub async fn login(
        self,
        role: Option<&str>,
        jwt: SecretString,
    ) -> Result<(Client<Authenticated>, JwtLoginMetadata)> {
        let response = self.login_response(role, &jwt).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((
            self.client.clone_without_state().try_with_token(token)?,
            metadata,
        ))
    }

    async fn login_response(&self, role: Option<&str>, jwt: &SecretString) -> Result<JwtLoginAuth> {
        let role = role
            .map(|role| validate_mount_path(role).map(|segments| segments.join("/")))
            .transpose()?;
        let request = JwtLoginRequest {
            role: role.as_deref(),
            jwt: jwt.expose_secret(),
        };
        let response: JwtLoginResponse = self
            .client
            .request_json(
                Method::POST,
                &format!("auth/{}/login", self.mount),
                Some(&request),
            )
            .await?;
        response.auth.ok_or(Error::MissingField("auth"))
    }
}

impl JwtAuthAdmin<'_> {
    /// Configures the JWT/OIDC auth method.
    pub async fn configure(&self, config: &JwtConfig) -> Result<Empty> {
        let payload = JwtConfigPayload {
            oidc_discovery_url: config.oidc_discovery_url.as_deref(),
            oidc_discovery_ca_pem: config.oidc_discovery_ca_pem.as_deref(),
            jwks_url: config.jwks_url.as_deref(),
            jwks_ca_pem: config.jwks_ca_pem.as_deref(),
            jwt_validation_pubkeys: config
                .jwt_validation_pubkeys
                .iter()
                .map(String::as_str)
                .collect(),
            bound_issuer: config.bound_issuer.as_deref(),
            jwt_supported_algs: config
                .jwt_supported_algs
                .iter()
                .map(String::as_str)
                .collect(),
            default_role: config.default_role.as_deref(),
            oidc_client_id: config.oidc_client_id.as_deref(),
            oidc_client_secret: config
                .oidc_client_secret
                .as_ref()
                .map(SecretString::expose_secret),
            oidc_response_mode: config.oidc_response_mode.as_deref(),
            oidc_response_types: config
                .oidc_response_types
                .iter()
                .map(String::as_str)
                .collect(),
            provider_config: &config.provider_config,
            namespace_in_state: config.namespace_in_state,
        };
        self.client
            .request_json(
                Method::POST,
                &format!("auth/{}/config", self.mount),
                Some(&payload),
            )
            .await
    }

    /// Reads the JWT/OIDC auth method configuration.
    pub async fn read_config(&self) -> Result<JwtConfig> {
        let envelope: ResponseEnvelope<JwtConfig> = self
            .client
            .request_json(
                Method::GET,
                &format!("auth/{}/config", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Creates or updates a JWT/OIDC auth role.
    pub async fn write_role(&self, name: &str, role: &JwtRole) -> Result<Empty> {
        let name = validate_mount_path(name)?.join("/");
        self.client
            .request_json(
                Method::POST,
                &format!("auth/{}/role/{name}", self.mount),
                Some(role),
            )
            .await
    }

    /// Reads a JWT/OIDC auth role.
    pub async fn read_role(&self, name: &str) -> Result<JwtRole> {
        let name = validate_mount_path(name)?.join("/");
        let envelope: ResponseEnvelope<JwtRole> = self
            .client
            .request_json(
                Method::GET,
                &format!("auth/{}/role/{name}", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists JWT/OIDC auth role names.
    pub async fn list_roles(&self) -> Result<JwtRoleList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<JwtRoleList> = self
            .client
            .request_json(
                method,
                &format!("auth/{}/role", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a JWT/OIDC auth role.
    pub async fn delete_role(&self, name: &str) -> Result<Empty> {
        let name = validate_mount_path(name)?.join("/");
        self.client
            .request_json_accepting(
                Method::DELETE,
                &format!("auth/{}/role/{name}", self.mount),
                Option::<&Empty>::None,
                &[reqwest::StatusCode::OK, reqwest::StatusCode::NO_CONTENT],
            )
            .await
    }
}

fn split_login_auth(auth: JwtLoginAuth) -> (SecretString, JwtLoginMetadata) {
    let JwtLoginAuth {
        client_token,
        accessor,
        policies,
        lease_duration,
        renewable,
        metadata,
    } = auth;
    let metadata = JwtLoginMetadata {
        accessor,
        policies,
        lease_duration,
        renewable,
        metadata,
    };
    (client_token, metadata)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::{ExposeSecret, SecretString};

    use super::{JwtConfig, JwtLoginResponse, JwtRoleList};

    #[test]
    fn jwt_login_auth_deserializes_secret_token_fields() {
        let response: JwtLoginResponse = serde_json::from_str(
            r#"{"auth":{"client_token":"token-value","accessor":"accessor-value","metadata":{"role":"web"}}}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let auth = response.auth.unwrap_or_else(|| panic!("auth missing"));

        assert_eq!(auth.client_token.expose_secret(), "token-value");
        assert_eq!(auth.accessor.expose_secret(), "accessor-value");
        assert_eq!(auth.metadata.get("role").map(String::as_str), Some("web"));
    }

    #[test]
    fn jwt_role_list_is_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("role-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<JwtRoleList>(value) {
            Ok(_) => panic!("oversized JWT role list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn jwt_config_debug_redacts_client_secret() {
        let config = JwtConfig {
            oidc_client_secret: Some(SecretString::from("client-secret")),
            ..Default::default()
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("client-secret"));
    }
}
