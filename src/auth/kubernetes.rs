//! Kubernetes authentication support.

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

/// Handle for Kubernetes auth login at a configured mount.
#[derive(Debug)]
pub struct KubernetesAuth<'a> {
    client: &'a Client<Unauthenticated>,
    mount: String,
}

/// Handle for Kubernetes auth administration at a configured mount.
#[derive(Debug)]
pub struct KubernetesAuthAdmin<'a> {
    client: &'a Client<Authenticated>,
    mount: String,
}

/// Kubernetes auth method configuration.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct KubernetesConfig {
    /// Kubernetes API host, host:port pair, or URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_host: Option<String>,
    /// PEM-encoded CA certificate used by OpenBao to reach Kubernetes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_ca_cert: Option<String>,
    /// Service account JWT used by OpenBao for TokenReview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_reviewer_jwt: Option<SecretString>,
    /// Public keys or certificates used to verify service account JWTs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pem_keys: Vec<String>,
    /// Disable default local CA/JWT discovery when OpenBao runs in Kubernetes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_local_ca_jwt: Option<bool>,
}

/// Kubernetes auth role configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KubernetesRole {
    /// Bound Kubernetes service account names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bound_service_account_names: Vec<String>,
    /// Bound Kubernetes namespaces.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bound_service_account_namespaces: Vec<String>,
    /// Optional JWT audience to verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Alias source, usually `serviceaccount_uid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias_name_source: Option<String>,
    /// Policies attached to generated tokens.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    /// Token TTL such as `30m`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    /// Token max TTL such as `2h`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
    /// Periodic token period.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_period: Option<String>,
    /// Generated token type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

/// Kubernetes auth role list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct KubernetesRoleList {
    /// Role names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

/// Metadata returned after a successful Kubernetes login.
#[derive(Debug, Deserialize)]
pub struct KubernetesLoginMetadata {
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
    /// Metadata returned by OpenBao, such as service account identity fields.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct KubernetesLoginRequest<'a> {
    role: &'a str,
    jwt: &'a str,
}

#[derive(Serialize)]
struct KubernetesConfigPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    kubernetes_host: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kubernetes_ca_cert: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_reviewer_jwt: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pem_keys: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disable_local_ca_jwt: Option<bool>,
}

#[derive(Deserialize)]
struct KubernetesLoginResponse {
    auth: Option<KubernetesLoginAuth>,
}

#[derive(Deserialize)]
struct KubernetesLoginAuth {
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
    /// Uses the Kubernetes auth method mounted at `auth/kubernetes`.
    pub fn kubernetes(&self) -> Result<KubernetesAuth<'_>> {
        self.kubernetes_at("kubernetes")
    }

    /// Uses the Kubernetes auth method mounted at `auth/{mount}`.
    pub fn kubernetes_at(&self, mount: impl Into<String>) -> Result<KubernetesAuth<'_>> {
        Ok(KubernetesAuth {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }

    /// Logs in with Kubernetes auth at `auth/kubernetes`.
    pub async fn login_kubernetes(
        self,
        role: &str,
        jwt: SecretString,
    ) -> Result<(Client<Authenticated>, KubernetesLoginMetadata)> {
        let response = self.kubernetes()?.login_response(role, &jwt).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((self.try_with_token(token)?, metadata))
    }
}

impl Client<Authenticated> {
    /// Administers the Kubernetes auth method mounted at `auth/kubernetes`.
    pub fn kubernetes_admin(&self) -> Result<KubernetesAuthAdmin<'_>> {
        self.kubernetes_admin_at("kubernetes")
    }

    /// Administers the Kubernetes auth method mounted at `auth/{mount}`.
    pub fn kubernetes_admin_at(&self, mount: impl Into<String>) -> Result<KubernetesAuthAdmin<'_>> {
        Ok(KubernetesAuthAdmin {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }
}

impl KubernetesAuth<'_> {
    /// Logs in and returns token metadata plus an authenticated client.
    pub async fn login(
        self,
        role: &str,
        jwt: SecretString,
    ) -> Result<(Client<Authenticated>, KubernetesLoginMetadata)> {
        let response = self.login_response(role, &jwt).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((
            self.client.clone_without_state().try_with_token(token)?,
            metadata,
        ))
    }

    async fn login_response(&self, role: &str, jwt: &SecretString) -> Result<KubernetesLoginAuth> {
        let role = validate_mount_path(role)?.join("/");
        let request = KubernetesLoginRequest {
            role: &role,
            jwt: jwt.expose_secret(),
        };
        let response: KubernetesLoginResponse = self
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

impl KubernetesAuthAdmin<'_> {
    /// Configures the Kubernetes auth method.
    pub async fn configure(&self, config: &KubernetesConfig) -> Result<Empty> {
        let payload = KubernetesConfigPayload {
            kubernetes_host: config.kubernetes_host.as_deref(),
            kubernetes_ca_cert: config.kubernetes_ca_cert.as_deref(),
            token_reviewer_jwt: config
                .token_reviewer_jwt
                .as_ref()
                .map(SecretString::expose_secret),
            pem_keys: config.pem_keys.iter().map(String::as_str).collect(),
            disable_local_ca_jwt: config.disable_local_ca_jwt,
        };
        self.client
            .request_json(
                Method::POST,
                &format!("auth/{}/config", self.mount),
                Some(&payload),
            )
            .await
    }

    /// Reads the Kubernetes auth method configuration.
    pub async fn read_config(&self) -> Result<KubernetesConfig> {
        let envelope: ResponseEnvelope<KubernetesConfig> = self
            .client
            .request_json(
                Method::GET,
                &format!("auth/{}/config", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Creates or updates a Kubernetes auth role.
    pub async fn write_role(&self, name: &str, role: &KubernetesRole) -> Result<Empty> {
        let name = validate_mount_path(name)?.join("/");
        self.client
            .request_json(
                Method::POST,
                &format!("auth/{}/role/{name}", self.mount),
                Some(role),
            )
            .await
    }

    /// Reads a Kubernetes auth role.
    pub async fn read_role(&self, name: &str) -> Result<KubernetesRole> {
        let name = validate_mount_path(name)?.join("/");
        let envelope: ResponseEnvelope<KubernetesRole> = self
            .client
            .request_json(
                Method::GET,
                &format!("auth/{}/role/{name}", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists Kubernetes auth role names.
    pub async fn list_roles(&self) -> Result<KubernetesRoleList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<KubernetesRoleList> = self
            .client
            .request_json(
                method,
                &format!("auth/{}/role", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a Kubernetes auth role.
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

fn split_login_auth(auth: KubernetesLoginAuth) -> (SecretString, KubernetesLoginMetadata) {
    let KubernetesLoginAuth {
        client_token,
        accessor,
        policies,
        lease_duration,
        renewable,
        metadata,
    } = auth;
    let metadata = KubernetesLoginMetadata {
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

    use secrecy::ExposeSecret;

    use super::{KubernetesLoginResponse, KubernetesRoleList};

    #[test]
    fn kubernetes_login_auth_deserializes_secret_token_fields() {
        let response: KubernetesLoginResponse = serde_json::from_str(
            r#"{"auth":{"client_token":"token-value","accessor":"accessor-value","metadata":{"role":"web"}}}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let auth = response.auth.unwrap_or_else(|| panic!("auth missing"));

        assert_eq!(auth.client_token.expose_secret(), "token-value");
        assert_eq!(auth.accessor.expose_secret(), "accessor-value");
        assert_eq!(auth.metadata.get("role").map(String::as_str), Some("web"));
    }

    #[test]
    fn kubernetes_role_list_is_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("role-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<KubernetesRoleList>(value) {
            Ok(_) => panic!("oversized Kubernetes role list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }
}
