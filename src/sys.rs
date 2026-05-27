//! System backend helpers.

use std::collections::BTreeMap;

use reqwest::{
    Method, StatusCode,
    header::{HeaderName, HeaderValue},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    Authenticated, Client, Error, Result,
    path::validate_mount_path,
    response::{Empty, ResponseEnvelope, WrapInfo},
};

/// System backend handle.
#[derive(Debug)]
pub struct Sys<'a, State> {
    client: &'a Client<State>,
}

/// OpenBao health response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Health {
    /// Whether the node is initialized.
    pub initialized: bool,
    /// Whether the node is sealed.
    pub sealed: bool,
    /// Whether the node is standby.
    #[serde(default)]
    pub standby: bool,
    /// Server version.
    pub version: String,
    /// Cluster name.
    #[serde(default)]
    pub cluster_name: Option<String>,
    /// Cluster identifier.
    #[serde(default)]
    pub cluster_id: Option<String>,
}

/// OpenBao seal status response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealStatus {
    /// Seal type.
    #[serde(rename = "type")]
    pub seal_type: String,
    /// Whether the node is initialized.
    pub initialized: bool,
    /// Whether the node is sealed.
    pub sealed: bool,
    /// Key shares configured for Shamir seal.
    #[serde(default)]
    pub n: Option<u64>,
    /// Key threshold configured for Shamir seal.
    #[serde(default)]
    pub t: Option<u64>,
    /// Progress toward unseal threshold.
    #[serde(default)]
    pub progress: Option<u64>,
    /// Server version.
    pub version: String,
}

/// Mount or auth backend information returned by `/sys/mounts` and `/sys/auth`.
#[derive(Clone, Debug, Deserialize)]
pub struct MountInfo {
    /// Backend type, such as `kv`, `pki`, or `approle`.
    #[serde(rename = "type")]
    pub backend_type: String,
    /// Human-readable backend description.
    #[serde(default)]
    pub description: Option<String>,
    /// Mount accessor, when returned. Treat as sensitive metadata.
    #[serde(default)]
    pub accessor: Option<SecretString>,
    /// Backend configuration.
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub config: MountConfig,
    /// Backend options.
    #[serde(default)]
    pub options: Option<BTreeMap<String, String>>,
    /// Whether this mount is local to the node.
    #[serde(default)]
    pub local: bool,
    /// Whether this mount is sealed wrapped.
    #[serde(default)]
    pub seal_wrap: bool,
    /// Whether this mount is external entropy access enabled.
    #[serde(default)]
    pub external_entropy_access: bool,
}

/// Mount or auth backend tuning/configuration fields.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct MountConfig {
    /// Human-readable backend description for tune requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Default lease TTL, in seconds when returned by OpenBao or duration string when submitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_lease_ttl: Option<serde_json::Value>,
    /// Maximum lease TTL, in seconds when returned by OpenBao or duration string when submitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lease_ttl: Option<serde_json::Value>,
    /// Whether backend caching is disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_no_cache: Option<bool>,
    /// Audit non-HMAC request keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_non_hmac_request_keys: Option<Vec<String>>,
    /// Audit non-HMAC response keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_non_hmac_response_keys: Option<Vec<String>>,
    /// Listing visibility, such as `unauth`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing_visibility: Option<String>,
    /// Passthrough request headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passthrough_request_headers: Option<Vec<String>>,
    /// Allowed response headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_response_headers: Option<Vec<String>>,
    /// Plugin version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_version: Option<String>,
    /// Token type used by auth mounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// User lockout configuration used by auth mounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_lockout_config: Option<BTreeMap<String, serde_json::Value>>,
}

/// Request for enabling a secrets engine.
#[derive(Clone, Debug, Serialize)]
pub struct MountEnableRequest {
    /// Backend type, such as `kv`, `pki`, or `transit`.
    #[serde(rename = "type")]
    pub backend_type: String,
    /// Human-readable backend description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Backend configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<MountConfig>,
    /// Backend options.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
    /// Whether this mount is local to the node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<bool>,
    /// Whether this mount is seal wrapped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal_wrap: Option<bool>,
    /// Whether this mount can access external entropy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_entropy_access: Option<bool>,
}

/// Request for enabling an auth method.
#[derive(Clone, Debug, Serialize)]
pub struct AuthEnableRequest {
    /// Auth backend type, such as `approle`, `userpass`, or `kubernetes`.
    #[serde(rename = "type")]
    pub backend_type: String,
    /// Human-readable backend description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Backend configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<MountConfig>,
    /// Whether this auth method is local to the node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<bool>,
}

/// Response wrapping lookup metadata.
#[derive(Clone, Debug, Deserialize)]
pub struct WrappingLookup {
    /// Wrapping token creation time.
    #[serde(default)]
    pub creation_time: Option<String>,
    /// Wrapping token creation path.
    #[serde(default)]
    pub creation_path: Option<String>,
    /// Wrapping token creation TTL in seconds.
    #[serde(default)]
    pub creation_ttl: u64,
}

#[derive(Serialize)]
struct WrappingTokenPayload<'a> {
    token: &'a str,
}

impl<State> Client<State> {
    /// Accesses system backend helpers.
    pub fn sys(&self) -> Sys<'_, State> {
        Sys { client: self }
    }
}

impl<State> Sys<'_, State> {
    /// Reads `/sys/health`.
    ///
    /// Health endpoints intentionally return non-200 status codes for standby,
    /// sealed, or uninitialized nodes. Those statuses are accepted and decoded.
    pub async fn health(&self) -> Result<Health> {
        self.client
            .request_json_accepting(
                Method::GET,
                "sys/health",
                Option::<&Empty>::None,
                &[
                    StatusCode::OK,
                    StatusCode::NO_CONTENT,
                    StatusCode::TOO_MANY_REQUESTS,
                    StatusCode::NOT_IMPLEMENTED,
                    StatusCode::SERVICE_UNAVAILABLE,
                    openbao_status(472)?,
                    openbao_status(473)?,
                ],
            )
            .await
    }

    /// Reads `/sys/seal-status`.
    pub async fn seal_status(&self) -> Result<SealStatus> {
        self.client
            .request_json(Method::GET, "sys/seal-status", Option::<&Empty>::None)
            .await
    }
}

impl Sys<'_, Authenticated> {
    /// Lists mounted secrets engines.
    pub async fn list_mounts(&self) -> Result<BTreeMap<String, MountInfo>> {
        let envelope: ResponseEnvelope<BTreeMap<String, MountInfo>> = self
            .client
            .request_json(Method::GET, "sys/mounts", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Reads one mounted secrets engine.
    pub async fn read_mount(&self, mount_path: &str) -> Result<MountInfo> {
        let envelope: ResponseEnvelope<MountInfo> = self
            .client
            .request_json(
                Method::GET,
                &sys_path("sys/mounts", mount_path, None)?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Enables a secrets engine at `mount_path`.
    pub async fn enable_mount(
        &self,
        mount_path: &str,
        request: &MountEnableRequest,
    ) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                &sys_path("sys/mounts", mount_path, None)?,
                Some(request),
            )
            .await
    }

    /// Disables a mounted secrets engine.
    pub async fn disable_mount(&self, mount_path: &str) -> Result<Empty> {
        self.client
            .request_json_accepting(
                Method::DELETE,
                &sys_path("sys/mounts", mount_path, None)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Reads tune data for a secrets engine.
    pub async fn read_mount_tune(&self, mount_path: &str) -> Result<MountConfig> {
        self.client
            .request_json(
                Method::GET,
                &sys_path("sys/mounts", mount_path, Some("tune"))?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Tunes a secrets engine.
    pub async fn tune_mount(&self, mount_path: &str, config: &MountConfig) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                &sys_path("sys/mounts", mount_path, Some("tune"))?,
                Some(config),
            )
            .await
    }

    /// Lists enabled auth methods.
    pub async fn list_auth_methods(&self) -> Result<BTreeMap<String, MountInfo>> {
        let envelope: ResponseEnvelope<BTreeMap<String, MountInfo>> = self
            .client
            .request_json(Method::GET, "sys/auth", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Enables an auth method at `mount_path`.
    pub async fn enable_auth_method(
        &self,
        mount_path: &str,
        request: &AuthEnableRequest,
    ) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                &sys_path("sys/auth", mount_path, None)?,
                Some(request),
            )
            .await
    }

    /// Disables an auth method.
    pub async fn disable_auth_method(&self, mount_path: &str) -> Result<Empty> {
        self.client
            .request_json_accepting(
                Method::DELETE,
                &sys_path("sys/auth", mount_path, None)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Reads tune data for an auth method.
    pub async fn read_auth_tune(&self, mount_path: &str) -> Result<MountConfig> {
        self.client
            .request_json(
                Method::GET,
                &sys_path("sys/auth", mount_path, Some("tune"))?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Tunes an auth method.
    pub async fn tune_auth_method(&self, mount_path: &str, config: &MountConfig) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                &sys_path("sys/auth", mount_path, Some("tune"))?,
                Some(config),
            )
            .await
    }

    /// Looks up a wrapping token.
    pub async fn wrapping_lookup(&self, token: &SecretString) -> Result<WrappingLookup> {
        let payload = WrappingTokenPayload {
            token: token.expose_secret(),
        };
        let envelope: ResponseEnvelope<WrappingLookup> = self
            .client
            .request_json(Method::POST, "sys/wrapping/lookup", Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Wraps arbitrary JSON data and returns wrapping token metadata.
    pub async fn wrapping_wrap<T>(&self, ttl: &str, data: &T) -> Result<WrapInfo>
    where
        T: Serialize + ?Sized,
    {
        let ttl =
            HeaderValue::from_str(ttl).map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<Option<Empty>> = self
            .client
            .request_json_headers_accepting(
                Method::POST,
                "sys/wrapping/wrap",
                &[(HeaderName::from_static("x-vault-wrap-ttl"), ttl)],
                Some(data),
                &[StatusCode::OK],
            )
            .await?;
        envelope.wrap_info.ok_or(Error::MissingField("wrap_info"))
    }

    /// Unwraps a wrapping token and decodes the original response data.
    pub async fn wrapping_unwrap<T>(&self, token: Option<&SecretString>) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        match token {
            Some(token) => {
                let payload = WrappingTokenPayload {
                    token: token.expose_secret(),
                };
                let envelope: ResponseEnvelope<T> = self
                    .client
                    .request_json(Method::POST, "sys/wrapping/unwrap", Some(&payload))
                    .await?;
                Ok(envelope.data)
            }
            None => {
                let envelope: ResponseEnvelope<T> = self
                    .client
                    .request_json(Method::POST, "sys/wrapping/unwrap", Option::<&Empty>::None)
                    .await?;
                Ok(envelope.data)
            }
        }
    }

    /// Rewraps a wrapping token and returns replacement wrapping token metadata.
    pub async fn wrapping_rewrap(&self, token: &SecretString) -> Result<WrapInfo> {
        let payload = WrappingTokenPayload {
            token: token.expose_secret(),
        };
        let envelope: ResponseEnvelope<Option<Empty>> = self
            .client
            .request_json(Method::POST, "sys/wrapping/rewrap", Some(&payload))
            .await?;
        envelope.wrap_info.ok_or(Error::MissingField("wrap_info"))
    }
}

fn openbao_status(code: u16) -> Result<StatusCode> {
    StatusCode::from_u16(code)
        .map_err(|_| crate::Error::Internal("invalid OpenBao health status code"))
}

fn sys_path(prefix: &str, mount_path: &str, suffix: Option<&str>) -> Result<String> {
    let mut segments = vec![prefix.to_owned()];
    segments.extend(validate_mount_path(mount_path)?);
    if let Some(suffix) = suffix {
        segments.push(suffix.to_owned());
    }
    Ok(segments.join("/"))
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> core::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::sys_path;

    #[test]
    fn sys_paths_are_validated() {
        assert_eq!(
            sys_path("sys/mounts", "secret", Some("tune"))
                .unwrap_or_else(|error| panic!("{error}")),
            "sys/mounts/secret/tune"
        );
        assert!(sys_path("sys/mounts", "../secret", None).is_err());
    }
}
