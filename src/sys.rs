//! System backend helpers.

use core::fmt;
use std::collections::BTreeMap;

use reqwest::{
    Method, StatusCode,
    header::{HeaderName, HeaderValue},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as DeError, Visitor},
};

use crate::{
    Authenticated, Client, Error, Result,
    path::{validate_mount_path, validate_secret_path},
    response::{
        Empty, ResponseEnvelope, WrapInfo, deserialize_bounded_string_map,
        deserialize_bounded_string_vec, deserialize_optional_bounded_string_vec,
    },
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
    pub default_lease_ttl: Option<LeaseDuration>,
    /// Maximum lease TTL, in seconds when returned by OpenBao or duration string when submitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lease_ttl: Option<LeaseDuration>,
    /// Whether backend caching is disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_no_cache: Option<bool>,
    /// Audit non-HMAC request keys.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_bounded_string_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub audit_non_hmac_request_keys: Option<Vec<String>>,
    /// Audit non-HMAC response keys.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_bounded_string_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub audit_non_hmac_response_keys: Option<Vec<String>>,
    /// Listing visibility, such as `unauth`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing_visibility: Option<String>,
    /// Passthrough request headers.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_bounded_string_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub passthrough_request_headers: Option<Vec<String>>,
    /// Allowed response headers.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_bounded_string_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub allowed_response_headers: Option<Vec<String>>,
    /// Plugin version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_version: Option<String>,
    /// Token type used by auth mounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// User lockout configuration used by auth mounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_lockout_config: Option<UserLockoutConfig>,
}

/// Lease duration as OpenBao returns or accepts it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaseDuration {
    /// Duration in whole seconds.
    Seconds(u64),
    /// Duration string such as `30m` or `1h`.
    Duration(String),
}

impl Serialize for LeaseDuration {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Seconds(seconds) => serializer.serialize_u64(*seconds),
            Self::Duration(duration) => serializer.serialize_str(duration),
        }
    }
}

impl<'de> Deserialize<'de> for LeaseDuration {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(LeaseDurationVisitor)
    }
}

struct LeaseDurationVisitor;

impl Visitor<'_> for LeaseDurationVisitor {
    type Value = LeaseDuration;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a non-negative second count or a duration string")
    }

    fn visit_u64<E>(self, value: u64) -> core::result::Result<Self::Value, E> {
        Ok(LeaseDuration::Seconds(value))
    }

    fn visit_i64<E>(self, value: i64) -> core::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        u64::try_from(value)
            .map(LeaseDuration::Seconds)
            .map_err(|_| E::custom("duration seconds must not be negative"))
    }

    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        validate_duration_string(value, true)
            .then(|| LeaseDuration::Duration(value.to_owned()))
            .ok_or_else(|| E::custom("invalid duration string"))
    }

    fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        validate_duration_string(&value, true)
            .then_some(LeaseDuration::Duration(value))
            .ok_or_else(|| E::custom("invalid duration string"))
    }
}

/// User lockout configuration for auth method tuning.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UserLockoutConfig {
    /// Number of failed attempts before lockout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockout_threshold: Option<u64>,
    /// Lockout duration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockout_duration: Option<LeaseDuration>,
    /// Duration after which the failed-attempt counter is reset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockout_counter_reset_duration: Option<LeaseDuration>,
    /// Disable lockout handling for the mount.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockout_disable: Option<bool>,
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

/// ACL policy list response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicyList {
    /// Policy names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub policies: Vec<String>,
}

/// ACL policy read response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicyInfo {
    /// Policy name.
    pub name: String,
    /// Policy document.
    pub rules: String,
    /// Last modification timestamp, when returned by OpenBao.
    #[serde(default)]
    pub modified: Option<String>,
    /// Policy version, when returned by OpenBao.
    #[serde(default)]
    pub version: Option<u64>,
    /// Whether check-and-set is required for future updates.
    #[serde(default)]
    pub cas_required: bool,
}

/// ACL policy create/update request.
#[derive(Clone, Debug, Serialize)]
pub struct PolicyWriteRequest {
    /// Policy document.
    pub policy: String,
    /// Expiration timestamp. Mutually exclusive with `ttl`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    /// Policy lifetime duration. Mutually exclusive with `expiration`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Check-and-set version. Use `-1` for strict create.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas: Option<i64>,
    /// Whether check-and-set should be required by this update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas_required: Option<bool>,
}

/// Capabilities returned for queried OpenBao paths.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Capabilities {
    /// Backwards-compatible capabilities field returned for single-path queries.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub capabilities: Vec<String>,
    /// Capabilities keyed by queried path.
    #[serde(flatten)]
    pub by_path: BTreeMap<String, Vec<String>>,
}

/// Enabled audit device information returned by `/sys/audit`.
#[derive(Clone, Debug, Deserialize)]
pub struct AuditDevice {
    /// Audit device type, such as `file`, `socket`, or `syslog`.
    #[serde(rename = "type")]
    pub backend_type: String,
    /// Human-readable audit device description.
    #[serde(default)]
    pub description: Option<String>,
    /// Audit-device-specific options.
    #[serde(default, deserialize_with = "deserialize_bounded_string_map")]
    pub options: BTreeMap<String, String>,
    /// Whether this audit device is local to the node.
    #[serde(default)]
    pub local: bool,
}

/// Request for enabling an audit device.
#[derive(Clone, Debug, Serialize)]
pub struct AuditEnableRequest {
    /// Audit device type, such as `file`, `socket`, or `syslog`.
    #[serde(rename = "type")]
    pub backend_type: String,
    /// Human-readable audit device description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Audit-device-specific options.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
    /// Whether this audit device is local to the node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<bool>,
}

/// Audit hash response returned by `/sys/audit-hash/:path`.
#[derive(Clone, Debug, Deserialize)]
pub struct AuditHash {
    /// HMAC value computed by OpenBao for the supplied audit device and input.
    pub hash: String,
}

/// Metadata returned by `/sys/leases/lookup`.
#[derive(Clone, Deserialize)]
pub struct LeaseLookup {
    /// Lease identifier. This can revoke the secret and is treated as secret material.
    pub id: SecretString,
    /// Lease issue timestamp.
    pub issue_time: String,
    /// Lease expiration timestamp.
    pub expire_time: String,
    /// Last renewal timestamp, when the lease has been renewed.
    #[serde(default)]
    pub last_renewal: Option<String>,
    /// Whether this lease is renewable.
    #[serde(default)]
    pub renewable: bool,
    /// Remaining lease TTL in seconds.
    #[serde(default)]
    pub ttl: u64,
}

impl fmt::Debug for LeaseLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseLookup")
            .field("id", &"<redacted>")
            .field("issue_time", &self.issue_time)
            .field("expire_time", &self.expire_time)
            .field("last_renewal", &self.last_renewal)
            .field("renewable", &self.renewable)
            .field("ttl", &self.ttl)
            .finish()
    }
}

/// Result of renewing a lease.
#[derive(Clone)]
pub struct LeaseRenewal {
    /// Renewed lease identifier. This can revoke the secret and is treated as secret material.
    pub lease_id: SecretString,
    /// Renewed lease duration in seconds.
    pub lease_duration: u64,
    /// Whether this lease remains renewable.
    pub renewable: bool,
}

impl fmt::Debug for LeaseRenewal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseRenewal")
            .field("lease_id", &"<redacted>")
            .field("lease_duration", &self.lease_duration)
            .field("renewable", &self.renewable)
            .finish()
    }
}

#[derive(Serialize)]
struct WrappingTokenPayload<'a> {
    token: &'a str,
}

#[derive(Serialize)]
struct AuditHashPayload<'a> {
    input: &'a str,
}

#[derive(Serialize)]
struct LeaseLookupPayload<'a> {
    lease_id: &'a str,
}

#[derive(Serialize)]
struct LeaseRenewPayload<'a> {
    lease_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    increment: Option<u64>,
}

#[derive(Serialize)]
struct LeaseRevokePayload<'a> {
    lease_id: &'a str,
}

#[derive(Serialize)]
struct CapabilitiesPayload<'a> {
    paths: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accessor: Option<&'a str>,
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

    /// Lists ACL policies.
    pub async fn list_policies(&self) -> Result<PolicyList> {
        self.client
            .request_json(Method::GET, "sys/policy", Option::<&Empty>::None)
            .await
    }

    /// Lists ACL policies below a policy prefix.
    pub async fn list_policies_with_prefix(&self, prefix: &str) -> Result<PolicyList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        self.client
            .request_json(
                method,
                &sys_path("sys/policy", prefix, None)?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Reads one ACL policy.
    pub async fn read_policy(&self, name: &str) -> Result<PolicyInfo> {
        self.client
            .request_json(
                Method::GET,
                &sys_path("sys/policy", name, None)?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Creates or updates an ACL policy.
    pub async fn write_policy(&self, name: &str, request: &PolicyWriteRequest) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                &sys_path("sys/policy", name, None)?,
                Some(request),
            )
            .await
    }

    /// Deletes an ACL policy.
    pub async fn delete_policy(&self, name: &str) -> Result<Empty> {
        self.client
            .request_json_accepting(
                Method::DELETE,
                &sys_path("sys/policy", name, None)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Queries capabilities for the caller's token.
    pub async fn capabilities_self<I, P>(&self, paths: I) -> Result<Capabilities>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<str>,
    {
        let paths = validate_capability_paths(paths)?;
        let payload = CapabilitiesPayload {
            paths: &paths,
            token: None,
            accessor: None,
        };
        let envelope: ResponseEnvelope<Capabilities> = self
            .client
            .request_json(Method::POST, "sys/capabilities-self", Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Queries capabilities for a token value.
    pub async fn capabilities<I, P>(&self, token: &SecretString, paths: I) -> Result<Capabilities>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<str>,
    {
        let paths = validate_capability_paths(paths)?;
        let payload = CapabilitiesPayload {
            paths: &paths,
            token: Some(token.expose_secret()),
            accessor: None,
        };
        let envelope: ResponseEnvelope<Capabilities> = self
            .client
            .request_json(Method::POST, "sys/capabilities", Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Queries capabilities for a token accessor.
    pub async fn capabilities_accessor<I, P>(
        &self,
        accessor: &SecretString,
        paths: I,
    ) -> Result<Capabilities>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<str>,
    {
        let paths = validate_capability_paths(paths)?;
        let payload = CapabilitiesPayload {
            paths: &paths,
            token: None,
            accessor: Some(accessor.expose_secret()),
        };
        let envelope: ResponseEnvelope<Capabilities> = self
            .client
            .request_json(Method::POST, "sys/capabilities-accessor", Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Lists enabled audit devices.
    pub async fn list_audit_devices(&self) -> Result<BTreeMap<String, AuditDevice>> {
        self.client
            .request_json(Method::GET, "sys/audit", Option::<&Empty>::None)
            .await
    }

    /// Enables an audit device at `path`.
    pub async fn enable_audit_device(
        &self,
        path: &str,
        request: &AuditEnableRequest,
    ) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                &sys_path("sys/audit", path, None)?,
                Some(request),
            )
            .await
    }

    /// Disables an audit device.
    ///
    /// OpenBao creates a new audit salt if a device is later re-enabled, so
    /// stored audit HMACs from the disabled device cannot be recomputed.
    pub async fn disable_audit_device(&self, path: &str) -> Result<Empty> {
        self.client
            .request_json_accepting(
                Method::DELETE,
                &sys_path("sys/audit", path, None)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Calculates the HMAC OpenBao would write for `input` through an audit device.
    pub async fn audit_hash(&self, path: &str, input: &SecretString) -> Result<AuditHash> {
        let payload = AuditHashPayload {
            input: input.expose_secret(),
        };
        self.client
            .request_json(
                Method::POST,
                &sys_path("sys/audit-hash", path, None)?,
                Some(&payload),
            )
            .await
    }

    /// Looks up lease metadata using the non-prefix `/sys/leases/lookup` endpoint.
    pub async fn lookup_lease(&self, lease_id: &SecretString) -> Result<LeaseLookup> {
        let payload = LeaseLookupPayload {
            lease_id: validate_lease_id(lease_id)?,
        };
        let envelope: ResponseEnvelope<LeaseLookup> = self
            .client
            .request_json(Method::POST, "sys/leases/lookup", Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Renews a non-token lease using the JSON-body `/sys/leases/renew` endpoint.
    ///
    /// Token leases should be renewed with the token helpers instead.
    pub async fn renew_lease(
        &self,
        lease_id: &SecretString,
        increment_seconds: Option<u64>,
    ) -> Result<LeaseRenewal> {
        let payload = LeaseRenewPayload {
            lease_id: validate_lease_id(lease_id)?,
            increment: increment_seconds,
        };
        let envelope: ResponseEnvelope<Option<Empty>> = self
            .client
            .request_json(Method::POST, "sys/leases/renew", Some(&payload))
            .await?;
        Ok(LeaseRenewal {
            lease_id: envelope.lease_id,
            lease_duration: envelope.lease_duration,
            renewable: envelope.renewable,
        })
    }

    /// Revokes one exact lease using the non-prefix `/sys/leases/revoke` endpoint.
    pub async fn revoke_lease(&self, lease_id: &SecretString) -> Result<Empty> {
        let payload = LeaseRevokePayload {
            lease_id: validate_lease_id(lease_id)?,
        };
        self.client
            .request_json_accepting(
                Method::POST,
                "sys/leases/revoke",
                Some(&payload),
                &[StatusCode::OK, StatusCode::NO_CONTENT],
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
        validate_wrapping_ttl(ttl)?;
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

fn validate_wrapping_ttl(ttl: &str) -> Result<()> {
    if validate_duration_string(ttl, false) {
        return Ok(());
    }
    Err(Error::InvalidHeader(
        "wrapping TTL must be a positive duration such as 30s, 5m, or 1h".into(),
    ))
}

fn validate_duration_string(value: &str, allow_zero: bool) -> bool {
    if value.is_empty() {
        return false;
    }

    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let digit_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if digit_start == index {
            return false;
        }
        if !allow_zero && bytes[digit_start..index].iter().all(|byte| *byte == b'0') {
            return false;
        }
        if index >= bytes.len() {
            return false;
        }
        match bytes[index] {
            b's' | b'm' | b'h' => index += 1,
            _ => return false,
        }
    }
    true
}

fn validate_capability_paths<I, P>(paths: I) -> Result<Vec<String>>
where
    I: IntoIterator<Item = P>,
    P: AsRef<str>,
{
    let mut validated = Vec::new();
    for path in paths {
        let path = path.as_ref();
        if path.trim_matches('/').is_empty() {
            return Err(Error::InvalidPath(
                "capability path must not be empty".into(),
            ));
        }
        validated.push(validate_secret_path(path)?.join("/"));
    }
    if validated.is_empty() {
        return Err(Error::InvalidPath(
            "at least one capability path is required".into(),
        ));
    }
    Ok(validated)
}

fn validate_lease_id(lease_id: &SecretString) -> Result<&str> {
    let lease_id = lease_id.expose_secret();
    if lease_id.is_empty() {
        return Err(Error::InvalidPath("lease ID must not be empty".into()));
    }
    if lease_id.as_bytes().iter().any(u8::is_ascii_control) {
        return Err(Error::InvalidPath(
            "lease ID must not contain control characters".into(),
        ));
    }
    Ok(lease_id)
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

    use secrecy::SecretString;

    use super::{
        LeaseDuration, PolicyList, sys_path, validate_capability_paths, validate_lease_id,
        validate_wrapping_ttl,
    };

    #[test]
    fn sys_paths_are_validated() {
        assert_eq!(
            sys_path("sys/mounts", "secret", Some("tune"))
                .unwrap_or_else(|error| panic!("{error}")),
            "sys/mounts/secret/tune"
        );
        assert!(sys_path("sys/mounts", "../secret", None).is_err());
    }

    #[test]
    fn capability_paths_are_validated() {
        let paths = validate_capability_paths(["secret/data/app", "/sys/policy/default"])
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(paths, ["secret/data/app", "sys/policy/default"]);
        assert!(validate_capability_paths([""]).is_err());
        assert!(validate_capability_paths(["../secret"]).is_err());
    }

    #[test]
    fn wrapping_ttl_is_validated() {
        assert!(validate_wrapping_ttl("30s").is_ok());
        assert!(validate_wrapping_ttl("5m").is_ok());
        assert!(validate_wrapping_ttl("1h").is_ok());
        assert!(validate_wrapping_ttl("").is_err());
        assert!(validate_wrapping_ttl("0s").is_err());
        assert!(validate_wrapping_ttl("-1h").is_err());
        assert!(validate_wrapping_ttl("forever").is_err());
    }

    #[test]
    fn lease_ids_are_validated_for_json_body_use() {
        assert!(validate_lease_id(&SecretString::from("database/creds/ro/abc")).is_ok());
        assert!(validate_lease_id(&SecretString::from("")).is_err());
        assert!(validate_lease_id(&SecretString::from("database/creds/ro\nabc")).is_err());
    }

    #[test]
    fn lease_duration_rejects_untyped_json() {
        assert_eq!(
            serde_json::from_str::<LeaseDuration>("3600").unwrap_or_else(|error| panic!("{error}")),
            LeaseDuration::Seconds(3600)
        );
        assert_eq!(
            serde_json::from_str::<LeaseDuration>(r#""30m""#)
                .unwrap_or_else(|error| panic!("{error}")),
            LeaseDuration::Duration("30m".to_owned())
        );
        assert!(serde_json::from_str::<LeaseDuration>("-1").is_err());
        assert!(serde_json::from_str::<LeaseDuration>(r#""never""#).is_err());
        assert!(serde_json::from_str::<LeaseDuration>(r#"{"ttl":3600}"#).is_err());
    }

    #[test]
    fn policy_list_is_bounded() {
        let mut policies = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            policies.push(format!("policy-{index}"));
        }
        let value = serde_json::json!({ "policies": policies });
        let error = match serde_json::from_value::<PolicyList>(value) {
            Ok(_) => panic!("oversized policy list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn mount_config_header_lists_are_bounded() {
        let mut headers = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            headers.push(format!("x-header-{index}"));
        }
        let value = serde_json::json!({ "allowed_response_headers": headers });
        let error = match serde_json::from_value::<super::MountConfig>(value) {
            Ok(_) => panic!("oversized mount header list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn audit_device_options_are_bounded() {
        let mut options = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            options.insert(format!("option-{index}"), serde_json::json!("value"));
        }
        let value = serde_json::json!({
            "type": "file",
            "options": options,
        });
        let error = match serde_json::from_value::<super::AuditDevice>(value) {
            Ok(_) => panic!("oversized audit options unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }
}
