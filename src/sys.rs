//! System backend helpers.

use core::{fmt, marker::PhantomData};
use std::{collections::BTreeMap, net::IpAddr};

use reqwest::{
    Method, StatusCode,
    header::{HeaderName, HeaderValue},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as DeError, IgnoredAny, MapAccess, SeqAccess, Visitor},
};

use crate::{
    Authenticated, Client, Error, JsonValue, Result, Unauthenticated,
    path::{validate_endpoint_path, validate_mount_path},
    response::{
        Empty, ListEntries, ResponseEnvelope, WrapInfo, deserialize_bounded_secret_string_vec,
        deserialize_bounded_string_map, deserialize_bounded_string_vec,
        deserialize_optional_bounded_string_map, deserialize_optional_bounded_string_vec,
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

/// OpenBao initialization status returned by `/sys/init`.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct InitStatus {
    /// Whether the node has already been initialized.
    pub initialized: bool,
}

/// High Availability leader status returned by `/sys/leader`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LeaderStatus {
    /// Whether HA mode is enabled.
    #[serde(default)]
    pub ha_enabled: bool,
    /// Whether this node is the active leader.
    #[serde(default)]
    pub is_self: bool,
    /// Active leader API address.
    #[serde(default)]
    pub leader_address: Option<String>,
    /// Active leader cluster address.
    #[serde(default)]
    pub leader_cluster_address: Option<String>,
    /// Whether this node is a performance standby.
    #[serde(default)]
    pub performance_standby: bool,
    /// Last remote WAL observed by a performance standby.
    #[serde(default)]
    pub performance_standby_last_remote_wal: Option<u64>,
}

/// Runtime logger verbosity accepted by `/sys/loggers`.
///
/// OpenBao documents these changes as transient: they are not persisted and
/// revert to configured log levels when the service reloads or restarts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoggerLevel {
    /// Most verbose logging.
    Trace,
    /// Debug logging.
    Debug,
    /// Informational logging.
    Info,
    /// Warning logging.
    Warn,
    /// Error logging.
    Error,
}

impl LoggerLevel {
    /// Returns the OpenBao logger level value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Logger levels keyed by logger name.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LoggerLevels(
    #[serde(deserialize_with = "deserialize_bounded_logger_level_map")] BTreeMap<String, String>,
);

impl LoggerLevels {
    /// Returns the logger level by logger name.
    #[must_use]
    pub fn get(&self, logger: &str) -> Option<&str> {
        self.0.get(logger).map(String::as_str)
    }

    /// Returns all logger levels.
    #[must_use]
    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    /// Consumes this wrapper and returns the logger map.
    #[must_use]
    pub fn into_inner(self) -> BTreeMap<String, String> {
        self.0
    }
}

/// Installed OpenBao version history.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VersionHistory {
    /// Installed versions in chronological order.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
    /// Version metadata keyed by version string.
    #[serde(default, deserialize_with = "deserialize_bounded_version_history_map")]
    pub key_info: BTreeMap<String, VersionHistoryEntry>,
}

impl ListEntries for VersionHistory {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Metadata for one installed OpenBao version.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VersionHistoryEntry {
    /// Build timestamp, when OpenBao returned one.
    #[serde(default)]
    pub build_date: Option<String>,
    /// Previous installed version, when known.
    #[serde(default)]
    pub previous_version: Option<String>,
    /// Installation timestamp.
    #[serde(default)]
    pub timestamp_installed: Option<String>,
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

/// OpenBao unseal progress response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UnsealStatus {
    /// Whether the node is still sealed.
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
    /// Cluster name when OpenBao is unsealed.
    #[serde(default)]
    pub cluster_name: Option<String>,
    /// Cluster identifier when OpenBao is unsealed.
    #[serde(default)]
    pub cluster_id: Option<String>,
}

/// Production initialization request for `/sys/init`.
///
/// This type is available only with the explicit `operator-ops` feature. It can
/// cause OpenBao to return root, unseal, or recovery material. Prefer an
/// operator ceremony and external custody system over application automation.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Debug, Default, Serialize)]
pub struct OperatorInitRequest {
    /// Number of Shamir unseal key shares to create.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_shares: Option<u8>,
    /// Number of shares required to unseal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_threshold: Option<u8>,
    /// Base64-encoded PGP public keys for unseal share encryption.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pgp_keys: Vec<String>,
    /// Base64-encoded PGP public key for root token encryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_token_pgp_key: Option<String>,
    /// Number of recovery shares for auto-unseal deployments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_shares: Option<u8>,
    /// Number of recovery shares required for recovery operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_threshold: Option<u8>,
    /// Base64-encoded PGP public keys for recovery share encryption.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recovery_pgp_keys: Vec<String>,
    /// Number of shares stored by the seal backend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_shares: Option<u8>,
}

/// Production initialization response from `/sys/init`.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Deserialize)]
pub struct OperatorInitResponse {
    /// Unseal key shares. Treat as highly sensitive operator material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub keys: Vec<SecretString>,
    /// Base64-encoded unseal key shares. Treat as highly sensitive operator material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub keys_base64: Vec<SecretString>,
    /// Initial root token. Treat as highly sensitive operator material.
    pub root_token: SecretString,
    /// Recovery key shares. Treat as highly sensitive operator material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub recovery_keys: Vec<SecretString>,
    /// Base64-encoded recovery key shares. Treat as highly sensitive operator material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub recovery_keys_base64: Vec<SecretString>,
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for OperatorInitResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorInitResponse")
            .field("keys_count", &self.keys.len())
            .field("keys_base64_count", &self.keys_base64.len())
            .field("root_token", &"<redacted>")
            .field("recovery_keys_count", &self.recovery_keys.len())
            .field(
                "recovery_keys_base64_count",
                &self.recovery_keys_base64.len(),
            )
            .finish()
    }
}

/// Production unseal request for `/sys/unseal`.
#[cfg(feature = "operator-ops")]
#[derive(Clone)]
pub struct OperatorUnsealRequest {
    /// Unseal or recovery key share.
    pub key: SecretString,
    /// Reset unseal progress.
    pub reset: Option<bool>,
    /// Seal migration flag.
    pub migrate: Option<bool>,
}

#[cfg(feature = "operator-ops")]
impl OperatorUnsealRequest {
    /// Creates an unseal request for one key share.
    pub fn new(key: SecretString) -> Self {
        Self {
            key,
            reset: None,
            migrate: None,
        }
    }
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for OperatorUnsealRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorUnsealRequest")
            .field("key", &"<redacted>")
            .field("reset", &self.reset)
            .field("migrate", &self.migrate)
            .finish()
    }
}

/// Production rekey/rotation initialization request.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Debug, Default, Serialize)]
pub struct OperatorKeySharesRequest {
    /// Number of shares to create.
    pub secret_shares: u8,
    /// Number of shares required to reconstruct.
    pub secret_threshold: u8,
    /// Number of shares stored by a seal backend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_shares: Option<u8>,
    /// Base64-encoded PGP public keys for share encryption.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pgp_keys: Vec<String>,
    /// Whether PGP-encrypted shares should be backed up in storage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<bool>,
    /// Whether new shares must be verified before finalizing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_verification: Option<bool>,
}

#[cfg(feature = "operator-ops")]
impl OperatorKeySharesRequest {
    /// Creates a validated key-share request.
    pub fn new(secret_shares: u8, secret_threshold: u8) -> Result<Self> {
        validate_key_share_options(secret_shares, secret_threshold)?;
        Ok(Self {
            secret_shares,
            secret_threshold,
            ..Self::default()
        })
    }
}

/// Rekey/rotation progress status.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorKeySharesStatus {
    /// Whether an operation has started.
    #[serde(default)]
    pub started: bool,
    /// Operation nonce.
    #[serde(default)]
    pub nonce: Option<String>,
    /// Required threshold.
    #[serde(default)]
    pub t: Option<u64>,
    /// New share count.
    #[serde(default)]
    pub n: Option<u64>,
    /// Current progress count.
    #[serde(default)]
    pub progress: Option<u64>,
    /// Required progress count.
    #[serde(default)]
    pub required: Option<u64>,
    /// PGP fingerprints used for encrypted shares.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub pgp_fingerprints: Vec<String>,
    /// Whether backup is enabled.
    #[serde(default)]
    pub backup: bool,
    /// Whether verification is required.
    #[serde(default)]
    pub verification_required: bool,
}

/// Rekey/rotation update request containing one existing key share.
#[cfg(feature = "operator-ops")]
#[derive(Clone)]
pub struct OperatorKeyShareUpdateRequest {
    /// Existing key share used to authorize progress.
    pub key: SecretString,
    /// Operation nonce.
    pub nonce: String,
}

#[cfg(feature = "operator-ops")]
impl OperatorKeyShareUpdateRequest {
    /// Creates an update request.
    pub fn new(key: SecretString, nonce: impl Into<String>) -> Self {
        Self {
            key,
            nonce: nonce.into(),
        }
    }
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for OperatorKeyShareUpdateRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorKeyShareUpdateRequest")
            .field("key", &"<redacted>")
            .field("nonce", &self.nonce)
            .finish()
    }
}

/// Rekey/rotation update response.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Deserialize)]
pub struct OperatorKeyShareUpdateResponse {
    /// Whether the operation completed.
    #[serde(default)]
    pub complete: bool,
    /// Newly generated key shares. Treat as highly sensitive operator material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub keys: Vec<SecretString>,
    /// Newly generated base64 key shares. Treat as highly sensitive operator material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub keys_base64: Vec<SecretString>,
    /// Operation nonce.
    #[serde(default)]
    pub nonce: Option<String>,
    /// PGP fingerprints used for encrypted shares.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub pgp_fingerprints: Vec<String>,
    /// Whether backup is enabled.
    #[serde(default)]
    pub backup: bool,
    /// Whether verification is required.
    #[serde(default)]
    pub verification_required: bool,
    /// Verification nonce when verification is required.
    #[serde(default)]
    pub verification_nonce: Option<String>,
    /// Current progress, when the operation has not completed.
    #[serde(default)]
    pub progress: Option<u64>,
    /// Required progress, when the operation has not completed.
    #[serde(default)]
    pub required: Option<u64>,
}

#[cfg(feature = "operator-ops")]
impl fmt::Debug for OperatorKeyShareUpdateResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperatorKeyShareUpdateResponse")
            .field("complete", &self.complete)
            .field("keys_count", &self.keys.len())
            .field("keys_base64_count", &self.keys_base64.len())
            .field("nonce", &self.nonce)
            .field("pgp_fingerprints", &self.pgp_fingerprints)
            .field("backup", &self.backup)
            .field("verification_required", &self.verification_required)
            .field("verification_nonce", &self.verification_nonce)
            .field("progress", &self.progress)
            .field("required", &self.required)
            .finish()
    }
}

/// Target for authenticated OpenBao v2.4+ key-share rotation endpoints.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorRotateTarget {
    /// Rotate root key / Shamir unseal key shares.
    Root,
    /// Rotate recovery key shares.
    Recovery,
}

#[cfg(feature = "operator-ops")]
impl OperatorRotateTarget {
    fn path_segment(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Recovery => "recovery",
        }
    }
}

/// Options for [`Sys::bootstrap_dev`].
///
/// The default is intentionally the smallest useful Shamir setup: one share
/// and a threshold of one. That is suitable for disposable local development
/// only and is not a production initialization ceremony.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevBootstrapOptions {
    /// Number of Shamir unseal key shares to create.
    pub secret_shares: u8,
    /// Number of shares required to unseal the development instance.
    pub secret_threshold: u8,
}

impl DevBootstrapOptions {
    /// Creates validated development bootstrap options.
    pub fn new(secret_shares: u8, secret_threshold: u8) -> Result<Self> {
        validate_dev_bootstrap_options(secret_shares, secret_threshold)?;
        Ok(Self {
            secret_shares,
            secret_threshold,
        })
    }

    /// Returns the default single-key development configuration.
    pub const fn single_key() -> Self {
        Self {
            secret_shares: 1,
            secret_threshold: 1,
        }
    }
}

impl Default for DevBootstrapOptions {
    fn default() -> Self {
        Self::single_key()
    }
}

/// Result from [`Sys::bootstrap_dev`].
///
/// This type intentionally does not implement `Clone`. It contains a root
/// token and unseal shares for a disposable local development instance.
pub struct DevBootstrap {
    /// Authenticated root client for the freshly bootstrapped dev instance.
    pub client: Client<Authenticated>,
    /// Initial root token returned by OpenBao.
    ///
    /// This is identical to the token stored in [`Self::client`]. Both copies
    /// are zeroed on drop. Prefer using `client` for API calls and expose this
    /// field only when an operator ceremony or test fixture needs the raw root
    /// token.
    pub root_token: SecretString,
    /// Unseal key shares returned by OpenBao.
    pub unseal_keys: Vec<SecretString>,
    /// Base64-encoded unseal key shares returned by OpenBao.
    pub unseal_keys_base64: Vec<SecretString>,
    /// Final unseal response after bootstrap.
    pub unseal_status: UnsealStatus,
}

impl fmt::Debug for DevBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevBootstrap")
            .field("client", &self.client)
            .field("root_token", &"<redacted>")
            .field("unseal_key_count", &self.unseal_keys.len())
            .field("unseal_key_base64_count", &self.unseal_keys_base64.len())
            .field("unseal_status", &self.unseal_status)
            .finish()
    }
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
    #[serde(default, deserialize_with = "deserialize_optional_bounded_string_map")]
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
        crate::validation::validate_duration_string(value, true)
            .then(|| LeaseDuration::Duration(value.to_owned()))
            .ok_or_else(|| E::custom("invalid duration string"))
    }

    fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        crate::validation::validate_duration_string(&value, true)
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
#[derive(Clone, Debug, Default, Serialize)]
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

impl MountEnableRequest {
    /// Creates a secrets-engine enable request for `backend_type`.
    pub fn new(backend_type: impl Into<String>) -> Self {
        Self {
            backend_type: backend_type.into(),
            ..Self::default()
        }
    }

    /// Creates a KV v2 secrets-engine enable request.
    pub fn kv2() -> Self {
        let mut options = BTreeMap::new();
        options.insert("version".to_owned(), "2".to_owned());
        Self {
            backend_type: "kv".to_owned(),
            options,
            ..Self::default()
        }
    }

    /// Sets a human-readable backend description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the backend default lease TTL after validating duration syntax.
    pub fn with_default_lease_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        crate::validation::validate_duration_parameter(&ttl, "mount default_lease_ttl")?;
        self.config
            .get_or_insert_with(MountConfig::default)
            .default_lease_ttl = Some(LeaseDuration::Duration(ttl));
        Ok(self)
    }

    /// Sets the backend maximum lease TTL after validating duration syntax.
    pub fn with_max_lease_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        crate::validation::validate_duration_parameter(&ttl, "mount max_lease_ttl")?;
        self.config
            .get_or_insert_with(MountConfig::default)
            .max_lease_ttl = Some(LeaseDuration::Duration(ttl));
        Ok(self)
    }
}

/// Request for enabling an auth method.
#[derive(Clone, Debug, Default, Serialize)]
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

impl AuthEnableRequest {
    /// Creates an auth-method enable request for `backend_type`.
    pub fn new(backend_type: impl Into<String>) -> Self {
        Self {
            backend_type: backend_type.into(),
            ..Self::default()
        }
    }

    /// Sets a human-readable auth-method description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the auth method default lease TTL after validating duration syntax.
    pub fn with_default_lease_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        crate::validation::validate_duration_parameter(&ttl, "auth default_lease_ttl")?;
        self.config
            .get_or_insert_with(MountConfig::default)
            .default_lease_ttl = Some(LeaseDuration::Duration(ttl));
        Ok(self)
    }

    /// Sets the auth method maximum lease TTL after validating duration syntax.
    pub fn with_max_lease_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        crate::validation::validate_duration_parameter(&ttl, "auth max_lease_ttl")?;
        self.config
            .get_or_insert_with(MountConfig::default)
            .max_lease_ttl = Some(LeaseDuration::Duration(ttl));
        Ok(self)
    }
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

impl ListEntries for PolicyList {
    fn entries(&self) -> &[String] {
        &self.policies
    }
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
#[derive(Clone, Debug, Default, Serialize)]
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

impl PolicyWriteRequest {
    /// Creates a policy write request from an ACL policy document.
    pub fn new(policy: impl Into<String>) -> Self {
        Self {
            policy: policy.into(),
            ..Self::default()
        }
    }

    /// Sets the policy lifetime duration.
    #[must_use]
    pub fn with_ttl(mut self, ttl: impl Into<String>) -> Self {
        self.ttl = Some(ttl.into());
        self
    }
}

/// Capability name returned by OpenBao capability inspection endpoints.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Capability {
    /// Allows creation when a value does not already exist.
    Create,
    /// Allows reading an existing value or metadata.
    Read,
    /// Allows updating an existing value.
    Update,
    /// Allows deleting a value.
    Delete,
    /// Allows listing path children.
    List,
    /// Allows partial patch updates.
    Patch,
    /// Allows privileged system operations on paths that require sudo.
    Sudo,
    /// Denies access.
    Deny,
    /// Root-level capability returned for root tokens.
    Root,
    /// Capability name not known by this crate version.
    Unknown(String),
}

impl Capability {
    /// Parses a capability name while preserving unknown future values.
    #[must_use]
    pub fn from_name(name: impl AsRef<str>) -> Self {
        match name.as_ref() {
            "create" => Self::Create,
            "read" => Self::Read,
            "update" => Self::Update,
            "delete" => Self::Delete,
            "list" => Self::List,
            "patch" => Self::Patch,
            "sudo" => Self::Sudo,
            "deny" => Self::Deny,
            "root" => Self::Root,
            other => Self::Unknown(other.to_owned()),
        }
    }

    /// Returns the OpenBao capability name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Create => "create",
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Patch => "patch",
            Self::Sudo => "sudo",
            Self::Deny => "deny",
            Self::Root => "root",
            Self::Unknown(name) => name.as_str(),
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl From<&str> for Capability {
    fn from(value: &str) -> Self {
        Self::from_name(value)
    }
}

impl From<String> for Capability {
    fn from(value: String) -> Self {
        Self::from_name(value)
    }
}

/// Borrowed typed view over one OpenBao capability list.
#[derive(Clone, Copy, Debug)]
pub struct CapabilityView<'a> {
    capabilities: &'a [String],
}

impl<'a> CapabilityView<'a> {
    /// Returns the original capability names returned by OpenBao.
    #[must_use]
    pub fn raw(self) -> &'a [String] {
        self.capabilities
    }

    /// Iterates over typed capabilities, preserving unknown future values.
    pub fn iter(self) -> impl Iterator<Item = Capability> + 'a {
        self.capabilities.iter().map(Capability::from_name)
    }

    /// Returns true when this list contains the given capability.
    #[must_use]
    pub fn contains(self, capability: Capability) -> bool {
        self.contains_name(capability.as_str())
    }

    /// Returns true when OpenBao explicitly denied access.
    #[must_use]
    pub fn is_denied(self) -> bool {
        self.contains_name(Capability::Deny.as_str())
    }

    /// Returns true when the capability list allows create.
    #[must_use]
    pub fn can_create(self) -> bool {
        self.allows(Capability::Create)
    }

    /// Returns true when the capability list allows read.
    #[must_use]
    pub fn can_read(self) -> bool {
        self.allows(Capability::Read)
    }

    /// Returns true when the capability list allows update.
    #[must_use]
    pub fn can_update(self) -> bool {
        self.allows(Capability::Update)
    }

    /// Returns true when the capability list allows delete.
    #[must_use]
    pub fn can_delete(self) -> bool {
        self.allows(Capability::Delete)
    }

    /// Returns true when the capability list allows list.
    #[must_use]
    pub fn can_list(self) -> bool {
        self.allows(Capability::List)
    }

    /// Returns true when the capability list allows patch.
    #[must_use]
    pub fn can_patch(self) -> bool {
        self.allows(Capability::Patch)
    }

    /// Returns true when the capability list allows sudo.
    #[must_use]
    pub fn can_sudo(self) -> bool {
        self.allows(Capability::Sudo)
    }

    fn allows(self, capability: Capability) -> bool {
        !self.is_denied()
            && (self.contains_name(Capability::Root.as_str()) || self.contains(capability))
    }

    fn contains_name(self, capability: &str) -> bool {
        self.capabilities
            .iter()
            .any(|candidate| candidate == capability)
    }
}

/// Capabilities returned for queried OpenBao paths.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Capabilities {
    /// Backwards-compatible capabilities field returned for single-path queries.
    pub capabilities: Vec<String>,
    /// Capabilities keyed by queried path.
    #[serde(flatten)]
    pub by_path: BTreeMap<String, Vec<String>>,
}

impl Capabilities {
    /// Returns the single-path compatibility capability list.
    #[must_use]
    pub fn single_path(&self) -> CapabilityView<'_> {
        CapabilityView {
            capabilities: &self.capabilities,
        }
    }

    /// Returns capabilities for one queried path.
    ///
    /// Leading slashes are ignored to match the normalization used by request
    /// path validation.
    #[must_use]
    pub fn for_path(&self, path: &str) -> Option<CapabilityView<'_>> {
        let path = path.trim_start_matches('/');
        self.by_path
            .get(path)
            .map(|capabilities| CapabilityView { capabilities })
    }

    /// Iterates over path-keyed capability lists.
    pub fn paths(&self) -> impl Iterator<Item = (&str, CapabilityView<'_>)> {
        self.by_path
            .iter()
            .map(|(path, capabilities)| (path.as_str(), CapabilityView { capabilities }))
    }

    /// Returns true when the path-keyed capability list allows read.
    #[must_use]
    pub fn can_read_path(&self, path: &str) -> bool {
        self.for_path(path).is_some_and(CapabilityView::can_read)
    }

    /// Returns true when the path-keyed capability list allows update.
    #[must_use]
    pub fn can_update_path(&self, path: &str) -> bool {
        self.for_path(path).is_some_and(CapabilityView::can_update)
    }

    /// Returns true when the path-keyed capability list allows delete.
    #[must_use]
    pub fn can_delete_path(&self, path: &str) -> bool {
        self.for_path(path).is_some_and(CapabilityView::can_delete)
    }

    /// Returns true when the path-keyed capability list allows list.
    #[must_use]
    pub fn can_list_path(&self, path: &str) -> bool {
        self.for_path(path).is_some_and(CapabilityView::can_list)
    }
}

impl<'de> Deserialize<'de> for Capabilities {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(CapabilitiesVisitor)
    }
}

struct CapabilitiesVisitor;

impl<'de> Visitor<'de> for CapabilitiesVisitor {
    type Value = Capabilities;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded OpenBao capabilities object")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut capabilities = None;
        let mut by_path = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if key == "capabilities" {
                if capabilities.is_some() {
                    return Err(A::Error::custom("duplicate capabilities field"));
                }
                capabilities = Some(map.next_value::<BoundedStringList>()?.0);
                continue;
            }
            if by_path.len() >= crate::response::MAX_RESPONSE_STRINGS {
                let _ignored = map.next_value::<IgnoredAny>()?;
                return Err(A::Error::custom(
                    "OpenBao capabilities map exceeds item limit",
                ));
            }
            by_path.insert(key, map.next_value::<BoundedStringList>()?.0);
        }
        Ok(Capabilities {
            capabilities: capabilities.unwrap_or_default(),
            by_path,
        })
    }
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
#[derive(Clone, Debug, Default, Serialize)]
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

impl AuditEnableRequest {
    /// Creates an audit-device enable request for `backend_type`.
    pub fn new(backend_type: impl Into<String>) -> Self {
        Self {
            backend_type: backend_type.into(),
            ..Self::default()
        }
    }

    /// Sets a human-readable audit-device description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
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

/// OpenBao plugin catalog type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginType {
    /// Auth method plugin.
    Auth,
    /// Database plugin.
    Database,
    /// Secret engine plugin.
    Secret,
}

impl PluginType {
    fn as_path_segment(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Database => "database",
            Self::Secret => "secret",
        }
    }
}

/// Summary of all plugin catalog entries grouped by type.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PluginCatalog {
    /// Auth plugin names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub auth: Vec<String>,
    /// Database plugin names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub database: Vec<String>,
    /// Secret plugin names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub secret: Vec<String>,
    /// Detailed plugin summaries, when returned by OpenBao.
    #[serde(default, deserialize_with = "deserialize_bounded_plugin_detail_vec")]
    pub detailed: Vec<PluginDetail>,
}

/// Plugin catalog entry returned in detailed listings.
#[derive(Clone, Debug, Deserialize)]
pub struct PluginDetail {
    /// Plugin name.
    pub name: String,
    /// Plugin type.
    #[serde(rename = "type")]
    pub plugin_type: String,
    /// Plugin version.
    #[serde(default)]
    pub version: Option<String>,
    /// Whether this is built into OpenBao.
    #[serde(default)]
    pub builtin: bool,
    /// OpenBao deprecation status.
    #[serde(default)]
    pub deprecation_status: Option<String>,
}

/// Plugin names for one catalog type.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PluginList {
    /// Plugin names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for PluginList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Request for registering or updating a plugin catalog entry.
#[derive(Clone)]
pub struct PluginRegisterRequest {
    /// Semantic plugin version.
    pub version: Option<String>,
    /// 64-character hex SHA-256 digest of the plugin binary.
    pub sha256: String,
    /// Command used to execute the plugin, relative to OpenBao's plugin directory.
    pub command: String,
    /// Command arguments. Treat as secret material because operators often put credentials in args.
    pub args: Vec<SecretString>,
    /// Environment entries in `KEY=value` form. Treat as secret material.
    pub env: Vec<SecretString>,
    /// Whether the plugin is an OCI-backed declarative plugin.
    pub oci: Option<bool>,
}

impl fmt::Debug for PluginRegisterRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginRegisterRequest")
            .field("version", &self.version)
            .field("sha256", &self.sha256)
            .field("command", &self.command)
            .field("args", &format_args!("<{} redacted>", self.args.len()))
            .field("env", &format_args!("<{} redacted>", self.env.len()))
            .field("oci", &self.oci)
            .finish()
    }
}

/// Plugin catalog entry configuration.
#[derive(Clone, Deserialize)]
pub struct PluginInfo {
    /// Plugin name.
    pub name: String,
    /// Semantic plugin version.
    #[serde(default)]
    pub version: Option<String>,
    /// Whether this plugin is built into OpenBao.
    #[serde(default)]
    pub builtin: bool,
    /// Command used to execute the plugin.
    #[serde(default)]
    pub command: Option<String>,
    /// Plugin binary SHA-256 digest.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Command arguments. Treated as secret material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub args: Vec<SecretString>,
    /// Environment entries. Treated as secret material.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    pub env: Vec<SecretString>,
    /// OpenBao deprecation status.
    #[serde(default)]
    pub deprecation_status: Option<String>,
}

impl fmt::Debug for PluginInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginInfo")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("builtin", &self.builtin)
            .field("command", &self.command)
            .field("sha256", &self.sha256)
            .field("args", &format_args!("<{} redacted>", self.args.len()))
            .field("env", &format_args!("<{} redacted>", self.env.len()))
            .field("deprecation_status", &self.deprecation_status)
            .finish()
    }
}

/// Request for reloading mounted plugin backends.
#[derive(Clone, Debug, Default)]
pub struct PluginReloadRequest {
    /// Plugin name to reload across all mounts on this node or cluster.
    pub plugin: Option<String>,
    /// Mount paths to reload.
    pub mounts: Vec<String>,
    /// Reload scope, such as `global`.
    pub scope: Option<String>,
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
struct PluginRegisterPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    sha256: &'a str,
    command: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    args: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    env: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oci: Option<bool>,
}

#[derive(Serialize)]
struct PluginReloadPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mounts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
}

#[derive(Serialize)]
struct LoggerLevelPayload<'a> {
    level: &'a str,
}

#[derive(Serialize)]
struct CapabilitiesPayload<'a> {
    paths: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accessor: Option<&'a str>,
}

#[derive(Serialize)]
struct InitPayload {
    secret_shares: u8,
    secret_threshold: u8,
}

#[derive(Deserialize)]
struct InitResponse {
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    keys: Vec<SecretString>,
    #[serde(default, deserialize_with = "deserialize_bounded_secret_string_vec")]
    keys_base64: Vec<SecretString>,
    root_token: SecretString,
}

#[derive(Serialize)]
struct UnsealPayload<'a> {
    key: &'a str,
}

#[cfg(feature = "operator-ops")]
#[derive(Serialize)]
struct OperatorUnsealPayload<'a> {
    key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reset: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    migrate: Option<bool>,
}

#[cfg(feature = "operator-ops")]
#[derive(Serialize)]
struct OperatorKeyShareUpdatePayload<'a> {
    key: &'a str,
    nonce: &'a str,
}

impl<State> Client<State> {
    /// Accesses system backend helpers.
    pub fn sys(&self) -> Sys<'_, State> {
        Sys { client: self }
    }
}

impl<State> Sys<'_, State> {
    /// Reads `/sys/init` initialization status.
    pub async fn init_status(&self) -> Result<InitStatus> {
        self.client
            .request_json(Method::GET, "sys/init", Option::<&Empty>::None)
            .await
    }

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

    /// Reads `/sys/leader`.
    pub async fn leader_status(&self) -> Result<LeaderStatus> {
        self.client
            .request_json(Method::GET, "sys/leader", Option::<&Empty>::None)
            .await
    }

    /// Reads `/sys/internal/specs/openapi`.
    ///
    /// Set `generic_mount_paths` to replace concrete mount paths with a
    /// dynamic `{mountPath}` parameter when OpenBao supports it.
    pub async fn openapi_document(&self, generic_mount_paths: bool) -> Result<JsonValue> {
        self.client
            .request_json_query_accepting(
                Method::GET,
                "sys/internal/specs/openapi",
                &[("generic_mount_paths", generic_mount_paths.to_string())],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await
    }

    /// Reads JSON telemetry metrics from `/sys/metrics`.
    ///
    /// The Prometheus text format is intentionally left to a future raw-body
    /// helper. This method keeps the current JSON-only transport boundary.
    pub async fn metrics_json(&self) -> Result<JsonValue> {
        self.client
            .request_json_query_accepting(
                Method::GET,
                "sys/metrics",
                &[("format", "json".to_owned())],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await
    }

    /// Reads runtime logger levels from `/sys/loggers`.
    pub async fn logger_levels(&self) -> Result<LoggerLevels> {
        self.client
            .request_json(Method::GET, "sys/loggers", Option::<&Empty>::None)
            .await
    }

    /// Reads one runtime logger level from `/sys/loggers/:name`.
    pub async fn logger_level(&self, name: &str) -> Result<LoggerLevels> {
        self.client
            .request_json(Method::GET, &sys_logger_path(name)?, Option::<&Empty>::None)
            .await
    }
}

impl Sys<'_, Unauthenticated> {
    /// Initializes a production OpenBao instance.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    /// This can return root, unseal, or recovery material. Do not call this
    /// from normal application startup.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_init(
        &self,
        request: &OperatorInitRequest,
    ) -> Result<OperatorInitResponse> {
        if let (Some(shares), Some(threshold)) = (request.secret_shares, request.secret_threshold) {
            validate_key_share_options(shares, threshold)?;
        }
        if let (Some(shares), Some(threshold)) =
            (request.recovery_shares, request.recovery_threshold)
        {
            validate_key_share_options(shares, threshold)?;
        }
        self.client
            .request_json(Method::POST, "sys/init", Some(request))
            .await
    }

    /// Submits one production unseal key share.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_unseal(&self, request: &OperatorUnsealRequest) -> Result<UnsealStatus> {
        self.client
            .request_json(
                Method::POST,
                "sys/unseal",
                Some(&OperatorUnsealPayload {
                    key: request.key.expose_secret(),
                    reset: request.reset,
                    migrate: request.migrate,
                }),
            )
            .await
    }

    /// Initializes and unseals a fresh loopback OpenBao development instance.
    ///
    /// This helper is intentionally narrow:
    ///
    /// - it refuses non-loopback targets;
    /// - it refuses already-initialized OpenBao instances;
    /// - it uses Shamir key shares and returns root/unseal material in memory;
    /// - it is for disposable local development and automated tests only.
    ///
    /// Do not use this for production, staging, shared labs, HSM/KMS-backed
    /// auto-unseal deployments, or any environment where root-token and unseal
    /// key handling must follow an operator ceremony.
    pub async fn bootstrap_dev(&self, options: &DevBootstrapOptions) -> Result<DevBootstrap> {
        validate_dev_bootstrap_options(options.secret_shares, options.secret_threshold)?;
        require_loopback_dev_target(self.client)?;

        let init_status = self.init_status().await?;
        if init_status.initialized {
            return Err(Error::InvalidParameter(
                "dev bootstrap refuses to run against an already initialized OpenBao instance"
                    .into(),
            ));
        }

        let init_response: InitResponse = self
            .client
            .request_json(
                Method::POST,
                "sys/init",
                Some(&InitPayload {
                    secret_shares: options.secret_shares,
                    secret_threshold: options.secret_threshold,
                }),
            )
            .await?;

        if init_response.root_token.expose_secret().is_empty() {
            return Err(Error::MissingField("root_token"));
        }
        if init_response.keys.len() < usize::from(options.secret_threshold) {
            return Err(Error::MissingField("keys"));
        }

        let mut unseal_status = None;
        for key in init_response
            .keys
            .iter()
            .take(usize::from(options.secret_threshold))
        {
            let status = self.unseal_once(key).await?;
            let sealed = status.sealed;
            unseal_status = Some(status);
            if !sealed {
                break;
            }
        }

        let unseal_status = unseal_status.ok_or(Error::MissingField("unseal status"))?;
        if unseal_status.sealed {
            return Err(Error::Decode(
                "OpenBao remained sealed after submitting the configured dev threshold".into(),
            ));
        }

        let client = Client {
            config: self.client.config.clone(),
            http: self.client.http.clone(),
            sensitive_http: self.client.sensitive_http.clone(),
            token: None,
            _state: PhantomData,
        }
        .try_with_token(init_response.root_token.clone())?;

        Ok(DevBootstrap {
            client,
            root_token: init_response.root_token,
            unseal_keys: init_response.keys,
            unseal_keys_base64: init_response.keys_base64,
            unseal_status,
        })
    }

    async fn unseal_once(&self, key: &SecretString) -> Result<UnsealStatus> {
        self.client
            .request_json(
                Method::POST,
                "sys/unseal",
                Some(&UnsealPayload {
                    key: key.expose_secret(),
                }),
            )
            .await
    }
}

impl Sys<'_, Authenticated> {
    /// Seals the active OpenBao node.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_seal(&self) -> Result<Empty> {
        self.client
            .request_json(Method::PUT, "sys/seal", Option::<&Empty>::None)
            .await
    }

    /// Rotates the barrier encryption keyring.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_keyring(&self) -> Result<Empty> {
        self.client
            .request_json(Method::POST, "sys/rotate/keyring", Option::<&Empty>::None)
            .await
    }

    /// Reads legacy rekey status from `/sys/rekey/init`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_status(&self) -> Result<OperatorKeySharesStatus> {
        self.client
            .request_json(Method::GET, "sys/rekey/init", Option::<&Empty>::None)
            .await
    }

    /// Starts legacy rekey through `/sys/rekey/init`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_start(
        &self,
        request: &OperatorKeySharesRequest,
    ) -> Result<OperatorKeySharesStatus> {
        validate_key_share_options(request.secret_shares, request.secret_threshold)?;
        self.client
            .request_json(Method::POST, "sys/rekey/init", Some(request))
            .await
    }

    /// Cancels legacy rekey through `/sys/rekey/init`.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_cancel(&self) -> Result<Empty> {
        self.client
            .request_json(Method::DELETE, "sys/rekey/init", Option::<&Empty>::None)
            .await
    }

    /// Submits one key share to legacy rekey.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rekey_update(
        &self,
        request: &OperatorKeyShareUpdateRequest,
    ) -> Result<OperatorKeyShareUpdateResponse> {
        self.client
            .request_json(
                Method::POST,
                "sys/rekey/update",
                Some(&OperatorKeyShareUpdatePayload {
                    key: request.key.expose_secret(),
                    nonce: &request.nonce,
                }),
            )
            .await
    }

    /// Reads OpenBao v2.4+ key-share rotation status.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_status(
        &self,
        target: OperatorRotateTarget,
    ) -> Result<OperatorKeySharesStatus> {
        self.client
            .request_json(
                Method::GET,
                &rotate_init_path(target),
                Option::<&Empty>::None,
            )
            .await
    }

    /// Starts OpenBao v2.4+ key-share rotation.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_start(
        &self,
        target: OperatorRotateTarget,
        request: &OperatorKeySharesRequest,
    ) -> Result<OperatorKeySharesStatus> {
        validate_key_share_options(request.secret_shares, request.secret_threshold)?;
        self.client
            .request_json(Method::POST, &rotate_init_path(target), Some(request))
            .await
    }

    /// Cancels OpenBao v2.4+ key-share rotation.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_cancel(&self, target: OperatorRotateTarget) -> Result<Empty> {
        self.client
            .request_json(
                Method::DELETE,
                &rotate_init_path(target),
                Option::<&Empty>::None,
            )
            .await
    }

    /// Submits one key share to OpenBao v2.4+ key-share rotation.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn operator_rotate_update(
        &self,
        target: OperatorRotateTarget,
        request: &OperatorKeyShareUpdateRequest,
    ) -> Result<OperatorKeyShareUpdateResponse> {
        self.client
            .request_json(
                Method::POST,
                &rotate_update_path(target),
                Some(&OperatorKeyShareUpdatePayload {
                    key: request.key.expose_secret(),
                    nonce: &request.nonce,
                }),
            )
            .await
    }

    /// Lists mounted secrets engines.
    pub async fn list_mounts(&self) -> Result<BTreeMap<String, MountInfo>> {
        let envelope: ResponseEnvelope<MountInfoMap> = self
            .client
            .request_json(Method::GET, "sys/mounts", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data.0)
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

    /// Enables a KV v2 secrets engine at `mount_path`.
    pub async fn enable_kv2(&self, mount_path: &str, description: Option<&str>) -> Result<Empty> {
        let mut request = MountEnableRequest::kv2();
        if let Some(description) = description {
            request.description = Some(description.to_owned());
        }
        self.enable_mount(mount_path, &request).await
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
        let envelope: ResponseEnvelope<MountInfoMap> = self
            .client
            .request_json(Method::GET, "sys/auth", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data.0)
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
        let devices: AuditDeviceMap = self
            .client
            .request_json(Method::GET, "sys/audit", Option::<&Empty>::None)
            .await?;
        Ok(devices.0)
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

    /// Lists all plugin catalog entries grouped by plugin type.
    pub async fn list_plugins(&self) -> Result<PluginCatalog> {
        let envelope: ResponseEnvelope<PluginCatalog> = self
            .client
            .request_json(Method::GET, "sys/plugins/catalog", Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Lists plugin names for one plugin type.
    pub async fn list_plugins_by_type(&self, plugin_type: PluginType) -> Result<PluginList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<PluginList> = self
            .client
            .request_json(
                method,
                &plugin_catalog_type_path(plugin_type)?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Registers or updates a plugin catalog entry.
    ///
    /// OpenBao requires `sudo` capability for this endpoint. The SDK treats
    /// plugin args and env values as secret material because they commonly
    /// carry credentials or deployment-specific sensitive data.
    pub async fn register_plugin(
        &self,
        plugin_type: PluginType,
        name: &str,
        request: &PluginRegisterRequest,
    ) -> Result<Empty> {
        validate_sha256_hex(&request.sha256, "plugin SHA-256")?;
        let payload = PluginRegisterPayload {
            version: request.version.as_deref(),
            sha256: &request.sha256,
            command: &request.command,
            args: request
                .args
                .iter()
                .map(|value| value.expose_secret())
                .collect(),
            env: request
                .env
                .iter()
                .map(|value| value.expose_secret())
                .collect(),
            oci: request.oci,
        };
        self.client
            .request_json(
                Method::POST,
                &plugin_catalog_entry_path(plugin_type, name)?,
                Some(&payload),
            )
            .await
    }

    /// Reads one plugin catalog entry.
    pub async fn read_plugin(
        &self,
        plugin_type: PluginType,
        name: &str,
        version: Option<&str>,
    ) -> Result<PluginInfo> {
        let query = plugin_version_query(version)?;
        let envelope: ResponseEnvelope<PluginInfo> = self
            .client
            .request_json_query_accepting(
                Method::GET,
                &plugin_catalog_entry_path(plugin_type, name)?,
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Removes one plugin catalog entry.
    ///
    /// OpenBao requires `sudo` capability for this endpoint.
    pub async fn delete_plugin(
        &self,
        plugin_type: PluginType,
        name: &str,
        version: Option<&str>,
    ) -> Result<Empty> {
        let query = plugin_version_query(version)?;
        self.client
            .request_json_query_accepting(
                Method::DELETE,
                &plugin_catalog_entry_path(plugin_type, name)?,
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Reloads mounted plugin backends by plugin name or explicit mount paths.
    ///
    /// Exactly one of `plugin` or `mounts` must be supplied.
    pub async fn reload_plugin_backend(&self, request: &PluginReloadRequest) -> Result<Empty> {
        let payload = validate_plugin_reload_request(request)?;
        self.client
            .request_json(Method::POST, "sys/plugins/reload/backend", Some(&payload))
            .await
    }

    /// Sets all runtime logger levels through `/sys/loggers`.
    ///
    /// OpenBao does not persist this change across reload or restart.
    pub async fn set_logger_levels(&self, level: LoggerLevel) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                "sys/loggers",
                Some(&LoggerLevelPayload {
                    level: level.as_str(),
                }),
            )
            .await
    }

    /// Sets one runtime logger level through `/sys/loggers/:name`.
    ///
    /// OpenBao does not persist this change across reload or restart.
    pub async fn set_logger_level(&self, name: &str, level: LoggerLevel) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                &sys_logger_path(name)?,
                Some(&LoggerLevelPayload {
                    level: level.as_str(),
                }),
            )
            .await
    }

    /// Reverts all runtime logger levels to the configured level.
    pub async fn reset_logger_levels(&self) -> Result<Empty> {
        self.client
            .request_json_accepting(
                Method::DELETE,
                "sys/loggers",
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Reverts one runtime logger level to the configured level.
    pub async fn reset_logger_level(&self, name: &str) -> Result<Empty> {
        self.client
            .request_json_accepting(
                Method::DELETE,
                &sys_logger_path(name)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Lists installed OpenBao versions through `/sys/version-history`.
    pub async fn version_history(&self) -> Result<VersionHistory> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        self.client
            .request_json(method, "sys/version-history", Option::<&Empty>::None)
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

fn validate_dev_bootstrap_options(secret_shares: u8, secret_threshold: u8) -> Result<()> {
    if secret_shares == 0 {
        return Err(Error::InvalidParameter(
            "secret_shares must be greater than zero".into(),
        ));
    }
    if secret_threshold == 0 {
        return Err(Error::InvalidParameter(
            "secret_threshold must be greater than zero".into(),
        ));
    }
    if secret_threshold > secret_shares {
        return Err(Error::InvalidParameter(
            "secret_threshold must be less than or equal to secret_shares".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "operator-ops")]
fn validate_key_share_options(secret_shares: u8, secret_threshold: u8) -> Result<()> {
    if secret_shares == 0 {
        return Err(Error::InvalidParameter(
            "secret_shares must be greater than zero".into(),
        ));
    }
    if secret_threshold == 0 {
        return Err(Error::InvalidParameter(
            "secret_threshold must be greater than zero".into(),
        ));
    }
    if secret_threshold > secret_shares {
        return Err(Error::InvalidParameter(
            "secret_threshold must be less than or equal to secret_shares".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "operator-ops")]
fn rotate_init_path(target: OperatorRotateTarget) -> String {
    format!("sys/rotate/{}/init", target.path_segment())
}

#[cfg(feature = "operator-ops")]
fn rotate_update_path(target: OperatorRotateTarget) -> String {
    format!("sys/rotate/{}/update", target.path_segment())
}

fn require_loopback_dev_target<State>(client: &Client<State>) -> Result<()> {
    let url = client.base_url();
    let Some(host) = url.host_str() else {
        return Err(Error::InvalidBaseUrl(
            "dev bootstrap requires a numeric loopback OpenBao host".into(),
        ));
    };
    if !host
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
    {
        return Err(Error::InvalidBaseUrl(
            "dev bootstrap is restricted to numeric loopback OpenBao hosts".into(),
        ));
    }
    Ok(())
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

fn sys_logger_path(name: &str) -> Result<String> {
    let segments = validate_mount_path(name)?;
    if segments.len() != 1 {
        return Err(Error::InvalidPath(
            "logger name must be a single path segment".into(),
        ));
    }
    Ok(["sys/loggers", &segments[0]].join("/"))
}

fn validate_wrapping_ttl(ttl: &str) -> Result<()> {
    if crate::validation::validate_duration_string(ttl, false) {
        return Ok(());
    }
    Err(Error::InvalidHeader(
        "wrapping TTL must be a positive duration such as 30s, 5m, or 1h".into(),
    ))
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
        validated.push(validate_endpoint_path(path)?.join("/"));
    }
    if validated.is_empty() {
        return Err(Error::InvalidPath(
            "at least one capability path is required".into(),
        ));
    }
    Ok(validated)
}

fn validate_lease_id(lease_id: &SecretString) -> Result<&str> {
    const MAX_LEASE_ID_BYTES: usize = 512;

    let lease_id = lease_id.expose_secret();
    if lease_id.is_empty() {
        return Err(Error::InvalidPath("lease ID must not be empty".into()));
    }
    if lease_id.len() > MAX_LEASE_ID_BYTES {
        return Err(Error::InvalidPath(
            "lease ID exceeds maximum allowed length".into(),
        ));
    }
    if lease_id.as_bytes().iter().any(u8::is_ascii_control) {
        return Err(Error::InvalidPath(
            "lease ID must not contain control characters".into(),
        ));
    }
    Ok(lease_id)
}

fn plugin_catalog_type_path(plugin_type: PluginType) -> Result<String> {
    Ok(["sys/plugins/catalog", plugin_type.as_path_segment()].join("/"))
}

fn plugin_catalog_entry_path(plugin_type: PluginType, name: &str) -> Result<String> {
    let mut segments = vec![
        "sys/plugins/catalog".to_owned(),
        plugin_type.as_path_segment().to_owned(),
    ];
    segments.extend(validate_mount_path(name)?);
    Ok(segments.join("/"))
}

fn validate_sha256_hex(value: &str, field: &'static str) -> Result<()> {
    if value.len() != 64 {
        return Err(Error::InvalidPath(format!(
            "{field} must be a 64-character SHA-256 hex digest"
        )));
    }
    if !value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(Error::InvalidPath(format!(
            "{field} must contain only lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn plugin_version_query(version: Option<&str>) -> Result<Vec<(&'static str, String)>> {
    match version {
        Some(version) => {
            validate_query_string_value(version, "plugin version")?;
            Ok(vec![("version", version.to_owned())])
        }
        None => Ok(Vec::new()),
    }
}

fn validate_plugin_reload_request<'a>(
    request: &'a PluginReloadRequest,
) -> Result<PluginReloadPayload<'a>> {
    let has_plugin = request
        .plugin
        .as_deref()
        .is_some_and(|value| !value.is_empty());
    let has_mounts = !request.mounts.is_empty();
    match (has_plugin, has_mounts) {
        (true, false) | (false, true) => {}
        (false, false) => {
            return Err(Error::InvalidPath(
                "plugin reload requires a plugin name or mount paths".into(),
            ));
        }
        (true, true) => {
            return Err(Error::InvalidPath(
                "plugin reload accepts either plugin or mounts, not both".into(),
            ));
        }
    }

    let plugin = match request.plugin.as_deref() {
        Some(plugin) if !plugin.is_empty() => {
            let _segments = validate_mount_path(plugin)?;
            Some(plugin)
        }
        _ => None,
    };
    let mut mounts = Vec::new();
    for mount in &request.mounts {
        mounts.push(validate_mount_path(mount)?.join("/"));
    }
    if let Some(scope) = request.scope.as_deref() {
        validate_query_string_value(scope, "plugin reload scope")?;
    }

    Ok(PluginReloadPayload {
        plugin,
        mounts,
        scope: request.scope.as_deref(),
    })
}

fn validate_query_string_value(value: &str, kind: &'static str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidPath(format!("{kind} must not be empty")));
    }
    if value.as_bytes().iter().any(u8::is_ascii_control) {
        return Err(Error::InvalidPath(format!(
            "{kind} must not contain control characters"
        )));
    }
    Ok(())
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> core::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_bounded_plugin_detail_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<PluginDetail>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(
        BoundedPluginDetailListVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>,
    )
}

#[derive(Deserialize)]
struct BoundedStringList(#[serde(deserialize_with = "deserialize_bounded_string_vec")] Vec<String>);

#[derive(Deserialize)]
struct MountInfoMap(
    #[serde(deserialize_with = "deserialize_bounded_mount_info_map")] BTreeMap<String, MountInfo>,
);

#[derive(Deserialize)]
struct AuditDeviceMap(
    #[serde(deserialize_with = "deserialize_bounded_audit_device_map")]
    BTreeMap<String, AuditDevice>,
);

fn deserialize_bounded_logger_level_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_string_map(deserializer)
}

fn deserialize_bounded_version_history_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, VersionHistoryEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(
        BoundedVersionHistoryMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>,
    )
}

fn deserialize_bounded_mount_info_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, MountInfo>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer
        .deserialize_map(BoundedMountInfoMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

struct BoundedMountInfoMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedMountInfoMapVisitor<MAX> {
    type Value = BTreeMap<String, MountInfo>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} mount entries")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, MountInfo>()? else {
                return Ok(values);
            };
            values.insert(key, value);
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("OpenBao mount map exceeds item limit"));
        }
        Ok(values)
    }
}

fn deserialize_bounded_audit_device_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, AuditDevice>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer
        .deserialize_map(BoundedAuditDeviceMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

struct BoundedAuditDeviceMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedAuditDeviceMapVisitor<MAX> {
    type Value = BTreeMap<String, AuditDevice>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} audit devices")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, AuditDevice>()? else {
                return Ok(values);
            };
            values.insert(key, value);
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "OpenBao audit device map exceeds item limit",
            ));
        }
        Ok(values)
    }
}

struct BoundedVersionHistoryMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedVersionHistoryMapVisitor<MAX> {
    type Value = BTreeMap<String, VersionHistoryEntry>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} version history entries")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, VersionHistoryEntry>()? else {
                return Ok(values);
            };
            values.insert(key, value);
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "OpenBao version history map exceeds item limit",
            ));
        }
        Ok(values)
    }
}

struct BoundedPluginDetailListVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedPluginDetailListVisitor<MAX> {
    type Value = Vec<PluginDetail>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a list of at most {MAX} plugin details")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while values.len() < MAX {
            let Some(value) = seq.next_element::<PluginDetail>()? else {
                return Ok(values);
            };
            values.push(value);
        }
        if seq.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "OpenBao plugin detail list exceeds item limit",
            ));
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::SecretString;

    use super::{
        AuditEnableRequest, AuthEnableRequest, Capabilities, Capability, LeaseDuration,
        LoggerLevel, MountEnableRequest, PolicyList, PolicyWriteRequest, VersionHistory, sys_path,
        validate_capability_paths, validate_dev_bootstrap_options, validate_lease_id,
        validate_sha256_hex, validate_wrapping_ttl,
    };
    #[cfg(feature = "operator-ops")]
    use super::{OperatorInitResponse, OperatorKeyShareUpdateResponse, OperatorKeySharesRequest};

    #[test]
    fn sys_paths_are_validated() {
        assert_eq!(
            sys_path("sys/mounts", "secret", Some("tune"))
                .unwrap_or_else(|error| panic!("{error}")),
            "sys/mounts/secret/tune"
        );
        assert!(sys_path("sys/mounts", "../secret", None).is_err());
        assert_eq!(
            super::sys_logger_path("core").unwrap_or_else(|error| panic!("{error}")),
            "sys/loggers/core"
        );
        assert!(super::sys_logger_path("core/nested").is_err());
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
    fn capability_views_cover_common_access_checks() {
        let capabilities = serde_json::from_value::<Capabilities>(serde_json::json!({
            "capabilities": ["root"],
            "secret/data/app": ["read", "list", "future-capability"],
            "secret/data/blocked": ["deny"]
        }))
        .unwrap_or_else(|error| panic!("{error}"));

        assert!(capabilities.single_path().can_delete());
        assert!(capabilities.can_read_path("/secret/data/app"));
        assert!(capabilities.can_list_path("secret/data/app"));
        assert!(!capabilities.can_delete_path("secret/data/app"));
        assert!(!capabilities.can_read_path("secret/data/blocked"));
        assert!(
            capabilities
                .for_path("secret/data/app")
                .unwrap_or_else(|| panic!("missing capability view"))
                .contains(Capability::Unknown("future-capability".to_owned()))
        );
        let paths = capabilities
            .paths()
            .map(|(path, view)| (path.to_owned(), view.raw().len()))
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            [
                ("secret/data/app".to_owned(), 3),
                ("secret/data/blocked".to_owned(), 1)
            ]
        );
    }

    #[test]
    fn wrapping_ttl_is_validated() {
        assert!(validate_wrapping_ttl("30s").is_ok());
        assert!(validate_wrapping_ttl("5m").is_ok());
        assert!(validate_wrapping_ttl("1h").is_ok());
        assert!(validate_wrapping_ttl("1h30m").is_ok());
        assert!(validate_wrapping_ttl("").is_err());
        assert!(validate_wrapping_ttl("0s").is_err());
        assert!(validate_wrapping_ttl("1h1h").is_err());
        assert!(validate_wrapping_ttl("1m1h").is_err());
        assert!(validate_wrapping_ttl("999999999999h").is_err());
        assert!(validate_wrapping_ttl("-1h").is_err());
        assert!(validate_wrapping_ttl("forever").is_err());
    }

    #[test]
    fn dev_bootstrap_options_are_validated() {
        assert!(validate_dev_bootstrap_options(1, 1).is_ok());
        assert!(validate_dev_bootstrap_options(3, 2).is_ok());
        assert!(validate_dev_bootstrap_options(0, 0).is_err());
        assert!(validate_dev_bootstrap_options(1, 0).is_err());
        assert!(validate_dev_bootstrap_options(1, 2).is_err());
    }

    #[cfg(feature = "operator-ops")]
    #[test]
    fn operator_key_share_options_are_validated() {
        assert!(OperatorKeySharesRequest::new(1, 1).is_ok());
        assert!(OperatorKeySharesRequest::new(0, 1).is_err());
        assert!(OperatorKeySharesRequest::new(1, 0).is_err());
        assert!(OperatorKeySharesRequest::new(1, 2).is_err());
    }

    #[cfg(feature = "operator-ops")]
    #[test]
    fn operator_secret_debug_is_redacted() {
        let init = OperatorInitResponse {
            keys: vec![SecretString::from(["unseal-", "share"].concat())],
            keys_base64: vec![SecretString::from(["base64-", "share"].concat())],
            root_token: SecretString::from(["root-", "token"].concat()),
            recovery_keys: vec![SecretString::from(["recovery-", "share"].concat())],
            recovery_keys_base64: Vec::new(),
        };
        let init_debug = format!("{init:?}");
        assert!(!init_debug.contains(&["root-", "token"].concat()));
        assert!(!init_debug.contains(&["unseal-", "share"].concat()));
        assert!(init_debug.contains("keys_count"));

        let update = OperatorKeyShareUpdateResponse {
            complete: true,
            keys: vec![SecretString::from(["new-", "share"].concat())],
            keys_base64: Vec::new(),
            nonce: Some("nonce".to_owned()),
            pgp_fingerprints: Vec::new(),
            backup: false,
            verification_required: false,
            verification_nonce: None,
            progress: None,
            required: None,
        };
        let update_debug = format!("{update:?}");
        assert!(!update_debug.contains(&["new-", "share"].concat()));
        assert!(update_debug.contains("keys_count"));
    }

    #[test]
    fn lease_ids_are_validated_for_json_body_use() {
        assert!(validate_lease_id(&SecretString::from("database/creds/ro/abc")).is_ok());
        assert!(validate_lease_id(&SecretString::from("")).is_err());
        assert!(validate_lease_id(&SecretString::from("database/creds/ro\nabc")).is_err());
        assert!(validate_lease_id(&SecretString::from("x".repeat(513))).is_err());
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
    fn logger_level_values_are_stable() {
        assert_eq!(LoggerLevel::Trace.as_str(), "trace");
        assert_eq!(LoggerLevel::Debug.as_str(), "debug");
        assert_eq!(LoggerLevel::Info.as_str(), "info");
        assert_eq!(LoggerLevel::Warn.as_str(), "warn");
        assert_eq!(LoggerLevel::Error.as_str(), "error");
    }

    #[test]
    fn logger_and_version_history_maps_are_bounded() {
        let mut loggers = serde_json::Map::new();
        let mut key_info = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            loggers.insert(format!("logger-{index}"), serde_json::json!("info"));
            key_info.insert(
                format!("2.5.{index}"),
                serde_json::json!({
                    "build_date": null,
                    "previous_version": null,
                    "timestamp_installed": "2026-05-27T00:00:00Z"
                }),
            );
        }

        let error =
            match serde_json::from_value::<super::LoggerLevels>(serde_json::Value::Object(loggers))
            {
                Ok(_) => panic!("oversized logger map unexpectedly decoded"),
                Err(error) => error,
            };
        assert!(error.to_string().contains("exceeds item limit"));

        let error = match serde_json::from_value::<VersionHistory>(serde_json::json!({
            "keys": ["2.5.4"],
            "key_info": key_info
        })) {
            Ok(_) => panic!("oversized version history map unexpectedly decoded"),
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

    #[test]
    fn capabilities_path_map_is_bounded() {
        let mut value = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            value.insert(format!("secret/data/{index}"), serde_json::json!(["read"]));
        }
        let error =
            match serde_json::from_value::<super::Capabilities>(serde_json::Value::Object(value)) {
                Ok(_) => panic!("oversized capabilities map unexpectedly decoded"),
                Err(error) => error,
            };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn mount_and_audit_maps_are_bounded() {
        let mut mounts = serde_json::Map::new();
        let mut audits = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            mounts.insert(
                format!("secret-{index}/"),
                serde_json::json!({ "type": "kv", "config": {} }),
            );
            audits.insert(
                format!("file-{index}/"),
                serde_json::json!({ "type": "file", "options": {} }),
            );
        }

        let error = match serde_json::from_value::<super::MountInfoMap>(serde_json::Value::Object(
            mounts,
        )) {
            Ok(_) => panic!("oversized mount map unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));

        let error = match serde_json::from_value::<super::AuditDeviceMap>(
            serde_json::Value::Object(audits),
        ) {
            Ok(_) => panic!("oversized audit device map unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn plugin_sha256_is_validated() {
        assert!(
            validate_sha256_hex(
                "d130b9a0fbfddef9709d8ff92e5e6053ccd246b78632fc03b8548457026961e9",
                "sha256"
            )
            .is_ok()
        );
        assert!(validate_sha256_hex("", "sha256").is_err());
        assert!(validate_sha256_hex("not-a-sha256", "sha256").is_err());
        assert!(
            validate_sha256_hex(
                "g130b9a0fbfddef9709d8ff92e5e6053ccd246b78632fc03b8548457026961e9",
                "sha256"
            )
            .is_err()
        );
        assert!(
            validate_sha256_hex(
                "D130B9A0FBFDDEF9709D8FF92E5E6053CCD246B78632FC03B8548457026961E9",
                "sha256"
            )
            .is_err()
        );
    }

    #[test]
    fn request_constructors_fill_required_fields() {
        assert_eq!(MountEnableRequest::new("pki").backend_type, "pki");
        assert_eq!(MountEnableRequest::kv2().backend_type, "kv");
        assert_eq!(
            MountEnableRequest::kv2()
                .options
                .get("version")
                .map(String::as_str),
            Some("2")
        );
        let mount = MountEnableRequest::kv2()
            .with_default_lease_ttl("1h")
            .and_then(|request| request.with_max_lease_ttl("24h"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            mount.config.as_ref().and_then(|config| config.default_lease_ttl.as_ref()),
            Some(LeaseDuration::Duration(ttl)) if ttl == "1h"
        ));
        assert!(
            MountEnableRequest::kv2()
                .with_default_lease_ttl("never")
                .is_err()
        );
        assert_eq!(
            AuthEnableRequest::new("kubernetes")
                .with_description("cluster auth")
                .description
                .as_deref(),
            Some("cluster auth")
        );
        let auth = AuthEnableRequest::new("approle")
            .with_default_lease_ttl("30m")
            .and_then(|request| request.with_max_lease_ttl("2h"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(
            auth.config.as_ref().and_then(|config| config.max_lease_ttl.as_ref()),
            Some(LeaseDuration::Duration(ttl)) if ttl == "2h"
        ));
        assert_eq!(
            AuditEnableRequest::new("file")
                .with_description("audit log")
                .description
                .as_deref(),
            Some("audit log")
        );
        assert_eq!(
            PolicyWriteRequest::new("path \"secret/*\" { capabilities = [\"read\"] }").ttl,
            None
        );
    }

    #[test]
    fn plugin_detail_list_is_bounded() {
        let mut detailed = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            detailed.push(serde_json::json!({
                "name": format!("plugin-{index}"),
                "type": "secret",
            }));
        }
        let value = serde_json::json!({ "detailed": detailed });
        let error = match serde_json::from_value::<super::PluginCatalog>(value) {
            Ok(_) => panic!("oversized plugin detail list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn plugin_reload_request_is_validated() {
        assert!(
            super::validate_plugin_reload_request(&super::PluginReloadRequest {
                plugin: Some("database-plugin".to_owned()),
                mounts: Vec::new(),
                scope: Some("global".to_owned()),
            })
            .is_ok()
        );
        assert!(
            super::validate_plugin_reload_request(&super::PluginReloadRequest {
                plugin: None,
                mounts: vec!["secret".to_owned()],
                scope: None,
            })
            .is_ok()
        );
        assert!(
            super::validate_plugin_reload_request(&super::PluginReloadRequest {
                plugin: None,
                mounts: Vec::new(),
                scope: None,
            })
            .is_err()
        );
        assert!(
            super::validate_plugin_reload_request(&super::PluginReloadRequest {
                plugin: Some("database-plugin".to_owned()),
                mounts: vec!["secret".to_owned()],
                scope: None,
            })
            .is_err()
        );
    }
}
