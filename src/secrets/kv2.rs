//! KV version 2 secrets engine support.

use core::fmt;
use std::collections::BTreeMap;

use reqwest::{
    Method, StatusCode,
    header::{CONTENT_TYPE, HeaderValue},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, IgnoredAny, MapAccess, Visitor},
    ser::SerializeMap,
};

use crate::{
    Authenticated, Client, Error, Result,
    path::{validate_endpoint_path, validate_mount_path},
    response::{
        Empty, ListEntries, ListPageOptions, ResponseEnvelope, deserialize_bounded_string_vec,
        deserialize_optional_bounded_string_map,
    },
};

/// Handle for a mounted KV v2 secrets engine.
#[derive(Debug)]
pub struct Kv2<'a> {
    client: &'a Client<Authenticated>,
    mount: Vec<String>,
}

/// Options for KV v2 writes.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct Kv2WriteOptions {
    /// Check-and-set version. Use `0` to require creation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas: Option<u64>,
}

/// Backend-level KV v2 configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Kv2Config {
    /// Number of versions to retain per key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_versions: Option<u64>,
    /// Whether check-and-set is required for writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cas_required: Option<bool>,
    /// Duration after which deleted versions are destroyed, such as `3h`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_version_after: Option<String>,
}

/// A KV v2 secret and its version metadata.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Kv2Secret<T> {
    /// User secret payload.
    pub data: T,
    /// KV v2 metadata.
    pub metadata: Kv2Metadata,
}

/// Service configuration loaded from KV v2 as secret string values.
#[derive(Clone, Default)]
pub struct Kv2ServiceConfig {
    /// Configuration key/value pairs.
    pub values: BTreeMap<String, SecretString>,
}

impl Kv2ServiceConfig {
    /// Returns a secret value by key.
    pub fn get(&self, key: &str) -> Option<&SecretString> {
        self.values.get(key)
    }

    /// Returns a required secret value or a descriptive error.
    pub fn required(&self, key: &str) -> Result<&SecretString> {
        self.values.get(key).ok_or_else(|| {
            Error::InvalidParameter(format!("required config key `{key}` is missing"))
        })
    }

    /// Returns true when no configuration entries were loaded.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns the number of loaded configuration entries.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Consumes the wrapper and returns the secret value map.
    pub fn into_inner(self) -> BTreeMap<String, SecretString> {
        self.values
    }
}

impl fmt::Debug for Kv2ServiceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Kv2ServiceConfig")
            .field("key_count", &self.values.len())
            .field("keys", &"<redacted>")
            .field("values", &"<redacted>")
            .finish()
    }
}

impl<'de> Deserialize<'de> for Kv2ServiceConfig {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self {
            values: deserialize_bounded_secret_map(deserializer)?,
        })
    }
}

impl Serialize for Kv2ServiceConfig {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.values.len()))?;
        for (key, value) in &self.values {
            map.serialize_entry(key, value.expose_secret())?;
        }
        map.end()
    }
}

/// KV v2 version metadata.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Kv2Metadata {
    /// Secret creation timestamp.
    pub created_time: String,
    /// Secret deletion timestamp, if deleted.
    #[serde(default)]
    pub deletion_time: String,
    /// Whether this version was destroyed.
    #[serde(default)]
    pub destroyed: bool,
    /// Secret version number.
    pub version: u64,
}

/// Full KV v2 key metadata.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Kv2KeyMetadata {
    /// Key creation timestamp.
    pub created_time: String,
    /// Key update timestamp.
    pub updated_time: String,
    /// Current version number.
    pub current_version: u64,
    /// Oldest retained version number.
    pub oldest_version: u64,
    /// Per-key max version override.
    #[serde(default)]
    pub max_versions: Option<u64>,
    /// Per-key check-and-set requirement.
    #[serde(default)]
    pub cas_required: Option<bool>,
    /// Per-key delete-version-after duration.
    #[serde(default)]
    pub delete_version_after: Option<String>,
    /// Caller-defined metadata.
    #[serde(default, deserialize_with = "deserialize_optional_bounded_string_map")]
    pub custom_metadata: Option<BTreeMap<String, String>>,
    /// Metadata for each retained version.
    #[serde(default, deserialize_with = "deserialize_bounded_version_metadata_map")]
    pub versions: BTreeMap<String, Kv2VersionMetadata>,
}

/// Metadata for one KV v2 version.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Kv2VersionMetadata {
    /// Version creation timestamp.
    pub created_time: String,
    /// Version deletion timestamp, when deleted.
    #[serde(default)]
    pub deletion_time: String,
    /// Whether this version was destroyed.
    #[serde(default)]
    pub destroyed: bool,
}

/// KV v2 write response data.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Kv2WriteResponse {
    /// Version creation timestamp.
    pub created_time: String,
    /// Version number written.
    pub version: u64,
}

/// KV v2 list response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Kv2List {
    /// Child keys. Directory-like entries end with `/`.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for Kv2List {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Options for updating KV v2 key metadata.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Kv2MetadataOptions {
    /// Number of versions to retain for this key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_versions: Option<u64>,
    /// Whether check-and-set is required for this key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas_required: Option<bool>,
    /// Duration after which deleted versions are destroyed, such as `3h`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_version_after: Option<String>,
    /// Caller-defined metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_metadata: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
struct Kv2ReadEnvelope<T> {
    data: Kv2Secret<T>,
}

#[derive(Serialize)]
struct Kv2WritePayload<T> {
    data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<Kv2WriteOptions>,
}

#[derive(Serialize)]
struct VersionsPayload<'a> {
    versions: &'a [u64],
}

impl Client<Authenticated> {
    /// Uses the KV v2 engine mounted at `mount`.
    pub fn kv2(&self, mount: impl Into<String>) -> Result<Kv2<'_>> {
        let mount = mount.into();
        Ok(Kv2 {
            client: self,
            mount: validate_mount_path(&mount)?,
        })
    }
}

impl Kv2<'_> {
    /// Reads a KV v2 secret.
    pub async fn read<T>(&self, path: &str) -> Result<Kv2Secret<T>>
    where
        T: DeserializeOwned,
    {
        let envelope: Kv2ReadEnvelope<T> = self
            .client
            .request_json(Method::GET, &self.data_path(path)?, Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Reads a KV v2 secret, returning `None` when OpenBao returns 404.
    pub async fn read_optional<T>(&self, path: &str) -> Result<Option<Kv2Secret<T>>>
    where
        T: DeserializeOwned,
    {
        match self.read(path).await {
            Ok(secret) => Ok(Some(secret)),
            Err(error) if error.is_not_found() => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Reads only the user data from a KV v2 secret.
    ///
    /// This is a convenience for service configuration structs where callers
    /// do not need KV version metadata.
    pub async fn read_data<T>(&self, path: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        Ok(self.read::<T>(path).await?.data)
    }

    /// Reads only user data from a KV v2 secret, returning `None` on 404.
    pub async fn read_data_optional<T>(&self, path: &str) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        Ok(self.read_optional(path).await?.map(|secret| secret.data))
    }

    /// Reads a specific KV v2 secret version.
    pub async fn read_version<T>(&self, path: &str, version: u64) -> Result<Kv2Secret<T>>
    where
        T: DeserializeOwned,
    {
        let version = version.to_string();
        let envelope: Kv2ReadEnvelope<T> = self
            .client
            .request_json_query_accepting(
                Method::GET,
                &self.data_path(path)?,
                &[("version", version)],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Reads only the user data from a specific KV v2 secret version.
    pub async fn read_data_version<T>(&self, path: &str, version: u64) -> Result<T>
    where
        T: DeserializeOwned,
    {
        Ok(self.read_version::<T>(path, version).await?.data)
    }

    /// Reads a KV v2 secret as a bounded service configuration map.
    ///
    /// Each value must be a JSON string and is loaded as [`SecretString`].
    /// This is intended for environment-style service config, not arbitrary
    /// nested JSON documents.
    pub async fn read_service_config(&self, path: &str) -> Result<Kv2ServiceConfig> {
        self.read_data(path).await
    }

    /// Reads a specific KV v2 secret version as a bounded service configuration map.
    pub async fn read_service_config_version(
        &self,
        path: &str,
        version: u64,
    ) -> Result<Kv2ServiceConfig> {
        self.read_data_version(path, version).await
    }

    /// Writes a bounded service configuration map to a KV v2 secret.
    pub async fn write_service_config(
        &self,
        path: &str,
        config: &Kv2ServiceConfig,
    ) -> Result<Kv2WriteResponse> {
        self.write(path, config).await
    }

    /// Writes a bounded service configuration map with optional check-and-set.
    pub async fn write_service_config_with_options(
        &self,
        path: &str,
        config: &Kv2ServiceConfig,
        options: Option<Kv2WriteOptions>,
    ) -> Result<Kv2WriteResponse> {
        self.write_with_options(path, config, options).await
    }

    /// Writes a KV v2 secret without check-and-set.
    pub async fn write<T>(&self, path: &str, data: T) -> Result<Kv2WriteResponse>
    where
        T: Serialize,
    {
        self.write_with_options(path, data, None).await
    }

    /// Writes a KV v2 secret with optional check-and-set.
    pub async fn write_with_options<T>(
        &self,
        path: &str,
        data: T,
        options: Option<Kv2WriteOptions>,
    ) -> Result<Kv2WriteResponse>
    where
        T: Serialize,
    {
        let payload = Kv2WritePayload { data, options };
        let envelope: ResponseEnvelope<Kv2WriteResponse> = self
            .client
            .request_json(Method::POST, &self.data_path(path)?, Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Patches a KV v2 secret without replacing unspecified fields.
    pub async fn patch<T>(&self, path: &str, data: T) -> Result<Kv2WriteResponse>
    where
        T: Serialize,
    {
        self.patch_with_options(path, data, None).await
    }

    /// Patches a KV v2 secret with optional check-and-set.
    pub async fn patch_with_options<T>(
        &self,
        path: &str,
        data: T,
        options: Option<Kv2WriteOptions>,
    ) -> Result<Kv2WriteResponse>
    where
        T: Serialize,
    {
        let payload = Kv2WritePayload { data, options };
        let envelope: ResponseEnvelope<Kv2WriteResponse> = self
            .client
            .request_json_headers_accepting(
                Method::PATCH,
                &self.data_path(path)?,
                &[(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/merge-patch+json"),
                )],
                Some(&payload),
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes the latest version of a KV v2 secret.
    pub async fn delete_latest(&self, path: &str) -> Result<Empty> {
        self.client
            .request_json(
                Method::DELETE,
                &self.data_path(path)?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Soft-deletes specific KV v2 versions.
    pub async fn delete_versions(&self, path: &str, versions: &[u64]) -> Result<Empty> {
        let payload = VersionsPayload { versions };
        self.client
            .request_json(
                Method::POST,
                &self.version_path("delete", path)?,
                Some(&payload),
            )
            .await
    }

    /// Restores soft-deleted KV v2 versions.
    pub async fn undelete_versions(&self, path: &str, versions: &[u64]) -> Result<Empty> {
        let payload = VersionsPayload { versions };
        self.client
            .request_json(
                Method::POST,
                &self.version_path("undelete", path)?,
                Some(&payload),
            )
            .await
    }

    /// Permanently destroys KV v2 versions.
    pub async fn destroy_versions(&self, path: &str, versions: &[u64]) -> Result<Empty> {
        let payload = VersionsPayload { versions };
        self.client
            .request_json(
                Method::POST,
                &self.version_path("destroy", path)?,
                Some(&payload),
            )
            .await
    }

    /// Lists keys below a KV v2 metadata path.
    pub async fn list(&self, path: &str) -> Result<Kv2List> {
        self.list_after(path, None, None).await
    }

    /// Lists keys below a KV v2 metadata path with optional pagination.
    pub async fn list_after(
        &self,
        path: &str,
        after: Option<&str>,
        limit: Option<u64>,
    ) -> Result<Kv2List> {
        let method = Method::from_bytes(b"LIST")
            .map_err(|error| crate::Error::InvalidHeader(error.to_string()))?;
        let query = ListPageOptions::from_after_limit(after, limit)?.query_pairs();
        let envelope: ResponseEnvelope<Kv2List> = self
            .client
            .request_json_query_accepting(
                method,
                &self.metadata_path(path)?,
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Reads backend-level KV v2 configuration.
    pub async fn config(&self) -> Result<Kv2Config> {
        let envelope: ResponseEnvelope<Kv2Config> = self
            .client
            .request_json(
                Method::GET,
                &self.mount_path("config")?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Updates backend-level KV v2 configuration.
    pub async fn configure(&self, config: &Kv2Config) -> Result<Empty> {
        self.client
            .request_json(Method::POST, &self.mount_path("config")?, Some(config))
            .await
    }

    /// Reads KV v2 metadata for a key.
    pub async fn metadata(&self, path: &str) -> Result<Kv2KeyMetadata> {
        let envelope: ResponseEnvelope<Kv2KeyMetadata> = self
            .client
            .request_json(
                Method::GET,
                &self.metadata_path(path)?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Replaces KV v2 metadata for a key.
    pub async fn put_metadata(&self, path: &str, metadata: &Kv2MetadataOptions) -> Result<Empty> {
        self.client
            .request_json(Method::POST, &self.metadata_path(path)?, Some(metadata))
            .await
    }

    /// Patches KV v2 metadata for a key.
    pub async fn patch_metadata(&self, path: &str, metadata: &Kv2MetadataOptions) -> Result<Empty> {
        self.client
            .request_json_headers_accepting(
                Method::PATCH,
                &self.metadata_path(path)?,
                &[(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/merge-patch+json"),
                )],
                Some(metadata),
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Permanently deletes all KV v2 metadata and versions for a key.
    pub async fn delete_metadata(&self, path: &str) -> Result<Empty> {
        self.client
            .request_json(
                Method::DELETE,
                &self.metadata_path(path)?,
                Option::<&Empty>::None,
            )
            .await
    }

    fn data_path(&self, path: &str) -> Result<String> {
        let mut segments = self.mount.clone();
        segments.push("data".to_owned());
        segments.extend(validate_endpoint_path(path)?);
        Ok(segments.join("/"))
    }

    fn version_path(&self, operation: &str, path: &str) -> Result<String> {
        let mut segments = self.mount.clone();
        segments.extend(validate_mount_path(operation)?);
        segments.extend(validate_endpoint_path(path)?);
        Ok(segments.join("/"))
    }

    fn metadata_path(&self, path: &str) -> Result<String> {
        let mut segments = self.mount.clone();
        segments.push("metadata".to_owned());
        segments.extend(validate_endpoint_path(path)?);
        Ok(segments.join("/"))
    }

    fn mount_path(&self, child: &str) -> Result<String> {
        let mut segments = self.mount.clone();
        segments.extend(validate_mount_path(child)?);
        Ok(segments.join("/"))
    }
}

fn deserialize_bounded_version_metadata_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, Kv2VersionMetadata>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(
        BoundedVersionMetadataMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>,
    )
}

fn deserialize_bounded_secret_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, SecretString>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer
        .deserialize_map(BoundedSecretMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

struct BoundedSecretMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedSecretMapVisitor<MAX> {
    type Value = BTreeMap<String, SecretString>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a map of at most {MAX} string service config values"
        )
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, String>()? else {
                return Ok(values);
            };
            values.insert(key, SecretString::from(value));
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(
                "OpenBao service config map exceeds item limit",
            ));
        }
        Ok(values)
    }
}

struct BoundedVersionMetadataMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedVersionMetadataMapVisitor<MAX> {
    type Value = BTreeMap<String, Kv2VersionMetadata>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "a map of at most {MAX} KV v2 versions")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, Kv2VersionMetadata>()? else {
                return Ok(values);
            };
            values.insert(key, value);
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(
                "OpenBao KV v2 version map exceeds item limit",
            ));
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(deprecated)]

    use secrecy::{ExposeSecret, SecretString};

    use crate::{Client, OpenBaoConfig};

    use super::{Kv2KeyMetadata, Kv2List, Kv2ServiceConfig};

    #[test]
    fn kv2_paths_are_validated() {
        let config = OpenBaoConfig::new("http://127.0.0.1:8200")
            .and_then(OpenBaoConfig::allow_localhost_http)
            .unwrap_or_else(|error| panic!("{error}"));
        let client = Client::from_config(config)
            .unwrap_or_else(|error| panic!("{error}"))
            .with_token(SecretString::from("token"));
        let kv = client
            .kv2("secret")
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(kv.data_path("app/config").is_ok());
        assert!(kv.data_path("../config").is_err());
        assert_eq!(
            kv.version_path("destroy", "app/config")
                .unwrap_or_else(|error| panic!("{error}")),
            "secret/destroy/app/config"
        );
    }

    #[test]
    fn kv2_validates_mount_at_construction() {
        let config = OpenBaoConfig::new("http://127.0.0.1:8200")
            .and_then(OpenBaoConfig::allow_localhost_http)
            .unwrap_or_else(|error| panic!("{error}"));
        let client = Client::from_config(config)
            .unwrap_or_else(|error| panic!("{error}"))
            .with_token(SecretString::from("token"));
        assert!(client.kv2("../secret").is_err());
    }

    #[test]
    fn kv2_list_keys_are_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("key-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<Kv2List>(value) {
            Ok(_) => panic!("oversized KV v2 key list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn kv2_metadata_maps_are_bounded() {
        let mut custom_metadata = serde_json::Map::new();
        let mut versions = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            custom_metadata.insert(format!("key-{index}"), serde_json::json!("value"));
            versions.insert(
                index.to_string(),
                serde_json::json!({
                    "created_time": "2026-05-28T00:00:00Z",
                    "deletion_time": "",
                    "destroyed": false
                }),
            );
        }
        let base = serde_json::json!({
            "created_time": "2026-05-28T00:00:00Z",
            "updated_time": "2026-05-28T00:00:00Z",
            "current_version": 1,
            "oldest_version": 1,
        });

        let mut value = base.clone();
        value["custom_metadata"] = serde_json::Value::Object(custom_metadata);
        let error = match serde_json::from_value::<Kv2KeyMetadata>(value) {
            Ok(_) => panic!("oversized KV v2 custom metadata unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));

        let mut value = base;
        value["versions"] = serde_json::Value::Object(versions);
        let error = match serde_json::from_value::<Kv2KeyMetadata>(value) {
            Ok(_) => panic!("oversized KV v2 versions unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn kv2_service_config_values_are_secret_and_redacted() {
        let config: Kv2ServiceConfig =
            serde_json::from_str(r#"{"DATABASE_URL":"postgres://secret","API_KEY":"key-value"}"#)
                .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(config.len(), 2);
        assert_eq!(
            config.get("API_KEY").map(SecretString::expose_secret),
            Some("key-value")
        );
        assert_eq!(
            config
                .required("API_KEY")
                .map(SecretString::expose_secret)
                .unwrap_or_else(|error| panic!("{error}")),
            "key-value"
        );
        assert!(config.required("MISSING").is_err());
        let debug = format!("{config:?}");
        assert!(debug.contains("key_count"));
        assert!(!debug.contains("API_KEY"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("key-value"));
    }

    #[test]
    fn kv2_service_config_map_is_bounded() {
        let mut values = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            values.insert(format!("KEY_{index}"), serde_json::json!("value"));
        }
        let value = serde_json::Value::Object(values);
        let error = match serde_json::from_value::<Kv2ServiceConfig>(value) {
            Ok(_) => panic!("oversized KV v2 service config unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }
}
