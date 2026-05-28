//! KV version 2 secrets engine support.

use std::collections::BTreeMap;

use reqwest::{
    Method, StatusCode,
    header::{CONTENT_TYPE, HeaderValue},
};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, IgnoredAny, MapAccess, Visitor},
};

use crate::{
    Authenticated, Client, Result,
    path::{validate_mount_path, validate_secret_path},
    response::{
        Empty, ResponseEnvelope, deserialize_bounded_string_vec,
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
        let method = Method::from_bytes(b"LIST")
            .map_err(|error| crate::Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<Kv2List> = self
            .client
            .request_json(method, &self.metadata_path(path)?, Option::<&Empty>::None)
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
        segments.extend(validate_secret_path(path)?);
        Ok(segments.join("/"))
    }

    fn version_path(&self, operation: &str, path: &str) -> Result<String> {
        let mut segments = self.mount.clone();
        segments.extend(validate_mount_path(operation)?);
        segments.extend(validate_secret_path(path)?);
        Ok(segments.join("/"))
    }

    fn metadata_path(&self, path: &str) -> Result<String> {
        let mut segments = self.mount.clone();
        segments.push("metadata".to_owned());
        segments.extend(validate_secret_path(path)?);
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

    use secrecy::SecretString;

    use crate::{Client, OpenBaoConfig};

    use super::{Kv2KeyMetadata, Kv2List};

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
}
