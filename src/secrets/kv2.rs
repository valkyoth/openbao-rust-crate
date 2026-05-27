//! KV version 2 secrets engine support.

use reqwest::Method;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    Authenticated, Client, Result,
    path::{validate_mount_path, validate_secret_path},
    response::{Empty, ResponseEnvelope},
};

/// Handle for a mounted KV v2 secrets engine.
#[derive(Debug)]
pub struct Kv2<'a> {
    client: &'a Client<Authenticated>,
    mount: String,
}

/// Options for KV v2 writes.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct Kv2WriteOptions {
    /// Check-and-set version. Use `0` to require creation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas: Option<u64>,
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
    #[serde(default)]
    pub keys: Vec<String>,
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

impl Client<Authenticated> {
    /// Uses the KV v2 engine mounted at `mount`.
    pub fn kv2(&self, mount: impl Into<String>) -> Result<Kv2<'_>> {
        let mount = mount.into();
        let mount = validate_mount_path(&mount)?.join("/");
        Ok(Kv2 {
            client: self,
            mount,
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

    fn data_path(&self, path: &str) -> Result<String> {
        let mut segments = validate_mount_path(&self.mount)?;
        segments.push("data".to_owned());
        segments.extend(validate_secret_path(path)?);
        Ok(segments.join("/"))
    }

    fn metadata_path(&self, path: &str) -> Result<String> {
        let mut segments = validate_mount_path(&self.mount)?;
        segments.push("metadata".to_owned());
        segments.extend(validate_secret_path(path)?);
        Ok(segments.join("/"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::SecretString;

    use crate::{Client, OpenBaoConfig};

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
}
