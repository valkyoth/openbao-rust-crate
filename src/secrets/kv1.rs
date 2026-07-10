//! KV version 1 secrets engine support.

use reqwest::Method;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    Authenticated, Client, Result,
    path::{validate_endpoint_path, validate_mount_path},
    response::{Empty, ListEntries, ResponseEnvelope, deserialize_bounded_string_vec},
};

/// Handle for a mounted KV v1 secrets engine.
#[derive(Debug)]
pub struct Kv1<'a> {
    client: &'a Client<Authenticated>,
    mount: Vec<String>,
}

/// KV v1 list response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Kv1List {
    /// Child keys. Directory-like entries end with `/`.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for Kv1List {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

impl Client<Authenticated> {
    /// Uses the KV v1 engine mounted at `mount`.
    pub fn kv1(&self, mount: impl Into<String>) -> Result<Kv1<'_>> {
        let mount = mount.into();
        Ok(Kv1 {
            client: self,
            mount: validate_mount_path(&mount)?,
        })
    }
}

impl Kv1<'_> {
    /// Reads a KV v1 secret.
    pub async fn read<T>(&self, path: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let envelope: ResponseEnvelope<T> = self
            .client
            .request_json_internal(Method::GET, &self.path(path)?, Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Writes a KV v1 secret.
    pub async fn write<T>(&self, path: &str, data: T) -> Result<Empty>
    where
        T: Serialize,
    {
        self.client
            .request_json_internal(Method::POST, &self.path(path)?, Some(&data))
            .await
    }

    /// Deletes a KV v1 secret.
    pub async fn delete(&self, path: &str) -> Result<Empty> {
        self.client
            .request_json_internal(Method::DELETE, &self.path(path)?, Option::<&Empty>::None)
            .await
    }

    /// Lists keys below a KV v1 path.
    pub async fn list(&self, path: &str) -> Result<Kv1List> {
        let method = Method::from_bytes(b"LIST")
            .map_err(|error| crate::Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<Kv1List> = self
            .client
            .request_json_internal(method, &self.path(path)?, Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    fn path(&self, path: &str) -> Result<String> {
        let mut segments = self.mount.clone();
        segments.extend(validate_endpoint_path(path)?);
        Ok(segments.join("/"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(deprecated)]

    use secrecy::SecretString;

    use crate::{Client, OpenBaoConfig};

    use super::Kv1List;

    #[test]
    fn kv1_paths_are_validated() {
        let config = OpenBaoConfig::new("http://127.0.0.1:8200")
            .and_then(OpenBaoConfig::allow_localhost_http)
            .unwrap_or_else(|error| panic!("{error}"));
        let client = Client::from_config(config)
            .unwrap_or_else(|error| panic!("{error}"))
            .with_token(SecretString::from("token"));
        let kv = client
            .kv1("secret")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            kv.path("app/config")
                .unwrap_or_else(|error| panic!("{error}")),
            "secret/app/config"
        );
        assert!(kv.path("../config").is_err());
    }

    #[test]
    fn kv1_list_keys_are_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("key-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<Kv1List>(value) {
            Ok(_) => panic!("oversized KV v1 key list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }
}
