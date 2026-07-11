//! Cubbyhole secrets engine support.
//!
//! Cubbyhole data is scoped to the client token used for each request. It is
//! useful for short-lived handoff data, response wrapping workflows, and
//! per-token scratch storage. Do not use it as a replacement for shared KV
//! application configuration.

use reqwest::Method;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    Authenticated, Client, Result,
    path::{validate_endpoint_path, validate_mount_path},
    response::{Empty, ListEntries, ResponseEnvelope, deserialize_bounded_string_vec},
};

/// Handle for a mounted Cubbyhole secrets engine.
#[derive(Debug)]
pub struct Cubbyhole<'a> {
    client: &'a Client<Authenticated>,
    mount: Vec<String>,
}

/// Cubbyhole list response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CubbyholeList {
    /// Child keys. Directory-like entries end with `/`.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for CubbyholeList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

impl Client<Authenticated> {
    /// Uses the default Cubbyhole engine mounted at `cubbyhole`.
    pub fn cubbyhole(&self) -> Result<Cubbyhole<'_>> {
        self.cubbyhole_at("cubbyhole")
    }

    /// Uses a Cubbyhole engine mounted at `mount`.
    pub fn cubbyhole_at(&self, mount: impl Into<String>) -> Result<Cubbyhole<'_>> {
        let mount = mount.into();
        Ok(Cubbyhole {
            client: self,
            mount: validate_mount_path(&mount)?,
        })
    }
}

impl Cubbyhole<'_> {
    /// Reads a Cubbyhole secret scoped to the authenticated token.
    pub async fn read<T>(&self, path: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let mount = self.mount.join("/");
        let envelope: ResponseEnvelope<T> = self
            .client
            .request_secret_json_internal(
                "/cubbyhole/",
                "cubbyhole",
                &mount,
                Method::GET,
                &self.path(path)?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Reads a Cubbyhole secret and maps OpenBao `404` to `None`.
    pub async fn read_optional<T>(&self, path: &str) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        match self.read(path).await {
            Ok(secret) => Ok(Some(secret)),
            Err(error) if error.is_not_found() => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Reads a Cubbyhole secret as a bounded service configuration map.
    ///
    /// Each value must be a JSON string and is loaded as
    /// [`SecretString`](crate::SecretString).
    #[cfg(feature = "kv2")]
    pub async fn read_service_config(
        &self,
        path: &str,
    ) -> Result<crate::secrets::kv2::Kv2ServiceConfig> {
        self.read(path).await
    }

    /// Writes a Cubbyhole secret scoped to the authenticated token.
    pub async fn write<T>(&self, path: &str, data: T) -> Result<Empty>
    where
        T: Serialize,
    {
        let mount = self.mount.join("/");
        self.client
            .request_secret_json_internal(
                "/cubbyhole/",
                "cubbyhole",
                &mount,
                Method::POST,
                &self.path(path)?,
                Some(&data),
            )
            .await
    }

    /// Deletes a Cubbyhole secret scoped to the authenticated token.
    pub async fn delete(&self, path: &str) -> Result<Empty> {
        let mount = self.mount.join("/");
        self.client
            .request_secret_json_internal(
                "/cubbyhole/",
                "cubbyhole",
                &mount,
                Method::DELETE,
                &self.path(path)?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Lists keys below a Cubbyhole path.
    pub async fn list(&self, path: &str) -> Result<CubbyholeList> {
        let method = Method::from_bytes(b"LIST")
            .map_err(|error| crate::Error::InvalidHeader(error.to_string()))?;
        let mount = self.mount.join("/");
        let envelope: ResponseEnvelope<CubbyholeList> = self
            .client
            .request_secret_json_internal(
                "/cubbyhole/",
                "cubbyhole",
                &mount,
                method,
                &self.path(path)?,
                Option::<&Empty>::None,
            )
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

    use secrecy::SecretString;

    use crate::{Client, OpenBaoConfig};

    use super::CubbyholeList;

    #[test]
    fn cubbyhole_paths_are_validated() {
        let config = OpenBaoConfig::new("http://127.0.0.1:8200")
            .and_then(OpenBaoConfig::allow_localhost_http)
            .unwrap_or_else(|error| panic!("{error}"));
        let client = Client::from_config(config)
            .and_then(|client| client.try_with_token(SecretString::from("token")))
            .unwrap_or_else(|error| panic!("{error}"));
        let cubbyhole = client.cubbyhole().unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            cubbyhole
                .path("handoff/config")
                .unwrap_or_else(|error| panic!("{error}")),
            "cubbyhole/handoff/config"
        );
        assert!(cubbyhole.path("../config").is_err());
        assert!(client.cubbyhole_at("../cubbyhole").is_err());
    }

    #[test]
    fn cubbyhole_list_keys_are_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("key-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<CubbyholeList>(value) {
            Ok(_) => panic!("oversized Cubbyhole key list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }
}
