//! RabbitMQ secrets engine support.
//!
//! This engine configures OpenBao to generate dynamic RabbitMQ users. The
//! connection URI may contain credentials, and generated passwords are treated
//! as secret material and redacted from debug output.

use core::fmt;

use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeMap};

use crate::{
    Authenticated, Client, Error, Result,
    path::{validate_endpoint_path, validate_mount_path},
    response::{Empty, ResponseEnvelope, deserialize_bounded_string_vec},
};

/// Handle for a mounted RabbitMQ secrets engine.
#[derive(Debug)]
pub struct RabbitMq<'a> {
    client: &'a Client<Authenticated>,
    mount: Vec<String>,
}

/// RabbitMQ connection configuration request.
#[derive(Clone)]
pub struct RabbitMqConnectionConfig {
    /// RabbitMQ management API URI.
    ///
    /// This is secret-aware because URIs may embed credentials.
    pub connection_uri: SecretString,
    /// RabbitMQ management administrator username.
    pub username: String,
    /// RabbitMQ management administrator password.
    pub password: SecretString,
    /// Whether OpenBao should verify the connection while configuring it.
    pub verify_connection: Option<bool>,
    /// Password policy used for generated dynamic credentials.
    pub password_policy: Option<String>,
    /// Username template used for generated dynamic usernames.
    pub username_template: Option<String>,
}

impl RabbitMqConnectionConfig {
    /// Creates a RabbitMQ connection configuration request.
    pub fn new(
        connection_uri: SecretString,
        username: impl Into<String>,
        password: SecretString,
    ) -> Self {
        Self {
            connection_uri,
            username: username.into(),
            password,
            verify_connection: None,
            password_policy: None,
            username_template: None,
        }
    }

    /// Sets whether OpenBao should verify the RabbitMQ connection.
    #[must_use]
    pub fn with_verify_connection(mut self, verify_connection: bool) -> Self {
        self.verify_connection = Some(verify_connection);
        self
    }

    /// Sets the generated password policy name.
    #[must_use]
    pub fn with_password_policy(mut self, password_policy: impl Into<String>) -> Self {
        self.password_policy = Some(password_policy.into());
        self
    }

    /// Sets the generated username template.
    #[must_use]
    pub fn with_username_template(mut self, username_template: impl Into<String>) -> Self {
        self.username_template = Some(username_template.into());
        self
    }
}

impl fmt::Debug for RabbitMqConnectionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RabbitMqConnectionConfig")
            .field("connection_uri", &"<redacted>")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("verify_connection", &self.verify_connection)
            .field("password_policy", &self.password_policy)
            .field("username_template", &self.username_template)
            .finish()
    }
}

/// RabbitMQ generated credential lease configuration.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct RabbitMqLeaseConfig {
    /// Default credential lease TTL in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    /// Maximum credential lease TTL in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl: Option<u64>,
}

impl RabbitMqLeaseConfig {
    /// Creates a lease config from default and maximum TTL seconds.
    pub fn new(ttl: u64, max_ttl: u64) -> Self {
        Self {
            ttl: Some(ttl),
            max_ttl: Some(max_ttl),
        }
    }
}

/// RabbitMQ role definition.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RabbitMqRole {
    /// Comma-separated RabbitMQ management tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
    /// JSON string mapping virtual hosts to configure/write/read permissions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vhosts: Option<String>,
    /// JSON string mapping virtual hosts and exchanges to topic permissions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vhost_topics: Option<String>,
}

impl RabbitMqRole {
    /// Creates an empty RabbitMQ role definition.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets RabbitMQ management tags.
    #[must_use]
    pub fn with_tags(mut self, tags: impl Into<String>) -> Self {
        self.tags = Some(tags.into());
        self
    }

    /// Sets the virtual-host permission JSON string.
    #[must_use]
    pub fn with_vhosts(mut self, vhosts: impl Into<String>) -> Self {
        self.vhosts = Some(vhosts.into());
        self
    }

    /// Sets the virtual-host topic permission JSON string.
    #[must_use]
    pub fn with_vhost_topics(mut self, vhost_topics: impl Into<String>) -> Self {
        self.vhost_topics = Some(vhost_topics.into());
        self
    }
}

/// RabbitMQ role list.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RabbitMqRoleList {
    /// Role names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

/// Generated RabbitMQ credentials.
#[derive(Clone, Deserialize)]
pub struct RabbitMqCredentials {
    /// Generated RabbitMQ username.
    pub username: String,
    /// Generated RabbitMQ password.
    pub password: SecretString,
    /// Lease ID for revocation/renewal.
    pub lease_id: SecretString,
    /// Lease duration in seconds.
    pub lease_duration: u64,
    /// Whether the lease is renewable.
    pub renewable: bool,
}

impl fmt::Debug for RabbitMqCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RabbitMqCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("lease_id", &"<redacted>")
            .field("lease_duration", &self.lease_duration)
            .field("renewable", &self.renewable)
            .finish()
    }
}

#[derive(Deserialize)]
struct RabbitMqCredentialData {
    username: String,
    password: SecretString,
}

impl Client<Authenticated> {
    /// Uses the RabbitMQ secrets engine mounted at `rabbitmq`.
    pub fn rabbitmq(&self) -> Result<RabbitMq<'_>> {
        self.rabbitmq_at("rabbitmq")
    }

    /// Uses the RabbitMQ secrets engine mounted at `mount`.
    pub fn rabbitmq_at(&self, mount: impl Into<String>) -> Result<RabbitMq<'_>> {
        let mount = mount.into();
        Ok(RabbitMq {
            client: self,
            mount: validate_mount_path(&mount)?,
        })
    }
}

impl RabbitMq<'_> {
    /// Creates or updates the RabbitMQ connection configuration.
    pub async fn configure_connection(&self, config: &RabbitMqConnectionConfig) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                &self.path(&["config", "connection"])?,
                Some(config),
            )
            .await
    }

    /// Creates or updates the RabbitMQ credential lease configuration.
    pub async fn configure_lease(&self, config: &RabbitMqLeaseConfig) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                &self.path(&["config", "lease"])?,
                Some(config),
            )
            .await
    }

    /// Creates or updates a RabbitMQ role.
    pub async fn write_role(&self, name: &str, role: &RabbitMqRole) -> Result<Empty> {
        self.client
            .request_json(Method::POST, &self.path(&["roles", name])?, Some(role))
            .await
    }

    /// Reads a RabbitMQ role.
    pub async fn read_role(&self, name: &str) -> Result<RabbitMqRole> {
        let envelope: ResponseEnvelope<RabbitMqRole> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["roles", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists RabbitMQ role names.
    pub async fn list_roles(&self) -> Result<RabbitMqRoleList> {
        self.list_roles_after(None, None).await
    }

    /// Lists RabbitMQ role names with optional pagination parameters.
    pub async fn list_roles_after(
        &self,
        after: Option<&str>,
        limit: Option<u64>,
    ) -> Result<RabbitMqRoleList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let mut query = Vec::new();
        if let Some(after) = after {
            query.push(("after", validate_mount_path(after)?.join("/")));
        }
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        let envelope: ResponseEnvelope<RabbitMqRoleList> = self
            .client
            .request_json_query_accepting(
                method,
                &self.path(&["roles"])?,
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a RabbitMQ role.
    pub async fn delete_role(&self, name: &str) -> Result<Empty> {
        self.client
            .request_json_accepting(
                Method::DELETE,
                &self.path(&["roles", name])?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Generates RabbitMQ credentials for a role.
    pub async fn credentials(&self, name: &str) -> Result<RabbitMqCredentials> {
        let envelope: ResponseEnvelope<RabbitMqCredentialData> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["creds", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(rabbitmq_credentials_from_envelope(envelope))
    }

    fn path(&self, tail: &[&str]) -> Result<String> {
        let mut segments = self.mount.clone();
        for segment in tail {
            segments.extend(validate_endpoint_path(segment)?);
        }
        Ok(segments.join("/"))
    }
}

impl Serialize for RabbitMqConnectionConfig {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut count = 3;
        count += usize::from(self.verify_connection.is_some());
        count += usize::from(self.password_policy.is_some());
        count += usize::from(self.username_template.is_some());

        let mut map = serializer.serialize_map(Some(count))?;
        map.serialize_entry("connection_uri", self.connection_uri.expose_secret())?;
        map.serialize_entry("username", &self.username)?;
        map.serialize_entry("password", self.password.expose_secret())?;
        if let Some(verify_connection) = self.verify_connection {
            map.serialize_entry("verify_connection", &verify_connection)?;
        }
        if let Some(password_policy) = self.password_policy.as_ref() {
            map.serialize_entry("password_policy", password_policy)?;
        }
        if let Some(username_template) = self.username_template.as_ref() {
            map.serialize_entry("username_template", username_template)?;
        }
        map.end()
    }
}

fn rabbitmq_credentials_from_envelope(
    envelope: ResponseEnvelope<RabbitMqCredentialData>,
) -> RabbitMqCredentials {
    RabbitMqCredentials {
        username: envelope.data.username,
        password: envelope.data.password,
        lease_id: envelope.lease_id,
        lease_duration: envelope.lease_duration,
        renewable: envelope.renewable,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(deprecated)]

    use secrecy::{ExposeSecret, SecretString};

    use crate::{Client, OpenBaoConfig};

    use super::{RabbitMqConnectionConfig, RabbitMqCredentials, RabbitMqRoleList};

    #[test]
    fn rabbitmq_paths_are_validated() {
        let config = OpenBaoConfig::new("http://127.0.0.1:8200")
            .and_then(OpenBaoConfig::allow_localhost_http)
            .unwrap_or_else(|error| panic!("{error}"));
        let client = Client::from_config(config)
            .unwrap_or_else(|error| panic!("{error}"))
            .with_token(SecretString::from("token"));
        let rabbitmq = client
            .rabbitmq_at("rabbitmq")
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            rabbitmq
                .path(&["roles", "app/worker"])
                .unwrap_or_else(|error| panic!("{error}")),
            "rabbitmq/roles/app/worker"
        );
        assert!(client.rabbitmq_at("../rabbitmq").is_err());
        assert!(rabbitmq.path(&["roles", "../worker"]).is_err());
    }

    #[test]
    fn rabbitmq_role_list_is_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("role-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<RabbitMqRoleList>(value) {
            Ok(_) => panic!("oversized RabbitMQ role list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn rabbitmq_debug_redacts_secret_fields() {
        let config = RabbitMqConnectionConfig::new(
            SecretString::from("https://admin:secret@example.test:15672"),
            "admin",
            SecretString::from("admin-password"),
        );
        let config_debug = format!("{config:?}");
        assert!(config_debug.contains("RabbitMqConnectionConfig"));
        assert!(!config_debug.contains("admin-password"));
        assert!(!config_debug.contains("secret@example"));

        let credentials = RabbitMqCredentials {
            username: "generated-user".to_owned(),
            password: SecretString::from("generated-password"),
            lease_id: SecretString::from("rabbitmq/creds/app/lease"),
            lease_duration: 3600,
            renewable: true,
        };
        let credentials_debug = format!("{credentials:?}");
        assert!(credentials_debug.contains("generated-user"));
        assert!(!credentials_debug.contains(credentials.password.expose_secret()));
        assert!(!credentials_debug.contains(credentials.lease_id.expose_secret()));
    }
}
