//! Database secrets engine support.

use core::fmt;
use std::collections::BTreeMap;

use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{IgnoredAny, MapAccess, Visitor},
    ser::SerializeMap,
};

use crate::{
    Authenticated, Client, Error, Result,
    path::{validate_endpoint_path, validate_mount_path},
    response::{
        Empty, ListEntries, ListPageOptions, ResponseEnvelope,
        deserialize_bounded_string_map_or_default, deserialize_bounded_string_vec,
    },
};

const DATABASE_CONNECTION_CONFIG_FIELDS: [&str; 10] = [
    "plugin_name",
    "plugin_version",
    "verify_connection",
    "allowed_roles",
    "root_rotation_statements",
    "password_policy",
    "connection_url",
    "username",
    "password",
    "disable_escaping",
];

const DATABASE_CONNECTION_EXTRA_COLLISION_ERROR: &str =
    "database connection extra field collides with a typed field";

/// Handle for a mounted Database secrets engine.
#[derive(Debug)]
pub struct Database<'a> {
    client: &'a Client<Authenticated>,
    mount: Vec<String>,
}

/// Database connection configuration request.
#[derive(Clone, Default)]
pub struct DatabaseConnectionConfig {
    /// Database plugin name, such as `postgresql-database-plugin`.
    pub plugin_name: String,
    /// Optional plugin version.
    pub plugin_version: Option<String>,
    /// Whether OpenBao should verify the connection during configuration.
    pub verify_connection: Option<bool>,
    /// Roles allowed to use this connection. Use `*` to allow any role.
    pub allowed_roles: Vec<String>,
    /// Statements used to rotate the root database user's credentials.
    pub root_rotation_statements: Vec<String>,
    /// Password policy used by generated credentials.
    pub password_policy: Option<String>,
    /// Database connection URL or plugin-specific URL field.
    ///
    /// This is secret-aware because database URLs commonly embed credentials.
    /// Prefer separate `username` and `password` fields when the plugin
    /// supports them.
    pub connection_url: Option<SecretString>,
    /// Database username used by OpenBao to manage generated users.
    pub username: Option<String>,
    /// Database password used by OpenBao to manage generated users.
    pub password: Option<SecretString>,
    /// Whether to disable username/password escaping in supported plugins.
    pub disable_escaping: Option<bool>,
    /// Additional plugin-specific string fields.
    ///
    /// Extension schemas are deployment- and plugin-specific, so the crate
    /// cannot safely determine whether an unknown value is credential
    /// material. Values therefore fail closed as [`SecretString`] and are
    /// redacted from [`Debug`](fmt::Debug). Prefer the typed fields above when
    /// the plugin supports them.
    pub extra: BTreeMap<String, SecretString>,
}

impl DatabaseConnectionConfig {
    /// Creates a database connection config request with the required plugin name.
    pub fn new(plugin_name: impl Into<String>) -> Self {
        Self {
            plugin_name: plugin_name.into(),
            ..Self::default()
        }
    }
}

impl fmt::Debug for DatabaseConnectionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConnectionConfig")
            .field("plugin_name", &self.plugin_name)
            .field("plugin_version", &self.plugin_version)
            .field("verify_connection", &self.verify_connection)
            .field("allowed_roles", &self.allowed_roles)
            .field("root_rotation_statements", &self.root_rotation_statements)
            .field("password_policy", &self.password_policy)
            .field("has_connection_url", &self.connection_url.is_some())
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("disable_escaping", &self.disable_escaping)
            .field("extra_field_count", &self.extra.len())
            .finish()
    }
}

/// Database connection configuration returned by OpenBao.
#[derive(Clone, Default, Deserialize)]
pub struct DatabaseConnectionInfo {
    /// Roles allowed to use this connection.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub allowed_roles: Vec<String>,
    /// Plugin-specific connection details returned by OpenBao.
    ///
    /// Unknown database plugins may return credential or key material in this
    /// object, so values fail closed as [`SecretString`] even when a known
    /// plugin currently returns only non-secret metadata.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_secret_string_map_or_default"
    )]
    pub connection_details: BTreeMap<String, SecretString>,
    /// Password policy used by generated credentials.
    #[serde(default)]
    pub password_policy: Option<String>,
    /// Database plugin name.
    pub plugin_name: String,
    /// Optional plugin version.
    #[serde(default)]
    pub plugin_version: Option<String>,
    /// Root credential rotation statements.
    #[serde(
        default,
        alias = "root_rotation_statements",
        deserialize_with = "deserialize_bounded_string_vec"
    )]
    pub root_credentials_rotate_statements: Vec<String>,
}

impl fmt::Debug for DatabaseConnectionInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConnectionInfo")
            .field("allowed_roles", &self.allowed_roles)
            .field("connection_detail_count", &self.connection_details.len())
            .field("password_policy", &self.password_policy)
            .field("plugin_name", &self.plugin_name)
            .field("plugin_version", &self.plugin_version)
            .field(
                "root_credentials_rotate_statement_count",
                &self.root_credentials_rotate_statements.len(),
            )
            .finish()
    }
}

/// List response for database connections or roles.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct DatabaseList {
    /// Names returned by OpenBao.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for DatabaseList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Dynamic database role request and response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DatabaseRole {
    /// Database connection name used by this role.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub db_name: String,
    /// Statements used to create and configure dynamic users.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub creation_statements: Vec<String>,
    /// Lease default TTL.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_ttl: Option<String>,
    /// Lease maximum TTL.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_ttl: Option<String>,
    /// Statements used to revoke generated users.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub revocation_statements: Vec<String>,
    /// Statements used to roll back failed user creation.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rollback_statements: Vec<String>,
    /// Statements used to renew generated users.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub renew_statements: Vec<String>,
    /// Credential type, such as `password`, `rsa_private_key`, or
    /// `client_certificate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    /// Credential-type-specific string configuration.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub credential_config: BTreeMap<String, String>,
}

impl DatabaseRole {
    /// Creates a dynamic role request with the required database connection name.
    pub fn new(db_name: impl Into<String>) -> Self {
        Self {
            db_name: db_name.into(),
            ..Self::default()
        }
    }

    /// Adds a creation statement.
    #[must_use]
    pub fn with_creation_statement(mut self, statement: impl Into<String>) -> Self {
        self.creation_statements.push(statement.into());
        self
    }
}

/// Static database role request and response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DatabaseStaticRole {
    /// Database connection name used by this static role.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub db_name: String,
    /// Existing database username managed by the static role.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub username: String,
    /// Rotation period.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub rotation_period: Option<String>,
    /// Statements used to rotate the static user's password.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rotation_statements: Vec<String>,
    /// Credential type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    /// Credential-type-specific string configuration.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub credential_config: BTreeMap<String, String>,
}

impl DatabaseStaticRole {
    /// Creates a static role request with required database and username fields.
    pub fn new(db_name: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            db_name: db_name.into(),
            username: username.into(),
            ..Self::default()
        }
    }
}

/// Dynamic database credentials with lease metadata.
#[derive(Clone)]
pub struct DatabaseCredentials {
    /// Generated database username.
    pub username: String,
    /// Generated password, when the role uses password credentials.
    pub password: Option<SecretString>,
    /// Generated private key, when the role uses key credentials.
    pub private_key: Option<SecretString>,
    /// Generated client certificate, when returned by the plugin.
    pub certificate: Option<String>,
    /// Issuing CA certificate, when returned by the plugin.
    pub issuing_ca: Option<String>,
    /// CA chain, when returned by the plugin.
    pub ca_chain: Vec<String>,
    /// Lease ID for revocation/renewal.
    pub lease_id: SecretString,
    /// Lease duration in seconds.
    pub lease_duration: u64,
    /// Whether the lease is renewable.
    pub renewable: bool,
}

impl fmt::Debug for DatabaseCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseCredentials")
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("certificate", &self.certificate)
            .field("issuing_ca", &self.issuing_ca)
            .field("ca_chain", &self.ca_chain)
            .field("lease_id", &"<redacted>")
            .field("lease_duration", &self.lease_duration)
            .field("renewable", &self.renewable)
            .finish()
    }
}

/// Static database credentials.
#[derive(Clone, Deserialize)]
pub struct DatabaseStaticCredentials {
    /// Static database username.
    pub username: String,
    /// Current static database password.
    pub password: SecretString,
    /// Last OpenBao rotation timestamp, when returned.
    #[serde(default)]
    pub last_openbao_rotation: Option<String>,
    /// Rotation period in seconds, when returned.
    #[serde(default)]
    pub rotation_period: Option<u64>,
    /// Remaining TTL in seconds, when returned.
    #[serde(default)]
    pub ttl: Option<u64>,
}

impl fmt::Debug for DatabaseStaticCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseStaticCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("last_openbao_rotation", &self.last_openbao_rotation)
            .field("rotation_period", &self.rotation_period)
            .field("ttl", &self.ttl)
            .finish()
    }
}

#[derive(Deserialize)]
struct DatabaseCredentialData {
    username: String,
    #[serde(default)]
    password: Option<SecretString>,
    #[serde(default)]
    private_key: Option<SecretString>,
    #[serde(default)]
    certificate: Option<String>,
    #[serde(default)]
    issuing_ca: Option<String>,
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    ca_chain: Vec<String>,
}

impl Client<Authenticated> {
    /// Uses the Database secrets engine mounted at `mount`.
    pub fn database(&self, mount: impl Into<String>) -> Result<Database<'_>> {
        let mount = mount.into();
        Ok(Database {
            client: self,
            mount: validate_mount_path(&mount)?,
        })
    }
}

impl Database<'_> {
    /// Creates or updates a database connection configuration.
    pub async fn configure_connection(
        &self,
        name: &str,
        config: &DatabaseConnectionConfig,
    ) -> Result<Empty> {
        self.client
            .request_json_internal(Method::POST, &self.path(&["config", name])?, Some(config))
            .await
    }

    /// Reads a database connection configuration.
    pub async fn read_connection(&self, name: &str) -> Result<DatabaseConnectionInfo> {
        let envelope: ResponseEnvelope<DatabaseConnectionInfo> = self
            .client
            .request_json_internal(
                Method::GET,
                &self.path(&["config", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists database connection names.
    pub async fn list_connections(&self) -> Result<DatabaseList> {
        self.list_at("config", None, None).await
    }

    /// Deletes a database connection configuration.
    pub async fn delete_connection(&self, name: &str) -> Result<Empty> {
        self.delete_at("config", name).await
    }

    /// Resets a database connection plugin.
    pub async fn reset_connection(&self, name: &str) -> Result<Empty> {
        self.client
            .request_json_internal(Method::POST, &self.path(&["reset", name])?, Some(&Empty {}))
            .await
    }

    /// Rotates the root credentials for a database connection.
    pub async fn rotate_root(&self, name: &str) -> Result<Empty> {
        self.client
            .request_json_internal(
                Method::POST,
                &self.path(&["rotate-root", name])?,
                Some(&Empty {}),
            )
            .await
    }

    /// Creates or updates a dynamic database role.
    pub async fn write_role(&self, name: &str, role: &DatabaseRole) -> Result<Empty> {
        self.client
            .request_json_internal(Method::POST, &self.path(&["roles", name])?, Some(role))
            .await
    }

    /// Reads a dynamic database role.
    pub async fn read_role(&self, name: &str) -> Result<DatabaseRole> {
        let envelope: ResponseEnvelope<DatabaseRole> = self
            .client
            .request_json_internal(
                Method::GET,
                &self.path(&["roles", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists dynamic database role names.
    pub async fn list_roles(&self) -> Result<DatabaseList> {
        self.list_roles_after(None, None).await
    }

    /// Lists dynamic database role names with optional pagination parameters.
    pub async fn list_roles_after(
        &self,
        after: Option<&str>,
        limit: Option<u64>,
    ) -> Result<DatabaseList> {
        self.list_at("roles", after, limit).await
    }

    /// Deletes a dynamic database role.
    pub async fn delete_role(&self, name: &str) -> Result<Empty> {
        self.delete_at("roles", name).await
    }

    /// Generates dynamic database credentials for a role.
    pub async fn credentials(&self, name: &str) -> Result<DatabaseCredentials> {
        let envelope: ResponseEnvelope<DatabaseCredentialData> = self
            .client
            .request_json_internal(
                Method::GET,
                &self.path(&["creds", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(database_credentials_from_envelope(envelope))
    }

    /// Creates or updates a static database role.
    pub async fn write_static_role(&self, name: &str, role: &DatabaseStaticRole) -> Result<Empty> {
        self.client
            .request_json_internal(
                Method::POST,
                &self.path(&["static-roles", name])?,
                Some(role),
            )
            .await
    }

    /// Reads a static database role.
    pub async fn read_static_role(&self, name: &str) -> Result<DatabaseStaticRole> {
        let envelope: ResponseEnvelope<DatabaseStaticRole> = self
            .client
            .request_json_internal(
                Method::GET,
                &self.path(&["static-roles", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists static database role names.
    pub async fn list_static_roles(&self) -> Result<DatabaseList> {
        self.list_static_roles_after(None, None).await
    }

    /// Lists static database role names with optional pagination parameters.
    pub async fn list_static_roles_after(
        &self,
        after: Option<&str>,
        limit: Option<u64>,
    ) -> Result<DatabaseList> {
        self.list_at("static-roles", after, limit).await
    }

    /// Deletes a static database role.
    pub async fn delete_static_role(&self, name: &str) -> Result<Empty> {
        self.delete_at("static-roles", name).await
    }

    /// Reads current credentials for a static database role.
    pub async fn static_credentials(&self, name: &str) -> Result<DatabaseStaticCredentials> {
        let envelope: ResponseEnvelope<DatabaseStaticCredentials> = self
            .client
            .request_json_internal(
                Method::GET,
                &self.path(&["static-creds", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Rotates credentials for a static database role.
    pub async fn rotate_static_role(&self, name: &str) -> Result<Empty> {
        self.client
            .request_json_internal(
                Method::POST,
                &self.path(&["rotate-role", name])?,
                Some(&Empty {}),
            )
            .await
    }

    async fn list_at(
        &self,
        segment: &'static str,
        after: Option<&str>,
        limit: Option<u64>,
    ) -> Result<DatabaseList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let query = ListPageOptions::from_after_limit(after, limit)?.query_pairs();
        let envelope: ResponseEnvelope<DatabaseList> = self
            .client
            .request_json_query_accepting(
                method,
                &self.path(&[segment])?,
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    async fn delete_at(&self, segment: &'static str, name: &str) -> Result<Empty> {
        self.client
            .request_json_accepting(
                Method::DELETE,
                &self.path(&[segment, name])?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    fn path(&self, tail: &[&str]) -> Result<String> {
        let mut segments = self.mount.clone();
        for segment in tail {
            segments.extend(validate_endpoint_path(segment)?);
        }
        Ok(segments.join("/"))
    }
}

fn database_credentials_from_envelope(
    envelope: ResponseEnvelope<DatabaseCredentialData>,
) -> DatabaseCredentials {
    DatabaseCredentials {
        username: envelope.data.username,
        password: envelope.data.password,
        private_key: envelope.data.private_key,
        certificate: envelope.data.certificate,
        issuing_ca: envelope.data.issuing_ca,
        ca_chain: envelope.data.ca_chain,
        lease_id: envelope.lease_id,
        lease_duration: envelope.lease_duration,
        renewable: envelope.renewable,
    }
}

impl Serialize for DatabaseConnectionConfig {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.extra.keys().any(|key| {
            DATABASE_CONNECTION_CONFIG_FIELDS
                .iter()
                .any(|field| key == field)
        }) {
            return Err(<S::Error as serde::ser::Error>::custom(
                DATABASE_CONNECTION_EXTRA_COLLISION_ERROR,
            ));
        }

        let mut count = 1 + self.extra.len();
        count += usize::from(self.plugin_version.is_some());
        count += usize::from(self.verify_connection.is_some());
        count += usize::from(!self.allowed_roles.is_empty());
        count += usize::from(!self.root_rotation_statements.is_empty());
        count += usize::from(self.password_policy.is_some());
        count += usize::from(self.connection_url.is_some());
        count += usize::from(self.username.is_some());
        count += usize::from(self.password.is_some());
        count += usize::from(self.disable_escaping.is_some());

        let mut map = serializer.serialize_map(Some(count))?;
        map.serialize_entry("plugin_name", &self.plugin_name)?;
        if let Some(plugin_version) = self.plugin_version.as_ref() {
            map.serialize_entry("plugin_version", plugin_version)?;
        }
        if let Some(verify_connection) = self.verify_connection {
            map.serialize_entry("verify_connection", &verify_connection)?;
        }
        if !self.allowed_roles.is_empty() {
            map.serialize_entry("allowed_roles", &self.allowed_roles)?;
        }
        if !self.root_rotation_statements.is_empty() {
            map.serialize_entry("root_rotation_statements", &self.root_rotation_statements)?;
        }
        if let Some(password_policy) = self.password_policy.as_ref() {
            map.serialize_entry("password_policy", password_policy)?;
        }
        if let Some(connection_url) = self.connection_url.as_ref() {
            map.serialize_entry("connection_url", connection_url.expose_secret())?;
        }
        if let Some(username) = self.username.as_ref() {
            map.serialize_entry("username", username)?;
        }
        if let Some(password) = self.password.as_ref() {
            map.serialize_entry("password", password.expose_secret())?;
        }
        if let Some(disable_escaping) = self.disable_escaping {
            map.serialize_entry("disable_escaping", &disable_escaping)?;
        }
        for (key, value) in &self.extra {
            map.serialize_entry(key, value.expose_secret())?;
        }
        map.end()
    }
}

fn deserialize_bounded_secret_string_map_or_default<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, SecretString>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(
        Option::<BoundedDatabaseConnectionDetails>::deserialize(deserializer)?
            .map(|details| details.0)
            .unwrap_or_default(),
    )
}

#[derive(Deserialize)]
struct BoundedDatabaseConnectionDetails(
    #[serde(deserialize_with = "deserialize_bounded_secret_string_map")]
    BTreeMap<String, SecretString>,
);

fn deserialize_bounded_secret_string_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, SecretString>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer
        .deserialize_map(BoundedSecretStringMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

struct BoundedSecretStringMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedSecretStringMapVisitor<MAX> {
    type Value = BTreeMap<String, SecretString>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} secret string pairs")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        let mut entry_count = 0_usize;
        while entry_count < MAX {
            let Some((key, value)) = map.next_entry::<String, String>()? else {
                return Ok(values);
            };
            entry_count += 1;
            if values.insert(key, SecretString::from(value)).is_some() {
                return Err(serde::de::Error::custom(
                    "OpenBao database connection details contain duplicate keys",
                ));
            }
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(
                "OpenBao database connection details exceed item limit",
            ));
        }
        Ok(values)
    }
}

fn deserialize_bounded_string_or_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(StringOrListVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

struct StringOrListVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for StringOrListVisitor<MAX> {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a comma-separated string or a list of at most {MAX} strings"
        )
    }

    fn visit_unit<E>(self) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Vec::new())
    }

    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.trim().is_empty() {
            return Ok(Vec::new());
        }
        let values: Vec<String> = value
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect();
        if values.len() > MAX {
            return Err(E::custom("OpenBao string list exceeds item limit"));
        }
        Ok(values)
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while values.len() < MAX {
            let Some(value) = seq.next_element::<String>()? else {
                return Ok(values);
            };
            values.push(value);
        }
        if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(
                "OpenBao string list exceeds item limit",
            ));
        }
        Ok(values)
    }
}

fn deserialize_optional_string_or_u64<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(OptionalStringOrU64Visitor)
}

struct OptionalStringOrU64Visitor;

impl<'de> Visitor<'de> for OptionalStringOrU64Visitor {
    type Value = Option<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string, integer, null, or omitted value")
    }

    fn visit_none<E>(self) -> core::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E>(self) -> core::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> core::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }

    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Some(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E> {
        Ok(Some(value))
    }

    fn visit_u64<E>(self, value: u64) -> core::result::Result<Self::Value, E> {
        Ok(Some(value.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::{ExposeSecret, SecretString};

    use super::{
        DATABASE_CONNECTION_CONFIG_FIELDS, DATABASE_CONNECTION_EXTRA_COLLISION_ERROR,
        DatabaseConnectionConfig, DatabaseConnectionInfo, DatabaseCredentials, DatabaseList,
        DatabaseRole, DatabaseStaticCredentials,
    };

    #[test]
    fn database_connection_extension_values_are_secret_and_debug_redacted() {
        let mut config = DatabaseConnectionConfig::new("custom-database-plugin");
        config.extra.insert(
            "private_key".to_owned(),
            SecretString::from("plugin-private-key"),
        );

        let debug = format!("{config:?}");
        assert!(debug.contains("extra_field_count"));
        assert!(!debug.contains("private_key"));
        assert!(!debug.contains("plugin-private-key"));

        let serialized = serde_json::to_value(&config).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(serialized["private_key"], "plugin-private-key");

        let info = serde_json::from_value::<DatabaseConnectionInfo>(serde_json::json!({
            "plugin_name": "custom-database-plugin",
            "connection_details": {
                "private_key": "returned-plugin-private-key"
            }
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        let debug = format!("{info:?}");
        assert!(debug.contains("connection_detail_count"));
        assert!(!debug.contains("private_key"));
        assert!(!debug.contains("returned-plugin-private-key"));
        assert_eq!(
            info.connection_details["private_key"].expose_secret(),
            "returned-plugin-private-key"
        );
    }

    #[test]
    fn database_connection_extension_rejects_typed_field_collisions() {
        for field in DATABASE_CONNECTION_CONFIG_FIELDS {
            let mut config = DatabaseConnectionConfig::new("custom-database-plugin");
            config
                .extra
                .insert(field.to_owned(), SecretString::from("shadowed-value"));

            let error = match serde_json::to_value(&config) {
                Ok(_) => panic!("typed database field collision unexpectedly serialized"),
                Err(error) => error,
            };
            assert_eq!(error.to_string(), DATABASE_CONNECTION_EXTRA_COLLISION_ERROR);
            assert!(!error.to_string().contains(field));
            assert!(!error.to_string().contains("shadowed-value"));
        }
    }

    #[test]
    fn database_connection_details_are_bounded_before_extra_value_parsing() {
        let mut details = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            details.insert(format!("field-{index}"), serde_json::json!("value"));
        }
        let value = serde_json::json!({
            "plugin_name": "custom-database-plugin",
            "connection_details": details,
        });

        let error = match serde_json::from_value::<DatabaseConnectionInfo>(value) {
            Ok(_) => panic!("oversized database connection details unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceed item limit"));
    }

    #[test]
    fn database_connection_details_reject_duplicate_keys() {
        let error = match serde_json::from_str::<DatabaseConnectionInfo>(
            r#"{"plugin_name":"custom-database-plugin","connection_details":{"private_key":"first","private_key":"second"}}"#,
        ) {
            Ok(_) => panic!("duplicate database connection detail unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("contain duplicate keys"));
        assert!(!error.to_string().contains("private_key"));
        assert!(!error.to_string().contains("first"));
        assert!(!error.to_string().contains("second"));
    }

    #[test]
    fn database_credentials_debug_redacts_password_and_lease() {
        let credentials = DatabaseCredentials {
            username: "app".to_owned(),
            password: Some(SecretString::from("db-password")),
            private_key: Some(SecretString::from("private-key")),
            certificate: None,
            issuing_ca: None,
            ca_chain: Vec::new(),
            lease_id: SecretString::from("database/creds/app/lease"),
            lease_duration: 3600,
            renewable: true,
        };
        let debug = format!("{credentials:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("db-password"));
        assert!(!debug.contains("private-key"));
        assert!(!debug.contains("database/creds/app/lease"));
    }

    #[test]
    fn database_static_credentials_debug_redacts_password() {
        let credentials = DatabaseStaticCredentials {
            username: "static-user".to_owned(),
            password: SecretString::from("static-password"),
            last_openbao_rotation: None,
            rotation_period: Some(3600),
            ttl: Some(300),
        };
        let debug = format!("{credentials:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("static-password"));
    }

    #[test]
    fn database_list_is_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("role-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<DatabaseList>(value) {
            Ok(_) => panic!("oversized database list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn database_role_accepts_integer_ttls_and_string_statements() {
        let role: DatabaseRole = serde_json::from_str(
            r#"{"db_name":"postgres","creation_statements":"CREATE ROLE {{name}}","default_ttl":3600,"max_ttl":"24h"}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(role.creation_statements, ["CREATE ROLE {{name}}"]);
        assert_eq!(role.default_ttl.as_deref(), Some("3600"));
        assert_eq!(role.max_ttl.as_deref(), Some("24h"));
    }

    #[test]
    fn database_static_password_deserializes_secret() {
        let credentials: DatabaseStaticCredentials =
            serde_json::from_str(r#"{"username":"static","password":"secret"}"#)
                .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(credentials.password.expose_secret(), "secret");
    }
}
