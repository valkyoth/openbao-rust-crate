//! Database secrets engine support.

use core::fmt;
use std::collections::BTreeMap;

use reqwest::{Method, StatusCode, Url};
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

const DATABASE_BUILTIN_CONNECTION_FIELDS: [&str; 26] = [
    "host",
    "hosts",
    "port",
    "tls",
    "insecure_tls",
    "tls_server_name",
    "tls_skip_verify",
    "tls_ca",
    "tls_certificate_key",
    "pem_bundle",
    "pem_json",
    "skip_verification",
    "protocol_version",
    "connect_timeout",
    "local_datacenter",
    "socket_keep_alive",
    "consistency",
    "username_template",
    "max_open_connections",
    "max_idle_connections",
    "max_connection_lifetime",
    "password_authentication",
    "connection_url",
    "username",
    "password",
    "disable_escaping",
];

const DATABASE_CONNECTION_EXTRA_COLLISION_ERROR: &str =
    "database connection extra field collides with a typed field";
const REVIEWED_BUILTIN_DATABASE_PLUGINS: [&str; 8] = [
    "postgresql-database-plugin",
    "mysql-database-plugin",
    "mysql-aurora-database-plugin",
    "mysql-rds-database-plugin",
    "mysql-legacy-database-plugin",
    "cassandra-database-plugin",
    "influxdb-database-plugin",
    "valkey-database-plugin",
];

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
    /// Reviewed options for an OpenBao built-in database plugin.
    ///
    /// Use [`Self::builtin`] so the plugin name and option shape cannot drift.
    pub builtin_options: Option<DatabaseBuiltinConnectionConfig>,
}

impl DatabaseConnectionConfig {
    /// Creates a database connection request for an external or custom plugin.
    ///
    /// Reviewed built-in plugin names are rejected during validation; use
    /// [`Self::builtin`] so their security-sensitive fields remain typed.
    pub fn new(plugin_name: impl Into<String>) -> Self {
        Self {
            plugin_name: plugin_name.into(),
            ..Self::default()
        }
    }

    /// Creates a connection configuration for a reviewed built-in plugin.
    pub fn builtin(options: DatabaseBuiltinConnectionConfig) -> Self {
        Self {
            plugin_name: options.plugin_name().to_owned(),
            builtin_options: Some(options),
            ..Self::default()
        }
    }

    fn validate(&self) -> Result<()> {
        if self.plugin_name.trim().is_empty() {
            return Err(Error::InvalidParameter(
                "database plugin_name must not be empty".into(),
            ));
        }
        if self.builtin_options.is_none()
            && REVIEWED_BUILTIN_DATABASE_PLUGINS.contains(&self.plugin_name.as_str())
        {
            return Err(Error::InvalidParameter(
                "reviewed built-in database plugins require DatabaseConnectionConfig::builtin"
                    .into(),
            ));
        }
        if self.allowed_roles.len() > crate::response::MAX_RESPONSE_STRINGS
            || self.root_rotation_statements.len() > crate::response::MAX_RESPONSE_STRINGS
            || self.extra.len() > crate::response::MAX_RESPONSE_STRINGS
        {
            return Err(Error::InvalidParameter(
                "database connection configuration exceeds item limit".into(),
            ));
        }
        let required = |value: &str, field: &'static str| {
            if value.trim().is_empty() {
                Err(Error::InvalidParameter(format!(
                    "{field} must not be empty"
                )))
            } else {
                Ok(())
            }
        };
        let disables_tls_verification = match self.builtin_options.as_ref() {
            Some(DatabaseBuiltinConnectionConfig::PostgreSql(options)) => {
                !postgres_dsn_uses_hardened_tcp_tls(options.connection_url.expose_secret())
            }
            Some(DatabaseBuiltinConnectionConfig::MySql(options)) => {
                options.tls_skip_verify == Some(true)
            }
            Some(DatabaseBuiltinConnectionConfig::Cassandra(options)) => {
                options.insecure_tls == Some(true)
            }
            Some(DatabaseBuiltinConnectionConfig::InfluxDb(options)) => {
                options.insecure_tls == Some(true)
            }
            Some(DatabaseBuiltinConnectionConfig::Valkey(options)) => {
                options.insecure_tls == Some(true)
            }
            _ => false,
        };
        #[cfg(not(feature = "insecure-database-tls-acknowledged"))]
        if disables_tls_verification {
            return Err(Error::InvalidParameter(
                "database TLS verification bypass requires the insecure-database-tls-acknowledged Cargo feature".into(),
            ));
        }
        #[cfg(feature = "insecure-database-tls-acknowledged")]
        let _ = disables_tls_verification;
        match self.builtin_options.as_ref() {
            Some(DatabaseBuiltinConnectionConfig::PostgreSql(options)) => {
                required(
                    options.connection_url.expose_secret(),
                    "PostgreSQL connection_url",
                )?;
                validate_optional_database_duration(
                    options.max_connection_lifetime.as_deref(),
                    "PostgreSQL max_connection_lifetime",
                )?;
            }
            Some(DatabaseBuiltinConnectionConfig::MySql(options)) => {
                required(
                    options.connection_url.expose_secret(),
                    "MySQL connection_url",
                )?;
                validate_optional_database_duration(
                    options.max_connection_lifetime.as_deref(),
                    "MySQL max_connection_lifetime",
                )?;
            }
            Some(DatabaseBuiltinConnectionConfig::Cassandra(options)) => {
                required(&options.hosts, "Cassandra hosts")?;
                required(&options.username, "Cassandra username")?;
                required(options.password.expose_secret(), "Cassandra password")?;
                if options.port == Some(0) || options.protocol_version == Some(0) {
                    return Err(Error::InvalidParameter(
                        "Cassandra port and protocol_version must be non-zero".into(),
                    ));
                }
                if options.pem_bundle.is_some() && options.pem_json.is_some() {
                    return Err(Error::InvalidParameter(
                        "Cassandra pem_bundle and pem_json are mutually exclusive".into(),
                    ));
                }
                if options.insecure_tls == Some(true) && options.tls == Some(false) {
                    return Err(Error::InvalidParameter(
                        "Cassandra insecure_tls conflicts with tls=false".into(),
                    ));
                }
                validate_optional_database_duration(
                    options.connect_timeout.as_deref(),
                    "Cassandra connect_timeout",
                )?;
                validate_optional_database_duration(
                    options.socket_keep_alive.as_deref(),
                    "Cassandra socket_keep_alive",
                )?;
            }
            Some(DatabaseBuiltinConnectionConfig::InfluxDb(options)) => {
                required(&options.host, "InfluxDB host")?;
                required(&options.username, "InfluxDB username")?;
                required(options.password.expose_secret(), "InfluxDB password")?;
                if options.port == Some(0) {
                    return Err(Error::InvalidParameter(
                        "InfluxDB port must be non-zero".into(),
                    ));
                }
                if options.pem_bundle.is_some() && options.pem_json.is_some() {
                    return Err(Error::InvalidParameter(
                        "InfluxDB pem_bundle and pem_json are mutually exclusive".into(),
                    ));
                }
                if options.insecure_tls == Some(true) && options.tls == Some(false) {
                    return Err(Error::InvalidParameter(
                        "InfluxDB insecure_tls conflicts with tls=false".into(),
                    ));
                }
                validate_optional_database_duration(
                    options.connect_timeout.as_deref(),
                    "InfluxDB connect_timeout",
                )?;
            }
            Some(DatabaseBuiltinConnectionConfig::Valkey(options)) => {
                required(&options.host, "Valkey host")?;
                required(&options.username, "Valkey username")?;
                required(options.password.expose_secret(), "Valkey password")?;
                if options.port == 0 {
                    return Err(Error::InvalidParameter(
                        "Valkey port must be non-zero".into(),
                    ));
                }
                if options.insecure_tls == Some(true) && options.tls == Some(false) {
                    return Err(Error::InvalidParameter(
                        "Valkey insecure_tls conflicts with tls=false".into(),
                    ));
                }
            }
            None => {}
        }
        Ok(())
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
            .field(
                "builtin_plugin",
                &self
                    .builtin_options
                    .as_ref()
                    .map(|options| options.plugin_name()),
            )
            .finish()
    }
}

/// Reviewed connection options for OpenBao's built-in database plugins.
#[derive(Clone)]
#[non_exhaustive]
pub enum DatabaseBuiltinConnectionConfig {
    /// PostgreSQL built-in plugin options.
    PostgreSql(PostgreSqlConnectionOptions),
    /// MySQL, MariaDB, Aurora, RDS, or legacy MySQL built-in plugin options.
    MySql(MySqlConnectionOptions),
    /// Cassandra built-in plugin options.
    Cassandra(CassandraConnectionOptions),
    /// InfluxDB built-in plugin options.
    InfluxDb(InfluxDbConnectionOptions),
    /// Valkey built-in plugin options.
    Valkey(ValkeyConnectionOptions),
}

impl DatabaseBuiltinConnectionConfig {
    fn plugin_name(&self) -> &'static str {
        match self {
            Self::PostgreSql(_) => "postgresql-database-plugin",
            Self::MySql(options) => options.plugin.plugin_name(),
            Self::Cassandra(_) => "cassandra-database-plugin",
            Self::InfluxDb(_) => "influxdb-database-plugin",
            Self::Valkey(_) => "valkey-database-plugin",
        }
    }
}

impl fmt::Debug for DatabaseBuiltinConnectionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseBuiltinConnectionConfig")
            .field("plugin_name", &self.plugin_name())
            .finish_non_exhaustive()
    }
}

/// MySQL-family built-in plugin selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MySqlPlugin {
    /// Standard MySQL/MariaDB plugin.
    MySql,
    /// Amazon Aurora MySQL plugin.
    Aurora,
    /// Amazon RDS MySQL plugin.
    Rds,
    /// Legacy MySQL plugin.
    Legacy,
}

impl MySqlPlugin {
    fn plugin_name(self) -> &'static str {
        match self {
            Self::MySql => "mysql-database-plugin",
            Self::Aurora => "mysql-aurora-database-plugin",
            Self::Rds => "mysql-rds-database-plugin",
            Self::Legacy => "mysql-legacy-database-plugin",
        }
    }
}

/// PostgreSQL built-in plugin connection options.
#[derive(Clone, Default)]
pub struct PostgreSqlConnectionOptions {
    /// Templated PostgreSQL DSN.
    ///
    /// The DSN must explicitly select `sslmode=verify-full` and an effective
    /// TCP host. Missing, empty, duplicated, service-file-indirect, Unix-socket,
    /// unsupported URI, or weaker TLS configurations require the
    /// `insecure-database-tls-acknowledged` Cargo feature. Both URI query
    /// parameters and PostgreSQL keyword/value DSNs are checked using pgx's
    /// case-sensitive parameter spellings.
    pub connection_url: SecretString,
    /// Root username.
    pub username: Option<String>,
    /// Root password.
    pub password: Option<SecretString>,
    /// Maximum open connections.
    pub max_open_connections: Option<u32>,
    /// Maximum idle connections; negative disables idle connections.
    pub max_idle_connections: Option<i32>,
    /// Maximum connection lifetime.
    pub max_connection_lifetime: Option<String>,
    /// Dynamic username template.
    pub username_template: Option<String>,
    /// Disables username/password escaping.
    pub disable_escaping: Option<bool>,
    /// PostgreSQL password authentication mode.
    pub password_authentication: Option<String>,
}

impl PostgreSqlConnectionOptions {
    /// Creates PostgreSQL options with the required connection URL.
    pub fn new(connection_url: SecretString) -> Self {
        Self {
            connection_url,
            ..Self::default()
        }
    }
}

impl fmt::Debug for PostgreSqlConnectionOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgreSqlConnectionOptions")
            .field("connection_url", &"<redacted>")
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("max_open_connections", &self.max_open_connections)
            .field("max_idle_connections", &self.max_idle_connections)
            .field("max_connection_lifetime", &self.max_connection_lifetime)
            .field("username_template", &self.username_template)
            .field("disable_escaping", &self.disable_escaping)
            .field("password_authentication", &self.password_authentication)
            .finish()
    }
}

fn postgres_dsn_uses_hardened_tcp_tls(dsn: &str) -> bool {
    if postgres_dsn_uses_uri_syntax(dsn) {
        return postgres_uri_uses_hardened_tcp_tls(dsn);
    }
    if postgres_dsn_has_unsupported_uri_like_prefix(dsn) {
        return false;
    }
    postgres_keyword_dsn_uses_hardened_tcp_tls(dsn)
}

fn postgres_dsn_uses_uri_syntax(dsn: &str) -> bool {
    dsn.starts_with("postgresql://") || dsn.starts_with("postgres://")
}

fn postgres_dsn_has_unsupported_uri_like_prefix(dsn: &str) -> bool {
    let Some(first) = dsn.split_ascii_whitespace().next() else {
        return false;
    };
    let Some(scheme_separator) = first.find("://") else {
        return false;
    };
    first
        .find('=')
        .is_none_or(|assignment| scheme_separator < assignment)
}

fn postgres_uri_uses_hardened_tcp_tls(dsn: &str) -> bool {
    let Ok(url) = Url::parse(dsn) else {
        return false;
    };
    if !matches!(url.scheme(), "postgres" | "postgresql") || url.fragment().is_some() {
        return false;
    }
    let Some(query) = url.query() else {
        return false;
    };
    let mut verify_full = false;
    let mut host_override: Option<Vec<u8>> = None;
    for parameter in query.split('&') {
        let (key, value) = match parameter.split_once('=') {
            Some((key, value)) => (key, value),
            None => (parameter, ""),
        };
        let Some(key) = percent_decode_strict(key) else {
            return false;
        };
        if key != b"sslmode"
            && key != b"host"
            && key != b"service"
            && key != b"servicefile"
            && [b"sslmode".as_slice(), b"host", b"service", b"servicefile"]
                .iter()
                .any(|expected| ascii_eq_ignore_case(&key, expected))
        {
            return false;
        }
        if key == b"sslmode" {
            if verify_full || percent_decode_strict(value).as_deref() != Some(b"verify-full") {
                return false;
            }
            verify_full = true;
        } else if key == b"host" {
            if host_override.is_some() {
                return false;
            }
            host_override = percent_decode_strict(value);
            if host_override.is_none() {
                return false;
            }
        } else if matches!(key.as_slice(), b"service" | b"servicefile") {
            return false;
        }
    }
    if !verify_full {
        return false;
    }
    match host_override {
        Some(host) => postgres_hosts_are_explicit_tcp(&host),
        None => url
            .host_str()
            .is_some_and(|host| postgres_hosts_are_explicit_tcp(host.as_bytes())),
    }
}

fn postgres_keyword_dsn_uses_hardened_tcp_tls(dsn: &str) -> bool {
    let bytes = dsn.as_bytes();
    let mut offset = 0_usize;
    let mut verify_full = false;
    let mut host: Option<Vec<u8>> = None;
    while offset < bytes.len() {
        while bytes.get(offset).is_some_and(u8::is_ascii_whitespace) {
            offset += 1;
        }
        if offset == bytes.len() {
            break;
        }
        let key_start = offset;
        while bytes
            .get(offset)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && *byte != b'=')
        {
            offset += 1;
        }
        let key_end = offset;
        while bytes.get(offset).is_some_and(u8::is_ascii_whitespace) {
            offset += 1;
        }
        if bytes.get(offset) != Some(&b'=') {
            return false;
        }
        offset += 1;
        while bytes.get(offset).is_some_and(u8::is_ascii_whitespace) {
            offset += 1;
        }

        let quoted = bytes.get(offset) == Some(&b'\'');
        if quoted {
            offset += 1;
        }
        let value_start = offset;
        let mut escaped = false;
        while let Some(byte) = bytes.get(offset) {
            if escaped {
                escaped = false;
                offset += 1;
            } else if *byte == b'\\' {
                escaped = true;
                offset += 1;
            } else if (quoted && *byte == b'\'') || (!quoted && byte.is_ascii_whitespace()) {
                break;
            } else {
                offset += 1;
            }
        }
        let value_end = offset;
        if quoted {
            if bytes.get(offset) != Some(&b'\'') {
                return false;
            }
            offset += 1;
            if bytes
                .get(offset)
                .is_some_and(|byte| !byte.is_ascii_whitespace())
            {
                return false;
            }
        } else if escaped {
            return false;
        }

        let key = &bytes[key_start..key_end];
        if key != b"sslmode"
            && key != b"host"
            && key != b"service"
            && key != b"servicefile"
            && [b"sslmode".as_slice(), b"host", b"service", b"servicefile"]
                .iter()
                .any(|expected| ascii_eq_ignore_case(key, expected))
        {
            return false;
        }
        if key == b"sslmode" {
            if verify_full {
                return false;
            }
            let Some(value) = decode_keyword_value(&bytes[value_start..value_end]) else {
                return false;
            };
            if value != b"verify-full" {
                return false;
            }
            verify_full = true;
        } else if key == b"host" {
            if host.is_some() {
                return false;
            }
            host = decode_keyword_value(&bytes[value_start..value_end]);
            if host.is_none() {
                return false;
            }
        } else if matches!(key, b"service" | b"servicefile") {
            return false;
        }
    }
    verify_full && host.is_some_and(|host| postgres_hosts_are_explicit_tcp(&host))
}

fn decode_keyword_value(value: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut offset = 0_usize;
    while let Some(byte) = value.get(offset) {
        if *byte == b'\\' {
            offset += 1;
            decoded.push(*value.get(offset)?);
        } else {
            decoded.push(*byte);
        }
        offset += 1;
    }
    Some(decoded)
}

fn ascii_eq_ignore_case(value: &[u8], expected: &[u8]) -> bool {
    value.len() == expected.len()
        && value
            .iter()
            .zip(expected)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn percent_decode_strict(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut offset = 0_usize;
    while let Some(byte) = bytes.get(offset) {
        if *byte == b'%' {
            let (Some(high), Some(low)) = (bytes.get(offset + 1), bytes.get(offset + 2)) else {
                return None;
            };
            let (Some(high), Some(low)) = (hex_value(*high), hex_value(*low)) else {
                return None;
            };
            offset += 2;
            decoded.push((high << 4) | low);
        } else if *byte == b'+' {
            decoded.push(b' ');
        } else {
            decoded.push(*byte);
        }
        offset += 1;
    }
    Some(decoded)
}

fn postgres_hosts_are_explicit_tcp(hosts: &[u8]) -> bool {
    let Ok(hosts) = core::str::from_utf8(hosts) else {
        return false;
    };
    hosts.split(',').all(|host| {
        let host = host.trim();
        !host.is_empty()
            && host
                .bytes()
                .all(|byte| !byte.is_ascii_whitespace() && !byte.is_ascii_control())
            && !matches!(host.as_bytes().first(), Some(b'/' | b'\\'))
            && !postgres_host_is_windows_absolute_path(host)
    })
}

fn postgres_host_is_windows_absolute_path(host: &str) -> bool {
    let bytes = host.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// MySQL-family built-in plugin connection options.
#[derive(Clone)]
pub struct MySqlConnectionOptions {
    /// Built-in MySQL plugin variant.
    pub plugin: MySqlPlugin,
    /// Templated MySQL DSN.
    pub connection_url: SecretString,
    /// Root username.
    pub username: Option<String>,
    /// Root password.
    pub password: Option<SecretString>,
    /// Maximum open connections.
    pub max_open_connections: Option<u32>,
    /// Maximum idle connections; negative disables idle connections.
    pub max_idle_connections: Option<i32>,
    /// Maximum connection lifetime.
    pub max_connection_lifetime: Option<String>,
    /// Client certificate and private key PEM.
    pub tls_certificate_key: Option<SecretString>,
    /// Server CA PEM.
    pub tls_ca: Option<String>,
    /// Expected TLS server name.
    pub tls_server_name: Option<String>,
    /// Disables TLS certificate verification.
    pub tls_skip_verify: Option<bool>,
    /// Dynamic username template.
    pub username_template: Option<String>,
    /// Disables username/password escaping.
    pub disable_escaping: Option<bool>,
}

impl MySqlConnectionOptions {
    /// Creates MySQL-family options with the required DSN.
    pub fn new(plugin: MySqlPlugin, connection_url: SecretString) -> Self {
        Self {
            plugin,
            connection_url,
            username: None,
            password: None,
            max_open_connections: None,
            max_idle_connections: None,
            max_connection_lifetime: None,
            tls_certificate_key: None,
            tls_ca: None,
            tls_server_name: None,
            tls_skip_verify: None,
            username_template: None,
            disable_escaping: None,
        }
    }
}

impl fmt::Debug for MySqlConnectionOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MySqlConnectionOptions")
            .field("plugin", &self.plugin)
            .field("connection_url", &"<redacted>")
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field(
                "tls_certificate_key",
                &self.tls_certificate_key.as_ref().map(|_| "<redacted>"),
            )
            .field("tls_ca", &self.tls_ca.as_ref().map(|_| "<configured>"))
            .field("tls_skip_verify", &self.tls_skip_verify)
            .finish_non_exhaustive()
    }
}

/// Cassandra built-in plugin connection options.
#[derive(Clone, Default)]
pub struct CassandraConnectionOptions {
    /// Comma-separated Cassandra hosts.
    pub hosts: String,
    /// Root username.
    pub username: String,
    /// Root password.
    pub password: SecretString,
    /// Cassandra port.
    pub port: Option<u16>,
    /// Enables TLS.
    pub tls: Option<bool>,
    /// Disables TLS certificate verification.
    pub insecure_tls: Option<bool>,
    /// Expected TLS server name.
    pub tls_server_name: Option<String>,
    /// PEM bundle containing TLS material.
    pub pem_bundle: Option<SecretString>,
    /// JSON containing TLS material.
    pub pem_json: Option<SecretString>,
    /// Skips initial permission verification.
    pub skip_verification: Option<bool>,
    /// CQL protocol version.
    pub protocol_version: Option<u8>,
    /// Connection timeout.
    pub connect_timeout: Option<String>,
    /// Preferred local datacenter.
    pub local_datacenter: Option<String>,
    /// Socket keep-alive period.
    pub socket_keep_alive: Option<String>,
    /// Cassandra consistency mode.
    pub consistency: Option<String>,
    /// Dynamic username template.
    pub username_template: Option<String>,
}

impl CassandraConnectionOptions {
    /// Creates Cassandra options with required connection credentials.
    pub fn new(
        hosts: impl Into<String>,
        username: impl Into<String>,
        password: SecretString,
    ) -> Self {
        Self {
            hosts: hosts.into(),
            username: username.into(),
            password,
            ..Self::default()
        }
    }
}

impl fmt::Debug for CassandraConnectionOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CassandraConnectionOptions")
            .field("hosts", &self.hosts)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field(
                "pem_bundle",
                &self.pem_bundle.as_ref().map(|_| "<redacted>"),
            )
            .field("pem_json", &self.pem_json.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

/// InfluxDB built-in plugin connection options.
#[derive(Clone, Default)]
pub struct InfluxDbConnectionOptions {
    /// InfluxDB host.
    pub host: String,
    /// Root username.
    pub username: String,
    /// Root password.
    pub password: SecretString,
    /// InfluxDB port.
    pub port: Option<u16>,
    /// Enables TLS.
    pub tls: Option<bool>,
    /// Disables TLS certificate verification.
    pub insecure_tls: Option<bool>,
    /// PEM bundle containing TLS material.
    pub pem_bundle: Option<SecretString>,
    /// JSON containing TLS material.
    pub pem_json: Option<SecretString>,
    /// Connection timeout.
    pub connect_timeout: Option<String>,
    /// Dynamic username template.
    pub username_template: Option<String>,
}

impl InfluxDbConnectionOptions {
    /// Creates InfluxDB options with required connection credentials.
    pub fn new(
        host: impl Into<String>,
        username: impl Into<String>,
        password: SecretString,
    ) -> Self {
        Self {
            host: host.into(),
            username: username.into(),
            password,
            ..Self::default()
        }
    }
}

impl fmt::Debug for InfluxDbConnectionOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InfluxDbConnectionOptions")
            .field("host", &self.host)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field(
                "pem_bundle",
                &self.pem_bundle.as_ref().map(|_| "<redacted>"),
            )
            .field("pem_json", &self.pem_json.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

/// Valkey built-in plugin connection options.
#[derive(Clone, Default)]
pub struct ValkeyConnectionOptions {
    /// Valkey host.
    pub host: String,
    /// Valkey port.
    pub port: u16,
    /// Administrative username.
    pub username: String,
    /// Administrative password.
    pub password: SecretString,
    /// Enables TLS.
    pub tls: Option<bool>,
    /// Disables TLS certificate verification.
    pub insecure_tls: Option<bool>,
}

impl ValkeyConnectionOptions {
    /// Creates Valkey options with required connection credentials.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: SecretString,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            username: username.into(),
            password,
            tls: None,
            insecure_tls: None,
        }
    }
}

impl fmt::Debug for ValkeyConnectionOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValkeyConnectionOptions")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("tls", &self.tls)
            .field("insecure_tls", &self.insecure_tls)
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
        config.validate()?;
        self.request(Method::POST, &self.path(&["config", name])?, Some(config))
            .await
    }

    /// Reads a database connection configuration.
    pub async fn read_connection(&self, name: &str) -> Result<DatabaseConnectionInfo> {
        let envelope: ResponseEnvelope<DatabaseConnectionInfo> = self
            .request(
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
        self.request(Method::POST, &self.path(&["reset", name])?, Some(&Empty {}))
            .await
    }

    /// Rotates the root credentials for a database connection.
    pub async fn rotate_root(&self, name: &str) -> Result<Empty> {
        self.request(
            Method::POST,
            &self.path(&["rotate-root", name])?,
            Some(&Empty {}),
        )
        .await
    }

    /// Creates or updates a dynamic database role.
    pub async fn write_role(&self, name: &str, role: &DatabaseRole) -> Result<Empty> {
        self.request(Method::POST, &self.path(&["roles", name])?, Some(role))
            .await
    }

    /// Reads a dynamic database role.
    pub async fn read_role(&self, name: &str) -> Result<DatabaseRole> {
        let envelope: ResponseEnvelope<DatabaseRole> = self
            .request(
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
            .request(
                Method::GET,
                &self.path(&["creds", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(database_credentials_from_envelope(envelope))
    }

    /// Creates or updates a static database role.
    pub async fn write_static_role(&self, name: &str, role: &DatabaseStaticRole) -> Result<Empty> {
        self.request(
            Method::POST,
            &self.path(&["static-roles", name])?,
            Some(role),
        )
        .await
    }

    /// Reads a static database role.
    pub async fn read_static_role(&self, name: &str) -> Result<DatabaseStaticRole> {
        let envelope: ResponseEnvelope<DatabaseStaticRole> = self
            .request(
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
            .request(
                Method::GET,
                &self.path(&["static-creds", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Rotates credentials for a static database role.
    pub async fn rotate_static_role(&self, name: &str) -> Result<Empty> {
        self.request(
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
            .request_query(
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
        self.request_accepting(
            Method::DELETE,
            &self.path(&[segment, name])?,
            Option::<&Empty>::None,
            &[StatusCode::OK, StatusCode::NO_CONTENT],
        )
        .await
    }

    async fn request<T, B>(&self, method: Method, path: &str, body: Option<&B>) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.client
            .request_secret_json_internal(
                "/database/",
                "database",
                &self.mount.join("/"),
                method,
                path,
                body,
            )
            .await
    }

    async fn request_accepting<T, B>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        accepted_statuses: &[StatusCode],
    ) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.client
            .request_secret_json_accepting(
                "/database/",
                "database",
                &self.mount.join("/"),
                method,
                path,
                body,
                accepted_statuses,
            )
            .await
    }

    async fn request_query<T, B>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&B>,
        accepted_statuses: &[StatusCode],
    ) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.client
            .request_secret_json_query_headers_accepting(
                "/database/",
                "database",
                &self.mount.join("/"),
                method,
                path,
                query,
                &[],
                body,
                accepted_statuses,
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

fn validate_optional_database_duration(value: Option<&str>, field: &'static str) -> Result<()> {
    if let Some(value) = value {
        crate::validation::validate_duration_parameter(value, field)?;
    }
    Ok(())
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
                || (self.builtin_options.is_some()
                    && DATABASE_BUILTIN_CONNECTION_FIELDS
                        .iter()
                        .any(|field| key == field))
        }) {
            return Err(<S::Error as serde::ser::Error>::custom(
                DATABASE_CONNECTION_EXTRA_COLLISION_ERROR,
            ));
        }

        if let Some(options) = self.builtin_options.as_ref() {
            if self.plugin_name != options.plugin_name() {
                return Err(<S::Error as serde::ser::Error>::custom(
                    "database built-in options do not match plugin_name",
                ));
            }
            if self.connection_url.is_some()
                || self.username.is_some()
                || self.password.is_some()
                || self.disable_escaping.is_some()
            {
                return Err(<S::Error as serde::ser::Error>::custom(
                    "database built-in options conflict with legacy typed fields",
                ));
            }
        }

        let mut map = serializer.serialize_map(None)?;
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
        if let Some(options) = self.builtin_options.as_ref() {
            macro_rules! optional_entry {
                ($name:literal, $value:expr) => {
                    if let Some(value) = $value.as_ref() {
                        map.serialize_entry($name, value)?;
                    }
                };
            }
            macro_rules! optional_secret_entry {
                ($name:literal, $value:expr) => {
                    if let Some(value) = $value.as_ref() {
                        map.serialize_entry($name, value.expose_secret())?;
                    }
                };
            }
            match options {
                DatabaseBuiltinConnectionConfig::PostgreSql(options) => {
                    map.serialize_entry("connection_url", options.connection_url.expose_secret())?;
                    optional_entry!("username", options.username);
                    optional_secret_entry!("password", options.password);
                    optional_entry!("max_open_connections", options.max_open_connections);
                    optional_entry!("max_idle_connections", options.max_idle_connections);
                    optional_entry!("max_connection_lifetime", options.max_connection_lifetime);
                    optional_entry!("username_template", options.username_template);
                    optional_entry!("disable_escaping", options.disable_escaping);
                    optional_entry!("password_authentication", options.password_authentication);
                }
                DatabaseBuiltinConnectionConfig::MySql(options) => {
                    map.serialize_entry("connection_url", options.connection_url.expose_secret())?;
                    optional_entry!("username", options.username);
                    optional_secret_entry!("password", options.password);
                    optional_entry!("max_open_connections", options.max_open_connections);
                    optional_entry!("max_idle_connections", options.max_idle_connections);
                    optional_entry!("max_connection_lifetime", options.max_connection_lifetime);
                    optional_secret_entry!("tls_certificate_key", options.tls_certificate_key);
                    optional_entry!("tls_ca", options.tls_ca);
                    optional_entry!("tls_server_name", options.tls_server_name);
                    optional_entry!("tls_skip_verify", options.tls_skip_verify);
                    optional_entry!("username_template", options.username_template);
                    optional_entry!("disable_escaping", options.disable_escaping);
                }
                DatabaseBuiltinConnectionConfig::Cassandra(options) => {
                    map.serialize_entry("hosts", &options.hosts)?;
                    map.serialize_entry("username", &options.username)?;
                    map.serialize_entry("password", options.password.expose_secret())?;
                    optional_entry!("port", options.port);
                    optional_entry!("tls", options.tls);
                    optional_entry!("insecure_tls", options.insecure_tls);
                    optional_entry!("tls_server_name", options.tls_server_name);
                    optional_secret_entry!("pem_bundle", options.pem_bundle);
                    optional_secret_entry!("pem_json", options.pem_json);
                    optional_entry!("skip_verification", options.skip_verification);
                    optional_entry!("protocol_version", options.protocol_version);
                    optional_entry!("connect_timeout", options.connect_timeout);
                    optional_entry!("local_datacenter", options.local_datacenter);
                    optional_entry!("socket_keep_alive", options.socket_keep_alive);
                    optional_entry!("consistency", options.consistency);
                    optional_entry!("username_template", options.username_template);
                }
                DatabaseBuiltinConnectionConfig::InfluxDb(options) => {
                    map.serialize_entry("host", &options.host)?;
                    map.serialize_entry("username", &options.username)?;
                    map.serialize_entry("password", options.password.expose_secret())?;
                    optional_entry!("port", options.port);
                    optional_entry!("tls", options.tls);
                    optional_entry!("insecure_tls", options.insecure_tls);
                    optional_secret_entry!("pem_bundle", options.pem_bundle);
                    optional_secret_entry!("pem_json", options.pem_json);
                    optional_entry!("connect_timeout", options.connect_timeout);
                    optional_entry!("username_template", options.username_template);
                }
                DatabaseBuiltinConnectionConfig::Valkey(options) => {
                    map.serialize_entry("host", &options.host)?;
                    map.serialize_entry("port", &options.port)?;
                    map.serialize_entry("username", &options.username)?;
                    map.serialize_entry("password", options.password.expose_secret())?;
                    optional_entry!("tls", options.tls);
                    optional_entry!("insecure_tls", options.insecure_tls);
                }
            }
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
        CassandraConnectionOptions, DATABASE_BUILTIN_CONNECTION_FIELDS,
        DATABASE_CONNECTION_CONFIG_FIELDS, DATABASE_CONNECTION_EXTRA_COLLISION_ERROR,
        DatabaseBuiltinConnectionConfig, DatabaseConnectionConfig, DatabaseConnectionInfo,
        DatabaseCredentials, DatabaseList, DatabaseRole, DatabaseStaticCredentials,
        InfluxDbConnectionOptions, MySqlConnectionOptions, MySqlPlugin,
        PostgreSqlConnectionOptions, REVIEWED_BUILTIN_DATABASE_PLUGINS, ValkeyConnectionOptions,
        postgres_dsn_uses_hardened_tcp_tls,
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

        for field in DATABASE_BUILTIN_CONNECTION_FIELDS {
            let mut config =
                DatabaseConnectionConfig::builtin(DatabaseBuiltinConnectionConfig::PostgreSql(
                    PostgreSqlConnectionOptions::new(SecretString::from("postgres-dsn")),
                ));
            config
                .extra
                .insert(field.to_owned(), SecretString::from("shadowed-value"));
            let error = serde_json::to_value(&config).err().unwrap_or_else(|| {
                panic!("built-in database field collision unexpectedly serialized")
            });
            assert_eq!(error.to_string(), DATABASE_CONNECTION_EXTRA_COLLISION_ERROR);
            assert!(!error.to_string().contains(field));
            assert!(!error.to_string().contains("shadowed-value"));
        }
    }

    #[test]
    fn built_in_database_connection_options_preserve_types_and_redact_secrets() {
        let mut postgres = PostgreSqlConnectionOptions::new(SecretString::from("postgres-dsn"));
        postgres.password = Some(SecretString::from("postgres-password"));
        postgres.max_open_connections = Some(8);
        let postgres = DatabaseConnectionConfig::builtin(
            DatabaseBuiltinConnectionConfig::PostgreSql(postgres),
        );
        let value = serde_json::to_value(&postgres).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(value["plugin_name"], "postgresql-database-plugin");
        assert_eq!(value["max_open_connections"], 8);
        assert!(!format!("{postgres:?}").contains("postgres-password"));

        let mysql = DatabaseConnectionConfig::builtin(DatabaseBuiltinConnectionConfig::MySql(
            MySqlConnectionOptions::new(MySqlPlugin::Aurora, SecretString::from("mysql-dsn")),
        ));
        assert_eq!(
            serde_json::to_value(mysql).unwrap_or_else(|error| panic!("{error}"))["plugin_name"],
            "mysql-aurora-database-plugin"
        );

        let cassandra = DatabaseConnectionConfig::builtin(
            DatabaseBuiltinConnectionConfig::Cassandra(CassandraConnectionOptions::new(
                "db.example.com",
                "admin",
                SecretString::from("cassandra-password"),
            )),
        );
        let value = serde_json::to_value(&cassandra).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(value["hosts"], "db.example.com");
        assert!(!format!("{cassandra:?}").contains("cassandra-password"));

        let influx = DatabaseConnectionConfig::builtin(DatabaseBuiltinConnectionConfig::InfluxDb(
            InfluxDbConnectionOptions::new(
                "influx.example.com",
                "admin",
                SecretString::from("influx-password"),
            ),
        ));
        assert_eq!(
            serde_json::to_value(influx).unwrap_or_else(|error| panic!("{error}"))["host"],
            "influx.example.com"
        );

        let valkey = DatabaseConnectionConfig::builtin(DatabaseBuiltinConnectionConfig::Valkey(
            ValkeyConnectionOptions::new(
                "valkey.example.com",
                6379,
                "admin",
                SecretString::from("valkey-password"),
            ),
        ));
        let value = serde_json::to_value(&valkey).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(value["port"], 6379);
        assert!(!format!("{valkey:?}").contains("valkey-password"));
    }

    #[test]
    #[cfg(not(feature = "insecure-database-tls-acknowledged"))]
    fn built_in_database_tls_verification_bypass_requires_acknowledgement() {
        let mut options = ValkeyConnectionOptions::new(
            "valkey.example.com",
            6379,
            "admin",
            SecretString::from("password"),
        );
        options.tls = Some(true);
        options.insecure_tls = Some(true);
        let config =
            DatabaseConnectionConfig::builtin(DatabaseBuiltinConnectionConfig::Valkey(options));
        let error = config
            .validate()
            .err()
            .unwrap_or_else(|| panic!("insecure database TLS unexpectedly accepted"));
        assert!(error.to_string().contains("requires"));
        assert!(!error.to_string().contains("password"));
    }

    #[test]
    fn postgres_dsn_requires_effective_verify_full() {
        for dsn in [
            "postgresql://db.example/openbao",
            "postgresql://db.example/openbao?sslmode=disable",
            "postgresql://db.example/openbao?sslmode=",
            "postgresql://db.example/openbao?sslmode=verify-full&sslmode=require",
            "postgresql://db.example/openbao?sslmode=require&sslmode=verify-full",
            "postgresql://db.example/openbao?sslmode=verify-full&%73slmode=verify-full",
            "postgresql://db.example/openbao?sslmode&sslmode=verify-full",
            "postgresql://db.example/openbao?sslmode=verify-full&sslmode",
            "postgresql://db.example/openbao?%73slmode&sslmode=verify-full",
            "postgresql://db.example/openbao?sslmode",
            "postgresql://db.example/openbao?service=production",
            "postgresql://db.example/openbao?sslmode=verify-full&host=%2Ftmp",
            "postgresql://db.example/openbao?sslmode=verify-full&host=db+example",
            "postgresql:///openbao?sslmode=verify-full&host=%2Ftmp",
            "postgresql://db.example/openbao?sslmode=verify-full&host=C%3A%5Cpg",
            "postgresql://db.example/openbao?sslmode=verify-full&service=production",
            "postgres://db.example/openbao?SSLMode=VERIFY-FULL",
            "postgres://db.example/openbao?sslmode=VERIFY-FULL",
            "POSTGRESQL://db.example/openbao?sslmode=verify-full",
            "mysql://db.example/openbao?sslmode=verify-full",
            "host=db.example dbname=openbao",
            "host=db.example sslmode=disable dbname=openbao",
            "host=db.example sslmode=verify-full sslmode=prefer",
            "host=db.example sslmode=prefer sslmode=verify-full",
            "host=/tmp sslmode=verify-full dbname=openbao",
            r"host='C:\\pg' sslmode=verify-full dbname=openbao",
            "host=db.example SSLMODE=verify-full dbname=openbao",
            "host=db.example sslmode=VERIFY-FULL dbname=openbao",
            "host=db.example sslmode='verify-full dbname=openbao",
            "host=db.example sslmode=verify-full service=production",
            "service=production",
        ] {
            assert!(
                !postgres_dsn_uses_hardened_tcp_tls(dsn),
                "missing or insecure effective sslmode was accepted"
            );
        }

        for dsn in [
            "postgresql://db.example/openbao?sslmode=verify-full",
            "postgresql://{{username}}:{{password}}@db.example/openbao?sslmode=verify-full",
            "postgresql://db.example/openbao?%73slmode=verify%2Dfull",
            "postgresql:///openbao?sslmode=verify-full&host=db.example",
            "postgresql://db.example/openbao?sslmode=verify-full&host=db.internal%2Cdb.backup",
            "host=db.example sslmode=verify-full dbname=openbao",
            r"host=db.example sslmode='verify\-full' dbname=openbao",
            "host=db.example,db.backup sslmode=verify-full",
        ] {
            assert!(
                postgres_dsn_uses_hardened_tcp_tls(dsn),
                "effective verify-full sslmode was rejected"
            );
        }
    }

    #[test]
    #[cfg(not(feature = "insecure-database-tls-acknowledged"))]
    fn postgres_dsn_tls_bypass_requires_acknowledgement() {
        let config =
            DatabaseConnectionConfig::builtin(DatabaseBuiltinConnectionConfig::PostgreSql(
                PostgreSqlConnectionOptions::new(SecretString::from(
                    "postgresql://{{username}}:{{password}}@db.example/openbao?sslmode=require",
                )),
            ));
        let error = config
            .validate()
            .err()
            .unwrap_or_else(|| panic!("insecure PostgreSQL TLS unexpectedly accepted"));
        assert!(error.to_string().contains("requires"));
        assert!(!error.to_string().contains("username"));
        assert!(!error.to_string().contains("password"));
        assert!(!error.to_string().contains("db.example"));
    }

    #[test]
    #[cfg(feature = "insecure-database-tls-acknowledged")]
    fn acknowledged_postgres_dsn_may_omit_verify_full() {
        let config = DatabaseConnectionConfig::builtin(
            DatabaseBuiltinConnectionConfig::PostgreSql(PostgreSqlConnectionOptions::new(
                SecretString::from("postgresql://db.example/openbao"),
            )),
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn reviewed_builtin_plugins_require_typed_configuration() {
        for plugin_name in REVIEWED_BUILTIN_DATABASE_PLUGINS {
            let mut config = DatabaseConnectionConfig::new(plugin_name);
            config.connection_url = Some(SecretString::from(
                "postgresql://root:password@db/openbao?sslmode=disable",
            ));
            config
                .extra
                .insert("insecure_tls".to_owned(), SecretString::from("true"));
            let error = config
                .validate()
                .err()
                .unwrap_or_else(|| panic!("reviewed built-in raw config unexpectedly accepted"));
            assert!(error.to_string().contains("require"));
            assert!(!error.to_string().contains(plugin_name));
            assert!(!error.to_string().contains("password"));
        }

        assert!(
            DatabaseConnectionConfig::new("custom-database-plugin")
                .validate()
                .is_ok()
        );
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
