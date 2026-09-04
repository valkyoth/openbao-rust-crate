//! LDAP secrets engine support.
//!
//! The LDAP secrets engine can manage static LDAP account passwords, generate
//! dynamic LDAP accounts, and broker access to pre-existing service accounts
//! through library sets.

use core::fmt;
use std::collections::BTreeMap;

use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor, ser::SerializeMap};

use crate::{
    Authenticated, Client, Error, Result,
    path::{validate_endpoint_path, validate_mount_path},
    response::{Empty, ListEntries, ResponseEnvelope, deserialize_bounded_string_vec},
    validation::{validate_duration_string, validate_ldap_urls},
};

/// Handle for a mounted LDAP secrets engine.
#[derive(Debug)]
pub struct Ldap<'a> {
    client: &'a Client<Authenticated>,
    mount: Vec<String>,
}

/// LDAP secrets engine configuration.
#[derive(Clone, Deserialize)]
pub struct LdapConfig {
    /// Distinguished name used by OpenBao to manage LDAP entries.
    pub binddn: String,
    /// Password used with `binddn`.
    pub bindpass: SecretString,
    /// LDAP server URL or comma-separated URL list.
    ///
    /// Use `ldaps://`, or set `starttls=true`. This configuration always
    /// carries bind credentials and therefore rejects unverified transport.
    #[serde(default)]
    pub url: Option<String>,
    /// Password policy used for generated LDAP passwords.
    #[serde(default)]
    pub password_policy: Option<String>,
    /// LDAP schema, such as `openldap`, `ad`, or `racf`.
    #[serde(default)]
    pub schema: Option<String>,
    /// Base DN used for user search.
    #[serde(default)]
    pub userdn: Option<String>,
    /// Attribute used for user search.
    #[serde(default)]
    pub userattr: Option<String>,
    /// UPN domain for Active Directory.
    #[serde(default)]
    pub upndomain: Option<String>,
    /// Connection timeout as seconds or OpenBao duration string.
    #[serde(default, deserialize_with = "deserialize_optional_string_or_u64")]
    pub connection_timeout: Option<String>,
    /// Request timeout as seconds or OpenBao duration string.
    #[serde(default, deserialize_with = "deserialize_optional_string_or_u64")]
    pub request_timeout: Option<String>,
    /// Whether to use StartTLS.
    #[serde(default)]
    pub starttls: Option<bool>,
    /// Whether to skip LDAP TLS certificate verification.
    #[serde(default)]
    pub insecure_tls: Option<bool>,
    /// CA certificate for LDAP TLS verification.
    #[serde(default)]
    pub certificate: Option<String>,
    /// Client TLS certificate.
    #[serde(default)]
    pub client_tls_cert: Option<String>,
    /// Client TLS private key.
    #[serde(default)]
    pub client_tls_key: Option<SecretString>,
    /// Generated password length.
    #[serde(default)]
    pub length: Option<u64>,
}

impl LdapConfig {
    /// Creates an LDAP config with the required bind DN and password.
    pub fn new(binddn: impl Into<String>, bindpass: SecretString) -> Self {
        Self {
            binddn: binddn.into(),
            bindpass,
            url: None,
            password_policy: None,
            schema: None,
            userdn: None,
            userattr: None,
            upndomain: None,
            connection_timeout: None,
            request_timeout: None,
            starttls: None,
            insecure_tls: None,
            certificate: None,
            client_tls_cert: None,
            client_tls_key: None,
            length: None,
        }
    }

    /// Sets the LDAP URL.
    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Sets the LDAP schema.
    #[must_use]
    pub fn with_schema(mut self, schema: impl Into<String>) -> Self {
        self.schema = Some(schema.into());
        self
    }

    fn validate(&self) -> Result<()> {
        #[cfg(not(feature = "insecure-ldap-tls-acknowledged"))]
        if self.insecure_tls == Some(true) {
            return Err(crate::Error::InvalidParameter(
                "ldap insecure_tls=true requires the insecure-ldap-tls-acknowledged Cargo feature because it disables LDAP TLS certificate verification".into(),
            ));
        }
        if self.insecure_tls == Some(true) {
            return Err(crate::Error::InvalidParameter(
                "ldap insecure_tls=true must not be combined with bindpass because credentials would cross an unverified TLS connection".into(),
            ));
        }
        validate_ldap_urls(&self.url, self.starttls, "LDAP", true)?;
        if let Some(value) = &self.connection_timeout {
            validate_duration_or_seconds(value, "LDAP connection_timeout", true)?;
        }
        if let Some(value) = &self.request_timeout {
            validate_duration_or_seconds(value, "LDAP request_timeout", true)?;
        }
        Ok(())
    }
}

impl fmt::Debug for LdapConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LdapConfig")
            .field("binddn", &self.binddn)
            .field("bindpass", &"<redacted>")
            .field("url", &self.url.as_ref().map(|_| "<redacted-url>"))
            .field("password_policy", &self.password_policy)
            .field("schema", &self.schema)
            .field("userdn", &self.userdn)
            .field("userattr", &self.userattr)
            .field("upndomain", &self.upndomain)
            .field("connection_timeout", &self.connection_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("starttls", &self.starttls)
            .field("insecure_tls", &self.insecure_tls)
            .field("certificate", &self.certificate)
            .field("client_tls_cert", &self.client_tls_cert)
            .field(
                "client_tls_key",
                &self.client_tls_key.as_ref().map(|_| "<redacted>"),
            )
            .field("length", &self.length)
            .finish()
    }
}

/// Static LDAP role request and response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LdapStaticRole {
    /// Existing LDAP username to manage.
    pub username: String,
    /// Distinguished name for the LDAP entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dn: Option<String>,
    /// Rotation period as seconds or OpenBao duration string.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub rotation_period: Option<String>,
    /// Last rotation timestamp returned by OpenBao.
    #[serde(default, skip_serializing)]
    pub last_vault_rotation: Option<String>,
}

impl LdapStaticRole {
    /// Creates a static role request for an existing LDAP username.
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            ..Self::default()
        }
    }

    /// Sets the static role rotation period.
    pub fn with_rotation_period(mut self, rotation_period: impl Into<String>) -> Result<Self> {
        let rotation_period = rotation_period.into();
        validate_duration_or_seconds(&rotation_period, "LDAP static role rotation_period", false)?;
        self.rotation_period = Some(rotation_period);
        Ok(self)
    }

    /// Sets the static role rotation period from a Rust duration.
    pub fn with_rotation_period_duration(
        self,
        rotation_period: std::time::Duration,
    ) -> Result<Self> {
        self.with_rotation_period(crate::duration::nonzero_duration_to_bao_string(
            rotation_period,
            "LDAP static role rotation_period",
        )?)
    }

    fn validate(&self) -> Result<()> {
        if let Some(value) = &self.rotation_period {
            validate_duration_or_seconds(value, "LDAP static role rotation_period", false)?;
        }
        Ok(())
    }
}

/// List response for LDAP static roles, dynamic roles, or library sets.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LdapList {
    /// Names returned by OpenBao.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for LdapList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Static LDAP credentials.
#[derive(Clone, Deserialize)]
pub struct LdapStaticCredentials {
    /// LDAP username.
    pub username: String,
    /// Distinguished name for the LDAP entry.
    #[serde(default)]
    pub dn: Option<String>,
    /// Current LDAP password.
    pub password: SecretString,
    /// Previous LDAP password, when returned.
    #[serde(default)]
    pub last_password: Option<SecretString>,
    /// Last rotation timestamp.
    #[serde(default)]
    pub last_vault_rotation: Option<String>,
    /// Rotation period in seconds.
    #[serde(default)]
    pub rotation_period: Option<u64>,
    /// Remaining TTL in seconds.
    #[serde(default)]
    pub ttl: Option<u64>,
}

impl fmt::Debug for LdapStaticCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LdapStaticCredentials")
            .field("username", &self.username)
            .field("dn", &self.dn)
            .field("password", &"<redacted>")
            .field(
                "last_password",
                &self.last_password.as_ref().map(|_| "<redacted>"),
            )
            .field("last_vault_rotation", &self.last_vault_rotation)
            .field("rotation_period", &self.rotation_period)
            .field("ttl", &self.ttl)
            .finish()
    }
}

/// Dynamic LDAP role request and response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LdapDynamicRole {
    /// Templated LDIF used to create a user account.
    pub creation_ldif: String,
    /// Templated LDIF used to delete a user account.
    pub deletion_ldif: String,
    /// Templated LDIF used to roll back failed user creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_ldif: Option<String>,
    /// Dynamic username template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username_template: Option<String>,
    /// Default lease TTL as seconds or OpenBao duration string.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_ttl: Option<String>,
    /// Maximum lease TTL as seconds or OpenBao duration string.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_ttl: Option<String>,
}

impl LdapDynamicRole {
    /// Creates a dynamic role request with required create/delete LDIF.
    pub fn new(creation_ldif: impl Into<String>, deletion_ldif: impl Into<String>) -> Self {
        Self {
            creation_ldif: creation_ldif.into(),
            deletion_ldif: deletion_ldif.into(),
            ..Self::default()
        }
    }

    /// Sets the default lease TTL.
    pub fn with_default_ttl(mut self, default_ttl: impl Into<String>) -> Result<Self> {
        let default_ttl = default_ttl.into();
        validate_duration_or_seconds(&default_ttl, "LDAP dynamic role default_ttl", true)?;
        self.default_ttl = Some(default_ttl);
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        if let Some(value) = &self.default_ttl {
            validate_duration_or_seconds(value, "LDAP dynamic role default_ttl", true)?;
        }
        if let Some(value) = &self.max_ttl {
            validate_duration_or_seconds(value, "LDAP dynamic role max_ttl", true)?;
        }
        Ok(())
    }
}

/// Generated dynamic LDAP credentials.
#[derive(Clone, Deserialize)]
pub struct LdapDynamicCredentials {
    /// Generated LDAP username.
    pub username: String,
    /// Generated LDAP password.
    pub password: SecretString,
    /// Distinguished names created for this lease.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub distinguished_names: Vec<String>,
    /// Lease ID for revocation/renewal.
    pub lease_id: SecretString,
    /// Lease duration in seconds.
    pub lease_duration: u64,
    /// Whether the lease is renewable.
    pub renewable: bool,
}

impl fmt::Debug for LdapDynamicCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LdapDynamicCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("distinguished_names", &self.distinguished_names)
            .field("lease_id", &"<redacted>")
            .field("lease_duration", &self.lease_duration)
            .field("renewable", &self.renewable)
            .finish()
    }
}

#[derive(Deserialize)]
struct LdapDynamicCredentialData {
    username: String,
    password: SecretString,
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    distinguished_names: Vec<String>,
}

/// LDAP library set request and response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LdapLibrarySet {
    /// Service account names in the library set.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub service_account_names: Vec<String>,
    /// Maximum single checkout duration.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub ttl: Option<String>,
    /// Maximum renewable checkout duration.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_ttl: Option<String>,
    /// Disable same-entity/same-token check-in enforcement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_check_in_enforcement: Option<bool>,
}

impl LdapLibrarySet {
    /// Creates a library set with service account names.
    pub fn new(service_account_names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            service_account_names: service_account_names.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Sets the checkout TTL.
    pub fn with_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        validate_duration_or_seconds(&ttl, "LDAP library ttl", true)?;
        self.ttl = Some(ttl);
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        validate_count(
            self.service_account_names.len(),
            "LDAP library service accounts",
            true,
        )?;
        if let Some(value) = &self.ttl {
            validate_duration_or_seconds(value, "LDAP library ttl", true)?;
        }
        if let Some(value) = &self.max_ttl {
            validate_duration_or_seconds(value, "LDAP library max_ttl", true)?;
        }
        Ok(())
    }
}

/// LDAP library status response.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct LdapLibraryStatus {
    /// Service account statuses.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_library_account_map_or_default"
    )]
    pub service_account_names: BTreeMap<String, LdapLibraryAccountStatus>,
}

/// Status for one LDAP library service account.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct LdapLibraryAccountStatus {
    /// Service account name.
    #[serde(default)]
    pub service_account_name: String,
    /// Whether the service account is checked out.
    #[serde(default)]
    pub checked_out: bool,
    /// Current borrower client token, when returned.
    #[serde(default)]
    pub borrower_client_token: Option<SecretString>,
    /// Current borrower entity ID, when returned.
    #[serde(default)]
    pub borrower_entity_id: Option<String>,
}

/// LDAP library checkout request.
#[derive(Clone, Debug, Default, Serialize)]
pub struct LdapCheckOutRequest {
    /// Requested checkout TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
}

impl LdapCheckOutRequest {
    /// Creates an empty checkout request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the requested checkout TTL.
    pub fn with_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        validate_duration_or_seconds(&ttl, "LDAP library checkout ttl", false)?;
        self.ttl = Some(ttl);
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        if let Some(value) = &self.ttl {
            validate_duration_or_seconds(value, "LDAP library checkout ttl", false)?;
        }
        Ok(())
    }
}

/// LDAP library checkout response.
#[derive(Clone, Deserialize)]
pub struct LdapCheckOut {
    /// Checked-out service account name.
    pub service_account_name: String,
    /// Generated service account password.
    pub password: SecretString,
    /// Lease ID for revocation/renewal.
    pub lease_id: SecretString,
    /// Lease duration in seconds.
    pub lease_duration: u64,
    /// Whether the lease is renewable.
    pub renewable: bool,
}

impl fmt::Debug for LdapCheckOut {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LdapCheckOut")
            .field("service_account_name", &self.service_account_name)
            .field("password", &"<redacted>")
            .field("lease_id", &"<redacted>")
            .field("lease_duration", &self.lease_duration)
            .field("renewable", &self.renewable)
            .finish()
    }
}

#[derive(Deserialize)]
struct LdapCheckOutData {
    service_account_name: String,
    password: SecretString,
}

/// LDAP library check-in request.
#[derive(Clone, Debug, Default, Serialize)]
pub struct LdapCheckInRequest {
    /// Service account names to check in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_account_names: Vec<String>,
}

impl LdapCheckInRequest {
    /// Creates a check-in request.
    pub fn new(service_account_names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            service_account_names: service_account_names.into_iter().map(Into::into).collect(),
        }
    }

    fn validate(&self) -> Result<()> {
        validate_count(
            self.service_account_names.len(),
            "LDAP check-in service accounts",
            false,
        )
    }
}

/// LDAP library check-in response.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct LdapCheckIn {
    /// Service account names checked in by this call.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub check_ins: Vec<String>,
}

impl Client<Authenticated> {
    /// Uses the LDAP secrets engine mounted at `ldap`.
    pub fn ldap(&self) -> Result<Ldap<'_>> {
        self.ldap_at("ldap")
    }

    /// Uses the LDAP secrets engine mounted at `mount`.
    pub fn ldap_at(&self, mount: impl Into<String>) -> Result<Ldap<'_>> {
        let mount = mount.into();
        Ok(Ldap {
            client: self,
            mount: validate_mount_path(&mount)?,
        })
    }
}

impl Ldap<'_> {
    /// Creates or updates LDAP engine configuration.
    pub async fn write_config(&self, config: &LdapConfig) -> Result<Empty> {
        config.validate()?;
        self.request(Method::POST, &self.path(&["config"])?, Some(config))
            .await
    }

    /// Reads LDAP engine configuration.
    pub async fn read_config(&self) -> Result<LdapConfig> {
        let envelope: ResponseEnvelope<LdapConfig> = self
            .request(
                Method::GET,
                &self.path(&["config"])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes LDAP engine configuration.
    pub async fn delete_config(&self) -> Result<Empty> {
        self.delete_at(&["config"]).await
    }

    /// Rotates the LDAP bind user's password.
    pub async fn rotate_root(&self) -> Result<Empty> {
        self.request(Method::POST, &self.path(&["rotate-root"])?, Some(&Empty {}))
            .await
    }

    /// Creates or updates a static LDAP role.
    pub async fn write_static_role(&self, name: &str, role: &LdapStaticRole) -> Result<Empty> {
        role.validate()?;
        self.request(
            Method::POST,
            &self.path(&["static-role", name])?,
            Some(role),
        )
        .await
    }

    /// Reads a static LDAP role.
    pub async fn read_static_role(&self, name: &str) -> Result<LdapStaticRole> {
        let envelope: ResponseEnvelope<LdapStaticRole> = self
            .request(
                Method::GET,
                &self.path(&["static-role", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists static LDAP role names.
    pub async fn list_static_roles(&self) -> Result<LdapList> {
        self.list_at(&["static-role"]).await
    }

    /// Deletes a static LDAP role.
    pub async fn delete_static_role(&self, name: &str) -> Result<Empty> {
        self.delete_at(&["static-role", name]).await
    }

    /// Reads static LDAP credentials.
    pub async fn static_credentials(&self, name: &str) -> Result<LdapStaticCredentials> {
        let envelope: ResponseEnvelope<LdapStaticCredentials> = self
            .request(
                Method::GET,
                &self.path(&["static-cred", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Rotates a static LDAP role password.
    pub async fn rotate_static_role(&self, name: &str) -> Result<Empty> {
        self.request(
            Method::POST,
            &self.path(&["rotate-role", name])?,
            Some(&Empty {}),
        )
        .await
    }

    /// Creates or updates a dynamic LDAP role.
    pub async fn write_dynamic_role(&self, name: &str, role: &LdapDynamicRole) -> Result<Empty> {
        role.validate()?;
        self.request(Method::POST, &self.path(&["role", name])?, Some(role))
            .await
    }

    /// Reads a dynamic LDAP role.
    pub async fn read_dynamic_role(&self, name: &str) -> Result<LdapDynamicRole> {
        let envelope: ResponseEnvelope<LdapDynamicRole> = self
            .request(
                Method::GET,
                &self.path(&["role", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a dynamic LDAP role.
    pub async fn delete_dynamic_role(&self, name: &str) -> Result<Empty> {
        self.delete_at(&["role", name]).await
    }

    /// Generates dynamic LDAP credentials.
    pub async fn dynamic_credentials(&self, name: &str) -> Result<LdapDynamicCredentials> {
        let envelope: ResponseEnvelope<LdapDynamicCredentialData> = self
            .request(
                Method::GET,
                &self.path(&["creds", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(LdapDynamicCredentials {
            username: envelope.data.username,
            password: envelope.data.password,
            distinguished_names: envelope.data.distinguished_names,
            lease_id: envelope.lease_id,
            lease_duration: envelope.lease_duration,
            renewable: envelope.renewable,
        })
    }

    /// Creates or updates a library set.
    pub async fn write_library_set(&self, name: &str, set: &LdapLibrarySet) -> Result<Empty> {
        set.validate()?;
        self.request(Method::POST, &self.path(&["library", name])?, Some(set))
            .await
    }

    /// Reads a library set.
    pub async fn read_library_set(&self, name: &str) -> Result<LdapLibrarySet> {
        let envelope: ResponseEnvelope<LdapLibrarySet> = self
            .request(
                Method::GET,
                &self.path(&["library", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists library set names.
    pub async fn list_library_sets(&self) -> Result<LdapList> {
        self.list_at(&["library"]).await
    }

    /// Deletes a library set.
    pub async fn delete_library_set(&self, name: &str) -> Result<Empty> {
        self.delete_at(&["library", name]).await
    }

    /// Reads library set account status.
    pub async fn library_status(&self, name: &str) -> Result<LdapLibraryStatus> {
        let envelope: ResponseEnvelope<LdapLibraryStatus> = self
            .request(
                Method::GET,
                &self.path(&["library", name, "status"])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Checks out one service account from a library set.
    pub async fn check_out(
        &self,
        name: &str,
        request: &LdapCheckOutRequest,
    ) -> Result<LdapCheckOut> {
        request.validate()?;
        let envelope: ResponseEnvelope<LdapCheckOutData> = self
            .request(
                Method::POST,
                &self.path(&["library", name, "check-out"])?,
                Some(request),
            )
            .await?;
        Ok(LdapCheckOut {
            service_account_name: envelope.data.service_account_name,
            password: envelope.data.password,
            lease_id: envelope.lease_id,
            lease_duration: envelope.lease_duration,
            renewable: envelope.renewable,
        })
    }

    /// Checks service accounts back into a library set.
    pub async fn check_in(&self, name: &str, request: &LdapCheckInRequest) -> Result<LdapCheckIn> {
        request.validate()?;
        let envelope: ResponseEnvelope<LdapCheckIn> = self
            .request(
                Method::POST,
                &self.path(&["library", name, "check-in"])?,
                Some(request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Force-checks service accounts back into a library set through the
    /// privileged management endpoint.
    pub async fn force_check_in(
        &self,
        name: &str,
        request: &LdapCheckInRequest,
    ) -> Result<LdapCheckIn> {
        request.validate()?;
        let envelope: ResponseEnvelope<LdapCheckIn> = self
            .request(
                Method::POST,
                &self.path(&["library", "manage", name, "check-in"])?,
                Some(request),
            )
            .await?;
        Ok(envelope.data)
    }

    async fn list_at(&self, tail: &[&str]) -> Result<LdapList> {
        let method = if tail == ["static-role"] {
            Method::GET
        } else {
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?
        };
        let envelope: ResponseEnvelope<LdapList> = self
            .request_query(
                method,
                &self.path(tail)?,
                &[],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    async fn delete_at(&self, tail: &[&str]) -> Result<Empty> {
        self.request_accepting(
            Method::DELETE,
            &self.path(tail)?,
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
                "/ldap/",
                "ldap",
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
                "/ldap/",
                "ldap",
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
                "/ldap/",
                "ldap",
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

impl Serialize for LdapConfig {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut count = 2;
        count += usize::from(self.url.is_some());
        count += usize::from(self.password_policy.is_some());
        count += usize::from(self.schema.is_some());
        count += usize::from(self.userdn.is_some());
        count += usize::from(self.userattr.is_some());
        count += usize::from(self.upndomain.is_some());
        count += usize::from(self.connection_timeout.is_some());
        count += usize::from(self.request_timeout.is_some());
        count += usize::from(self.starttls.is_some());
        count += usize::from(self.insecure_tls.is_some());
        count += usize::from(self.certificate.is_some());
        count += usize::from(self.client_tls_cert.is_some());
        count += usize::from(self.client_tls_key.is_some());
        count += usize::from(self.length.is_some());

        let mut map = serializer.serialize_map(Some(count))?;
        map.serialize_entry("binddn", &self.binddn)?;
        map.serialize_entry("bindpass", self.bindpass.expose_secret())?;
        if let Some(value) = self.url.as_ref() {
            map.serialize_entry("url", value)?;
        }
        if let Some(value) = self.password_policy.as_ref() {
            map.serialize_entry("password_policy", value)?;
        }
        if let Some(value) = self.schema.as_ref() {
            map.serialize_entry("schema", value)?;
        }
        if let Some(value) = self.userdn.as_ref() {
            map.serialize_entry("userdn", value)?;
        }
        if let Some(value) = self.userattr.as_ref() {
            map.serialize_entry("userattr", value)?;
        }
        if let Some(value) = self.upndomain.as_ref() {
            map.serialize_entry("upndomain", value)?;
        }
        if let Some(value) = self.connection_timeout.as_ref() {
            map.serialize_entry("connection_timeout", value)?;
        }
        if let Some(value) = self.request_timeout.as_ref() {
            map.serialize_entry("request_timeout", value)?;
        }
        if let Some(value) = self.starttls {
            map.serialize_entry("starttls", &value)?;
        }
        if let Some(value) = self.insecure_tls {
            map.serialize_entry("insecure_tls", &value)?;
        }
        if let Some(value) = self.certificate.as_ref() {
            map.serialize_entry("certificate", value)?;
        }
        if let Some(value) = self.client_tls_cert.as_ref() {
            map.serialize_entry("client_tls_cert", value)?;
        }
        if let Some(value) = self.client_tls_key.as_ref() {
            map.serialize_entry("client_tls_key", value.expose_secret())?;
        }
        if let Some(value) = self.length {
            map.serialize_entry("length", &value)?;
        }
        map.end()
    }
}

fn validate_duration_or_seconds(value: &str, field: &'static str, allow_zero: bool) -> Result<()> {
    if value
        .parse::<u64>()
        .is_ok_and(|seconds| allow_zero || seconds > 0)
        || validate_duration_string(value, allow_zero)
    {
        return Ok(());
    }
    Err(Error::InvalidParameter(format!(
        "{field} must be a duration such as 30s, 5m, or 1h or an unsigned second count"
    )))
}

fn validate_count(count: usize, field: &'static str, require_non_empty: bool) -> Result<()> {
    if require_non_empty && count == 0 {
        return Err(Error::InvalidParameter(format!(
            "{field} must include at least one item"
        )));
    }
    if count > crate::response::MAX_RESPONSE_STRINGS {
        return Err(Error::InvalidParameter(format!(
            "{field} exceeds maximum item count"
        )));
    }
    Ok(())
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
        formatter.write_str("a string, an unsigned integer, or null")
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
        deserializer.deserialize_any(Self)
    }

    fn visit_u64<E>(self, value: u64) -> core::result::Result<Self::Value, E> {
        Ok(Some(value.to_string()))
    }

    fn visit_i64<E>(self, value: i64) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let value =
            u64::try_from(value).map_err(|_| E::custom("duration seconds must not be negative"))?;
        Ok(Some(value.to_string()))
    }

    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E> {
        Ok(Some(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E> {
        Ok(Some(value))
    }
}

fn deserialize_bounded_library_account_map_or_default<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, LdapLibraryAccountStatus>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<BoundedLibraryAccountMap>::deserialize(deserializer)
        .map(|value| value.map(|value| value.0).unwrap_or_default())
}

#[derive(Deserialize)]
struct BoundedLibraryAccountMap(
    #[serde(deserialize_with = "deserialize_bounded_library_account_map")]
    BTreeMap<String, LdapLibraryAccountStatus>,
);

fn deserialize_bounded_library_account_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, LdapLibraryAccountStatus>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(
        BoundedLibraryAccountMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>,
    )
}

struct BoundedLibraryAccountMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedLibraryAccountMapVisitor<MAX> {
    type Value = BTreeMap<String, LdapLibraryAccountStatus>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} LDAP library accounts")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, LdapLibraryAccountStatus>()? else {
                return Ok(values);
            };
            if values.insert(key, value).is_some() {
                return Err(serde::de::Error::custom(
                    "OpenBao response map contains a duplicate key",
                ));
            }
        }
        if map
            .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
            .is_some()
        {
            return Err(serde::de::Error::custom(
                "OpenBao LDAP library account map exceeds item limit",
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

    use super::{
        LdapCheckOut, LdapConfig, LdapDynamicCredentials, LdapLibrarySet, LdapLibraryStatus,
        LdapList, LdapStaticCredentials,
    };

    #[test]
    fn ldap_paths_are_validated() {
        let config = OpenBaoConfig::new("http://127.0.0.1:8200")
            .and_then(OpenBaoConfig::allow_localhost_http)
            .unwrap_or_else(|error| panic!("{error}"));
        let client = Client::from_config(config)
            .unwrap_or_else(|error| panic!("{error}"))
            .with_token(SecretString::from("token"));
        let ldap = client
            .ldap_at("ldap")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            ldap.path(&["static-role", "app"])
                .unwrap_or_else(|error| panic!("{error}")),
            "ldap/static-role/app"
        );
        assert!(client.ldap_at("../ldap").is_err());
        assert!(ldap.path(&["static-role", "../app"]).is_err());
    }

    #[test]
    fn ldap_lists_are_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("role-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        assert!(serde_json::from_value::<LdapList>(value).is_err());

        let mut accounts = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            accounts.push((
                format!("account-{index}"),
                serde_json::json!({
                    "checked_out": false
                }),
            ));
        }
        let value = serde_json::json!({ "service_account_names": accounts.into_iter().collect::<serde_json::Map<_, _>>() });
        assert!(serde_json::from_value::<LdapLibraryStatus>(value).is_err());
    }

    #[test]
    fn ldap_debug_redacts_secret_fields() {
        let url_secret = ["ldap-uri", "-credential"].concat();
        let mut config = LdapConfig::new(
            "cn=openbao,ou=Users,dc=example,dc=com",
            SecretString::from("bind-password"),
        );
        config.url = Some(format!("ldap://test:{url_secret}@ldap.example.test"));
        let debug = format!("{config:?}");
        assert!(debug.contains("LdapConfig"));
        assert!(!debug.contains("bind-password"));
        assert!(!debug.contains(&url_secret));

        let static_credentials = LdapStaticCredentials {
            username: "app".to_owned(),
            dn: None,
            password: SecretString::from("current-password"),
            last_password: Some(SecretString::from("last-password")),
            last_vault_rotation: None,
            rotation_period: Some(3600),
            ttl: Some(300),
        };
        let debug = format!("{static_credentials:?}");
        assert!(!debug.contains(static_credentials.password.expose_secret()));
        assert!(!debug.contains("last-password"));

        let dynamic_credentials = LdapDynamicCredentials {
            username: "generated".to_owned(),
            password: SecretString::from("dynamic-password"),
            distinguished_names: vec!["cn=generated,ou=Users,dc=example,dc=com".to_owned()],
            lease_id: SecretString::from("ldap/creds/app/lease"),
            lease_duration: 3600,
            renewable: true,
        };
        let debug = format!("{dynamic_credentials:?}");
        assert!(!debug.contains(dynamic_credentials.password.expose_secret()));
        assert!(!debug.contains(dynamic_credentials.lease_id.expose_secret()));

        let checkout = LdapCheckOut {
            service_account_name: "service@example.com".to_owned(),
            password: SecretString::from("checkout-password"),
            lease_id: SecretString::from("ldap/library/app/check-out/lease"),
            lease_duration: 3600,
            renewable: true,
        };
        let debug = format!("{checkout:?}");
        assert!(!debug.contains(checkout.password.expose_secret()));
        assert!(!debug.contains(checkout.lease_id.expose_secret()));
    }

    #[test]
    fn ldap_request_validation_bounds_service_accounts() {
        let set = LdapLibrarySet::new(Vec::<String>::new());
        assert!(set.validate().is_err());

        let mut names = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            names.push(format!("service-{index}"));
        }
        let set = LdapLibrarySet::new(names);
        assert!(set.validate().is_err());
    }

    #[cfg(not(feature = "insecure-ldap-tls-acknowledged"))]
    #[test]
    fn ldap_insecure_tls_requires_acknowledgement_feature() {
        let mut config = LdapConfig::new("cn=openbao", SecretString::from("bind-password"));
        config.insecure_tls = Some(true);

        assert!(config.validate().is_err());
    }

    #[cfg(feature = "insecure-ldap-tls-acknowledged")]
    #[test]
    fn ldap_insecure_tls_rejects_bind_credentials_even_when_acknowledged() {
        let mut config = LdapConfig::new("cn=openbao", SecretString::from("bind-password"));
        config.insecure_tls = Some(true);

        assert!(config.validate().is_err());
    }

    #[cfg(not(feature = "insecure-ldap-tls-acknowledged"))]
    #[test]
    fn ldap_config_requires_encrypted_urls() {
        let mut config = LdapConfig::new("cn=openbao", SecretString::from("bind-password"))
            .with_url("ldap://ldap.example.com");
        assert!(config.validate().is_err());

        config.starttls = Some(true);
        assert!(config.validate().is_ok());

        let config = LdapConfig::new("cn=openbao", SecretString::from("bind-password"))
            .with_url("ldaps://ldap.example.com");
        assert!(config.validate().is_ok());
    }
}
