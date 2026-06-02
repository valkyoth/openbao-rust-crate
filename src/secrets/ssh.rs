//! SSH secrets engine support.
//!
//! OTP credentials and generated private keys are treated as secret material
//! and are redacted from debug output.

use core::fmt;
use std::{collections::BTreeMap, net::IpAddr};

use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as DeError, IgnoredAny, MapAccess, Visitor},
};

use crate::{
    Authenticated, Client, Error, Result,
    path::{validate_endpoint_path, validate_mount_path},
    response::{Empty, ListEntries, ResponseEnvelope, deserialize_bounded_string_vec},
};

const MAX_SSH_FIELD_BYTES: usize = 4096;
const MAX_SSH_PUBLIC_KEY_BYTES: usize = 16 * 1024;
const MIN_RSA_KEY_BITS: u16 = 3072;

/// Handle for a mounted SSH secrets engine.
#[derive(Debug)]
pub struct Ssh<'a> {
    client: &'a Client<Authenticated>,
    mount: Vec<String>,
}

/// SSH role key type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SshRoleKeyType {
    /// One-time password credentials.
    Otp,
    /// SSH certificate authority signing credentials.
    Ca,
}

/// SSH certificate type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SshCertificateType {
    /// User certificate.
    User,
    /// Host certificate.
    Host,
}

/// Generated SSH key type for `/ssh/issue/:name`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SshIssueKeyType {
    /// RSA key.
    Rsa,
    /// Ed25519 key.
    Ed25519,
    /// ECDSA key.
    Ec,
}

/// SSH role list response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SshRoleList {
    /// Role names.
    #[serde(
        default,
        alias = "keys",
        deserialize_with = "deserialize_bounded_string_vec"
    )]
    pub roles: Vec<String>,
}

impl ListEntries for SshRoleList {
    fn entries(&self) -> &[String] {
        &self.roles
    }
}

/// SSH role create/update request.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SshRoleRequest {
    /// Default username for generated credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_user: Option<String>,
    /// Whether `default_user` is an identity template.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_user_template: Option<bool>,
    /// Comma-separated CIDR list for OTP roles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cidr_list: Option<String>,
    /// SSH port returned for OTP roles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Role credential type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<SshRoleKeyType>,
    /// Comma-separated allowed principal/user list for CA roles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_users: Option<String>,
    /// Whether `allowed_users` is an identity template.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_users_template: Option<bool>,
    /// Whether users/hosts outside configured lists are allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_user_certificates: Option<bool>,
    /// Whether host certificates are allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_host_certificates: Option<bool>,
    /// Whether bare domains are allowed in host certificate principals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_bare_domains: Option<bool>,
    /// Whether subdomains are allowed in host certificate principals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_subdomains: Option<bool>,
    /// Default certificate extensions.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub default_extensions: BTreeMap<String, String>,
    /// Allowed certificate extensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_extensions: Option<String>,
    /// Default critical options.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub default_critical_options: BTreeMap<String, String>,
    /// Allowed critical options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_critical_options: Option<String>,
    /// Default certificate TTL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Maximum certificate TTL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ttl: Option<String>,
    /// Issuer reference used by this role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_ref: Option<String>,
}

impl SshRoleRequest {
    /// Creates an OTP role request.
    pub fn otp(default_user: impl Into<String>, cidr_list: impl Into<String>) -> Self {
        Self {
            key_type: Some(SshRoleKeyType::Otp),
            default_user: Some(default_user.into()),
            cidr_list: Some(cidr_list.into()),
            ..Self::default()
        }
    }

    /// Creates a CA role request.
    pub fn ca(allowed_users: impl Into<String>) -> Self {
        Self {
            key_type: Some(SshRoleKeyType::Ca),
            allowed_users: Some(allowed_users.into()),
            allow_user_certificates: Some(true),
            ..Self::default()
        }
    }

    /// Sets the role TTL.
    #[must_use]
    pub fn with_ttl(mut self, ttl: impl Into<String>) -> Self {
        self.ttl = Some(ttl.into());
        self
    }

    /// Sets the role maximum TTL.
    #[must_use]
    pub fn with_max_ttl(mut self, max_ttl: impl Into<String>) -> Self {
        self.max_ttl = Some(max_ttl.into());
        self
    }

    fn validate(&self) -> Result<()> {
        validate_optional_ssh_field(self.default_user.as_deref(), "ssh default_user")?;
        validate_optional_ssh_field(self.cidr_list.as_deref(), "ssh cidr_list")?;
        validate_optional_ssh_field(self.allowed_users.as_deref(), "ssh allowed_users")?;
        validate_optional_duration(self.ttl.as_deref(), "ssh role ttl")?;
        validate_optional_duration(self.max_ttl.as_deref(), "ssh role max_ttl")?;
        Ok(())
    }
}

/// SSH role read response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SshRoleInfo {
    /// Default username for generated credentials.
    #[serde(default)]
    pub default_user: Option<String>,
    /// Comma-separated CIDR list.
    #[serde(default)]
    pub cidr_list: Option<String>,
    /// SSH port for OTP roles.
    #[serde(default)]
    pub port: Option<u16>,
    /// Role credential type.
    #[serde(default)]
    pub key_type: Option<SshRoleKeyType>,
    /// Allowed principal/user list.
    #[serde(default)]
    pub allowed_users: Option<String>,
    /// Default certificate TTL.
    #[serde(default)]
    pub ttl: Option<String>,
    /// Maximum certificate TTL.
    #[serde(default)]
    pub max_ttl: Option<String>,
    /// Issuer reference used by this role.
    #[serde(default)]
    pub issuer_ref: Option<String>,
}

/// SSH OTP credential request.
#[derive(Clone, Debug, Serialize)]
pub struct SshCredentialsRequest {
    /// Remote username.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Remote host IP.
    pub ip: IpAddr,
}

impl SshCredentialsRequest {
    /// Creates an SSH OTP credential request.
    #[must_use]
    pub fn new(ip: IpAddr) -> Self {
        Self { username: None, ip }
    }

    /// Sets the remote username.
    #[must_use]
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }
}

/// SSH OTP credential response.
#[derive(Clone, Deserialize)]
pub struct SshCredentials {
    /// Remote host IP.
    pub ip: String,
    /// One-time SSH credential. Treat as secret material.
    pub key: SecretString,
    /// Credential type.
    pub key_type: String,
    /// SSH port.
    pub port: u16,
    /// Remote username.
    pub username: String,
}

impl fmt::Debug for SshCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshCredentials")
            .field("ip", &self.ip)
            .field("key", &"<redacted>")
            .field("key_type", &self.key_type)
            .field("port", &self.port)
            .field("username", &self.username)
            .finish()
    }
}

/// SSH CA sign request.
#[derive(Clone, Debug, Serialize)]
pub struct SshSignRequest {
    /// SSH public key to sign.
    pub public_key: String,
    /// Requested certificate TTL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Comma-separated valid principals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_principals: Option<String>,
    /// Certificate type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_type: Option<SshCertificateType>,
    /// Certificate key ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Critical options.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub critical_options: BTreeMap<String, String>,
    /// Extensions.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, String>,
}

impl SshSignRequest {
    /// Creates a sign request from an SSH public key.
    pub fn new(public_key: impl Into<String>) -> Self {
        Self {
            public_key: public_key.into(),
            ttl: None,
            valid_principals: None,
            cert_type: None,
            key_id: None,
            critical_options: BTreeMap::new(),
            extensions: BTreeMap::new(),
        }
    }

    /// Sets valid principals.
    #[must_use]
    pub fn with_valid_principals(mut self, principals: impl Into<String>) -> Self {
        self.valid_principals = Some(principals.into());
        self
    }

    fn validate(&self) -> Result<()> {
        validate_ssh_public_key(&self.public_key)?;
        validate_optional_duration(self.ttl.as_deref(), "ssh sign ttl")?;
        validate_optional_ssh_field(self.valid_principals.as_deref(), "ssh valid_principals")?;
        Ok(())
    }
}

/// SSH CA sign response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SshSignResponse {
    /// Issuer ID used for signing.
    #[serde(default)]
    pub issuer_id: Option<String>,
    /// Certificate serial number.
    #[serde(default)]
    pub serial_number: Option<String>,
    /// Signed SSH certificate.
    pub signed_key: String,
}

/// SSH certificate and key issue request.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SshIssueRequest {
    /// Generated private key type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<SshIssueKeyType>,
    /// Generated key bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<u16>,
    /// Requested certificate TTL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Comma-separated valid principals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_principals: Option<String>,
    /// Certificate type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_type: Option<SshCertificateType>,
    /// Certificate key ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Critical options.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub critical_options: BTreeMap<String, String>,
    /// Extensions.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, String>,
}

impl SshIssueRequest {
    /// Creates a generated-key issue request.
    #[must_use]
    pub fn new(key_type: SshIssueKeyType) -> Self {
        Self {
            key_type: Some(key_type),
            ..Self::default()
        }
    }

    /// Sets generated key bits after validating the selected key type.
    pub fn with_key_bits(mut self, key_bits: u16) -> Result<Self> {
        self.key_bits = Some(key_bits);
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        validate_optional_duration(self.ttl.as_deref(), "ssh issue ttl")?;
        validate_ssh_issue_key_bits(self.key_type, self.key_bits)?;
        validate_optional_ssh_field(self.valid_principals.as_deref(), "ssh valid_principals")?;
        Ok(())
    }
}

/// SSH certificate and key issue response.
#[derive(Clone, Deserialize)]
pub struct SshIssueResponse {
    /// Issuer ID used for signing.
    #[serde(default)]
    pub issuer_id: Option<String>,
    /// Certificate serial number.
    #[serde(default)]
    pub serial_number: Option<String>,
    /// Signed SSH certificate.
    pub signed_key: String,
    /// Generated private key. Treat as secret material.
    pub private_key: SecretString,
    /// Generated private key type.
    pub private_key_type: String,
}

impl fmt::Debug for SshIssueResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshIssueResponse")
            .field("issuer_id", &self.issuer_id)
            .field("serial_number", &self.serial_number)
            .field("signed_key", &self.signed_key)
            .field("private_key", &"<redacted>")
            .field("private_key_type", &self.private_key_type)
            .finish()
    }
}

/// SSH issuer configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SshIssuerConfig {
    /// Default issuer reference.
    #[serde(rename = "default")]
    pub default_issuer: String,
}

/// SSH issuer configuration request.
#[derive(Clone, Debug, Serialize)]
pub struct SshIssuerConfigRequest {
    /// Default issuer reference.
    #[serde(rename = "default")]
    pub default_issuer: String,
}

impl SshIssuerConfigRequest {
    /// Creates a default issuer configuration request.
    pub fn new(default_issuer: impl Into<String>) -> Self {
        Self {
            default_issuer: default_issuer.into(),
        }
    }
}

/// SSH issuer list response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SshIssuerList {
    /// Issuer identifiers.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
    /// Issuer metadata keyed by issuer identifier.
    #[serde(default, deserialize_with = "deserialize_bounded_issuer_info_map")]
    pub key_info: BTreeMap<String, SshIssuerInfo>,
}

impl ListEntries for SshIssuerList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// SSH issuer metadata.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SshIssuerInfo {
    /// Issuer ID.
    #[serde(default)]
    pub issuer_id: Option<String>,
    /// Operator-assigned issuer name.
    #[serde(default)]
    pub issuer_name: Option<String>,
    /// Whether this issuer is the mount default.
    #[serde(default)]
    pub is_default: Option<bool>,
    /// SSH CA public key.
    pub public_key: String,
}

/// SSH CA submission request.
#[derive(Clone)]
pub struct SshCaSubmitRequest {
    /// Private key part of the SSH CA key pair. Treat as secret material.
    pub private_key: Option<SecretString>,
    /// Public key part of the SSH CA key pair.
    pub public_key: Option<String>,
    /// Whether OpenBao should generate the signing key pair internally.
    pub generate_signing_key: Option<bool>,
    /// Desired generated key type.
    pub key_type: Option<String>,
    /// Desired generated key bits.
    pub key_bits: Option<u16>,
    /// Whether a submitted named issuer should become the default issuer.
    pub set_default: Option<bool>,
}

impl SshCaSubmitRequest {
    /// Creates a request for OpenBao-generated SSH CA key material.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            private_key: None,
            public_key: None,
            generate_signing_key: Some(true),
            key_type: None,
            key_bits: None,
            set_default: None,
        }
    }

    /// Creates a request from caller-provided SSH CA key material.
    pub fn from_key_pair(private_key: SecretString, public_key: impl Into<String>) -> Self {
        Self {
            private_key: Some(private_key),
            public_key: Some(public_key.into()),
            generate_signing_key: Some(false),
            key_type: None,
            key_bits: None,
            set_default: None,
        }
    }

    /// Sets the generated key type.
    #[must_use]
    pub fn with_key_type(mut self, key_type: impl Into<String>) -> Self {
        self.key_type = Some(key_type.into());
        self
    }

    /// Sets the generated key bits.
    #[must_use]
    pub fn with_key_bits(mut self, key_bits: u16) -> Self {
        self.key_bits = Some(key_bits);
        self
    }

    /// Sets whether a named issuer should become the default issuer.
    #[must_use]
    pub fn with_set_default(mut self, set_default: bool) -> Self {
        self.set_default = Some(set_default);
        self
    }

    fn payload(&self) -> SshCaSubmitPayload<'_> {
        SshCaSubmitPayload {
            private_key: self.private_key.as_ref().map(SecretString::expose_secret),
            public_key: self.public_key.as_deref(),
            generate_signing_key: self.generate_signing_key,
            key_type: self.key_type.as_deref(),
            key_bits: self.key_bits,
            set_default: self.set_default,
        }
    }
}

impl fmt::Debug for SshCaSubmitRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshCaSubmitRequest")
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("public_key", &self.public_key)
            .field("generate_signing_key", &self.generate_signing_key)
            .field("key_type", &self.key_type)
            .field("key_bits", &self.key_bits)
            .field("set_default", &self.set_default)
            .finish()
    }
}

#[derive(Serialize)]
struct SshCaSubmitPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generate_signing_key: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_bits: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_default: Option<bool>,
}

/// SSH issuer update request.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SshIssuerUpdateRequest {
    /// New operator-assigned issuer name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_name: Option<String>,
}

impl SshIssuerUpdateRequest {
    /// Creates an issuer-name update request.
    #[must_use]
    pub fn new(issuer_name: impl Into<String>) -> Self {
        Self {
            issuer_name: Some(issuer_name.into()),
        }
    }
}

/// SSH CA public-key information.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SshPublicKeyInfo {
    /// Issuer ID.
    #[serde(default)]
    pub issuer_id: Option<String>,
    /// Issuer name.
    #[serde(default)]
    pub issuer_name: Option<String>,
    /// SSH CA public key.
    pub public_key: String,
}

/// SSH OTP verification request.
#[derive(Clone)]
pub struct SshVerifyRequest {
    /// One-time password to verify.
    pub otp: SecretString,
}

impl SshVerifyRequest {
    /// Creates an SSH OTP verification request.
    pub fn new(otp: SecretString) -> Self {
        Self { otp }
    }
}

impl fmt::Debug for SshVerifyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshVerifyRequest")
            .field("otp", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize)]
struct SshVerifyPayload<'a> {
    otp: &'a str,
}

/// SSH OTP verification response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SshVerifyResponse {
    /// Remote host IP associated with the OTP.
    pub ip: String,
    /// Remote username associated with the OTP.
    pub username: String,
}

#[derive(Serialize)]
struct SshLookupPayload {
    ip: IpAddr,
}

impl Client<Authenticated> {
    /// Uses the SSH secrets engine mounted at `mount`.
    pub fn ssh(&self, mount: impl Into<String>) -> Result<Ssh<'_>> {
        let mount = mount.into();
        Ok(Ssh {
            client: self,
            mount: validate_mount_path(&mount)?,
        })
    }
}

impl Ssh<'_> {
    /// Lists SSH role names.
    pub async fn list_roles(&self) -> Result<SshRoleList> {
        self.list_roles_after(None, None).await
    }

    /// Lists SSH role names with optional OpenBao pagination parameters.
    pub async fn list_roles_after(
        &self,
        after: Option<&str>,
        limit: Option<u64>,
    ) -> Result<SshRoleList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let mut query = Vec::new();
        if let Some(after) = after {
            query.push(("after", validate_mount_path(after)?.join("/")));
        }
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        let envelope: ResponseEnvelope<SshRoleList> = self
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

    /// Looks up roles that can issue OTP credentials for an IP address.
    pub async fn lookup_roles_by_ip(&self, ip: IpAddr) -> Result<SshRoleList> {
        let payload = SshLookupPayload { ip };
        let envelope: ResponseEnvelope<SshRoleList> = self
            .client
            .request_json(Method::POST, &self.path(&["lookup"])?, Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Creates or updates an SSH role.
    pub async fn write_role(&self, name: &str, request: &SshRoleRequest) -> Result<Empty> {
        request.validate()?;
        self.client
            .request_json(Method::POST, &self.path(&["roles", name])?, Some(request))
            .await
    }

    /// Reads an SSH role.
    pub async fn read_role(&self, name: &str) -> Result<SshRoleInfo> {
        let envelope: ResponseEnvelope<SshRoleInfo> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["roles", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes an SSH role.
    pub async fn delete_role(&self, name: &str) -> Result<Empty> {
        self.client
            .request_json(
                Method::DELETE,
                &self.path(&["roles", name])?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Reads zero-address role configuration.
    pub async fn read_zero_address_roles(&self) -> Result<SshRoleList> {
        let envelope: ResponseEnvelope<SshRoleList> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["config", "zeroaddress"])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Configures zero-address roles.
    pub async fn write_zero_address_roles(&self, roles: &[String]) -> Result<Empty> {
        #[derive(Serialize)]
        struct Payload<'a> {
            roles: &'a [String],
        }
        self.client
            .request_json(
                Method::POST,
                &self.path(&["config", "zeroaddress"])?,
                Some(&Payload { roles }),
            )
            .await
    }

    /// Deletes zero-address role configuration.
    pub async fn delete_zero_address_roles(&self) -> Result<Empty> {
        self.client
            .request_json(
                Method::DELETE,
                &self.path(&["config", "zeroaddress"])?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Generates SSH OTP credentials for a role.
    pub async fn credentials(
        &self,
        role: &str,
        request: &SshCredentialsRequest,
    ) -> Result<SshCredentials> {
        let envelope: ResponseEnvelope<SshCredentials> = self
            .client
            .request_json(Method::POST, &self.path(&["creds", role])?, Some(request))
            .await?;
        Ok(envelope.data)
    }

    /// Reads the default issuer configuration.
    pub async fn read_issuer_config(&self) -> Result<SshIssuerConfig> {
        let envelope: ResponseEnvelope<SshIssuerConfig> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["config", "issuers"])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Sets the default issuer configuration.
    pub async fn write_issuer_config(
        &self,
        request: &SshIssuerConfigRequest,
    ) -> Result<SshIssuerConfig> {
        let envelope: ResponseEnvelope<SshIssuerConfig> = self
            .client
            .request_json(
                Method::POST,
                &self.path(&["config", "issuers"])?,
                Some(request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists SSH issuers.
    pub async fn list_issuers(&self) -> Result<SshIssuerList> {
        self.list_issuers_after(None, None).await
    }

    /// Lists SSH issuers with optional OpenBao pagination parameters.
    pub async fn list_issuers_after(
        &self,
        after: Option<&str>,
        limit: Option<u64>,
    ) -> Result<SshIssuerList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let mut query = Vec::new();
        if let Some(after) = after {
            query.push(("after", validate_mount_path(after)?.join("/")));
        }
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        let envelope: ResponseEnvelope<SshIssuerList> = self
            .client
            .request_json_query_accepting(
                method,
                &self.path(&["issuers"])?,
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Submits CA information and assigns it to the default issuer reference.
    pub async fn submit_default_ca(&self, request: &SshCaSubmitRequest) -> Result<SshIssuerInfo> {
        let payload = request.payload();
        let envelope: ResponseEnvelope<SshIssuerInfo> = self
            .client
            .request_json(Method::POST, &self.path(&["config", "ca"])?, Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Submits CA information as a new issuer, optionally with an explicit name.
    pub async fn submit_issuer(
        &self,
        issuer_name: Option<&str>,
        request: &SshCaSubmitRequest,
    ) -> Result<SshIssuerInfo> {
        let payload = request.payload();
        let path = if let Some(issuer_name) = issuer_name {
            self.path(&["issuers", "import", issuer_name])?
        } else {
            self.path(&["issuers", "import"])?
        };
        let envelope: ResponseEnvelope<SshIssuerInfo> = self
            .client
            .request_json(Method::POST, &path, Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    /// Reads SSH issuer metadata by issuer ID, name, or `default`.
    pub async fn read_issuer(&self, issuer_ref: &str) -> Result<SshIssuerInfo> {
        let envelope: ResponseEnvelope<SshIssuerInfo> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["issuer", issuer_ref])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Updates SSH issuer metadata by issuer ID, name, or `default`.
    ///
    /// OpenBao supports both `POST` and `PATCH`; this helper uses `PATCH`
    /// because the request represents a partial metadata update.
    pub async fn update_issuer(
        &self,
        issuer_ref: &str,
        request: &SshIssuerUpdateRequest,
    ) -> Result<SshIssuerInfo> {
        let envelope: ResponseEnvelope<SshIssuerInfo> = self
            .client
            .request_json(
                Method::PATCH,
                &self.path(&["issuer", issuer_ref])?,
                Some(request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Reads the authenticated default CA public key metadata.
    pub async fn read_ca_public_key(&self) -> Result<SshPublicKeyInfo> {
        let envelope: ResponseEnvelope<SshPublicKeyInfo> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["config", "ca"])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes all SSH CA information in the mount, including the default issuer.
    pub async fn delete_ca_information(&self) -> Result<Empty> {
        self.client
            .request_json_accepting(
                Method::DELETE,
                &self.path(&["config", "ca"])?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Deletes an SSH issuer by issuer ID, name, or `default`.
    pub async fn delete_issuer(&self, issuer_ref: &str) -> Result<Empty> {
        self.client
            .request_json_accepting(
                Method::DELETE,
                &self.path(&["issuer", issuer_ref])?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Signs an SSH public key with a role.
    pub async fn sign(&self, role: &str, request: &SshSignRequest) -> Result<SshSignResponse> {
        request.validate()?;
        let envelope: ResponseEnvelope<SshSignResponse> = self
            .client
            .request_json(Method::POST, &self.path(&["sign", role])?, Some(request))
            .await?;
        Ok(envelope.data)
    }

    /// Issues a generated SSH private key and certificate with a role.
    pub async fn issue(&self, role: &str, request: &SshIssueRequest) -> Result<SshIssueResponse> {
        request.validate()?;
        let envelope: ResponseEnvelope<SshIssueResponse> = self
            .client
            .request_json(Method::POST, &self.path(&["issue", role])?, Some(request))
            .await?;
        Ok(envelope.data)
    }

    /// Verifies an SSH OTP.
    pub async fn verify(&self, request: &SshVerifyRequest) -> Result<SshVerifyResponse> {
        let payload = SshVerifyPayload {
            otp: request.otp.expose_secret(),
        };
        let envelope: ResponseEnvelope<SshVerifyResponse> = self
            .client
            .request_json(Method::POST, &self.path(&["verify"])?, Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    fn path(&self, tail: &[&str]) -> Result<String> {
        let mut segments = self.mount.clone();
        for segment in tail {
            segments.extend(validate_endpoint_path(segment)?);
        }
        Ok(segments.join("/"))
    }
}

fn validate_ssh_public_key(public_key: &str) -> Result<()> {
    let trimmed = public_key.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidParameter(
            "SSH public key must not be empty".into(),
        ));
    }
    if trimmed.len() > MAX_SSH_PUBLIC_KEY_BYTES {
        return Err(Error::InvalidParameter(
            "SSH public key exceeds maximum allowed length".into(),
        ));
    }
    if trimmed.as_bytes().iter().any(u8::is_ascii_control) {
        return Err(Error::InvalidParameter(
            "SSH public key must not contain control characters".into(),
        ));
    }
    const ALLOWED_PREFIXES: &[&str] = &[
        "ssh-rsa ",
        "rsa-sha2-256 ",
        "rsa-sha2-512 ",
        "ssh-ed25519 ",
        "sk-ssh-ed25519@openssh.com ",
        "ecdsa-sha2-nistp256 ",
        "ecdsa-sha2-nistp384 ",
        "ecdsa-sha2-nistp521 ",
    ];
    if !ALLOWED_PREFIXES
        .iter()
        .any(|prefix| trimmed.starts_with(prefix))
    {
        return Err(Error::InvalidParameter(
            "SSH public key must use an approved algorithm prefix".into(),
        ));
    }
    Ok(())
}

fn validate_optional_ssh_field(value: Option<&str>, field: &'static str) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_empty() {
        return Err(Error::InvalidParameter(format!(
            "{field} must not be empty"
        )));
    }
    if value.len() > MAX_SSH_FIELD_BYTES {
        return Err(Error::InvalidParameter(format!(
            "{field} exceeds maximum allowed length"
        )));
    }
    if value.as_bytes().iter().any(u8::is_ascii_control) {
        return Err(Error::InvalidParameter(format!(
            "{field} must not contain control characters"
        )));
    }
    Ok(())
}

fn validate_optional_duration(value: Option<&str>, field: &'static str) -> Result<()> {
    if let Some(value) = value {
        crate::validation::validate_duration_parameter(value, field)?;
    }
    Ok(())
}

fn validate_ssh_issue_key_bits(
    key_type: Option<SshIssueKeyType>,
    key_bits: Option<u16>,
) -> Result<()> {
    let Some(key_bits) = key_bits else {
        return Ok(());
    };
    match key_type.unwrap_or(SshIssueKeyType::Rsa) {
        SshIssueKeyType::Rsa if key_bits < MIN_RSA_KEY_BITS => Err(Error::InvalidParameter(
            "SSH RSA key_bits must be at least 3072".into(),
        )),
        SshIssueKeyType::Ec if !matches!(key_bits, 256 | 384 | 521) => Err(
            Error::InvalidParameter("SSH EC key_bits must be 256, 384, or 521".into()),
        ),
        SshIssueKeyType::Ed25519 => Err(Error::InvalidParameter(
            "SSH Ed25519 key_bits must be omitted".into(),
        )),
        _ => Ok(()),
    }
}

fn deserialize_bounded_issuer_info_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, SshIssuerInfo>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer
        .deserialize_map(SshIssuerInfoMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

struct SshIssuerInfoMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for SshIssuerInfoMapVisitor<MAX> {
    type Value = BTreeMap<String, SshIssuerInfo>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} SSH issuer records")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, SshIssuerInfo>()? else {
                return Ok(values);
            };
            values.insert(key, value);
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "OpenBao SSH issuer map exceeds item limit",
            ));
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(deprecated)]

    use std::net::{IpAddr, Ipv4Addr};

    use secrecy::SecretString;

    use crate::{Client, OpenBaoConfig};

    use super::{
        SshCaSubmitRequest, SshCredentials, SshIssueKeyType, SshIssueRequest, SshIssueResponse,
        SshIssuerList, SshRoleList, SshRoleRequest, SshSignRequest, SshVerifyRequest,
    };

    #[test]
    fn ssh_paths_are_validated() {
        let config = OpenBaoConfig::new("http://127.0.0.1:8200")
            .and_then(OpenBaoConfig::allow_localhost_http)
            .unwrap_or_else(|error| panic!("{error}"));
        let client = Client::from_config(config)
            .unwrap_or_else(|error| panic!("{error}"))
            .with_token(SecretString::from("token"));
        let ssh = client.ssh("ssh").unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            ssh.path(&["roles", "web"])
                .unwrap_or_else(|error| panic!("{error}")),
            "ssh/roles/web"
        );
        assert!(ssh.path(&["roles", "../web"]).is_err());
    }

    #[test]
    fn ssh_role_lists_are_bounded() {
        let keys = serde_json::json!({ "keys": ["role-a"] });
        let list: SshRoleList =
            serde_json::from_value(keys).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(list.roles, ["role-a"]);

        let mut roles = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            roles.push(format!("role-{index}"));
        }
        let value = serde_json::json!({ "roles": roles });
        let error = match serde_json::from_value::<SshRoleList>(value) {
            Ok(_) => panic!("oversized SSH role list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn ssh_request_inputs_are_validated() {
        let role = SshRoleRequest::otp("alice", "127.0.0.1/32").with_ttl("30m");
        assert!(role.validate().is_ok());

        let role = SshRoleRequest::otp("alice", "127.0.0.1/32").with_ttl("forever");
        assert!(role.validate().is_err());

        let role = SshRoleRequest::otp("alice", "127.0.0.1/32\nbad");
        assert!(role.validate().is_err());

        let sign = SshSignRequest::new("ssh-rsa AAAA test").with_valid_principals("alice,bob");
        assert!(sign.validate().is_ok());

        let sign = SshSignRequest::new("ssh-dss AAAA weak");
        assert!(sign.validate().is_err());

        let sign = SshSignRequest::new("ssh-rsa AAAA\nbad");
        assert!(sign.validate().is_err());

        assert!(
            SshIssueRequest::new(SshIssueKeyType::Rsa)
                .with_key_bits(2048)
                .is_err()
        );
        assert!(
            SshIssueRequest::new(SshIssueKeyType::Rsa)
                .with_key_bits(3072)
                .is_ok()
        );
    }

    #[test]
    fn ssh_issuer_lists_are_bounded() {
        let mut key_info = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            key_info.insert(
                format!("issuer-{index}"),
                serde_json::json!({ "public_key": "ssh-rsa AAAA" }),
            );
        }
        let value = serde_json::json!({ "keys": ["issuer-0"], "key_info": key_info });
        let error = match serde_json::from_value::<SshIssuerList>(value) {
            Ok(_) => panic!("oversized SSH issuer map unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn ssh_secret_debug_is_redacted() {
        let credentials = SshCredentials {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST).to_string(),
            key: SecretString::from(["otp-", "secret"].concat()),
            key_type: "otp".to_owned(),
            port: 22,
            username: "alice".to_owned(),
        };
        let credentials_debug = format!("{credentials:?}");
        assert!(!credentials_debug.contains(&["otp-", "secret"].concat()));
        assert!(credentials_debug.contains("redacted"));

        let issue = SshIssueResponse {
            issuer_id: Some("issuer".to_owned()),
            serial_number: Some("serial".to_owned()),
            signed_key: "ssh-rsa-cert-v01 cert".to_owned(),
            private_key: SecretString::from(["private-", "key"].concat()),
            private_key_type: "rsa".to_owned(),
        };
        let issue_debug = format!("{issue:?}");
        assert!(!issue_debug.contains(&["private-", "key"].concat()));
        assert!(issue_debug.contains("redacted"));

        let verify = SshVerifyRequest::new(SecretString::from(["verify-", "secret"].concat()));
        let verify_debug = format!("{verify:?}");
        assert!(!verify_debug.contains(&["verify-", "secret"].concat()));
        assert!(verify_debug.contains("redacted"));

        let submit = SshCaSubmitRequest::from_key_pair(
            SecretString::from(["ssh-ca-private-", "key"].concat()),
            "ssh-rsa AAAA",
        );
        let submit_debug = format!("{submit:?}");
        assert!(!submit_debug.contains(&["ssh-ca-private-", "key"].concat()));
        assert!(submit_debug.contains("redacted"));
    }
}
