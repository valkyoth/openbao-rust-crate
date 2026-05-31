//! SSH secrets engine support.
//!
//! OTP credentials and generated private keys are treated as secret material
//! and are redacted from debug output.

use core::fmt;
use std::{collections::BTreeMap, net::IpAddr};

use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    Authenticated, Client, Error, Result,
    path::{validate_mount_path, validate_secret_path},
    response::{Empty, ResponseEnvelope, deserialize_bounded_string_vec},
};

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
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub roles: Vec<String>,
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

    /// Signs an SSH public key with a role.
    pub async fn sign(&self, role: &str, request: &SshSignRequest) -> Result<SshSignResponse> {
        let envelope: ResponseEnvelope<SshSignResponse> = self
            .client
            .request_json(Method::POST, &self.path(&["sign", role])?, Some(request))
            .await?;
        Ok(envelope.data)
    }

    /// Issues a generated SSH private key and certificate with a role.
    pub async fn issue(&self, role: &str, request: &SshIssueRequest) -> Result<SshIssueResponse> {
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
            segments.extend(validate_secret_path(segment)?);
        }
        Ok(segments.join("/"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use std::net::{IpAddr, Ipv4Addr};

    use secrecy::SecretString;

    use crate::{Client, OpenBaoConfig};

    use super::{SshCredentials, SshIssueResponse, SshRoleList, SshVerifyRequest};

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
    }
}
