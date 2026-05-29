//! PKI secrets engine support.

use core::fmt;

use reqwest::{Method, StatusCode};
use secrecy::SecretString;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{IgnoredAny, SeqAccess, Visitor},
};

use crate::{
    Authenticated, Client, Error, Result,
    path::{validate_mount_path, validate_secret_path},
    response::{Empty, ResponseEnvelope, deserialize_bounded_string_vec},
};

/// Handle for a mounted PKI secrets engine.
#[derive(Debug)]
pub struct Pki<'a> {
    client: &'a Client<Authenticated>,
    mount: Vec<String>,
}

/// PKI role configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PkiRole {
    /// Issuer reference used by this role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_ref: Option<String>,
    /// Allowed DNS domains.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_domains: Vec<String>,
    /// Allows issuing for the bare allowed domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_bare_domains: Option<bool>,
    /// Allows issuing for subdomains of allowed domains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_subdomains: Option<bool>,
    /// Allows glob domain matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_glob_domains: Option<bool>,
    /// Allows any common name or SAN value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_any_name: Option<bool>,
    /// Enforces hostnames in certificate names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforce_hostnames: Option<bool>,
    /// Allows localhost names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_localhost: Option<bool>,
    /// Allows wildcard certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_wildcard_certificates: Option<bool>,
    /// Key usages for issued certificates.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub key_usage: Vec<String>,
    /// Extended key usages for issued certificates.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ext_key_usage: Vec<String>,
    /// Extended key usage OIDs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ext_key_usage_oids: Vec<String>,
    /// Whether generated certificates include server auth usage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_flag: Option<bool>,
    /// Whether generated certificates include client auth usage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_flag: Option<bool>,
    /// Whether generated certificates include code signing usage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_signing_flag: Option<bool>,
    /// Whether generated certificates include email protection usage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_protection_flag: Option<bool>,
    /// Generated private key type, such as `rsa` or `ec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    /// Generated private key bits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<u64>,
    /// Certificate TTL such as `24h`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Maximum certificate TTL such as `720h`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl: Option<String>,
    /// Not-before skew duration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before_duration: Option<String>,
    /// Whether key usage is marked critical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_usage_critical: Option<bool>,
    /// Whether basic constraints are marked critical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic_constraints_valid_for_non_ca: Option<bool>,
    /// Whether issued certificates are not stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_store: Option<bool>,
}

/// PKI role list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiRoleList {
    /// Role names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

/// PKI URL configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PkiUrlsConfig {
    /// Issuing certificate URLs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub issuing_certificates: Vec<String>,
    /// CRL distribution point URLs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub crl_distribution_points: Vec<String>,
    /// OCSP server URLs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ocsp_servers: Vec<String>,
    /// Enables templating in configured URLs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_templating: Option<bool>,
}

/// PKI authority key generation mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PkiKeyGenerationType {
    /// Generate key material inside OpenBao and do not return it.
    Internal,
    /// Generate key material inside OpenBao and return the private key.
    Exported,
    /// Use an existing key reference when supported by OpenBao.
    Existing,
}

impl PkiKeyGenerationType {
    fn as_path_segment(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::Exported => "exported",
            Self::Existing => "existing",
        }
    }
}

/// Request for generating a root CA certificate.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PkiGenerateRootRequest {
    /// Common name for the generated root.
    pub common_name: String,
    /// Issuer display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_name: Option<String>,
    /// Requested TTL such as `87600h`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Certificate return format, such as `pem`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Private key return format for exported generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_format: Option<String>,
    /// Key type, such as `rsa` or `ec`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    /// Key size in bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<u64>,
    /// Existing key reference for `existing` generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<String>,
    /// Excludes the common name from SANs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_cn_from_sans: Option<bool>,
}

/// Request for generating an intermediate CA CSR.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PkiGenerateIntermediateRequest {
    /// Common name for the intermediate.
    pub common_name: String,
    /// Issuer display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_name: Option<String>,
    /// Certificate return format, such as `pem`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Private key return format for exported generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_format: Option<String>,
    /// Key type, such as `rsa` or `ec`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    /// Key size in bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<u64>,
    /// Existing key reference for `existing` generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<String>,
}

/// Response from root or intermediate authority generation.
#[derive(Clone, Deserialize)]
pub struct PkiAuthorityBundle {
    /// Generated certificate, when returned.
    #[serde(default)]
    pub certificate: Option<String>,
    /// Generated CSR, when returned.
    #[serde(default)]
    pub csr: Option<String>,
    /// Issuing CA certificate.
    #[serde(default)]
    pub issuing_ca: Option<String>,
    /// CA certificate chain.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub ca_chain: Vec<String>,
    /// Generated private key, when OpenBao returned one.
    #[serde(default)]
    pub private_key: Option<SecretString>,
    /// Generated private key type, when returned.
    #[serde(default)]
    pub private_key_type: Option<String>,
    /// Certificate serial number.
    #[serde(default)]
    pub serial_number: Option<String>,
    /// Certificate expiration as Unix seconds.
    #[serde(default)]
    pub expiration: Option<u64>,
}

impl fmt::Debug for PkiAuthorityBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PkiAuthorityBundle")
            .field("certificate", &self.certificate)
            .field("csr", &self.csr)
            .field("issuing_ca", &self.issuing_ca)
            .field("ca_chain", &self.ca_chain)
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("private_key_type", &self.private_key_type)
            .field("serial_number", &self.serial_number)
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// Request for signing an intermediate CA CSR with the root.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PkiSignIntermediateRequest {
    /// PEM-format intermediate CSR.
    pub csr: String,
    /// Common name override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    /// Issuer reference that signs the CSR.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_ref: Option<String>,
    /// Issuer display name for the generated issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_name: Option<String>,
    /// Requested TTL such as `43800h`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Certificate return format, such as `pem`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Uses subject and SAN values from the CSR where supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_csr_values: Option<bool>,
    /// Maximum path length for issued CA certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_path_length: Option<i64>,
    /// Permitted DNS domains for the intermediate.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub permitted_dns_domains: Vec<String>,
}

/// Request for installing a signed intermediate certificate.
#[derive(Clone, Debug, Serialize)]
pub struct PkiSetSignedIntermediateRequest {
    /// PEM-format signed intermediate certificate.
    pub certificate: String,
}

/// PKI CRL configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PkiCrlConfig {
    /// CRL expiry duration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    /// Disables CRL generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable: Option<bool>,
    /// Disables OCSP responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsp_disable: Option<bool>,
    /// Enables automatic CRL rebuild.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_rebuild: Option<bool>,
    /// Grace period used before automatic CRL rebuild.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_rebuild_grace_period: Option<String>,
    /// Enables delta CRL generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_delta: Option<bool>,
    /// Delta CRL rebuild interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_rebuild_interval: Option<String>,
}

/// PKI tidy request.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PkiTidyRequest {
    /// Tidies stored certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidy_cert_store: Option<bool>,
    /// Tidies revoked certificate entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidy_revoked_certs: Option<bool>,
    /// Tidies certificate revocation queue entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidy_revocation_queue: Option<bool>,
    /// Safety buffer duration before deleting entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety_buffer: Option<String>,
    /// Tidies ACME state where supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidy_acme: Option<bool>,
}

/// CRL rotation response.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiRotateCrlResponse {
    /// Whether rotation succeeded.
    #[serde(default)]
    pub success: bool,
}

/// Request for issuing a certificate and private key.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PkiIssueRequest {
    /// Common name for the certificate.
    pub common_name: String,
    /// Requested alternative names.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alt_names: Vec<String>,
    /// Requested IP SANs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ip_sans: Vec<String>,
    /// Requested URI SANs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uri_sans: Vec<String>,
    /// Requested TTL such as `24h`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Certificate return format, such as `pem` or `der`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Private key return format, such as `der` or `pkcs8`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_format: Option<String>,
    /// Excludes the common name from DNS SANs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_cn_from_sans: Option<bool>,
}

/// Request for signing a caller-provided CSR.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PkiSignRequest {
    /// PEM-format certificate signing request.
    pub csr: String,
    /// Optional common name override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    /// Requested alternative names.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alt_names: Vec<String>,
    /// Requested IP SANs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ip_sans: Vec<String>,
    /// Requested URI SANs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uri_sans: Vec<String>,
    /// Requested TTL such as `24h`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Certificate return format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// Response from PKI issue/sign endpoints.
#[derive(Clone, Deserialize)]
pub struct PkiCertificateBundle {
    /// Issued certificate.
    pub certificate: String,
    /// Issuing CA certificate.
    #[serde(default)]
    pub issuing_ca: Option<String>,
    /// CA certificate chain.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub ca_chain: Vec<String>,
    /// Generated private key, if OpenBao returned one.
    #[serde(default)]
    pub private_key: Option<SecretString>,
    /// Generated private key type, if OpenBao returned one.
    #[serde(default)]
    pub private_key_type: Option<String>,
    /// Certificate serial number.
    #[serde(default)]
    pub serial_number: Option<String>,
    /// Certificate expiration as Unix seconds.
    #[serde(default)]
    pub expiration: Option<u64>,
}

impl fmt::Debug for PkiCertificateBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PkiCertificateBundle")
            .field("certificate", &self.certificate)
            .field("issuing_ca", &self.issuing_ca)
            .field("ca_chain", &self.ca_chain)
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("private_key_type", &self.private_key_type)
            .field("serial_number", &self.serial_number)
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// Request for revoking a certificate by serial number.
#[derive(Clone, Debug, Serialize)]
pub struct PkiRevokeRequest {
    /// Certificate serial number.
    pub serial_number: String,
}

/// Response from certificate revocation.
#[derive(Clone, Debug, Deserialize)]
pub struct PkiRevokeResponse {
    /// Revocation time as Unix seconds.
    #[serde(default)]
    pub revocation_time: Option<u64>,
    /// Revocation time formatted as RFC3339, when returned.
    #[serde(default)]
    pub revocation_time_rfc3339: Option<String>,
}

/// Certificate list response.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiCertificateList {
    /// Certificate serial numbers.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

/// Read certificate response.
#[derive(Clone, Debug, Deserialize)]
pub struct PkiCertificate {
    /// PEM-format certificate.
    pub certificate: String,
}

/// PKI issuer list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiIssuerList {
    /// Issuer identifiers or names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

/// PKI issuer metadata returned by OpenBao.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiIssuerInfo {
    /// Issuer identifier.
    #[serde(default)]
    pub issuer_id: Option<String>,
    /// Issuer display name.
    #[serde(default)]
    pub issuer_name: Option<String>,
    /// Backing key identifier.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Backing key display name.
    #[serde(default)]
    pub key_name: Option<String>,
    /// Issuer certificate.
    #[serde(default)]
    pub certificate: Option<String>,
    /// CA certificate chain.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    pub ca_chain: Vec<String>,
    /// Manual chain references configured for this issuer.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    pub manual_chain: Vec<String>,
    /// CRL distribution point URLs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    pub crl_distribution_points: Vec<String>,
    /// Issuing certificate URLs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    pub issuing_certificates: Vec<String>,
    /// OCSP server URLs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    pub ocsp_servers: Vec<String>,
    /// Usage flags reported by OpenBao.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    pub usage: Vec<String>,
    /// Leaf not-after behavior reported by OpenBao.
    #[serde(default)]
    pub leaf_not_after_behavior: Option<String>,
}

/// PKI key list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiKeyList {
    /// Key identifiers or names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

/// PKI key metadata returned by OpenBao.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiKeyInfo {
    /// Key identifier.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Key display name.
    #[serde(default)]
    pub key_name: Option<String>,
    /// Key type, such as `rsa` or `ec`.
    #[serde(default)]
    pub key_type: Option<String>,
    /// Key size in bits, when OpenBao returns it.
    #[serde(default)]
    pub key_bits: Option<u64>,
}

impl Client<Authenticated> {
    /// Uses the PKI engine mounted at `mount`.
    pub fn pki(&self, mount: impl Into<String>) -> Result<Pki<'_>> {
        let mount = mount.into();
        Ok(Pki {
            client: self,
            mount: validate_mount_path(&mount)?,
        })
    }
}

impl Pki<'_> {
    /// Generates a root CA certificate.
    pub async fn generate_root(
        &self,
        generation_type: PkiKeyGenerationType,
        request: &PkiGenerateRootRequest,
    ) -> Result<PkiAuthorityBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&["root", "generate", generation_type.as_path_segment()])?,
            Some(request),
        )
        .await
    }

    /// Generates an intermediate CA CSR and key material.
    pub async fn generate_intermediate(
        &self,
        generation_type: PkiKeyGenerationType,
        request: &PkiGenerateIntermediateRequest,
    ) -> Result<PkiAuthorityBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&[
                "intermediate",
                "generate",
                generation_type.as_path_segment(),
            ])?,
            Some(request),
        )
        .await
    }

    /// Signs an intermediate CA CSR with the mounted root.
    pub async fn sign_intermediate(
        &self,
        request: &PkiSignIntermediateRequest,
    ) -> Result<PkiCertificateBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&["root", "sign-intermediate"])?,
            Some(request),
        )
        .await
    }

    /// Installs a signed intermediate certificate.
    pub async fn set_signed_intermediate(
        &self,
        request: &PkiSetSignedIntermediateRequest,
    ) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                &self.path(&["intermediate", "set-signed"])?,
                Some(request),
            )
            .await
    }

    /// Creates or replaces a PKI role.
    pub async fn write_role(&self, name: &str, role: &PkiRole) -> Result<Empty> {
        self.client
            .request_json(Method::POST, &self.path(&["roles", name])?, Some(role))
            .await
    }

    /// Reads a PKI role.
    pub async fn read_role(&self, name: &str) -> Result<PkiRole> {
        self.enveloped(
            Method::GET,
            &self.path(&["roles", name])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Lists PKI role names.
    pub async fn list_roles(&self) -> Result<PkiRoleList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        self.enveloped(method, &self.path(&["roles"])?, Option::<&Empty>::None)
            .await
    }

    /// Deletes a PKI role.
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

    /// Reads PKI URL configuration.
    pub async fn read_urls(&self) -> Result<PkiUrlsConfig> {
        self.enveloped(
            Method::GET,
            &self.path(&["config", "urls"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Sets PKI URL configuration.
    pub async fn write_urls(&self, config: &PkiUrlsConfig) -> Result<Empty> {
        self.client
            .request_json(Method::POST, &self.path(&["config", "urls"])?, Some(config))
            .await
    }

    /// Reads PKI CRL configuration.
    pub async fn read_crl_config(&self) -> Result<PkiCrlConfig> {
        self.enveloped(
            Method::GET,
            &self.path(&["config", "crl"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Sets PKI CRL configuration.
    pub async fn write_crl_config(&self, config: &PkiCrlConfig) -> Result<Empty> {
        self.client
            .request_json(Method::POST, &self.path(&["config", "crl"])?, Some(config))
            .await
    }

    /// Rotates the CRL.
    pub async fn rotate_crl(&self) -> Result<PkiRotateCrlResponse> {
        self.enveloped(
            Method::POST,
            &self.path(&["crl", "rotate"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Starts PKI tidy with the requested options.
    pub async fn tidy(&self, request: &PkiTidyRequest) -> Result<Empty> {
        self.client
            .request_json(Method::POST, &self.path(&["tidy"])?, Some(request))
            .await
    }

    /// Issues a certificate and private key using a PKI role.
    pub async fn issue(
        &self,
        role: &str,
        request: &PkiIssueRequest,
    ) -> Result<PkiCertificateBundle> {
        self.enveloped(Method::POST, &self.path(&["issue", role])?, Some(request))
            .await
    }

    /// Signs a caller-provided CSR using a PKI role.
    pub async fn sign(&self, role: &str, request: &PkiSignRequest) -> Result<PkiCertificateBundle> {
        self.enveloped(Method::POST, &self.path(&["sign", role])?, Some(request))
            .await
    }

    /// Revokes a certificate by serial number.
    pub async fn revoke(&self, request: &PkiRevokeRequest) -> Result<PkiRevokeResponse> {
        self.enveloped(Method::POST, &self.path(&["revoke"])?, Some(request))
            .await
    }

    /// Lists known certificate serial numbers.
    pub async fn list_certificates(&self) -> Result<PkiCertificateList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        self.enveloped(method, &self.path(&["certs"])?, Option::<&Empty>::None)
            .await
    }

    /// Reads a certificate by serial number.
    pub async fn read_certificate(&self, serial: &str) -> Result<PkiCertificate> {
        self.enveloped(
            Method::GET,
            &self.path(&["cert", serial])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Lists PKI issuers.
    pub async fn list_issuers(&self) -> Result<PkiIssuerList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        self.enveloped(method, &self.path(&["issuers"])?, Option::<&Empty>::None)
            .await
    }

    /// Reads PKI issuer metadata by issuer reference.
    pub async fn read_issuer(&self, issuer_ref: &str) -> Result<PkiIssuerInfo> {
        self.enveloped(
            Method::GET,
            &self.path(&["issuer", issuer_ref])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Deletes a PKI issuer by issuer reference.
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

    /// Lists PKI keys.
    pub async fn list_keys(&self) -> Result<PkiKeyList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        self.enveloped(method, &self.path(&["keys"])?, Option::<&Empty>::None)
            .await
    }

    /// Reads PKI key metadata by key reference.
    pub async fn read_key(&self, key_ref: &str) -> Result<PkiKeyInfo> {
        self.enveloped(
            Method::GET,
            &self.path(&["key", key_ref])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Deletes a PKI key by key reference.
    pub async fn delete_key(&self, key_ref: &str) -> Result<Empty> {
        self.client
            .request_json_accepting(
                Method::DELETE,
                &self.path(&["key", key_ref])?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    async fn enveloped<T, B>(&self, method: Method, path: &str, request: Option<&B>) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
        B: Serialize + ?Sized,
    {
        let envelope: ResponseEnvelope<T> = self.client.request_json(method, path, request).await?;
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

    fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&value)
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while values.len() < MAX {
            let Some(value) = seq.next_element::<String>()? else {
                return Ok(values);
            };
            values.push(value);
        }
        if seq.next_element::<IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(
                "OpenBao string list exceeds item limit",
            ));
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::{ExposeSecret, SecretString};

    use super::{
        PkiAuthorityBundle, PkiCertificateBundle, PkiIssuerInfo, PkiIssuerList, PkiKeyList,
        PkiRole, PkiRoleList,
    };

    #[test]
    fn pki_role_accepts_string_and_array_lists() {
        let role: PkiRole = serde_json::from_str(
            r#"{"allowed_domains":"example.com,api.example.com","key_usage":["DigitalSignature"]}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(role.allowed_domains, ["example.com", "api.example.com"]);
        assert_eq!(role.key_usage, ["DigitalSignature"]);
    }

    #[test]
    fn pki_certificate_bundle_redacts_private_key_debug() {
        let bundle: PkiCertificateBundle = serde_json::from_str(
            r#"{"certificate":"cert","private_key":"secret-key","serial_number":"01"}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            bundle.private_key.as_ref().map(SecretString::expose_secret),
            Some("secret-key")
        );
        let debug = format!("{bundle:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-key"));
    }

    #[test]
    fn pki_authority_bundle_redacts_private_key_debug() {
        let bundle: PkiAuthorityBundle =
            serde_json::from_str(r#"{"csr":"csr","private_key":"authority-key"}"#)
                .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            bundle.private_key.as_ref().map(SecretString::expose_secret),
            Some("authority-key")
        );
        let debug = format!("{bundle:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("authority-key"));
    }

    #[test]
    fn pki_role_list_is_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("role-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<PkiRoleList>(value) {
            Ok(_) => panic!("oversized PKI role list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn pki_issuer_info_accepts_string_and_array_lists() {
        let issuer: PkiIssuerInfo = serde_json::from_str(
            r#"{
                "issuer_id":"issuer-1",
                "manual_chain":"root,intermediate",
                "usage":["issuing-certificates","crl-signing"],
                "issuing_certificates":"https://bao.example/v1/pki/ca"
            }"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(issuer.manual_chain, ["root", "intermediate"]);
        assert_eq!(issuer.usage, ["issuing-certificates", "crl-signing"]);
        assert_eq!(
            issuer.issuing_certificates,
            ["https://bao.example/v1/pki/ca"]
        );
    }

    #[test]
    fn pki_issuer_and_key_lists_are_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("item-{index}"));
        }
        let issuer_error =
            match serde_json::from_value::<PkiIssuerList>(serde_json::json!({ "keys": keys })) {
                Ok(_) => panic!("oversized PKI issuer list unexpectedly decoded"),
                Err(error) => error,
            };
        assert!(issuer_error.to_string().contains("exceeds item limit"));

        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("item-{index}"));
        }
        let key_error =
            match serde_json::from_value::<PkiKeyList>(serde_json::json!({ "keys": keys })) {
                Ok(_) => panic!("oversized PKI key list unexpectedly decoded"),
                Err(error) => error,
            };
        assert!(key_error.to_string().contains("exceeds item limit"));
    }
}
