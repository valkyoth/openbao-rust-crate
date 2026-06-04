//! PKI secrets engine support.

use core::fmt;
use std::collections::BTreeMap;

use reqwest::{
    Method, StatusCode, Url,
    header::{CONTENT_TYPE, HeaderValue},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{IgnoredAny, MapAccess, SeqAccess, Visitor},
};

use crate::{
    Authenticated, Client, Error, Result,
    path::{validate_endpoint_path, validate_mount_path},
    response::{
        Empty, ListEntries, ResponseEnvelope, deserialize_bounded_string_map,
        deserialize_bounded_string_vec,
    },
};

/// Handle for a mounted PKI secrets engine.
#[derive(Debug)]
pub struct Pki<'a> {
    client: &'a Client<Authenticated>,
    mount: Vec<String>,
}

/// Confirmation token required by [`Pki::delete_root`].
///
/// Construct this at the call site with [`PkiRootDeletion::confirm`]. The
/// explicit construction is intentional: deleting a PKI root permanently
/// destroys the default root key material for the mount.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PkiRootDeletion(());

#[cfg(feature = "operator-ops")]
impl PkiRootDeletion {
    /// Confirms intentional default root CA deletion.
    #[must_use]
    pub fn confirm() -> Self {
        Self(())
    }
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

impl ListEntries for PkiRoleList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
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

/// PKI issuer configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PkiIssuersConfig {
    /// Default issuer reference, by issuer name or ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Whether new root/import operations update the default issuer.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_bool_or_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_follows_latest_issuer: Option<bool>,
}

/// PKI key configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PkiKeysConfig {
    /// Default key reference, by key name or ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
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

/// PKI tidy status returned by `/pki/tidy-status`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiTidyStatus {
    /// Safety buffer in seconds, when returned.
    #[serde(default)]
    pub safety_buffer: Option<u64>,
    /// Whether certificate-store tidy is enabled.
    #[serde(default)]
    pub tidy_cert_store: Option<bool>,
    /// Whether revoked-certificate tidy is enabled.
    #[serde(default)]
    pub tidy_revoked_certs: Option<bool>,
    /// Error message for the tidy operation, when returned.
    #[serde(default)]
    pub error: Option<String>,
    /// Whether a tidy operation is currently running, when returned.
    #[serde(default)]
    pub running: Option<bool>,
    /// Current tidy state, when returned.
    #[serde(default)]
    pub state: Option<String>,
    /// Human-readable tidy message, when returned.
    #[serde(default)]
    pub message: Option<String>,
    /// Last tidy start timestamp, when returned.
    #[serde(default)]
    pub time_started: Option<String>,
    /// Last tidy finish timestamp, when returned.
    #[serde(default)]
    pub time_finished: Option<String>,
    /// Number of revoked certificates deleted, when returned.
    #[serde(default)]
    pub revoked_cert_deleted_count: Option<u64>,
    /// Number of certificate-store entries deleted, when returned.
    #[serde(default)]
    pub cert_store_deleted_count: Option<u64>,
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

impl PkiIssueRequest {
    /// Creates a certificate issue request for `common_name`.
    pub fn new(common_name: impl Into<String>) -> Self {
        Self {
            common_name: common_name.into(),
            ..Self::default()
        }
    }
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

impl ListEntries for PkiCertificateList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
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

impl ListEntries for PkiIssuerList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
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
    /// Revocation time as Unix seconds, when this issuer was revoked.
    #[serde(default)]
    pub revocation_time: Option<u64>,
    /// Revocation time formatted as RFC3339, when returned.
    #[serde(default)]
    pub revocation_time_rfc3339: Option<String>,
}

/// PKI key list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiKeyList {
    /// Key identifiers or names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for PkiKeyList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
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

/// Request for patching PKI issuer metadata.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PkiIssuerPatch {
    /// New issuer display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_name: Option<String>,
    /// Manual issuer chain references.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manual_chain: Option<Vec<String>>,
    /// Issuer usage flags such as `issuing-certificates` or `crl-signing`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<Vec<String>>,
    /// Leaf not-after behavior, such as `truncate` or `err`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_not_after_behavior: Option<String>,
}

/// Response from PKI CA/key import endpoints.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiImportResponse {
    /// Newly imported issuer identifiers.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub imported_issuers: Vec<String>,
    /// Newly imported key identifiers.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub imported_keys: Vec<String>,
    /// Issuer identifiers already present in this mount.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub existing_issuers: Vec<String>,
    /// Key identifiers already present in this mount.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub existing_keys: Vec<String>,
    /// Issuer-to-key mapping returned by OpenBao.
    #[serde(default, deserialize_with = "deserialize_bounded_string_map")]
    pub mapping: BTreeMap<String, String>,
}

/// PKI ACME server configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PkiAcmeConfig {
    /// Issuers allowed for explicit ACME issuer paths.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_issuers: Vec<String>,
    /// Roles allowed for ACME issuance.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_roles: Vec<String>,
    /// Whether role extended key usages are honored for ACME issuance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_role_ext_key_usage: Option<bool>,
    /// Default ACME directory policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_directory_policy: Option<String>,
    /// Optional DNS resolver used for challenge lookups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_resolver: Option<String>,
    /// External account binding policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eab_policy: Option<String>,
    /// Whether ACME is enabled for this mount.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

/// ACME external account binding token.
///
/// This token is meant to be passed to a dedicated ACME client together with
/// one of the ACME directory URL helpers. The `key` field is an HMAC key and
/// must be treated as credential material; do not log it or persist it outside
/// the ACME client configuration path that needs it.
#[derive(Clone, Deserialize)]
pub struct PkiAcmeEabToken {
    /// Token creation time.
    #[serde(default)]
    pub created_on: Option<String>,
    /// Key identifier for ACME EAB registration.
    pub id: String,
    /// EAB key type.
    #[serde(default)]
    pub key_type: Option<String>,
    /// ACME directory this token is scoped to.
    #[serde(default)]
    pub acme_directory: Option<String>,
    /// EAB HMAC key. Treat as secret material.
    pub key: SecretString,
}

impl fmt::Debug for PkiAcmeEabToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PkiAcmeEabToken")
            .field("created_on", &self.created_on)
            .field("id", &self.id)
            .field("key_type", &self.key_type)
            .field("acme_directory", &self.acme_directory)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Metadata for an unused ACME external account binding token.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiAcmeEabInfo {
    /// Token creation time.
    #[serde(default)]
    pub created_on: Option<String>,
    /// EAB key type.
    #[serde(default)]
    pub key_type: Option<String>,
    /// ACME directory this token is scoped to.
    #[serde(default)]
    pub acme_directory: Option<String>,
}

/// List of unused ACME external account binding tokens.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiAcmeEabList {
    /// EAB key identifiers.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
    /// Metadata keyed by EAB key identifier.
    #[serde(default, deserialize_with = "deserialize_bounded_eab_info_map")]
    pub key_info: BTreeMap<String, PkiAcmeEabInfo>,
}

impl ListEntries for PkiAcmeEabList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
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

    /// Permanently deletes the default root key material for this PKI mount.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    ///
    /// This is an irreversible mount-scope operator operation. It destroys the
    /// current default root key material and leaves the mount unable to issue
    /// new certificates until a new root is generated or imported. Already
    /// issued certificates are not deleted by this call, and named issuers or
    /// keys not backed by the deleted default root key are not its target.
    ///
    /// This is distinct from [`Pki::revoke_issuer`], which revokes issuer
    /// metadata without destroying key material, and [`Pki::delete_issuer`],
    /// which targets one named issuer record. Use [`PkiRootDeletion::confirm`]
    /// at the call site so reviews can identify every intentional root
    /// deletion.
    #[cfg(feature = "operator-ops")]
    pub async fn delete_root(&self, _confirmation: PkiRootDeletion) -> Result<Empty> {
        self.client
            .request_json_accepting(
                Method::DELETE,
                &self.path(&["root"])?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
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

    /// Patches a PKI role with JSON Merge Patch semantics.
    pub async fn patch_role(&self, name: &str, patch: &PkiRole) -> Result<PkiRole> {
        self.enveloped_with_headers(
            Method::PATCH,
            &self.path(&["roles", name])?,
            &[(
                CONTENT_TYPE,
                HeaderValue::from_static("application/merge-patch+json"),
            )],
            Some(patch),
        )
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

    /// Reads the default PKI issuer configuration.
    pub async fn read_issuers_config(&self) -> Result<PkiIssuersConfig> {
        self.enveloped(
            Method::GET,
            &self.path(&["config", "issuers"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Sets the default PKI issuer configuration.
    pub async fn write_issuers_config(&self, config: &PkiIssuersConfig) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                &self.path(&["config", "issuers"])?,
                Some(config),
            )
            .await
    }

    /// Reads the default PKI key configuration.
    pub async fn read_keys_config(&self) -> Result<PkiKeysConfig> {
        self.enveloped(
            Method::GET,
            &self.path(&["config", "keys"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Sets the default PKI key configuration.
    pub async fn write_keys_config(&self, config: &PkiKeysConfig) -> Result<Empty> {
        self.client
            .request_json(Method::POST, &self.path(&["config", "keys"])?, Some(config))
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

    /// Reads the status of the current or most recent PKI tidy operation.
    pub async fn tidy_status(&self) -> Result<PkiTidyStatus> {
        self.enveloped(
            Method::GET,
            &self.path(&["tidy-status"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Cancels an in-progress PKI tidy operation.
    pub async fn tidy_cancel(&self) -> Result<PkiTidyStatus> {
        self.enveloped(
            Method::POST,
            &self.path(&["tidy-cancel"])?,
            Option::<&Empty>::None,
        )
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

    /// Patches PKI issuer metadata with JSON Merge Patch semantics.
    ///
    /// OpenBao also supports `POST /pki/issuer/:issuer_ref`, but that endpoint
    /// replaces omitted fields with defaults. This helper intentionally uses
    /// `PATCH` so callers update only the provided fields.
    pub async fn patch_issuer(
        &self,
        issuer_ref: &str,
        patch: &PkiIssuerPatch,
    ) -> Result<PkiIssuerInfo> {
        self.enveloped_with_headers(
            Method::PATCH,
            &self.path(&["issuer", issuer_ref])?,
            &[(
                CONTENT_TYPE,
                HeaderValue::from_static("application/merge-patch+json"),
            )],
            Some(patch),
        )
        .await
    }

    /// Revokes a PKI issuer by issuer reference.
    pub async fn revoke_issuer(&self, issuer_ref: &str) -> Result<PkiIssuerInfo> {
        self.enveloped(
            Method::POST,
            &self.path(&["issuer", issuer_ref, "revoke"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Imports a CA certificate/key PEM bundle through the legacy config path.
    ///
    /// This endpoint may import private key material into OpenBao. Use only for
    /// tightly controlled administrative workflows.
    pub async fn import_ca_bundle(&self, pem_bundle: &SecretString) -> Result<PkiImportResponse> {
        let payload = PkiPemBundlePayload {
            pem_bundle: pem_bundle.expose_secret(),
        };
        self.enveloped(Method::POST, &self.path(&["config", "ca"])?, Some(&payload))
            .await
    }

    /// Imports CA certificates and private keys as issuer/key entries.
    ///
    /// This endpoint may import private key material into OpenBao. Use only for
    /// tightly controlled administrative workflows.
    pub async fn import_issuer_bundle(
        &self,
        pem_bundle: &SecretString,
    ) -> Result<PkiImportResponse> {
        let payload = PkiPemBundlePayload {
            pem_bundle: pem_bundle.expose_secret(),
        };
        self.enveloped(
            Method::POST,
            &self.path(&["issuers", "import", "bundle"])?,
            Some(&payload),
        )
        .await
    }

    /// Imports CA certificates without private keys.
    pub async fn import_issuer_certificates(&self, pem_bundle: &str) -> Result<PkiImportResponse> {
        let payload = PkiPemBundlePayload { pem_bundle };
        self.enveloped(
            Method::POST,
            &self.path(&["issuers", "import", "cert"])?,
            Some(&payload),
        )
        .await
    }

    /// Imports a single PEM-encoded private key.
    ///
    /// This endpoint does not enforce cryptographic strength; callers should
    /// validate key algorithms and sizes before importing.
    pub async fn import_key(
        &self,
        pem_bundle: &SecretString,
        key_name: Option<&str>,
    ) -> Result<PkiKeyInfo> {
        let payload = PkiImportKeyPayload {
            pem_bundle: pem_bundle.expose_secret(),
            key_name,
        };
        self.enveloped(
            Method::POST,
            &self.path(&["keys", "import"])?,
            Some(&payload),
        )
        .await
    }

    /// Renames a PKI key.
    ///
    /// OpenBao exposes key renaming through `POST /pki/key/:key_ref`; this
    /// helper keeps the request payload to the only documented mutable field.
    pub async fn rename_key(&self, key_ref: &str, key_name: &str) -> Result<PkiKeyInfo> {
        let payload = PkiRenameKeyPayload { key_name };
        self.enveloped(Method::POST, &self.path(&["key", key_ref])?, Some(&payload))
            .await
    }

    /// Reads ACME configuration for this PKI mount.
    pub async fn read_acme_config(&self) -> Result<PkiAcmeConfig> {
        self.enveloped(
            Method::GET,
            &self.path(&["config", "acme"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Sets ACME configuration for this PKI mount.
    pub async fn write_acme_config(&self, config: &PkiAcmeConfig) -> Result<PkiAcmeConfig> {
        self.enveloped(Method::POST, &self.path(&["config", "acme"])?, Some(config))
            .await
    }

    /// Generates an ACME EAB token for the default ACME directory.
    pub async fn generate_acme_eab(&self) -> Result<PkiAcmeEabToken> {
        self.enveloped(
            Method::POST,
            &self.path(&["acme", "new-eab"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Generates an ACME EAB token scoped to an issuer directory.
    pub async fn generate_issuer_acme_eab(&self, issuer_ref: &str) -> Result<PkiAcmeEabToken> {
        self.enveloped(
            Method::POST,
            &self.path(&["issuer", issuer_ref, "acme", "new-eab"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Generates an ACME EAB token scoped to a role directory.
    pub async fn generate_role_acme_eab(&self, role: &str) -> Result<PkiAcmeEabToken> {
        self.enveloped(
            Method::POST,
            &self.path(&["roles", role, "acme", "new-eab"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Generates an ACME EAB token scoped to an issuer and role directory.
    pub async fn generate_issuer_role_acme_eab(
        &self,
        issuer_ref: &str,
        role: &str,
    ) -> Result<PkiAcmeEabToken> {
        self.enveloped(
            Method::POST,
            &self.path(&["issuer", issuer_ref, "roles", role, "acme", "new-eab"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Lists unused ACME EAB tokens.
    pub async fn list_acme_eab_tokens(&self) -> Result<PkiAcmeEabList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        self.enveloped(method, &self.path(&["eab"])?, Option::<&Empty>::None)
            .await
    }

    /// Deletes an unused ACME EAB token.
    pub async fn delete_acme_eab_token(&self, key_id: &str) -> Result<Empty> {
        self.client
            .request_json_accepting(
                Method::DELETE,
                &self.path(&["eab", key_id])?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Returns the default ACME directory URL for use with ACME clients.
    ///
    /// OpenBao ACME directory endpoints are unauthenticated by OpenBao token
    /// and are internally authenticated by the ACME protocol. This helper only
    /// builds the documented directory URL; it does not implement ACME
    /// account, order, authorization, or challenge flows.
    ///
    /// Pair this URL with [`PkiAcmeEabToken`] from [`Pki::generate_acme_eab`]
    /// and pass both values to a dedicated ACME client library. The ACME
    /// client owns account registration, nonce handling, order state,
    /// challenge responses, certificate polling, and certificate download.
    pub fn acme_directory_url(&self) -> Result<Url> {
        self.client
            .url_for_path(&self.path(&["acme", "directory"])?)
    }

    /// Returns an issuer-scoped ACME directory URL for use with ACME clients.
    pub fn issuer_acme_directory_url(&self, issuer_ref: &str) -> Result<Url> {
        self.client
            .url_for_path(&self.path(&["issuer", issuer_ref, "acme", "directory"])?)
    }

    /// Returns a role-scoped ACME directory URL for use with ACME clients.
    pub fn role_acme_directory_url(&self, role: &str) -> Result<Url> {
        self.client
            .url_for_path(&self.path(&["roles", role, "acme", "directory"])?)
    }

    /// Returns an issuer-and-role-scoped ACME directory URL for use with ACME clients.
    pub fn issuer_role_acme_directory_url(&self, issuer_ref: &str, role: &str) -> Result<Url> {
        self.client.url_for_path(&self.path(&[
            "issuer",
            issuer_ref,
            "roles",
            role,
            "acme",
            "directory",
        ])?)
    }

    async fn enveloped<T, B>(&self, method: Method, path: &str, request: Option<&B>) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
        B: Serialize + ?Sized,
    {
        let envelope: ResponseEnvelope<T> = self.client.request_json(method, path, request).await?;
        Ok(envelope.data)
    }

    async fn enveloped_with_headers<T, B>(
        &self,
        method: Method,
        path: &str,
        headers: &[(reqwest::header::HeaderName, HeaderValue)],
        request: Option<&B>,
    ) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
        B: Serialize + ?Sized,
    {
        let envelope: ResponseEnvelope<T> = self
            .client
            .request_json_headers_accepting(method, path, headers, request, &[StatusCode::OK])
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

#[derive(Serialize)]
struct PkiPemBundlePayload<'a> {
    pem_bundle: &'a str,
}

#[derive(Serialize)]
struct PkiImportKeyPayload<'a> {
    pem_bundle: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_name: Option<&'a str>,
}

#[derive(Serialize)]
struct PkiRenameKeyPayload<'a> {
    key_name: &'a str,
}

fn deserialize_bounded_string_or_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(StringOrListVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

fn deserialize_optional_bool_or_string<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolOrString {
        Bool(bool),
        String(String),
    }

    match Option::<BoolOrString>::deserialize(deserializer)? {
        None => Ok(None),
        Some(BoolOrString::Bool(value)) => Ok(Some(value)),
        Some(BoolOrString::String(value)) if value == "true" => Ok(Some(true)),
        Some(BoolOrString::String(value)) if value == "false" => Ok(Some(false)),
        Some(BoolOrString::String(_)) => Err(serde::de::Error::custom(
            "expected boolean or boolean string for field",
        )),
    }
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

fn deserialize_bounded_eab_info_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, PkiAcmeEabInfo>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer
        .deserialize_map(BoundedEabInfoMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

struct BoundedEabInfoMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedEabInfoMapVisitor<MAX> {
    type Value = BTreeMap<String, PkiAcmeEabInfo>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a map of at most {MAX} ACME EAB metadata entries"
        )
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, PkiAcmeEabInfo>()? else {
                return Ok(values);
            };
            values.insert(key, value);
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(
                "OpenBao ACME EAB metadata exceeds item limit",
            ));
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(deprecated)]

    use crate::{Client, OpenBaoConfig};

    use secrecy::{ExposeSecret, SecretString};

    use super::{
        PkiAcmeConfig, PkiAcmeEabList, PkiAcmeEabToken, PkiAuthorityBundle, PkiCertificateBundle,
        PkiImportResponse, PkiIssuerInfo, PkiIssuerList, PkiIssuersConfig, PkiKeyList, PkiRole,
        PkiRoleList,
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
    fn pki_issuers_config_accepts_documented_string_boolean() {
        let config: PkiIssuersConfig = serde_json::from_str(
            r#"{"default":"issuer-1","default_follows_latest_issuer":"false"}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(config.default.as_deref(), Some("issuer-1"));
        assert_eq!(config.default_follows_latest_issuer, Some(false));
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

    #[test]
    fn pki_acme_config_accepts_string_and_array_lists() {
        let config: PkiAcmeConfig = serde_json::from_str(
            r#"{
                "allowed_issuers":"*",
                "allowed_roles":["web","api"],
                "enabled":true,
                "eab_policy":"always-required"
            }"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(config.allowed_issuers, ["*"]);
        assert_eq!(config.allowed_roles, ["web", "api"]);
        assert_eq!(config.enabled, Some(true));
    }

    #[test]
    fn pki_acme_eab_token_redacts_key_debug() {
        let token: PkiAcmeEabToken = serde_json::from_str(
            r#"{"id":"eab-1","key_type":"hs","acme_directory":"acme/directory","key":"hmac-secret"}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(token.key.expose_secret(), "hmac-secret");
        let debug = format!("{token:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("hmac-secret"));
    }

    #[test]
    fn pki_acme_eab_metadata_map_is_bounded() {
        let mut keys = Vec::new();
        let mut key_info = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            let key = format!("eab-{index}");
            keys.push(key.clone());
            key_info.insert(
                key,
                serde_json::json!({
                    "created_on": "2026-05-29T00:00:00Z",
                    "key_type": "hs",
                    "acme_directory": "acme/directory"
                }),
            );
        }
        let value = serde_json::json!({ "keys": keys, "key_info": key_info });
        let error = match serde_json::from_value::<PkiAcmeEabList>(value) {
            Ok(_) => panic!("oversized PKI ACME EAB list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn pki_import_response_maps_are_bounded() {
        let mut mapping = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            mapping.insert(format!("issuer-{index}"), serde_json::json!("key"));
        }
        let value = serde_json::json!({
            "imported_issuers": [],
            "imported_keys": [],
            "existing_issuers": [],
            "existing_keys": [],
            "mapping": mapping
        });
        let error = match serde_json::from_value::<PkiImportResponse>(value) {
            Ok(_) => panic!("oversized PKI import mapping unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn pki_acme_directory_urls_are_validated_and_built_from_base_url() {
        let config =
            OpenBaoConfig::new("https://bao.example.com").unwrap_or_else(|error| panic!("{error}"));
        let client = Client::from_config(config)
            .unwrap_or_else(|error| panic!("{error}"))
            .with_token(SecretString::from("token"));
        let pki = client.pki("pki").unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            pki.acme_directory_url()
                .unwrap_or_else(|error| panic!("{error}"))
                .as_str(),
            "https://bao.example.com/v1/pki/acme/directory"
        );
        assert_eq!(
            pki.issuer_acme_directory_url("issuer-1")
                .unwrap_or_else(|error| panic!("{error}"))
                .as_str(),
            "https://bao.example.com/v1/pki/issuer/issuer-1/acme/directory"
        );
        assert_eq!(
            pki.role_acme_directory_url("web")
                .unwrap_or_else(|error| panic!("{error}"))
                .as_str(),
            "https://bao.example.com/v1/pki/roles/web/acme/directory"
        );
        assert_eq!(
            pki.issuer_role_acme_directory_url("issuer-1", "web")
                .unwrap_or_else(|error| panic!("{error}"))
                .as_str(),
            "https://bao.example.com/v1/pki/issuer/issuer-1/roles/web/acme/directory"
        );
        assert!(pki.issuer_acme_directory_url("../issuer").is_err());
        assert!(pki.role_acme_directory_url("web?x=1").is_err());
    }
}
