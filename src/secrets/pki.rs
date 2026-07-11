//! PKI secrets engine support.

use core::fmt;
use std::collections::BTreeMap;

use reqwest::{
    Method, StatusCode, Url,
    header::{ACCEPT, CONTENT_TYPE, HeaderValue},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{IgnoredAny, MapAccess, SeqAccess, Visitor},
    ser::SerializeStruct,
};

use crate::{
    Authenticated, Client, Error, JsonValue, Result, SecretVec, Unauthenticated,
    path::{validate_endpoint_path, validate_mount_path},
    response::{
        Empty, ListEntries, ListPageOptions, ResponseEnvelope, deserialize_bounded_string_map,
        deserialize_bounded_string_vec,
    },
};

/// Handle for a mounted PKI secrets engine.
#[derive(Debug)]
pub struct Pki<'a> {
    client: &'a Client<Authenticated>,
    mount: Vec<String>,
}

/// Unauthenticated handle for public PKI protocol and distribution endpoints.
///
/// This handle is available only from [`Client<Unauthenticated>`], ensuring
/// OpenBao tokens are never attached to public certificate, CRL, OCSP, or ACME
/// directory requests.
#[derive(Debug)]
pub struct PkiPublic<'a> {
    client: &'a Client<Unauthenticated>,
    mount: Vec<String>,
}

/// Output representation for issuer certificate and CRL distribution reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PkiPublicFormat {
    /// DER-encoded binary data.
    Der,
    /// PEM-encoded text data.
    Pem,
    /// OpenBao's JSON representation.
    Json,
}

/// Scope of an OpenBao PKI ACME directory.
#[cfg(feature = "acme-protocol")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PkiAcmeScope {
    /// Mount-wide default directory.
    Default,
    /// Directory restricted to one issuer.
    Issuer(String),
    /// Directory restricted to one role.
    Role(String),
    /// Directory restricted to one issuer and role.
    IssuerRole {
        /// Issuer reference used by the directory.
        issuer_ref: String,
        /// Role used by the directory.
        role: String,
    },
}

/// Handoff configuration for an established ACME protocol client.
///
/// This crate deliberately does not implement JWS signing, nonce management,
/// order polling, or challenge fulfillment. Pass this configuration to an
/// ACME client library that owns those protocol state machines.
#[cfg(feature = "acme-protocol")]
#[derive(Clone)]
pub struct PkiAcmeClientConfig {
    /// OpenBao ACME directory URL.
    pub directory_url: Url,
    /// Optional OpenBao external-account-binding credential.
    pub external_account_binding: Option<PkiAcmeEabToken>,
}

#[cfg(feature = "acme-protocol")]
impl fmt::Debug for PkiAcmeClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PkiAcmeClientConfig")
            .field("directory_url", &self.directory_url)
            .field("external_account_binding", &self.external_account_binding)
            .finish()
    }
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
    /// Allows ACL templating in allowed domains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_domains_template: Option<bool>,
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
    /// Allows requested IP SANs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_ip_sans: Option<bool>,
    /// CIDR ranges allowed for requested IP SANs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_ip_sans_cidr: Vec<String>,
    /// URI SAN values or glob patterns allowed for requests.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_uri_sans: Vec<String>,
    /// Allows ACL templating in allowed URI SANs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_uri_sans_template: Option<bool>,
    /// Other SAN values or glob patterns allowed for requests.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_other_sans: Vec<String>,
    /// Subject serial-number values allowed for requests.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_serial_numbers: Vec<String>,
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
    /// Not-before request bound mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before_bound: Option<String>,
    /// Explicit not-before timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Not-after request bound mode or timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after_bound: Option<String>,
    /// Explicit not-after timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// Whether key usage is marked critical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_usage_critical: Option<bool>,
    /// Whether basic constraints are marked critical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic_constraints_valid_for_non_ca: Option<bool>,
    /// Whether issued certificates are not stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_store: Option<bool>,
    /// Whether issued certificates receive OpenBao leases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generate_lease: Option<bool>,
    /// Whether common name is required on issuance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_cn: Option<bool>,
    /// Certificate policy OIDs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policy_identifiers: Vec<String>,
    /// Common-name validation modes.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cn_validations: Vec<String>,
    /// User ID subject values allowed for requests.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_user_ids: Vec<String>,
    /// Subject organizational units for issued certificates.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ou: Vec<String>,
    /// Subject organizations for issued certificates.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub organization: Vec<String>,
    /// Subject countries for issued certificates.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub country: Vec<String>,
    /// Subject localities for issued certificates.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locality: Vec<String>,
    /// Subject provinces for issued certificates.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub province: Vec<String>,
    /// Subject street addresses for issued certificates.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub street_address: Vec<String>,
    /// Subject postal codes for issued certificates.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub postal_code: Vec<String>,
    /// Uses the CSR common name when signing through this role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_csr_common_name: Option<bool>,
    /// Uses CSR SAN values when signing through this role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_csr_sans: Option<bool>,
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
    /// Delta CRL distribution point URLs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub delta_crl_distribution_points: Vec<String>,
    /// Enables templating in configured URLs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_templating: Option<bool>,
    /// Enables AIA URL templating on issuer distribution endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_aia_url_templating: Option<bool>,
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

/// PKI cluster-local configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PkiClusterConfig {
    /// OpenBao API URL for this PKI mount on the current cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// AIA distribution URL for public CA/CRL material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aia_path: Option<String>,
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
    /// Key display name when OpenBao creates new key material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_name: Option<String>,
    /// Requested TTL such as `87600h`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Requested alternative names.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alt_names: Vec<String>,
    /// Requested IP SANs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ip_sans: Vec<String>,
    /// Requested URI SANs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uri_sans: Vec<String>,
    /// Requested other SANs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub other_sans: Vec<String>,
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
    /// Maximum path length to encode in the generated certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_path_length: Option<i64>,
    /// Permitted DNS domains for name constraints.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub permitted_dns_domains: Vec<String>,
    /// Subject organizational units.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ou: Vec<String>,
    /// Subject organizations.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub organization: Vec<String>,
    /// Subject countries.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub country: Vec<String>,
    /// Subject localities.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locality: Vec<String>,
    /// Subject provinces.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub province: Vec<String>,
    /// Subject street addresses.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub street_address: Vec<String>,
    /// Subject postal codes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub postal_code: Vec<String>,
    /// Subject serial number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    /// Not-before skew duration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before_duration: Option<String>,
    /// Explicit not-before timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Explicit not-after timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// Default key usages.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub key_usage: Vec<String>,
    /// Default extended key usages.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ext_key_usage: Vec<String>,
    /// Default extended key usage OIDs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ext_key_usage_oids: Vec<String>,
    /// Adds basic constraints to generated authority certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add_basic_constraints: Option<bool>,
    /// Signature algorithm used for authority revocation signatures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_signature_algorithm: Option<String>,
    /// Enables AIA URL templating for the generated issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_aia_url_templating: Option<bool>,
}

/// Request for generating an intermediate CA CSR.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PkiGenerateIntermediateRequest {
    /// Common name for the intermediate.
    pub common_name: String,
    /// Issuer display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_name: Option<String>,
    /// Key display name when OpenBao creates new key material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_name: Option<String>,
    /// Requested alternative names.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alt_names: Vec<String>,
    /// Requested IP SANs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ip_sans: Vec<String>,
    /// Requested URI SANs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uri_sans: Vec<String>,
    /// Requested other SANs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub other_sans: Vec<String>,
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
    /// Permitted DNS domains for name constraints.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub permitted_dns_domains: Vec<String>,
    /// Subject organizational units.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ou: Vec<String>,
    /// Subject organizations.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub organization: Vec<String>,
    /// Subject countries.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub country: Vec<String>,
    /// Subject localities.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locality: Vec<String>,
    /// Subject provinces.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub province: Vec<String>,
    /// Subject street addresses.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub street_address: Vec<String>,
    /// Subject postal codes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub postal_code: Vec<String>,
    /// Subject serial number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    /// Not-before skew duration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before_duration: Option<String>,
    /// Explicit not-before timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Explicit not-after timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// Default key usages.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub key_usage: Vec<String>,
    /// Default extended key usages.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ext_key_usage: Vec<String>,
    /// Default extended key usage OIDs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ext_key_usage_oids: Vec<String>,
    /// Adds basic constraints to generated authority certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add_basic_constraints: Option<bool>,
    /// Signature algorithm used for authority revocation signatures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_signature_algorithm: Option<String>,
    /// Enables AIA URL templating for the generated issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_aia_url_templating: Option<bool>,
}

/// Request for generating standalone PKI key material.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PkiGenerateKeyRequest {
    /// Key display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_name: Option<String>,
    /// Key type, such as `rsa`, `ec`, or `ed25519`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    /// Key size in bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<u64>,
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
    /// Generated issuer identifier, when returned.
    #[serde(default)]
    pub issuer_id: Option<String>,
    /// Generated issuer display name, when returned.
    #[serde(default)]
    pub issuer_name: Option<String>,
    /// Generated or reused key identifier, when returned.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Generated or reused key display name, when returned.
    #[serde(default)]
    pub key_name: Option<String>,
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
            .field("issuer_id", &self.issuer_id)
            .field("issuer_name", &self.issuer_name)
            .field("key_id", &self.key_id)
            .field("key_name", &self.key_name)
            .finish()
    }
}

/// Response from standalone PKI key generation.
#[derive(Clone, Deserialize)]
pub struct PkiGeneratedKey {
    /// Generated key identifier.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Generated key display name.
    #[serde(default)]
    pub key_name: Option<String>,
    /// Generated key type.
    #[serde(default)]
    pub key_type: Option<String>,
    /// Generated key size in bits, when returned.
    #[serde(default)]
    pub key_bits: Option<u64>,
    /// Generated private key, when `exported` key generation returned one.
    #[serde(default)]
    pub private_key: Option<SecretString>,
    /// Generated private key type, when returned.
    #[serde(default)]
    pub private_key_type: Option<String>,
}

impl fmt::Debug for PkiGeneratedKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PkiGeneratedKey")
            .field("key_id", &self.key_id)
            .field("key_name", &self.key_name)
            .field("key_type", &self.key_type)
            .field("key_bits", &self.key_bits)
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("private_key_type", &self.private_key_type)
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

/// Request for signing a self-issued certificate.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PkiSignSelfIssuedRequest {
    /// PEM-format self-issued certificate.
    pub certificate: String,
    /// Issuer display name for the generated issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_name: Option<String>,
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
    /// OCSP expiry duration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsp_expiry: Option<String>,
    /// Enables unified CRL building.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unified_crl: Option<bool>,
    /// Serves unified CRLs on legacy paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unified_crl_on_existing_paths: Option<bool>,
    /// Enables cross-cluster revocation where supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_cluster_revocation: Option<bool>,
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
    /// Tidies invalid certificates where supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidy_invalid_certs: Option<bool>,
    /// Tidies expired issuer metadata where supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidy_expired_issuers: Option<bool>,
    /// Tidies moved issuer metadata where supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidy_move_legacy_ca_bundle: Option<bool>,
    /// Tidies cross-cluster revoked certificates where supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidy_cross_cluster_revoked_certs: Option<bool>,
    /// Tidies revoked certificate issuer associations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tidy_revoked_cert_issuer_associations: Option<bool>,
    /// Revocation queue safety buffer duration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_queue_safety_buffer: Option<String>,
    /// Issuer safety buffer duration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_safety_buffer: Option<String>,
    /// Pause duration between tidy batches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pause_duration: Option<String>,
    /// Page size for tidy operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u64>,
    /// Whether to maintain stored certificate counts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maintain_stored_certificate_counts: Option<bool>,
    /// Whether to publish stored certificate count metrics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publish_stored_certificate_count_metrics: Option<bool>,
    /// ACME account safety buffer duration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acme_account_safety_buffer: Option<String>,
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
    /// Number of revoked certificates missing a valid issuer reference.
    #[serde(default)]
    pub missing_issuer_cert_count: Option<u64>,
    /// Number of revocation queue entries deleted.
    #[serde(default)]
    pub revocation_queue_deleted_count: Option<u64>,
    /// Number of cross-cluster revoked certificate entries deleted.
    #[serde(default)]
    pub cross_revoked_cert_deleted_count: Option<u64>,
    /// Whether invalid certificate tidy is enabled.
    #[serde(default)]
    pub tidy_invalid_certs: Option<bool>,
    /// Whether expired issuer tidy is enabled.
    #[serde(default)]
    pub tidy_expired_issuers: Option<bool>,
    /// Whether moved issuer tidy is enabled.
    #[serde(default)]
    pub tidy_move_legacy_ca_bundle: Option<bool>,
    /// Whether revoked certificate issuer association tidy is enabled.
    #[serde(default)]
    pub tidy_revoked_cert_issuer_associations: Option<bool>,
    /// Whether cross-cluster revoked certificate tidy is enabled.
    #[serde(default)]
    pub tidy_cross_cluster_revoked_certs: Option<bool>,
    /// Whether revocation queue tidy is enabled.
    #[serde(default)]
    pub tidy_revocation_queue: Option<bool>,
    /// Pause duration between tidy batches.
    #[serde(default, deserialize_with = "deserialize_optional_string_or_u64")]
    pub pause_duration: Option<String>,
    /// Issuer safety buffer duration.
    #[serde(default, deserialize_with = "deserialize_optional_string_or_u64")]
    pub issuer_safety_buffer: Option<String>,
    /// Revocation queue safety buffer duration.
    #[serde(default, deserialize_with = "deserialize_optional_string_or_u64")]
    pub revocation_queue_safety_buffer: Option<String>,
    /// Page size for tidy batches.
    #[serde(default)]
    pub page_size: Option<u64>,
    /// Last automatic tidy finish time.
    #[serde(default)]
    pub last_auto_tidy_finished: Option<String>,
}

/// PKI automatic tidy configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PkiAutoTidyConfig {
    /// Enables automatic tidy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Duration between automatic tidy operations.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub interval_duration: Option<String>,
    /// Tidies stored certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tidy_cert_store: Option<bool>,
    /// Tidies revoked certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tidy_revoked_certs: Option<bool>,
    /// Tidies revocation queue entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tidy_revocation_queue: Option<bool>,
    /// Tidies invalid certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tidy_invalid_certs: Option<bool>,
    /// Tidies expired issuer metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tidy_expired_issuers: Option<bool>,
    /// Tidies moved legacy CA bundles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tidy_move_legacy_ca_bundle: Option<bool>,
    /// Tidies cross-cluster revoked certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tidy_cross_cluster_revoked_certs: Option<bool>,
    /// Tidies revoked certificate issuer associations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tidy_revoked_cert_issuer_associations: Option<bool>,
    /// Safety buffer duration.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub safety_buffer: Option<String>,
    /// Safety buffer applied specifically to revoked certificates.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub revoked_safety_buffer: Option<String>,
    /// Revocation queue safety buffer duration.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub revocation_queue_safety_buffer: Option<String>,
    /// Issuer safety buffer duration.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub issuer_safety_buffer: Option<String>,
    /// Pause duration between batches.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub pause_duration: Option<String>,
    /// Page size for tidy batches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u64>,
    /// Whether to maintain stored certificate counts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintain_stored_certificate_counts: Option<bool>,
    /// Whether to publish stored certificate count metrics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_stored_certificate_count_metrics: Option<bool>,
    /// ACME account safety buffer duration.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub acme_account_safety_buffer: Option<String>,
}

/// CRL rotation response.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiRotateCrlResponse {
    /// Whether rotation succeeded.
    #[serde(default)]
    pub success: bool,
}

/// Response from CRL signing and resigning endpoints.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiCrlBundle {
    /// PEM or DER encoded CRL material returned by OpenBao.
    #[serde(default)]
    pub crl: Option<String>,
    /// PEM encoded delta CRL material returned by OpenBao.
    #[serde(default)]
    pub delta_crl: Option<String>,
    /// CRL serial number, when returned.
    #[serde(default)]
    pub serial_number: Option<String>,
    /// Next CRL update timestamp or duration returned by OpenBao.
    #[serde(default)]
    pub next_update: Option<String>,
}

/// X.509 extension included in a manually signed CRL.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Debug, Default, Serialize)]
pub struct PkiCrlExtension {
    /// Extension object identifier.
    pub id: String,
    /// Whether the extension is critical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub critical: Option<bool>,
    /// Extension value in the encoding expected by OpenBao.
    pub value: String,
}

/// Request for manually signing a revocation list.
///
/// This bypasses OpenBao's ordinary CRL construction path and is available
/// only behind the `operator-ops` feature gate.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Debug, Default, Serialize)]
pub struct PkiSignRevocationListRequest {
    /// CRL number to place in the generated CRL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crl_number: Option<u64>,
    /// Base CRL number when generating a delta CRL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_crl_base_number: Option<u64>,
    /// Requested CRL format, such as `pem` or `der`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Revoked certificate entries to include.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub revoked_certs: Vec<PkiRevokedCertificateEntry>,
    /// Requested next-update duration or timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_update: Option<String>,
    /// Safety buffer applied to revoked entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_safety_buffer: Option<String>,
    /// Additional reviewed X.509 CRL extensions.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<PkiCrlExtension>,
}

/// Revoked certificate entry used by manual CRL signing.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Debug, Default, Serialize)]
pub struct PkiRevokedCertificateEntry {
    /// Certificate serial number.
    pub serial_number: String,
    /// Revocation time as Unix seconds.
    pub revocation_time: u64,
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
    /// Explicit subject key identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skid: Option<String>,
    /// Requires certificate and issuer signature algorithms to match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_matching_certificate_algorithms: Option<bool>,
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
    /// Explicit subject key identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skid: Option<String>,
    /// Requires certificate and issuer signature algorithms to match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_matching_certificate_algorithms: Option<bool>,
}

/// Request for sign-verbatim certificate signing.
///
/// Sign-verbatim bypasses normal role constraints and takes certificate
/// content largely from the CSR. Methods using this request are available only
/// behind the `operator-ops` feature gate.
#[cfg(feature = "operator-ops")]
#[derive(Clone, Debug, Default, Serialize)]
pub struct PkiSignVerbatimRequest {
    /// PEM-format certificate signing request.
    pub csr: String,
    /// Default key usage values used when the CSR omits key usage.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub key_usage: Vec<String>,
    /// Default extended key usage values used when the CSR omits extended key usage.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ext_key_usage: Vec<String>,
    /// Default extended key usage OIDs used when the CSR omits extended key usage.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ext_key_usage_oids: Vec<String>,
    /// Requested TTL such as `24h`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Certificate return format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Explicit not-before timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Explicit not-after timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// RSA signature digest size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_bits: Option<u64>,
    /// Uses RSA-PSS signatures where supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_pss: Option<bool>,
    /// Removes self-signed roots from the returned chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remove_roots_from_chain: Option<bool>,
    /// Requested User ID subject values.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub user_ids: Vec<String>,
    /// Marks basic constraints valid on non-CA certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_constraints_valid_for_non_ca: Option<bool>,
    /// Explicit subject key identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skid: Option<String>,
    /// Requires certificate and issuer signature algorithms to match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_matching_certificate_algorithms: Option<bool>,
}

#[cfg(feature = "operator-ops")]
impl PkiSignVerbatimRequest {
    /// Creates a sign-verbatim request from a PEM CSR.
    pub fn new(csr: impl Into<String>) -> Self {
        Self {
            csr: csr.into(),
            ..Self::default()
        }
    }
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

/// Request for revoking a certificate by proving private-key possession.
#[derive(Clone)]
pub struct PkiRevokeWithKeyRequest {
    /// Certificate serial number.
    pub serial_number: String,
    /// Private key corresponding to the certificate being revoked.
    pub private_key: SecretString,
}

impl PkiRevokeWithKeyRequest {
    /// Creates a revoke-with-key request.
    pub fn new(serial_number: impl Into<String>, private_key: SecretString) -> Self {
        Self {
            serial_number: serial_number.into(),
            private_key,
        }
    }
}

impl fmt::Debug for PkiRevokeWithKeyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PkiRevokeWithKeyRequest")
            .field("serial_number", &self.serial_number)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl Serialize for PkiRevokeWithKeyRequest {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PkiRevokeWithKeyRequest", 2)?;
        state.serialize_field("serial_number", &self.serial_number)?;
        state.serialize_field("private_key", self.private_key.expose_secret())?;
        state.end()
    }
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

/// Detailed certificate list response.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiDetailedCertificateList {
    /// Certificate serial numbers.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
    /// Certificate metadata keyed by serial number.
    #[serde(default, deserialize_with = "deserialize_bounded_primitive_json_map")]
    pub key_info: BTreeMap<String, JsonValue>,
}

impl ListEntries for PkiDetailedCertificateList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Revocation queue list response.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiRevocationQueueList {
    /// Queued certificate serial numbers.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
    /// Queue metadata keyed by serial number.
    #[serde(default, deserialize_with = "deserialize_bounded_primitive_json_map")]
    pub key_info: BTreeMap<String, JsonValue>,
}

impl ListEntries for PkiRevocationQueueList {
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
    /// Signature algorithm used for issuer revocation signatures.
    #[serde(default)]
    pub revocation_signature_algorithm: Option<String>,
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
    /// Signature algorithm used for issuer revocation signatures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_signature_algorithm: Option<String>,
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

/// Request for creating or patching a PKI CEL role.
///
/// CEL roles are newer OpenBao PKI functionality. Their endpoint paths are
/// typed here, while the CEL program text remains caller-owned and is passed
/// to OpenBao unchanged.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PkiCelRoleRequest {
    /// CEL expression evaluated by OpenBao.
    #[serde(
        default,
        rename = "cel_program",
        skip_serializing_if = "Option::is_none"
    )]
    pub expression: Option<String>,
    /// Optional description for this CEL role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// PKI CEL role configuration returned by OpenBao.
///
/// CEL roles are newer OpenBao PKI functionality. Unknown fields are retained
/// in `extra` for forward-compatible reads, but writes use
/// [`PkiCelRoleRequest`] so callers do not accidentally smuggle arbitrary JSON
/// through a typed helper.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiCelRole {
    /// CEL expression evaluated by OpenBao.
    #[serde(default, alias = "cel_program")]
    pub expression: Option<String>,
    /// Optional description for this CEL role.
    #[serde(default)]
    pub description: Option<String>,
    /// Additional OpenBao-documented role fields not yet modelled explicitly.
    #[serde(default, deserialize_with = "deserialize_bounded_json_map")]
    #[serde(flatten)]
    pub extra: BTreeMap<String, JsonValue>,
}

/// PKI CEL role list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PkiCelRoleList {
    /// CEL role names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for PkiCelRoleList {
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

impl Client<Unauthenticated> {
    /// Uses public endpoints on the PKI engine mounted at `mount`.
    pub fn pki_public(&self, mount: impl Into<String>) -> Result<PkiPublic<'_>> {
        let mount = mount.into();
        Ok(PkiPublic {
            client: self,
            mount: validate_mount_path(&mount)?,
        })
    }
}

impl PkiPublic<'_> {
    /// Reads the default CA certificate as DER.
    pub async fn ca_der(&self) -> Result<SecretVec> {
        self.get(&["ca"], "application/pkix-cert").await
    }

    /// Reads the default CA certificate as PEM.
    pub async fn ca_pem(&self) -> Result<SecretVec> {
        self.get(&["ca", "pem"], "application/x-pem-file").await
    }

    /// Reads the default CA chain as PEM.
    pub async fn ca_chain_pem(&self) -> Result<SecretVec> {
        self.get(&["ca_chain"], "application/x-pem-file").await
    }

    /// Reads the legacy CA distribution path as DER.
    pub async fn legacy_ca_der(&self) -> Result<SecretVec> {
        self.get(&["cert", "ca"], "application/pkix-cert").await
    }

    /// Reads the legacy CA-chain distribution path as PEM.
    pub async fn legacy_ca_chain_pem(&self) -> Result<SecretVec> {
        self.get(&["cert", "ca_chain"], "application/x-pem-file")
            .await
    }

    /// Reads the current CRL as DER.
    pub async fn crl_der(&self) -> Result<SecretVec> {
        self.get(&["crl"], "application/pkix-crl").await
    }

    /// Reads the current CRL as PEM.
    pub async fn crl_pem(&self) -> Result<SecretVec> {
        self.get(&["crl", "pem"], "application/x-pem-file").await
    }

    /// Reads the current delta CRL as DER.
    pub async fn delta_crl_der(&self) -> Result<SecretVec> {
        self.get(&["crl", "delta"], "application/pkix-crl").await
    }

    /// Reads the current delta CRL as PEM.
    pub async fn delta_crl_pem(&self) -> Result<SecretVec> {
        self.get(&["crl", "delta", "pem"], "application/x-pem-file")
            .await
    }

    /// Reads the legacy CRL distribution path as DER.
    pub async fn legacy_crl_der(&self) -> Result<SecretVec> {
        self.get(&["cert", "crl"], "application/pkix-crl").await
    }

    /// Reads the legacy delta-CRL distribution path as DER.
    pub async fn legacy_delta_crl_der(&self) -> Result<SecretVec> {
        self.get(&["cert", "delta-crl"], "application/pkix-crl")
            .await
    }

    /// Reads a stored certificate by serial as DER.
    pub async fn certificate_der(&self, serial: &str) -> Result<SecretVec> {
        self.get(&["cert", serial, "raw"], "application/pkix-cert")
            .await
    }

    /// Reads a stored certificate by serial as PEM.
    pub async fn certificate_pem(&self, serial: &str) -> Result<SecretVec> {
        self.get(&["cert", serial, "raw", "pem"], "application/x-pem-file")
            .await
    }

    /// Reads an issuer certificate in the requested representation.
    pub async fn issuer_certificate(
        &self,
        issuer_ref: &str,
        format: PkiPublicFormat,
    ) -> Result<SecretVec> {
        let (suffix, accept) = match format {
            PkiPublicFormat::Der => ("der", "application/pkix-cert"),
            PkiPublicFormat::Pem => ("pem", "application/x-pem-file"),
            PkiPublicFormat::Json => ("json", "application/json"),
        };
        self.get(&["issuer", issuer_ref, suffix], accept).await
    }

    /// Reads an issuer CRL or delta CRL in the requested representation.
    pub async fn issuer_crl(
        &self,
        issuer_ref: &str,
        delta: bool,
        format: PkiPublicFormat,
    ) -> Result<SecretVec> {
        let (suffix, accept) = match format {
            PkiPublicFormat::Der => (Some("der"), "application/pkix-crl"),
            PkiPublicFormat::Pem => (Some("pem"), "application/x-pem-file"),
            PkiPublicFormat::Json => (None, "application/json"),
        };
        let mut tail = vec!["issuer", issuer_ref, "crl"];
        if delta {
            tail.push("delta");
        }
        if let Some(suffix) = suffix {
            tail.push(suffix);
        }
        self.get(&tail, accept).await
    }

    /// Sends a DER OCSP request using the documented POST transport.
    pub async fn ocsp_post(&self, request_der: &[u8]) -> Result<SecretVec> {
        if request_der.is_empty() {
            return Err(Error::InvalidParameter(
                "OCSP request must not be empty".into(),
            ));
        }
        self.bytes(
            Method::POST,
            &self.path(&["ocsp"])?,
            &[
                (
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/ocsp-request"),
                ),
                (
                    ACCEPT,
                    HeaderValue::from_static("application/ocsp-response"),
                ),
            ],
            Some(request_der),
        )
        .await
    }

    /// Sends a URL-safe base64 encoded DER OCSP request using GET.
    ///
    /// Encoding and ASN.1 parsing remain the responsibility of the caller's
    /// OCSP library; this helper validates and transports one path segment.
    pub async fn ocsp_get_encoded(&self, encoded_request: &str) -> Result<SecretVec> {
        if encoded_request.is_empty()
            || !encoded_request
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(Error::InvalidParameter(
                "encoded OCSP request must be unpadded URL-safe base64".into(),
            ));
        }
        self.bytes(
            Method::GET,
            &self.path(&["ocsp", encoded_request])?,
            &[(
                ACCEPT,
                HeaderValue::from_static("application/ocsp-response"),
            )],
            None,
        )
        .await
    }

    /// Builds a reviewed handoff configuration for an ACME client library.
    #[cfg(feature = "acme-protocol")]
    pub fn acme_client_config(
        &self,
        scope: PkiAcmeScope,
        external_account_binding: Option<PkiAcmeEabToken>,
    ) -> Result<PkiAcmeClientConfig> {
        let path = match scope {
            PkiAcmeScope::Default => self.path(&["acme", "directory"])?,
            PkiAcmeScope::Issuer(issuer_ref) => {
                self.path(&["issuer", &issuer_ref, "acme", "directory"])?
            }
            PkiAcmeScope::Role(role) => self.path(&["roles", &role, "acme", "directory"])?,
            PkiAcmeScope::IssuerRole { issuer_ref, role } => {
                self.path(&["issuer", &issuer_ref, "roles", &role, "acme", "directory"])?
            }
        };
        Ok(PkiAcmeClientConfig {
            directory_url: self.client.url_for_path(&path)?,
            external_account_binding,
        })
    }

    async fn get(&self, tail: &[&str], accept: &'static str) -> Result<SecretVec> {
        self.bytes(
            Method::GET,
            &self.path(tail)?,
            &[(ACCEPT, HeaderValue::from_static(accept))],
            None,
        )
        .await
    }

    async fn bytes(
        &self,
        method: Method,
        path: &str,
        headers: &[(reqwest::header::HeaderName, HeaderValue)],
        body: Option<&[u8]>,
    ) -> Result<SecretVec> {
        let mount = self.mount.join("/");
        self.client
            .request_secret_bytes_headers_accepting(
                "/pki/",
                "pki",
                &mount,
                method,
                path,
                &[] as &[(&str, String)],
                headers,
                body,
                &[StatusCode::OK],
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

    /// Generates a multi-issuer-aware root CA certificate.
    pub async fn generate_issuer_root(
        &self,
        generation_type: PkiKeyGenerationType,
        request: &PkiGenerateRootRequest,
    ) -> Result<PkiAuthorityBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&[
                "issuers",
                "generate",
                "root",
                generation_type.as_path_segment(),
            ])?,
            Some(request),
        )
        .await
    }

    /// Rotates the root CA certificate for this PKI mount.
    pub async fn rotate_root(
        &self,
        generation_type: PkiKeyGenerationType,
        request: &PkiGenerateRootRequest,
    ) -> Result<PkiAuthorityBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&["root", "rotate", generation_type.as_path_segment()])?,
            Some(request),
        )
        .await
    }

    /// Updates the default root issuer reference.
    pub async fn replace_root(&self, config: &PkiIssuersConfig) -> Result<PkiIssuersConfig> {
        self.enveloped(
            Method::POST,
            &self.path(&["root", "replace"])?,
            Some(config),
        )
        .await
    }

    /// Generates standalone key material for this PKI mount.
    pub async fn generate_key(
        &self,
        generation_type: PkiKeyGenerationType,
        request: &PkiGenerateKeyRequest,
    ) -> Result<PkiGeneratedKey> {
        self.enveloped(
            Method::POST,
            &self.path(&["keys", "generate", generation_type.as_path_segment()])?,
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
        self.request_accepting(
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

    /// Generates a multi-issuer-aware intermediate CA CSR and key material.
    pub async fn generate_issuer_intermediate(
        &self,
        generation_type: PkiKeyGenerationType,
        request: &PkiGenerateIntermediateRequest,
    ) -> Result<PkiAuthorityBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&[
                "issuers",
                "generate",
                "intermediate",
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

    /// Signs an intermediate CA CSR with an explicit issuer.
    pub async fn sign_intermediate_with_issuer(
        &self,
        issuer_ref: &str,
        request: &PkiSignIntermediateRequest,
    ) -> Result<PkiCertificateBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&["issuer", issuer_ref, "sign-intermediate"])?,
            Some(request),
        )
        .await
    }

    /// Signs a self-issued certificate with the default root.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`
    /// because this can establish cross-trust with an external CA.
    #[cfg(feature = "operator-ops")]
    pub async fn sign_self_issued(
        &self,
        request: &PkiSignSelfIssuedRequest,
    ) -> Result<PkiCertificateBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&["root", "sign-self-issued"])?,
            Some(request),
        )
        .await
    }

    /// Signs a self-issued certificate with an explicit issuer.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`
    /// because this can establish cross-trust with an external CA.
    #[cfg(feature = "operator-ops")]
    pub async fn sign_self_issued_with_issuer(
        &self,
        issuer_ref: &str,
        request: &PkiSignSelfIssuedRequest,
    ) -> Result<PkiCertificateBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&["issuer", issuer_ref, "sign-self-issued"])?,
            Some(request),
        )
        .await
    }

    /// Cross-signs an intermediate CA CSR for CA migration workflows.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    #[cfg(feature = "operator-ops")]
    pub async fn cross_sign_intermediate(
        &self,
        request: &PkiSignIntermediateRequest,
    ) -> Result<PkiCertificateBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&["intermediate", "cross-sign"])?,
            Some(request),
        )
        .await
    }

    /// Installs a signed intermediate certificate.
    pub async fn set_signed_intermediate(
        &self,
        request: &PkiSetSignedIntermediateRequest,
    ) -> Result<Empty> {
        self.request(
            Method::POST,
            &self.path(&["intermediate", "set-signed"])?,
            Some(request),
        )
        .await
    }

    /// Creates or replaces a PKI role.
    pub async fn write_role(&self, name: &str, role: &PkiRole) -> Result<Empty> {
        self.request(Method::POST, &self.path(&["roles", name])?, Some(role))
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
        self.request_accepting(
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
        self.request(Method::POST, &self.path(&["config", "urls"])?, Some(config))
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
        self.request(
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
        self.request(Method::POST, &self.path(&["config", "keys"])?, Some(config))
            .await
    }

    /// Reads PKI cluster-local configuration.
    pub async fn read_cluster_config(&self) -> Result<PkiClusterConfig> {
        self.enveloped(
            Method::GET,
            &self.path(&["config", "cluster"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Sets PKI cluster-local configuration.
    pub async fn write_cluster_config(&self, config: &PkiClusterConfig) -> Result<Empty> {
        self.request(
            Method::POST,
            &self.path(&["config", "cluster"])?,
            Some(config),
        )
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
        self.request(Method::POST, &self.path(&["config", "crl"])?, Some(config))
            .await
    }

    /// Rotates the CRL.
    pub async fn rotate_crl(&self) -> Result<PkiRotateCrlResponse> {
        self.enveloped(
            Method::GET,
            &self.path(&["crl", "rotate"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Rotates the delta CRL.
    pub async fn rotate_delta_crl(&self) -> Result<PkiRotateCrlResponse> {
        self.enveloped(
            Method::GET,
            &self.path(&["crl", "rotate-delta"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Starts PKI tidy with the requested options.
    pub async fn tidy(&self, request: &PkiTidyRequest) -> Result<Empty> {
        self.request(Method::POST, &self.path(&["tidy"])?, Some(request))
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

    /// Reads PKI automatic tidy configuration.
    pub async fn read_auto_tidy_config(&self) -> Result<PkiAutoTidyConfig> {
        self.enveloped(
            Method::GET,
            &self.path(&["config", "auto-tidy"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Sets PKI automatic tidy configuration.
    pub async fn write_auto_tidy_config(&self, config: &PkiAutoTidyConfig) -> Result<Empty> {
        self.request(
            Method::POST,
            &self.path(&["config", "auto-tidy"])?,
            Some(config),
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

    /// Issues a certificate and private key using a PKI role and explicit issuer.
    pub async fn issue_with_issuer(
        &self,
        issuer_ref: &str,
        role: &str,
        request: &PkiIssueRequest,
    ) -> Result<PkiCertificateBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&["issuer", issuer_ref, "issue", role])?,
            Some(request),
        )
        .await
    }

    /// Signs a caller-provided CSR using a PKI role.
    pub async fn sign(&self, role: &str, request: &PkiSignRequest) -> Result<PkiCertificateBundle> {
        self.enveloped(Method::POST, &self.path(&["sign", role])?, Some(request))
            .await
    }

    /// Signs a caller-provided CSR using a PKI role and explicit issuer.
    pub async fn sign_with_issuer(
        &self,
        issuer_ref: &str,
        role: &str,
        request: &PkiSignRequest,
    ) -> Result<PkiCertificateBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&["issuer", issuer_ref, "sign", role])?,
            Some(request),
        )
        .await
    }

    /// Signs a CSR verbatim with the default issuer.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    /// This bypasses normal PKI role constraints and should be restricted to
    /// highly trusted operator automation.
    #[cfg(feature = "operator-ops")]
    pub async fn sign_verbatim(
        &self,
        request: &PkiSignVerbatimRequest,
    ) -> Result<PkiCertificateBundle> {
        self.enveloped(Method::POST, &self.path(&["sign-verbatim"])?, Some(request))
            .await
    }

    /// Signs a CSR verbatim while routing through a named sign-verbatim path.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    /// This bypasses normal PKI role constraints and should be restricted to
    /// highly trusted operator automation.
    #[cfg(feature = "operator-ops")]
    pub async fn sign_verbatim_at_role(
        &self,
        role: &str,
        request: &PkiSignVerbatimRequest,
    ) -> Result<PkiCertificateBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&["sign-verbatim", role])?,
            Some(request),
        )
        .await
    }

    /// Signs a CSR verbatim with an explicit issuer.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    /// This bypasses normal PKI role constraints and should be restricted to
    /// highly trusted operator automation.
    #[cfg(feature = "operator-ops")]
    pub async fn sign_verbatim_with_issuer(
        &self,
        issuer_ref: &str,
        request: &PkiSignVerbatimRequest,
    ) -> Result<PkiCertificateBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&["issuer", issuer_ref, "sign-verbatim"])?,
            Some(request),
        )
        .await
    }

    /// Signs a CSR verbatim with an explicit issuer and named path.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    /// This bypasses normal PKI role constraints and should be restricted to
    /// highly trusted operator automation.
    #[cfg(feature = "operator-ops")]
    pub async fn sign_verbatim_with_issuer_at_role(
        &self,
        issuer_ref: &str,
        role: &str,
        request: &PkiSignVerbatimRequest,
    ) -> Result<PkiCertificateBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&["issuer", issuer_ref, "sign-verbatim", role])?,
            Some(request),
        )
        .await
    }

    /// Revokes a certificate by serial number.
    pub async fn revoke(&self, request: &PkiRevokeRequest) -> Result<PkiRevokeResponse> {
        self.enveloped(Method::POST, &self.path(&["revoke"])?, Some(request))
            .await
    }

    /// Revokes a certificate by proving possession of its private key.
    ///
    /// The private key is accepted as [`SecretString`] and redacted from
    /// `Debug`. OpenBao documents this endpoint as authenticated but not a
    /// privileged operator action; access should still be scoped carefully to
    /// avoid unwanted revocation.
    pub async fn revoke_with_key(
        &self,
        request: &PkiRevokeWithKeyRequest,
    ) -> Result<PkiRevokeResponse> {
        self.enveloped(
            Method::POST,
            &self.path(&["revoke-with-key"])?,
            Some(request),
        )
        .await
    }

    /// Lists known certificate serial numbers.
    pub async fn list_certificates(&self) -> Result<PkiCertificateList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        self.enveloped(method, &self.path(&["certs"])?, Option::<&Empty>::None)
            .await
    }

    /// Lists revoked certificate serial numbers.
    pub async fn list_revoked_certificates(&self) -> Result<PkiCertificateList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        self.enveloped(
            method,
            &self.path(&["certs", "revoked"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Lists certificate revocation queue entries.
    pub async fn list_revocation_queue(&self) -> Result<PkiRevocationQueueList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        self.enveloped(
            method,
            &self.path(&["certs", "revocation-queue"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Lists certificate serial numbers with detailed metadata.
    pub async fn list_certificates_detailed(
        &self,
        after: Option<&str>,
        limit: Option<u64>,
    ) -> Result<PkiDetailedCertificateList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let mut query = ListPageOptions::from_after_limit(after, limit)?.query_pairs();
        query.insert(0, ("detailed", "true".to_owned()));
        let envelope: ResponseEnvelope<PkiDetailedCertificateList> = self
            .request_query(
                method,
                &self.path(&["certs", "detailed"])?,
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
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

    /// Resigns CRLs for an issuer.
    pub async fn resign_crls(&self, issuer_ref: &str) -> Result<PkiCrlBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&["issuer", issuer_ref, "resign-crls"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Manually signs a revocation list with an issuer.
    ///
    /// Available only with `operator-ops` and `operator-ops-acknowledged`.
    /// This can create arbitrary CRL material and should be restricted to
    /// trusted PKI operator automation.
    #[cfg(feature = "operator-ops")]
    pub async fn sign_revocation_list(
        &self,
        issuer_ref: &str,
        request: &PkiSignRevocationListRequest,
    ) -> Result<PkiCrlBundle> {
        if request.extensions.len() > crate::response::MAX_RESPONSE_STRINGS {
            return Err(Error::InvalidParameter(
                "PKI CRL extensions exceed item limit".into(),
            ));
        }
        self.enveloped(
            Method::POST,
            &self.path(&["issuer", issuer_ref, "sign-revocation-list"])?,
            Some(request),
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
        self.request_accepting(
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
        self.request_accepting(
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
        self.request_accepting(
            Method::DELETE,
            &self.path(&["eab", key_id])?,
            Option::<&Empty>::None,
            &[StatusCode::OK, StatusCode::NO_CONTENT],
        )
        .await
    }

    /// Writes a PKI CEL role.
    ///
    /// CEL roles are newer OpenBao PKI functionality; callers should test this
    /// workflow against the OpenBao version they deploy.
    pub async fn write_cel_role(&self, name: &str, role: &PkiCelRoleRequest) -> Result<Empty> {
        self.request(
            Method::POST,
            &self.path(&["cel", "roles", name])?,
            Some(role),
        )
        .await
    }

    /// Patches a PKI CEL role with JSON Merge Patch semantics.
    pub async fn patch_cel_role(
        &self,
        name: &str,
        patch: &PkiCelRoleRequest,
    ) -> Result<PkiCelRole> {
        self.enveloped_with_headers(
            Method::PATCH,
            &self.path(&["cel", "roles", name])?,
            &[(
                CONTENT_TYPE,
                HeaderValue::from_static("application/merge-patch+json"),
            )],
            Some(patch),
        )
        .await
    }

    /// Reads a PKI CEL role.
    pub async fn read_cel_role(&self, name: &str) -> Result<PkiCelRole> {
        self.enveloped(
            Method::GET,
            &self.path(&["cel", "roles", name])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Lists PKI CEL role names.
    pub async fn list_cel_roles(&self) -> Result<PkiCelRoleList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        self.enveloped(
            method,
            &self.path(&["cel", "roles"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Deletes a PKI CEL role.
    pub async fn delete_cel_role(&self, name: &str) -> Result<Empty> {
        self.request_accepting(
            Method::DELETE,
            &self.path(&["cel", "roles", name])?,
            Option::<&Empty>::None,
            &[StatusCode::OK, StatusCode::NO_CONTENT],
        )
        .await
    }

    /// Issues a certificate and private key using a PKI CEL role.
    pub async fn cel_issue(
        &self,
        role: &str,
        request: &PkiIssueRequest,
    ) -> Result<PkiCertificateBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&["cel", "issue", role])?,
            Some(request),
        )
        .await
    }

    /// Signs a caller-provided CSR using a PKI CEL role.
    pub async fn cel_sign(
        &self,
        role: &str,
        request: &PkiSignRequest,
    ) -> Result<PkiCertificateBundle> {
        self.enveloped(
            Method::POST,
            &self.path(&["cel", "sign", role])?,
            Some(request),
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
        let envelope: ResponseEnvelope<T> = self.request(method, path, request).await?;
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
            .request_query_headers(
                method,
                path,
                &[] as &[(&str, String)],
                headers,
                request,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    async fn request<T, B>(&self, method: Method, path: &str, body: Option<&B>) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
        B: Serialize + ?Sized,
    {
        let mount = self.mount.join("/");
        self.client
            .request_secret_json_internal("/pki/", "pki", &mount, method, path, body)
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
        T: for<'de> Deserialize<'de>,
        B: Serialize + ?Sized,
    {
        let mount = self.mount.join("/");
        self.client
            .request_secret_json_accepting(
                "/pki/",
                "pki",
                &mount,
                method,
                path,
                body,
                accepted_statuses,
            )
            .await
    }

    async fn request_query<T, B, Q, K>(
        &self,
        method: Method,
        path: &str,
        query: &[(K, Q)],
        body: Option<&B>,
        accepted_statuses: &[StatusCode],
    ) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
        B: Serialize + ?Sized,
        Q: AsRef<str>,
        K: AsRef<str>,
    {
        self.request_query_headers(method, path, query, &[], body, accepted_statuses)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_query_headers<T, B, Q, K>(
        &self,
        method: Method,
        path: &str,
        query: &[(K, Q)],
        headers: &[(reqwest::header::HeaderName, HeaderValue)],
        body: Option<&B>,
        accepted_statuses: &[StatusCode],
    ) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
        B: Serialize + ?Sized,
        Q: AsRef<str>,
        K: AsRef<str>,
    {
        let mount = self.mount.join("/");
        self.client
            .request_secret_json_query_headers_accepting(
                "/pki/",
                "pki",
                &mount,
                method,
                path,
                query,
                headers,
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
        formatter.write_str("null, a string duration, or an integer duration")
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
        deserialize_optional_string_or_u64(deserializer)
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

fn deserialize_bounded_json_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, JsonValue>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(BoundedJsonMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

fn deserialize_bounded_primitive_json_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, JsonValue>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(
        BoundedPrimitiveJsonMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>,
    )
}

struct BoundedJsonMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedJsonMapVisitor<MAX> {
    type Value = BTreeMap<String, JsonValue>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} JSON metadata entries")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, JsonValue>()? else {
                return Ok(values);
            };
            values.insert(key, value);
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(
                "OpenBao JSON metadata map exceeds item limit",
            ));
        }
        Ok(values)
    }
}

struct BoundedPrimitiveJsonMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedPrimitiveJsonMapVisitor<MAX> {
    type Value = BTreeMap<String, JsonValue>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a map of at most {MAX} primitive JSON metadata entries"
        )
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, JsonValue>()? else {
                return Ok(values);
            };
            if value.is_array() || value.is_object() {
                return Err(serde::de::Error::custom(
                    "OpenBao JSON metadata values must be primitive",
                ));
            }
            values.insert(key, value);
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(
                "OpenBao JSON metadata map exceeds item limit",
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
        PkiAcmeConfig, PkiAcmeEabList, PkiAcmeEabToken, PkiAuthorityBundle, PkiAutoTidyConfig,
        PkiCelRole, PkiCertificateBundle, PkiDetailedCertificateList, PkiGenerateRootRequest,
        PkiImportResponse, PkiIssuerInfo, PkiIssuerList, PkiIssuersConfig, PkiKeyList,
        PkiRevocationQueueList, PkiRevokeWithKeyRequest, PkiRole, PkiRoleList, PkiTidyStatus,
    };

    #[test]
    fn pki_role_accepts_string_and_array_lists() {
        let role: PkiRole = serde_json::from_str(
            r#"{
                "allowed_domains":"example.com,api.example.com",
                "allowed_uri_sans":"spiffe://example.com/*",
                "allowed_other_sans":["1.2.3.4;UTF8:*"],
                "allowed_serial_numbers":"device-1,device-2",
                "organization":["Example Org"],
                "country":"SE",
                "key_usage":["DigitalSignature"]
            }"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(role.allowed_domains, ["example.com", "api.example.com"]);
        assert_eq!(role.allowed_uri_sans, ["spiffe://example.com/*"]);
        assert_eq!(role.allowed_other_sans, ["1.2.3.4;UTF8:*"]);
        assert_eq!(role.allowed_serial_numbers, ["device-1", "device-2"]);
        assert_eq!(role.organization, ["Example Org"]);
        assert_eq!(role.country, ["SE"]);
        assert_eq!(role.key_usage, ["DigitalSignature"]);
    }

    #[test]
    fn pki_generation_requests_serialize_current_doc_fields() {
        let request = PkiGenerateRootRequest {
            common_name: "root.example.com".to_owned(),
            permitted_dns_domains: vec!["example.com".to_owned()],
            organization: vec!["Example Org".to_owned()],
            country: vec!["SE".to_owned()],
            serial_number: Some("subject-serial".to_owned()),
            max_path_length: Some(1),
            key_usage: vec!["CertSign".to_owned()],
            ext_key_usage_oids: vec!["1.2.3.4".to_owned()],
            add_basic_constraints: Some(true),
            revocation_signature_algorithm: Some("SHA256WithRSA".to_owned()),
            enable_aia_url_templating: Some(true),
            ..Default::default()
        };
        let value = serde_json::to_value(request).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(value["permitted_dns_domains"][0], "example.com");
        assert_eq!(value["organization"][0], "Example Org");
        assert_eq!(value["country"][0], "SE");
        assert_eq!(value["serial_number"], "subject-serial");
        assert_eq!(value["max_path_length"], 1);
        assert_eq!(value["key_usage"][0], "CertSign");
        assert_eq!(value["ext_key_usage_oids"][0], "1.2.3.4");
        assert_eq!(value["add_basic_constraints"], true);
        assert_eq!(value["revocation_signature_algorithm"], "SHA256WithRSA");
        assert_eq!(value["enable_aia_url_templating"], true);
    }

    #[test]
    fn pki_cel_requests_use_the_documented_program_field() {
        let value = serde_json::to_value(super::PkiCelRoleRequest {
            expression: Some("subject.common_name == 'web'".to_owned()),
            description: None,
        })
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(value.get("expression").is_none());
        assert_eq!(value["cel_program"], "subject.common_name == 'web'");

        let role: super::PkiCelRole =
            serde_json::from_value(value).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            role.expression.as_deref(),
            Some("subject.common_name == 'web'")
        );
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
    fn pki_auto_tidy_config_accepts_integer_duration_responses() {
        let config: PkiAutoTidyConfig = serde_json::from_str(
            r#"{"enabled":true,"interval_duration":43200,"safety_buffer":259200,"pause_duration":"0s"}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(config.interval_duration.as_deref(), Some("43200"));
        assert_eq!(config.safety_buffer.as_deref(), Some("259200"));
        assert_eq!(config.pause_duration.as_deref(), Some("0s"));
    }

    #[test]
    fn pki_tidy_status_accepts_current_doc_fields() {
        let status: PkiTidyStatus = serde_json::from_str(
            r#"{
                "safety_buffer":60,
                "tidy_cross_cluster_revoked_certs":true,
                "missing_issuer_cert_count":2,
                "revocation_queue_deleted_count":3,
                "cross_revoked_cert_deleted_count":4,
                "issuer_safety_buffer":31536000,
                "revocation_queue_safety_buffer":172800,
                "page_size":50,
                "last_auto_tidy_finished":"2026-06-04T00:00:00Z"
            }"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(status.missing_issuer_cert_count, Some(2));
        assert_eq!(status.revocation_queue_deleted_count, Some(3));
        assert_eq!(status.cross_revoked_cert_deleted_count, Some(4));
        assert_eq!(status.issuer_safety_buffer.as_deref(), Some("31536000"));
        assert_eq!(
            status.revocation_queue_safety_buffer.as_deref(),
            Some("172800")
        );
        assert_eq!(status.page_size, Some(50));
        assert_eq!(
            status.last_auto_tidy_finished.as_deref(),
            Some("2026-06-04T00:00:00Z")
        );
    }

    #[test]
    fn pki_revoke_with_key_request_redacts_private_key_debug() {
        let request =
            PkiRevokeWithKeyRequest::new("01:02", SecretString::from(["private-", "key"].concat()));

        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("private-key"));
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
    fn pki_specialized_metadata_maps_are_bounded() {
        let mut exact_key_info = serde_json::Map::new();
        for index in 0..crate::response::MAX_RESPONSE_STRINGS {
            exact_key_info.insert(format!("{index:04x}"), serde_json::json!(1_893_456_000_u64));
        }
        let exact = serde_json::json!({
            "keys": ["0000"],
            "key_info": exact_key_info
        });
        let detailed: PkiDetailedCertificateList =
            serde_json::from_value(exact).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(detailed.keys, ["0000"]);
        assert_eq!(
            detailed.key_info.len(),
            crate::response::MAX_RESPONSE_STRINGS
        );

        let mut overflow_key_info = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            overflow_key_info.insert(format!("{index:04x}"), serde_json::json!(1_893_456_000_u64));
        }
        let overflow = serde_json::json!({
            "keys": ["0000"],
            "key_info": overflow_key_info
        });
        let error = match serde_json::from_value::<PkiDetailedCertificateList>(overflow.clone()) {
            Ok(_) => panic!("oversized PKI detailed certificate list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("OpenBao JSON metadata map exceeds item limit")
        );
        let error = match serde_json::from_value::<PkiRevocationQueueList>(overflow) {
            Ok(_) => panic!("oversized PKI revocation queue unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("OpenBao JSON metadata map exceeds item limit")
        );

        let nested = serde_json::json!({
            "keys": ["0000"],
            "key_info": {
                "0000": { "expiration": 1_893_456_000_u64 }
            }
        });
        let error = match serde_json::from_value::<PkiDetailedCertificateList>(nested) {
            Ok(_) => panic!("nested PKI detailed certificate metadata unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("OpenBao JSON metadata values must be primitive")
        );
    }

    #[test]
    fn pki_cel_role_preserves_bounded_extra_fields() {
        let role: PkiCelRole = serde_json::from_str(
            r#"{
                "expression":"subject.common_name.endsWith(\".example.com\")",
                "description":"web CEL role",
                "issuer_ref":"root-x1"
            }"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(role.description.as_deref(), Some("web CEL role"));
        assert_eq!(
            role.extra
                .get("issuer_ref")
                .and_then(|value| value.as_str()),
            Some("root-x1")
        );

        let mut overflow_extra = serde_json::Map::new();
        overflow_extra.insert("expression".to_owned(), serde_json::json!("true"));
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            overflow_extra.insert(format!("field_{index}"), serde_json::json!("value"));
        }
        let error =
            match serde_json::from_value::<PkiCelRole>(serde_json::Value::Object(overflow_extra)) {
                Ok(_) => panic!("oversized PKI CEL role extras unexpectedly decoded"),
                Err(error) => error,
            };
        assert!(
            error
                .to_string()
                .contains("OpenBao JSON metadata map exceeds item limit")
        );
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

    #[cfg(feature = "acme-protocol")]
    #[test]
    fn pki_acme_handoff_covers_all_scopes_and_redacts_eab_key() {
        let config = crate::OpenBaoConfig::new("http://127.0.0.1:8200")
            .and_then(crate::OpenBaoConfig::allow_localhost_http)
            .unwrap_or_else(|error| panic!("{error}"));
        let client = crate::Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));
        let pki = client
            .pki_public("team/pki")
            .unwrap_or_else(|error| panic!("{error}"));
        let scopes = [
            super::PkiAcmeScope::Default,
            super::PkiAcmeScope::Issuer("root".to_owned()),
            super::PkiAcmeScope::Role("web".to_owned()),
            super::PkiAcmeScope::IssuerRole {
                issuer_ref: "root".to_owned(),
                role: "web".to_owned(),
            },
        ];
        for scope in scopes {
            let config = pki
                .acme_client_config(
                    scope,
                    Some(super::PkiAcmeEabToken {
                        created_on: None,
                        id: "eab-id".to_owned(),
                        key_type: Some("hs".to_owned()),
                        acme_directory: None,
                        key: SecretString::from("eab-secret"),
                    }),
                )
                .unwrap_or_else(|error| panic!("{error}"));
            assert!(config.directory_url.path().ends_with("/acme/directory"));
            let debug = format!("{config:?}");
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("eab-secret"));
        }
    }
}
