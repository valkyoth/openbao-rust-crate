//! Transit secrets engine support.

use core::fmt;
use std::collections::BTreeMap;

use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as DeError, IgnoredAny, MapAccess, Visitor},
};
#[cfg(feature = "transit-import")]
use zeroize::Zeroize;
#[cfg(any(feature = "transit-bytes", feature = "transit-import"))]
use zeroize::Zeroizing;

use crate::{
    Authenticated, Client, Error, Result,
    path::{validate_endpoint_path, validate_mount_path},
    response::{
        Empty, ListEntries, ListPageOptions, ResponseEnvelope, deserialize_bounded_string_vec,
    },
};

#[cfg(feature = "transit-import")]
const TRANSIT_WRAPPING_KEY_BYTES: usize = 512;
#[cfg(feature = "transit-import")]
const TRANSIT_IMPORT_EPHEMERAL_AES_KEY_BYTES: usize = 32;
#[cfg(feature = "transit-import")]
const MAX_TRANSIT_IMPORT_KEY_MATERIAL_BYTES: usize = 16 * 1024;

/// Handle for a mounted Transit secrets engine.
#[derive(Debug)]
pub struct Transit<'a> {
    client: &'a Client<Authenticated>,
    mount: Vec<String>,
}

/// Transit key type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum TransitKeyType {
    /// AES-128-GCM with 96-bit nonce.
    #[serde(rename = "aes128-gcm96")]
    Aes128Gcm96,
    /// AES-256-GCM with 96-bit nonce.
    #[serde(rename = "aes256-gcm96")]
    Aes256Gcm96,
    /// ChaCha20-Poly1305.
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
    /// XChaCha20-Poly1305.
    #[serde(rename = "xchacha20-poly1305")]
    XChaCha20Poly1305,
    /// Ed25519 signing key.
    #[serde(rename = "ed25519")]
    Ed25519,
    /// ECDSA P-256 signing key.
    #[serde(rename = "ecdsa-p256")]
    EcdsaP256,
    /// ECDSA P-384 signing key.
    #[serde(rename = "ecdsa-p384")]
    EcdsaP384,
    /// ECDSA P-521 signing key.
    #[serde(rename = "ecdsa-p521")]
    EcdsaP521,
    /// RSA 2048-bit key.
    #[serde(rename = "rsa-2048")]
    Rsa2048,
    /// RSA 3072-bit key.
    #[serde(rename = "rsa-3072")]
    Rsa3072,
    /// RSA 4096-bit key.
    #[serde(rename = "rsa-4096")]
    Rsa4096,
    /// HMAC-only key.
    #[serde(rename = "hmac")]
    Hmac,
}

/// Transit data key return mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitDataKeyType {
    /// Return both plaintext and wrapped ciphertext.
    Plaintext,
    /// Return only wrapped ciphertext.
    Wrapped,
}

impl TransitDataKeyType {
    fn as_path_segment(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Wrapped => "wrapped",
        }
    }
}

/// Transit random source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitRandomSource {
    /// Use platform entropy.
    Platform,
    /// Use all available OpenBao entropy sources.
    All,
}

impl TransitRandomSource {
    fn as_path_segment(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::All => "all",
        }
    }
}

/// Hash or signature algorithm path segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitHashAlgorithm {
    /// SHA-1. Legacy only.
    #[cfg(feature = "allow-sha1")]
    #[deprecated(since = "0.3.0", note = "SHA-1 is broken; use SHA2-256 or stronger")]
    Sha1,
    /// SHA2-224.
    Sha2_224,
    /// SHA2-256.
    Sha2_256,
    /// SHA2-384.
    Sha2_384,
    /// SHA2-512.
    Sha2_512,
    /// SHA3-224.
    Sha3_224,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
    /// No hashing. Valid only for documented sign/verify cases.
    None,
}

impl TransitHashAlgorithm {
    fn as_path_segment(self) -> &'static str {
        match self {
            #[cfg(feature = "allow-sha1")]
            #[allow(deprecated)]
            Self::Sha1 => "sha1",
            Self::Sha2_224 => "sha2-224",
            Self::Sha2_256 => "sha2-256",
            Self::Sha2_384 => "sha2-384",
            Self::Sha2_512 => "sha2-512",
            Self::Sha3_224 => "sha3-224",
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_384 => "sha3-384",
            Self::Sha3_512 => "sha3-512",
            Self::None => "none",
        }
    }
}

/// Output encoding for Transit hash and random endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum TransitOutputFormat {
    /// Hexadecimal output.
    #[serde(rename = "hex")]
    Hex,
    /// Base64 output.
    #[serde(rename = "base64")]
    Base64,
}

/// RSA signature algorithm for Transit signing and verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum TransitSignatureAlgorithm {
    /// RSA-PSS.
    #[serde(rename = "pss")]
    Pss,
    /// RSASSA-PKCS1-v1_5.
    #[serde(rename = "pkcs1v15")]
    Pkcs1v15,
}

/// Signature marshaling format for Transit signing and verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum TransitMarshalingAlgorithm {
    /// ASN.1 format, used by OpenSSL and X.509.
    #[serde(rename = "asn1")]
    Asn1,
    /// JWS-compatible format for JWT/JWS workflows.
    #[serde(rename = "jws")]
    Jws,
}

/// RSA-PSS salt length selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitSaltLength {
    /// OpenBao/Golang default.
    Auto,
    /// Match the hash output length.
    Hash,
    /// Explicit salt length.
    Value(u64),
}

impl Serialize for TransitSaltLength {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Auto => serializer.serialize_str("auto"),
            Self::Hash => serializer.serialize_str("hash"),
            Self::Value(value) => serializer.serialize_u64(*value),
        }
    }
}

/// Request for creating a Transit key.
#[derive(Clone, Debug, Default, Serialize)]
pub struct TransitCreateKeyRequest {
    /// Key type. OpenBao defaults to `aes256-gcm96` when omitted.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub key_type: Option<TransitKeyType>,
    /// Whether convergent encryption is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convergent_encryption: Option<bool>,
    /// Whether key derivation is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived: Option<bool>,
    /// Whether key material may be exported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exportable: Option<bool>,
    /// Whether plaintext backup is allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_plaintext_backup: Option<bool>,
    /// Automatic rotation period, such as `24h`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_rotate_period: Option<String>,
}

impl TransitCreateKeyRequest {
    fn validate(&self) -> Result<()> {
        if let Some(period) = &self.auto_rotate_period {
            crate::validation::validate_duration_parameter(period, "Transit auto_rotate_period")?;
        }
        Ok(())
    }
}

/// Transit key information.
#[derive(Clone, Debug, Deserialize)]
pub struct TransitKeyInfo {
    /// Key name.
    #[serde(default)]
    pub name: Option<String>,
    /// OpenBao key type string.
    #[serde(rename = "type")]
    pub key_type: String,
    /// Whether deletion is allowed.
    #[serde(default)]
    pub deletion_allowed: bool,
    /// Whether derivation is required.
    #[serde(default)]
    pub derived: bool,
    /// Whether key material can be exported.
    #[serde(default)]
    pub exportable: bool,
    /// Whether plaintext backup is allowed.
    #[serde(default)]
    pub allow_plaintext_backup: bool,
    /// Key version creation times keyed by version string.
    #[serde(default, deserialize_with = "deserialize_bounded_u64_map")]
    pub keys: BTreeMap<String, u64>,
    /// Minimum version allowed for decryption or verification.
    #[serde(default)]
    pub min_decryption_version: u64,
    /// Minimum version allowed for encryption, signing, or HMAC generation.
    #[serde(default)]
    pub min_encryption_version: u64,
    /// Whether encryption is supported.
    #[serde(default)]
    pub supports_encryption: bool,
    /// Whether decryption is supported.
    #[serde(default)]
    pub supports_decryption: bool,
    /// Whether derivation is supported.
    #[serde(default)]
    pub supports_derivation: bool,
    /// Whether signing is supported.
    #[serde(default)]
    pub supports_signing: bool,
    /// Whether this key was imported.
    #[serde(default)]
    pub imported: bool,
}

/// Request for updating a Transit key's mutable configuration.
#[derive(Clone, Debug, Default, Serialize)]
pub struct TransitUpdateKeyRequest {
    /// Minimum version allowed for decryption or verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_decryption_version: Option<u64>,
    /// Minimum version allowed for encryption, signing, or HMAC generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_encryption_version: Option<u64>,
    /// Whether key deletion is allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion_allowed: Option<bool>,
    /// Whether raw key material may be exported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exportable: Option<bool>,
    /// Whether plaintext key backup is allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_plaintext_backup: Option<bool>,
    /// Automatic rotation period, such as `24h`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_rotate_period: Option<String>,
}

impl TransitUpdateKeyRequest {
    /// Allows the key to be deleted.
    #[must_use]
    pub fn allow_deletion(mut self) -> Self {
        self.deletion_allowed = Some(true);
        self
    }

    /// Sets the automatic rotation period after validating duration syntax.
    pub fn with_auto_rotate_period(mut self, period: impl Into<String>) -> Result<Self> {
        let period = period.into();
        crate::validation::validate_duration_parameter(&period, "Transit auto_rotate_period")?;
        self.auto_rotate_period = Some(period);
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        if let Some(period) = &self.auto_rotate_period {
            crate::validation::validate_duration_parameter(period, "Transit auto_rotate_period")?;
        }
        Ok(())
    }
}

/// RSA-OAEP hash function used for Transit BYOK import/export wrapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum TransitImportHashFunction {
    /// SHA-1. Legacy only.
    #[cfg(feature = "allow-sha1")]
    #[serde(rename = "SHA1")]
    #[deprecated(since = "0.11.0", note = "SHA-1 is broken; use SHA256 or stronger")]
    Sha1,
    /// SHA2-224.
    #[serde(rename = "SHA224")]
    Sha224,
    /// SHA2-256.
    #[serde(rename = "SHA256")]
    Sha256,
    /// SHA2-384.
    #[serde(rename = "SHA384")]
    Sha384,
    /// SHA2-512.
    #[serde(rename = "SHA512")]
    Sha512,
}

impl TransitImportHashFunction {
    fn as_query_value(self) -> &'static str {
        match self {
            #[cfg(feature = "allow-sha1")]
            #[allow(deprecated)]
            Self::Sha1 => "SHA1",
            Self::Sha224 => "SHA224",
            Self::Sha256 => "SHA256",
            Self::Sha384 => "SHA384",
            Self::Sha512 => "SHA512",
        }
    }
}

/// Transit wrapping key used by BYOK import workflows.
#[derive(Clone, Debug, Deserialize)]
pub struct TransitWrappingKey {
    /// RSA public key PEM returned by OpenBao.
    ///
    /// This is public certificate material. Raw key bytes to import must be
    /// wrapped outside this endpoint wrapper before constructing an import
    /// request.
    pub public_key: String,
}

/// Request for importing pre-wrapped Transit key material.
#[derive(Clone)]
pub struct TransitImportRequest {
    /// Base64 BYOK ciphertext produced outside this crate.
    pub ciphertext: Option<SecretString>,
    /// Plaintext PEM public key for public-key-only import.
    pub public_key: Option<String>,
    /// Transit key type to create.
    pub key_type: TransitKeyType,
    /// RSA-OAEP hash function used when producing `ciphertext`.
    pub hash_function: Option<TransitImportHashFunction>,
    /// Whether this imported key may be rotated inside OpenBao.
    pub allow_rotation: Option<bool>,
    /// Whether key derivation is enabled.
    pub derived: Option<bool>,
    /// Base64 derivation context. Required by OpenBao when `derived=true`.
    pub context: Option<SecretString>,
    /// Whether key material may be exported.
    pub exportable: Option<bool>,
    /// Whether plaintext backup is allowed.
    pub allow_plaintext_backup: Option<bool>,
    /// Automatic rotation period, such as `24h`.
    pub auto_rotate_period: Option<String>,
}

impl fmt::Debug for TransitImportRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitImportRequest")
            .field(
                "ciphertext",
                &self.ciphertext.as_ref().map(|_| "<redacted>"),
            )
            .field("public_key", &self.public_key)
            .field("key_type", &self.key_type)
            .field("hash_function", &self.hash_function)
            .field("allow_rotation", &self.allow_rotation)
            .field("derived", &self.derived)
            .field("context", &self.context.as_ref().map(|_| "<redacted>"))
            .field("exportable", &self.exportable)
            .field("allow_plaintext_backup", &self.allow_plaintext_backup)
            .field("auto_rotate_period", &self.auto_rotate_period)
            .finish()
    }
}

impl TransitImportRequest {
    /// Creates an import request from a pre-wrapped BYOK ciphertext blob.
    ///
    /// The crate does not perform client-side BYOK wrapping in this endpoint
    /// wrapper. Raw key bytes must not be passed here. Use
    /// [`Transit::wrapping_key`] to obtain OpenBao's RSA wrapping public key,
    /// wrap key material externally through an HSM, OpenSSL, or a reviewed
    /// crypto library, then pass only the base64 ciphertext blob here.
    pub fn new(ciphertext: SecretString, key_type: TransitKeyType) -> Result<Self> {
        validate_non_empty_secret(&ciphertext, "Transit import ciphertext")?;
        Ok(Self {
            ciphertext: Some(ciphertext),
            public_key: None,
            key_type,
            hash_function: None,
            allow_rotation: None,
            derived: None,
            context: None,
            exportable: None,
            allow_plaintext_backup: None,
            auto_rotate_period: None,
        })
    }

    /// Creates a public-key-only import request.
    ///
    /// Public-key-only Transit keys can support verification and encryption
    /// operations, depending on key type and OpenBao policy, but no private key
    /// material is imported.
    pub fn from_public_key(
        public_key: impl Into<String>,
        key_type: TransitKeyType,
    ) -> Result<Self> {
        let public_key = public_key.into();
        validate_non_empty_public_key(&public_key, "Transit import public_key")?;
        Ok(Self {
            ciphertext: None,
            public_key: Some(public_key),
            key_type,
            hash_function: None,
            allow_rotation: None,
            derived: None,
            context: None,
            exportable: None,
            allow_plaintext_backup: None,
            auto_rotate_period: None,
        })
    }

    /// Sets the BYOK wrapping hash function.
    #[must_use]
    pub fn with_hash_function(mut self, hash_function: TransitImportHashFunction) -> Self {
        self.hash_function = Some(hash_function);
        self
    }

    /// Allows OpenBao-side rotation of the imported key.
    #[must_use]
    pub fn allow_rotation(mut self) -> Self {
        self.allow_rotation = Some(true);
        self
    }

    /// Sets base64 derivation context for derived imported keys.
    #[must_use]
    pub fn with_context(mut self, context: SecretString) -> Self {
        self.derived = Some(true);
        self.context = Some(context);
        self
    }

    /// Marks the imported key as exportable.
    #[must_use]
    pub fn exportable(mut self) -> Self {
        self.exportable = Some(true);
        self
    }

    /// Allows plaintext backup of the imported key.
    #[must_use]
    pub fn allow_plaintext_backup(mut self) -> Self {
        self.allow_plaintext_backup = Some(true);
        self
    }

    /// Sets the automatic rotation period after validating duration syntax.
    pub fn with_auto_rotate_period(mut self, period: impl Into<String>) -> Result<Self> {
        let period = period.into();
        crate::validation::validate_duration_parameter(&period, "Transit auto_rotate_period")?;
        self.auto_rotate_period = Some(period);
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        validate_import_material(
            self.ciphertext.as_ref(),
            self.public_key.as_deref(),
            "Transit import",
        )?;
        if let Some(period) = &self.auto_rotate_period {
            crate::validation::validate_duration_parameter(period, "Transit auto_rotate_period")?;
        }
        Ok(())
    }
}

/// Request for importing a new version of an existing imported Transit key.
#[derive(Clone)]
pub struct TransitImportVersionRequest {
    /// Base64 BYOK ciphertext produced outside this crate.
    pub ciphertext: Option<SecretString>,
    /// Plaintext PEM public key for public-key-only import.
    pub public_key: Option<String>,
    /// RSA-OAEP hash function used when producing `ciphertext`.
    pub hash_function: Option<TransitImportHashFunction>,
    /// Base64 derivation context for derived keys.
    pub context: Option<SecretString>,
    /// Existing key version to update.
    pub version: Option<u64>,
}

impl fmt::Debug for TransitImportVersionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitImportVersionRequest")
            .field(
                "ciphertext",
                &self.ciphertext.as_ref().map(|_| "<redacted>"),
            )
            .field("public_key", &self.public_key)
            .field("hash_function", &self.hash_function)
            .field("context", &self.context.as_ref().map(|_| "<redacted>"))
            .field("version", &self.version)
            .finish()
    }
}

impl TransitImportVersionRequest {
    /// Creates an import-version request from a pre-wrapped BYOK ciphertext.
    ///
    /// The crate does not perform client-side BYOK wrapping in this endpoint
    /// wrapper. Raw key bytes must not be passed here.
    pub fn new(ciphertext: SecretString) -> Result<Self> {
        validate_non_empty_secret(&ciphertext, "Transit import ciphertext")?;
        Ok(Self {
            ciphertext: Some(ciphertext),
            public_key: None,
            hash_function: None,
            context: None,
            version: None,
        })
    }

    /// Creates a public-key-only import-version request.
    pub fn from_public_key(public_key: impl Into<String>) -> Result<Self> {
        let public_key = public_key.into();
        validate_non_empty_public_key(&public_key, "Transit import public_key")?;
        Ok(Self {
            ciphertext: None,
            public_key: Some(public_key),
            hash_function: None,
            context: None,
            version: None,
        })
    }

    /// Sets the BYOK wrapping hash function.
    #[must_use]
    pub fn with_hash_function(mut self, hash_function: TransitImportHashFunction) -> Self {
        self.hash_function = Some(hash_function);
        self
    }

    /// Sets base64 derivation context for derived imported keys.
    #[must_use]
    pub fn with_context(mut self, context: SecretString) -> Self {
        self.context = Some(context);
        self
    }

    /// Selects an existing version to update.
    pub fn with_version(mut self, version: u64) -> Result<Self> {
        if version == 0 {
            return Err(Error::InvalidParameter(
                "Transit import version must be greater than zero".into(),
            ));
        }
        self.version = Some(version);
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        validate_import_material(
            self.ciphertext.as_ref(),
            self.public_key.as_deref(),
            "Transit import",
        )
    }
}

/// Client-side BYOK ciphertext prepared for Transit import.
///
/// This type is available only with the `transit-import` feature. It is an
/// ergonomic software wrapping helper for development and audited automation;
/// it is not an HSM, FIPS, certification, or post-quantum claim. Prefer
/// OpenBao-generated Transit keys or HSM-backed wrapping workflows for
/// high-assurance production deployments.
#[cfg(feature = "transit-import")]
#[derive(Clone)]
pub struct TransitWrappedImportKey {
    /// Base64 BYOK ciphertext accepted by OpenBao import endpoints.
    pub ciphertext: SecretString,
    /// RSA-OAEP hash function used to wrap the ephemeral AES key.
    pub hash_function: TransitImportHashFunction,
}

#[cfg(feature = "transit-import")]
impl fmt::Debug for TransitWrappedImportKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitWrappedImportKey")
            .field("ciphertext", &"<redacted>")
            .field("hash_function", &self.hash_function)
            .finish()
    }
}

#[cfg(feature = "transit-import")]
impl TransitWrappedImportKey {
    /// Wraps raw key material for OpenBao Transit import using OS randomness.
    ///
    /// The implementation follows OpenBao's documented BYOK software flow:
    /// generate a 256-bit ephemeral AES key, wrap `key_material` with
    /// AES-KWP, wrap the ephemeral AES key with the 4096-bit Transit RSA
    /// wrapping key using RSA-OAEP, concatenate the two binary blobs, and
    /// base64 encode the result.
    pub fn wrap_key_material(
        wrapping_key_pem: &str,
        key_material: Zeroizing<Vec<u8>>,
        hash_function: TransitImportHashFunction,
    ) -> Result<Self> {
        let mut rng = rand::rng();
        Self::wrap_key_material_with_rng(&mut rng, wrapping_key_pem, key_material, hash_function)
    }

    /// Wraps raw key material for OpenBao Transit import with caller-provided randomness.
    ///
    /// This variant exists for tests and deployments that inject a reviewed
    /// cryptographic RNG. Production callers that do not need custom RNG
    /// policy should use [`TransitWrappedImportKey::wrap_key_material`].
    pub fn wrap_key_material_with_rng<R>(
        rng: &mut R,
        wrapping_key_pem: &str,
        key_material: Zeroizing<Vec<u8>>,
        hash_function: TransitImportHashFunction,
    ) -> Result<Self>
    where
        R: rand::CryptoRng + ?Sized,
    {
        wrap_import_key_material(rng, wrapping_key_pem, key_material, hash_function)
    }

    /// Converts this wrapped blob into a new-key import request.
    pub fn into_import_request(self, key_type: TransitKeyType) -> Result<TransitImportRequest> {
        Ok(TransitImportRequest::new(self.ciphertext, key_type)?
            .with_hash_function(self.hash_function))
    }

    /// Converts this wrapped blob into an import-version request.
    pub fn into_import_version_request(self) -> Result<TransitImportVersionRequest> {
        Ok(TransitImportVersionRequest::new(self.ciphertext)?
            .with_hash_function(self.hash_function))
    }
}

/// Destination-wrapped Transit key material returned by BYOK export.
#[derive(Clone, Deserialize)]
pub struct TransitByokExport {
    /// Exported key name, when returned.
    #[serde(default)]
    pub name: Option<String>,
    /// Destination-wrapped ciphertext blobs keyed by source key version.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_map")]
    pub keys: BTreeMap<String, SecretString>,
}

impl fmt::Debug for TransitByokExport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitByokExport")
            .field("name", &self.name)
            .field("keys", &format_args!("<{} redacted>", self.keys.len()))
            .finish()
    }
}

/// Transit global key configuration.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct TransitGlobalKeyConfig {
    /// Whether Transit should refuse automatic key creation through encrypt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_upsert: Option<bool>,
}

/// Transit cache configuration.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct TransitCacheConfig {
    /// LRU cache size. `0` means unlimited; non-zero values must be at least 10.
    pub size: u64,
}

impl TransitCacheConfig {
    /// Creates a cache configuration request.
    pub fn new(size: u64) -> Result<Self> {
        if size != 0 && size < 10 {
            return Err(Error::InvalidParameter(
                "Transit cache size must be 0 or at least 10".into(),
            ));
        }
        Ok(Self { size })
    }
}

/// Request for generating a CSR from a Transit asymmetric signing key.
#[derive(Clone, Debug, Default, Serialize)]
pub struct TransitCsrRequest {
    /// Key version to use. Omitted means OpenBao uses the current version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    /// Optional PEM-encoded CSR template.
    ///
    /// This is public certificate request material, not private key material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub csr: Option<String>,
}

/// CSR generated by a Transit asymmetric signing key.
#[derive(Clone, Debug, Deserialize)]
pub struct TransitCsrResponse {
    /// Transit key name.
    pub name: String,
    /// Transit key type.
    #[serde(rename = "type")]
    pub key_type: String,
    /// PEM-encoded CSR.
    pub csr: String,
}

/// Request for installing a certificate chain on a Transit key.
#[derive(Clone, Debug, Serialize)]
pub struct TransitSetCertificateRequest {
    /// Key version to attach the chain to. Omitted means OpenBao uses current.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    /// PEM-encoded certificate chain, end-entity certificate first.
    ///
    /// This is public certificate material, not private key material.
    pub certificate_chain: String,
}

impl TransitSetCertificateRequest {
    /// Creates a certificate-chain install request.
    pub fn new(certificate_chain: impl Into<String>) -> Result<Self> {
        let certificate_chain = certificate_chain.into();
        if certificate_chain.trim().is_empty() {
            return Err(Error::InvalidParameter(
                "Transit certificate chain must not be empty".into(),
            ));
        }
        Ok(Self {
            version: None,
            certificate_chain,
        })
    }

    /// Selects a key version.
    pub fn with_version(mut self, version: u64) -> Result<Self> {
        if version == 0 {
            return Err(Error::InvalidParameter(
                "Transit certificate version must be greater than zero".into(),
            ));
        }
        self.version = Some(version);
        Ok(self)
    }
}

/// Certificate chain attached to a Transit key.
#[derive(Clone, Debug, Deserialize)]
pub struct TransitCertificateChain {
    /// Transit key name.
    pub name: String,
    /// Transit key type.
    #[serde(rename = "type")]
    pub key_type: String,
    /// PEM-encoded certificate chain.
    pub certificate_chain: String,
}

/// Transit export key material type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitExportKeyType {
    /// Symmetric encryption key material.
    EncryptionKey,
    /// Signing key material.
    SigningKey,
    /// HMAC key material.
    HmacKey,
    /// Public key material only.
    PublicKey,
    /// Certificate chain material.
    CertificateChain,
}

impl TransitExportKeyType {
    fn as_path_segment(self) -> &'static str {
        match self {
            Self::EncryptionKey => "encryption-key",
            Self::SigningKey => "signing-key",
            Self::HmacKey => "hmac-key",
            Self::PublicKey => "public-key",
            Self::CertificateChain => "certificate-chain",
        }
    }
}

/// Exported Transit key material.
#[derive(Clone, Deserialize)]
pub struct TransitExportResponse {
    /// Exported keys keyed by version.
    #[serde(default, deserialize_with = "deserialize_bounded_secret_map")]
    pub keys: BTreeMap<String, SecretString>,
    /// Exported key type, when returned.
    #[serde(default, rename = "type")]
    pub key_type: Option<String>,
    /// Key name, when returned.
    #[serde(default)]
    pub name: Option<String>,
}

impl fmt::Debug for TransitExportResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitExportResponse")
            .field("keys", &format_args!("<{} redacted>", self.keys.len()))
            .field("key_type", &self.key_type)
            .field("name", &self.name)
            .finish()
    }
}

/// Backup payload returned by the Transit backup endpoint.
#[derive(Clone, Deserialize)]
pub struct TransitBackup {
    /// Opaque encrypted key backup.
    pub backup: SecretString,
}

impl fmt::Debug for TransitBackup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitBackup")
            .field("backup", &"<redacted>")
            .finish()
    }
}

/// Request for restoring a Transit key backup.
#[derive(Clone)]
pub struct TransitRestoreRequest {
    /// Opaque backup returned by OpenBao.
    pub backup: SecretString,
    /// Overwrite an existing key with the same name.
    pub force: Option<bool>,
}

impl fmt::Debug for TransitRestoreRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitRestoreRequest")
            .field("backup", &"<redacted>")
            .field("force", &self.force)
            .finish()
    }
}

impl TransitRestoreRequest {
    /// Creates a restore request from an opaque Transit backup.
    pub fn new(backup: SecretString) -> Self {
        Self {
            backup,
            force: None,
        }
    }

    /// Forces restore over an existing key.
    #[must_use]
    pub fn force(mut self) -> Self {
        self.force = Some(true);
        self
    }
}

/// Request for trimming older Transit key versions.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct TransitTrimRequest {
    /// Minimum key version that must remain available.
    pub min_available_version: u64,
}

impl TransitTrimRequest {
    /// Creates a trim request.
    pub fn new(min_available_version: u64) -> Result<Self> {
        if min_available_version == 0 {
            return Err(Error::InvalidParameter(
                "Transit min_available_version must be greater than zero".into(),
            ));
        }
        Ok(Self {
            min_available_version,
        })
    }
}

/// Transit key list response.
#[derive(Clone, Debug, Deserialize)]
pub struct TransitKeyList {
    /// Transit key names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for TransitKeyList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Request for Transit encryption.
#[derive(Clone, Debug)]
pub struct TransitEncryptRequest {
    /// Base64-encoded plaintext.
    pub plaintext: SecretString,
    /// Base64-encoded AEAD associated data.
    pub associated_data: Option<SecretString>,
    /// Base64-encoded derivation context.
    pub context: Option<SecretString>,
    /// Key version to use.
    pub key_version: Option<u64>,
    /// Base64-encoded nonce for convergent encryption.
    pub nonce: Option<SecretString>,
}

impl TransitEncryptRequest {
    /// Creates an encryption request from base64-encoded plaintext.
    pub fn new(plaintext: SecretString) -> Self {
        Self {
            plaintext,
            associated_data: None,
            context: None,
            key_version: None,
            nonce: None,
        }
    }

    /// Creates an encryption request from raw plaintext bytes.
    ///
    /// Requires the `transit-bytes` feature. The bytes are base64-encoded for
    /// OpenBao before the request reaches the shared HTTP layer.
    #[cfg(feature = "transit-bytes")]
    pub fn from_plaintext_bytes(plaintext: &[u8]) -> Result<Self> {
        Ok(Self::new(base64_encode_secret(plaintext)?))
    }

    /// Sets raw AEAD associated data.
    #[cfg(feature = "transit-bytes")]
    pub fn with_associated_data_bytes(mut self, associated_data: &[u8]) -> Result<Self> {
        self.associated_data = Some(base64_encode_secret(associated_data)?);
        Ok(self)
    }

    /// Sets raw derivation context bytes.
    #[cfg(feature = "transit-bytes")]
    pub fn with_context_bytes(mut self, context: &[u8]) -> Result<Self> {
        self.context = Some(base64_encode_secret(context)?);
        Ok(self)
    }

    /// Sets raw nonce bytes for convergent encryption.
    #[cfg(feature = "transit-bytes")]
    pub fn with_nonce_bytes(mut self, nonce: &[u8]) -> Result<Self> {
        self.nonce = Some(base64_encode_secret(nonce)?);
        Ok(self)
    }
}

/// Transit encryption response.
#[derive(Clone, Deserialize)]
pub struct TransitEncryptResponse {
    /// OpenBao ciphertext.
    pub ciphertext: SecretString,
    /// Key version used, when returned by OpenBao.
    #[serde(default)]
    pub key_version: Option<u64>,
}

impl fmt::Debug for TransitEncryptResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitEncryptResponse")
            .field("ciphertext", &"<redacted>")
            .field("key_version", &self.key_version)
            .finish()
    }
}

/// Request for Transit decryption.
#[derive(Clone, Debug)]
pub struct TransitDecryptRequest {
    /// OpenBao ciphertext.
    pub ciphertext: SecretString,
    /// Base64-encoded AEAD associated data.
    pub associated_data: Option<SecretString>,
    /// Base64-encoded derivation context.
    pub context: Option<SecretString>,
    /// Base64-encoded nonce.
    pub nonce: Option<SecretString>,
}

impl TransitDecryptRequest {
    /// Creates a decryption request from an OpenBao ciphertext.
    pub fn new(ciphertext: SecretString) -> Self {
        Self {
            ciphertext,
            associated_data: None,
            context: None,
            nonce: None,
        }
    }

    /// Sets raw AEAD associated data.
    #[cfg(feature = "transit-bytes")]
    pub fn with_associated_data_bytes(mut self, associated_data: &[u8]) -> Result<Self> {
        self.associated_data = Some(base64_encode_secret(associated_data)?);
        Ok(self)
    }

    /// Sets raw derivation context bytes.
    #[cfg(feature = "transit-bytes")]
    pub fn with_context_bytes(mut self, context: &[u8]) -> Result<Self> {
        self.context = Some(base64_encode_secret(context)?);
        Ok(self)
    }

    /// Sets raw nonce bytes.
    #[cfg(feature = "transit-bytes")]
    pub fn with_nonce_bytes(mut self, nonce: &[u8]) -> Result<Self> {
        self.nonce = Some(base64_encode_secret(nonce)?);
        Ok(self)
    }
}

/// Transit decryption response.
#[derive(Clone, Deserialize)]
pub struct TransitDecryptResponse {
    /// Base64-encoded plaintext.
    pub plaintext: SecretString,
}

impl fmt::Debug for TransitDecryptResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitDecryptResponse")
            .field("plaintext", &"<redacted>")
            .finish()
    }
}

impl TransitDecryptResponse {
    /// Decodes OpenBao's base64 plaintext into zeroizing raw bytes.
    #[cfg(feature = "transit-bytes")]
    pub fn plaintext_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        decode_base64_secret(&self.plaintext)
    }
}

/// Request for Transit rewrap.
#[derive(Clone, Debug)]
pub struct TransitRewrapRequest {
    /// OpenBao ciphertext.
    pub ciphertext: SecretString,
    /// Base64-encoded derivation context.
    pub context: Option<SecretString>,
    /// Key version to use.
    pub key_version: Option<u64>,
    /// Base64-encoded nonce.
    pub nonce: Option<SecretString>,
}

impl TransitRewrapRequest {
    /// Creates a rewrap request from an OpenBao ciphertext.
    pub fn new(ciphertext: SecretString) -> Self {
        Self {
            ciphertext,
            context: None,
            key_version: None,
            nonce: None,
        }
    }
}

/// Transit rewrap response.
#[derive(Clone, Deserialize)]
pub struct TransitRewrapResponse {
    /// Rewrapped OpenBao ciphertext.
    pub ciphertext: SecretString,
}

impl fmt::Debug for TransitRewrapResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitRewrapResponse")
            .field("ciphertext", &"<redacted>")
            .finish()
    }
}

/// Request for generating a Transit data key.
#[derive(Clone, Debug, Default)]
pub struct TransitDataKeyRequest {
    /// Base64-encoded AEAD associated data.
    pub associated_data: Option<SecretString>,
    /// Base64-encoded derivation context.
    pub context: Option<SecretString>,
    /// Base64-encoded nonce.
    pub nonce: Option<SecretString>,
    /// Desired key size in bits.
    pub bits: Option<u64>,
}

impl TransitDataKeyRequest {
    /// Sets raw AEAD associated data.
    #[cfg(feature = "transit-bytes")]
    pub fn with_associated_data_bytes(mut self, associated_data: &[u8]) -> Result<Self> {
        self.associated_data = Some(base64_encode_secret(associated_data)?);
        Ok(self)
    }

    /// Sets raw derivation context bytes.
    #[cfg(feature = "transit-bytes")]
    pub fn with_context_bytes(mut self, context: &[u8]) -> Result<Self> {
        self.context = Some(base64_encode_secret(context)?);
        Ok(self)
    }

    /// Sets raw nonce bytes.
    #[cfg(feature = "transit-bytes")]
    pub fn with_nonce_bytes(mut self, nonce: &[u8]) -> Result<Self> {
        self.nonce = Some(base64_encode_secret(nonce)?);
        Ok(self)
    }
}

/// Transit data key response.
#[derive(Clone, Deserialize)]
pub struct TransitDataKeyResponse {
    /// Plaintext data key, when requested and permitted.
    #[serde(default)]
    pub plaintext: Option<SecretString>,
    /// OpenBao ciphertext for the data key.
    pub ciphertext: SecretString,
}

impl fmt::Debug for TransitDataKeyResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitDataKeyResponse")
            .field("plaintext", &self.plaintext.as_ref().map(|_| "<redacted>"))
            .field("ciphertext", &"<redacted>")
            .finish()
    }
}

impl TransitDataKeyResponse {
    /// Decodes the returned plaintext data key into zeroizing raw bytes.
    #[cfg(feature = "transit-bytes")]
    pub fn plaintext_bytes(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.plaintext
            .as_ref()
            .map(decode_base64_secret)
            .transpose()
    }
}

/// Request for generating random bytes.
#[derive(Clone, Debug, Default, Serialize)]
pub struct TransitRandomRequest {
    /// Output encoding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<TransitOutputFormat>,
}

/// Transit random bytes response.
#[derive(Clone, Deserialize)]
pub struct TransitRandomResponse {
    /// Random bytes in the requested encoding.
    pub random_bytes: SecretString,
}

impl fmt::Debug for TransitRandomResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitRandomResponse")
            .field("random_bytes", &"<redacted>")
            .finish()
    }
}

impl TransitRandomResponse {
    /// Decodes base64 random bytes returned with `TransitOutputFormat::Base64`.
    #[cfg(feature = "transit-bytes")]
    pub fn random_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        decode_base64_secret(&self.random_bytes)
    }
}

/// Request for hashing data with Transit.
#[derive(Clone, Debug)]
pub struct TransitHashRequest {
    /// Base64-encoded input.
    pub input: SecretString,
    /// Output encoding.
    pub format: Option<TransitOutputFormat>,
}

impl TransitHashRequest {
    /// Creates a hash request from raw input bytes.
    #[cfg(feature = "transit-bytes")]
    pub fn from_input_bytes(input: &[u8]) -> Result<Self> {
        Ok(Self {
            input: base64_encode_secret(input)?,
            format: None,
        })
    }
}

/// Transit hash response.
#[derive(Clone, Deserialize)]
pub struct TransitHashResponse {
    /// Digest in the requested encoding.
    pub sum: SecretString,
}

impl fmt::Debug for TransitHashResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitHashResponse")
            .field("sum", &"<redacted>")
            .finish()
    }
}

/// Request for generating a Transit HMAC.
#[derive(Clone, Debug)]
pub struct TransitHmacRequest {
    /// Base64-encoded input.
    pub input: SecretString,
    /// Key version to use.
    pub key_version: Option<u64>,
}

impl TransitHmacRequest {
    /// Creates an HMAC request from raw input bytes.
    #[cfg(feature = "transit-bytes")]
    pub fn from_input_bytes(input: &[u8]) -> Result<Self> {
        Ok(Self {
            input: base64_encode_secret(input)?,
            key_version: None,
        })
    }
}

/// Transit HMAC response.
#[derive(Clone, Deserialize)]
pub struct TransitHmacResponse {
    /// HMAC in OpenBao's encoded format.
    pub hmac: SecretString,
}

impl fmt::Debug for TransitHmacResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitHmacResponse")
            .field("hmac", &"<redacted>")
            .finish()
    }
}

/// Request for Transit signing.
#[derive(Clone, Debug)]
pub struct TransitSignRequest {
    /// Base64-encoded input.
    pub input: SecretString,
    /// Key version to use.
    pub key_version: Option<u64>,
    /// Base64-encoded derivation context.
    pub context: Option<SecretString>,
    /// Whether `input` is already hashed.
    pub prehashed: Option<bool>,
    /// RSA signature algorithm.
    pub signature_algorithm: Option<TransitSignatureAlgorithm>,
    /// Signature marshaling algorithm.
    pub marshaling_algorithm: Option<TransitMarshalingAlgorithm>,
    /// RSA-PSS salt length.
    pub salt_length: Option<TransitSaltLength>,
}

impl TransitSignRequest {
    /// Creates a signing request from base64-encoded input.
    pub fn new(input: SecretString) -> Self {
        Self {
            input,
            key_version: None,
            context: None,
            prehashed: None,
            signature_algorithm: None,
            marshaling_algorithm: None,
            salt_length: None,
        }
    }

    /// Creates a JWS-compatible signing request from base64-encoded input.
    ///
    /// OpenBao uses `marshaling_algorithm = "jws"` for ECDSA signatures used
    /// in JWT/JWS workflows.
    pub fn jws(input: SecretString) -> Self {
        Self::new(input).with_marshaling_algorithm(TransitMarshalingAlgorithm::Jws)
    }

    /// Creates a signing request from raw input bytes.
    #[cfg(feature = "transit-bytes")]
    pub fn from_input_bytes(input: &[u8]) -> Result<Self> {
        Ok(Self::new(base64_encode_secret(input)?))
    }

    /// Sets raw derivation context bytes.
    #[cfg(feature = "transit-bytes")]
    pub fn with_context_bytes(mut self, context: &[u8]) -> Result<Self> {
        self.context = Some(base64_encode_secret(context)?);
        Ok(self)
    }

    /// Sets the key version.
    #[must_use]
    pub fn with_key_version(mut self, key_version: u64) -> Self {
        self.key_version = Some(key_version);
        self
    }

    /// Sets base64-encoded derivation context.
    #[must_use]
    pub fn with_context(mut self, context: SecretString) -> Self {
        self.context = Some(context);
        self
    }

    /// Marks the input as already hashed.
    #[must_use]
    pub fn with_prehashed(mut self, prehashed: bool) -> Self {
        self.prehashed = Some(prehashed);
        self
    }

    /// Sets the RSA signature algorithm.
    #[must_use]
    pub fn with_signature_algorithm(mut self, algorithm: TransitSignatureAlgorithm) -> Self {
        self.signature_algorithm = Some(algorithm);
        self
    }

    /// Sets the signature marshaling algorithm.
    #[must_use]
    pub fn with_marshaling_algorithm(mut self, algorithm: TransitMarshalingAlgorithm) -> Self {
        self.marshaling_algorithm = Some(algorithm);
        self
    }

    /// Sets the RSA-PSS salt length.
    #[must_use]
    pub fn with_salt_length(mut self, salt_length: TransitSaltLength) -> Self {
        self.salt_length = Some(salt_length);
        self
    }
}

/// Transit signing response.
#[derive(Clone, Deserialize)]
pub struct TransitSignResponse {
    /// Signature in OpenBao's encoded format.
    pub signature: SecretString,
    /// Derived public key, when returned by OpenBao.
    #[serde(default, alias = "publickey")]
    pub public_key: Option<SecretString>,
}

impl fmt::Debug for TransitSignResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitSignResponse")
            .field("signature", &"<redacted>")
            .field(
                "public_key",
                &self.public_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Request for Transit verification.
#[derive(Clone, Debug)]
pub struct TransitVerifyRequest {
    /// Base64-encoded input.
    pub input: SecretString,
    /// Signature to verify.
    pub signature: Option<SecretString>,
    /// HMAC to verify.
    pub hmac: Option<SecretString>,
    /// Base64-encoded derivation context.
    pub context: Option<SecretString>,
    /// Whether `input` is already hashed.
    pub prehashed: Option<bool>,
    /// RSA signature algorithm.
    pub signature_algorithm: Option<TransitSignatureAlgorithm>,
    /// Signature marshaling algorithm.
    pub marshaling_algorithm: Option<TransitMarshalingAlgorithm>,
    /// RSA-PSS salt length.
    pub salt_length: Option<TransitSaltLength>,
}

impl TransitVerifyRequest {
    /// Creates a verification request from base64-encoded input.
    pub fn new(input: SecretString) -> Self {
        Self {
            input,
            signature: None,
            hmac: None,
            context: None,
            prehashed: None,
            signature_algorithm: None,
            marshaling_algorithm: None,
            salt_length: None,
        }
    }

    /// Creates a verification request from base64-encoded input and signature.
    pub fn from_base64_input_with_signature(input: SecretString, signature: SecretString) -> Self {
        Self::new(input).with_signature(signature)
    }

    /// Creates a verification request from base64-encoded input and HMAC.
    pub fn from_base64_input_with_hmac(input: SecretString, hmac: SecretString) -> Self {
        Self::new(input).with_hmac(hmac)
    }

    /// Creates a JWS-compatible verification request from base64-encoded input
    /// and signature.
    ///
    /// OpenBao expects URL-safe Base64 input when verifying JWS-marshaled ECDSA
    /// signatures.
    pub fn jws_with_signature(input: SecretString, signature: SecretString) -> Self {
        Self::from_base64_input_with_signature(input, signature)
            .with_marshaling_algorithm(TransitMarshalingAlgorithm::Jws)
    }

    /// Creates a verification request from raw input bytes and a signature.
    #[cfg(feature = "transit-bytes")]
    pub fn from_input_bytes_with_signature(input: &[u8], signature: SecretString) -> Result<Self> {
        Ok(Self::from_base64_input_with_signature(
            base64_encode_secret(input)?,
            signature,
        ))
    }

    /// Creates a verification request from raw input bytes and an HMAC.
    #[cfg(feature = "transit-bytes")]
    pub fn from_input_bytes_with_hmac(input: &[u8], hmac: SecretString) -> Result<Self> {
        Ok(Self::from_base64_input_with_hmac(
            base64_encode_secret(input)?,
            hmac,
        ))
    }

    /// Sets raw derivation context bytes.
    #[cfg(feature = "transit-bytes")]
    pub fn with_context_bytes(mut self, context: &[u8]) -> Result<Self> {
        self.context = Some(base64_encode_secret(context)?);
        Ok(self)
    }

    /// Sets the signature to verify.
    #[must_use]
    pub fn with_signature(mut self, signature: SecretString) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Sets the HMAC to verify.
    #[must_use]
    pub fn with_hmac(mut self, hmac: SecretString) -> Self {
        self.hmac = Some(hmac);
        self
    }

    /// Sets base64-encoded derivation context.
    #[must_use]
    pub fn with_context(mut self, context: SecretString) -> Self {
        self.context = Some(context);
        self
    }

    /// Marks the input as already hashed.
    #[must_use]
    pub fn with_prehashed(mut self, prehashed: bool) -> Self {
        self.prehashed = Some(prehashed);
        self
    }

    /// Sets the RSA signature algorithm.
    #[must_use]
    pub fn with_signature_algorithm(mut self, algorithm: TransitSignatureAlgorithm) -> Self {
        self.signature_algorithm = Some(algorithm);
        self
    }

    /// Sets the signature marshaling algorithm.
    #[must_use]
    pub fn with_marshaling_algorithm(mut self, algorithm: TransitMarshalingAlgorithm) -> Self {
        self.marshaling_algorithm = Some(algorithm);
        self
    }

    /// Sets the RSA-PSS salt length.
    #[must_use]
    pub fn with_salt_length(mut self, salt_length: TransitSaltLength) -> Self {
        self.salt_length = Some(salt_length);
        self
    }
}

/// Transit verification response.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct TransitVerifyResponse {
    /// Whether verification succeeded.
    pub valid: bool,
}

/// Batch encryption request using the same endpoint as single-item encryption.
#[derive(Clone, Debug, Default)]
pub struct TransitBatchEncryptRequest {
    /// Batch items. OpenBao enforces its own maximum; the crate bounds locally.
    pub batch_input: Vec<TransitEncryptRequest>,
}

/// Batch decryption request using the same endpoint as single-item decryption.
#[derive(Clone, Debug, Default)]
pub struct TransitBatchDecryptRequest {
    /// Batch items. OpenBao enforces its own maximum; the crate bounds locally.
    pub batch_input: Vec<TransitDecryptRequest>,
}

/// Batch rewrap request using the same endpoint as single-item rewrap.
#[derive(Clone, Debug, Default)]
pub struct TransitBatchRewrapRequest {
    /// Batch items. OpenBao enforces its own maximum; the crate bounds locally.
    pub batch_input: Vec<TransitRewrapRequest>,
}

/// Batch signing request using the same endpoint as single-item signing.
#[derive(Clone, Debug, Default)]
pub struct TransitBatchSignRequest {
    /// Batch items. OpenBao enforces its own maximum; the crate bounds locally.
    pub batch_input: Vec<TransitSignRequest>,
}

/// Batch verification request using the same endpoint as single-item verification.
#[derive(Clone, Debug, Default)]
pub struct TransitBatchVerifyRequest {
    /// Batch items. OpenBao enforces its own maximum; the crate bounds locally.
    pub batch_input: Vec<TransitVerifyRequest>,
}

/// One item returned by a batch encryption operation.
#[derive(Clone, Deserialize)]
pub struct TransitBatchEncryptItem {
    /// Ciphertext for this item, when successful.
    #[serde(default)]
    pub ciphertext: Option<SecretString>,
    /// Key version used, when returned.
    #[serde(default)]
    pub key_version: Option<u64>,
    /// OpenBao item error, when this item failed.
    #[serde(default)]
    pub error: Option<String>,
}

impl fmt::Debug for TransitBatchEncryptItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitBatchEncryptItem")
            .field(
                "ciphertext",
                &self.ciphertext.as_ref().map(|_| "<redacted>"),
            )
            .field("key_version", &self.key_version)
            .field("error", &self.error)
            .finish()
    }
}

/// One item returned by a batch decryption operation.
#[derive(Clone, Deserialize)]
pub struct TransitBatchDecryptItem {
    /// Base64-encoded plaintext for this item, when successful.
    #[serde(default)]
    pub plaintext: Option<SecretString>,
    /// OpenBao item error, when this item failed.
    #[serde(default)]
    pub error: Option<String>,
}

impl fmt::Debug for TransitBatchDecryptItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitBatchDecryptItem")
            .field("plaintext", &self.plaintext.as_ref().map(|_| "<redacted>"))
            .field("error", &self.error)
            .finish()
    }
}

/// One item returned by a batch rewrap operation.
#[derive(Clone, Deserialize)]
pub struct TransitBatchRewrapItem {
    /// Rewrapped ciphertext for this item, when successful.
    #[serde(default)]
    pub ciphertext: Option<SecretString>,
    /// OpenBao item error, when this item failed.
    #[serde(default)]
    pub error: Option<String>,
}

impl fmt::Debug for TransitBatchRewrapItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitBatchRewrapItem")
            .field(
                "ciphertext",
                &self.ciphertext.as_ref().map(|_| "<redacted>"),
            )
            .field("error", &self.error)
            .finish()
    }
}

/// One item returned by a batch signing operation.
#[derive(Clone, Deserialize)]
pub struct TransitBatchSignItem {
    /// Signature for this item, when successful.
    #[serde(default)]
    pub signature: Option<SecretString>,
    /// OpenBao item error, when this item failed.
    #[serde(default)]
    pub error: Option<String>,
}

impl fmt::Debug for TransitBatchSignItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransitBatchSignItem")
            .field("signature", &self.signature.as_ref().map(|_| "<redacted>"))
            .field("error", &self.error)
            .finish()
    }
}

/// One item returned by a batch verification operation.
#[derive(Clone, Debug, Deserialize)]
pub struct TransitBatchVerifyItem {
    /// Whether this item verified successfully.
    #[serde(default)]
    pub valid: bool,
    /// OpenBao item error, when this item failed.
    #[serde(default)]
    pub error: Option<String>,
}

/// Batch encryption response.
#[derive(Clone, Debug, Deserialize)]
pub struct TransitBatchEncryptResponse {
    /// Per-item results.
    #[serde(default, deserialize_with = "deserialize_bounded_batch_encrypt_vec")]
    pub batch_results: Vec<TransitBatchEncryptItem>,
}

/// Batch decryption response.
#[derive(Clone, Debug, Deserialize)]
pub struct TransitBatchDecryptResponse {
    /// Per-item results.
    #[serde(default, deserialize_with = "deserialize_bounded_batch_decrypt_vec")]
    pub batch_results: Vec<TransitBatchDecryptItem>,
}

/// Batch rewrap response.
#[derive(Clone, Debug, Deserialize)]
pub struct TransitBatchRewrapResponse {
    /// Per-item results.
    #[serde(default, deserialize_with = "deserialize_bounded_batch_rewrap_vec")]
    pub batch_results: Vec<TransitBatchRewrapItem>,
}

/// Batch signing response.
#[derive(Clone, Debug, Deserialize)]
pub struct TransitBatchSignResponse {
    /// Per-item results.
    #[serde(default, deserialize_with = "deserialize_bounded_batch_sign_vec")]
    pub batch_results: Vec<TransitBatchSignItem>,
}

/// Batch verification response.
#[derive(Clone, Debug, Deserialize)]
pub struct TransitBatchVerifyResponse {
    /// Per-item results.
    #[serde(default, deserialize_with = "deserialize_bounded_batch_verify_vec")]
    pub batch_results: Vec<TransitBatchVerifyItem>,
}

#[derive(Serialize)]
struct TransitEncryptPayload<'a> {
    plaintext: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    associated_data: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
}

#[derive(Serialize)]
struct TransitDecryptPayload<'a> {
    ciphertext: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    associated_data: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
}

#[derive(Serialize)]
struct TransitRewrapPayload<'a> {
    ciphertext: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
}

#[derive(Serialize)]
struct TransitDataKeyPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    associated_data: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bits: Option<u64>,
}

#[derive(Serialize)]
struct TransitHashPayload<'a> {
    input: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<TransitOutputFormat>,
}

#[derive(Serialize)]
struct TransitHmacPayload<'a> {
    input: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_version: Option<u64>,
}

#[derive(Serialize)]
struct TransitSignPayload<'a> {
    input: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prehashed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_algorithm: Option<TransitSignatureAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    marshaling_algorithm: Option<TransitMarshalingAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    salt_length: Option<TransitSaltLength>,
}

#[derive(Serialize)]
struct TransitVerifyPayload<'a> {
    input: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hmac: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prehashed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_algorithm: Option<TransitSignatureAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    marshaling_algorithm: Option<TransitMarshalingAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    salt_length: Option<TransitSaltLength>,
}

#[derive(Serialize)]
struct TransitBatchPayload<T> {
    batch_input: Vec<T>,
}

#[derive(Serialize)]
struct TransitRestorePayload<'a> {
    backup: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    force: Option<bool>,
}

#[derive(Serialize)]
struct TransitImportPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<&'a str>,
    #[serde(rename = "type")]
    key_type: TransitKeyType,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash_function: Option<TransitImportHashFunction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_rotation: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derived: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exportable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_plaintext_backup: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_rotate_period: Option<&'a str>,
}

#[derive(Serialize)]
struct TransitImportVersionPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash_function: Option<TransitImportHashFunction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<u64>,
}

impl Client<Authenticated> {
    /// Uses the Transit engine mounted at `mount`.
    pub fn transit(&self, mount: impl Into<String>) -> Result<Transit<'_>> {
        let mount = mount.into();
        Ok(Transit {
            client: self,
            mount: validate_mount_path(&mount)?,
        })
    }
}

impl Transit<'_> {
    /// Creates a named Transit key.
    pub async fn create_key(&self, name: &str, request: &TransitCreateKeyRequest) -> Result<Empty> {
        request.validate()?;
        self.client
            .request_json(Method::POST, &self.key_path(name, None)?, Some(request))
            .await
    }

    /// Reads a named Transit key.
    pub async fn read_key(&self, name: &str) -> Result<TransitKeyInfo> {
        let envelope: ResponseEnvelope<TransitKeyInfo> = self
            .client
            .request_json(
                Method::GET,
                &self.key_path(name, None)?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Reads the RSA wrapping public key used by Transit BYOK import.
    ///
    /// The returned PEM is public key material. Raw key bytes for import must
    /// be wrapped outside this endpoint wrapper before calling
    /// [`Transit::import_key`] or [`Transit::import_key_version`].
    pub async fn wrapping_key(&self) -> Result<TransitWrappingKey> {
        let envelope: ResponseEnvelope<TransitWrappingKey> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["wrapping_key"])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists Transit key names.
    pub async fn list_keys(&self) -> Result<TransitKeyList> {
        self.list_keys_after(None, None).await
    }

    /// Lists Transit key names with optional OpenBao pagination parameters.
    pub async fn list_keys_after(
        &self,
        after: Option<&str>,
        limit: Option<u64>,
    ) -> Result<TransitKeyList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let query = ListPageOptions::from_after_limit(after, limit)?.query_pairs();
        let envelope: ResponseEnvelope<TransitKeyList> = self
            .client
            .request_json_query_accepting(
                method,
                &self.path(&["keys"])?,
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a named Transit key.
    ///
    /// OpenBao requires `deletion_allowed=true` on the key configuration before
    /// this endpoint succeeds.
    pub async fn delete_key(&self, name: &str) -> Result<Empty> {
        self.client
            .request_json_accepting(
                Method::DELETE,
                &self.key_path(name, None)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Updates a named Transit key's mutable configuration.
    pub async fn update_key(&self, name: &str, request: &TransitUpdateKeyRequest) -> Result<Empty> {
        request.validate()?;
        self.client
            .request_json(
                Method::POST,
                &self.key_path(name, Some("config"))?,
                Some(request),
            )
            .await
    }

    /// Rotates a named Transit key to a new key version.
    pub async fn rotate_key(&self, name: &str) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                &self.key_path(name, Some("rotate"))?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Imports a new Transit key from pre-wrapped BYOK ciphertext.
    ///
    /// This endpoint wrapper never accepts raw key bytes and does not perform
    /// RSA-OAEP/AES-KWP wrapping. Fetch [`Transit::wrapping_key`], wrap key
    /// material externally through an HSM, OpenSSL, or reviewed crypto
    /// library, and pass only the base64 ciphertext blob in `request`.
    pub async fn import_key(&self, name: &str, request: &TransitImportRequest) -> Result<Empty> {
        request.validate()?;
        let payload = TransitImportPayload {
            ciphertext: request
                .ciphertext
                .as_ref()
                .map(|secret| secret.expose_secret()),
            public_key: request.public_key.as_deref(),
            key_type: request.key_type,
            hash_function: request.hash_function,
            allow_rotation: request.allow_rotation,
            derived: request.derived,
            context: request
                .context
                .as_ref()
                .map(|secret| secret.expose_secret()),
            exportable: request.exportable,
            allow_plaintext_backup: request.allow_plaintext_backup,
            auto_rotate_period: request.auto_rotate_period.as_deref(),
        };
        self.client
            .request_json(
                Method::POST,
                &self.key_path(name, Some("import"))?,
                Some(&payload),
            )
            .await
    }

    /// Imports new pre-wrapped key material into an existing imported key.
    ///
    /// Keys generated by OpenBao cannot import external material. This wrapper
    /// accepts only the already-wrapped BYOK ciphertext; raw key bytes remain
    /// outside this crate's endpoint wrapper.
    pub async fn import_key_version(
        &self,
        name: &str,
        request: &TransitImportVersionRequest,
    ) -> Result<Empty> {
        request.validate()?;
        let payload = TransitImportVersionPayload {
            ciphertext: request
                .ciphertext
                .as_ref()
                .map(|secret| secret.expose_secret()),
            public_key: request.public_key.as_deref(),
            hash_function: request.hash_function,
            context: request
                .context
                .as_ref()
                .map(|secret| secret.expose_secret()),
            version: request.version,
        };
        self.client
            .request_json(
                Method::POST,
                &self.key_path(name, Some("import_version"))?,
                Some(&payload),
            )
            .await
    }

    /// Soft-deletes a Transit key without requiring `deletion_allowed=true`.
    ///
    /// OpenBao disables cryptographic operations for the key until it is
    /// restored with [`Transit::restore_soft_deleted_key`].
    pub async fn soft_delete_key(&self, name: &str) -> Result<Empty> {
        self.client
            .request_json_accepting(
                Method::DELETE,
                &self.key_path(name, Some("soft-delete"))?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Restores a soft-deleted Transit key.
    pub async fn restore_soft_deleted_key(&self, name: &str) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                &self.key_path(name, Some("soft-delete-restore"))?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Exports source key material wrapped for another Transit destination key.
    ///
    /// Returned BYOK blobs are ciphertext but are still treated as
    /// secret-aware values and redacted from `Debug`.
    pub async fn byok_export(
        &self,
        destination: &str,
        source: &str,
        version: Option<&str>,
        hash_function: Option<TransitImportHashFunction>,
    ) -> Result<TransitByokExport> {
        let mut segments = vec!["byok-export"];
        let destination = validate_key_name(destination)?;
        for segment in &destination {
            segments.push(segment);
        }
        let source = validate_key_name(source)?;
        for segment in &source {
            segments.push(segment);
        }
        if let Some(version) = version {
            segments.push(version);
        }
        let query = hash_function
            .map(|hash| vec![("hash", hash.as_query_value().to_owned())])
            .unwrap_or_default();
        let envelope: ResponseEnvelope<TransitByokExport> = self
            .client
            .request_json_query_accepting(
                Method::GET,
                &self.path(&segments)?,
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Writes global Transit key configuration.
    pub async fn write_global_key_config(
        &self,
        request: &TransitGlobalKeyConfig,
    ) -> Result<TransitGlobalKeyConfig> {
        let envelope: ResponseEnvelope<TransitGlobalKeyConfig> = self
            .client
            .request_json(
                Method::POST,
                &self.path(&["config", "keys"])?,
                Some(request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Reads global Transit key configuration.
    pub async fn read_global_key_config(&self) -> Result<TransitGlobalKeyConfig> {
        let envelope: ResponseEnvelope<TransitGlobalKeyConfig> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["config", "keys"])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Exports key material for an exportable Transit key.
    ///
    /// The returned key material is secret-aware and redacted from `Debug`.
    /// Operators must ensure the target key was explicitly configured as
    /// exportable for a controlled workflow.
    pub async fn export_key(
        &self,
        key_type: TransitExportKeyType,
        name: &str,
        version: Option<u64>,
    ) -> Result<TransitExportResponse> {
        let version = version.map(|version| version.to_string());
        let mut segments = vec!["export", key_type.as_path_segment()];
        let name = validate_key_name(name)?;
        for segment in &name {
            segments.push(segment);
        }
        if let Some(version) = version.as_deref() {
            segments.push(version);
        }
        let envelope: ResponseEnvelope<TransitExportResponse> = self
            .client
            .request_json(Method::GET, &self.path(&segments)?, Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    /// Reads an encrypted backup of a Transit key.
    ///
    /// Backup payloads can restore key material and are therefore returned as
    /// secret material.
    pub async fn backup_key(&self, name: &str) -> Result<TransitBackup> {
        let name = validate_key_name(name)?.join("/");
        let envelope: ResponseEnvelope<TransitBackup> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["backup", &name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Restores a Transit key backup.
    ///
    /// When `name` is `None`, OpenBao restores the key name contained inside
    /// the backup. Supplying a name restores to that key name.
    pub async fn restore_key(
        &self,
        name: Option<&str>,
        request: &TransitRestoreRequest,
    ) -> Result<Empty> {
        let payload = TransitRestorePayload {
            backup: request.backup.expose_secret(),
            force: request.force,
        };
        let path = match name {
            Some(name) => {
                let name = validate_key_name(name)?.join("/");
                self.path(&["restore", &name])?
            }
            None => self.path(&["restore"])?,
        };
        self.client
            .request_json(Method::POST, &path, Some(&payload))
            .await
    }

    /// Trims older Transit key versions up to `min_available_version`.
    pub async fn trim_key(&self, name: &str, request: &TransitTrimRequest) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                &self.key_path(name, Some("trim"))?,
                Some(request),
            )
            .await
    }

    /// Writes Transit cache configuration.
    pub async fn write_cache_config(
        &self,
        request: &TransitCacheConfig,
    ) -> Result<TransitCacheConfig> {
        let request = TransitCacheConfig::new(request.size)?;
        let envelope: ResponseEnvelope<TransitCacheConfig> = self
            .client
            .request_json(Method::POST, &self.path(&["cache-config"])?, Some(&request))
            .await?;
        Ok(envelope.data)
    }

    /// Reads Transit cache configuration.
    pub async fn read_cache_config(&self) -> Result<TransitCacheConfig> {
        let envelope: ResponseEnvelope<TransitCacheConfig> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["cache-config"])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Generates a PEM-encoded CSR signed by a Transit asymmetric key.
    ///
    /// The returned CSR is public certificate request material. The private key
    /// remains inside Transit.
    pub async fn generate_csr(
        &self,
        name: &str,
        request: &TransitCsrRequest,
    ) -> Result<TransitCsrResponse> {
        let envelope: ResponseEnvelope<TransitCsrResponse> = self
            .client
            .request_json(
                Method::POST,
                &self.key_path(name, Some("csr"))?,
                Some(request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Installs a PEM certificate chain on a Transit key.
    ///
    /// Certificate chains are public certificate material. This method does not
    /// transmit private key material.
    pub async fn set_certificate(
        &self,
        name: &str,
        request: &TransitSetCertificateRequest,
    ) -> Result<TransitCertificateChain> {
        let envelope: ResponseEnvelope<TransitCertificateChain> = self
            .client
            .request_json(
                Method::POST,
                &self.key_path(name, Some("set-certificate"))?,
                Some(request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Encrypts base64-encoded plaintext with a Transit key.
    ///
    /// The plaintext is wrapped in `SecretString` and the crate zeroizes its
    /// serialization buffer, but serde, reqwest, TLS, kernel, and device
    /// buffers can retain transient body copies outside this crate's control
    /// during request transmission. Callers that use raw plaintext buffers
    /// should zeroize their own buffers immediately after constructing the
    /// request.
    pub async fn encrypt(
        &self,
        name: &str,
        request: &TransitEncryptRequest,
    ) -> Result<TransitEncryptResponse> {
        let payload = encrypt_payload(request);
        self.enveloped(
            Method::POST,
            &self.operation_path("encrypt", name, None)?,
            &payload,
        )
        .await
    }

    /// Decrypts Transit ciphertext.
    ///
    /// Ciphertext and returned plaintext are secret-aware at the public API
    /// boundary. Request and response buffers can still exist transiently in
    /// the HTTP/TLS stack while the operation is in flight.
    pub async fn decrypt(
        &self,
        name: &str,
        request: &TransitDecryptRequest,
    ) -> Result<TransitDecryptResponse> {
        let payload = decrypt_payload(request);
        self.enveloped(
            Method::POST,
            &self.operation_path("decrypt", name, None)?,
            &payload,
        )
        .await
    }

    /// Rewraps ciphertext to the latest or requested Transit key version.
    ///
    /// Ciphertext is secret-aware at the public API boundary. Request buffers
    /// can still exist transiently in the HTTP/TLS stack while the operation is
    /// in flight.
    pub async fn rewrap(
        &self,
        name: &str,
        request: &TransitRewrapRequest,
    ) -> Result<TransitRewrapResponse> {
        let payload = rewrap_payload(request);
        self.enveloped(
            Method::POST,
            &self.operation_path("rewrap", name, None)?,
            &payload,
        )
        .await
    }

    /// Generates a high-entropy data key encrypted by a Transit key.
    pub async fn data_key(
        &self,
        name: &str,
        data_key_type: TransitDataKeyType,
        request: &TransitDataKeyRequest,
    ) -> Result<TransitDataKeyResponse> {
        let payload = TransitDataKeyPayload {
            associated_data: request
                .associated_data
                .as_ref()
                .map(|secret| secret.expose_secret()),
            context: request
                .context
                .as_ref()
                .map(|secret| secret.expose_secret()),
            nonce: request.nonce.as_ref().map(|secret| secret.expose_secret()),
            bits: request.bits,
        };
        self.enveloped(
            Method::POST,
            &self.path(&["datakey", data_key_type.as_path_segment(), name])?,
            &payload,
        )
        .await
    }

    /// Generates random bytes from the default Transit entropy source.
    pub async fn random(
        &self,
        bytes: Option<u64>,
        request: &TransitRandomRequest,
    ) -> Result<TransitRandomResponse> {
        let bytes = bytes.map(|value| value.to_string());
        let mut segments = vec!["random"];
        if let Some(bytes) = bytes.as_deref() {
            segments.push(bytes);
        }
        self.enveloped(Method::POST, &self.path(&segments)?, request)
            .await
    }

    /// Generates random bytes from a specific Transit entropy source.
    pub async fn random_from_source(
        &self,
        source: TransitRandomSource,
        bytes: Option<u64>,
        request: &TransitRandomRequest,
    ) -> Result<TransitRandomResponse> {
        let bytes = bytes.map(|value| value.to_string());
        let mut segments = vec!["random", source.as_path_segment()];
        if let Some(bytes) = bytes.as_deref() {
            segments.push(bytes);
        }
        self.enveloped(Method::POST, &self.path(&segments)?, request)
            .await
    }

    /// Hashes base64-encoded input with the requested algorithm.
    pub async fn hash(
        &self,
        algorithm: TransitHashAlgorithm,
        request: &TransitHashRequest,
    ) -> Result<TransitHashResponse> {
        let payload = TransitHashPayload {
            input: request.input.expose_secret(),
            format: request.format,
        };
        self.enveloped(
            Method::POST,
            &self.path(&["hash", algorithm.as_path_segment()])?,
            &payload,
        )
        .await
    }

    /// Generates an HMAC for base64-encoded input.
    pub async fn hmac(
        &self,
        name: &str,
        algorithm: Option<TransitHashAlgorithm>,
        request: &TransitHmacRequest,
    ) -> Result<TransitHmacResponse> {
        let payload = TransitHmacPayload {
            input: request.input.expose_secret(),
            key_version: request.key_version,
        };
        self.enveloped(
            Method::POST,
            &self.operation_path("hmac", name, algorithm)?,
            &payload,
        )
        .await
    }

    /// Signs base64-encoded input.
    pub async fn sign(
        &self,
        name: &str,
        algorithm: Option<TransitHashAlgorithm>,
        request: &TransitSignRequest,
    ) -> Result<TransitSignResponse> {
        let payload = sign_payload(request);
        self.enveloped(
            Method::POST,
            &self.operation_path("sign", name, algorithm)?,
            &payload,
        )
        .await
    }

    /// Verifies a Transit signature or HMAC.
    pub async fn verify(
        &self,
        name: &str,
        algorithm: Option<TransitHashAlgorithm>,
        request: &TransitVerifyRequest,
    ) -> Result<TransitVerifyResponse> {
        let payload = verify_payload(request);
        self.enveloped(
            Method::POST,
            &self.operation_path("verify", name, algorithm)?,
            &payload,
        )
        .await
    }

    /// Encrypts multiple base64-encoded plaintext values in one Transit request.
    ///
    /// The same residual-memory warning as [`Transit::encrypt`] applies to
    /// every plaintext item in the batch.
    pub async fn batch_encrypt(
        &self,
        name: &str,
        request: &TransitBatchEncryptRequest,
    ) -> Result<TransitBatchEncryptResponse> {
        validate_batch_len(request.batch_input.len())?;
        let payload = TransitBatchPayload {
            batch_input: request
                .batch_input
                .iter()
                .map(encrypt_payload)
                .collect::<Vec<_>>(),
        };
        self.enveloped(
            Method::POST,
            &self.operation_path("encrypt", name, None)?,
            &payload,
        )
        .await
    }

    /// Decrypts multiple Transit ciphertext values in one Transit request.
    pub async fn batch_decrypt(
        &self,
        name: &str,
        request: &TransitBatchDecryptRequest,
    ) -> Result<TransitBatchDecryptResponse> {
        validate_batch_len(request.batch_input.len())?;
        let payload = TransitBatchPayload {
            batch_input: request
                .batch_input
                .iter()
                .map(decrypt_payload)
                .collect::<Vec<_>>(),
        };
        self.enveloped(
            Method::POST,
            &self.operation_path("decrypt", name, None)?,
            &payload,
        )
        .await
    }

    /// Rewraps multiple Transit ciphertext values in one Transit request.
    pub async fn batch_rewrap(
        &self,
        name: &str,
        request: &TransitBatchRewrapRequest,
    ) -> Result<TransitBatchRewrapResponse> {
        validate_batch_len(request.batch_input.len())?;
        let payload = TransitBatchPayload {
            batch_input: request
                .batch_input
                .iter()
                .map(rewrap_payload)
                .collect::<Vec<_>>(),
        };
        self.enveloped(
            Method::POST,
            &self.operation_path("rewrap", name, None)?,
            &payload,
        )
        .await
    }

    /// Signs multiple base64-encoded inputs in one Transit request.
    pub async fn batch_sign(
        &self,
        name: &str,
        algorithm: Option<TransitHashAlgorithm>,
        request: &TransitBatchSignRequest,
    ) -> Result<TransitBatchSignResponse> {
        validate_batch_len(request.batch_input.len())?;
        let payload = TransitBatchPayload {
            batch_input: request
                .batch_input
                .iter()
                .map(sign_payload)
                .collect::<Vec<_>>(),
        };
        self.enveloped(
            Method::POST,
            &self.operation_path("sign", name, algorithm)?,
            &payload,
        )
        .await
    }

    /// Verifies multiple Transit signatures or HMACs in one Transit request.
    pub async fn batch_verify(
        &self,
        name: &str,
        algorithm: Option<TransitHashAlgorithm>,
        request: &TransitBatchVerifyRequest,
    ) -> Result<TransitBatchVerifyResponse> {
        validate_batch_len(request.batch_input.len())?;
        let payload = TransitBatchPayload {
            batch_input: request
                .batch_input
                .iter()
                .map(verify_payload)
                .collect::<Vec<_>>(),
        };
        self.enveloped(
            Method::POST,
            &self.operation_path("verify", name, algorithm)?,
            &payload,
        )
        .await
    }

    async fn enveloped<T, B>(&self, method: Method, path: &str, request: &B) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
        B: Serialize + ?Sized,
    {
        let envelope: ResponseEnvelope<T> = self
            .client
            .request_json(method, path, Some(request))
            .await?;
        Ok(envelope.data)
    }

    fn key_path(&self, name: &str, suffix: Option<&str>) -> Result<String> {
        let mut segments = vec!["keys"];
        let name = validate_key_name(name)?;
        for segment in &name {
            segments.push(segment);
        }
        if let Some(suffix) = suffix {
            segments.push(suffix);
        }
        self.path(&segments)
    }

    fn operation_path(
        &self,
        operation: &'static str,
        name: &str,
        algorithm: Option<TransitHashAlgorithm>,
    ) -> Result<String> {
        let mut segments = vec![operation];
        let name = validate_key_name(name)?;
        for segment in &name {
            segments.push(segment);
        }
        if let Some(algorithm) = algorithm {
            segments.push(algorithm.as_path_segment());
        }
        self.path(&segments)
    }

    fn path(&self, tail: &[&str]) -> Result<String> {
        let mut segments = self.mount.clone();
        for segment in tail {
            segments.extend(validate_endpoint_path(segment)?);
        }
        Ok(segments.join("/"))
    }
}

fn validate_key_name(name: &str) -> Result<Vec<String>> {
    validate_mount_path(name)
}

fn validate_batch_len(len: usize) -> Result<()> {
    if len == 0 {
        return Err(Error::InvalidParameter(
            "Transit batch_input must not be empty".into(),
        ));
    }
    if len > crate::response::MAX_RESPONSE_STRINGS {
        return Err(Error::InvalidParameter(
            "Transit batch_input exceeds item limit".into(),
        ));
    }
    Ok(())
}

fn validate_non_empty_secret(secret: &SecretString, label: &'static str) -> Result<()> {
    if secret.expose_secret().is_empty() {
        return Err(Error::InvalidParameter(format!(
            "{label} must not be empty"
        )));
    }
    Ok(())
}

fn validate_non_empty_public_key(public_key: &str, label: &'static str) -> Result<()> {
    if public_key.trim().is_empty() {
        return Err(Error::InvalidParameter(format!(
            "{label} must not be empty"
        )));
    }
    Ok(())
}

fn validate_import_material(
    ciphertext: Option<&SecretString>,
    public_key: Option<&str>,
    label: &'static str,
) -> Result<()> {
    match (ciphertext, public_key) {
        (Some(ciphertext), None) => {
            validate_non_empty_secret(ciphertext, "Transit import ciphertext")
        }
        (None, Some(public_key)) => {
            validate_non_empty_public_key(public_key, "Transit import public_key")
        }
        (Some(_), Some(_)) => Err(Error::InvalidParameter(format!(
            "{label} must use either ciphertext or public_key, not both"
        ))),
        (None, None) => Err(Error::InvalidParameter(format!(
            "{label} requires ciphertext or public_key"
        ))),
    }
}

fn encrypt_payload(request: &TransitEncryptRequest) -> TransitEncryptPayload<'_> {
    TransitEncryptPayload {
        plaintext: request.plaintext.expose_secret(),
        associated_data: request
            .associated_data
            .as_ref()
            .map(|secret| secret.expose_secret()),
        context: request
            .context
            .as_ref()
            .map(|secret| secret.expose_secret()),
        key_version: request.key_version,
        nonce: request.nonce.as_ref().map(|secret| secret.expose_secret()),
    }
}

fn decrypt_payload(request: &TransitDecryptRequest) -> TransitDecryptPayload<'_> {
    TransitDecryptPayload {
        ciphertext: request.ciphertext.expose_secret(),
        associated_data: request
            .associated_data
            .as_ref()
            .map(|secret| secret.expose_secret()),
        context: request
            .context
            .as_ref()
            .map(|secret| secret.expose_secret()),
        nonce: request.nonce.as_ref().map(|secret| secret.expose_secret()),
    }
}

fn rewrap_payload(request: &TransitRewrapRequest) -> TransitRewrapPayload<'_> {
    TransitRewrapPayload {
        ciphertext: request.ciphertext.expose_secret(),
        context: request
            .context
            .as_ref()
            .map(|secret| secret.expose_secret()),
        key_version: request.key_version,
        nonce: request.nonce.as_ref().map(|secret| secret.expose_secret()),
    }
}

fn sign_payload(request: &TransitSignRequest) -> TransitSignPayload<'_> {
    TransitSignPayload {
        input: request.input.expose_secret(),
        key_version: request.key_version,
        context: request
            .context
            .as_ref()
            .map(|secret| secret.expose_secret()),
        prehashed: request.prehashed,
        signature_algorithm: request.signature_algorithm,
        marshaling_algorithm: request.marshaling_algorithm,
        salt_length: request.salt_length,
    }
}

fn verify_payload(request: &TransitVerifyRequest) -> TransitVerifyPayload<'_> {
    TransitVerifyPayload {
        input: request.input.expose_secret(),
        signature: request
            .signature
            .as_ref()
            .map(|secret| secret.expose_secret()),
        hmac: request.hmac.as_ref().map(|secret| secret.expose_secret()),
        context: request
            .context
            .as_ref()
            .map(|secret| secret.expose_secret()),
        prehashed: request.prehashed,
        signature_algorithm: request.signature_algorithm,
        marshaling_algorithm: request.marshaling_algorithm,
        salt_length: request.salt_length,
    }
}

#[cfg(feature = "transit-import")]
fn wrap_import_key_material<R>(
    rng: &mut R,
    wrapping_key_pem: &str,
    mut key_material: Zeroizing<Vec<u8>>,
    hash_function: TransitImportHashFunction,
) -> Result<TransitWrappedImportKey>
where
    R: rand::CryptoRng + ?Sized,
{
    if key_material.is_empty() {
        return Err(Error::InvalidParameter(
            "Transit import key material must not be empty".into(),
        ));
    }
    if key_material.len() > MAX_TRANSIT_IMPORT_KEY_MATERIAL_BYTES {
        return Err(Error::InvalidParameter(
            "Transit import key material exceeds local helper limit".into(),
        ));
    }

    use aes_kw::{KeyInit, KwpAes256};

    let mut ephemeral_aes_key = Zeroizing::new([0_u8; TRANSIT_IMPORT_EPHEMERAL_AES_KEY_BYTES]);
    rng.fill_bytes(&mut ephemeral_aes_key[..]);

    let kwp = KwpAes256::new((&*ephemeral_aes_key).into());
    let wrapped_target_len = (key_material.len().div_ceil(8) + 1) * 8;
    let mut wrapped_target = Zeroizing::new(vec![0_u8; wrapped_target_len]);
    let wrapped_target_len = kwp
        .wrap_key(&key_material, &mut wrapped_target)
        .map_err(|_| {
            Error::InvalidParameter("Transit import key material could not be wrapped".into())
        })?
        .len();
    wrapped_target.truncate(wrapped_target_len);
    key_material.zeroize();

    let wrapped_aes_key = Zeroizing::new(rsa_oaep_wrap_aes_key(
        wrapping_key_pem,
        &ephemeral_aes_key[..],
        hash_function,
    )?);

    let mut combined = Zeroizing::new(Vec::with_capacity(
        wrapped_aes_key.len() + wrapped_target.len(),
    ));
    combined.extend_from_slice(&wrapped_aes_key);
    combined.extend_from_slice(&wrapped_target);
    let ciphertext = base64_encode_secret(&combined)?;

    Ok(TransitWrappedImportKey {
        ciphertext,
        hash_function,
    })
}

#[cfg(feature = "transit-import")]
fn rsa_oaep_wrap_aes_key(
    wrapping_key_pem: &str,
    ephemeral_aes_key: &[u8],
    hash_function: TransitImportHashFunction,
) -> Result<Vec<u8>> {
    use openssl::{
        md::Md,
        pkey::{PKey, Public},
        pkey_ctx::PkeyCtx,
        rsa::Padding,
    };

    let wrapping_key: PKey<Public> = PKey::public_key_from_pem(wrapping_key_pem.as_bytes())
        .map_err(|_| Error::InvalidParameter("Transit wrapping key PEM is invalid".into()))?;
    if wrapping_key.size() != TRANSIT_WRAPPING_KEY_BYTES {
        return Err(Error::InvalidParameter(
            "Transit wrapping key must be a 4096-bit RSA public key".into(),
        ));
    }

    let digest = match hash_function {
        #[cfg(feature = "allow-sha1")]
        #[allow(deprecated)]
        TransitImportHashFunction::Sha1 => Md::sha1(),
        TransitImportHashFunction::Sha224 => Md::sha224(),
        TransitImportHashFunction::Sha256 => Md::sha256(),
        TransitImportHashFunction::Sha384 => Md::sha384(),
        TransitImportHashFunction::Sha512 => Md::sha512(),
    };

    let mut context = PkeyCtx::new(&wrapping_key)
        .map_err(|_| Error::InvalidParameter("Transit wrapping key is invalid".into()))?;
    context
        .encrypt_init()
        .map_err(|_| Error::InvalidParameter("Transit wrapping key encryption failed".into()))?;
    context
        .set_rsa_padding(Padding::PKCS1_OAEP)
        .map_err(|_| Error::InvalidParameter("Transit wrapping key encryption failed".into()))?;
    context
        .set_rsa_oaep_md(digest)
        .map_err(|_| Error::InvalidParameter("Transit wrapping key encryption failed".into()))?;
    context
        .set_rsa_mgf1_md(digest)
        .map_err(|_| Error::InvalidParameter("Transit wrapping key encryption failed".into()))?;

    let mut encrypted = Vec::new();
    context
        .encrypt_to_vec(ephemeral_aes_key, &mut encrypted)
        .map_err(|_| Error::InvalidParameter("Transit wrapping key encryption failed".into()))?;
    Ok(encrypted)
}

#[cfg(any(feature = "transit-bytes", feature = "transit-import"))]
fn base64_encode_secret(input: &[u8]) -> Result<SecretString> {
    let encoded = base64_ng::STANDARD
        .encode_secret(input)
        .map_err(|_| Error::InvalidParameter("base64 input is too large".into()))?;
    let exposed = encoded.try_into_exposed_string().map_err(|_| {
        Error::Internal("base64-ng produced non-UTF-8 text for standard base64 output")
    })?;
    Ok(SecretString::from(
        exposed.into_exposed_unprotected_string_caller_must_zeroize(),
    ))
}

#[cfg(feature = "transit-bytes")]
fn decode_base64_secret(input: &SecretString) -> Result<Zeroizing<Vec<u8>>> {
    let decoded = base64_ng::STANDARD
        .decode_secret(input.expose_secret().as_bytes())
        .map_err(|_| Error::Decode("OpenBao response contained invalid base64".into()))?;
    let exposed = decoded.into_exposed_vec();
    Ok(Zeroizing::new(
        exposed.into_exposed_unprotected_vec_caller_must_zeroize(),
    ))
}

fn deserialize_bounded_u64_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, u64>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(BoundedU64MapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

fn deserialize_bounded_secret_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, SecretString>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer
        .deserialize_map(BoundedSecretMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

fn deserialize_bounded_batch_encrypt_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<TransitBatchEncryptItem>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer)
}

fn deserialize_bounded_batch_decrypt_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<TransitBatchDecryptItem>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer)
}

fn deserialize_bounded_batch_rewrap_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<TransitBatchRewrapItem>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer)
}

fn deserialize_bounded_batch_sign_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<TransitBatchSignItem>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer)
}

fn deserialize_bounded_batch_verify_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<TransitBatchVerifyItem>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer)
}

fn deserialize_bounded_vec<'de, D, T>(deserializer: D) -> core::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserializer.deserialize_seq(
        BoundedVecVisitor::<T, { crate::response::MAX_RESPONSE_STRINGS }> {
            _marker: core::marker::PhantomData,
        },
    )
}

struct BoundedU64MapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedU64MapVisitor<MAX> {
    type Value = BTreeMap<String, u64>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} integer values")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, u64>()? else {
                return Ok(values);
            };
            values.insert(key, value);
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("OpenBao integer map exceeds item limit"));
        }
        Ok(values)
    }
}

struct BoundedSecretMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedSecretMapVisitor<MAX> {
    type Value = BTreeMap<String, SecretString>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} secret string values")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, SecretString>()? else {
                return Ok(values);
            };
            values.insert(key, value);
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("OpenBao secret map exceeds item limit"));
        }
        Ok(values)
    }
}

struct BoundedVecVisitor<T, const MAX: usize> {
    _marker: core::marker::PhantomData<T>,
}

impl<'de, T, const MAX: usize> Visitor<'de> for BoundedVecVisitor<T, MAX>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a list of at most {MAX} values")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while values.len() < MAX {
            let Some(value) = seq.next_element::<T>()? else {
                return Ok(values);
            };
            values.push(value);
        }
        if seq.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("OpenBao batch result exceeds item limit"));
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(deprecated)]

    use std::collections::BTreeMap;

    #[cfg(feature = "transit-bytes")]
    use secrecy::ExposeSecret;
    use secrecy::SecretString;

    use crate::{Client, OpenBaoConfig};

    #[cfg(feature = "transit-bytes")]
    use super::{TransitDecryptResponse, TransitEncryptRequest, TransitHashRequest};
    use super::{TransitEncryptResponse, TransitKeyInfo, TransitKeyList};

    #[test]
    fn transit_paths_are_validated() {
        let config = OpenBaoConfig::new("http://127.0.0.1:8200")
            .and_then(OpenBaoConfig::allow_localhost_http)
            .unwrap_or_else(|error| panic!("{error}"));
        let client = Client::from_config(config)
            .unwrap_or_else(|error| panic!("{error}"))
            .with_token(SecretString::from("token"));
        let transit = client
            .transit("transit")
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            transit
                .operation_path("encrypt", "app-key", None)
                .unwrap_or_else(|error| panic!("{error}")),
            "transit/encrypt/app-key"
        );
        assert!(
            transit
                .operation_path("encrypt", "../app-key", None)
                .is_err()
        );
        assert!(client.transit("../transit").is_err());
    }

    #[test]
    fn transit_key_list_is_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("key-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<TransitKeyList>(value) {
            Ok(_) => panic!("oversized Transit key list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn transit_create_key_validates_direct_auto_rotate_period_assignment() {
        let request = super::TransitCreateKeyRequest {
            auto_rotate_period: Some("forever".to_owned()),
            ..super::TransitCreateKeyRequest::default()
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn transit_key_version_map_is_bounded() {
        let mut keys = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.insert(index.to_string(), serde_json::json!(1));
        }
        let value = serde_json::json!({
            "type": "aes256-gcm96",
            "keys": keys,
        });
        let error = match serde_json::from_value::<TransitKeyInfo>(value) {
            Ok(_) => panic!("oversized Transit key version map unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn transit_encrypt_debug_redacts_ciphertext() {
        let response = TransitEncryptResponse {
            ciphertext: SecretString::from("vault:v1:secret-ciphertext"),
            key_version: Some(1),
        };
        let debug = format!("{response:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-ciphertext"));
    }

    #[test]
    fn transit_import_requests_reject_empty_ciphertext_and_redact_debug() {
        assert!(
            super::TransitImportRequest::new(
                SecretString::from(""),
                super::TransitKeyType::Aes256Gcm96
            )
            .is_err()
        );
        assert!(super::TransitImportVersionRequest::new(SecretString::from("")).is_err());

        let request = super::TransitImportRequest::new(
            SecretString::from("wrapped-secret"),
            super::TransitKeyType::Aes256Gcm96,
        )
        .unwrap_or_else(|error| panic!("{error}"))
        .with_context(SecretString::from("secret-context"));
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("wrapped-secret"));
        assert!(!debug.contains("secret-context"));

        let public_request = super::TransitImportRequest::from_public_key(
            "-----BEGIN PUBLIC KEY-----",
            super::TransitKeyType::Rsa2048,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(public_request.ciphertext.is_none());
        assert!(public_request.public_key.is_some());
        assert!(
            super::TransitImportRequest::from_public_key("", super::TransitKeyType::Rsa2048)
                .is_err()
        );

        let public_version =
            super::TransitImportVersionRequest::from_public_key("-----BEGIN PUBLIC KEY-----")
                .unwrap_or_else(|error| panic!("{error}"));
        assert!(public_version.ciphertext.is_none());
        assert!(public_version.public_key.is_some());
        assert!(super::TransitImportVersionRequest::from_public_key("").is_err());

        let mut conflicting_request = super::TransitImportRequest::new(
            SecretString::from("wrapped-secret"),
            super::TransitKeyType::Aes256Gcm96,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        conflicting_request.public_key = Some("-----BEGIN PUBLIC KEY-----".to_owned());
        assert!(conflicting_request.validate().is_err());

        let mut missing_material =
            super::TransitImportVersionRequest::new(SecretString::from("wrapped-version"))
                .unwrap_or_else(|error| panic!("{error}"));
        missing_material.ciphertext = None;
        assert!(missing_material.validate().is_err());
    }

    #[cfg(feature = "transit-import")]
    #[test]
    fn transit_import_helper_wraps_key_material_without_leaking_debug() {
        use openssl::rsa::Rsa;
        use secrecy::ExposeSecret;
        use zeroize::Zeroizing;

        let mut rng = rand::rng();
        let public_key_pem = Rsa::generate(4096)
            .unwrap_or_else(|error| panic!("{error}"))
            .public_key_to_pem()
            .unwrap_or_else(|error| panic!("{error}"));
        let public_key_pem =
            String::from_utf8(public_key_pem).unwrap_or_else(|error| panic!("{error}"));

        let wrapped = super::TransitWrappedImportKey::wrap_key_material_with_rng(
            &mut rng,
            &public_key_pem,
            Zeroizing::new(b"key-material-for-import".to_vec()),
            super::TransitImportHashFunction::Sha256,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert!(!wrapped.ciphertext.expose_secret().is_empty());
        let debug = format!("{wrapped:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(wrapped.ciphertext.expose_secret()));

        let request = wrapped
            .clone()
            .into_import_request(super::TransitKeyType::Aes256Gcm96)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(request.ciphertext.is_some());
        assert_eq!(
            request.hash_function,
            Some(super::TransitImportHashFunction::Sha256)
        );

        let version_request = wrapped
            .into_import_version_request()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(version_request.ciphertext.is_some());
        assert_eq!(
            version_request.hash_function,
            Some(super::TransitImportHashFunction::Sha256)
        );
    }

    #[test]
    fn transit_byok_export_redacts_wrapped_blobs() {
        let response = super::TransitByokExport {
            name: Some("key".to_owned()),
            keys: BTreeMap::from([("1".to_owned(), SecretString::from("wrapped-secret"))]),
        };
        let debug = format!("{response:?}");
        assert!(debug.contains("<1 redacted>"));
        assert!(!debug.contains("wrapped-secret"));
    }

    #[test]
    fn transit_cache_config_validates_small_nonzero_sizes() {
        assert!(super::TransitCacheConfig::new(0).is_ok());
        assert!(super::TransitCacheConfig::new(10).is_ok());
        assert!(super::TransitCacheConfig::new(9).is_err());
    }

    #[cfg(feature = "transit-bytes")]
    #[test]
    fn transit_byte_helpers_use_base64_ng_and_zeroizing_decode() {
        let request = TransitEncryptRequest::from_plaintext_bytes(b"secret")
            .unwrap_or_else(|error| panic!("{error}"))
            .with_context_bytes(b"app")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(request.plaintext.expose_secret(), "c2VjcmV0");
        assert_eq!(
            request.context.as_ref().map(SecretString::expose_secret),
            Some("YXBw")
        );

        let hash = TransitHashRequest::from_input_bytes(b"payload")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(hash.input.expose_secret(), "cGF5bG9hZA==");

        let response = TransitDecryptResponse {
            plaintext: SecretString::from("c2VjcmV0"),
        };
        let bytes = response
            .plaintext_bytes()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(&bytes[..], b"secret");
    }
}
