//! Transit secrets engine support.

use core::fmt;
use std::collections::BTreeMap;

use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as DeError, IgnoredAny, MapAccess, Visitor},
};
#[cfg(feature = "transit-bytes")]
use zeroize::Zeroizing;

use crate::{
    Authenticated, Client, Error, Result,
    path::{validate_endpoint_path, validate_mount_path},
    response::{
        Empty, ListEntries, ListPageOptions, ResponseEnvelope, deserialize_bounded_string_vec,
    },
};

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

#[cfg(feature = "transit-bytes")]
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
