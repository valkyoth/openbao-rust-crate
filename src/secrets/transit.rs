//! Transit secrets engine support.

use core::fmt;
use std::collections::BTreeMap;

use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as DeError, IgnoredAny, MapAccess, Visitor},
};

use crate::{
    Authenticated, Client, Error, Result,
    path::{validate_mount_path, validate_secret_path},
    response::{Empty, ResponseEnvelope, deserialize_bounded_string_vec},
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

/// Transit key list response.
#[derive(Clone, Debug, Deserialize)]
pub struct TransitKeyList {
    /// Transit key names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
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

/// Request for hashing data with Transit.
#[derive(Clone, Debug)]
pub struct TransitHashRequest {
    /// Base64-encoded input.
    pub input: SecretString,
    /// Output encoding.
    pub format: Option<TransitOutputFormat>,
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
    /// OpenBao signature algorithm string, such as `pss` or `pkcs1v15`.
    pub signature_algorithm: Option<String>,
}

/// Transit signing response.
#[derive(Clone, Deserialize)]
pub struct TransitSignResponse {
    /// Signature in OpenBao's encoded format.
    pub signature: SecretString,
    /// Derived public key, when returned by OpenBao.
    #[serde(default)]
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
    /// OpenBao signature algorithm string, such as `pss` or `pkcs1v15`.
    pub signature_algorithm: Option<String>,
}

/// Transit verification response.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct TransitVerifyResponse {
    /// Whether verification succeeded.
    pub valid: bool,
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
    signature_algorithm: Option<&'a str>,
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
    signature_algorithm: Option<&'a str>,
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
        let mut query = Vec::new();
        if let Some(after) = after {
            query.push(("after", validate_key_name(after)?.join("/")));
        }
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
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

    /// Encrypts base64-encoded plaintext with a Transit key.
    ///
    /// The plaintext is wrapped in `SecretString` and the crate zeroizes its
    /// serialization buffer, but the HTTP stack can retain transient body
    /// copies outside this crate's control during request transmission.
    pub async fn encrypt(
        &self,
        name: &str,
        request: &TransitEncryptRequest,
    ) -> Result<TransitEncryptResponse> {
        let payload = TransitEncryptPayload {
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
        };
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
        let payload = TransitDecryptPayload {
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
        };
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
        let payload = TransitRewrapPayload {
            ciphertext: request.ciphertext.expose_secret(),
            context: request
                .context
                .as_ref()
                .map(|secret| secret.expose_secret()),
            key_version: request.key_version,
            nonce: request.nonce.as_ref().map(|secret| secret.expose_secret()),
        };
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
        let payload = TransitSignPayload {
            input: request.input.expose_secret(),
            key_version: request.key_version,
            context: request
                .context
                .as_ref()
                .map(|secret| secret.expose_secret()),
            prehashed: request.prehashed,
            signature_algorithm: request.signature_algorithm.as_deref(),
        };
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
        let payload = TransitVerifyPayload {
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
            signature_algorithm: request.signature_algorithm.as_deref(),
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
            segments.extend(validate_secret_path(segment)?);
        }
        Ok(segments.join("/"))
    }
}

fn validate_key_name(name: &str) -> Result<Vec<String>> {
    validate_mount_path(name)
}

fn deserialize_bounded_u64_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, u64>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(BoundedU64MapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::SecretString;

    use crate::{Client, OpenBaoConfig};

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
}
