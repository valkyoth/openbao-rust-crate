//! Additive OpenBao 2.7 Transit contracts. Never bypass registered dispatch.

use super::*;
use crate::compatibility::{OpenBaoVersion, latest_routable_profile};
use serde::ser::SerializeStruct;

/// ML-DSA parameter set. This describes server-side signing, not TLS support.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum MldsaParameterSet {
    /// ML-DSA-44.
    #[serde(rename = "mldsa-44")]
    MlDsa44,
    /// ML-DSA-65.
    #[serde(rename = "mldsa-65")]
    MlDsa65,
    /// ML-DSA-87.
    #[serde(rename = "mldsa-87")]
    MlDsa87,
}

/// A bounded `config:key` registry reference, not key material or a mount path.
/// Grants must separately authorize the consuming mount in the same namespace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TransitExternalKeyReference(String);

impl TransitExternalKeyReference {
    /// Validates both registry names against OpenBao's ASCII generic-name grammar.
    pub fn new(config: &str, key: &str) -> Result<Self> {
        for name in [config, key] {
            validate_name(name)?;
        }
        Ok(Self(format!("{config}:{key}")))
    }

    /// Returns the validated reference, without resolving it or inspecting grants.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn invalid(message: &'static str) -> Error {
    Error::InvalidParameter(message.into())
}

fn validate_name(name: &str) -> Result<()> {
    let word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let bytes = name.as_bytes();
    if bytes.len() > 256
        || !bytes.first().is_some_and(|byte| word(*byte))
        || !bytes.last().is_some_and(|byte| word(*byte))
        || !bytes
            .iter()
            .all(|byte| word(*byte) || matches!(byte, b'-' | b'.'))
    {
        return Err(invalid("invalid bounded Transit key or registry name"));
    }
    Ok(())
}

/// Creates an ML-DSA key on OpenBao 2.7+. Derivation and convergence are not supported.
#[derive(Clone, Debug, Serialize)]
pub struct TransitMldsaCreateRequest {
    #[serde(rename = "type")]
    parameters: MldsaParameterSet,
    exportable: bool,
    allow_plaintext_backup: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_rotate_period: Option<String>,
}

impl TransitMldsaCreateRequest {
    /// Creates a non-exportable key with plaintext backups disabled.
    pub fn new(parameters: MldsaParameterSet) -> Self {
        Self {
            parameters,
            exportable: false,
            allow_plaintext_backup: false,
            auto_rotate_period: None,
        }
    }

    /// Irreversibly allows export of private key material on the server.
    #[must_use]
    pub fn exportable(mut self) -> Self {
        self.exportable = true;
        self
    }

    /// Irreversibly allows plaintext server backups of private key material.
    #[must_use]
    pub fn allow_plaintext_backup(mut self) -> Self {
        self.allow_plaintext_backup = true;
        self
    }

    /// Sets a validated rotation duration. The server enforces its minimum period.
    pub fn with_auto_rotate_period(mut self, period: impl Into<String>) -> Result<Self> {
        let period = period.into();
        crate::validation::validate_duration_parameter(&period, "Transit auto_rotate_period")?;
        self.auto_rotate_period = Some(period);
        Ok(self)
    }
}

/// Creates a reference-backed key. Does not create or rotate remote provider material.
/// Export, derivation, convergence and automatic rotation are intentionally unavailable.
#[derive(Clone, Debug, Serialize)]
pub struct TransitExternalKeyCreateRequest {
    #[serde(rename = "type")]
    key_type: &'static str,
    external_key_ref: TransitExternalKeyReference,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_size: Option<u16>,
}

impl TransitExternalKeyCreateRequest {
    /// References an existing, separately granted registry key.
    pub fn new(reference: TransitExternalKeyReference) -> Self {
        Self {
            key_type: "external-key",
            external_key_ref: reference,
            key_size: None,
        }
    }

    /// Sets the locally generated auxiliary HMAC key size, not the remote key size.
    pub fn with_hmac_key_size(mut self, bytes: u16) -> Result<Self> {
        if !(32..=512).contains(&bytes) {
            return Err(invalid(
                "Transit HMAC key size must be 32 through 512 bytes",
            ));
        }
        self.key_size = Some(bytes);
        Ok(self)
    }
}

/// ML-DSA import of externally wrapped PKCS#8 private material or a PEM public key.
/// Raw private key bytes must never be passed as ciphertext. This type performs no wrapping.
/// External registry keys cannot be imported; create a reference-backed key instead.
#[derive(Clone, Debug)]
pub struct TransitMldsaImportRequest {
    parameters: MldsaParameterSet,
    ciphertext: Option<SecretString>,
    public_key: Option<String>,
    hash_function: Option<TransitImportHashFunction>,
    allow_rotation: bool,
    exportable: bool,
    allow_plaintext_backup: bool,
    auto_rotate_period: Option<String>,
}

impl TransitMldsaImportRequest {
    fn empty(parameters: MldsaParameterSet) -> Self {
        Self {
            parameters,
            ciphertext: None,
            public_key: None,
            hash_function: None,
            allow_rotation: false,
            exportable: false,
            allow_plaintext_backup: false,
            auto_rotate_period: None,
        }
    }

    /// Accepts only nonempty base64 BYOK ciphertext, produced by an external wrapper.
    /// The server requires PKCS#8 private material inside that wrapping, not a raw seed.
    pub fn new(parameters: MldsaParameterSet, ciphertext: SecretString) -> Result<Self> {
        validate_non_empty_secret(&ciphertext, "Transit import ciphertext")?;
        Ok(Self {
            ciphertext: Some(ciphertext),
            ..Self::empty(parameters)
        })
    }

    /// Imports a public-only PEM SubjectPublicKeyInfo key. The server checks the parameter set.
    pub fn from_public_key(
        parameters: MldsaParameterSet,
        public_key: impl Into<String>,
    ) -> Result<Self> {
        let public_key = public_key.into();
        validate_non_empty_public_key(&public_key, "Transit import public_key")?;
        Ok(Self {
            public_key: Some(public_key),
            ..Self::empty(parameters)
        })
    }

    /// Sets the RSA-OAEP hash used by the external BYOK wrapper, not ML-DSA signing.
    #[must_use]
    pub fn with_hash_function(mut self, hash: TransitImportHashFunction) -> Self {
        self.hash_function = Some(hash);
        self
    }
    /// Allows server-side rotation; once rotated, further imports are forbidden by OpenBao.
    #[must_use]
    pub fn allow_rotation(mut self) -> Self {
        self.allow_rotation = true;
        self
    }
    /// Irreversibly enables private key export.
    #[must_use]
    pub fn exportable(mut self) -> Self {
        self.exportable = true;
        self
    }
    /// Irreversibly enables plaintext backups.
    #[must_use]
    pub fn allow_plaintext_backup(mut self) -> Self {
        self.allow_plaintext_backup = true;
        self
    }
    /// Sets a validated rotation duration; the server enforces rotation permission and minimum.
    pub fn with_auto_rotate_period(mut self, period: impl Into<String>) -> Result<Self> {
        let period = period.into();
        crate::validation::validate_duration_parameter(&period, "Transit auto_rotate_period")?;
        self.auto_rotate_period = Some(period);
        Ok(self)
    }
}

impl Serialize for TransitMldsaImportRequest {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        let mut object = serializer.serialize_struct("TransitMldsaImportRequest", 8)?;
        object.serialize_field("type", &self.parameters)?;
        if let Some(value) = &self.ciphertext {
            object.serialize_field("ciphertext", value.expose_secret())?;
        }
        if let Some(value) = &self.public_key {
            object.serialize_field("public_key", value)?;
        }
        if let Some(value) = &self.hash_function {
            object.serialize_field("hash_function", value)?;
        }
        object.serialize_field("allow_rotation", &self.allow_rotation)?;
        object.serialize_field("exportable", &self.exportable)?;
        object.serialize_field("allow_plaintext_backup", &self.allow_plaintext_backup)?;
        if let Some(value) = &self.auto_rotate_period {
            object.serialize_field("auto_rotate_period", value)?;
        }
        object.end()
    }
}

/// How the ML-DSA signing input is interpreted. This is not generic digest signing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TransitMldsaSignMode {
    /// Sign the original message. OpenBao performs ML-DSA's internal hashing.
    Message,
    /// Sign a caller-computed 64-byte external mu with `mldsa-mu` and `prehashed=true`.
    /// The caller owns correct public-key/message binding. OpenBao cannot verify mu directly.
    ExternalMu,
}

/// Validated ML-DSA signing input. Secrets are redacted from Debug.
#[derive(Clone, Debug)]
pub struct TransitMldsaSignRequest {
    input: SecretString,
    mode: TransitMldsaSignMode,
    key_version: Option<u64>,
}

impl TransitMldsaSignRequest {
    /// Accepts base64 message input, or exactly 64 decoded bytes for external mu.
    pub fn new(input: SecretString, mode: TransitMldsaSignMode) -> Result<Self> {
        if mode == TransitMldsaSignMode::ExternalMu {
            if input.expose_secret().len() != 88 {
                return Err(invalid("ML-DSA external mu must encode exactly 64 bytes"));
            }
            let decoded = base64_ng::ct::STANDARD
                .decode_secret(input.expose_secret().as_bytes())
                .map_err(|_| invalid("invalid ML-DSA external mu base64"))?;
            if decoded.len() != 64 {
                return Err(invalid("ML-DSA external mu must encode exactly 64 bytes"));
            }
        }
        Ok(Self {
            input,
            mode,
            key_version: None,
        })
    }

    /// Selects an explicit positive key version (bounded for signed server integers).
    pub fn with_key_version(mut self, version: u64) -> Result<Self> {
        validate_version(version)?;
        self.key_version = Some(version);
        Ok(self)
    }
}

fn validate_version(version: u64) -> Result<()> {
    if version == 0 || version > i32::MAX as u64 {
        return Err(invalid(
            "Transit explicit version must be in 1..=2147483647",
        ));
    }
    Ok(())
}

/// ML-DSA verification always takes the original base64 message, never external mu.
#[derive(Clone, Debug)]
pub struct TransitMldsaVerifyRequest {
    input: SecretString,
    signature: SecretString,
}

impl TransitMldsaVerifyRequest {
    /// Verifies a server-format signature against the original message.
    pub fn new(input: SecretString, signature: SecretString) -> Result<Self> {
        validate_non_empty_secret(&signature, "Transit signature")?;
        Ok(Self { input, signature })
    }
}

/// Export representation on OpenBao 2.7+. All returned key material remains secret-aware.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TransitExportFormat {
    /// Key-type-dependent original representation.
    Default,
    /// Base64 raw bytes. ML-DSA private exports are seeds, not importable PKCS#8 objects.
    Raw,
    /// Base64 PKIX public or PKCS#8 private DER.
    Der,
    /// PEM PKIX public or PKCS#8 private object.
    Pem,
}

impl TransitExportFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Default => "",
            Self::Raw => "raw",
            Self::Der => "der",
            Self::Pem => "pem",
        }
    }
}

/// One key-version record. Unlike legacy `TransitKeyInfo`, accepts every server key shape.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum TransitKeyVersionDetails {
    /// Symmetric-key creation timestamp.
    Timestamp(u64),
    /// A registry reference for an external-key version.
    ExternalReference(String),
    /// Public asymmetric-key metadata, never private material.
    Asymmetric {
        /// Public-key algorithm name.
        name: String,
        /// RFC3339 creation time.
        creation_time: String,
        /// Public key in the algorithm's representation.
        public_key: String,
        /// PEM certificate chain, when installed.
        #[serde(default)]
        certificate_chain: Option<String>,
    },
}

/// Additive detailed read response for all Transit key types, including 2.7 additions.
/// External-key capability flags describe the generic type; actual provider support may differ.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct TransitKeyDetails {
    /// Key name.
    pub name: String,
    /// OpenBao's key type string.
    #[serde(rename = "type")]
    pub key_type: String,
    /// Version metadata, bounded and duplicate-key rejecting.
    #[serde(default, deserialize_with = "version_details")]
    pub keys: BTreeMap<String, TransitKeyVersionDetails>,
    /// Latest key version.
    pub latest_version: u64,
    /// Minimum retained version.
    #[serde(default)]
    pub min_available_version: u64,
    /// Minimum version for decrypt/verify.
    #[serde(default)]
    pub min_decryption_version: u64,
    /// Minimum version for encrypt/sign.
    #[serde(default)]
    pub min_encryption_version: u64,
    /// Whether derivation is enabled.
    #[serde(default)]
    pub derived: bool,
    /// Whether deletion is enabled.
    #[serde(default)]
    pub deletion_allowed: bool,
    /// Whether exports are enabled.
    #[serde(default)]
    pub exportable: bool,
    /// Whether plaintext backups are enabled.
    #[serde(default)]
    pub allow_plaintext_backup: bool,
    /// Rotation period in seconds.
    #[serde(default)]
    pub auto_rotate_period: u64,
    /// Whether material was imported.
    #[serde(default, alias = "imported")]
    pub imported_key: bool,
    /// Whether imported material permits server rotation.
    #[serde(default)]
    pub imported_key_allow_rotation: bool,
    /// Whether the key is soft-deleted.
    #[serde(default)]
    pub soft_deleted: bool,
    /// Generic type encryption support; not a provider capability guarantee.
    #[serde(default)]
    pub supports_encryption: bool,
    /// Generic type decryption support.
    #[serde(default)]
    pub supports_decryption: bool,
    /// Generic type signing support.
    #[serde(default)]
    pub supports_signing: bool,
    /// Generic type derivation support.
    #[serde(default)]
    pub supports_derivation: bool,
}

fn version_details<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, TransitKeyVersionDetails>, D::Error> {
    struct Versions;
    impl<'de> Visitor<'de> for Versions {
        type Value = BTreeMap<String, TransitKeyVersionDetails>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("bounded Transit key versions")
        }
        fn visit_map<A: MapAccess<'de>>(
            self,
            mut map: A,
        ) -> core::result::Result<Self::Value, A::Error> {
            let mut versions = BTreeMap::new();
            while versions.len() < crate::response::MAX_RESPONSE_STRINGS {
                let Some(key) = map.next_key::<String>()? else {
                    return Ok(versions);
                };
                if versions.contains_key(&key) {
                    return Err(A::Error::custom("duplicate Transit key version"));
                }
                versions.insert(key, map.next_value()?);
            }
            map.next_key_seed(crate::response::RejectOverflow::new(
                "Transit key version limit exceeded",
            ))?;
            Ok(versions)
        }
    }
    deserializer.deserialize_map(Versions)
}

#[derive(Serialize)]
struct MldsaSignPayload<'a> {
    input: &'a str,
    prehashed: bool,
    hash_algorithm: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_version: Option<u64>,
}

fn sign_payload(request: &TransitMldsaSignRequest) -> MldsaSignPayload<'_> {
    let external = request.mode == TransitMldsaSignMode::ExternalMu;
    MldsaSignPayload {
        input: request.input.expose_secret(),
        prehashed: external,
        hash_algorithm: if external { "mldsa-mu" } else { "none" },
        key_version: request.key_version,
    }
}

#[derive(Serialize)]
struct MldsaVerifyPayload<'a> {
    input: &'a str,
    signature: &'a str,
}

fn verify_payload(request: &TransitMldsaVerifyRequest) -> MldsaVerifyPayload<'_> {
    MldsaVerifyPayload {
        input: request.input.expose_secret(),
        signature: request.signature.expose_secret(),
    }
}

#[derive(Serialize)]
struct MldsaBatchPayload<T> {
    batch_input: Vec<T>,
    prehashed: bool,
    hash_algorithm: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_version: Option<u64>,
}

#[derive(Serialize)]
struct MldsaInput<'a> {
    input: &'a str,
}

fn batch_sign_payload(
    requests: &[TransitMldsaSignRequest],
) -> Result<MldsaBatchPayload<MldsaInput<'_>>> {
    validate_batch_len(requests.len())?;
    let first = requests
        .first()
        .ok_or_else(|| invalid("empty ML-DSA batch"))?;
    if requests
        .iter()
        .any(|item| item.mode != first.mode || item.key_version != first.key_version)
    {
        return Err(invalid("ML-DSA batch mode and key version must match"));
    }
    let options = sign_payload(first);
    Ok(MldsaBatchPayload {
        batch_input: requests
            .iter()
            .map(|item| MldsaInput {
                input: item.input.expose_secret(),
            })
            .collect(),
        prehashed: options.prehashed,
        hash_algorithm: options.hash_algorithm,
        key_version: options.key_version,
    })
}

impl Transit<'_> {
    async fn require_27(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        let report = self.client.compatibility_report().await?;
        let version = report
            .profile_version()
            .or_else(latest_routable_profile)
            .ok_or(Error::Internal("no Transit compatibility profile"))?;
        if version < OpenBaoVersion::new(2, 7, 0) {
            return Err(Error::UnsupportedOpenBaoCapability {
                endpoint: "transit.2.7",
                version,
            });
        }
        Ok(())
    }

    /// Creates an ML-DSA key (2.7+). Unpromoted and older profiles fail before serialization.
    pub async fn create_mldsa_key(
        &self,
        name: &str,
        request: &TransitMldsaCreateRequest,
    ) -> Result<TransitKeyDetails> {
        self.require_27(name).await?;
        self.enveloped(Method::POST, &self.key_path(name, None)?, request)
            .await
    }

    /// Creates an external-key reference, not remote key material (2.7+).
    /// Provider support and grants determine available cryptographic operations.
    pub async fn create_external_key(
        &self,
        name: &str,
        request: &TransitExternalKeyCreateRequest,
    ) -> Result<TransitKeyDetails> {
        self.require_27(name).await?;
        self.enveloped(Method::POST, &self.key_path(name, None)?, request)
            .await
    }

    /// Rotates a reference-backed key to another granted mapping, retaining old versions.
    /// Does not rotate remote material. Never reuse a mapping for different key material.
    pub async fn rotate_external_key(
        &self,
        name: &str,
        reference: &TransitExternalKeyReference,
    ) -> Result<TransitKeyDetails> {
        self.require_27(name).await?;
        #[derive(Serialize)]
        struct Rotation<'a> {
            external_key_ref: &'a TransitExternalKeyReference,
        }
        self.enveloped(
            Method::POST,
            &self.key_path(name, Some("rotate"))?,
            &Rotation {
                external_key_ref: reference,
            },
        )
        .await
    }

    /// Reads all version metadata without the legacy timestamp-only restriction.
    /// Available on existing profiles too; no new request fields are sent.
    pub async fn read_key_details(&self, name: &str) -> Result<TransitKeyDetails> {
        validate_name(name)?;
        let envelope: ResponseEnvelope<TransitKeyDetails> = self
            .request(
                Method::GET,
                &self.key_path(name, None)?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Imports wrapped PKCS#8 private material or a PEM public ML-DSA key (2.7+).
    /// Raw private bytes must not be supplied. Fetch the wrapping key and wrap externally.
    /// For later versions use `import_mldsa_key_version`; external-key import is unsupported.
    pub async fn import_mldsa_key(
        &self,
        name: &str,
        request: &TransitMldsaImportRequest,
    ) -> Result<Empty> {
        self.require_27(name).await?;
        self.request(
            Method::POST,
            &self.key_path(name, Some("import"))?,
            Some(request),
        )
        .await
    }

    /// Imports a version into an existing ML-DSA key (2.7+). Never pass raw private bytes.
    /// The server enforces matching parameter sets and refuses imports after server rotation.
    pub async fn import_mldsa_key_version(
        &self,
        name: &str,
        request: &TransitImportVersionRequest,
    ) -> Result<Empty> {
        self.require_27(name).await?;
        if request.context.is_some() {
            return Err(invalid("ML-DSA does not support derivation context"));
        }
        if let Some(version) = request.version {
            validate_version(version)?;
        }
        self.import_key_version(name, request).await
    }

    /// Exports in an explicit representation (2.7+); raw ML-DSA seeds are not PKCS#8 imports.
    /// External keys cannot be exported. Returned private material remains secret-aware.
    pub async fn export_key_with_format(
        &self,
        key_type: TransitExportKeyType,
        name: &str,
        version: Option<u64>,
        format: TransitExportFormat,
    ) -> Result<TransitExportResponse> {
        self.require_27(name).await?;
        if let Some(version) = version {
            validate_version(version)?;
        }
        let mut path = self.path(&[
            "export",
            key_type.as_path_segment(),
            &validate_key_name(name)?.join("/"),
        ])?;
        if let Some(version) = version {
            path.push_str(&format!("/{version}"));
        }
        let envelope: ResponseEnvelope<TransitExportResponse> = self
            .request_query(
                Method::GET,
                &path,
                &[("format", format.as_str())],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Signs an ML-DSA message or externally computed mu (2.7+), including compatible providers.
    /// No metadata lookup is performed: callers must select an ML-DSA key or compatible
    /// provider. The server validates the operation, not this SDK method's name.
    pub async fn sign_mldsa(
        &self,
        name: &str,
        request: &TransitMldsaSignRequest,
    ) -> Result<TransitSignResponse> {
        self.require_27(name).await?;
        self.enveloped(
            Method::POST,
            &self.operation_path("sign", name, None)?,
            &sign_payload(request),
        )
        .await
    }

    /// Verifies an ML-DSA signature against its original message (2.7+).
    /// OpenBao explicitly rejects external-mu verification; it is not exposed here.
    /// Callers select the key; this method does not perform a metadata lookup.
    pub async fn verify_mldsa(
        &self,
        name: &str,
        request: &TransitMldsaVerifyRequest,
    ) -> Result<TransitVerifyResponse> {
        self.require_27(name).await?;
        self.enveloped(
            Method::POST,
            &self.operation_path("verify", name, None)?,
            &verify_payload(request),
        )
        .await
    }

    /// Signs a bounded homogeneous batch (2.7+). Mode and version are request-wide on the server.
    /// Mixed modes/versions are rejected, not silently dropped from individual batch items.
    pub async fn batch_sign_mldsa(
        &self,
        name: &str,
        requests: &[TransitMldsaSignRequest],
    ) -> Result<TransitBatchSignResponse> {
        let payload = batch_sign_payload(requests)?;
        self.require_27(name).await?;
        self.enveloped(
            Method::POST,
            &self.operation_path("sign", name, None)?,
            &payload,
        )
        .await
    }

    /// Verifies a bounded ML-DSA message/signature batch (2.7+), never external mu or HMAC.
    pub async fn batch_verify_mldsa(
        &self,
        name: &str,
        requests: &[TransitMldsaVerifyRequest],
    ) -> Result<TransitBatchVerifyResponse> {
        validate_batch_len(requests.len())?;
        self.require_27(name).await?;
        let payload = MldsaBatchPayload {
            batch_input: requests.iter().map(verify_payload).collect(),
            prehashed: false,
            hash_algorithm: "none",
            key_version: None,
        };
        self.enveloped(
            Method::POST,
            &self.operation_path("verify", name, None)?,
            &payload,
        )
        .await
    }
}

#[cfg(test)]
#[path = "extensions_tests.rs"]
mod tests;
