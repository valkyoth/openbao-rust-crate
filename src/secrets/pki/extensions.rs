//! Additive PKI algorithm and KMS contracts; registered dispatch and profile gates remain mandatory.

use super::*;

/// A bounded external-key registry reference (`config:key`), not private key material.
/// The provider must separately grant access to this PKI mount in the same namespace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PkiExternalKeyReference(String);

impl PkiExternalKeyReference {
    /// Validates registry names using OpenBao's ASCII generic-name grammar.
    /// Each component is limited to 256 bytes by the SDK.
    pub fn new(config: &str, key: &str) -> Result<Self> {
        for name in [config, key] {
            let word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
            let bytes = name.as_bytes();
            if bytes.len() > 256
                || !bytes.first().is_some_and(|byte| word(*byte))
                || !bytes.last().is_some_and(|byte| word(*byte))
                || !bytes
                    .iter()
                    .all(|byte| word(*byte) || matches!(byte, b'-' | b'.'))
            {
                return Err(Error::InvalidParameter(
                    "invalid bounded PKI external-key registry name".into(),
                ));
            }
        }
        Ok(Self(format!("{config}:{key}")))
    }

    /// Returns the validated reference without resolving the provider or grants.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PkiExternalKeyReference {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        struct ReferenceVisitor;
        impl Visitor<'_> for ReferenceVisitor {
            type Value = PkiExternalKeyReference;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded PKI external-key registry reference")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                value: &str,
            ) -> core::result::Result<Self::Value, E> {
                if value.len() > 513 {
                    return Err(E::custom(
                        "PKI external-key registry reference exceeds byte limit",
                    ));
                }
                let (config, key) = value
                    .split_once(':')
                    .ok_or_else(|| E::custom("invalid PKI external-key registry reference"))?;
                PkiExternalKeyReference::new(config, key)
                    .map_err(|_| E::custom("invalid PKI external-key registry reference"))
            }
        }
        deserializer.deserialize_str(ReferenceVisitor)
    }
}

/// Additive standalone key-generation response, including external-key metadata.
/// Any private key returned unexpectedly still uses the existing secret-aware storage
/// and redacted Debug implementation in [`PkiGeneratedKey`].
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct PkiGeneratedKeyDetails {
    /// Existing generation response fields.
    #[serde(flatten)]
    pub key: PkiGeneratedKey,
    /// Registry reference returned by KMS generation, not private key material.
    #[serde(default)]
    pub external_key_ref: Option<PkiExternalKeyReference>,
}

#[derive(Serialize)]
struct KmsPayload<'a, T> {
    #[serde(flatten)]
    request: &'a T,
    external_key_ref: &'a PkiExternalKeyReference,
}

pub(super) fn validate_kms_fields(
    key_type: Option<&str>,
    key_bits: Option<u64>,
    key_ref: Option<&str>,
    private_key_format: Option<&str>,
) -> Result<()> {
    if key_type.is_some() || key_bits.is_some() || key_ref.is_some() || private_key_format.is_some()
    {
        return Err(Error::InvalidParameter(
            "PKI KMS generation cannot set key_type, key_bits, key_ref or private_key_format"
                .into(),
        ));
    }
    Ok(())
}

fn root_kms_payload<'a>(
    request: &'a PkiGenerateRootRequest,
    reference: &'a PkiExternalKeyReference,
) -> Result<KmsPayload<'a, PkiGenerateRootRequest>> {
    validate_kms_fields(
        request.key_type.as_deref(),
        request.key_bits,
        request.key_ref.as_deref(),
        request.private_key_format.as_deref(),
    )?;
    Ok(KmsPayload {
        request,
        external_key_ref: reference,
    })
}

fn intermediate_kms_payload<'a>(
    request: &'a PkiGenerateIntermediateRequest,
    reference: &'a PkiExternalKeyReference,
) -> Result<KmsPayload<'a, PkiGenerateIntermediateRequest>> {
    validate_kms_fields(
        request.key_type.as_deref(),
        request.key_bits,
        request.key_ref.as_deref(),
        request.private_key_format.as_deref(),
    )?;
    Ok(KmsPayload {
        request,
        external_key_ref: reference,
    })
}

fn key_kms_payload<'a>(
    request: &'a PkiGenerateKeyRequest,
    reference: &'a PkiExternalKeyReference,
) -> Result<KmsPayload<'a, PkiGenerateKeyRequest>> {
    validate_kms_fields(request.key_type.as_deref(), request.key_bits, None, None)?;
    Ok(KmsPayload {
        request,
        external_key_ref: reference,
    })
}

/// Server-side PKI ML-DSA parameter set, available on OpenBao 2.7+.
/// This is not an assertion of SDK TLS or OCSP support for ML-DSA certificates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PkiMldsaParameterSet {
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
}

impl PkiMldsaParameterSet {
    /// OpenBao encodes the parameter set in `key_bits`, not the actual key length.
    pub const fn key_bits(self) -> u64 {
        match self {
            Self::MlDsa44 => 44,
            Self::MlDsa65 => 65,
            Self::MlDsa87 => 87,
        }
    }
}

impl PkiGenerateRootRequest {
    /// Selects server-side ML-DSA, replacing any previous key type and size.
    /// Sending requires a promoted OpenBao 2.7+ profile, including for root rotation.
    #[must_use]
    pub fn with_mldsa(mut self, parameters: PkiMldsaParameterSet) -> Self {
        self.key_type = Some("mldsa".into());
        self.key_bits = Some(parameters.key_bits());
        self
    }
}

impl PkiGenerateIntermediateRequest {
    /// Selects server-side ML-DSA for CSR generation, replacing key type and size.
    /// Sending requires a promoted OpenBao 2.7+ profile.
    #[must_use]
    pub fn with_mldsa(mut self, parameters: PkiMldsaParameterSet) -> Self {
        self.key_type = Some("mldsa".into());
        self.key_bits = Some(parameters.key_bits());
        self
    }
}

impl PkiGenerateKeyRequest {
    /// Selects standalone server-side ML-DSA generation, replacing key type and size.
    /// Sending requires a promoted OpenBao 2.7+ profile.
    #[must_use]
    pub fn with_mldsa(mut self, parameters: PkiMldsaParameterSet) -> Self {
        self.key_type = Some("mldsa".into());
        self.key_bits = Some(parameters.key_bits());
        self
    }
}

impl PkiRole {
    /// Restricts generated keys and submitted CSRs to server-side ML-DSA.
    /// Replaces key type and size; sending requires a promoted OpenBao 2.7+ profile.
    #[must_use]
    pub fn with_mldsa(mut self, parameters: PkiMldsaParameterSet) -> Self {
        self.key_type = Some("mldsa".into());
        self.key_bits = Some(parameters.key_bits());
        self
    }
}

fn selects_mldsa(key_type: Option<&str>, key_bits: Option<u64>) -> Result<bool> {
    if !key_type.is_some_and(|value| value.eq_ignore_ascii_case("mldsa")) {
        return Ok(false);
    }
    if !matches!(key_bits, None | Some(0 | 44 | 65 | 87)) {
        return Err(Error::InvalidParameter(
            "PKI ML-DSA key_bits must be 0, 44, 65 or 87".into(),
        ));
    }
    Ok(true)
}

impl Pki<'_> {
    async fn require_kms_profile(&self) -> Result<()> {
        const KMS: crate::request_compatibility::VersionedRequestField =
            crate::request_compatibility::VersionedRequestField::since(
                "pki.generation",
                "external_key_ref",
                crate::OpenBaoVersion::new(2, 7, 0),
            );
        self.client
            .validate_versioned_request_fields(&[(&KMS, true)])
            .await
    }

    /// Generates a root using an external provider key (OpenBao 2.7+).
    /// Requires a provider grant for this mount. Key type/size, existing `key_ref`
    /// and private-key export format must be omitted; this does not export a key.
    /// Unpromoted and older compatibility profiles fail before sending the operation.
    pub async fn generate_root_kms(
        &self,
        reference: &PkiExternalKeyReference,
        request: &PkiGenerateRootRequest,
    ) -> Result<PkiAuthorityBundle> {
        let payload = root_kms_payload(request, reference)?;
        self.require_kms_profile().await?;
        self.validate_authority_request_fields(request.not_before.is_some())
            .await?;
        self.enveloped(
            Method::POST,
            &self.path(&["root", "generate", "kms"])?,
            Some(&payload),
        )
        .await
    }

    /// Generates a multi-issuer root using an external provider key (OpenBao 2.7+).
    /// Has the same grant, input and profile restrictions as [`Self::generate_root_kms`].
    pub async fn generate_issuer_root_kms(
        &self,
        reference: &PkiExternalKeyReference,
        request: &PkiGenerateRootRequest,
    ) -> Result<PkiAuthorityBundle> {
        let payload = root_kms_payload(request, reference)?;
        self.require_kms_profile().await?;
        self.validate_authority_request_fields(request.not_before.is_some())
            .await?;
        self.enveloped(
            Method::POST,
            &self.path(&["issuers", "generate", "root", "kms"])?,
            Some(&payload),
        )
        .await
    }

    /// Rotates the root using an external provider key (OpenBao 2.7+).
    /// Has the same grant, input and profile restrictions as [`Self::generate_root_kms`].
    pub async fn rotate_root_kms(
        &self,
        reference: &PkiExternalKeyReference,
        request: &PkiGenerateRootRequest,
    ) -> Result<PkiAuthorityBundle> {
        let payload = root_kms_payload(request, reference)?;
        self.require_kms_profile().await?;
        self.validate_authority_request_fields(request.not_before.is_some())
            .await?;
        self.enveloped(
            Method::POST,
            &self.path(&["root", "rotate", "kms"])?,
            Some(&payload),
        )
        .await
    }

    /// Generates an intermediate CSR using an external provider key (OpenBao 2.7+).
    /// Has the same grant, input and profile restrictions as [`Self::generate_root_kms`].
    pub async fn generate_intermediate_kms(
        &self,
        reference: &PkiExternalKeyReference,
        request: &PkiGenerateIntermediateRequest,
    ) -> Result<PkiAuthorityBundle> {
        let payload = intermediate_kms_payload(request, reference)?;
        self.require_kms_profile().await?;
        self.validate_authority_request_fields(request.not_before.is_some())
            .await?;
        self.enveloped(
            Method::POST,
            &self.path(&["intermediate", "generate", "kms"])?,
            Some(&payload),
        )
        .await
    }

    /// Generates a multi-issuer intermediate CSR with an external key (OpenBao 2.7+).
    /// Has the same grant, input and profile restrictions as [`Self::generate_root_kms`].
    pub async fn generate_issuer_intermediate_kms(
        &self,
        reference: &PkiExternalKeyReference,
        request: &PkiGenerateIntermediateRequest,
    ) -> Result<PkiAuthorityBundle> {
        let payload = intermediate_kms_payload(request, reference)?;
        self.require_kms_profile().await?;
        self.validate_authority_request_fields(request.not_before.is_some())
            .await?;
        self.enveloped(
            Method::POST,
            &self.path(&["issuers", "generate", "intermediate", "kms"])?,
            Some(&payload),
        )
        .await
    }

    /// Registers an external provider key in this PKI mount (OpenBao 2.7+).
    /// Requires a provider grant; this does not generate or export provider key material.
    /// `key_type` and `key_bits` must be omitted. Older/unpromoted profiles fail closed.
    pub async fn generate_key_kms(
        &self,
        reference: &PkiExternalKeyReference,
        request: &PkiGenerateKeyRequest,
    ) -> Result<PkiGeneratedKeyDetails> {
        let payload = key_kms_payload(request, reference)?;
        self.require_kms_profile().await?;
        self.enveloped(
            Method::POST,
            &self.path(&["keys", "generate", "kms"])?,
            Some(&payload),
        )
        .await
    }

    pub(super) async fn validate_pki_key_algorithm(
        &self,
        key_type: Option<&str>,
        key_bits: Option<u64>,
    ) -> Result<()> {
        const MLDSA: crate::request_compatibility::VersionedRequestField =
            crate::request_compatibility::VersionedRequestField::since(
                "pki.key",
                "key_type=mldsa",
                crate::OpenBaoVersion::new(2, 7, 0),
            );
        if !selects_mldsa(key_type, key_bits)? {
            return Ok(());
        }
        self.client
            .validate_versioned_request_fields(&[(&MLDSA, true)])
            .await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    use super::*;

    fn wire(value: &impl Serialize) -> serde_json::Value {
        serde_json::to_value(value).unwrap_or_else(|_| panic!("fixture serialization failed"))
    }

    #[test]
    fn external_references_are_bounded_and_cannot_inject_segments() {
        for name in ["a", "_", "provider.name-1", &"a".repeat(256)] {
            let reference = PkiExternalKeyReference::new(name, name)
                .unwrap_or_else(|_| panic!("valid reference rejected"));
            let expected = format!("{name}:{name}");
            assert_eq!(reference.as_str(), expected);
            assert_eq!(wire(&reference), expected);
            let decoded: PkiExternalKeyReference = serde_json::from_value(wire(&reference))
                .unwrap_or_else(|_| panic!("reference round trip failed"));
            assert_eq!(reference, decoded);
        }
        for name in [
            "",
            ".",
            "-a",
            "a-",
            "a.",
            "a/b",
            "a:b",
            "a%2fb",
            "a?b",
            "a#b",
            "a b",
            "a\nb",
            "a\0b",
            "caf\u{e9}",
            &"a".repeat(257),
        ] {
            assert!(PkiExternalKeyReference::new(name, "key").is_err());
            assert!(PkiExternalKeyReference::new("provider", name).is_err());
            let invalid = format!("provider:{name}");
            assert!(serde_json::from_value::<PkiExternalKeyReference>(invalid.into()).is_err());
        }
        for value in ["no-separator", "a:b:c", ":b", "a:"] {
            assert!(serde_json::from_value::<PkiExternalKeyReference>(value.into()).is_err());
        }
        let escaped: PkiExternalKeyReference = serde_json::from_str(r#""provider\u003akey""#)
            .unwrap_or_else(|_| panic!("escaped reference rejected"));
        assert_eq!(escaped.as_str(), "provider:key");
        let over_limit = format!("{}:{}", "a".repeat(256), "b".repeat(257));
        let encoded = serde_json::to_string(&over_limit)
            .unwrap_or_else(|_| panic!("reference serialization failed"));
        let error = serde_json::from_str::<PkiExternalKeyReference>(&encoded)
            .err()
            .unwrap_or_else(|| panic!("oversized reference accepted"));
        assert!(!error.to_string().contains(&over_limit));
    }

    #[test]
    fn kms_payloads_preserve_fields_and_reject_conflicts() {
        let reference = PkiExternalKeyReference::new("provider", "key")
            .unwrap_or_else(|_| panic!("reference failed"));
        let root = PkiGenerateRootRequest {
            common_name: "CA".into(),
            ttl: Some("1h".into()),
            ..Default::default()
        };
        let intermediate = PkiGenerateIntermediateRequest {
            common_name: "CA".into(),
            ..Default::default()
        };
        let key = PkiGenerateKeyRequest {
            key_name: Some("signing-key".into()),
            ..Default::default()
        };
        let root_wire =
            wire(&root_kms_payload(&root, &reference).unwrap_or_else(|_| panic!("root failed")));
        let csr_wire = wire(
            &intermediate_kms_payload(&intermediate, &reference)
                .unwrap_or_else(|_| panic!("CSR failed")),
        );
        let key_wire =
            wire(&key_kms_payload(&key, &reference).unwrap_or_else(|_| panic!("key failed")));
        assert_eq!(root_wire["ttl"], "1h");
        assert_eq!(csr_wire["common_name"], "CA");
        assert_eq!(key_wire["key_name"], "signing-key");
        for value in [root_wire, csr_wire, key_wire] {
            assert_eq!(value["external_key_ref"], "provider:key");
            for absent in [
                "key_type",
                "key_bits",
                "key_ref",
                "private_key_format",
                "use_pss",
            ] {
                assert!(value.get(absent).is_none());
            }
        }
        for index in 0..4 {
            let mut root = root.clone();
            let mut csr = intermediate.clone();
            match index {
                0 => {
                    root.key_type = Some(String::new());
                    csr.key_type = Some(String::new());
                }
                1 => {
                    root.key_bits = Some(0);
                    csr.key_bits = Some(0);
                }
                2 => {
                    root.key_ref = Some(String::new());
                    csr.key_ref = Some(String::new());
                }
                _ => {
                    root.private_key_format = Some(String::new());
                    csr.private_key_format = Some(String::new());
                }
            }
            assert!(root_kms_payload(&root, &reference).is_err());
            assert!(intermediate_kms_payload(&csr, &reference).is_err());
        }
        for request in [
            PkiGenerateKeyRequest {
                key_type: Some("rsa".into()),
                ..Default::default()
            },
            PkiGenerateKeyRequest {
                key_bits: Some(0),
                ..Default::default()
            },
        ] {
            assert!(key_kms_payload(&request, &reference).is_err());
        }
    }

    #[test]
    fn detailed_generated_keys_retain_metadata_and_redact_unexpected_private_keys() {
        let synthetic = ["fixture-", "private-value"].concat();
        let details: PkiGeneratedKeyDetails = serde_json::from_value(serde_json::json!({
            "key_id": "id", "key_type": "rsa", "external_key_ref": "provider:key",
            "private_key": synthetic,
        }))
        .unwrap_or_else(|_| panic!("details failed"));
        assert_eq!(details.key.key_type.as_deref(), Some("rsa"));
        assert_eq!(
            details
                .external_key_ref
                .as_ref()
                .map(PkiExternalKeyReference::as_str),
            Some("provider:key")
        );
        assert!(
            details
                .key
                .private_key
                .as_ref()
                .is_some_and(|value| value.expose_secret() == synthetic)
        );
        assert!(!format!("{details:?}").contains(&synthetic));
        for missing in [
            r#"{"key_type":"rsa"}"#,
            r#"{"key_type":"rsa","external_key_ref":null}"#,
        ] {
            let details: PkiGeneratedKeyDetails = serde_json::from_str(missing)
                .unwrap_or_else(|_| panic!("optional reference rejected"));
            assert!(details.external_key_ref.is_none());
        }
        assert!(
            serde_json::from_str::<PkiGeneratedKeyDetails>(
                r#"{"external_key_ref":"a:b","external_key_ref":"c:d"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn typed_mldsa_preserves_other_fields_and_wire_contracts() {
        for (parameters, bits) in [
            (PkiMldsaParameterSet::MlDsa44, 44),
            (PkiMldsaParameterSet::MlDsa65, 65),
            (PkiMldsaParameterSet::MlDsa87, 87),
        ] {
            let root = PkiGenerateRootRequest {
                common_name: "Test CA".into(),
                key_type: Some("rsa".into()),
                key_bits: Some(4096),
                ..Default::default()
            }
            .with_mldsa(parameters);
            assert_eq!(wire(&root)["common_name"], "Test CA");
            let csr = PkiGenerateIntermediateRequest::default().with_mldsa(parameters);
            let key = PkiGenerateKeyRequest::default().with_mldsa(parameters);
            let role = PkiRole {
                ttl: Some("1h".into()),
                ..Default::default()
            }
            .with_mldsa(parameters);
            assert_eq!(wire(&role)["ttl"], "1h");
            for value in [wire(&root), wire(&csr), wire(&key), wire(&role)] {
                assert_eq!(value["key_type"], "mldsa");
                assert_eq!(value["key_bits"], bits);
                assert!(value.get("external_key_ref").is_none());
                assert!(value.get("use_pss").is_none());
            }
        }
        assert!(
            wire(&PkiGenerateRootRequest::default())
                .get("key_type")
                .is_none()
        );
        assert!(
            wire(&PkiGenerateIntermediateRequest::default())
                .get("key_bits")
                .is_none()
        );
    }

    #[test]
    fn raw_mldsa_fields_cannot_bypass_parameter_validation() {
        for kind in ["mldsa", "MLDSA", "MlDsA"] {
            for bits in [None, Some(0), Some(44), Some(65), Some(87)] {
                assert!(matches!(selects_mldsa(Some(kind), bits), Ok(true)));
            }
            for bits in [1, 43, 45, 64, 66, 86, 88, 2048, u64::MAX] {
                assert!(selects_mldsa(Some(kind), Some(bits)).is_err());
            }
        }
        for kind in [None, Some("rsa"), Some("ec"), Some("ed25519"), Some("any")] {
            assert!(matches!(selects_mldsa(kind, Some(256)), Ok(false)));
        }
    }
}
