//! Authority signing options, with explicit key-source selection and registered dispatch.

use super::*;

/// Key source for authority generation with signature options (reviewed 2.7+ contract).
/// This additive selector does not extend the existing exhaustive
/// [`PkiKeyGenerationType`] enum. Provider grants and signer capabilities remain
/// server-enforced; selecting ML-DSA does not imply SDK TLS or OCSP support.
#[cfg_attr(
    not(feature = "operator-ops"),
    doc = r#"
Cross-sign CSR generation remains unavailable without operator operations:
```compile_fail
use openbao::secrets::pki::{Pki, PkiGenerateIntermediateRequest, PkiSignatureOptions};
async fn forbidden(pki: &Pki<'_>) {
    let _ = pki.cross_sign_intermediate_csr(
        &PkiGenerateIntermediateRequest::default(), &PkiSignatureOptions::default()
    ).await;
}
```
"#
)]
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum PkiAuthorityKeySource {
    /// Generates a key without exporting private key material.
    Internal,
    /// Generates a key and returns private key material in secret-aware fields.
    Exported,
    /// Reuses a registered mount key. The request must explicitly set `key_ref`
    /// (including `default` if intended), and omit key type/size/export format.
    Existing,
    /// Uses a granted external provider key. Local key settings must be omitted.
    Kms(PkiExternalKeyReference),
}

impl From<PkiKeyGenerationType> for PkiAuthorityKeySource {
    fn from(value: PkiKeyGenerationType) -> Self {
        match value {
            PkiKeyGenerationType::Internal => Self::Internal,
            PkiKeyGenerationType::Exported => Self::Exported,
            PkiKeyGenerationType::Existing => Self::Existing,
        }
    }
}

impl PkiAuthorityKeySource {
    fn segment(&self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::Exported => "exported",
            Self::Existing => "existing",
            Self::Kms(_) => "kms",
        }
    }

    fn reference(&self) -> Option<&PkiExternalKeyReference> {
        match self {
            Self::Kms(reference) => Some(reference),
            _ => None,
        }
    }

    fn validate(
        &self,
        key_type: Option<&str>,
        key_bits: Option<u64>,
        key_ref: Option<&str>,
        private_key_format: Option<&str>,
    ) -> Result<()> {
        match self {
            Self::Kms(_) => {
                extensions::validate_kms_fields(key_type, key_bits, key_ref, private_key_format)
            }
            Self::Existing => {
                if key_type.is_some() || key_bits.is_some() || private_key_format.is_some() {
                    return Err(Error::InvalidParameter(
                        "existing PKI keys cannot set key_type, key_bits or private_key_format"
                            .into(),
                    ));
                }
                let reference = key_ref.ok_or_else(|| {
                    Error::InvalidParameter(
                        "existing PKI generation requires an explicit key_ref".into(),
                    )
                })?;
                if reference.is_empty()
                    || reference.len() > 256
                    || validate_mount_path(reference)?.len() != 1
                    || reference.contains('/')
                {
                    return Err(Error::InvalidParameter(
                        "existing PKI key_ref must be a bounded single reference".into(),
                    ));
                }
                Ok(())
            }
            Self::Internal | Self::Exported => {
                if key_ref.is_some() {
                    return Err(Error::InvalidParameter(
                        "new PKI key generation cannot set key_ref".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

#[derive(Serialize)]
struct AuthorityPayload<'a, T> {
    #[serde(flatten)]
    request: &'a T,
    #[serde(flatten)]
    signature: &'a PkiSignatureOptions,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_key_ref: Option<&'a PkiExternalKeyReference>,
}

impl Pki<'_> {
    async fn generate_root_signed(
        &self,
        prefix: &[&str],
        source: &PkiAuthorityKeySource,
        request: &PkiGenerateRootRequest,
        signature: &PkiSignatureOptions,
    ) -> Result<PkiAuthorityBundle> {
        validate_private_key_output_format(
            request.format.as_deref(),
            matches!(source, PkiAuthorityKeySource::Exported),
        )?;
        source.validate(
            request.key_type.as_deref(),
            request.key_bits,
            request.key_ref.as_deref(),
            request.private_key_format.as_deref(),
        )?;
        self.require_signing_options_profile().await?;
        self.validate_pki_key_algorithm(request.key_type.as_deref(), request.key_bits)
            .await?;
        self.validate_authority_request_fields(request.not_before.is_some())
            .await?;
        let mut parts = prefix.to_vec();
        parts.push(source.segment());
        self.enveloped(
            Method::POST,
            &self.path(&parts)?,
            Some(&AuthorityPayload {
                request,
                signature,
                external_key_ref: source.reference(),
            }),
        )
        .await
    }

    async fn generate_intermediate_signed(
        &self,
        parts: &[&str],
        source: &PkiAuthorityKeySource,
        request: &PkiGenerateIntermediateRequest,
        signature: &PkiSignatureOptions,
    ) -> Result<PkiAuthorityBundle> {
        validate_private_key_output_format(
            request.format.as_deref(),
            matches!(source, PkiAuthorityKeySource::Exported),
        )?;
        source.validate(
            request.key_type.as_deref(),
            request.key_bits,
            request.key_ref.as_deref(),
            request.private_key_format.as_deref(),
        )?;
        self.require_signing_options_profile().await?;
        self.validate_pki_key_algorithm(request.key_type.as_deref(), request.key_bits)
            .await?;
        self.validate_authority_request_fields(request.not_before.is_some())
            .await?;
        self.enveloped(
            Method::POST,
            &self.path(parts)?,
            Some(&AuthorityPayload {
                request,
                signature,
                external_key_ref: source.reference(),
            }),
        )
        .await
    }

    /// Generates a root with signature preferences (reviewed 2.7+ contract).
    /// RSA-PSS applies only to RSA signers. Existing/KMS keys reject conflicting
    /// local generation settings; exported generation returns sensitive key material.
    /// Older and unpromoted profiles fail closed, even with empty signature options.
    pub async fn generate_root_with_signature_options(
        &self,
        source: &PkiAuthorityKeySource,
        request: &PkiGenerateRootRequest,
        signature: &PkiSignatureOptions,
    ) -> Result<PkiAuthorityBundle> {
        self.generate_root_signed(&["root", "generate"], source, request, signature)
            .await
    }

    /// Generates a multi-issuer root with the same source/signature restrictions
    /// as [`Self::generate_root_with_signature_options`] (2.7+).
    pub async fn generate_issuer_root_with_signature_options(
        &self,
        source: &PkiAuthorityKeySource,
        request: &PkiGenerateRootRequest,
        signature: &PkiSignatureOptions,
    ) -> Result<PkiAuthorityBundle> {
        self.generate_root_signed(&["issuers", "generate", "root"], source, request, signature)
            .await
    }

    /// Rotates a root with the same source/signature restrictions as
    /// [`Self::generate_root_with_signature_options`] (2.7+).
    pub async fn rotate_root_with_signature_options(
        &self,
        source: &PkiAuthorityKeySource,
        request: &PkiGenerateRootRequest,
        signature: &PkiSignatureOptions,
    ) -> Result<PkiAuthorityBundle> {
        self.generate_root_signed(&["root", "rotate"], source, request, signature)
            .await
    }

    /// Generates an intermediate CSR with signature preferences (2.7+).
    /// The signature options apply to the CSR, not the certificate later issued
    /// by its parent. Source restrictions match [`Self::generate_root_with_signature_options`].
    pub async fn generate_intermediate_with_signature_options(
        &self,
        source: &PkiAuthorityKeySource,
        request: &PkiGenerateIntermediateRequest,
        signature: &PkiSignatureOptions,
    ) -> Result<PkiAuthorityBundle> {
        self.generate_intermediate_signed(
            &["intermediate", "generate", source.segment()],
            source,
            request,
            signature,
        )
        .await
    }

    /// Generates a multi-issuer intermediate CSR with signature preferences (2.7+).
    /// Has the same restrictions as [`Self::generate_intermediate_with_signature_options`].
    pub async fn generate_issuer_intermediate_with_signature_options(
        &self,
        source: &PkiAuthorityKeySource,
        request: &PkiGenerateIntermediateRequest,
        signature: &PkiSignatureOptions,
    ) -> Result<PkiAuthorityBundle> {
        self.generate_intermediate_signed(
            &["issuers", "generate", "intermediate", source.segment()],
            source,
            request,
            signature,
        )
        .await
    }

    /// Signs an intermediate CSR with signature preferences for the issuer (2.7+).
    /// This does not change the subject key encoded in the CSR.
    pub async fn sign_intermediate_with_signature_options(
        &self,
        request: &PkiSignIntermediateRequest,
        signature: &PkiSignatureOptions,
    ) -> Result<PkiCertificateBundle> {
        self.require_signing_options_profile().await?;
        self.enveloped(
            Method::POST,
            &self.path(&["root", "sign-intermediate"])?,
            Some(&AuthorityPayload {
                request,
                signature,
                external_key_ref: None,
            }),
        )
        .await
    }

    /// Signs an intermediate CSR with a named issuer and signature preferences (2.7+).
    pub async fn sign_intermediate_with_issuer_and_signature_options(
        &self,
        issuer_ref: &str,
        request: &PkiSignIntermediateRequest,
        signature: &PkiSignatureOptions,
    ) -> Result<PkiCertificateBundle> {
        let path = self.path(&["issuer", issuer_ref, "sign-intermediate"])?;
        self.require_signing_options_profile().await?;
        self.enveloped(
            Method::POST,
            &path,
            Some(&AuthorityPayload {
                request,
                signature,
                external_key_ref: None,
            }),
        )
        .await
    }

    /// Generates a CSR for cross-signing using an existing mount key (2.7+).
    /// This does not sign an input CSR or return a certificate. Set `key_ref`
    /// explicitly and omit key type/size/export format. Submit the returned
    /// `csr` to the intended parent CA separately. Signature settings apply to
    /// the CSR only. Requires both operator feature gates; it does not export a key.
    #[cfg(feature = "operator-ops")]
    pub async fn cross_sign_intermediate_csr(
        &self,
        request: &PkiGenerateIntermediateRequest,
        signature: &PkiSignatureOptions,
    ) -> Result<PkiAuthorityBundle> {
        self.generate_intermediate_signed(
            &["intermediate", "cross-sign"],
            &PkiAuthorityKeySource::Existing,
            request,
            signature,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    use super::*;

    fn wire(value: &impl Serialize) -> JsonValue {
        serde_json::to_value(value).unwrap_or_else(|_| panic!("serialization failed"))
    }

    #[test]
    fn authority_sources_have_explicit_modes_and_conflict_rules() {
        let reference = PkiExternalKeyReference::new("provider", "key")
            .unwrap_or_else(|_| panic!("reference failed"));
        let kms = PkiAuthorityKeySource::Kms(reference);
        assert_eq!(kms.segment(), "kms");
        assert_eq!(
            kms.reference().map(PkiExternalKeyReference::as_str),
            Some("provider:key")
        );
        assert!(kms.validate(None, None, None, None).is_ok());
        for (key_type, bits, key_ref, format) in [
            (Some(""), None, None, None),
            (None, Some(0), None, None),
            (None, None, Some(""), None),
            (None, None, None, Some("")),
        ] {
            assert!(kms.validate(key_type, bits, key_ref, format).is_err());
        }
        for (legacy, expected) in [
            (PkiKeyGenerationType::Internal, "internal"),
            (PkiKeyGenerationType::Exported, "exported"),
            (PkiKeyGenerationType::Existing, "existing"),
        ] {
            let source = PkiAuthorityKeySource::from(legacy);
            assert_eq!(source.segment(), expected);
            assert!(source.reference().is_none());
        }
        for source in [
            PkiAuthorityKeySource::Internal,
            PkiAuthorityKeySource::Exported,
        ] {
            assert!(
                source
                    .validate(Some("rsa"), Some(2048), None, Some("pkcs8"))
                    .is_ok()
            );
            for reference in ["", "default", "existing-key"] {
                assert!(source.validate(None, None, Some(reference), None).is_err());
            }
        }
        let existing = PkiAuthorityKeySource::Existing;
        assert!(existing.validate(None, None, None, None).is_err());
        for reference in ["default", "signing-key", &"a".repeat(256)] {
            assert!(existing.validate(None, None, Some(reference), None).is_ok());
            assert!(
                existing
                    .validate(Some("rsa"), None, Some(reference), None)
                    .is_err()
            );
            assert!(
                existing
                    .validate(None, Some(0), Some(reference), None)
                    .is_err()
            );
            assert!(
                existing
                    .validate(None, None, Some(reference), Some("pkcs8"))
                    .is_err()
            );
        }
        for reference in [
            "",
            "/default",
            "default/",
            "a/b",
            "..",
            "a%2fb",
            "a?b",
            "a\nb",
            &"a".repeat(257),
        ] {
            assert!(
                existing
                    .validate(None, None, Some(reference), None)
                    .is_err()
            );
        }
    }

    #[test]
    fn private_output_cannot_enter_public_bundle_fields() {
        for format in [None, Some("pem"), Some("der")] {
            assert!(validate_private_key_output_format(format, true).is_ok());
        }
        for format in ["pem_bundle", "PEM_BUNDLE"] {
            assert!(validate_private_key_output_format(Some(format), true).is_err());
            assert!(validate_private_key_output_format(Some(format), false).is_ok());
        }
    }

    #[test]
    fn authority_payloads_preserve_signature_defaults_and_key_sources() {
        let root = PkiGenerateRootRequest {
            common_name: "CA".into(),
            ttl: Some("24h".into()),
            ..Default::default()
        };
        let csr = PkiGenerateIntermediateRequest {
            common_name: "CA".into(),
            key_ref: Some("existing-key".into()),
            ..Default::default()
        };
        let sign = PkiSignIntermediateRequest {
            csr: "public-csr-fixture".into(),
            ttl: Some("1h".into()),
            ..Default::default()
        };
        let reference = PkiExternalKeyReference::new("provider", "key")
            .unwrap_or_else(|_| panic!("reference failed"));
        let default_signature = PkiSignatureOptions::default();
        assert_eq!(
            wire(&AuthorityPayload {
                request: &root,
                signature: &default_signature,
                external_key_ref: None
            }),
            wire(&root)
        );
        for enabled in [false, true] {
            for bits in [0, 256, 384, 512] {
                let signature = PkiSignatureOptions::default()
                    .with_pss(enabled)
                    .with_signature_bits(bits)
                    .unwrap_or_else(|_| panic!("signature failed"));
                let root_value = wire(&AuthorityPayload {
                    request: &root,
                    signature: &signature,
                    external_key_ref: Some(&reference),
                });
                let csr_value = wire(&AuthorityPayload {
                    request: &csr,
                    signature: &signature,
                    external_key_ref: None,
                });
                let sign_value = wire(&AuthorityPayload {
                    request: &sign,
                    signature: &signature,
                    external_key_ref: None,
                });
                assert_eq!(root_value["ttl"], "24h");
                assert_eq!(root_value["external_key_ref"], "provider:key");
                assert_eq!(csr_value["key_ref"], "existing-key");
                assert!(csr_value.get("external_key_ref").is_none());
                assert_eq!(sign_value["csr"], "public-csr-fixture");
                assert_eq!(sign_value["ttl"], "1h");
                for value in [root_value, csr_value, sign_value] {
                    assert_eq!(value["use_pss"], enabled);
                    assert_eq!(value["signature_bits"], bits);
                    assert!(value.get("key_type").is_none());
                    assert!(value.get("private_key_format").is_none());
                }
            }
        }
    }

    #[test]
    fn csr_response_does_not_require_a_certificate_and_redacts_private_material() {
        let synthetic = ["fixture-", "private-value"].concat();
        let value = serde_json::json!({"csr":"public-csr-fixture","key_id":"existing-key","private_key":synthetic});
        let response: PkiAuthorityBundle =
            serde_json::from_value(value).unwrap_or_else(|_| panic!("CSR response failed"));
        assert_eq!(response.csr.as_deref(), Some("public-csr-fixture"));
        assert_eq!(response.key_id.as_deref(), Some("existing-key"));
        assert!(response.certificate.is_none());
        assert!(
            response
                .private_key
                .as_ref()
                .is_some_and(|key| key.expose_secret() == synthetic)
        );
        assert!(!format!("{response:?}").contains(&synthetic));
    }
}
