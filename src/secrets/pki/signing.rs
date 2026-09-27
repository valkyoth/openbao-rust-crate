//! Additive signing controls. Role policy remains authoritative for ordinary issue/sign.

use super::*;

/// Signature preferences for RSA signers. Other signer algorithms use their own
/// signature scheme; these fields do not turn a non-RSA signer into RSA.
/// Omission preserves server defaults, or existing values during a role PATCH.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct PkiSignatureOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    use_pss: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_bits: Option<u64>,
}

impl PkiSignatureOptions {
    /// Explicitly enables RSA-PSS or selects PKCS#1 v1.5 for RSA signers.
    /// This does not change the public-key algorithm of the certificate subject.
    #[must_use]
    pub fn with_pss(mut self, enabled: bool) -> Self {
        self.use_pss = Some(enabled);
        self
    }

    /// Selects SHA-256, SHA-384, SHA-512, or zero for the server's default.
    /// These are signature digest sizes, not RSA key sizes.
    pub fn with_signature_bits(mut self, bits: u64) -> Result<Self> {
        if !matches!(bits, 0 | 256 | 384 | 512) {
            return Err(Error::InvalidParameter(
                "PKI signature_bits must be 0, 256, 384 or 512".into(),
            ));
        }
        self.signature_bits = Some(bits);
        Ok(self)
    }
}

/// Additive role signing settings, preserving existing [`PkiRole`] literals.
/// Identity-template glob overrides cannot be enabled without the separate
/// acknowledgement feature and token.
///
/// Untrusted configuration cannot deserialize the acknowledgement-only override:
/// ```compile_fail
/// use openbao::secrets::pki::PkiRoleSigningOptions;
/// let _: PkiRoleSigningOptions = serde_json::from_str("{}").unwrap();
/// ```
/// Its fields also cannot be set through public struct literals:
/// ```compile_fail
/// use openbao::secrets::pki::PkiRoleSigningOptions;
/// let options = PkiRoleSigningOptions {
///     allow_globs_in_identity_templates: Some(true),
///     ..Default::default()
/// };
/// ```
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct PkiRoleSigningOptions {
    #[serde(flatten)]
    signature: PkiSignatureOptions,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_globs_in_identity_templates: Option<bool>,
}

// Deliberately no Deserialize: untrusted configuration must not construct the
// acknowledgement-only override through a generic deserialization path.

impl PkiRoleSigningOptions {
    /// Creates role options with the supplied signature preferences.
    pub fn new(signature: PkiSignatureOptions) -> Self {
        Self {
            signature,
            allow_globs_in_identity_templates: None,
        }
    }

    /// Allows globs rendered from trusted identity metadata. This has the same
    /// trust requirements as [`Pki::write_role_with_identity_template_globs`].
    #[cfg(feature = "identity-template-overrides-acknowledged")]
    #[must_use]
    pub fn with_identity_template_globs(mut self, _ack: PkiIdentityTemplateGlobOverride) -> Self {
        self.allow_globs_in_identity_templates = Some(true);
        self
    }
}

/// Additive role readback including signer preferences, where returned by the server.
#[derive(Clone, Debug, Default, Deserialize)]
#[non_exhaustive]
pub struct PkiRoleSigningDetails {
    /// Existing role and identity-template metadata.
    #[serde(flatten)]
    pub details: PkiRoleDetails,
    /// Whether the role requests RSA-PSS signatures.
    #[serde(default)]
    pub use_pss: Option<bool>,
    /// RSA signature digest size, with zero meaning the server default.
    #[serde(default)]
    pub signature_bits: Option<u64>,
}

/// Validated subject-key selection for issuance, not the issuer's signing key.
/// Ordinary roles must permit `key_type = "any"` to honor these fields. OpenBao
/// otherwise ignores them; this type cannot override role policy. CEL roles may
/// reject or transform the selection. Inspect the issued certificate as needed.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct PkiIssuanceKey {
    key_type: &'static str,
    key_bits: u64,
}

impl PkiIssuanceKey {
    /// Selects RSA, accepting 2048, 3072, 4096 or 8192 bits, or zero for default.
    pub fn rsa(bits: u64) -> Result<Self> {
        if !matches!(bits, 0 | 2048 | 3072 | 4096 | 8192) {
            return Err(Error::InvalidParameter("invalid PKI RSA key size".into()));
        }
        Ok(Self {
            key_type: "rsa",
            key_bits: bits,
        })
    }

    /// Selects a NIST curve: 224, 256, 384 or 521 bits, or zero for default.
    pub fn ec(bits: u64) -> Result<Self> {
        if !matches!(bits, 0 | 224 | 256 | 384 | 521) {
            return Err(Error::InvalidParameter("invalid PKI EC key size".into()));
        }
        Ok(Self {
            key_type: "ec",
            key_bits: bits,
        })
    }

    /// Selects Ed25519. Its key size is intrinsic to the algorithm.
    pub const fn ed25519() -> Self {
        Self {
            key_type: "ed25519",
            key_bits: 0,
        }
    }

    /// Selects an explicit ML-DSA parameter set. This does not imply transport
    /// TLS or OCSP support for ML-DSA certificates.
    pub const fn mldsa(parameters: PkiMldsaParameterSet) -> Self {
        Self {
            key_type: "mldsa",
            key_bits: parameters.key_bits(),
        }
    }
}

#[derive(Serialize)]
struct RolePayload<'a> {
    #[serde(flatten)]
    role: &'a PkiRole,
    #[serde(flatten)]
    options: &'a PkiRoleSigningOptions,
}

#[derive(Serialize)]
struct IssuePayload<'a> {
    #[serde(flatten)]
    request: &'a PkiIssueRequest,
    #[serde(flatten)]
    key: &'a PkiIssuanceKey,
}

#[derive(Serialize)]
struct CelPayload<'a, T> {
    #[serde(flatten)]
    request: &'a T,
    #[serde(flatten)]
    signature: &'a PkiSignatureOptions,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    key: Option<&'a PkiIssuanceKey>,
}

impl Pki<'_> {
    // Only the reviewed 2.7 contract is enabled for these additive options.
    // Existing methods retain their historical behavior and profile coverage.
    pub(super) async fn require_signing_options_profile(&self) -> Result<()> {
        const OPTIONS: crate::request_compatibility::VersionedRequestField =
            crate::request_compatibility::VersionedRequestField::since(
                "pki.signing",
                "signing_options",
                crate::OpenBaoVersion::new(2, 7, 0),
            );
        self.client
            .validate_versioned_request_fields(&[(&OPTIONS, true)])
            .await
    }

    async fn validate_role_signing_options(
        &self,
        role: &PkiRole,
        _options: &PkiRoleSigningOptions,
    ) -> Result<()> {
        self.require_signing_options_profile().await?;
        self.validate_role_request_fields(role).await?;
        #[cfg(feature = "identity-template-overrides-acknowledged")]
        self.client
            .validate_versioned_request_fields(&[(
                &crate::request_compatibility::fields::PKI_ROLE_ALLOW_TEMPLATE_GLOBS,
                _options.allow_globs_in_identity_templates.is_some(),
            )])
            .await?;
        Ok(())
    }

    /// Creates/replaces a role with signature preferences (reviewed 2.7+ contract).
    /// Ordinary issue/sign operations inherit these preferences from the role.
    /// Older/unpromoted profiles fail closed even for default options.
    pub async fn write_role_with_signing_options(
        &self,
        name: &str,
        role: &PkiRole,
        options: &PkiRoleSigningOptions,
    ) -> Result<Empty> {
        let path = self.path(&["roles", name])?;
        self.validate_role_signing_options(role, options).await?;
        self.request(Method::POST, &path, Some(&RolePayload { role, options }))
            .await
    }

    /// Patches a role using JSON Merge Patch and signature preferences (2.7+).
    /// Omitted signature fields leave existing values unchanged; explicit false
    /// disables RSA-PSS. Identity-template overrides remain separately gated.
    pub async fn patch_role_with_signing_options(
        &self,
        name: &str,
        role: &PkiRole,
        options: &PkiRoleSigningOptions,
    ) -> Result<PkiRoleSigningDetails> {
        let path = self.path(&["roles", name])?;
        self.validate_role_signing_options(role, options).await?;
        self.enveloped_with_headers(
            Method::PATCH,
            &path,
            &[(
                CONTENT_TYPE,
                HeaderValue::from_static("application/merge-patch+json"),
            )],
            Some(&RolePayload { role, options }),
        )
        .await
    }

    /// Reads role metadata including signature preferences when present.
    /// Works on existing profiles; missing fields remain `None`, not invented defaults.
    pub async fn read_role_signing_details(&self, name: &str) -> Result<PkiRoleSigningDetails> {
        self.enveloped(
            Method::GET,
            &self.path(&["roles", name])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Issues a certificate with an explicit subject key (reviewed 2.7+ contract).
    /// The role must permit `key_type = "any"`; otherwise OpenBao ignores this
    /// selection. Signature settings come from the role, not this request.
    pub async fn issue_with_key(
        &self,
        role: &str,
        request: &PkiIssueRequest,
        key: &PkiIssuanceKey,
    ) -> Result<PkiCertificateBundle> {
        validate_private_key_output_format(request.format.as_deref(), true)?;
        let path = self.path(&["issue", role])?;
        self.require_signing_options_profile().await?;
        self.enveloped(Method::POST, &path, Some(&IssuePayload { request, key }))
            .await
    }

    /// Issues with an explicit issuer and subject key (reviewed 2.7+ contract).
    /// Has the same role-policy restrictions as [`Self::issue_with_key`].
    pub async fn issue_with_issuer_and_key(
        &self,
        issuer_ref: &str,
        role: &str,
        request: &PkiIssueRequest,
        key: &PkiIssuanceKey,
    ) -> Result<PkiCertificateBundle> {
        validate_private_key_output_format(request.format.as_deref(), true)?;
        let path = self.path(&["issuer", issuer_ref, "issue", role])?;
        self.require_signing_options_profile().await?;
        self.enveloped(Method::POST, &path, Some(&IssuePayload { request, key }))
            .await
    }

    /// Issues through CEL with key/signature inputs (reviewed 2.7+ contract).
    /// CEL policy may reject or transform these inputs. `None` omits key selection;
    /// it does not select an algorithm independently of the policy.
    pub async fn cel_issue_with_options(
        &self,
        role: &str,
        request: &PkiIssueRequest,
        key: Option<&PkiIssuanceKey>,
        signature: &PkiSignatureOptions,
    ) -> Result<PkiCertificateBundle> {
        let path = self.path(&["cel", "issue", role])?;
        self.require_signing_options_profile().await?;
        self.enveloped(
            Method::POST,
            &path,
            Some(&CelPayload {
                request,
                key,
                signature,
            }),
        )
        .await
    }

    /// Signs a CSR through CEL with signature inputs (reviewed 2.7+ contract).
    /// The CSR supplies its subject key; CEL policy controls final signature settings.
    pub async fn cel_sign_with_signature_options(
        &self,
        role: &str,
        request: &PkiSignRequest,
        signature: &PkiSignatureOptions,
    ) -> Result<PkiCertificateBundle> {
        let path = self.path(&["cel", "sign", role])?;
        self.require_signing_options_profile().await?;
        self.enveloped(
            Method::POST,
            &path,
            Some(&CelPayload {
                request,
                key: None,
                signature,
            }),
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
    fn signature_options_preserve_omission_false_and_zero() {
        assert_eq!(wire(&PkiSignatureOptions::default()), serde_json::json!({}));
        for pss in [false, true] {
            for bits in [0, 256, 384, 512] {
                let options = PkiSignatureOptions::default()
                    .with_pss(pss)
                    .with_signature_bits(bits)
                    .unwrap_or_else(|_| panic!("valid digest rejected"));
                assert_eq!(
                    wire(&options),
                    serde_json::json!({"use_pss":pss,"signature_bits":bits})
                );
            }
        }
        for bits in [1, 160, 224, 255, 257, 2048, u64::MAX] {
            assert!(
                PkiSignatureOptions::default()
                    .with_signature_bits(bits)
                    .is_err()
            );
        }
        assert_eq!(
            wire(&PkiSignatureOptions::default().with_pss(false)),
            serde_json::json!({"use_pss":false})
        );
        assert_eq!(
            wire(
                &PkiSignatureOptions::default()
                    .with_signature_bits(0)
                    .unwrap_or_else(|_| panic!("zero rejected"))
            ),
            serde_json::json!({"signature_bits":0})
        );
    }

    #[test]
    fn role_options_preserve_patch_semantics_and_gate_template_override() {
        let role = PkiRole {
            ttl: Some("1h".into()),
            ..Default::default()
        };
        let omitted = PkiRoleSigningOptions::default();
        let value = wire(&RolePayload {
            role: &role,
            options: &omitted,
        });
        assert_eq!(value["ttl"], "1h");
        for key in [
            "use_pss",
            "signature_bits",
            "allow_globs_in_identity_templates",
        ] {
            assert!(value.get(key).is_none());
        }
        let options = PkiRoleSigningOptions::new(PkiSignatureOptions::default().with_pss(false));
        let value = wire(&RolePayload {
            role: &role,
            options: &options,
        });
        assert_eq!(value["use_pss"], false);
        assert!(value.get("signature_bits").is_none());
        assert!(value.get("allow_globs_in_identity_templates").is_none());
        #[cfg(feature = "identity-template-overrides-acknowledged")]
        {
            let options = options
                .with_identity_template_globs(PkiIdentityTemplateGlobOverride::acknowledge());
            let value = wire(&RolePayload {
                role: &role,
                options: &options,
            });
            assert_eq!(value["allow_globs_in_identity_templates"], true);
            assert_eq!(value["use_pss"], false);
        }
    }

    #[test]
    fn issuance_keys_and_payloads_match_algorithm_contracts() {
        let mut keys = Vec::new();
        for bits in [0, 2048, 3072, 4096, 8192] {
            keys.push((
                PkiIssuanceKey::rsa(bits).unwrap_or_else(|_| panic!("RSA rejected")),
                "rsa",
                bits,
            ));
        }
        for bits in [0, 224, 256, 384, 521] {
            keys.push((
                PkiIssuanceKey::ec(bits).unwrap_or_else(|_| panic!("EC rejected")),
                "ec",
                bits,
            ));
        }
        keys.push((PkiIssuanceKey::ed25519(), "ed25519", 0));
        for parameters in [
            PkiMldsaParameterSet::MlDsa44,
            PkiMldsaParameterSet::MlDsa65,
            PkiMldsaParameterSet::MlDsa87,
        ] {
            keys.push((
                PkiIssuanceKey::mldsa(parameters),
                "mldsa",
                parameters.key_bits(),
            ));
        }
        let request = PkiIssueRequest::new("example.test");
        let signature = PkiSignatureOptions::default().with_pss(true);
        for (key, kind, bits) in keys {
            let value = wire(&IssuePayload {
                request: &request,
                key: &key,
            });
            assert_eq!(value["common_name"], "example.test");
            assert_eq!(value["key_type"], kind);
            assert_eq!(value["key_bits"], bits);
            assert!(value.get("use_pss").is_none());
            let cel = wire(&CelPayload {
                request: &request,
                key: Some(&key),
                signature: &signature,
            });
            assert_eq!(cel["use_pss"], true);
            assert_eq!(cel["key_type"], kind);
            assert_eq!(cel["key_bits"], bits);
        }
        for bits in [1, 1024, 2047, 4095, 8193, u64::MAX] {
            assert!(PkiIssuanceKey::rsa(bits).is_err());
        }
        for bits in [1, 223, 255, 3840, 512, 522, u64::MAX] {
            assert!(PkiIssuanceKey::ec(bits).is_err());
        }
        let cel = wire(&CelPayload {
            request: &request,
            key: None,
            signature: &PkiSignatureOptions::default(),
        });
        assert_eq!(cel, wire(&request));
        let sign = PkiSignRequest {
            csr: "public-csr-fixture".into(),
            ..Default::default()
        };
        let cel = wire(&CelPayload {
            request: &sign,
            key: None,
            signature: &signature,
        });
        assert_eq!(cel["csr"], "public-csr-fixture");
        assert_eq!(cel["use_pss"], true);
        assert!(cel.get("key_type").is_none());
    }

    #[test]
    fn role_signing_readback_keeps_existing_metadata_and_rejects_duplicates() {
        let details: PkiRoleSigningDetails = serde_json::from_str(r#"{"key_type":"mldsa","key_bits":44,"use_pss":false,"signature_bits":0,"allow_globs_in_identity_templates":true}"#)
            .unwrap_or_else(|_| panic!("readback failed"));
        assert_eq!(details.details.role.key_type.as_deref(), Some("mldsa"));
        assert_eq!(details.details.role.key_bits, Some(44));
        assert!(details.details.allow_globs_in_identity_templates);
        assert_eq!(details.use_pss, Some(false));
        assert_eq!(details.signature_bits, Some(0));
        for input in ["{}", r#"{"use_pss":null,"signature_bits":null}"#] {
            let details: PkiRoleSigningDetails =
                serde_json::from_str(input).unwrap_or_else(|_| panic!("optional fields rejected"));
            assert!(details.use_pss.is_none());
            assert!(details.signature_bits.is_none());
        }
        for input in [
            r#"{"use_pss":true,"use_pss":false}"#,
            r#"{"signature_bits":256,"signature_bits":384}"#,
            r#"{"signature_bits":-1}"#,
        ] {
            assert!(serde_json::from_str::<PkiRoleSigningDetails>(input).is_err());
        }
    }
}
