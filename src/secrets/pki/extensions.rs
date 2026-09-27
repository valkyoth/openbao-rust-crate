//! Additive PKI algorithm selection; registered dispatch and profile gates remain mandatory.

use super::*;

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
