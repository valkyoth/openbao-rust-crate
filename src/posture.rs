//! Best-effort posture helpers for crate-visible OpenBao configuration.
//!
//! These helpers are advisory only. They do not certify OpenBao, the process,
//! the TLS stack, the cryptographic provider, HSM/KMS use, or the deployment.

use crate::secrets::transit::{
    TransitCreateKeyRequest, TransitHashAlgorithm, TransitKeyInfo, TransitKeyType,
    TransitSignatureAlgorithm,
};
use serde::{Deserialize, Serialize};

/// Best-effort FIPS-oriented posture builder.
#[derive(Clone, Debug, Default)]
pub struct FipsPosture {
    report: FipsPostureReport,
}

impl FipsPosture {
    /// Creates an empty posture report builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an item that the crate inspected.
    pub fn note_checked(
        &mut self,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) -> &mut Self {
        self.report.checked.push(FipsPostureNote {
            subject: subject.into(),
            detail: detail.into(),
        });
        self
    }

    /// Records a deployment property this crate cannot verify.
    pub fn note_unverified(
        &mut self,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) -> &mut Self {
        self.report.unverified.push(FipsPostureNote {
            subject: subject.into(),
            detail: detail.into(),
        });
        self
    }

    /// Records that the caller believes OpenBao is sealed by an HSM/KMS-backed
    /// mechanism. This is caller-supplied evidence and is not verified here.
    pub fn assume_hsm_or_kms_seal(&mut self, subject: impl Into<String>) -> &mut Self {
        self.note_checked(
            subject,
            "caller supplied an HSM/KMS-backed seal assumption; the SDK did not verify it",
        )
    }

    /// Records that the OpenBao seal mechanism is not verified as HSM/KMS
    /// backed.
    pub fn assume_unknown_or_non_hsm_seal(&mut self, subject: impl Into<String>) -> &mut Self {
        self.add_finding(
            FipsPostureSeverity::Warning,
            subject,
            "seal mechanism is not verified as HSM/KMS-backed by this SDK",
        )
    }

    /// Checks a Transit key creation request against a conservative
    /// FIPS-oriented allowlist.
    pub fn check_transit_create_key(
        &mut self,
        subject: impl Into<String>,
        request: &TransitCreateKeyRequest,
    ) -> &mut Self {
        let subject = subject.into();
        let key_type = request.key_type.unwrap_or(TransitKeyType::Aes256Gcm96);
        self.check_transit_key_type(subject.clone(), key_type);
        if request.convergent_encryption == Some(true) {
            self.add_finding(
                FipsPostureSeverity::Warning,
                format!("{subject}.convergent_encryption"),
                "convergent encryption is enabled; review deterministic encryption requirements",
            );
        }
        if request.exportable == Some(true) {
            self.add_finding(
                FipsPostureSeverity::Warning,
                format!("{subject}.exportable"),
                "Transit key material is exportable",
            );
        }
        if request.allow_plaintext_backup == Some(true) {
            self.add_finding(
                FipsPostureSeverity::Warning,
                format!("{subject}.allow_plaintext_backup"),
                "Transit plaintext backup is enabled",
            );
        }
        self
    }

    /// Checks Transit key metadata returned by OpenBao.
    pub fn check_transit_key_info(
        &mut self,
        subject: impl Into<String>,
        info: &TransitKeyInfo,
    ) -> &mut Self {
        let subject = subject.into();
        self.check_transit_key_type_name(subject.clone(), &info.key_type);
        if info.exportable {
            self.add_finding(
                FipsPostureSeverity::Warning,
                format!("{subject}.exportable"),
                "Transit key metadata reports exportable key material",
            );
        }
        if info.allow_plaintext_backup {
            self.add_finding(
                FipsPostureSeverity::Warning,
                format!("{subject}.allow_plaintext_backup"),
                "Transit key metadata reports plaintext backup is enabled",
            );
        }
        if info.imported {
            self.note_unverified(
                format!("{subject}.imported"),
                "imported Transit key provenance is outside what this SDK can verify",
            );
        }
        self
    }

    /// Checks a Transit hash/HMAC/signing hash algorithm choice.
    pub fn check_transit_hash_algorithm(
        &mut self,
        subject: impl Into<String>,
        algorithm: TransitHashAlgorithm,
    ) -> &mut Self {
        let subject = subject.into();
        match algorithm {
            #[cfg(feature = "allow-sha1-acknowledged")]
            #[allow(deprecated)]
            TransitHashAlgorithm::Sha1 => self.add_finding(
                FipsPostureSeverity::Reject,
                subject,
                "SHA-1 is not accepted by this FIPS-oriented helper",
            ),
            TransitHashAlgorithm::Sha2_256
            | TransitHashAlgorithm::Sha2_384
            | TransitHashAlgorithm::Sha2_512 => {
                self.note_checked(subject, "SHA-2 algorithm is in the conservative allowlist")
            }
            TransitHashAlgorithm::Sha2_224 => self.add_finding(
                FipsPostureSeverity::Warning,
                subject,
                "SHA2-224 is FIPS-defined but outside this helper's conservative allowlist",
            ),
            TransitHashAlgorithm::Sha3_224
            | TransitHashAlgorithm::Sha3_256
            | TransitHashAlgorithm::Sha3_384
            | TransitHashAlgorithm::Sha3_512 => self.add_finding(
                FipsPostureSeverity::Warning,
                subject,
                "SHA-3 requires provider/deployment validation outside this SDK",
            ),
            TransitHashAlgorithm::None => self.add_finding(
                FipsPostureSeverity::Warning,
                subject,
                "unhashed signing mode requires caller-side hash and protocol review",
            ),
        }
    }

    /// Checks a Transit RSA signature algorithm choice.
    pub fn check_transit_signature_algorithm(
        &mut self,
        subject: impl Into<String>,
        algorithm: TransitSignatureAlgorithm,
    ) -> &mut Self {
        match algorithm {
            TransitSignatureAlgorithm::Pss => {
                self.note_checked(subject, "RSA-PSS is in the conservative allowlist")
            }
            TransitSignatureAlgorithm::Pkcs1v15 => self.add_finding(
                FipsPostureSeverity::Warning,
                subject,
                "RSASSA-PKCS1-v1_5 is legacy; prefer RSA-PSS where possible",
            ),
        }
    }

    /// Consumes the builder and returns the report.
    #[must_use]
    pub fn finish(self) -> FipsPostureReport {
        self.report
    }

    fn check_transit_key_type(&mut self, subject: String, key_type: TransitKeyType) {
        match key_type {
            TransitKeyType::Aes128Gcm96
            | TransitKeyType::Aes256Gcm96
            | TransitKeyType::EcdsaP256
            | TransitKeyType::EcdsaP384
            | TransitKeyType::Rsa3072
            | TransitKeyType::Rsa4096
            | TransitKeyType::Hmac => {
                self.note_checked(subject, "Transit key type is in the conservative allowlist");
            }
            TransitKeyType::Rsa2048 => {
                self.add_finding(
                    FipsPostureSeverity::Warning,
                    subject,
                    "RSA-2048 is accepted by some profiles but below this helper's conservative RSA size",
                );
            }
            TransitKeyType::EcdsaP521 => {
                self.add_finding(
                    FipsPostureSeverity::Warning,
                    subject,
                    "ECDSA P-521 requires deployment-specific validation outside this SDK",
                );
            }
            TransitKeyType::ChaCha20Poly1305 | TransitKeyType::XChaCha20Poly1305 => {
                self.add_finding(
                    FipsPostureSeverity::Warning,
                    subject,
                    "ChaCha20/XChaCha20 is outside this helper's conservative FIPS-oriented allowlist",
                );
            }
            TransitKeyType::Ed25519 => {
                self.add_finding(
                    FipsPostureSeverity::Warning,
                    subject,
                    "Ed25519 is outside this helper's conservative FIPS-oriented allowlist",
                );
            }
        }
    }

    fn check_transit_key_type_name(&mut self, subject: String, key_type: &str) {
        match key_type {
            "aes128-gcm96" => self.check_transit_key_type(subject, TransitKeyType::Aes128Gcm96),
            "aes256-gcm96" => self.check_transit_key_type(subject, TransitKeyType::Aes256Gcm96),
            "chacha20-poly1305" => {
                self.check_transit_key_type(subject, TransitKeyType::ChaCha20Poly1305);
            }
            "xchacha20-poly1305" => {
                self.check_transit_key_type(subject, TransitKeyType::XChaCha20Poly1305);
            }
            "ed25519" => self.check_transit_key_type(subject, TransitKeyType::Ed25519),
            "ecdsa-p256" => self.check_transit_key_type(subject, TransitKeyType::EcdsaP256),
            "ecdsa-p384" => self.check_transit_key_type(subject, TransitKeyType::EcdsaP384),
            "ecdsa-p521" => self.check_transit_key_type(subject, TransitKeyType::EcdsaP521),
            "rsa-2048" => self.check_transit_key_type(subject, TransitKeyType::Rsa2048),
            "rsa-3072" => self.check_transit_key_type(subject, TransitKeyType::Rsa3072),
            "rsa-4096" => self.check_transit_key_type(subject, TransitKeyType::Rsa4096),
            "hmac" => self.check_transit_key_type(subject, TransitKeyType::Hmac),
            other => {
                self.add_finding(
                    FipsPostureSeverity::Warning,
                    subject,
                    format!("Transit key type `{other}` is unknown to this SDK version"),
                );
            }
        }
    }

    fn add_finding(
        &mut self,
        severity: FipsPostureSeverity,
        subject: impl Into<String>,
        message: impl Into<String>,
    ) -> &mut Self {
        self.report.findings.push(FipsPostureFinding {
            severity,
            subject: subject.into(),
            message: message.into(),
        });
        self
    }
}

/// Machine-readable best-effort posture report.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct FipsPostureReport {
    /// Items the SDK inspected.
    pub checked: Vec<FipsPostureNote>,
    /// Findings for crate-visible choices that need review.
    pub findings: Vec<FipsPostureFinding>,
    /// Items the SDK could not verify.
    pub unverified: Vec<FipsPostureNote>,
}

impl FipsPostureReport {
    /// Returns true when the report contains a rejecting finding.
    #[must_use]
    pub fn has_rejects(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == FipsPostureSeverity::Reject)
    }

    /// Returns true when the report contains warning or rejecting findings.
    #[must_use]
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }
}

/// One checked or unverifiable posture report item.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FipsPostureNote {
    /// Report subject.
    pub subject: String,
    /// Human-readable detail.
    pub detail: String,
}

/// One best-effort posture finding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FipsPostureFinding {
    /// Finding severity.
    pub severity: FipsPostureSeverity,
    /// Report subject.
    pub subject: String,
    /// Human-readable finding message.
    pub message: String,
}

/// FIPS posture finding severity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FipsPostureSeverity {
    /// Needs review for a conservative profile.
    Warning,
    /// Rejected by this helper's conservative profile.
    Reject,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::{FipsPosture, FipsPostureSeverity};
    use crate::secrets::transit::{TransitCreateKeyRequest, TransitHashAlgorithm, TransitKeyType};

    #[test]
    fn transit_create_key_posture_flags_risky_options() {
        let mut posture = FipsPosture::new();
        posture.check_transit_create_key(
            "transit/app",
            &TransitCreateKeyRequest {
                key_type: Some(TransitKeyType::ChaCha20Poly1305),
                convergent_encryption: Some(true),
                exportable: Some(true),
                allow_plaintext_backup: Some(true),
                ..Default::default()
            },
        );
        let report = posture.finish();

        assert_eq!(report.findings.len(), 4);
        assert!(report.findings.iter().any(|finding| {
            finding.subject == "transit/app.exportable"
                && finding.severity == FipsPostureSeverity::Warning
        }));
    }

    #[test]
    fn transit_hash_posture_accepts_sha2_and_warns_sha3() {
        let mut posture = FipsPosture::new();
        posture.check_transit_hash_algorithm("hash/ok", TransitHashAlgorithm::Sha2_256);
        posture.check_transit_hash_algorithm("hash/review", TransitHashAlgorithm::Sha3_256);
        let report = posture.finish();

        assert_eq!(report.checked.len(), 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].subject, "hash/review");
    }

    #[test]
    fn seal_assumptions_are_reported_without_verification_claims() {
        let mut posture = FipsPosture::new();
        posture.assume_hsm_or_kms_seal("seal").note_unverified(
            "provider",
            "cryptographic module validation is deployment-owned",
        );
        let report = posture.finish();

        assert_eq!(report.checked.len(), 1);
        assert_eq!(report.unverified.len(), 1);
        assert!(!report.has_findings());
    }
}
