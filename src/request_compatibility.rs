//! Reviewed request-field availability across locked OpenBao releases.

use crate::{Error, Result, compatibility::OpenBaoVersion};

/// One public request field whose availability is version-dependent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VersionedRequestField {
    endpoint: &'static str,
    field: &'static str,
    minimum: OpenBaoVersion,
    maximum: Option<OpenBaoVersion>,
}

impl VersionedRequestField {
    pub(crate) const fn since(
        endpoint: &'static str,
        field: &'static str,
        minimum: OpenBaoVersion,
    ) -> Self {
        Self {
            endpoint,
            field,
            minimum,
            maximum: None,
        }
    }

    fn supports(self, version: OpenBaoVersion) -> bool {
        version >= self.minimum && self.maximum.is_none_or(|maximum| version <= maximum)
    }
}

pub(crate) fn validate_request_fields(
    version: OpenBaoVersion,
    selected: &[(&'static VersionedRequestField, bool)],
) -> Result<()> {
    for (rule, is_selected) in selected {
        if *is_selected && !rule.supports(version) {
            return Err(Error::UnsupportedOpenBaoRequestField {
                endpoint: rule.endpoint,
                field: rule.field,
                version,
            });
        }
    }
    Ok(())
}

const V2_0_2: OpenBaoVersion = OpenBaoVersion::new(2, 0, 2);
const V2_1_0: OpenBaoVersion = OpenBaoVersion::new(2, 1, 0);
const V2_2_0: OpenBaoVersion = OpenBaoVersion::new(2, 2, 0);
const V2_3_1: OpenBaoVersion = OpenBaoVersion::new(2, 3, 1);
const V2_4_0: OpenBaoVersion = OpenBaoVersion::new(2, 4, 0);
const V2_5_0: OpenBaoVersion = OpenBaoVersion::new(2, 5, 0);
const V2_5_2: OpenBaoVersion = OpenBaoVersion::new(2, 5, 2);

pub(crate) mod fields {
    use super::*;

    pub(crate) const JWT_CONFIG_SKIP_JWKS_VALIDATION: VersionedRequestField =
        VersionedRequestField::since("auth.jwt.config", "skip_jwks_validation", V2_3_1);
    pub(crate) const JWT_CONFIG_OVERRIDE_ALLOWED_SERVER_NAMES: VersionedRequestField =
        VersionedRequestField::since("auth.jwt.config", "override_allowed_server_names", V2_4_0);
    pub(crate) const JWT_ROLE_CALLBACK_MODE: VersionedRequestField =
        VersionedRequestField::since("auth.jwt.role", "callback_mode", V2_1_0);
    pub(crate) const JWT_ROLE_POLL_INTERVAL: VersionedRequestField =
        VersionedRequestField::since("auth.jwt.role", "poll_interval", V2_1_0);
    pub(crate) const JWT_ROLE_TOKEN_POLICY_TEMPLATES: VersionedRequestField =
        VersionedRequestField::since("auth.jwt.role", "token_policies_template_claims", V2_1_0);
    pub(crate) const JWT_ROLE_DISABLE_CONFIRMATION: VersionedRequestField =
        VersionedRequestField::since("auth.jwt.role", "oidc_disable_confirmation", V2_5_2);

    pub(crate) const IDENTITY_PROVIDER_TOKEN_SCOPE: VersionedRequestField =
        VersionedRequestField::since("identity.oidc.provider.token", "scope", V2_5_0);

    pub(crate) const SSH_ROLE_ALLOW_EMPTY_PRINCIPALS: VersionedRequestField =
        VersionedRequestField::since("ssh.role", "allow_empty_principals", V2_0_2);
    pub(crate) const SSH_ROLE_ISSUER_REF: VersionedRequestField =
        VersionedRequestField::since("ssh.role", "issuer_ref", V2_3_1);

    pub(crate) const POLICY_EXPIRATION: VersionedRequestField =
        VersionedRequestField::since("sys.policy.write", "expiration", V2_3_1);
    pub(crate) const POLICY_TTL: VersionedRequestField =
        VersionedRequestField::since("sys.policy.write", "ttl", V2_3_1);
    pub(crate) const POLICY_CAS: VersionedRequestField =
        VersionedRequestField::since("sys.policy.write", "cas", V2_3_1);
    pub(crate) const POLICY_CAS_REQUIRED: VersionedRequestField =
        VersionedRequestField::since("sys.policy.write", "cas_required", V2_3_1);
    pub(crate) const RAFT_JOIN_NON_VOTER: VersionedRequestField =
        VersionedRequestField::since("sys.storage.raft.join", "non_voter", V2_2_0);
    #[cfg(any(feature = "operator-ops", test))]
    pub(crate) const ROTATION_INTERVAL: VersionedRequestField =
        VersionedRequestField::since("sys.rotate.config", "interval", V2_4_0);
    pub(crate) const PLUGIN_OCI: VersionedRequestField =
        VersionedRequestField::since("sys.plugins.catalog.register", "oci", V2_5_0);

    pub(crate) const TRANSIT_DATA_KEY_ASSOCIATED_DATA: VersionedRequestField =
        VersionedRequestField::since("transit.datakey", "associated_data", V2_5_0);

    pub(crate) const PKI_AUTHORITY_NOT_BEFORE: VersionedRequestField =
        VersionedRequestField::since("pki.authority.generate", "not_before", V2_1_0);
    #[cfg(any(feature = "operator-ops", test))]
    pub(crate) const PKI_SIGN_VERBATIM_NOT_BEFORE: VersionedRequestField =
        VersionedRequestField::since("pki.sign_verbatim", "not_before", V2_1_0);
    pub(crate) const PKI_ROLE_NOT_BEFORE: VersionedRequestField =
        VersionedRequestField::since("pki.role", "not_before", V2_1_0);
    pub(crate) const PKI_ROLE_NOT_BEFORE_BOUND: VersionedRequestField =
        VersionedRequestField::since("pki.role", "not_before_bound", V2_3_1);
    pub(crate) const PKI_ROLE_NOT_AFTER_BOUND: VersionedRequestField =
        VersionedRequestField::since("pki.role", "not_after_bound", V2_3_1);
    pub(crate) const PKI_ROLE_ALLOWED_IP_SANS_CIDR: VersionedRequestField =
        VersionedRequestField::since("pki.role", "allowed_ip_sans_cidr", V2_5_0);
    pub(crate) const PKI_TIDY_INVALID_CERTS: VersionedRequestField =
        VersionedRequestField::since("pki.tidy", "tidy_invalid_certs", V2_1_0);
    pub(crate) const PKI_TIDY_PAGE_SIZE: VersionedRequestField =
        VersionedRequestField::since("pki.tidy", "page_size", V2_2_0);
    pub(crate) const PKI_AUTO_TIDY_INVALID_CERTS: VersionedRequestField =
        VersionedRequestField::since("pki.config.auto_tidy", "tidy_invalid_certs", V2_1_0);
    pub(crate) const PKI_AUTO_TIDY_REVOKED_SAFETY_BUFFER: VersionedRequestField =
        VersionedRequestField::since("pki.config.auto_tidy", "revoked_safety_buffer", V2_1_0);
    pub(crate) const PKI_AUTO_TIDY_PAGE_SIZE: VersionedRequestField =
        VersionedRequestField::since("pki.config.auto_tidy", "page_size", V2_2_0);

    #[cfg(test)]
    pub(crate) const ALL: &[VersionedRequestField] = &[
        JWT_CONFIG_SKIP_JWKS_VALIDATION,
        JWT_CONFIG_OVERRIDE_ALLOWED_SERVER_NAMES,
        JWT_ROLE_CALLBACK_MODE,
        JWT_ROLE_POLL_INTERVAL,
        JWT_ROLE_TOKEN_POLICY_TEMPLATES,
        JWT_ROLE_DISABLE_CONFIRMATION,
        IDENTITY_PROVIDER_TOKEN_SCOPE,
        SSH_ROLE_ALLOW_EMPTY_PRINCIPALS,
        SSH_ROLE_ISSUER_REF,
        POLICY_EXPIRATION,
        POLICY_TTL,
        POLICY_CAS,
        POLICY_CAS_REQUIRED,
        RAFT_JOIN_NON_VOTER,
        ROTATION_INTERVAL,
        PLUGIN_OCI,
        TRANSIT_DATA_KEY_ASSOCIATED_DATA,
        PKI_AUTHORITY_NOT_BEFORE,
        PKI_SIGN_VERBATIM_NOT_BEFORE,
        PKI_ROLE_NOT_BEFORE,
        PKI_ROLE_NOT_BEFORE_BOUND,
        PKI_ROLE_NOT_AFTER_BOUND,
        PKI_ROLE_ALLOWED_IP_SANS_CIDR,
        PKI_TIDY_INVALID_CERTS,
        PKI_TIDY_PAGE_SIZE,
        PKI_AUTO_TIDY_INVALID_CERTS,
        PKI_AUTO_TIDY_REVOKED_SAFETY_BUFFER,
        PKI_AUTO_TIDY_PAGE_SIZE,
    ];
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::{fields, validate_request_fields};
    use crate::{Error, compatibility::OpenBaoVersion};

    #[test]
    fn selected_fields_fail_outside_their_reviewed_range() {
        let error = match validate_request_fields(
            OpenBaoVersion::new(2, 4, 4),
            &[(&fields::TRANSIT_DATA_KEY_ASSOCIATED_DATA, true)],
        ) {
            Ok(()) => panic!("unsupported field unexpectedly accepted"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            Error::UnsupportedOpenBaoRequestField {
                endpoint: "transit.datakey",
                field: "associated_data",
                version
            } if version == OpenBaoVersion::new(2, 4, 4)
        ));
        assert!(
            validate_request_fields(
                OpenBaoVersion::new(2, 5, 0),
                &[(&fields::TRANSIT_DATA_KEY_ASSOCIATED_DATA, true)],
            )
            .is_ok()
        );
    }

    #[test]
    fn unset_fields_preserve_old_profile_compatibility() {
        assert!(
            validate_request_fields(
                OpenBaoVersion::new(2, 0, 0),
                &[
                    (&fields::POLICY_TTL, false),
                    (&fields::POLICY_CAS_REQUIRED, false),
                ],
            )
            .is_ok()
        );
    }

    #[test]
    fn reviewed_rules_are_unique_and_documented() {
        let documentation = include_str!("../docs/OPENBAO_REQUEST_FIELD_COMPATIBILITY.md");
        let profiles = crate::compatibility::openbao_profile_versions();
        let mut identities = std::collections::BTreeSet::new();
        for rule in fields::ALL {
            assert!(identities.insert((rule.endpoint, rule.field)));
            let documented_row = format!(
                "| `{}` | `{}` | `{}` |",
                rule.endpoint, rule.field, rule.minimum
            );
            assert!(documentation.contains(&documented_row));
            let minimum_index = profiles
                .iter()
                .position(|version| *version == rule.minimum)
                .unwrap_or_else(|| panic!("request-field minimum lacks a locked profile"));
            assert!(minimum_index > 0);
            assert!(
                validate_request_fields(rule.minimum, &[(rule, true)]).is_ok(),
                "minimum profile rejected {}.{}",
                rule.endpoint,
                rule.field
            );
            assert!(matches!(
                validate_request_fields(profiles[minimum_index - 1], &[(rule, true)]),
                Err(Error::UnsupportedOpenBaoRequestField { .. })
            ));
        }
        assert_eq!(identities.len(), 28);
    }
}
