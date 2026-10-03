//! Exact external-plugin identities, separate from server compatibility.

use core::fmt;

use crate::{
    Error, OpenBaoCompatibilityReport, OpenBaoCompatibilityStatus, OpenBaoOperation,
    OpenBaoVersion, Result, path::validate_mount_path,
};

/// An official external plugin whose release artifact has been reviewed.
///
/// Artifact identity is not a verified SDK contract or proof of installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExternalPluginKind {
    /// LDAP authentication.
    LdapAuth,
    /// Kerberos authentication.
    KerberosAuth,
    /// RADIUS authentication; its existing protocol acknowledgement still applies.
    RadiusAuth,
    /// LDAP generated credentials.
    LdapSecrets,
}

impl ExternalPluginKind {
    /// Official plugin catalog command name.
    pub const fn command(self) -> &'static str {
        match self {
            Self::LdapAuth => "openbao-plugin-auth-ldap",
            Self::KerberosAuth => "openbao-plugin-auth-kerberos",
            Self::RadiusAuth => "openbao-plugin-auth-radius",
            Self::LdapSecrets => "openbao-plugin-secrets-ldap",
        }
    }

    /// Reviewed Linux amd64 v1 binary digest (not the compressed archive digest).
    pub const fn binary_sha256(self) -> &'static str {
        match self {
            Self::LdapAuth => super::artifacts::AUTH_LDAP,
            Self::KerberosAuth => super::artifacts::AUTH_KERBEROS,
            Self::RadiusAuth => super::artifacts::AUTH_RADIUS,
            Self::LdapSecrets => super::artifacts::SECRETS_LDAP,
        }
    }

    pub(crate) const fn is_auth(self) -> bool {
        !matches!(self, Self::LdapSecrets)
    }

    pub(crate) const fn documented_mount(self) -> &'static str {
        match self {
            Self::LdapAuth | Self::LdapSecrets => "ldap",
            Self::KerberosAuth => "kerberos",
            Self::RadiusAuth => "radius",
        }
    }

    pub(crate) fn for_path(path: &str) -> Option<Self> {
        [
            ("/auth/ldap", Self::LdapAuth),
            ("/auth/kerberos", Self::KerberosAuth),
            ("/auth/radius", Self::RadiusAuth),
            ("/ldap", Self::LdapSecrets),
        ]
        .into_iter()
        .find_map(|(prefix, kind)| {
            (path == prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|tail| tail.starts_with('/')))
            .then_some(kind)
        })
    }
}

/// Expected plugin artifact and mount in one client namespace.
///
/// This is a deployment assertion, not an installation probe. Construction
/// validates the reviewed artifact identity; it does not enable a route. Until
/// an exact plugin/server contract is promoted, all corresponding operations
/// remain blocked. Never infer installed identity from a server version alone.
#[derive(Clone)]
pub struct ExternalPluginSelection {
    kind: ExternalPluginKind,
    server: OpenBaoVersion,
    mount: String,
}

impl ExternalPluginSelection {
    /// Selects an exact reviewed artifact for a mount, without promoting support.
    ///
    /// Only `v0.1.0` Linux amd64 v1 artifacts and the exact 2.7.0/2.7.1 server
    /// targets are accepted. `mount` excludes the `auth/` prefix for auth engines.
    /// Floating versions, archive digests and alternate binaries are rejected.
    pub fn new(
        kind: ExternalPluginKind,
        server: OpenBaoVersion,
        mount: &str,
        plugin_version: &str,
        binary_sha256: &str,
    ) -> Result<Self> {
        if ![OpenBaoVersion::new(2, 7, 0), OpenBaoVersion::new(2, 7, 1)].contains(&server)
            || plugin_version != "v0.1.0"
            || binary_sha256 != kind.binary_sha256()
        {
            return Err(Error::InvalidParameter(
                "external plugin identity has no reviewed artifact".into(),
            ));
        }
        let segments = validate_mount_path(mount)?;
        // Require a canonical assertion, rather than normalizing ambiguous input.
        let normalized = segments.join("/");
        if normalized != mount {
            return Err(Error::InvalidParameter(
                "external plugin mount must be canonical".into(),
            ));
        }
        Ok(Self {
            kind,
            server,
            mount: normalized,
        })
    }

    /// Selected engine identity.
    pub const fn kind(&self) -> ExternalPluginKind {
        self.kind
    }

    /// Exact server target, independent of the plugin version.
    pub const fn server_version(&self) -> OpenBaoVersion {
        self.server
    }

    /// Exact reviewed plugin artifact version.
    pub const fn plugin_version(&self) -> &'static str {
        "v0.1.0"
    }

    pub(crate) fn same_mount(&self, other: &Self) -> bool {
        self.kind.is_auth() == other.kind.is_auth() && self.mount == other.mount
    }

    pub(crate) fn matches_mount_scope(&self, kind: ExternalPluginKind, mount: &str) -> bool {
        self.kind.is_auth() == kind.is_auth() && self.mount == mount
    }

    pub(crate) fn supports(
        &self,
        report: OpenBaoCompatibilityReport,
        operation: OpenBaoOperation,
    ) -> bool {
        report.status() == OpenBaoCompatibilityStatus::Verified
            && report.detected_version() == Some(self.server)
            && report.profile_version() == Some(self.server)
            && ExternalPluginKind::for_path(operation.path_template()) == Some(self.kind)
            && reviewed_operations(self.kind, self.server).contains(&operation.id())
    }
}

// Empty until positive/negative public-SDK evidence promotes each exact pair.
// Never substitute the old built-in registry or a whole route-family wildcard.
fn reviewed_operations(
    _kind: ExternalPluginKind,
    _server: OpenBaoVersion,
) -> &'static [&'static str] {
    &[]
}

impl fmt::Debug for ExternalPluginSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalPluginSelection")
            .field("kind", &self.kind)
            .field("server", &self.server)
            .field("mount", &"<redacted>")
            .field("plugin_version", &self.plugin_version())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::*;
    use crate::OpenBaoCompatibilityPolicy;

    const KINDS: [ExternalPluginKind; 4] = [
        ExternalPluginKind::LdapAuth,
        ExternalPluginKind::KerberosAuth,
        ExternalPluginKind::RadiusAuth,
        ExternalPluginKind::LdapSecrets,
    ];

    fn selection(kind: ExternalPluginKind, server: OpenBaoVersion) -> ExternalPluginSelection {
        ExternalPluginSelection::new(
            kind,
            server,
            "sensitive/mount",
            "v0.1.0",
            kind.binary_sha256(),
        )
        .unwrap_or_else(|_| panic!("selection failed"))
    }

    #[test]
    fn exact_artifacts_and_server_targets_only() {
        for kind in KINDS {
            for server in [OpenBaoVersion::new(2, 7, 0), OpenBaoVersion::new(2, 7, 1)] {
                let selected = selection(kind, server);
                assert_eq!(selected.kind(), kind);
                assert_eq!(selected.server_version(), server);
                assert_eq!(selected.plugin_version(), "v0.1.0");
                assert!(!format!("{selected:?}").contains("sensitive/mount"));
                for version in ["latest", "0.1.0", "v0.1.1", "v0.1.0+metadata", "v0.1.0-rc1"] {
                    assert!(
                        ExternalPluginSelection::new(
                            kind,
                            server,
                            "mount",
                            version,
                            kind.binary_sha256()
                        )
                        .is_err()
                    );
                }
                for digest in ["", "wrong", &"0".repeat(64)] {
                    let error =
                        ExternalPluginSelection::new(kind, server, "mount", "v0.1.0", digest)
                            .err()
                            .unwrap_or_else(|| panic!("accepted invalid digest"));
                    assert!(!format!("{error:?}").contains("wrong"));
                }
            }
            for server in [
                OpenBaoVersion::new(2, 6, 4),
                OpenBaoVersion::new(2, 7, 2),
                OpenBaoVersion::new(2, 8, 0),
            ] {
                assert!(
                    ExternalPluginSelection::new(
                        kind,
                        server,
                        "mount",
                        "v0.1.0",
                        kind.binary_sha256()
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn configuration_limits_duplicates_and_redaction() {
        let server = OpenBaoVersion::new(2, 7, 0);
        let kind = ExternalPluginKind::LdapAuth;
        let config = crate::OpenBaoConfig::new("https://bao.example.invalid")
            .unwrap_or_else(|_| panic!("config failed"))
            .external_plugin(selection(kind, server))
            .unwrap_or_else(|_| panic!("selection failed"));
        assert!(!format!("{config:?}").contains("sensitive/mount"));
        assert!(
            config
                .clone()
                .external_plugin(selection(kind, server))
                .is_err()
        );
        assert!(
            config
                .clone()
                .external_plugin(selection(ExternalPluginKind::KerberosAuth, server))
                .is_err()
        );
        assert!(
            config
                .external_plugin(selection(ExternalPluginKind::LdapSecrets, server))
                .is_ok()
        );
        let mut config = crate::OpenBaoConfig::new("https://bao.example.invalid")
            .unwrap_or_else(|_| panic!("config failed"));
        for index in 0..32 {
            let item = ExternalPluginSelection::new(
                kind,
                server,
                &format!("mount-{index}"),
                "v0.1.0",
                kind.binary_sha256(),
            )
            .unwrap_or_else(|_| panic!("selection failed"));
            config = config
                .external_plugin(item)
                .unwrap_or_else(|_| panic!("selection failed"));
        }
        assert!(config.external_plugin(selection(kind, server)).is_err());
    }

    #[test]
    fn canonical_mounts_and_kind_boundaries() {
        let kind = ExternalPluginKind::LdapAuth;
        let server = OpenBaoVersion::new(2, 7, 0);
        for mount in [
            "",
            "/mount",
            "mount/",
            "mount//tail",
            "../mount",
            "mount%2ftail",
            "mount?x=1",
            "mount\n",
        ] {
            assert!(
                ExternalPluginSelection::new(kind, server, mount, "v0.1.0", kind.binary_sha256())
                    .is_err()
            );
        }
        let selected = selection(kind, server);
        assert!(selected.matches_mount_scope(kind, "sensitive/mount"));
        assert!(selected.matches_mount_scope(ExternalPluginKind::KerberosAuth, "sensitive/mount"));
        assert!(!selected.matches_mount_scope(kind, "sensitive/mount/child"));
        assert!(!selected.matches_mount_scope(ExternalPluginKind::LdapSecrets, "sensitive/mount"));
        for (path, expected) in [
            ("/auth/ldap/config", Some(kind)),
            ("/auth/ldap", Some(kind)),
            ("/auth/ldap-other/config", None),
            ("/ldap/config", Some(ExternalPluginKind::LdapSecrets)),
            ("/ldap-other/config", None),
            ("/auth/radius/login", Some(ExternalPluginKind::RadiusAuth)),
            (
                "/auth/kerberos/login",
                Some(ExternalPluginKind::KerberosAuth),
            ),
        ] {
            assert_eq!(ExternalPluginKind::for_path(path), expected);
        }
    }

    #[test]
    fn artifact_selection_never_promotes_contracts() {
        for kind in KINDS {
            for server in [OpenBaoVersion::new(2, 7, 0), OpenBaoVersion::new(2, 7, 1)] {
                let selected = selection(kind, server);
                let verified = OpenBaoCompatibilityPolicy::automatic_strict()
                    .evaluate_detected(server)
                    .unwrap_or_else(|_| panic!("profile failed"));
                let unknown = OpenBaoCompatibilityReport::acknowledged_unknown_newer(
                    OpenBaoVersion::new(2, 7, 2),
                    server,
                );
                for operation in crate::compatibility::openbao_operations() {
                    assert!(!selected.supports(verified, *operation));
                    assert!(
                        !selected.supports(OpenBaoCompatibilityReport::assumed(server), *operation)
                    );
                    assert!(
                        !selected.supports(OpenBaoCompatibilityReport::unverified(), *operation)
                    );
                    assert!(!selected.supports(unknown, *operation));
                }
            }
        }
    }
}
