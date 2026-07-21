//! Idempotent administration bootstrap helpers.
//!
//! This module builds on typed `sys`, KV v2, Transit, and token helpers. It is
//! meant for already-initialized OpenBao clusters. It does not initialize,
//! unseal, rekey, or rotate production seal material.

use core::fmt;
use std::collections::BTreeMap;

use secrecy::{ExposeSecret, SecretString};
use subtle::{Choice, ConstantTimeEq};

#[cfg(feature = "approle")]
use crate::auth::approle::{AppRoleRoleRequest, AppRoleSecretId, AppRoleSecretIdRequest};
#[cfg(feature = "database")]
use crate::secrets::database::{DatabaseRole, DatabaseStaticRole};
#[cfg(feature = "identity")]
use crate::secrets::identity::{
    IdentityEntityInfo, IdentityEntityRequest, IdentityGroupInfo, IdentityGroupRequest,
};
#[cfg(feature = "pki")]
use crate::secrets::pki::PkiRole;
#[cfg(feature = "ssh")]
use crate::secrets::ssh::{SshRoleInfo, SshRoleRequest};
use crate::{
    AclPolicyBuilder, Authenticated, Client, Error, Result,
    auth::token::{TokenAuth, TokenCreateRequest},
    path::{validate_endpoint_path, validate_mount_path},
    secrets::{
        kv2::{Kv2ServiceConfig, Kv2WriteOptions},
        transit::TransitCreateKeyRequest,
    },
    sys::{AuthEnableRequest, MountEnableRequest, PolicyWriteRequest},
};

const MAX_BOOTSTRAP_OPERATIONS: usize = 512;
const MAX_BOOTSTRAP_SECRET_VALUE_BYTES: usize = crate::validation::MAX_JSON_OBJECT_BYTES;

/// Builder for a small, idempotent OpenBao admin bootstrap plan.
///
/// # Locking requirement
///
/// All `ensure_*` operations use read-compare-write convergence without
/// distributed locking. This helper must be called with external mutual
/// exclusion in multi-operator, GitOps, CI/CD, or otherwise concurrent
/// environments. Use a Kubernetes Lease, CI environment lock, database advisory
/// lock, OpenBao-backed coordination primitive, or another operator-owned lock
/// before calling [`Self::run`]. Omitting that lock can allow a concurrent
/// writer to inject or overwrite security-critical configuration between the
/// read and write phases. KV v2 secret convergence uses CAS where OpenBao
/// exposes it; ACL policies, AppRole roles, PKI roles, SSH roles, database
/// roles, Identity entities, and groups do not have equivalent OpenBao CAS.
#[derive(Clone, Debug, Default)]
pub struct AdminBootstrap {
    operations: Vec<BootstrapOperation>,
}

#[derive(Clone)]
enum BootstrapOperation {
    AuthMethod {
        path: String,
        backend_type: String,
        description: Option<String>,
    },
    Kv2Mount {
        path: String,
        description: Option<String>,
    },
    TransitMount {
        path: String,
        description: Option<String>,
    },
    #[cfg(feature = "pki")]
    PkiMount {
        path: String,
        description: Option<String>,
    },
    #[cfg(feature = "database")]
    DatabaseMount {
        path: String,
        description: Option<String>,
    },
    #[cfg(feature = "ssh")]
    SshMount {
        path: String,
        description: Option<String>,
    },
    TransitKey {
        mount: String,
        name: String,
        request: TransitCreateKeyRequest,
    },
    Policy {
        name: String,
        policy: String,
    },
    Kv2SecretValues {
        mount: String,
        path: String,
        values: BTreeMap<String, SecretString>,
    },
    #[cfg(feature = "pki")]
    PkiRole {
        mount: String,
        name: String,
        role: Box<PkiRole>,
    },
    #[cfg(feature = "database")]
    DatabaseRole {
        mount: String,
        name: String,
        role: DatabaseRole,
    },
    #[cfg(feature = "database")]
    DatabaseStaticRole {
        mount: String,
        name: String,
        role: DatabaseStaticRole,
    },
    #[cfg(feature = "ssh")]
    SshRole {
        mount: String,
        name: String,
        request: SshRoleRequest,
    },
    #[cfg(feature = "identity")]
    IdentityEntity {
        mount: String,
        name: String,
        request: IdentityEntityRequest,
    },
    #[cfg(feature = "identity")]
    IdentityGroup {
        mount: String,
        name: String,
        request: IdentityGroupRequest,
    },
    ServiceToken {
        name: String,
        request: TokenCreateRequest,
    },
    #[cfg(feature = "approle")]
    AppRoleRole {
        mount: String,
        name: String,
        request: AppRoleRoleRequest,
    },
    #[cfg(feature = "approle")]
    AppRoleSecretId {
        name: String,
        mount: String,
        role_name: String,
        request: AppRoleSecretIdRequest,
    },
}

/// Result of running an [`AdminBootstrap`] plan.
#[derive(Debug, Default)]
#[must_use = "inspect bootstrap reports so issued credentials, changed steps, and contention outcomes are handled"]
pub struct BootstrapReport {
    /// Per-operation status entries.
    pub steps: Vec<BootstrapStepReport>,
    /// Tokens explicitly issued by the plan.
    pub issued_tokens: Vec<BootstrapIssuedToken>,
    /// AppRole SecretIDs explicitly issued by the plan.
    #[cfg(feature = "approle")]
    pub issued_approle_secret_ids: Vec<BootstrapIssuedAppRoleSecretId>,
}

impl BootstrapReport {
    /// Returns the issued token with the given bootstrap name.
    #[must_use]
    pub fn issued_token(&self, name: &str) -> Option<&BootstrapIssuedToken> {
        self.issued_tokens.iter().find(|token| token.name == name)
    }

    /// Returns the issued AppRole SecretID with the given bootstrap name.
    #[cfg(feature = "approle")]
    #[must_use]
    pub fn issued_approle_secret_id(&self, name: &str) -> Option<&BootstrapIssuedAppRoleSecretId> {
        self.issued_approle_secret_ids
            .iter()
            .find(|secret_id| secret_id.name == name)
    }

    /// Returns true when every convergence step found existing matching state.
    ///
    /// Credential issuance steps are not idempotent and therefore make this
    /// return `false`.
    #[must_use]
    pub fn is_converged(&self) -> bool {
        self.steps
            .iter()
            .all(|step| step.status == BootstrapStepStatus::Unchanged)
    }

    /// Returns steps that created, updated, or issued state.
    pub fn changed_steps(&self) -> impl Iterator<Item = &BootstrapStepReport> {
        self.steps
            .iter()
            .filter(|step| step.status != BootstrapStepStatus::Unchanged)
    }
}

/// Read-only result of previewing an [`AdminBootstrap`] plan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BootstrapPreviewReport {
    /// Per-operation preview entries.
    pub steps: Vec<BootstrapPreviewStep>,
}

impl BootstrapPreviewReport {
    /// Returns true when every idempotent convergence step already matches and
    /// the plan contains no credential issuance steps.
    #[must_use]
    pub fn is_converged(&self) -> bool {
        self.steps
            .iter()
            .all(|step| step.status == BootstrapPreviewStatus::Unchanged)
    }

    /// Returns steps that would create, update, or issue state.
    pub fn changed_steps(&self) -> impl Iterator<Item = &BootstrapPreviewStep> {
        self.steps
            .iter()
            .filter(|step| step.status != BootstrapPreviewStatus::Unchanged)
    }
}

/// Per-operation bootstrap status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapStepStatus {
    /// The target already matched the desired state.
    Unchanged,
    /// The target was created.
    Created,
    /// The target existed but was updated.
    Updated,
    /// A new credential was issued. This is intentionally not idempotent.
    Issued,
}

/// Per-operation dry-run bootstrap status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapPreviewStatus {
    /// The target already matches the desired state.
    Unchanged,
    /// The target is absent and would be created by [`AdminBootstrap::run`].
    WouldCreate,
    /// The target exists and would be updated by [`AdminBootstrap::run`].
    WouldUpdate,
    /// A new credential would be issued by [`AdminBootstrap::run`].
    WouldIssue,
}

/// Per-operation bootstrap report entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapStepReport {
    /// Bootstrap target type.
    pub target_type: &'static str,
    /// Bootstrap target name or path.
    pub target: String,
    /// Operation status.
    pub status: BootstrapStepStatus,
}

impl BootstrapStepReport {
    fn new(
        target_type: &'static str,
        target: impl Into<String>,
        status: BootstrapStepStatus,
    ) -> Self {
        Self {
            target_type,
            target: target.into(),
            status,
        }
    }
}

/// Per-operation dry-run bootstrap report entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapPreviewStep {
    /// Bootstrap target type.
    pub target_type: &'static str,
    /// Bootstrap target name or path.
    pub target: String,
    /// Read-only preview status.
    pub status: BootstrapPreviewStatus,
}

impl BootstrapPreviewStep {
    fn new(
        target_type: &'static str,
        target: impl Into<String>,
        status: BootstrapPreviewStatus,
    ) -> Self {
        Self {
            target_type,
            target: target.into(),
            status,
        }
    }
}

/// Token material issued by a bootstrap plan.
pub struct BootstrapIssuedToken {
    /// Logical token name from the bootstrap plan.
    pub name: String,
    /// Token auth response. Contains secret token and accessor material.
    pub auth: TokenAuth,
}

/// AppRole SecretID material issued by a bootstrap plan.
#[cfg(feature = "approle")]
pub struct BootstrapIssuedAppRoleSecretId {
    /// Logical SecretID name from the bootstrap plan.
    pub name: String,
    /// Generated SecretID response. Contains SecretID and accessor material.
    pub secret_id: AppRoleSecretId,
}

#[cfg(feature = "approle")]
impl fmt::Debug for BootstrapIssuedAppRoleSecretId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapIssuedAppRoleSecretId")
            .field("name", &self.name)
            .field("secret_id", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for BootstrapIssuedToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapIssuedToken")
            .field("name", &self.name)
            .field("auth", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for BootstrapOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthMethod {
                path,
                backend_type,
                description,
            } => formatter
                .debug_struct("AuthMethod")
                .field("path", path)
                .field("backend_type", backend_type)
                .field("description", description)
                .finish(),
            Self::Kv2Mount { path, description } => formatter
                .debug_struct("Kv2Mount")
                .field("path", path)
                .field("description", description)
                .finish(),
            Self::TransitMount { path, description } => formatter
                .debug_struct("TransitMount")
                .field("path", path)
                .field("description", description)
                .finish(),
            #[cfg(feature = "pki")]
            Self::PkiMount { path, description } => formatter
                .debug_struct("PkiMount")
                .field("path", path)
                .field("description", description)
                .finish(),
            #[cfg(feature = "database")]
            Self::DatabaseMount { path, description } => formatter
                .debug_struct("DatabaseMount")
                .field("path", path)
                .field("description", description)
                .finish(),
            #[cfg(feature = "ssh")]
            Self::SshMount { path, description } => formatter
                .debug_struct("SshMount")
                .field("path", path)
                .field("description", description)
                .finish(),
            Self::TransitKey { mount, name, .. } => formatter
                .debug_struct("TransitKey")
                .field("mount", mount)
                .field("name", name)
                .field("request", &"<redacted>")
                .finish(),
            Self::Policy { name, .. } => formatter
                .debug_struct("Policy")
                .field("name", name)
                .field("policy", &"<redacted>")
                .finish(),
            Self::Kv2SecretValues { mount, path, .. } => formatter
                .debug_struct("Kv2SecretValues")
                .field("mount", mount)
                .field("path", path)
                .field("values", &"<redacted>")
                .finish(),
            #[cfg(feature = "pki")]
            Self::PkiRole { mount, name, role } => formatter
                .debug_struct("PkiRole")
                .field("mount", mount)
                .field("name", name)
                .field("role", role)
                .finish(),
            #[cfg(feature = "database")]
            Self::DatabaseRole { mount, name, role } => formatter
                .debug_struct("DatabaseRole")
                .field("mount", mount)
                .field("name", name)
                .field("role", role)
                .finish(),
            #[cfg(feature = "database")]
            Self::DatabaseStaticRole { mount, name, role } => formatter
                .debug_struct("DatabaseStaticRole")
                .field("mount", mount)
                .field("name", name)
                .field("role", role)
                .finish(),
            #[cfg(feature = "ssh")]
            Self::SshRole {
                mount,
                name,
                request,
            } => formatter
                .debug_struct("SshRole")
                .field("mount", mount)
                .field("name", name)
                .field("request", request)
                .finish(),
            #[cfg(feature = "identity")]
            Self::IdentityEntity { mount, name, .. } => formatter
                .debug_struct("IdentityEntity")
                .field("mount", mount)
                .field("name", name)
                .field("request", &"<redacted>")
                .finish(),
            #[cfg(feature = "identity")]
            Self::IdentityGroup { mount, name, .. } => formatter
                .debug_struct("IdentityGroup")
                .field("mount", mount)
                .field("name", name)
                .field("request", &"<redacted>")
                .finish(),
            Self::ServiceToken { name, .. } => formatter
                .debug_struct("ServiceToken")
                .field("name", name)
                .field("request", &"<redacted>")
                .finish(),
            #[cfg(feature = "approle")]
            Self::AppRoleRole { mount, name, .. } => formatter
                .debug_struct("AppRoleRole")
                .field("mount", mount)
                .field("name", name)
                .field("request", &"<redacted>")
                .finish(),
            #[cfg(feature = "approle")]
            Self::AppRoleSecretId {
                name,
                mount,
                role_name,
                ..
            } => formatter
                .debug_struct("AppRoleSecretId")
                .field("name", name)
                .field("mount", mount)
                .field("role_name", role_name)
                .field("request", &"<redacted>")
                .finish(),
        }
    }
}

impl AdminBootstrap {
    /// Creates an empty admin bootstrap plan.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ensures an auth method exists at `path`.
    pub fn ensure_auth_method(
        &mut self,
        path: impl AsRef<str>,
        backend_type: impl AsRef<str>,
        description: Option<&str>,
    ) -> Result<&mut Self> {
        let path = validate_mount_path(path.as_ref())?.join("/");
        let backend_type = validate_mount_path(backend_type.as_ref())?.join("/");
        self.push_operation(BootstrapOperation::AuthMethod {
            path,
            backend_type,
            description: description.map(str::to_owned),
        })
    }

    /// Ensures the AppRole auth method exists at `path`.
    pub fn ensure_approle_auth_method(
        &mut self,
        path: impl AsRef<str>,
        description: Option<&str>,
    ) -> Result<&mut Self> {
        self.ensure_auth_method(path, "approle", description)
    }

    /// Ensures a KV v2 mount exists at `path`.
    pub fn ensure_kv2_mount(
        &mut self,
        path: impl AsRef<str>,
        description: Option<&str>,
    ) -> Result<&mut Self> {
        let path = validate_mount_path(path.as_ref())?.join("/");
        self.push_operation(BootstrapOperation::Kv2Mount {
            path,
            description: description.map(str::to_owned),
        })
    }

    /// Ensures a Transit mount exists at `path`.
    pub fn ensure_transit_mount(
        &mut self,
        path: impl AsRef<str>,
        description: Option<&str>,
    ) -> Result<&mut Self> {
        let path = validate_mount_path(path.as_ref())?.join("/");
        self.push_operation(BootstrapOperation::TransitMount {
            path,
            description: description.map(str::to_owned),
        })
    }

    /// Ensures a PKI secrets engine mount exists at `path`.
    ///
    /// This does not generate or import CA material. PKI authority bootstrap is
    /// an operator ceremony outside this application bootstrap helper.
    #[cfg(feature = "pki")]
    pub fn ensure_pki_mount(
        &mut self,
        path: impl AsRef<str>,
        description: Option<&str>,
    ) -> Result<&mut Self> {
        let path = validate_mount_path(path.as_ref())?.join("/");
        self.push_operation(BootstrapOperation::PkiMount {
            path,
            description: description.map(str::to_owned),
        })
    }

    /// Ensures a database secrets engine mount exists at `path`.
    ///
    /// This intentionally does not configure database connections because
    /// connection configuration carries production database credentials.
    #[cfg(feature = "database")]
    pub fn ensure_database_mount(
        &mut self,
        path: impl AsRef<str>,
        description: Option<&str>,
    ) -> Result<&mut Self> {
        let path = validate_mount_path(path.as_ref())?.join("/");
        self.push_operation(BootstrapOperation::DatabaseMount {
            path,
            description: description.map(str::to_owned),
        })
    }

    /// Ensures an SSH secrets engine mount exists at `path`.
    ///
    /// This does not configure SSH CA key material. SSH authority setup remains
    /// an operator ceremony outside this bootstrap helper.
    #[cfg(feature = "ssh")]
    pub fn ensure_ssh_mount(
        &mut self,
        path: impl AsRef<str>,
        description: Option<&str>,
    ) -> Result<&mut Self> {
        let path = validate_mount_path(path.as_ref())?.join("/");
        self.push_operation(BootstrapOperation::SshMount {
            path,
            description: description.map(str::to_owned),
        })
    }

    /// Ensures a Transit key exists.
    pub fn ensure_transit_key(
        &mut self,
        mount: impl AsRef<str>,
        name: impl AsRef<str>,
        request: TransitCreateKeyRequest,
    ) -> Result<&mut Self> {
        let mount = validate_mount_path(mount.as_ref())?.join("/");
        let name = validate_mount_path(name.as_ref())?.join("/");
        self.push_operation(BootstrapOperation::TransitKey {
            mount,
            name,
            request,
        })
    }

    /// Ensures an ACL policy exists and matches the builder output.
    ///
    /// Policy convergence is read-compare-write and OpenBao does not expose a
    /// CAS/version guard for policy writes. Callers must serialize bootstrap
    /// execution with an external lock or single-runner deployment guarantee
    /// when multiple processes can update the same cluster.
    pub fn ensure_policy(
        &mut self,
        name: impl AsRef<str>,
        policy: &AclPolicyBuilder,
    ) -> Result<&mut Self> {
        self.ensure_policy_document(name, policy.build()?)
    }

    /// Ensures an ACL policy exists and matches an explicit policy document.
    ///
    /// Policy convergence is not atomic: a concurrent writer can modify the
    /// policy after the read phase and before the write phase. This method is
    /// safe only when bootstrap runs are serialized externally for the target
    /// OpenBao cluster.
    pub fn ensure_policy_document(
        &mut self,
        name: impl AsRef<str>,
        policy: impl Into<String>,
    ) -> Result<&mut Self> {
        let name = validate_mount_path(name.as_ref())?.join("/");
        let policy = policy.into();
        validate_bootstrap_policy_document(&policy)?;
        self.push_operation(BootstrapOperation::Policy { name, policy })
    }

    /// Ensures a KV v2 secret contains the provided string values.
    ///
    /// Existing extra keys are preserved. The secret is patched only when one
    /// of the requested values is missing or different.
    pub fn ensure_kv2_secret_values(
        &mut self,
        mount: impl AsRef<str>,
        path: impl AsRef<str>,
        values: BTreeMap<String, SecretString>,
    ) -> Result<&mut Self> {
        let mount = validate_mount_path(mount.as_ref())?.join("/");
        let path = validate_endpoint_path(path.as_ref())?.join("/");
        validate_bootstrap_secret_values(&values)?;
        self.push_operation(BootstrapOperation::Kv2SecretValues {
            mount,
            path,
            values,
        })
    }

    /// Ensures a PKI role exists and matches the desired fields supplied in
    /// `role`.
    ///
    /// This only converges role configuration. It intentionally does not
    /// generate or import CA material, sign intermediates, or manage trust
    /// stores; those are operator ceremonies outside application bootstrap.
    #[cfg(feature = "pki")]
    pub fn ensure_pki_role(
        &mut self,
        mount: impl AsRef<str>,
        name: impl AsRef<str>,
        role: PkiRole,
    ) -> Result<&mut Self> {
        let mount = validate_mount_path(mount.as_ref())?.join("/");
        let name = validate_mount_path(name.as_ref())?.join("/");
        self.push_operation(BootstrapOperation::PkiRole {
            mount,
            name,
            role: Box::new(role),
        })
    }

    /// Ensures a dynamic database role exists and matches desired fields.
    ///
    /// This converges role configuration only. It intentionally does not
    /// configure database connections or rotate database credentials.
    #[cfg(feature = "database")]
    pub fn ensure_database_role(
        &mut self,
        mount: impl AsRef<str>,
        name: impl AsRef<str>,
        role: DatabaseRole,
    ) -> Result<&mut Self> {
        let mount = validate_mount_path(mount.as_ref())?.join("/");
        let name = validate_mount_path(name.as_ref())?.join("/");
        self.push_operation(BootstrapOperation::DatabaseRole { mount, name, role })
    }

    /// Ensures a static database role exists and matches desired fields.
    ///
    /// This converges role configuration only. Credential rotation remains an
    /// explicit database-engine operation outside bootstrap convergence.
    #[cfg(feature = "database")]
    pub fn ensure_database_static_role(
        &mut self,
        mount: impl AsRef<str>,
        name: impl AsRef<str>,
        role: DatabaseStaticRole,
    ) -> Result<&mut Self> {
        let mount = validate_mount_path(mount.as_ref())?.join("/");
        let name = validate_mount_path(name.as_ref())?.join("/");
        self.push_operation(BootstrapOperation::DatabaseStaticRole { mount, name, role })
    }

    /// Ensures an SSH role exists and matches desired readable fields.
    ///
    /// This converges role configuration only. SSH CA key setup remains an
    /// operator ceremony outside this bootstrap helper.
    #[cfg(feature = "ssh")]
    pub fn ensure_ssh_role(
        &mut self,
        mount: impl AsRef<str>,
        name: impl AsRef<str>,
        request: SshRoleRequest,
    ) -> Result<&mut Self> {
        let mount = validate_mount_path(mount.as_ref())?.join("/");
        let name = validate_mount_path(name.as_ref())?.join("/");
        self.push_operation(BootstrapOperation::SshRole {
            mount,
            name,
            request,
        })
    }

    /// Ensures an Identity entity exists at the default `identity` mount.
    #[cfg(feature = "identity")]
    pub fn ensure_identity_entity(
        &mut self,
        name: impl AsRef<str>,
        request: IdentityEntityRequest,
    ) -> Result<&mut Self> {
        self.ensure_identity_entity_at("identity", name, request)
    }

    /// Ensures an Identity entity exists at `mount`.
    #[cfg(feature = "identity")]
    pub fn ensure_identity_entity_at(
        &mut self,
        mount: impl AsRef<str>,
        name: impl AsRef<str>,
        request: IdentityEntityRequest,
    ) -> Result<&mut Self> {
        let mount = validate_mount_path(mount.as_ref())?.join("/");
        let name = validate_mount_path(name.as_ref())?.join("/");
        if request.name.as_deref() != Some(name.as_str()) && request.name.is_some() {
            return Err(Error::InvalidParameter(
                "identity entity request name must match bootstrap target name".into(),
            ));
        }
        self.push_operation(BootstrapOperation::IdentityEntity {
            mount,
            name,
            request,
        })
    }

    /// Ensures an Identity group exists at the default `identity` mount.
    #[cfg(feature = "identity")]
    pub fn ensure_identity_group(
        &mut self,
        name: impl AsRef<str>,
        request: IdentityGroupRequest,
    ) -> Result<&mut Self> {
        self.ensure_identity_group_at("identity", name, request)
    }

    /// Ensures an Identity group exists at `mount`.
    #[cfg(feature = "identity")]
    pub fn ensure_identity_group_at(
        &mut self,
        mount: impl AsRef<str>,
        name: impl AsRef<str>,
        request: IdentityGroupRequest,
    ) -> Result<&mut Self> {
        let mount = validate_mount_path(mount.as_ref())?.join("/");
        let name = validate_mount_path(name.as_ref())?.join("/");
        if request.name.as_deref() != Some(name.as_str()) && request.name.is_some() {
            return Err(Error::InvalidParameter(
                "identity group request name must match bootstrap target name".into(),
            ));
        }
        self.push_operation(BootstrapOperation::IdentityGroup {
            mount,
            name,
            request,
        })
    }

    /// Issues a scoped service token at the end of the plan.
    ///
    /// Token issuance always creates a new credential. This method is explicit
    /// so callers can separate idempotent state convergence from credential
    /// handoff.
    pub fn issue_service_token(
        &mut self,
        name: impl AsRef<str>,
        request: TokenCreateRequest,
    ) -> Result<&mut Self> {
        let name = validate_mount_path(name.as_ref())?.join("/");
        self.push_operation(BootstrapOperation::ServiceToken { name, request })
    }

    /// Ensures an AppRole role exists and matches the desired fields supplied
    /// in `request`.
    ///
    /// This uses read-compare-write convergence because OpenBao does not expose
    /// CAS for AppRole role writes. Serialize concurrent bootstrap runs
    /// externally when role configuration integrity is safety-critical.
    #[cfg(feature = "approle")]
    pub fn ensure_approle_role(
        &mut self,
        mount: impl AsRef<str>,
        name: impl AsRef<str>,
        request: AppRoleRoleRequest,
    ) -> Result<&mut Self> {
        let mount = validate_mount_path(mount.as_ref())?.join("/");
        let name = validate_mount_path(name.as_ref())?.join("/");
        self.push_operation(BootstrapOperation::AppRoleRole {
            mount,
            name,
            request,
        })
    }

    /// Issues a new AppRole SecretID at the end of the plan.
    ///
    /// SecretID generation always creates a new credential. This method is
    /// explicit so callers can separate idempotent state convergence from
    /// credential handoff.
    ///
    /// Serialize concurrent bootstrap runs externally if the same AppRole role
    /// is also being converged or modified by another operator or pipeline.
    #[cfg(feature = "approle")]
    pub fn issue_approle_secret_id(
        &mut self,
        name: impl AsRef<str>,
        mount: impl AsRef<str>,
        role_name: impl AsRef<str>,
        request: AppRoleSecretIdRequest,
    ) -> Result<&mut Self> {
        let name = validate_mount_path(name.as_ref())?.join("/");
        let mount = validate_mount_path(mount.as_ref())?.join("/");
        let role_name = validate_mount_path(role_name.as_ref())?.join("/");
        self.push_operation(BootstrapOperation::AppRoleSecretId {
            name,
            mount,
            role_name,
            request,
        })
    }

    fn push_operation(&mut self, operation: BootstrapOperation) -> Result<&mut Self> {
        if self.operations.len() >= MAX_BOOTSTRAP_OPERATIONS {
            return Err(Error::InvalidParameter(
                "bootstrap plan exceeds maximum allowed operation count".into(),
            ));
        }
        self.operations.push(operation);
        Ok(self)
    }

    /// Previews the bootstrap plan without writing state or issuing
    /// credentials.
    ///
    /// This performs the same read-side comparisons as [`Self::run`] where
    /// possible. Credential issuance steps are reported as
    /// [`BootstrapPreviewStatus::WouldIssue`] and are never executed.
    pub async fn preview(&self, client: &Client<Authenticated>) -> Result<BootstrapPreviewReport> {
        let mut report = BootstrapPreviewReport::default();
        for operation in &self.operations {
            match operation {
                BootstrapOperation::AuthMethod {
                    path, backend_type, ..
                } => {
                    let status = preview_auth_method(client, path, backend_type).await?;
                    report
                        .steps
                        .push(BootstrapPreviewStep::new("auth_method", path, status));
                }
                BootstrapOperation::Kv2Mount { path, .. } => {
                    let status = preview_mount(client, path, "kv", Some(("version", "2"))).await?;
                    report
                        .steps
                        .push(BootstrapPreviewStep::new("kv2_mount", path, status));
                }
                BootstrapOperation::TransitMount { path, .. } => {
                    let status = preview_mount(client, path, "transit", None).await?;
                    report
                        .steps
                        .push(BootstrapPreviewStep::new("transit_mount", path, status));
                }
                #[cfg(feature = "pki")]
                BootstrapOperation::PkiMount { path, .. } => {
                    let status = preview_mount(client, path, "pki", None).await?;
                    report
                        .steps
                        .push(BootstrapPreviewStep::new("pki_mount", path, status));
                }
                #[cfg(feature = "database")]
                BootstrapOperation::DatabaseMount { path, .. } => {
                    let status = preview_mount(client, path, "database", None).await?;
                    report
                        .steps
                        .push(BootstrapPreviewStep::new("database_mount", path, status));
                }
                #[cfg(feature = "ssh")]
                BootstrapOperation::SshMount { path, .. } => {
                    let status = preview_mount(client, path, "ssh", None).await?;
                    report
                        .steps
                        .push(BootstrapPreviewStep::new("ssh_mount", path, status));
                }
                BootstrapOperation::TransitKey { mount, name, .. } => {
                    let status = match client.transit(mount)?.read_key(name).await {
                        Ok(_) => BootstrapPreviewStatus::Unchanged,
                        Err(error) if error.is_not_found() => BootstrapPreviewStatus::WouldCreate,
                        Err(error) => return Err(error),
                    };
                    report.steps.push(BootstrapPreviewStep::new(
                        "transit_key",
                        format!("{mount}/{name}"),
                        status,
                    ));
                }
                BootstrapOperation::Policy { name, policy } => {
                    let status = match client.sys().read_policy(name).await {
                        Ok(existing) if policy_matches_desired(&existing, policy) => {
                            BootstrapPreviewStatus::Unchanged
                        }
                        Ok(_) => BootstrapPreviewStatus::WouldUpdate,
                        Err(error) if error.is_not_found() => BootstrapPreviewStatus::WouldCreate,
                        Err(error) => return Err(error),
                    };
                    report
                        .steps
                        .push(BootstrapPreviewStep::new("policy", name, status));
                }
                BootstrapOperation::Kv2SecretValues {
                    mount,
                    path,
                    values,
                } => {
                    let kv = client.kv2(mount)?;
                    let current = match kv.read_service_config(path).await {
                        Ok(config) => Some(config),
                        Err(error) if error.is_not_found() => None,
                        Err(error) => return Err(error),
                    };
                    let mut needs_patch = current.is_none();
                    if let Some(config) = current.as_ref() {
                        for (key, value) in values {
                            needs_patch |= config.get(key).is_none_or(|current| {
                                !secret_values_equal(current.expose_secret(), value.expose_secret())
                            });
                        }
                    }
                    let status = if needs_patch {
                        if current.is_some() {
                            BootstrapPreviewStatus::WouldUpdate
                        } else {
                            BootstrapPreviewStatus::WouldCreate
                        }
                    } else {
                        BootstrapPreviewStatus::Unchanged
                    };
                    report.steps.push(BootstrapPreviewStep::new(
                        "kv2_secret",
                        format!("{mount}/{path}"),
                        status,
                    ));
                }
                #[cfg(feature = "pki")]
                BootstrapOperation::PkiRole { mount, name, role } => {
                    let pki = client.pki(mount)?;
                    let status = match pki.read_role(name).await {
                        Ok(existing) if pki_role_matches_desired(&existing, role) => {
                            BootstrapPreviewStatus::Unchanged
                        }
                        Ok(_) => BootstrapPreviewStatus::WouldUpdate,
                        Err(error) if error.is_not_found() => BootstrapPreviewStatus::WouldCreate,
                        Err(error) => return Err(error),
                    };
                    report.steps.push(BootstrapPreviewStep::new(
                        "pki_role",
                        format!("{mount}/{name}"),
                        status,
                    ));
                }
                #[cfg(feature = "database")]
                BootstrapOperation::DatabaseRole { mount, name, role } => {
                    let database = client.database(mount)?;
                    let status = match database.read_role(name).await {
                        Ok(existing) if database_role_matches_desired(&existing, role) => {
                            BootstrapPreviewStatus::Unchanged
                        }
                        Ok(_) => BootstrapPreviewStatus::WouldUpdate,
                        Err(error) if error.is_not_found() => BootstrapPreviewStatus::WouldCreate,
                        Err(error) => return Err(error),
                    };
                    report.steps.push(BootstrapPreviewStep::new(
                        "database_role",
                        format!("{mount}/{name}"),
                        status,
                    ));
                }
                #[cfg(feature = "database")]
                BootstrapOperation::DatabaseStaticRole { mount, name, role } => {
                    let database = client.database(mount)?;
                    let status = match database.read_static_role(name).await {
                        Ok(existing) if database_static_role_matches_desired(&existing, role) => {
                            BootstrapPreviewStatus::Unchanged
                        }
                        Ok(_) => BootstrapPreviewStatus::WouldUpdate,
                        Err(error) if error.is_not_found() => BootstrapPreviewStatus::WouldCreate,
                        Err(error) => return Err(error),
                    };
                    report.steps.push(BootstrapPreviewStep::new(
                        "database_static_role",
                        format!("{mount}/{name}"),
                        status,
                    ));
                }
                #[cfg(feature = "ssh")]
                BootstrapOperation::SshRole {
                    mount,
                    name,
                    request,
                } => {
                    let ssh = client.ssh(mount)?;
                    let status = match ssh.read_role(name).await {
                        Ok(existing) if ssh_role_matches_desired(&existing, request) => {
                            BootstrapPreviewStatus::Unchanged
                        }
                        Ok(_) => BootstrapPreviewStatus::WouldUpdate,
                        Err(error) if error.is_not_found() => BootstrapPreviewStatus::WouldCreate,
                        Err(error) => return Err(error),
                    };
                    report.steps.push(BootstrapPreviewStep::new(
                        "ssh_role",
                        format!("{mount}/{name}"),
                        status,
                    ));
                }
                #[cfg(feature = "identity")]
                BootstrapOperation::IdentityEntity {
                    mount,
                    name,
                    request,
                } => {
                    let identity = client.identity_at(mount)?;
                    let status = match identity.read_entity_by_name(name).await {
                        Ok(existing) if identity_entity_matches_desired(&existing, request) => {
                            BootstrapPreviewStatus::Unchanged
                        }
                        Ok(_) => BootstrapPreviewStatus::WouldUpdate,
                        Err(error) if error.is_not_found() => BootstrapPreviewStatus::WouldCreate,
                        Err(error) => return Err(error),
                    };
                    report.steps.push(BootstrapPreviewStep::new(
                        "identity_entity",
                        format!("{mount}/{name}"),
                        status,
                    ));
                }
                #[cfg(feature = "identity")]
                BootstrapOperation::IdentityGroup {
                    mount,
                    name,
                    request,
                } => {
                    let identity = client.identity_at(mount)?;
                    let status = match identity.read_group_by_name(name).await {
                        Ok(existing) if identity_group_matches_desired(&existing, request) => {
                            BootstrapPreviewStatus::Unchanged
                        }
                        Ok(_) => BootstrapPreviewStatus::WouldUpdate,
                        Err(error) if error.is_not_found() => BootstrapPreviewStatus::WouldCreate,
                        Err(error) => return Err(error),
                    };
                    report.steps.push(BootstrapPreviewStep::new(
                        "identity_group",
                        format!("{mount}/{name}"),
                        status,
                    ));
                }
                BootstrapOperation::ServiceToken { name, .. } => {
                    report.steps.push(BootstrapPreviewStep::new(
                        "service_token",
                        name,
                        BootstrapPreviewStatus::WouldIssue,
                    ));
                }
                #[cfg(feature = "approle")]
                BootstrapOperation::AppRoleRole {
                    mount,
                    name,
                    request,
                } => {
                    let admin = client.approle_admin_at(mount)?;
                    let status = match admin.read_role(name).await {
                        Ok(existing) if approle_role_matches_desired(&existing, request) => {
                            BootstrapPreviewStatus::Unchanged
                        }
                        Ok(_) => BootstrapPreviewStatus::WouldUpdate,
                        Err(error) if error.is_not_found() => BootstrapPreviewStatus::WouldCreate,
                        Err(error) => return Err(error),
                    };
                    report.steps.push(BootstrapPreviewStep::new(
                        "approle_role",
                        format!("{mount}/{name}"),
                        status,
                    ));
                }
                #[cfg(feature = "approle")]
                BootstrapOperation::AppRoleSecretId {
                    name,
                    mount,
                    role_name,
                    ..
                } => {
                    report.steps.push(BootstrapPreviewStep::new(
                        "approle_secret_id",
                        format!("{mount}/{role_name}/{name}"),
                        BootstrapPreviewStatus::WouldIssue,
                    ));
                }
            }
        }
        Ok(report)
    }

    /// Runs the bootstrap plan.
    pub async fn run(&self, client: &Client<Authenticated>) -> Result<BootstrapReport> {
        let mut report = BootstrapReport::default();
        for operation in &self.operations {
            match operation {
                BootstrapOperation::AuthMethod {
                    path,
                    backend_type,
                    description,
                } => {
                    let status = ensure_auth_method(client, path, backend_type, || {
                        AuthEnableRequest::new(backend_type.clone())
                            .with_optional_description(description)
                    })
                    .await?;
                    report
                        .steps
                        .push(BootstrapStepReport::new("auth_method", path, status));
                }
                BootstrapOperation::Kv2Mount { path, description } => {
                    let status = ensure_mount(client, path, "kv", Some(("version", "2")), || {
                        MountEnableRequest::kv2().with_optional_description(description)
                    })
                    .await?;
                    report
                        .steps
                        .push(BootstrapStepReport::new("kv2_mount", path, status));
                }
                BootstrapOperation::TransitMount { path, description } => {
                    let status = ensure_mount(client, path, "transit", None, || {
                        MountEnableRequest::new("transit").with_optional_description(description)
                    })
                    .await?;
                    report
                        .steps
                        .push(BootstrapStepReport::new("transit_mount", path, status));
                }
                #[cfg(feature = "pki")]
                BootstrapOperation::PkiMount { path, description } => {
                    let status = ensure_mount(client, path, "pki", None, || {
                        MountEnableRequest::new("pki").with_optional_description(description)
                    })
                    .await?;
                    report
                        .steps
                        .push(BootstrapStepReport::new("pki_mount", path, status));
                }
                #[cfg(feature = "database")]
                BootstrapOperation::DatabaseMount { path, description } => {
                    let status = ensure_mount(client, path, "database", None, || {
                        MountEnableRequest::new("database").with_optional_description(description)
                    })
                    .await?;
                    report
                        .steps
                        .push(BootstrapStepReport::new("database_mount", path, status));
                }
                #[cfg(feature = "ssh")]
                BootstrapOperation::SshMount { path, description } => {
                    let status = ensure_mount(client, path, "ssh", None, || {
                        MountEnableRequest::new("ssh").with_optional_description(description)
                    })
                    .await?;
                    report
                        .steps
                        .push(BootstrapStepReport::new("ssh_mount", path, status));
                }
                BootstrapOperation::TransitKey {
                    mount,
                    name,
                    request,
                } => {
                    let status = match client.transit(mount)?.read_key(name).await {
                        Ok(_) => BootstrapStepStatus::Unchanged,
                        Err(error) if error.is_not_found() => {
                            match client.transit(mount)?.create_key(name, request).await {
                                Ok(_) => BootstrapStepStatus::Created,
                                Err(error) if is_already_exists_error(&error) => {
                                    BootstrapStepStatus::Unchanged
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        Err(error) => return Err(error),
                    };
                    report.steps.push(BootstrapStepReport::new(
                        "transit_key",
                        format!("{mount}/{name}"),
                        status,
                    ));
                }
                BootstrapOperation::Policy { name, policy } => {
                    let status = match client.sys().read_policy(name).await {
                        Ok(existing) if policy_matches_desired(&existing, policy) => {
                            BootstrapStepStatus::Unchanged
                        }
                        Ok(_) => {
                            client
                                .sys()
                                .write_policy(name, &PolicyWriteRequest::new(policy.clone()))
                                .await?;
                            let verification = client.sys().read_policy(name).await?;
                            if !policy_matches_desired(&verification, policy) {
                                return Err(bootstrap_contention_error());
                            }
                            BootstrapStepStatus::Updated
                        }
                        Err(error) if error.is_not_found() => {
                            client
                                .sys()
                                .write_policy(name, &PolicyWriteRequest::new(policy.clone()))
                                .await?;
                            let verification = client.sys().read_policy(name).await?;
                            if !policy_matches_desired(&verification, policy) {
                                return Err(bootstrap_contention_error());
                            }
                            BootstrapStepStatus::Created
                        }
                        Err(error) => return Err(error),
                    };
                    report
                        .steps
                        .push(BootstrapStepReport::new("policy", name, status));
                }
                BootstrapOperation::Kv2SecretValues {
                    mount,
                    path,
                    values,
                } => {
                    let kv = client.kv2(mount)?;
                    let current = match kv.read::<Kv2ServiceConfig>(path).await {
                        Ok(secret) => Some(secret),
                        Err(error) if error.is_not_found() => None,
                        Err(error) => return Err(error),
                    };
                    let mut needs_patch = current.is_none();
                    if let Some(secret) = current.as_ref() {
                        for (key, value) in values {
                            needs_patch |= secret.data.get(key).is_none_or(|current| {
                                !secret_values_equal(current.expose_secret(), value.expose_secret())
                            });
                        }
                    }
                    let status = if needs_patch {
                        if let Some(current) = current {
                            kv.patch_with_options(
                                path,
                                secret_patch_payload(values),
                                Some(Kv2WriteOptions {
                                    cas: Some(current.metadata.version),
                                }),
                            )
                            .await?;
                            BootstrapStepStatus::Updated
                        } else {
                            kv.write_with_options(
                                path,
                                secret_patch_payload(values),
                                Some(Kv2WriteOptions { cas: Some(0) }),
                            )
                            .await?;
                            BootstrapStepStatus::Created
                        }
                    } else {
                        BootstrapStepStatus::Unchanged
                    };
                    report.steps.push(BootstrapStepReport::new(
                        "kv2_secret",
                        format!("{mount}/{path}"),
                        status,
                    ));
                }
                #[cfg(feature = "pki")]
                BootstrapOperation::PkiRole { mount, name, role } => {
                    let pki = client.pki(mount)?;
                    let status = match pki.read_role(name).await {
                        Ok(existing) if pki_role_matches_desired(&existing, role) => {
                            BootstrapStepStatus::Unchanged
                        }
                        Ok(_) => {
                            pki.write_role(name, role).await?;
                            let verification = pki.read_role(name).await?;
                            if !pki_role_matches_desired(&verification, role) {
                                return Err(bootstrap_contention_error());
                            }
                            BootstrapStepStatus::Updated
                        }
                        Err(error) if error.is_not_found() => {
                            pki.write_role(name, role).await?;
                            let verification = pki.read_role(name).await?;
                            if !pki_role_matches_desired(&verification, role) {
                                return Err(bootstrap_contention_error());
                            }
                            BootstrapStepStatus::Created
                        }
                        Err(error) => return Err(error),
                    };
                    report.steps.push(BootstrapStepReport::new(
                        "pki_role",
                        format!("{mount}/{name}"),
                        status,
                    ));
                }
                #[cfg(feature = "database")]
                BootstrapOperation::DatabaseRole { mount, name, role } => {
                    let database = client.database(mount)?;
                    let status = match database.read_role(name).await {
                        Ok(existing) if database_role_matches_desired(&existing, role) => {
                            BootstrapStepStatus::Unchanged
                        }
                        Ok(_) => {
                            database.write_role(name, role).await?;
                            let verification = database.read_role(name).await?;
                            if !database_role_matches_desired(&verification, role) {
                                return Err(bootstrap_contention_error());
                            }
                            BootstrapStepStatus::Updated
                        }
                        Err(error) if error.is_not_found() => {
                            database.write_role(name, role).await?;
                            let verification = database.read_role(name).await?;
                            if !database_role_matches_desired(&verification, role) {
                                return Err(bootstrap_contention_error());
                            }
                            BootstrapStepStatus::Created
                        }
                        Err(error) => return Err(error),
                    };
                    report.steps.push(BootstrapStepReport::new(
                        "database_role",
                        format!("{mount}/{name}"),
                        status,
                    ));
                }
                #[cfg(feature = "database")]
                BootstrapOperation::DatabaseStaticRole { mount, name, role } => {
                    let database = client.database(mount)?;
                    let status = match database.read_static_role(name).await {
                        Ok(existing) if database_static_role_matches_desired(&existing, role) => {
                            BootstrapStepStatus::Unchanged
                        }
                        Ok(_) => {
                            database.write_static_role(name, role).await?;
                            let verification = database.read_static_role(name).await?;
                            if !database_static_role_matches_desired(&verification, role) {
                                return Err(bootstrap_contention_error());
                            }
                            BootstrapStepStatus::Updated
                        }
                        Err(error) if error.is_not_found() => {
                            database.write_static_role(name, role).await?;
                            let verification = database.read_static_role(name).await?;
                            if !database_static_role_matches_desired(&verification, role) {
                                return Err(bootstrap_contention_error());
                            }
                            BootstrapStepStatus::Created
                        }
                        Err(error) => return Err(error),
                    };
                    report.steps.push(BootstrapStepReport::new(
                        "database_static_role",
                        format!("{mount}/{name}"),
                        status,
                    ));
                }
                #[cfg(feature = "ssh")]
                BootstrapOperation::SshRole {
                    mount,
                    name,
                    request,
                } => {
                    let ssh = client.ssh(mount)?;
                    let status = match ssh.read_role(name).await {
                        Ok(existing) if ssh_role_matches_desired(&existing, request) => {
                            BootstrapStepStatus::Unchanged
                        }
                        Ok(_) => {
                            ssh.write_role(name, request).await?;
                            let verification = ssh.read_role(name).await?;
                            if !ssh_role_matches_desired(&verification, request) {
                                return Err(bootstrap_contention_error());
                            }
                            BootstrapStepStatus::Updated
                        }
                        Err(error) if error.is_not_found() => {
                            ssh.write_role(name, request).await?;
                            let verification = ssh.read_role(name).await?;
                            if !ssh_role_matches_desired(&verification, request) {
                                return Err(bootstrap_contention_error());
                            }
                            BootstrapStepStatus::Created
                        }
                        Err(error) => return Err(error),
                    };
                    report.steps.push(BootstrapStepReport::new(
                        "ssh_role",
                        format!("{mount}/{name}"),
                        status,
                    ));
                }
                #[cfg(feature = "identity")]
                BootstrapOperation::IdentityEntity {
                    mount,
                    name,
                    request,
                } => {
                    let identity = client.identity_at(mount)?;
                    let status = match identity.read_entity_by_name(name).await {
                        Ok(existing) if identity_entity_matches_desired(&existing, request) => {
                            BootstrapStepStatus::Unchanged
                        }
                        Ok(_) => {
                            identity.write_entity_by_name(name, request).await?;
                            let verification = identity.read_entity_by_name(name).await?;
                            if !identity_entity_matches_desired(&verification, request) {
                                return Err(bootstrap_contention_error());
                            }
                            BootstrapStepStatus::Updated
                        }
                        Err(error) if error.is_not_found() => {
                            identity.write_entity_by_name(name, request).await?;
                            let verification = identity.read_entity_by_name(name).await?;
                            if !identity_entity_matches_desired(&verification, request) {
                                return Err(bootstrap_contention_error());
                            }
                            BootstrapStepStatus::Created
                        }
                        Err(error) => return Err(error),
                    };
                    report.steps.push(BootstrapStepReport::new(
                        "identity_entity",
                        format!("{mount}/{name}"),
                        status,
                    ));
                }
                #[cfg(feature = "identity")]
                BootstrapOperation::IdentityGroup {
                    mount,
                    name,
                    request,
                } => {
                    let identity = client.identity_at(mount)?;
                    let status = match identity.read_group_by_name(name).await {
                        Ok(existing) if identity_group_matches_desired(&existing, request) => {
                            BootstrapStepStatus::Unchanged
                        }
                        Ok(_) => {
                            identity.write_group_by_name(name, request).await?;
                            let verification = identity.read_group_by_name(name).await?;
                            if !identity_group_matches_desired(&verification, request) {
                                return Err(bootstrap_contention_error());
                            }
                            BootstrapStepStatus::Updated
                        }
                        Err(error) if error.is_not_found() => {
                            identity.write_group_by_name(name, request).await?;
                            let verification = identity.read_group_by_name(name).await?;
                            if !identity_group_matches_desired(&verification, request) {
                                return Err(bootstrap_contention_error());
                            }
                            BootstrapStepStatus::Created
                        }
                        Err(error) => return Err(error),
                    };
                    report.steps.push(BootstrapStepReport::new(
                        "identity_group",
                        format!("{mount}/{name}"),
                        status,
                    ));
                }
                BootstrapOperation::ServiceToken { name, request } => {
                    let auth = client.token().create(request).await?;
                    report.steps.push(BootstrapStepReport::new(
                        "service_token",
                        name,
                        BootstrapStepStatus::Issued,
                    ));
                    report.issued_tokens.push(BootstrapIssuedToken {
                        name: name.clone(),
                        auth,
                    });
                }
                #[cfg(feature = "approle")]
                BootstrapOperation::AppRoleRole {
                    mount,
                    name,
                    request,
                } => {
                    let admin = client.approle_admin_at(mount)?;
                    let status = match admin.read_role(name).await {
                        Ok(existing) if approle_role_matches_desired(&existing, request) => {
                            BootstrapStepStatus::Unchanged
                        }
                        Ok(_) => {
                            admin.write_role(name, request).await?;
                            let verification = admin.read_role(name).await?;
                            if !approle_role_matches_desired(&verification, request) {
                                return Err(bootstrap_contention_error());
                            }
                            BootstrapStepStatus::Updated
                        }
                        Err(error) if error.is_not_found() => {
                            admin.write_role(name, request).await?;
                            let verification = admin.read_role(name).await?;
                            if !approle_role_matches_desired(&verification, request) {
                                return Err(bootstrap_contention_error());
                            }
                            BootstrapStepStatus::Created
                        }
                        Err(error) => return Err(error),
                    };
                    report.steps.push(BootstrapStepReport::new(
                        "approle_role",
                        format!("{mount}/{name}"),
                        status,
                    ));
                }
                #[cfg(feature = "approle")]
                BootstrapOperation::AppRoleSecretId {
                    name,
                    mount,
                    role_name,
                    request,
                } => {
                    let secret_id = client
                        .approle_admin_at(mount)?
                        .generate_secret_id(role_name, request)
                        .await?;
                    report.steps.push(BootstrapStepReport::new(
                        "approle_secret_id",
                        format!("{mount}/{role_name}/{name}"),
                        BootstrapStepStatus::Issued,
                    ));
                    report
                        .issued_approle_secret_ids
                        .push(BootstrapIssuedAppRoleSecretId {
                            name: name.clone(),
                            secret_id,
                        });
                }
            }
        }
        Ok(report)
    }
}

trait MountDescriptionExt {
    fn with_optional_description(self, description: &Option<String>) -> Self;
}

impl MountDescriptionExt for AuthEnableRequest {
    fn with_optional_description(mut self, description: &Option<String>) -> Self {
        self.description.clone_from(description);
        self
    }
}

impl MountDescriptionExt for MountEnableRequest {
    fn with_optional_description(mut self, description: &Option<String>) -> Self {
        self.description.clone_from(description);
        self
    }
}

async fn ensure_auth_method<F>(
    client: &Client<Authenticated>,
    path: &str,
    expected_type: &str,
    request: F,
) -> Result<BootstrapStepStatus>
where
    F: FnOnce() -> AuthEnableRequest,
{
    let key = format!("{path}/");
    let auth_methods = client.sys().list_auth_methods().await?;
    match auth_methods.get(&key).or_else(|| auth_methods.get(path)) {
        Some(auth) => {
            if auth.backend_type != expected_type {
                return Err(Error::InvalidParameter(format!(
                    "auth method `{path}` exists with type `{}` instead of `{expected_type}`",
                    auth.backend_type
                )));
            }
            Ok(BootstrapStepStatus::Unchanged)
        }
        None => match client.sys().enable_auth_method(path, &request()).await {
            Ok(_) => {
                let auth_methods = client.sys().list_auth_methods().await?;
                let auth = auth_methods
                    .get(&key)
                    .or_else(|| auth_methods.get(path))
                    .ok_or_else(bootstrap_contention_error)?;
                if auth.backend_type != expected_type {
                    return Err(bootstrap_contention_error());
                }
                Ok(BootstrapStepStatus::Created)
            }
            Err(error) if is_already_exists_error(&error) => Ok(BootstrapStepStatus::Unchanged),
            Err(error) => Err(error),
        },
    }
}

async fn preview_auth_method(
    client: &Client<Authenticated>,
    path: &str,
    expected_type: &str,
) -> Result<BootstrapPreviewStatus> {
    let key = format!("{path}/");
    let auth_methods = client.sys().list_auth_methods().await?;
    match auth_methods.get(&key).or_else(|| auth_methods.get(path)) {
        Some(auth) => {
            if auth.backend_type != expected_type {
                return Err(Error::InvalidParameter(format!(
                    "auth method `{path}` exists with type `{}` instead of `{expected_type}`",
                    auth.backend_type
                )));
            }
            Ok(BootstrapPreviewStatus::Unchanged)
        }
        None => Ok(BootstrapPreviewStatus::WouldCreate),
    }
}

async fn ensure_mount<F>(
    client: &Client<Authenticated>,
    path: &str,
    expected_type: &str,
    expected_option: Option<(&str, &str)>,
    request: F,
) -> Result<BootstrapStepStatus>
where
    F: FnOnce() -> MountEnableRequest,
{
    match client.sys().read_mount(path).await {
        Ok(mount) => {
            if mount.backend_type != expected_type {
                return Err(Error::InvalidParameter(format!(
                    "mount `{path}` exists with type `{}` instead of `{expected_type}`",
                    mount.backend_type
                )));
            }
            if let Some((key, value)) = expected_option
                && mount
                    .options
                    .as_ref()
                    .and_then(|options| options.get(key))
                    .map(String::as_str)
                    != Some(value)
            {
                return Err(Error::InvalidParameter(format!(
                    "mount `{path}` exists without required option `{key}={value}`"
                )));
            }
            Ok(BootstrapStepStatus::Unchanged)
        }
        Err(error) if error.is_not_found() => {
            match client.sys().enable_mount(path, &request()).await {
                Ok(_) => {
                    let mount = client.sys().read_mount(path).await?;
                    if mount.backend_type != expected_type {
                        return Err(bootstrap_contention_error());
                    }
                    if let Some((key, value)) = expected_option
                        && mount
                            .options
                            .as_ref()
                            .and_then(|options| options.get(key))
                            .map(String::as_str)
                            != Some(value)
                    {
                        return Err(bootstrap_contention_error());
                    }
                    Ok(BootstrapStepStatus::Created)
                }
                Err(error) if is_already_exists_error(&error) => Ok(BootstrapStepStatus::Unchanged),
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

async fn preview_mount(
    client: &Client<Authenticated>,
    path: &str,
    expected_type: &str,
    expected_option: Option<(&str, &str)>,
) -> Result<BootstrapPreviewStatus> {
    match client.sys().read_mount(path).await {
        Ok(mount) => {
            if mount.backend_type != expected_type {
                return Err(Error::InvalidParameter(format!(
                    "mount `{path}` exists with type `{}` instead of `{expected_type}`",
                    mount.backend_type
                )));
            }
            if let Some((key, value)) = expected_option
                && mount
                    .options
                    .as_ref()
                    .and_then(|options| options.get(key))
                    .map(String::as_str)
                    != Some(value)
            {
                return Err(Error::InvalidParameter(format!(
                    "mount `{path}` exists without required option `{key}={value}`"
                )));
            }
            Ok(BootstrapPreviewStatus::Unchanged)
        }
        Err(error) if error.is_not_found() => Ok(BootstrapPreviewStatus::WouldCreate),
        Err(error) => Err(error),
    }
}

fn is_already_exists_error(error: &Error) -> bool {
    error.is_conflict()
}

fn bootstrap_contention_error() -> Error {
    #[cfg(feature = "tracing")]
    tracing::error!(
        target: "openbao::bootstrap",
        severity = "critical",
        "bootstrap contention detected during post-write verification; rerun with external serialization and investigate concurrent writers"
    );
    Error::BootstrapContention(
        "bootstrap convergence write was overwritten or changed by a concurrent writer; rerun with external serialization and investigate concurrent writers",
    )
}

fn secret_values_equal(current: &str, desired: &str) -> bool {
    constant_time_bounded_bytes_equal(
        current.as_bytes(),
        desired.as_bytes(),
        MAX_BOOTSTRAP_SECRET_VALUE_BYTES,
    )
}

fn policy_rules_equal(current: &str, desired: &str) -> bool {
    constant_time_bounded_bytes_equal(
        current.as_bytes(),
        desired.as_bytes(),
        crate::policy::MAX_POLICY_BYTES,
    )
}

fn constant_time_bounded_bytes_equal(current: &[u8], desired: &[u8], max_bytes: usize) -> bool {
    if current.len() > max_bytes || desired.len() > max_bytes {
        return false;
    }

    let mut equal = Choice::from((current.len() == desired.len()) as u8);
    for index in 0..max_bytes {
        let current_byte = current.get(index).copied().unwrap_or(0);
        let desired_byte = desired.get(index).copied().unwrap_or(0);
        equal &= current_byte.ct_eq(&desired_byte);
    }
    bool::from(equal)
}

fn validate_bootstrap_policy_document(policy: &str) -> Result<()> {
    if policy.len() > crate::policy::MAX_POLICY_BYTES {
        return Err(Error::InvalidParameter(
            "bootstrap ACL policy document exceeds maximum allowed length".into(),
        ));
    }
    Ok(())
}

fn validate_bootstrap_secret_values(values: &BTreeMap<String, SecretString>) -> Result<()> {
    for value in values.values() {
        if value.expose_secret().len() > MAX_BOOTSTRAP_SECRET_VALUE_BYTES {
            return Err(Error::InvalidParameter(
                "bootstrap KV v2 secret value exceeds maximum allowed size".into(),
            ));
        }
    }
    Ok(())
}

fn secret_patch_payload(values: &BTreeMap<String, SecretString>) -> BTreeMap<String, &str> {
    // SECURITY: the temporary map holds references into SecretString storage,
    // not copied secret bytes. The serialized request body is built into a
    // sanitizing buffer before the HTTP transport handoff.
    values
        .iter()
        .map(|(key, value)| (key.clone(), value.expose_secret()))
        .collect()
}

fn policy_matches_desired(existing: &crate::sys::PolicyInfo, desired: &str) -> bool {
    policy_rules_equal(&existing.rules, desired)
        && !existing.allow_slashes_in_identity_templates
        && !existing.allow_wildcards_in_identity_templates
}

#[cfg(feature = "pki")]
fn pki_role_matches_desired(existing: &PkiRole, desired: &PkiRole) -> bool {
    !existing.allow_globs_in_identity_templates
        && desired
            .issuer_ref
            .as_ref()
            .is_none_or(|value| existing.issuer_ref.as_ref() == Some(value))
        && vec_empty_or_equal(&existing.allowed_domains, &desired.allowed_domains)
        && desired
            .allow_subdomains
            .is_none_or(|value| existing.allow_subdomains == Some(value))
        && desired
            .ttl
            .as_ref()
            .is_none_or(|value| existing.ttl.as_ref() == Some(value))
        && desired
            .max_ttl
            .as_ref()
            .is_none_or(|value| existing.max_ttl.as_ref() == Some(value))
        && desired
            .key_type
            .as_ref()
            .is_none_or(|value| existing.key_type.as_ref() == Some(value))
        && desired
            .key_bits
            .is_none_or(|value| existing.key_bits == Some(value))
}

#[cfg(feature = "database")]
fn database_role_matches_desired(existing: &DatabaseRole, desired: &DatabaseRole) -> bool {
    (desired.db_name.is_empty() || existing.db_name == desired.db_name)
        && vec_empty_or_equal(&existing.creation_statements, &desired.creation_statements)
        && desired
            .default_ttl
            .as_ref()
            .is_none_or(|value| existing.default_ttl.as_ref() == Some(value))
        && desired
            .max_ttl
            .as_ref()
            .is_none_or(|value| existing.max_ttl.as_ref() == Some(value))
        && vec_empty_or_equal(
            &existing.revocation_statements,
            &desired.revocation_statements,
        )
        && vec_empty_or_equal(&existing.rollback_statements, &desired.rollback_statements)
        && vec_empty_or_equal(&existing.renew_statements, &desired.renew_statements)
        && desired
            .credential_type
            .as_ref()
            .is_none_or(|value| existing.credential_type.as_ref() == Some(value))
        && map_empty_or_contains(&existing.credential_config, &desired.credential_config)
}

#[cfg(feature = "database")]
fn database_static_role_matches_desired(
    existing: &DatabaseStaticRole,
    desired: &DatabaseStaticRole,
) -> bool {
    (desired.db_name.is_empty() || existing.db_name == desired.db_name)
        && (desired.username.is_empty() || existing.username == desired.username)
        && desired
            .rotation_period
            .as_ref()
            .is_none_or(|value| existing.rotation_period.as_ref() == Some(value))
        && vec_empty_or_equal(&existing.rotation_statements, &desired.rotation_statements)
        && desired
            .credential_type
            .as_ref()
            .is_none_or(|value| existing.credential_type.as_ref() == Some(value))
        && map_empty_or_contains(&existing.credential_config, &desired.credential_config)
}

#[cfg(feature = "ssh")]
fn ssh_role_matches_desired(existing: &SshRoleInfo, desired: &SshRoleRequest) -> bool {
    !existing.allow_commas_in_identity_templates
        && desired
            .default_user
            .as_ref()
            .is_none_or(|value| existing.default_user.as_ref() == Some(value))
        && desired
            .cidr_list
            .as_ref()
            .is_none_or(|value| existing.cidr_list.as_ref() == Some(value))
        && desired
            .port
            .is_none_or(|value| existing.port == Some(value))
        && desired
            .key_type
            .is_none_or(|value| existing.key_type == Some(value))
        && desired
            .allowed_users
            .as_ref()
            .is_none_or(|value| existing.allowed_users.as_ref() == Some(value))
        && desired
            .ttl
            .as_ref()
            .is_none_or(|value| existing.ttl.as_ref() == Some(value))
        && desired
            .max_ttl
            .as_ref()
            .is_none_or(|value| existing.max_ttl.as_ref() == Some(value))
        && desired
            .issuer_ref
            .as_ref()
            .is_none_or(|value| existing.issuer_ref.as_ref() == Some(value))
}

#[cfg(feature = "identity")]
fn identity_entity_matches_desired(
    existing: &IdentityEntityInfo,
    desired: &IdentityEntityRequest,
) -> bool {
    desired
        .name
        .as_ref()
        .is_none_or(|value| existing.name.as_ref() == Some(value))
        && vec_empty_or_equal(&existing.policies, &desired.policies)
        && map_empty_or_contains(&existing.metadata, &desired.metadata)
        && desired
            .disabled
            .is_none_or(|value| existing.disabled == value)
}

#[cfg(feature = "identity")]
fn identity_group_matches_desired(
    existing: &IdentityGroupInfo,
    desired: &IdentityGroupRequest,
) -> bool {
    desired
        .name
        .as_ref()
        .is_none_or(|value| existing.name.as_ref() == Some(value))
        && desired
            .group_type
            .is_none_or(|value| existing.group_type == Some(value))
        && vec_empty_or_equal(&existing.policies, &desired.policies)
        && vec_empty_or_equal(&existing.member_entity_ids, &desired.member_entity_ids)
        && vec_empty_or_equal(&existing.member_group_ids, &desired.member_group_ids)
        && map_empty_or_contains(&existing.metadata, &desired.metadata)
}

#[cfg(feature = "approle")]
fn approle_role_matches_desired(
    existing: &AppRoleRoleRequest,
    desired: &AppRoleRoleRequest,
) -> bool {
    desired
        .bind_secret_id
        .is_none_or(|value| existing.bind_secret_id == Some(value))
        && vec_empty_or_equal(
            &existing.secret_id_bound_cidrs,
            &desired.secret_id_bound_cidrs,
        )
        && desired
            .secret_id_num_uses
            .is_none_or(|value| existing.secret_id_num_uses == Some(value))
        && desired
            .secret_id_ttl
            .as_ref()
            .is_none_or(|value| existing.secret_id_ttl.as_ref() == Some(value))
        && desired
            .local_secret_ids
            .is_none_or(|value| existing.local_secret_ids == Some(value))
        && desired
            .token_ttl
            .as_ref()
            .is_none_or(|value| existing.token_ttl.as_ref() == Some(value))
        && desired
            .token_max_ttl
            .as_ref()
            .is_none_or(|value| existing.token_max_ttl.as_ref() == Some(value))
        && vec_empty_or_equal(&existing.token_policies, &desired.token_policies)
        && vec_empty_or_equal(&existing.token_bound_cidrs, &desired.token_bound_cidrs)
        && desired
            .token_strictly_bind_ip
            .is_none_or(|value| existing.token_strictly_bind_ip == Some(value))
        && desired
            .token_explicit_max_ttl
            .as_ref()
            .is_none_or(|value| existing.token_explicit_max_ttl.as_ref() == Some(value))
        && desired
            .token_no_default_policy
            .is_none_or(|value| existing.token_no_default_policy == Some(value))
        && desired
            .token_num_uses
            .is_none_or(|value| existing.token_num_uses == Some(value))
        && desired
            .token_period
            .as_ref()
            .is_none_or(|value| existing.token_period.as_ref() == Some(value))
        && desired
            .token_type
            .as_ref()
            .is_none_or(|value| existing.token_type.as_ref() == Some(value))
}

fn vec_empty_or_equal(existing: &[String], desired: &[String]) -> bool {
    desired.is_empty() || existing == desired
}

#[cfg(any(feature = "database", feature = "identity"))]
fn map_empty_or_contains(
    existing: &BTreeMap<String, String>,
    desired: &BTreeMap<String, String>,
) -> bool {
    desired
        .iter()
        .all(|(key, value)| existing.get(key) == Some(value))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(deprecated)]

    use std::collections::BTreeMap;

    use secrecy::SecretString;

    #[cfg(feature = "database")]
    use crate::secrets::database::{DatabaseRole, DatabaseStaticRole};
    #[cfg(feature = "identity")]
    use crate::secrets::identity::{
        IdentityEntityInfo, IdentityEntityRequest, IdentityGroupInfo, IdentityGroupRequest,
        IdentityGroupType,
    };
    #[cfg(feature = "pki")]
    use crate::secrets::pki::PkiRole;
    #[cfg(feature = "ssh")]
    use crate::secrets::ssh::{SshRoleInfo, SshRoleKeyType, SshRoleRequest};
    use crate::{
        AclCapability, AclPolicyBuilder, Authenticated, Client, Error, OpenBaoConfig,
        auth::token::TokenCreateRequest,
        bootstrap::{
            AdminBootstrap, BootstrapPreviewReport, BootstrapPreviewStatus, BootstrapPreviewStep,
            BootstrapStepStatus, MAX_BOOTSTRAP_OPERATIONS, is_already_exists_error,
            policy_matches_desired, policy_rules_equal, secret_values_equal,
        },
        secrets::transit::TransitCreateKeyRequest,
    };
    use reqwest::StatusCode;

    #[test]
    fn bootstrap_validates_paths_when_building_plan() {
        let mut bootstrap = AdminBootstrap::new();
        assert!(bootstrap.ensure_kv2_mount("../secret", None).is_err());
        assert!(
            bootstrap
                .ensure_transit_key("transit", "../key", TransitCreateKeyRequest::default())
                .is_err()
        );
        #[cfg(feature = "pki")]
        assert!(bootstrap.ensure_pki_mount("pki/../bad", None).is_err());
        #[cfg(feature = "database")]
        assert!(
            bootstrap
                .ensure_database_role("database", "../role", DatabaseRole::new("postgres"))
                .is_err()
        );
        #[cfg(feature = "ssh")]
        assert!(
            bootstrap
                .ensure_ssh_role(
                    "ssh",
                    "role/../bad",
                    SshRoleRequest::otp("alice", "127.0.0.1/32")
                )
                .is_err()
        );

        let mut oversized_values = BTreeMap::new();
        oversized_values.insert(
            "password".to_owned(),
            SecretString::from("a".repeat(crate::validation::MAX_JSON_OBJECT_BYTES + 1)),
        );
        assert!(
            bootstrap
                .ensure_kv2_secret_values("secret", "app", oversized_values)
                .is_err()
        );

        let oversized_policy = "a".repeat(crate::policy::MAX_POLICY_BYTES + 1);
        assert!(
            bootstrap
                .ensure_policy_document("oversized-policy", oversized_policy)
                .is_err()
        );
    }

    #[test]
    fn issued_token_debug_redacts_auth() {
        let config = OpenBaoConfig::new("http://127.0.0.1:8200")
            .and_then(OpenBaoConfig::allow_localhost_http)
            .unwrap_or_else(|error| panic!("{error}"));
        let client: Client<Authenticated> = Client::from_config(config)
            .unwrap_or_else(|error| panic!("{error}"))
            .with_token(SecretString::from("token"));

        let mut policy = AclPolicyBuilder::new();
        policy
            .allow_path("secret/data/app", [AclCapability::Read])
            .unwrap_or_else(|error| panic!("{error}"));

        let mut values = BTreeMap::new();
        let sensitive_value = ["sensitive-", "value"].concat();
        values.insert(
            "API_KEY".to_owned(),
            SecretString::from(sensitive_value.clone()),
        );

        let mut bootstrap = AdminBootstrap::new();
        bootstrap
            .ensure_policy("app-read", &policy)
            .and_then(|builder| builder.ensure_kv2_secret_values("secret", "app", values))
            .and_then(|builder| {
                builder.issue_service_token(
                    "app",
                    TokenCreateRequest {
                        policies: vec!["app-read".to_owned()],
                        no_default_policy: Some(true),
                        ..TokenCreateRequest::default()
                    },
                )
            })
            .unwrap_or_else(|error| panic!("{error}"));

        let report = format!("{:?}", bootstrap.operations);
        assert!(!report.contains(&sensitive_value));
        let _client = client;
    }

    #[test]
    fn bootstrap_statuses_are_stable_values() {
        assert_eq!(BootstrapStepStatus::Created, BootstrapStepStatus::Created);
        assert_ne!(BootstrapStepStatus::Created, BootstrapStepStatus::Unchanged);
        assert_eq!(
            BootstrapPreviewStatus::WouldCreate,
            BootstrapPreviewStatus::WouldCreate
        );
        assert_ne!(
            BootstrapPreviewStatus::WouldCreate,
            BootstrapPreviewStatus::Unchanged
        );
    }

    #[test]
    fn bootstrap_plan_operation_count_is_bounded() {
        let mut bootstrap = AdminBootstrap::new();
        for index in 0..MAX_BOOTSTRAP_OPERATIONS {
            bootstrap
                .ensure_policy_document(
                    format!("policy-{index}"),
                    "path \"secret/data/app\" { capabilities = [\"read\"] }",
                )
                .unwrap_or_else(|error| panic!("{error}"));
        }
        assert!(
            bootstrap
                .ensure_policy_document(
                    "one-too-many",
                    "path \"secret/data/app\" { capabilities = [\"read\"] }",
                )
                .is_err()
        );
    }

    #[test]
    fn bootstrap_secret_comparison_and_race_errors_are_handled() {
        assert!(secret_values_equal("same-secret", "same-secret"));
        assert!(!secret_values_equal("same-secret", "other-secret"));
        assert!(!secret_values_equal("same-secret", "same-secret-longer"));
        assert!(!secret_values_equal("", "x"));
        assert!(secret_values_equal("", ""));

        let at_limit = "a".repeat(crate::validation::MAX_JSON_OBJECT_BYTES);
        assert!(secret_values_equal(&at_limit, &at_limit));
        let oversized = "a".repeat(crate::validation::MAX_JSON_OBJECT_BYTES + 1);
        assert!(!secret_values_equal(&oversized, &oversized));

        assert!(policy_rules_equal(
            "path \"secret/*\" { capabilities = [\"read\"] }",
            "path \"secret/*\" { capabilities = [\"read\"] }",
        ));
        assert!(!policy_rules_equal(
            "path \"secret/*\" { capabilities = [\"read\"] }",
            "path \"secret/*\" { capabilities = [\"update\"] }",
        ));
        assert!(!policy_rules_equal("path \"a\" {}", "path \"longer\" {}"));
        let policy_at_limit = "a".repeat(crate::policy::MAX_POLICY_BYTES);
        assert!(policy_rules_equal(&policy_at_limit, &policy_at_limit));
        let oversized_policy = "a".repeat(crate::policy::MAX_POLICY_BYTES + 1);
        assert!(!policy_rules_equal(&oversized_policy, &oversized_policy));

        let safe_policy: crate::sys::PolicyInfo = serde_json::from_value(serde_json::json!({
            "name": "app-read",
            "policy": "path \"secret/data/app\" {}"
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(policy_matches_desired(
            &safe_policy,
            "path \"secret/data/app\" {}"
        ));
        let unsafe_slashes: crate::sys::PolicyInfo = serde_json::from_value(serde_json::json!({
            "name": "app-read",
            "policy": "path \"secret/data/app\" {}",
            "allow_slashes_in_identity_templates": true
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!policy_matches_desired(
            &unsafe_slashes,
            "path \"secret/data/app\" {}"
        ));
        let unsafe_wildcards: crate::sys::PolicyInfo = serde_json::from_value(serde_json::json!({
            "name": "app-read",
            "policy": "path \"secret/data/app\" {}",
            "allow_wildcards_in_identity_templates": true
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(!policy_matches_desired(
            &unsafe_wildcards,
            "path \"secret/data/app\" {}"
        ));

        let duplicate = Error::Api {
            status: StatusCode::BAD_REQUEST,
            errors: vec!["path is already in use".to_owned()],
        };
        assert!(is_already_exists_error(&duplicate));

        let unrelated = Error::Api {
            status: StatusCode::BAD_REQUEST,
            errors: vec!["permission denied".to_owned()],
        };
        assert!(!is_already_exists_error(&unrelated));
    }

    #[test]
    #[cfg(feature = "pki")]
    fn pki_role_convergence_compares_desired_fields_only() {
        let existing = PkiRole {
            issuer_ref: Some("issuer-a".to_owned()),
            allowed_domains: vec!["example.com".to_owned()],
            allow_subdomains: Some(true),
            ttl: Some("1h".to_owned()),
            max_ttl: Some("24h".to_owned()),
            key_type: Some("rsa".to_owned()),
            key_bits: Some(3072),
            ..PkiRole::default()
        };
        let desired = PkiRole {
            allowed_domains: vec!["example.com".to_owned()],
            ttl: Some("1h".to_owned()),
            ..PkiRole::default()
        };
        assert!(super::pki_role_matches_desired(&existing, &desired));

        let unsafe_existing = PkiRole {
            allow_globs_in_identity_templates: true,
            ..existing.clone()
        };
        assert!(!super::pki_role_matches_desired(&unsafe_existing, &desired));

        let different = PkiRole {
            allowed_domains: vec!["internal.example.com".to_owned()],
            ..PkiRole::default()
        };
        assert!(!super::pki_role_matches_desired(&existing, &different));
    }

    #[test]
    #[cfg(feature = "database")]
    fn database_role_convergence_compares_desired_fields_only() {
        let existing = DatabaseRole::new("postgres")
            .with_creation_statement("create user")
            .with_creation_statement("grant select");
        let desired = DatabaseRole::new("postgres")
            .with_creation_statement("create user")
            .with_creation_statement("grant select");
        assert!(super::database_role_matches_desired(&existing, &desired));

        let different = DatabaseRole::new("postgres").with_creation_statement("create user");
        assert!(!super::database_role_matches_desired(&existing, &different));

        let existing_static = DatabaseStaticRole {
            rotation_period: Some("24h".to_owned()),
            ..DatabaseStaticRole::new("postgres", "app_user")
        };
        let desired_static = DatabaseStaticRole::new("postgres", "app_user");
        assert!(super::database_static_role_matches_desired(
            &existing_static,
            &desired_static
        ));

        let different_static = DatabaseStaticRole::new("postgres", "other_user");
        assert!(!super::database_static_role_matches_desired(
            &existing_static,
            &different_static
        ));
    }

    #[test]
    #[cfg(feature = "ssh")]
    fn ssh_role_convergence_compares_desired_fields_only() {
        let existing = SshRoleInfo {
            default_user: Some("alice".to_owned()),
            cidr_list: Some("127.0.0.1/32".to_owned()),
            port: None,
            key_type: Some(SshRoleKeyType::Otp),
            allowed_users: None,
            ttl: Some("30m".to_owned()),
            max_ttl: None,
            issuer_ref: None,
            ..SshRoleInfo::default()
        };
        let desired = SshRoleRequest::otp("alice", "127.0.0.1/32");
        assert!(super::ssh_role_matches_desired(&existing, &desired));

        let unsafe_existing = SshRoleInfo {
            allow_commas_in_identity_templates: true,
            ..existing.clone()
        };
        assert!(!super::ssh_role_matches_desired(&unsafe_existing, &desired));

        let different = SshRoleRequest::otp("bob", "127.0.0.1/32");
        assert!(!super::ssh_role_matches_desired(&existing, &different));
    }

    #[test]
    #[cfg(feature = "identity")]
    fn identity_convergence_compares_desired_fields_only() {
        let mut entity_metadata = BTreeMap::new();
        entity_metadata.insert("owner".to_owned(), "platform".to_owned());
        entity_metadata.insert("ignored".to_owned(), "extra".to_owned());
        let existing_entity = IdentityEntityInfo {
            name: Some("app".to_owned()),
            policies: vec!["app-read".to_owned()],
            metadata: entity_metadata,
            disabled: false,
            ..IdentityEntityInfo::default()
        };
        let desired_entity = IdentityEntityRequest::named("app")
            .with_policy("app-read")
            .with_metadata("owner", "platform");
        assert!(super::identity_entity_matches_desired(
            &existing_entity,
            &desired_entity
        ));

        let existing_group = IdentityGroupInfo {
            name: Some("apps".to_owned()),
            group_type: Some(IdentityGroupType::Internal),
            policies: vec!["app-read".to_owned()],
            member_entity_ids: vec!["entity-1".to_owned()],
            ..IdentityGroupInfo::default()
        };
        let desired_group = IdentityGroupRequest::internal("apps")
            .with_policy("app-read")
            .with_member_entity_id("entity-1");
        assert!(super::identity_group_matches_desired(
            &existing_group,
            &desired_group
        ));

        let different_group = IdentityGroupRequest::internal("apps").with_policy("admin");
        assert!(!super::identity_group_matches_desired(
            &existing_group,
            &different_group
        ));
    }

    #[test]
    #[cfg(feature = "identity")]
    fn identity_bootstrap_rejects_mismatched_request_names() {
        let mut bootstrap = AdminBootstrap::new();
        assert!(
            bootstrap
                .ensure_identity_entity("app", IdentityEntityRequest::named("other"))
                .is_err()
        );
        assert!(
            bootstrap
                .ensure_identity_group("apps", IdentityGroupRequest::internal("other"))
                .is_err()
        );
    }

    #[test]
    fn bootstrap_report_helpers_find_issued_and_changed_steps() {
        let report = crate::bootstrap::BootstrapReport {
            steps: vec![
                crate::bootstrap::BootstrapStepReport {
                    target_type: "policy",
                    target: "app".to_owned(),
                    status: BootstrapStepStatus::Unchanged,
                },
                crate::bootstrap::BootstrapStepReport {
                    target_type: "token",
                    target: "app".to_owned(),
                    status: BootstrapStepStatus::Issued,
                },
            ],
            issued_tokens: vec![crate::bootstrap::BootstrapIssuedToken {
                name: "app".to_owned(),
                auth: crate::auth::token::TokenAuth {
                    client_token: SecretString::from("token"),
                    accessor: SecretString::from("accessor"),
                    policies: Vec::new(),
                    token_policies: Vec::new(),
                    metadata: BTreeMap::new(),
                    lease_duration: 3600,
                    renewable: true,
                    entity_id: None,
                    token_type: None,
                    orphan: false,
                },
            }],
            #[cfg(feature = "approle")]
            issued_approle_secret_ids: Vec::new(),
        };

        assert!(report.issued_token("app").is_some());
        assert!(report.issued_token("missing").is_none());
        assert!(!report.is_converged());
        assert_eq!(report.changed_steps().count(), 1);
    }

    #[test]
    fn bootstrap_preview_report_helpers_find_changed_steps() {
        let report = BootstrapPreviewReport {
            steps: vec![
                BootstrapPreviewStep {
                    target_type: "policy",
                    target: "app".to_owned(),
                    status: BootstrapPreviewStatus::Unchanged,
                },
                BootstrapPreviewStep {
                    target_type: "service_token",
                    target: "app".to_owned(),
                    status: BootstrapPreviewStatus::WouldIssue,
                },
            ],
        };

        assert!(!report.is_converged());
        assert_eq!(report.changed_steps().count(), 1);
    }
}
