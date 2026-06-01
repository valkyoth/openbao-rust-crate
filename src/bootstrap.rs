//! Idempotent administration bootstrap helpers.
//!
//! This module builds on typed `sys`, KV v2, Transit, and token helpers. It is
//! meant for already-initialized OpenBao clusters. It does not initialize,
//! unseal, rekey, or rotate production seal material.

use core::fmt;
use std::collections::BTreeMap;

use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;

#[cfg(feature = "approle")]
use crate::auth::approle::{AppRoleRoleRequest, AppRoleSecretId, AppRoleSecretIdRequest};
use crate::{
    AclPolicyBuilder, Authenticated, Client, Error, Result,
    auth::token::{TokenAuth, TokenCreateRequest},
    path::{validate_endpoint_path, validate_mount_path},
    secrets::transit::TransitCreateKeyRequest,
    sys::{AuthEnableRequest, MountEnableRequest, PolicyWriteRequest},
};

const MAX_BOOTSTRAP_OPERATIONS: usize = 512;

/// Builder for a small, idempotent OpenBao admin bootstrap plan.
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
pub struct BootstrapReport {
    /// Per-operation status entries.
    pub steps: Vec<BootstrapStepReport>,
    /// Tokens explicitly issued by the plan.
    pub issued_tokens: Vec<BootstrapIssuedToken>,
    /// AppRole SecretIDs explicitly issued by the plan.
    #[cfg(feature = "approle")]
    pub issued_approle_secret_ids: Vec<BootstrapIssuedAppRoleSecretId>,
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
    pub fn ensure_policy(
        &mut self,
        name: impl AsRef<str>,
        policy: &AclPolicyBuilder,
    ) -> Result<&mut Self> {
        self.ensure_policy_document(name, policy.build()?)
    }

    /// Ensures an ACL policy exists and matches an explicit policy document.
    pub fn ensure_policy_document(
        &mut self,
        name: impl AsRef<str>,
        policy: impl Into<String>,
    ) -> Result<&mut Self> {
        let name = validate_mount_path(name.as_ref())?.join("/");
        self.push_operation(BootstrapOperation::Policy {
            name,
            policy: policy.into(),
        })
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
        self.push_operation(BootstrapOperation::Kv2SecretValues {
            mount,
            path,
            values,
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
                        Ok(existing) if existing.rules == *policy => BootstrapStepStatus::Unchanged,
                        Ok(_) => {
                            client
                                .sys()
                                .write_policy(name, &PolicyWriteRequest::new(policy.clone()))
                                .await?;
                            BootstrapStepStatus::Updated
                        }
                        Err(error) if error.is_not_found() => {
                            client
                                .sys()
                                .write_policy(name, &PolicyWriteRequest::new(policy.clone()))
                                .await?;
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
                    let current = match kv.read_service_config(path).await {
                        Ok(config) => Some(config),
                        Err(error) if error.is_not_found() => None,
                        Err(error) => return Err(error),
                    };
                    let needs_patch = current.as_ref().is_none_or(|config| {
                        values.iter().any(|(key, value)| {
                            config.get(key).is_none_or(|current| {
                                !secret_values_equal(current.expose_secret(), value.expose_secret())
                            })
                        })
                    });
                    let status = if needs_patch {
                        kv.patch(path, secret_patch_payload(values)).await?;
                        if current.is_some() {
                            BootstrapStepStatus::Updated
                        } else {
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
                            BootstrapStepStatus::Updated
                        }
                        Err(error) if error.is_not_found() => {
                            admin.write_role(name, request).await?;
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
            Ok(_) => Ok(BootstrapStepStatus::Created),
            Err(error) if is_already_exists_error(&error) => Ok(BootstrapStepStatus::Unchanged),
            Err(error) => Err(error),
        },
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
                Ok(_) => Ok(BootstrapStepStatus::Created),
                Err(error) if is_already_exists_error(&error) => Ok(BootstrapStepStatus::Unchanged),
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

fn is_already_exists_error(error: &Error) -> bool {
    error.is_conflict()
}

fn secret_values_equal(current: &str, desired: &str) -> bool {
    current.as_bytes().ct_eq(desired.as_bytes()).into()
}

fn secret_patch_payload(values: &BTreeMap<String, SecretString>) -> BTreeMap<String, &str> {
    values
        .iter()
        .map(|(key, value)| (key.clone(), value.expose_secret()))
        .collect()
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

#[cfg(feature = "approle")]
fn vec_empty_or_equal(existing: &[String], desired: &[String]) -> bool {
    desired.is_empty() || existing == desired
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(deprecated)]

    use std::collections::BTreeMap;

    use secrecy::SecretString;

    use crate::{
        AclCapability, AclPolicyBuilder, Authenticated, Client, Error, OpenBaoConfig,
        auth::token::TokenCreateRequest,
        bootstrap::{
            AdminBootstrap, BootstrapStepStatus, MAX_BOOTSTRAP_OPERATIONS, is_already_exists_error,
            secret_values_equal,
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
}
