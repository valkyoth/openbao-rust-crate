//! Idempotent administration bootstrap helpers.
//!
//! This module builds on typed `sys`, KV v2, Transit, and token helpers. It is
//! meant for already-initialized OpenBao clusters. It does not initialize,
//! unseal, rekey, or rotate production seal material.

use core::fmt;
use std::collections::BTreeMap;

use secrecy::{ExposeSecret, SecretString};

use crate::{
    AclPolicyBuilder, Authenticated, Client, Error, Result,
    auth::token::{TokenAuth, TokenCreateRequest},
    path::{validate_mount_path, validate_secret_path},
    secrets::transit::TransitCreateKeyRequest,
    sys::{MountEnableRequest, PolicyWriteRequest},
};

/// Builder for a small, idempotent OpenBao admin bootstrap plan.
#[derive(Clone, Debug, Default)]
pub struct AdminBootstrap {
    operations: Vec<BootstrapOperation>,
}

#[derive(Clone)]
enum BootstrapOperation {
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
}

/// Result of running an [`AdminBootstrap`] plan.
#[derive(Debug, Default)]
pub struct BootstrapReport {
    /// Per-operation status entries.
    pub steps: Vec<BootstrapStepReport>,
    /// Tokens explicitly issued by the plan.
    pub issued_tokens: Vec<BootstrapIssuedToken>,
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
        }
    }
}

impl AdminBootstrap {
    /// Creates an empty admin bootstrap plan.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ensures a KV v2 mount exists at `path`.
    pub fn ensure_kv2_mount(
        &mut self,
        path: impl AsRef<str>,
        description: Option<&str>,
    ) -> Result<&mut Self> {
        let path = validate_mount_path(path.as_ref())?.join("/");
        self.operations.push(BootstrapOperation::Kv2Mount {
            path,
            description: description.map(str::to_owned),
        });
        Ok(self)
    }

    /// Ensures a Transit mount exists at `path`.
    pub fn ensure_transit_mount(
        &mut self,
        path: impl AsRef<str>,
        description: Option<&str>,
    ) -> Result<&mut Self> {
        let path = validate_mount_path(path.as_ref())?.join("/");
        self.operations.push(BootstrapOperation::TransitMount {
            path,
            description: description.map(str::to_owned),
        });
        Ok(self)
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
        self.operations.push(BootstrapOperation::TransitKey {
            mount,
            name,
            request,
        });
        Ok(self)
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
        self.operations.push(BootstrapOperation::Policy {
            name,
            policy: policy.into(),
        });
        Ok(self)
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
        let path = validate_secret_path(path.as_ref())?.join("/");
        self.operations.push(BootstrapOperation::Kv2SecretValues {
            mount,
            path,
            values,
        });
        Ok(self)
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
        self.operations
            .push(BootstrapOperation::ServiceToken { name, request });
        Ok(self)
    }

    /// Runs the bootstrap plan.
    pub async fn run(&self, client: &Client<Authenticated>) -> Result<BootstrapReport> {
        let mut report = BootstrapReport::default();
        for operation in &self.operations {
            match operation {
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
                            client.transit(mount)?.create_key(name, request).await?;
                            BootstrapStepStatus::Created
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
                            config.get(key).map(SecretString::expose_secret)
                                != Some(value.expose_secret())
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
            }
        }
        Ok(report)
    }
}

trait MountDescriptionExt {
    fn with_optional_description(self, description: &Option<String>) -> Self;
}

impl MountDescriptionExt for MountEnableRequest {
    fn with_optional_description(mut self, description: &Option<String>) -> Self {
        self.description.clone_from(description);
        self
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
            client.sys().enable_mount(path, &request()).await?;
            Ok(BootstrapStepStatus::Created)
        }
        Err(error) => Err(error),
    }
}

fn secret_patch_payload(values: &BTreeMap<String, SecretString>) -> BTreeMap<String, &str> {
    values
        .iter()
        .map(|(key, value)| (key.clone(), value.expose_secret()))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use std::collections::BTreeMap;

    use secrecy::SecretString;

    use crate::{
        AclCapability, AclPolicyBuilder, Authenticated, Client, OpenBaoConfig,
        auth::token::TokenCreateRequest,
        bootstrap::{AdminBootstrap, BootstrapStepStatus},
        secrets::transit::TransitCreateKeyRequest,
    };

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
}
