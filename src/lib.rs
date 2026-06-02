//! Secure, typed, async Rust SDK for OpenBao.
//!
//! This crate is intentionally conservative:
//!
//! - unsafe Rust is forbidden;
//! - tokens are stored as [`secrecy::SecretString`];
//! - HTTPS is required by default;
//! - OpenBao API URLs are assembled with structured URL path segments;
//! - authentication state is represented in the type system.
//!
//! The public API covers environment-based client construction, AppRole login,
//! direct token auth, LDAP/RADIUS auth, token lifecycle helpers, Cubbyhole,
//! Identity, KV v1/v2, Kubernetes secrets, RabbitMQ secrets, Transit, system
//! health/seal status, dev-only bootstrap, mount management, audit devices,
//! safe exact lease helpers, plugin catalog operations, SSH, TOTP, and raw
//! JSON calls for advanced users.
//!
//! Secret request payloads are serialized through a zeroizing intermediate
//! buffer before handoff to `reqwest`. The HTTP stack still owns a normal body
//! buffer after that handoff, and TLS, kernel, allocator, and device buffers
//! can retain transient copies outside this crate's control. Treat Transit
//! plaintext and other request-body secret material as process-resident during
//! the request lifecycle.

#![forbid(unsafe_code)]

#[cfg(not(any(feature = "rustls-tls", feature = "native-tls")))]
compile_error!("openbao requires either the rustls-tls or native-tls feature");

#[cfg(all(feature = "native-tls", not(feature = "native-tls-acknowledged")))]
compile_error!(
    "The native-tls feature pulls platform TLS/OpenSSL and may weaken transport security guarantees. \
     Add feature \"native-tls-acknowledged\" to confirm you have audited this choice."
);

#[cfg(all(feature = "operator-ops", not(feature = "operator-ops-acknowledged")))]
compile_error!(
    "The operator-ops feature exposes production init, unseal, rekey, and rotate APIs that can return or mutate root, unseal, recovery, and encryption-key material. \
     Add feature \"operator-ops-acknowledged\" to confirm you have audited this choice."
);

#[cfg(all(
    feature = "sys",
    feature = "kv2",
    feature = "transit",
    feature = "token"
))]
pub mod bootstrap;
mod client;
pub mod duration;
mod error;
mod path;
pub mod policy;
mod response;
mod validation;

#[cfg(any(
    feature = "approle",
    feature = "cert-auth",
    feature = "jwt-auth",
    feature = "kubernetes-auth",
    feature = "ldap-auth",
    feature = "radius-auth",
    feature = "userpass",
    feature = "token"
))]
pub mod auth;
#[cfg(any(
    feature = "cubbyhole",
    feature = "database",
    feature = "identity",
    feature = "kv1",
    feature = "kv2",
    feature = "kubernetes",
    feature = "ldap",
    feature = "pki",
    feature = "rabbitmq",
    feature = "ssh",
    feature = "totp",
    feature = "transit"
))]
pub mod secrets;
#[cfg(feature = "sys")]
pub mod sys;

pub use client::{
    Authenticated, Client, ClientBuilder, HeaderMode, HttpPolicy, OpenBao, OpenBaoConfig,
    RootCertificateMode, SharedClient, Unauthenticated,
};
pub use duration::duration_to_bao_string;
pub use error::{Error, Result};
pub use policy::{AclCapability, AclPolicyBuilder};
pub use reqwest::{self, Certificate, Identity, Method, StatusCode, tls};
pub use response::{Empty, ResponseEnvelope};
pub use secrecy::{self, ExposeSecret, SecretString};
pub use serde_json::{self, Value as JsonValue};

/// Common imports for application code using the OpenBao SDK.
pub mod prelude {
    pub use crate::{
        AclCapability, AclPolicyBuilder, Authenticated, Certificate, Client, ClientBuilder, Empty,
        Error, ExposeSecret, HeaderMode, Identity, JsonValue, Method, OpenBao, OpenBaoConfig,
        ResponseEnvelope, Result, SecretString, SharedClient, StatusCode, Unauthenticated,
        duration_to_bao_string,
    };

    #[cfg(all(
        feature = "sys",
        feature = "kv2",
        feature = "transit",
        feature = "token",
        feature = "approle"
    ))]
    pub use crate::bootstrap::BootstrapIssuedAppRoleSecretId;
    #[cfg(all(
        feature = "sys",
        feature = "kv2",
        feature = "transit",
        feature = "token"
    ))]
    pub use crate::bootstrap::{
        AdminBootstrap, BootstrapIssuedToken, BootstrapReport, BootstrapStepReport,
        BootstrapStepStatus,
    };

    #[cfg(any(
        feature = "approle",
        feature = "cert-auth",
        feature = "jwt-auth",
        feature = "kubernetes-auth",
        feature = "ldap-auth",
        feature = "radius-auth",
        feature = "userpass",
        feature = "token"
    ))]
    pub use crate::auth;
    #[cfg(feature = "approle")]
    pub use crate::auth::approle::{
        AppRole, AppRoleAdmin, AppRoleRoleId, AppRoleRoleList, AppRoleRoleRequest, AppRoleSecretId,
        AppRoleSecretIdInfo, AppRoleSecretIdRequest, LoginMetadata,
    };
    #[cfg(feature = "cert-auth")]
    pub use crate::auth::cert::{CertAuth, CertAuthAdmin, CertLoginMetadata, CertRole};
    #[cfg(feature = "jwt-auth")]
    pub use crate::auth::jwt::{JwtAuth, JwtAuthAdmin, JwtLoginMetadata, JwtRole};
    #[cfg(feature = "kubernetes-auth")]
    pub use crate::auth::kubernetes::{
        KubernetesAuth, KubernetesAuthAdmin, KubernetesLoginMetadata, KubernetesRole,
    };
    #[cfg(feature = "ldap-auth")]
    pub use crate::auth::ldap::{
        LdapAuth, LdapAuthAdmin, LdapAuthConfig, LdapAuthLoginMetadata, LdapAuthMappingRequest,
    };
    #[cfg(feature = "radius-auth")]
    pub use crate::auth::radius::{
        RadiusAuth, RadiusAuthAdmin, RadiusConfig, RadiusLoginMetadata, RadiusUserRequest,
    };
    #[cfg(feature = "token")]
    pub use crate::auth::token::{Token, TokenAuth, TokenCreateRequest, TokenInfo};
    #[cfg(feature = "userpass")]
    pub use crate::auth::userpass::{
        UserpassAuth, UserpassAuthAdmin, UserpassLoginMetadata, UserpassUserRequest,
    };
    #[cfg(any(
        feature = "cubbyhole",
        feature = "database",
        feature = "identity",
        feature = "kv1",
        feature = "kv2",
        feature = "kubernetes",
        feature = "ldap",
        feature = "pki",
        feature = "rabbitmq",
        feature = "ssh",
        feature = "totp",
        feature = "transit"
    ))]
    pub use crate::secrets;
    #[cfg(feature = "cubbyhole")]
    pub use crate::secrets::cubbyhole::{Cubbyhole, CubbyholeList};
    #[cfg(feature = "database")]
    pub use crate::secrets::database::{
        Database, DatabaseConnectionConfig, DatabaseCredentials, DatabaseRole,
    };
    #[cfg(feature = "identity")]
    pub use crate::secrets::identity::{
        IdentityAliasInfo, IdentityEntityInfo, IdentityEntityRequest, IdentityGroupInfo,
        IdentityGroupRequest,
    };
    #[cfg(feature = "kubernetes")]
    pub use crate::secrets::kubernetes::{
        KubernetesCredentials, KubernetesCredentialsRequest, KubernetesSecrets,
        KubernetesSecretsConfig, KubernetesSecretsRole,
    };
    #[cfg(feature = "kv1")]
    pub use crate::secrets::kv1::{Kv1, Kv1List};
    #[cfg(feature = "kv2")]
    pub use crate::secrets::kv2::{
        Kv2, Kv2Config, Kv2List, Kv2Metadata, Kv2Secret, Kv2ServiceConfig, Kv2WriteOptions,
        Kv2WriteResponse,
    };
    #[cfg(feature = "ldap")]
    pub use crate::secrets::ldap::{Ldap, LdapConfig, LdapDynamicRole, LdapStaticRole};
    #[cfg(feature = "pki")]
    pub use crate::secrets::pki::{Pki, PkiIssueRequest, PkiRole};
    #[cfg(feature = "rabbitmq")]
    pub use crate::secrets::rabbitmq::{
        RabbitMq, RabbitMqConnectionConfig, RabbitMqCredentials, RabbitMqRole,
    };
    #[cfg(feature = "ssh")]
    pub use crate::secrets::ssh::{Ssh, SshRoleInfo, SshRoleRequest};
    #[cfg(feature = "totp")]
    pub use crate::secrets::totp::{Totp, TotpKeyCreateRequest, TotpKeyInfo};
    #[cfg(feature = "transit")]
    pub use crate::secrets::transit::{
        Transit, TransitCreateKeyRequest, TransitKeyInfo, TransitKeyType,
    };
    #[cfg(feature = "sys")]
    pub use crate::sys::{Capability, CapabilityView, Health, LeaderStatus, Sys};
}
