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
//! direct token auth, LDAP/RADIUS/Kerberos auth, JWT/OIDC browser-flow helpers,
//! token lifecycle and token-role helpers, Cubbyhole, Identity lifecycle,
//! lookup, and merge helpers, KV v1/v2, Kubernetes secrets, RabbitMQ secrets,
//! Transit lifecycle, batch, single-operation cryptography, import/BYOK, and
//! PKI issue/sign/revoke/tidy helpers, system health/readiness, dev-only
//! bootstrap, mount management, audit devices, exact and prefix lease helpers,
//! password policies, resultant ACL inspection, operator-gated root/recovery
//! token ceremonies, in-flight request diagnostics, plugin catalog operations,
//! SSH, TOTP, and raw JSON calls for advanced users.
//! Public raw JSON, byte, and response-wrapping transports require the
//! non-default `raw-api` plus `raw-api-acknowledged` features because they
//! bypass typed endpoint validation and operation-specific feature gates.
//! OIDC browser callback redemption requires the non-default
//! `oidc-get-callback-acknowledged` feature because OpenBao places an
//! authorization code or ID token in the callback URL query string.
//! Selected system endpoints that return non-JSON data, such as Prometheus
//! metrics and capped Raft snapshots, are exposed through typed helpers rather
//! than a public raw-body escape hatch.
//!
//! `AdminBootstrap` performs read-compare-write convergence. Run only one
//! bootstrap plan per OpenBao cluster at a time unless the caller provides an
//! external lock. KV v2 secret convergence uses OpenBao CAS where available,
//! but ACL policies, AppRole settings, and other bootstrap operations still
//! require caller-owned serialization to avoid overwriting concurrent changes.
//!
//! Secret request payloads are serialized through a sanitizing intermediate
//! buffer before handoff to `reqwest`. The HTTP stack still owns a normal body
//! buffer after that handoff, and TLS, kernel, allocator, and device buffers
//! can retain transient copies outside this crate's control. Treat Transit
//! plaintext and other request-body secret material as process-resident during
//! the request lifecycle.
//!
//! With the optional `tracing` feature, request spans include HTTP method,
//! status, and a redacted URL path shape. Bodies, tokens, and namespaces are
//! not logged, but even path shapes can reveal operational activity. Deployments
//! with strict path-confidentiality requirements should suppress debug-level
//! `openbao.request` spans, for example with `EnvFilter::new("openbao=info")`,
//! or install a tracing layer that omits the `path` field.

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
    "The operator-ops feature exposes production init, unseal, rekey, rotate, and PKI root-deletion APIs that can return, mutate, or destroy root, unseal, recovery, and encryption-key material. \
     Add feature \"operator-ops-acknowledged\" to confirm you have audited this choice."
);

#[cfg(all(feature = "radius-auth", not(feature = "radius-auth-acknowledged")))]
compile_error!(
    "The radius-auth feature enables the legacy RADIUS authentication protocol, which relies on MD5-based RADIUS authenticators. \
     RADIUS is not recommended for new or classified deployments; prefer cert-auth, kerberos-auth, or ldap-auth with TLS. \
     Add feature \"radius-auth-acknowledged\" to confirm this compatibility choice was audited and RadSec or equivalent transport protection is enforced."
);

#[cfg(all(
    feature = "transit-import",
    not(feature = "transit-import-acknowledged")
))]
compile_error!(
    "The transit-import feature enables software BYOK wrapping with OpenSSL-managed heap residuals. \
     Prefer HSM-backed wrapping for high-assurance key material. \
     Add feature \"transit-import-acknowledged\" to confirm this software wrapping choice was audited."
);

#[cfg(all(feature = "memory-lock", not(feature = "memory-lock-acknowledged")))]
compile_error!(
    "The memory-lock feature asks sanitization to lock secret buffers out of swap. \
     Review OS mlock/VirtualLock limits, failure behavior, and deployment quotas before enabling it. \
     Add feature \"memory-lock-acknowledged\" to confirm this host-level control was audited."
);

#[cfg(all(feature = "raw-api", not(feature = "raw-api-acknowledged")))]
compile_error!(
    "The raw-api feature exposes generic JSON and byte transports that bypass typed endpoint validation and operation-specific feature gates. \
     Add feature \"raw-api-acknowledged\" only after auditing every deployment-specific raw wrapper."
);

#[cfg(all(
    feature = "sensitive-http-test-only",
    not(feature = "sensitive-http-test-only-acknowledged")
))]
compile_error!(
    "The sensitive-http-test-only feature disables HTTPS enforcement for credential-bearing loopback mock tests. \
     It must never be enabled in production application builds. \
     Add feature \"sensitive-http-test-only-acknowledged\" only for this crate's audited test harness."
);

#[cfg(all(
    feature = "sys",
    feature = "kv2",
    feature = "transit",
    feature = "token"
))]
pub mod bootstrap;
mod client;
pub mod compatibility;
pub mod duration;
mod error;
mod path;
pub mod plugin;
pub mod policy;
#[cfg(feature = "transit")]
pub mod posture;
mod response;
#[cfg(feature = "time")]
pub mod timestamp;
mod validation;

#[cfg(kani)]
mod kani_proofs;

#[cfg(any(
    feature = "approle",
    feature = "cert-auth",
    feature = "jwt-auth",
    feature = "kerberos-auth",
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
    RetryPolicy, RetryableMethod, RootCertificateMode, SharedClient, TlsBackend, Unauthenticated,
};
pub use compatibility::{
    OpenBaoCapabilityAvailability, OpenBaoCapabilityEvidence, OpenBaoCapabilityProfile,
    OpenBaoCapabilityRange, OpenBaoCapabilityStatus, OpenBaoHttpMethod, OpenBaoOperation,
    OpenBaoOperationDisposition, OpenBaoVersion, OpenBaoVersionRequirement, openbao_operation,
    openbao_operations, openbao_profile_versions,
};
pub use duration::{RenewalHint, duration_to_bao_string};
pub use error::{Error, Result};
pub use path::{validate_endpoint_path, validate_mount_path};
pub use plugin::PluginMount;
pub use policy::{AclCapability, AclPolicyBuilder};
#[cfg(feature = "transit")]
pub use posture::{
    FipsPosture, FipsPostureFinding, FipsPostureNote, FipsPostureReport, FipsPostureSeverity,
};
#[cfg(feature = "rustls-tls")]
pub use reqwest::tls::CertificateRevocationList;
pub use reqwest::{self, Certificate, Identity, Method, StatusCode, tls};
pub use response::{
    BoundedStringList, Empty, ListEntries, ListPageOptions, MAX_RESPONSE_STRINGS, ResponseEnvelope,
    deserialize_bounded_string_vec,
};
pub use sanitization::{self, SecretVec, SecureSanitize, sanitize_bytes};
pub use secrecy::{self, ExposeSecret, SecretString};
pub use serde_json::{self, Value as JsonValue};
#[cfg(feature = "time")]
pub use time::{self, OffsetDateTime};
#[cfg(feature = "time")]
pub use timestamp::{
    OptionalTimestampExt, TimestampExt, parse_optional_rfc3339_timestamp, parse_rfc3339_timestamp,
};

/// Common imports for application code using the OpenBao SDK.
pub mod prelude {
    #[cfg(feature = "rustls-tls")]
    pub use crate::CertificateRevocationList;
    pub use crate::{
        AclCapability, AclPolicyBuilder, Authenticated, BoundedStringList, Certificate, Client,
        ClientBuilder, Empty, Error, ExposeSecret, HeaderMode, Identity, JsonValue, ListEntries,
        ListPageOptions, MAX_RESPONSE_STRINGS, Method, OpenBao, OpenBaoCapabilityAvailability,
        OpenBaoCapabilityEvidence, OpenBaoCapabilityProfile, OpenBaoConfig, OpenBaoHttpMethod,
        OpenBaoOperationDisposition, OpenBaoVersion, OpenBaoVersionRequirement, PluginMount,
        RenewalHint, ResponseEnvelope, Result, SecretString, SecretVec, SecureSanitize,
        SharedClient, StatusCode, TlsBackend, Unauthenticated, deserialize_bounded_string_vec,
        duration_to_bao_string, openbao_operation, openbao_operations, openbao_profile_versions,
        validate_endpoint_path, validate_mount_path,
    };
    #[cfg(feature = "transit")]
    pub use crate::{
        FipsPosture, FipsPostureFinding, FipsPostureNote, FipsPostureReport, FipsPostureSeverity,
    };
    #[cfg(feature = "time")]
    pub use crate::{
        OffsetDateTime, OptionalTimestampExt, TimestampExt, parse_optional_rfc3339_timestamp,
        parse_rfc3339_timestamp,
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
        AdminBootstrap, BootstrapIssuedToken, BootstrapPreviewReport, BootstrapPreviewStatus,
        BootstrapPreviewStep, BootstrapReport, BootstrapStepReport, BootstrapStepStatus,
    };

    #[cfg(any(
        feature = "approle",
        feature = "cert-auth",
        feature = "jwt-auth",
        feature = "kerberos-auth",
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
    pub use crate::auth::jwt::{
        JwtAuth, JwtAuthAdmin, JwtLoginMetadata, JwtRole, OidcAuthUrlRequest, OidcAuthUrlResponse,
        OidcCallbackRequest, OidcPollRequest,
    };
    #[cfg(feature = "kerberos-auth")]
    pub use crate::auth::kerberos::{
        KerberosAuth, KerberosAuthAdmin, KerberosConfig, KerberosGroupInfo, KerberosGroupList,
        KerberosGroupRequest, KerberosLdapConfig, KerberosLoginMetadata,
    };
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
    pub use crate::auth::token::{
        Token, TokenAccessorList, TokenAuth, TokenCreateRequest, TokenInfo, TokenRole,
        TokenRoleList,
    };
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
        IdentityAliasInfo, IdentityEntityInfo, IdentityEntityLookupRequest,
        IdentityEntityMergeRequest, IdentityEntityRequest, IdentityGroupInfo,
        IdentityGroupLookupRequest, IdentityGroupRequest,
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
    pub use crate::secrets::pki::{Pki, PkiIssueRequest, PkiRole, PkiTidyRequest, PkiTidyStatus};
    #[cfg(feature = "rabbitmq")]
    pub use crate::secrets::rabbitmq::{
        RabbitMq, RabbitMqConnectionConfig, RabbitMqCredentials, RabbitMqRole,
    };
    #[cfg(feature = "ssh")]
    pub use crate::secrets::ssh::{Ssh, SshRoleInfo, SshRoleRequest};
    #[cfg(feature = "totp")]
    pub use crate::secrets::totp::{Totp, TotpKeyCreateRequest, TotpKeyInfo};
    #[cfg(all(feature = "transit", feature = "transit-import"))]
    pub use crate::secrets::transit::TransitWrappedImportKey;
    #[cfg(feature = "transit")]
    pub use crate::secrets::transit::{
        Transit, TransitBackup, TransitBatchDecryptItem, TransitBatchDecryptRequest,
        TransitBatchDecryptResponse, TransitBatchEncryptItem, TransitBatchEncryptRequest,
        TransitBatchEncryptResponse, TransitBatchRewrapItem, TransitBatchRewrapRequest,
        TransitBatchRewrapResponse, TransitBatchSignItem, TransitBatchSignRequest,
        TransitBatchSignResponse, TransitBatchVerifyItem, TransitBatchVerifyRequest,
        TransitBatchVerifyResponse, TransitByokExport, TransitCacheConfig, TransitCreateKeyRequest,
        TransitCsrRequest, TransitCsrResponse, TransitDecryptRequest, TransitDecryptResponse,
        TransitEncryptRequest, TransitEncryptResponse, TransitExportKeyType, TransitExportResponse,
        TransitGlobalKeyConfig, TransitImportHashFunction, TransitImportRequest,
        TransitImportVersionRequest, TransitKeyInfo, TransitKeyList, TransitKeyType,
        TransitRestoreRequest, TransitSetCertificateRequest, TransitSignRequest,
        TransitSignResponse, TransitTrimRequest, TransitUpdateKeyRequest, TransitVerifyRequest,
        TransitVerifyResponse, TransitWrappingKey,
    };
    #[cfg(feature = "sys")]
    pub use crate::sys::{
        AuditedRequestHeaderConfig, AuditedRequestHeaders, Capability, CapabilityView, CorsConfig,
        CorsConfigRequest, GeneratedPassword, HaNode, HaStatus, Health, KeyStatus, LeaderStatus,
        LeaseCount, LockedUsers, LockedUsersMountAccessor, LockedUsersNamespace, LoggerLevel,
        LoggerLevels, NamespaceInfo, NamespaceList, NamespaceRequest, PasswordPolicy,
        PasswordPolicyList, PasswordPolicyWriteRequest, RaftAutopilotConfig, RaftConfiguration,
        RaftJoinRequest, RaftJoinResponse, RaftPeerRequest, RaftServer, RateLimitQuotaConfig,
        RateLimitQuotaInfo, RateLimitQuotaList, RateLimitQuotaRequest, RemountMigrationInfo,
        RemountRequest, RemountResponse, RemountStatus, ResultantAcl, ResultantAclPath, SealStatus,
        Sys, UiMountDetails, UiMountSummary, UiMounts, UiNamespaces, VersionHistory,
        VersionHistoryEntry, WrappedResponse, WrappingContext,
    };
    #[cfg(all(feature = "sys", feature = "operator-ops"))]
    pub use crate::sys::{
        DecodeTokenRequest, DecodeTokenResponse, InFlightRequest, InFlightRequests,
        OperatorRecoveryKeyBackup, OperatorTokenGenerationStart,
        OperatorTokenGenerationStartRequest, OperatorTokenGenerationStatus,
    };
}
