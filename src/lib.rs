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
//! direct token auth, token lifecycle helpers, KV v1/v2, Transit, system
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

#[cfg(all(
    feature = "sys",
    feature = "kv2",
    feature = "transit",
    feature = "token"
))]
pub mod bootstrap;
mod client;
mod error;
mod path;
pub mod policy;
mod response;

#[cfg(any(
    feature = "approle",
    feature = "cert-auth",
    feature = "jwt-auth",
    feature = "kubernetes-auth",
    feature = "userpass",
    feature = "token"
))]
pub mod auth;
#[cfg(any(
    feature = "database",
    feature = "kv1",
    feature = "kv2",
    feature = "pki",
    feature = "ssh",
    feature = "totp",
    feature = "transit"
))]
pub mod secrets;
#[cfg(feature = "sys")]
pub mod sys;

pub use client::{
    Authenticated, Client, ClientBuilder, HeaderMode, HttpPolicy, OpenBao, OpenBaoConfig,
    RootCertificateMode, Unauthenticated,
};
pub use error::{Error, Result};
pub use policy::{AclCapability, AclPolicyBuilder};
pub use reqwest::{self, Certificate, Identity, Method, StatusCode, tls};
pub use response::{Empty, ResponseEnvelope};
pub use secrecy::{self, ExposeSecret, SecretString};

/// Common imports for application code using the OpenBao SDK.
pub mod prelude {
    pub use crate::{
        AclCapability, AclPolicyBuilder, Authenticated, Certificate, Client, ClientBuilder, Empty,
        Error, ExposeSecret, HeaderMode, Identity, Method, OpenBao, OpenBaoConfig,
        ResponseEnvelope, Result, SecretString, StatusCode, Unauthenticated,
    };

    #[cfg(all(
        feature = "sys",
        feature = "kv2",
        feature = "transit",
        feature = "token"
    ))]
    pub use crate::bootstrap;

    #[cfg(any(
        feature = "approle",
        feature = "cert-auth",
        feature = "jwt-auth",
        feature = "kubernetes-auth",
        feature = "userpass",
        feature = "token"
    ))]
    pub use crate::auth;
    #[cfg(any(
        feature = "database",
        feature = "kv1",
        feature = "kv2",
        feature = "pki",
        feature = "ssh",
        feature = "totp",
        feature = "transit"
    ))]
    pub use crate::secrets;
    #[cfg(feature = "sys")]
    pub use crate::sys;
}
