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
//! safe exact lease helpers, plugin catalog operations, and raw JSON calls for
//! advanced users.

#![forbid(unsafe_code)]

#[cfg(not(any(feature = "rustls-tls", feature = "native-tls")))]
compile_error!("openbao requires either the rustls-tls or native-tls feature");

#[cfg(all(feature = "native-tls", not(feature = "native-tls-acknowledged")))]
compile_error!(
    "The native-tls feature pulls platform TLS/OpenSSL and may weaken transport security guarantees. \
     Add feature \"native-tls-acknowledged\" to confirm you have audited this choice."
);

mod client;
mod error;
mod path;
mod response;

#[cfg(any(feature = "approle", feature = "token"))]
pub mod auth;
#[cfg(any(feature = "kv1", feature = "kv2"))]
pub mod secrets;
#[cfg(feature = "sys")]
pub mod sys;

pub use client::{
    Authenticated, Client, ClientBuilder, HeaderMode, HttpPolicy, OpenBao, OpenBaoConfig,
    RootCertificateMode, Unauthenticated,
};
pub use error::{Error, Result};
pub use response::{Empty, ResponseEnvelope};
