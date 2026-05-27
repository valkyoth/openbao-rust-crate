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
//! The public API starts small in `0.1.0`: AppRole login, direct token auth,
//! KV v2, system health/seal status, and raw JSON calls for advanced users.

#![forbid(unsafe_code)]

mod client;
mod error;
mod path;
mod response;

#[cfg(feature = "approle")]
pub mod auth;
#[cfg(feature = "kv2")]
pub mod secrets;
#[cfg(feature = "sys")]
pub mod sys;

pub use client::{
    Authenticated, Client, ClientBuilder, HeaderMode, HttpPolicy, OpenBao, OpenBaoConfig,
    Unauthenticated,
};
pub use error::{Error, Result};
pub use response::{Empty, ResponseEnvelope};
