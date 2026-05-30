//! Authentication methods.

#[cfg(feature = "approle")]
pub mod approle;
#[cfg(feature = "cert-auth")]
pub mod cert;
#[cfg(feature = "kubernetes-auth")]
pub mod kubernetes;
#[cfg(feature = "token")]
pub mod token;
#[cfg(feature = "userpass")]
pub mod userpass;
