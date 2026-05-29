//! Authentication methods.

#[cfg(feature = "approle")]
pub mod approle;
#[cfg(feature = "kubernetes-auth")]
pub mod kubernetes;
#[cfg(feature = "token")]
pub mod token;
