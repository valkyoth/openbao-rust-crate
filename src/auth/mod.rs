//! Authentication methods.

#[cfg(feature = "approle")]
pub mod approle;
#[cfg(feature = "token")]
pub mod token;
