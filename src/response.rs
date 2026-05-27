//! Shared OpenBao response envelopes.

use core::fmt;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// Empty JSON payload used for endpoints that do not require a body.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct Empty {}

/// Standard OpenBao response envelope for endpoints that return `data`.
#[derive(Clone, Deserialize)]
pub struct ResponseEnvelope<T> {
    /// Endpoint-specific response data.
    pub data: T,
    /// Lease identifier, when the endpoint returns one.
    #[serde(default = "empty_secret")]
    pub lease_id: SecretString,
    /// Lease duration in seconds.
    #[serde(default)]
    pub lease_duration: u64,
    /// Whether the lease is renewable.
    #[serde(default)]
    pub renewable: bool,
    /// Warnings emitted by OpenBao.
    #[serde(default)]
    pub warnings: Option<Vec<String>>,
}

impl<T: fmt::Debug> fmt::Debug for ResponseEnvelope<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseEnvelope")
            .field("data", &self.data)
            .field("lease_id", &"<redacted>")
            .field("lease_duration", &self.lease_duration)
            .field("renewable", &self.renewable)
            .field("warnings", &self.warnings)
            .finish()
    }
}

fn empty_secret() -> SecretString {
    SecretString::from(String::new())
}

#[derive(Debug, Deserialize)]
pub(crate) struct ErrorEnvelope {
    #[serde(default)]
    pub(crate) errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::ResponseEnvelope;

    #[test]
    fn response_debug_redacts_lease_id() {
        let envelope = ResponseEnvelope {
            data: "ok",
            lease_id: SecretString::from("secret-lease"),
            lease_duration: 30,
            renewable: true,
            warnings: None,
        };

        let debug = format!("{envelope:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-lease"));
    }
}
