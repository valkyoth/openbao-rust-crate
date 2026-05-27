//! Shared OpenBao response envelopes.

use serde::{Deserialize, Serialize};

/// Empty JSON payload used for endpoints that do not require a body.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct Empty {}

/// Standard OpenBao response envelope for endpoints that return `data`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResponseEnvelope<T> {
    /// Endpoint-specific response data.
    pub data: T,
    /// Lease identifier, when the endpoint returns one.
    #[serde(default)]
    pub lease_id: String,
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

#[derive(Debug, Deserialize)]
pub(crate) struct ErrorEnvelope {
    #[serde(default)]
    pub(crate) errors: Vec<String>,
}
