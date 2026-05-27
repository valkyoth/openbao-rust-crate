//! System backend helpers.

use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use crate::{Client, Result, response::Empty};

/// System backend handle.
#[derive(Debug)]
pub struct Sys<'a, State> {
    client: &'a Client<State>,
}

/// OpenBao health response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Health {
    /// Whether the node is initialized.
    pub initialized: bool,
    /// Whether the node is sealed.
    pub sealed: bool,
    /// Whether the node is standby.
    #[serde(default)]
    pub standby: bool,
    /// Server version.
    pub version: String,
    /// Cluster name.
    #[serde(default)]
    pub cluster_name: Option<String>,
    /// Cluster identifier.
    #[serde(default)]
    pub cluster_id: Option<String>,
}

/// OpenBao seal status response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealStatus {
    /// Seal type.
    #[serde(rename = "type")]
    pub seal_type: String,
    /// Whether the node is initialized.
    pub initialized: bool,
    /// Whether the node is sealed.
    pub sealed: bool,
    /// Key shares configured for Shamir seal.
    #[serde(default)]
    pub n: Option<u64>,
    /// Key threshold configured for Shamir seal.
    #[serde(default)]
    pub t: Option<u64>,
    /// Progress toward unseal threshold.
    #[serde(default)]
    pub progress: Option<u64>,
    /// Server version.
    pub version: String,
}

impl<State> Client<State> {
    /// Accesses system backend helpers.
    pub fn sys(&self) -> Sys<'_, State> {
        Sys { client: self }
    }
}

impl<State> Sys<'_, State> {
    /// Reads `/sys/health`.
    ///
    /// Health endpoints intentionally return non-200 status codes for standby,
    /// sealed, or uninitialized nodes. Those statuses are accepted and decoded.
    pub async fn health(&self) -> Result<Health> {
        self.client
            .request_json_accepting(
                Method::GET,
                "sys/health",
                Option::<&Empty>::None,
                &[
                    StatusCode::OK,
                    StatusCode::NO_CONTENT,
                    StatusCode::TOO_MANY_REQUESTS,
                    StatusCode::NOT_IMPLEMENTED,
                    StatusCode::SERVICE_UNAVAILABLE,
                    openbao_status(472)?,
                    openbao_status(473)?,
                ],
            )
            .await
    }

    /// Reads `/sys/seal-status`.
    pub async fn seal_status(&self) -> Result<SealStatus> {
        self.client
            .request_json(Method::GET, "sys/seal-status", Option::<&Empty>::None)
            .await
    }
}

fn openbao_status(code: u16) -> Result<StatusCode> {
    StatusCode::from_u16(code)
        .map_err(|_| crate::Error::Internal("invalid OpenBao health status code"))
}
