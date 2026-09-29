//! Explicit control-group approval operations for the staged OpenBao 2.7 API.
//!
//! Approval authorizes a deferred request; it does not execute it. Execution
//! occurs when the wrapping token is redeemed. These methods never approve or
//! replay requests automatically. Older, unselected and fallback profiles cannot
//! bypass the unpromoted 2.7 contract.

use core::fmt;
use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

pub(super) mod review;
pub use review::{ControlGroupAuthorization, ControlGroupRequest, ControlGroupRequestData};
mod execution;
pub use execution::{ControlGroupExecution, ControlGroupExecutionState};

use crate::{
    Authenticated, Error, Result,
    compatibility::{OpenBaoVersion, legacy_unverified_profile},
    response::ResponseEnvelope,
    sys::Sys,
};

const MAX_ACCESSOR_BYTES: usize = 4096;

/// Sensitive accessor identifying a control-group wrapping token.
///
/// This is not the wrapping token itself and cannot redeem the request. Keep it
/// confidential: principals with server-granted permissions can use it to review
/// or approve the saved request. Debug never exposes the value.
pub struct ControlGroupAccessor(SecretString);

impl ControlGroupAccessor {
    /// Accepts 1..=4096 bytes of visible ASCII without spaces or controls.
    ///
    /// This validates the local representation, not existence, ownership,
    /// namespace, expiry or authorization; OpenBao enforces those properties.
    pub fn new(value: SecretString) -> Result<Self> {
        let text = value.expose_secret();
        if text.is_empty()
            || text.len() > MAX_ACCESSOR_BYTES
            || !text.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(Error::InvalidParameter(
                "control-group accessor must be bounded visible ASCII".into(),
            ));
        }
        Ok(Self(value))
    }

    /// Explicitly borrows the secret accessor for transfer to an approver.
    #[must_use]
    pub fn as_secret(&self) -> &SecretString {
        &self.0
    }
}

impl fmt::Debug for ControlGroupAccessor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlGroupAccessor")
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct AccessorPayload<'a> {
    accessor: &'a str,
}

/// Whether the server's control-group approval requirements are currently met.
///
/// This is a point-in-time observation, not a transferable authorization grant
/// or a guarantee that a later unwrap succeeds. Approvals can expire. A missing,
/// null, duplicate or non-boolean `approved` field is a decoding error.
#[derive(Debug, Deserialize)]
pub struct ControlGroupApproval {
    /// True only when the server reports that approval requirements are met.
    pub approved: bool,
}

impl Sys<'_, Authenticated> {
    /// Writes a typed control-group ACL policy after requiring a promoted 2.7+
    /// profile. Older/unselected/fallback profiles fail before policy transport.
    ///
    /// This replaces the named policy. It does not authorize a request or create
    /// approving groups. Review other policies, namespace and group membership
    /// before granting tokens access. Server enforcement needs live verification.
    pub async fn write_control_group_policy(
        &self,
        name: &str,
        request: &crate::policy::ControlGroupPolicyWriteRequest,
    ) -> Result<crate::response::Empty> {
        self.require_control_groups().await?;
        self.write_policy(name, &request.request).await
    }

    async fn require_control_groups(&self) -> Result<()> {
        let report = self.client.compatibility_report().await?;
        let version = report
            .profile_version()
            .or_else(legacy_unverified_profile)
            .ok_or(Error::Internal("no control-group compatibility profile"))?;
        if version < OpenBaoVersion::new(2, 7, 0)
            || !matches!(
                report.status(),
                crate::OpenBaoCompatibilityStatus::Verified
                    | crate::OpenBaoCompatibilityStatus::Assumed
            )
        {
            return Err(Error::UnsupportedOpenBaoCapability {
                endpoint: "sys.control-group",
                version,
            });
        }
        Ok(())
    }

    /// Reviews a deferred request using its secret accessor (OpenBao 2.7+).
    ///
    /// Sends an authenticated POST in this client's namespace. This neither
    /// authorizes nor unwraps the request. Treat payload, paths, requester
    /// metadata and authorizer identities as sensitive. Approval is only a
    /// point-in-time observation; expiry and subsequent changes can invalidate it.
    /// Bound violations and malformed responses fail with secret-free errors.
    /// The staged profile must be promoted before dispatch is possible.
    pub async fn read_control_group_request(
        &self,
        accessor: &ControlGroupAccessor,
    ) -> Result<ControlGroupRequest> {
        self.require_control_groups().await?;
        let payload = AccessorPayload {
            accessor: accessor.0.expose_secret(),
        };
        let body = self
            .client
            .request_registered_secret_json_accepting(
                "/sys/",
                Method::POST,
                "sys/control-group/request",
                "sys/control-group/request",
                &[] as &[(&str, &str)],
                Some(&payload),
                &[StatusCode::OK],
            )
            .await?;
        ControlGroupRequest::from_envelope(body)
    }

    /// Explicitly records this principal's approval of a saved request (2.7+).
    ///
    /// Review the original request with the intended requester first. The server
    /// enforces group membership, self-approval restrictions and ACLs; the SDK
    /// does not bypass them. The accessor is sent in a sanitizing JSON body,
    /// never in the URL, using this client's namespace and credentials.
    ///
    /// This does not unwrap or execute the saved request. Cancellation, transport
    /// failure or a malformed response can leave approval outcome unknown; do
    /// not automatically retry or assume failure revoked an approval. Request
    /// review and the approval-aware wrapping lifecycle are separate operations.
    /// The staged profile must be promoted before this method can dispatch.
    pub async fn authorize_control_group(
        &self,
        accessor: &ControlGroupAccessor,
    ) -> Result<ControlGroupApproval> {
        self.require_control_groups().await?;
        let payload = AccessorPayload {
            accessor: accessor.0.expose_secret(),
        };
        let envelope: ResponseEnvelope<ControlGroupApproval> = self
            .client
            .request_sys_json_accepting(
                Method::POST,
                "sys/control-group/authorize",
                Some(&payload),
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    use super::*;

    #[test]
    fn accessor_bounds_redaction_and_wire_shape() {
        let marker = ["fixture", "approval", "accessor"].join("-");
        let accessor = ControlGroupAccessor::new(SecretString::from(marker.clone()))
            .unwrap_or_else(|_| panic!("valid accessor rejected"));
        assert!(!format!("{accessor:?}").contains(&marker));
        assert!(accessor.as_secret().expose_secret() == marker);
        let payload = AccessorPayload {
            accessor: accessor.0.expose_secret(),
        };
        let wire = crate::client::encode_bounded_json(&payload, 8192)
            .unwrap_or_else(|_| panic!("serialization failed"));
        wire.with_secret(|bytes| {
            let decoded: serde_json::Value =
                serde_json::from_slice(bytes).unwrap_or_else(|_| panic!("invalid serialization"));
            assert!(decoded == serde_json::json!({"accessor": marker}));
        });
        for length in [1, MAX_ACCESSOR_BYTES] {
            assert!(ControlGroupAccessor::new(SecretString::from("a".repeat(length))).is_ok());
        }
        for byte in 0_u8..=127 {
            let text = char::from(byte).to_string();
            assert_eq!(
                ControlGroupAccessor::new(SecretString::from(text)).is_ok(),
                (0x21..=0x7e).contains(&byte)
            );
        }
        for text in [
            String::new(),
            "a".repeat(MAX_ACCESSOR_BYTES + 1),
            format!("{marker}\r\n"),
            "has space".into(),
            "\u{7f}".into(),
            "\u{e9}".into(),
        ] {
            let Err(error) = ControlGroupAccessor::new(SecretString::from(text)) else {
                panic!("invalid accessor accepted");
            };
            assert!(!error.to_string().contains(&marker));
            assert!(!format!("{error:?}").contains(&marker));
        }
    }

    #[test]
    fn approval_requires_exact_boolean_and_rejects_duplicates() {
        for approved in [false, true] {
            let value: ControlGroupApproval = serde_json::from_value(
                serde_json::json!({"approved": approved, "future_field": "ignored"}),
            )
            .unwrap_or_else(|_| panic!("valid response rejected"));
            assert_eq!(value.approved, approved);
        }
        for text in [
            "{}",
            r#"{"approved":null}"#,
            r#"{"approved":0}"#,
            r#"{"approved":"true"}"#,
            r#"{"approved":false,"approved":true}"#,
        ] {
            assert!(serde_json::from_str::<ControlGroupApproval>(text).is_err());
        }
    }
}
