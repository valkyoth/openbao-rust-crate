use core::fmt;
use reqwest::{Method, StatusCode};
use sanitization::SecretVec;
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;

use crate::{
    Error, Result,
    sys::{WrappedResponse, WrappingTokenPayload},
};

/// Local execution state, not a claim about server-side approval or rollback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ControlGroupExecutionState {
    /// No execution attempt has passed the local compatibility check.
    Ready,
    /// An attempt started. It may have executed, even after error or cancellation.
    OutcomeUnknown,
    /// A complete accepted response was received and local credentials cleared.
    /// The original operation's response still needs application interpretation.
    ResponseReceived,
}

/// Explicit, one-attempt execution of a potentially deferred request.
///
/// Created by [`WrappedResponse::into_control_group_execution`]. The server
/// determines whether this is actually a control-group token and whether its
/// approvals remain valid. There is no automatic authorization or replay.
/// The original client, authentication and configured namespace remain bound.
///
/// After an attempt begins, this handle cannot execute again, even if denied,
/// expired, cancelled, disconnected or incorrectly decoded. It retains the
/// token on uncertain outcomes for deliberate application recovery; that does
/// not mean the token remains valid. Token copies made outside this handle are
/// not constrained by this local guard. Dropping the handle does not revoke it.
pub struct ControlGroupExecution<'a, T> {
    wrapped: WrappedResponse<'a, T>,
    state: ControlGroupExecutionState,
}

impl<'a, T> WrappedResponse<'a, T> {
    /// Transfers ownership to an explicit deferred-execution handle.
    ///
    /// Use this when the original request is governed by a control-group policy.
    /// OpenBao's wrapping metadata has no reliable control-group discriminator;
    /// conversion is an explicit caller decision, not proof of server state.
    /// Unwrapping can execute the original request, including writes. Review and
    /// authorize separately; no network request occurs during this conversion.
    /// Execution requires a promoted OpenBao 2.7+ compatibility profile.
    /// This new handle cannot track earlier attempts made through the ordinary
    /// wrapper or other token copies. Do not use conversion to retry an
    /// outcome-unknown request without an application-specific recovery decision.
    #[must_use]
    pub fn into_control_group_execution(self) -> ControlGroupExecution<'a, T> {
        let state = if self.consumed {
            ControlGroupExecutionState::ResponseReceived
        } else {
            ControlGroupExecutionState::Ready
        };
        ControlGroupExecution {
            wrapped: self,
            state,
        }
    }
}

impl<T> ControlGroupExecution<'_, T> {
    /// Returns only this handle's local state, not server-side approval status.
    #[must_use]
    pub const fn state(&self) -> ControlGroupExecutionState {
        self.state
    }

    /// Borrows retained credentials for deliberate recovery, not automatic retry.
    #[must_use]
    pub fn token(&self) -> Option<&SecretString> {
        (!self.wrapped.consumed).then_some(&self.wrapped.wrap_info.token)
    }

    /// Borrows the accessor for separate request review and approval.
    #[must_use]
    pub fn accessor(&self) -> Option<&SecretString> {
        self.wrapped.wrap_info.accessor.as_ref()
    }

    fn ensure_ready(&self) -> Result<()> {
        if self.state != ControlGroupExecutionState::Ready {
            return Err(Error::InvalidParameter(
                "control-group execution was already attempted; do not replay automatically".into(),
            ));
        }
        let token = self.wrapped.wrap_info.token.expose_secret();
        // OpenBao interprets an empty body token as the caller's auth token.
        // Never let malformed wrapping metadata silently select that fallback.
        if token.is_empty()
            || token.len() > 64 * 1024
            || !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(Error::InvalidParameter(
                "control-group wrapping token must be 1..=65536 visible ASCII bytes".into(),
            ));
        }
        Ok(())
    }

    /// Attempts execution once, returning the original JSON response bytes.
    ///
    /// A successful no-content response yields an empty sanitizing buffer. Only
    /// HTTP 200/204 are accepted; other statuses have an uncertain execution
    /// outcome and their bodies are discarded without exposing server errors.
    /// The wrapping token must be 1..=65536 visible ASCII bytes; invalid values
    /// fail locally without spending an attempt or falling back to the client's
    /// authentication token.
    /// Response collection uses the client's byte limit and sanitizing storage.
    /// HTTP/TLS and OS copies remain outside the SDK's cleanup guarantee.
    ///
    /// Approval/expiry and token namespace are enforced by OpenBao. No cached
    /// approval result is trusted. Cancellation after the attempt starts leaves
    /// `OutcomeUnknown`, even if the server executed successfully. A local
    /// compatibility rejection leaves `Ready` and sends no execution request.
    pub async fn try_execute_bytes(&mut self) -> Result<SecretVec> {
        self.ensure_ready()?;
        self.wrapped.client.sys().require_control_groups().await?;
        self.execute_after_profile_check().await
    }

    // Kept separate to exercise real transport lifecycle before 2.7 promotion.
    // Production callers must always pass the compatibility check above.
    async fn execute_after_profile_check(&mut self) -> Result<SecretVec> {
        self.ensure_ready()?;
        self.state = ControlGroupExecutionState::OutcomeUnknown;
        let payload = WrappingTokenPayload {
            token: self.wrapped.wrap_info.token.expose_secret(),
        };
        let body = self
            .wrapped
            .client
            .request_registered_secret_json_accepting(
                "/sys/",
                Method::POST,
                "sys/wrapping/unwrap",
                "sys/wrapping/unwrap",
                &[] as &[(&str, &str)],
                Some(&payload),
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await?;
        self.state = ControlGroupExecutionState::ResponseReceived;
        self.wrapped.consumed = true;
        self.wrapped.wrap_info.token = SecretString::from(String::new());
        self.wrapped.wrap_info.accessor = None;
        Ok(body)
    }

    /// Executes once and decodes the entire original response as `T`.
    ///
    /// For data endpoints use `T = ResponseEnvelope<MyData>`; KV v2 retains its
    /// nested data/metadata shape. For no-content operations use
    /// [`Self::try_execute_bytes`] instead. A decode error after receiving an
    /// accepted response does not restore the token or permit another attempt.
    /// Choose secret-aware field types: generic `T` can introduce ordinary
    /// allocations, as can Serde's parser scratch storage.
    pub async fn try_execute(&mut self) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let body = self.try_execute_bytes().await?;
        decode_response(body)
    }
}

fn decode_response<T: DeserializeOwned>(body: SecretVec) -> Result<T> {
    body.with_secret(|bytes| serde_json::from_slice(bytes))
        .map_err(|_| {
            Error::Decode("control-group execution response did not match expected schema".into())
        })
}

impl<T> fmt::Debug for ControlGroupExecution<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlGroupExecution")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, feature = "sensitive-http-test-only"))]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::{
        Client, OpenBaoCompatibilityPolicy, OpenBaoConfig, OpenBaoVersion, response::WrapInfo,
    };
    use core::marker::PhantomData;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread,
        time::Duration,
    };

    fn client(address: std::net::SocketAddr) -> Client<crate::Authenticated> {
        client_with(
            address,
            OpenBaoVersion::new(2, 6, 3),
            Duration::from_secs(3),
        )
    }

    fn client_with(
        address: std::net::SocketAddr,
        version: OpenBaoVersion,
        timeout: Duration,
    ) -> Client<crate::Authenticated> {
        let config = OpenBaoConfig::new(format!("http://{address}"))
            .and_then(OpenBaoConfig::allow_sensitive_local_http_for_tests)
            .and_then(|config| config.namespace("review-team"))
            .and_then(|config| config.timeout(timeout))
            .map(|config| {
                config.compatibility_policy(
                    OpenBaoCompatibilityPolicy::assume(version)
                        .unwrap_or_else(|_| panic!("profile failed")),
                )
            })
            .unwrap_or_else(|_| panic!("config failed"));
        Client::from_config(config)
            .and_then(|client| {
                client.try_with_token(SecretString::from(["fixture-", "client"].concat()))
            })
            .unwrap_or_else(|_| panic!("client failed"))
    }

    fn handle(
        client: &Client<crate::Authenticated>,
    ) -> ControlGroupExecution<'_, serde_json::Value> {
        WrappedResponse {
            client,
            wrap_info: WrapInfo {
                token: SecretString::from(["fixture-", "deferred"].concat()),
                accessor: Some(SecretString::from(["fixture-", "accessor"].concat())),
                ttl: 60,
                creation_time: None,
                creation_path: Some("private/path".into()),
            },
            consumed: false,
            _response: PhantomData,
        }
        .into_control_group_execution()
    }

    fn listener() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").unwrap_or_else(|_| panic!("bind failed"))
    }

    fn receive(stream: &mut TcpStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap_or_else(|_| panic!("timeout failed"));
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            assert!(headers.len() < 16384, "oversized test request");
            let mut byte = [0];
            stream
                .read_exact(&mut byte)
                .unwrap_or_else(|_| panic!("request read failed"));
            headers.push(byte[0]);
        }
        let headers = String::from_utf8(headers).unwrap_or_else(|_| panic!("invalid headers"));
        assert!(headers.starts_with("POST /v1/sys/wrapping/unwrap HTTP/1.1\r\n"));
        assert!(headers.contains("x-vault-namespace: review-team\r\n"));
        assert!(
            !headers.contains("fixture-deferred"),
            "wrapping token entered headers"
        );
        let length: usize = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("missing request length"));
        assert!(length < 16384);
        let mut body = vec![0; length];
        stream
            .read_exact(&mut body)
            .unwrap_or_else(|_| panic!("body read failed"));
        let body: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|_| panic!("invalid body"));
        assert!(
            body["token"].as_str() == Some("fixture-deferred"),
            "incorrect token payload"
        );
    }

    fn no_replay(listener: TcpListener) {
        listener
            .set_nonblocking(true)
            .unwrap_or_else(|_| panic!("nonblocking failed"));
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    #[tokio::test]
    async fn execution_preserves_response_shape_and_blocks_replay() {
        for (status, body, decodable) in [
            (
                "200 OK",
                r#"{"data":{"data":{"secret":"synthetic-value"},"metadata":{"version":2}}}"#,
                true,
            ),
            (
                "200 OK",
                r#"{"data":{"certificate":"synthetic-cert","private_key":"synthetic-key"}}"#,
                true,
            ),
            ("200 OK", "malformed-private-value", false),
            ("204 No Content", "", false),
            ("403 Forbidden", r#"{"errors":["private-error"]}"#, false),
            (
                "400 Bad Request",
                r#"{"errors":["expired-private-token"]}"#,
                false,
            ),
        ] {
            let listener = listener();
            let client = client(
                listener
                    .local_addr()
                    .unwrap_or_else(|_| panic!("address failed")),
            );
            let server = thread::spawn(move || {
                let (mut stream, _) = listener
                    .accept()
                    .unwrap_or_else(|_| panic!("accept failed"));
                receive(&mut stream);
                let reply = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(reply.as_bytes())
                    .unwrap_or_else(|_| panic!("response failed"));
                listener
            });
            let mut execution = handle(&client);
            assert!(!format!("{execution:?}").contains("private/path"));
            let result = execution.execute_after_profile_check().await;
            if status.starts_with('2') {
                let bytes = result.unwrap_or_else(|_| panic!("accepted response failed"));
                assert!(
                    bytes.with_secret(|value| value == body.as_bytes()),
                    "response shape changed"
                );
                assert_eq!(
                    execution.state(),
                    ControlGroupExecutionState::ResponseReceived
                );
                assert!(execution.token().is_none());
                assert!(execution.accessor().is_none());
                let decoded = decode_response::<serde_json::Value>(bytes);
                assert!(decoded.is_ok() == decodable);
                if let Err(error) = decoded {
                    assert!(
                        matches!(error, Error::Decode(message) if message == "control-group execution response did not match expected schema")
                    );
                }
            } else {
                assert!(matches!(result, Err(Error::Api { errors, .. }) if errors.is_empty()));
                assert_eq!(
                    execution.state(),
                    ControlGroupExecutionState::OutcomeUnknown
                );
                assert!(execution.token().is_some());
                assert!(execution.accessor().is_some());
            }
            assert!(execution.try_execute_bytes().await.is_err());
            assert!(execution.execute_after_profile_check().await.is_err());
            no_replay(server.join().unwrap_or_else(|_| panic!("server failed")));
        }
    }

    #[tokio::test]
    async fn execution_cancellation_after_transmission_retains_unknown_state() {
        let listener = listener();
        let client = client(
            listener
                .local_addr()
                .unwrap_or_else(|_| panic!("address failed")),
        );
        let (seen, ready) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener
                .accept()
                .unwrap_or_else(|_| panic!("accept failed"));
            receive(&mut stream);
            seen.send(())
                .unwrap_or_else(|_| panic!("notification failed"));
            wait.recv_timeout(Duration::from_secs(5))
                .unwrap_or_else(|_| panic!("release failed"));
            listener
        });
        let mut execution = handle(&client);
        {
            let future = execution.execute_after_profile_check();
            tokio::pin!(future);
            tokio::select! {
                _ = &mut future => panic!("execution completed before cancellation"),
                result = tokio::time::timeout(Duration::from_secs(3), ready) => {
                    assert!(matches!(result, Ok(Ok(()))));
                }
            }
        }
        assert_eq!(
            execution.state(),
            ControlGroupExecutionState::OutcomeUnknown
        );
        assert!(execution.token().is_some());
        assert!(execution.try_execute().await.is_err());
        release
            .send(())
            .unwrap_or_else(|_| panic!("release failed"));
        no_replay(server.join().unwrap_or_else(|_| panic!("server failed")));
    }

    #[tokio::test]
    async fn execution_profile_rejection_does_not_spend_attempt() {
        let listener = listener();
        for version in crate::openbao_profile_versions() {
            let client = client_with(
                listener
                    .local_addr()
                    .unwrap_or_else(|_| panic!("address failed")),
                *version,
                Duration::from_secs(3),
            );
            let mut execution = handle(&client);
            assert!(matches!(
                execution.try_execute().await,
                Err(Error::UnsupportedOpenBaoCapability {
                    endpoint: "sys.control-group",
                    ..
                })
            ));
            assert_eq!(execution.state(), ControlGroupExecutionState::Ready);
            assert!(execution.token().is_some());
        }
        no_replay(listener);
    }

    #[tokio::test]
    async fn conversion_does_not_restore_a_consumed_wrapper() {
        let listener = listener();
        let client = client(
            listener
                .local_addr()
                .unwrap_or_else(|_| panic!("address failed")),
        );
        let mut original = handle(&client).wrapped;
        original.consumed = true;
        original.wrap_info.token = SecretString::from(String::new());
        original.wrap_info.accessor = None;
        let mut execution = original.into_control_group_execution();
        assert_eq!(
            execution.state(),
            ControlGroupExecutionState::ResponseReceived
        );
        assert!(execution.token().is_none());
        assert!(execution.try_execute().await.is_err());
        no_replay(listener);
    }

    #[tokio::test]
    async fn execution_rejects_invalid_tokens_without_auth_token_fallback() {
        let listener = listener();
        let client = client(
            listener
                .local_addr()
                .unwrap_or_else(|_| panic!("address failed")),
        );
        for value in [
            String::new(),
            "token value".into(),
            "token\r\n".into(),
            "x".repeat(65537),
        ] {
            let mut execution = handle(&client);
            execution.wrapped.wrap_info.token = SecretString::from(value);
            assert!(matches!(
                execution.try_execute_bytes().await,
                Err(Error::InvalidParameter(_))
            ));
            assert!(matches!(
                execution.execute_after_profile_check().await,
                Err(Error::InvalidParameter(_))
            ));
            assert_eq!(execution.state(), ControlGroupExecutionState::Ready);
        }
        let mut execution = handle(&client);
        execution.wrapped.wrap_info.token = SecretString::from("x".repeat(65536));
        assert!(execution.ensure_ready().is_ok());
        no_replay(listener);
    }

    #[tokio::test]
    async fn execution_timeout_and_disconnect_cannot_replay() {
        for timeout in [false, true] {
            let listener = listener();
            let client = client_with(
                listener
                    .local_addr()
                    .unwrap_or_else(|_| panic!("address failed")),
                OpenBaoVersion::new(2, 6, 3),
                Duration::from_secs(2),
            );
            let (release, wait) = std::sync::mpsc::channel();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener
                    .accept()
                    .unwrap_or_else(|_| panic!("accept failed"));
                receive(&mut stream);
                if timeout {
                    wait.recv_timeout(Duration::from_secs(5))
                        .unwrap_or_else(|_| panic!("release failed"));
                }
                listener
            });
            let mut execution = handle(&client);
            let error = execution
                .execute_after_profile_check()
                .await
                .err()
                .unwrap_or_else(|| panic!("failed transport accepted"));
            assert!(
                !format!("{error:?}").contains("fixture-deferred"),
                "error exposed token"
            );
            assert_eq!(
                execution.state(),
                ControlGroupExecutionState::OutcomeUnknown
            );
            assert!(execution.token().is_some());
            assert!(execution.try_execute_bytes().await.is_err());
            if timeout {
                release
                    .send(())
                    .unwrap_or_else(|_| panic!("release failed"));
            }
            no_replay(server.join().unwrap_or_else(|_| panic!("server failed")));
        }
    }
}
