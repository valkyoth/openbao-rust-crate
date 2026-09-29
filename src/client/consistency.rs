use super::*;
use crate::compatibility::OpenBaoCompatibilityStatus;
use crate::consistency::{ConsistencyIndex, ConsistencyPolicy};

const REVIEWED_VERSION: OpenBaoVersion = OpenBaoVersion::new(2, 7, 0);

#[cfg(test)]
mod live;

fn require_consistency_profile(report: OpenBaoCompatibilityReport) -> Result<()> {
    // An assumed or newer-server fallback profile cannot establish this contract.
    if report.status() != OpenBaoCompatibilityStatus::Verified
        || !matches!(
            report.policy(),
            Some(
                crate::compatibility::OpenBaoCompatibilityPolicyKind::Exact
                    | crate::compatibility::OpenBaoCompatibilityPolicyKind::AutomaticStrict
            )
        )
        || report.profile_version() != Some(REVIEWED_VERSION)
        || report.detected_version() != Some(REVIEWED_VERSION)
        || !is_routable_profile(REVIEWED_VERSION)
    {
        return Err(Error::InvalidParameter(
            "consistency requires a verified, promoted and reviewed server profile".into(),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct ClusterHealth {
    cluster_id: SecretString,
    version: String,
    initialized: bool,
    sealed: bool,
}

impl Client<Authenticated> {
    /// Creates an independent consistency context for this immutable client.
    ///
    /// Requires a verified, promoted consistency profile. OpenBao 2.7 remains
    /// blocked until onboarding promotion. An unauthenticated TLS health request
    /// discovers the cluster identity; each operation rechecks it. Assumed and
    /// unknown-newer fallback and rolling-range policies are not accepted. Creating another context
    /// intentionally does not permit reuse of this context's captured indices.
    #[cfg(feature = "consistency")]
    pub async fn consistency(&self) -> Result<ConsistencyContext<'_>> {
        require_consistency_profile(self.ensure_compatibility().await?)?;
        Ok(ConsistencyContext {
            client: self,
            cluster: discover_cluster(self).await?,
            identity: Arc::new(()),
        })
    }
}

async fn discover_cluster(client: &Client<Authenticated>) -> Result<SecretString> {
    let url = client.url_for_path("sys/health")?;
    client.require_encrypted_transport_for_sensitive_request(&url)?;
    let response = client
        .send_non_sensitive_json_request(Method::GET, url)
        .await?;
    if !matches!(response.status().as_u16(), 200 | 429 | 472 | 473) {
        return Err(Error::OpenBaoCompatibilityProbe(
            "consistency health unavailable",
        ));
    }
    let health: ClusterHealth = read_json_response(
        response,
        client
            .config
            .max_response_bytes
            .min(MAX_COMPATIBILITY_HEALTH_BYTES),
    )
    .await
    .map_err(|_| Error::OpenBaoCompatibilityProbe("invalid consistency health response"))?;
    let cluster = health.cluster_id.expose_secret();
    if !health.initialized
        || health.sealed
        || health.version.parse::<OpenBaoVersion>().ok() != Some(REVIEWED_VERSION)
        || cluster.is_empty()
        || cluster.len() > 256
        || !cluster.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(Error::OpenBaoCompatibilityProbe(
            "invalid consistency cluster identity or state",
        ));
    }
    Ok(health.cluster_id)
}

/// Explicit consistency metadata scoped to one immutable client and namespace.
///
/// No global last-index tracker is maintained. Concurrent responses must not be
/// ordered by arrival time. This context never retries, including on HTTP 429.
/// Cluster preflight and the operation each use the configured request timeout;
/// this is not a single combined deadline. Cancellation never implies rollback.
///
/// Cluster checks cannot make a preflight and operation atomic. A restored cluster
/// retaining its ID, or a load balancer routing them to different clusters, is
/// outside this guarantee. Use an endpoint serving one trusted cluster. The server
/// itself does not bind indices to namespaces; the SDK enforces context ownership.
pub struct ConsistencyContext<'a> {
    client: &'a Client<Authenticated>,
    cluster: SecretString,
    identity: Arc<()>,
}

/// An index captured by a specific consistency context. Cannot be constructed
/// from unscoped metadata, serialized, or reused in a different context.
pub struct ScopedConsistencyIndex {
    index: ConsistencyIndex,
    identity: Arc<()>,
}

/// Original JSON response plus optional consistency metadata. Absence of an index
/// is normal for reads. Debug never formats the payload or index.
pub struct ConsistencyResponse<T> {
    /// Full original JSON response, not just its `data` field.
    pub response: T,
    /// Index bound to the originating context, when returned by the server.
    pub index: Option<ScopedConsistencyIndex>,
}

impl ConsistencyContext<'_> {
    /// Performs one advanced JSON request with explicit inconsistency behavior.
    ///
    /// Requires `raw-api` and `raw-api-acknowledged`: like the raw client API this
    /// does not perform engine-specific body validation. No caller-supplied HTTP
    /// headers are accepted, so auth, namespace and consistency headers cannot be
    /// overridden. `None` captures metadata without supplying a previous index;
    /// it is not a read-after-write guarantee. Only 200/204 are accepted.
    ///
    /// A malformed or wrong-cluster response index fails even after a successful
    /// write. Such an error must not be interpreted as permission to replay it.
    pub async fn request_json<T, B>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        after: Option<&ScopedConsistencyIndex>,
        policy: ConsistencyPolicy,
    ) -> Result<ConsistencyResponse<T>>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        ensure_public_raw_api_enabled()?;
        require_consistency_profile(self.client.ensure_compatibility().await?)?;
        self.execute(method, path, body, after, policy).await
    }

    fn validate_index(&self, after: Option<&ScopedConsistencyIndex>) -> Result<()> {
        if after.is_some_and(|after| {
            !Arc::ptr_eq(&self.identity, &after.identity)
                || !after.index.matches_cluster(self.cluster.expose_secret())
        }) {
            return Err(Error::InvalidParameter(
                "consistency index belongs to another context".into(),
            ));
        }
        Ok(())
    }

    async fn execute<T, B>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        after: Option<&ScopedConsistencyIndex>,
        policy: ConsistencyPolicy,
    ) -> Result<ConsistencyResponse<T>>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.validate_index(after)?;
        let url = self.client.url_for_path(path)?;
        self.client
            .require_encrypted_transport_for_sensitive_request(&url)?;
        let cluster = discover_cluster(self.client).await?;
        if cluster.expose_secret() != self.cluster.expose_secret() {
            return Err(Error::OpenBaoCompatibilityProbe(
                "consistency cluster changed",
            ));
        }
        let request = self.build_request(method, url, body, after, policy)?;
        let response =
            execute_openbao_http_request(self.client.http_for_sensitive_request(), request).await?;
        let status = response.status();
        if !matches!(status, StatusCode::OK | StatusCode::NO_CONTENT) {
            return Err(Error::Api {
                status,
                errors: Vec::new(),
            });
        }
        let index = ConsistencyIndex::from_headers(response.headers())?;
        if index
            .as_ref()
            .is_some_and(|index| !index.matches_cluster(self.cluster.expose_secret()))
        {
            return Err(Error::Decode(
                "consistency response belongs to another cluster".into(),
            ));
        }
        let payload = if status == StatusCode::NO_CONTENT {
            serde_json::from_str("{}").map_err(|_| {
                Error::Decode("OpenBao response did not match expected schema".into())
            })?
        } else {
            read_json_response(response, self.client.config.max_response_bytes).await?
        };
        Ok(ConsistencyResponse {
            response: payload,
            index: index.map(|index| ScopedConsistencyIndex {
                index,
                identity: Arc::clone(&self.identity),
            }),
        })
    }

    fn build_request<B: Serialize + ?Sized>(
        &self,
        method: Method,
        url: Url,
        body: Option<&B>,
        after: Option<&ScopedConsistencyIndex>,
        policy: ConsistencyPolicy,
    ) -> Result<reqwest::Request> {
        self.validate_index(after)?;
        let mut request = reqwest::Request::new(method, url);
        let headers = request.headers_mut();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert("x-vault-request", HeaderValue::from_static("true"));
        for value in policy.header_values() {
            headers.append("x-vault-inconsistent", HeaderValue::from_static(value));
        }
        if let Some(after) = after {
            headers.insert("x-vault-index", after.index.to_header_value()?);
        }
        if let Some(namespace) = self.client.config.namespace.as_deref() {
            headers.insert("x-vault-namespace", sensitive_header_value(namespace)?);
        }
        let token = self.client.token.as_ref().ok_or(Error::MissingToken)?;
        let (name, value) = token_header_for(
            token,
            self.client.config.header_mode,
            self.client.config.max_auth_token_bytes,
        )?;
        headers.insert(name, value);
        if let Some(body) = body {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            *request.body_mut() = Some(encode_bounded_json_body(
                body,
                self.client.sanitizing_body_buffer(),
            )?);
        }
        Ok(request)
    }
}

impl fmt::Debug for ConsistencyContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsistencyContext").finish_non_exhaustive()
    }
}
impl fmt::Debug for ScopedConsistencyIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedConsistencyIndex")
            .finish_non_exhaustive()
    }
}
impl<T> fmt::Debug for ConsistencyResponse<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsistencyResponse")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::compatibility::OpenBaoCompatibilityPolicyKind;
    use crate::consistency::ConsistencyFallback;

    fn client() -> Client<Authenticated> {
        Client::new("https://localhost")
            .and_then(|client| client.try_with_token(SecretString::from("synthetic-test-token")))
            .unwrap_or_else(|_| panic!("test client failed"))
    }

    fn context(client: &Client<Authenticated>) -> ConsistencyContext<'_> {
        ConsistencyContext {
            client,
            cluster: SecretString::from("test-cluster"),
            identity: Arc::new(()),
        }
    }

    fn encoded_index(cluster: &str) -> SecretString {
        let encoded = base64_ng::STANDARD
            .encode_secret(
                format!(r#"{{"cluster":"{cluster}","value":"opaque-test-index"}}"#).as_bytes(),
            )
            .unwrap_or_else(|_| panic!("encoding failed"));
        SecretString::from(
            encoded
                .try_into_exposed_string()
                .unwrap_or_else(|_| panic!("encoding failed"))
                .into_exposed_unprotected_string_caller_must_zeroize(),
        )
    }

    fn index(context: &ConsistencyContext<'_>) -> ScopedConsistencyIndex {
        ScopedConsistencyIndex {
            index: ConsistencyIndex::from_encoded(encoded_index("test-cluster"))
                .unwrap_or_else(|_| panic!("index failed")),
            identity: Arc::clone(&context.identity),
        }
    }

    #[test]
    fn only_reviewed_verified_profiles_enable_transport() {
        for version in crate::compatibility::openbao_profile_versions() {
            let report = OpenBaoCompatibilityReport::verified(
                OpenBaoCompatibilityPolicyKind::Exact,
                *version,
                None,
            );
            assert_eq!(
                require_consistency_profile(report).is_ok(),
                *version == REVIEWED_VERSION
            );
            assert!(
                require_consistency_profile(OpenBaoCompatibilityReport::assumed(*version)).is_err()
            );
        }
        assert!(require_consistency_profile(OpenBaoCompatibilityReport::unverified()).is_err());
        assert!(
            require_consistency_profile(OpenBaoCompatibilityReport::acknowledged_unknown_newer(
                OpenBaoVersion::new(2, 7, 1),
                REVIEWED_VERSION,
            ))
            .is_err()
        );
        assert!(
            require_consistency_profile(OpenBaoCompatibilityReport::verified(
                OpenBaoCompatibilityPolicyKind::Exact,
                REVIEWED_VERSION,
                None,
            ))
            .is_ok()
        );
    }

    #[tokio::test]
    async fn public_context_and_request_fail_closed_without_promotion() {
        let client = client();
        assert!(client.consistency().await.is_err());
        let context = context(&client);
        assert!(
            context
                .request_json::<serde_json::Value, ()>(
                    Method::GET,
                    "sys/health",
                    None,
                    None,
                    ConsistencyPolicy::Fail
                )
                .await
                .is_err()
        );
    }

    #[test]
    fn scope_and_header_wire_contracts() {
        let client = client();
        let context = context(&client);
        let after = index(&context);
        let request = context
            .build_request(
                Method::POST,
                client.base_url().clone(),
                Some(&serde_json::json!({"value":"synthetic-body"})),
                Some(&after),
                ConsistencyPolicy::AwaitState(ConsistencyFallback::Fail),
            )
            .unwrap_or_else(|_| panic!("request failed"));
        let values: Vec<_> = request
            .headers()
            .get_all("x-vault-inconsistent")
            .iter()
            .collect();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], "await-state");
        assert_eq!(values[1], "fail");
        assert!(request.headers()["x-vault-index"].is_sensitive());
        assert!(request.headers()["x-vault-token"].is_sensitive());
        let foreign = ConsistencyContext {
            client: &client,
            cluster: SecretString::from("test-cluster"),
            identity: Arc::new(()),
        };
        assert!(foreign.validate_index(Some(&after)).is_err());
        let changed = ConsistencyContext {
            client: &client,
            cluster: SecretString::from("other-cluster"),
            identity: Arc::clone(&context.identity),
        };
        assert!(changed.validate_index(Some(&after)).is_err());
        let response = ConsistencyResponse {
            response: SecretString::from("synthetic-payload"),
            index: Some(after),
        };
        assert_eq!(format!("{response:?}"), "ConsistencyResponse { .. }");
        assert_eq!(format!("{context:?}"), "ConsistencyContext { .. }");
    }

    #[test]
    fn request_serialization_is_bounded_and_errors_are_redacted() {
        let config = OpenBaoConfig::new("https://localhost")
            .and_then(|config| config.max_request_bytes(1024))
            .unwrap_or_else(|_| panic!("config failed"));
        let client = Client::from_config(config)
            .and_then(|client| client.try_with_token(SecretString::from("synthetic-test-token")))
            .unwrap_or_else(|_| panic!("client failed"));
        let context = context(&client);
        let result = context.build_request(
            Method::POST,
            client.base_url().clone(),
            Some(&"x".repeat(2048)),
            None,
            ConsistencyPolicy::Fail,
        );
        assert!(result.is_err());
        struct Failing;
        impl Serialize for Failing {
            fn serialize<S: serde::Serializer>(
                &self,
                _: S,
            ) -> core::result::Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("synthetic-sensitive-error"))
            }
        }
        let result = context.build_request(
            Method::POST,
            client.base_url().clone(),
            Some(&Failing),
            None,
            ConsistencyPolicy::Fail,
        );
        let error = result
            .err()
            .unwrap_or_else(|| panic!("serialization succeeded"));
        assert!(!format!("{error:?}").contains("synthetic-sensitive-error"));
    }

    #[cfg(feature = "sensitive-http-test-only")]
    mod transport {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const HEALTH: &str =
            r#"{"cluster_id":"test-cluster","version":"2.7.0","initialized":true,"sealed":false}"#;

        async fn server(
            replies: Vec<(u16, String, String)>,
        ) -> (Client<Authenticated>, tokio::task::JoinHandle<Vec<String>>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|_| panic!("bind failed"));
            let address = listener
                .local_addr()
                .unwrap_or_else(|_| panic!("address failed"));
            let task = tokio::spawn(async move {
                let mut requests = Vec::new();
                for (status, headers, body) in replies {
                    let (mut stream, _) =
                        tokio::time::timeout(Duration::from_secs(5), listener.accept())
                            .await
                            .unwrap_or_else(|_| panic!("accept timed out"))
                            .unwrap_or_else(|_| panic!("accept failed"));
                    let mut request = Vec::new();
                    loop {
                        let mut bytes = [0; 1024];
                        let len =
                            tokio::time::timeout(Duration::from_secs(5), stream.read(&mut bytes))
                                .await
                                .unwrap_or_else(|_| panic!("read timed out"))
                                .unwrap_or_else(|_| panic!("read failed"));
                        assert!(len > 0 && request.len() < 16384);
                        request.extend_from_slice(&bytes[..len]);
                        if request.windows(4).any(|value| value == b"\r\n\r\n") {
                            break;
                        }
                    }
                    requests.push(
                        String::from_utf8(request)
                            .unwrap_or_else(|_| panic!("request utf8 failed")),
                    );
                    let wire = format!(
                        "HTTP/1.1 {status} Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n{headers}\r\n{body}",
                        body.len()
                    );
                    stream
                        .write_all(wire.as_bytes())
                        .await
                        .unwrap_or_else(|_| panic!("write failed"));
                }
                requests
            });
            let config = OpenBaoConfig::new(format!("http://{address}"))
                .and_then(OpenBaoConfig::allow_sensitive_local_http_for_tests)
                .and_then(|config| config.namespace("test-namespace"))
                .unwrap_or_else(|_| panic!("config failed"));
            let client = Client::from_config(config)
                .and_then(|client| {
                    client.try_with_token(SecretString::from("synthetic-test-token"))
                })
                .unwrap_or_else(|_| panic!("client failed"));
            (client, task)
        }

        #[tokio::test]
        async fn capture_then_send_preserves_scope_headers_and_sanitizing_body() {
            let wire = encoded_index("test-cluster");
            let header = format!("x-vault-index: {}\r\n", wire.expose_secret());
            let (client, task) = server(vec![
                (200, String::new(), HEALTH.into()),
                (200, header, "{}".into()),
                (200, String::new(), HEALTH.into()),
                (204, String::new(), String::new()),
            ])
            .await;
            let probe = Arc::new(SanitizingBodyDropProbe::default());
            let client = client.with_sanitizing_body_probe(Arc::clone(&probe));
            let context = context(&client);
            let captured: ConsistencyResponse<serde_json::Value> = context
                .execute(
                    Method::POST,
                    "secret/data/test",
                    Some(&serde_json::json!({"value":"synthetic"})),
                    None,
                    ConsistencyPolicy::Fail,
                )
                .await
                .unwrap_or_else(|_| panic!("capture failed"));
            assert!(captured.index.is_some());
            let read: ConsistencyResponse<serde_json::Value> = context
                .execute::<_, ()>(
                    Method::GET,
                    "secret/data/test",
                    None,
                    captured.index.as_ref(),
                    ConsistencyPolicy::AwaitState(ConsistencyFallback::Fail),
                )
                .await
                .unwrap_or_else(|_| panic!("read failed"));
            assert!(read.index.is_none());
            let requests = task.await.unwrap_or_else(|_| panic!("server failed"));
            assert_eq!(requests.len(), 4);
            assert!(!requests[0].contains("x-vault-token"));
            assert!(requests[3].contains("x-vault-namespace: test-namespace\r\n"));
            assert!(requests[3].contains("x-vault-inconsistent: await-state\r\n"));
            assert!(requests[3].contains("x-vault-inconsistent: fail\r\n"));
            assert!(requests[3].contains("x-vault-index:"));
            use std::sync::atomic::Ordering;
            assert_eq!(probe.http_body_handoffs.load(Ordering::SeqCst), 1);
            assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
            assert!(probe.wipe_events.load(Ordering::SeqCst) >= 1);
            assert!(probe.wiped_initialized_bytes.load(Ordering::SeqCst) > 0);
            assert!(probe.observed_zeroed_before_clear.load(Ordering::SeqCst));
        }

        #[tokio::test]
        async fn rejects_wrong_duplicate_and_malformed_response_indices_and_bodies() {
            let wrong = encoded_index("wrong-cluster");
            let valid = encoded_index("test-cluster");
            for (header, body) in [
                (
                    format!("x-vault-index: {}\r\n", wrong.expose_secret()),
                    "{}",
                ),
                (
                    format!(
                        "x-vault-index: {}\r\nx-vault-index: {}\r\n",
                        valid.expose_secret(),
                        valid.expose_secret()
                    ),
                    "{}",
                ),
                ("x-vault-index: invalid\r\n".into(), "{}"),
                (String::new(), "malformed-private-response"),
            ] {
                let (client, task) = server(vec![
                    (200, String::new(), HEALTH.into()),
                    (200, header, body.into()),
                ])
                .await;
                let context = context(&client);
                let result = context
                    .execute::<serde_json::Value, ()>(
                        Method::GET,
                        "secret/data/test",
                        None,
                        None,
                        ConsistencyPolicy::Fail,
                    )
                    .await;
                assert!(result.is_err());
                assert!(!format!("{result:?}").contains("malformed-private-response"));
                task.await.unwrap_or_else(|_| panic!("server failed"));
            }
        }

        #[tokio::test]
        async fn changed_cluster_rejected_before_authenticated_operation() {
            let (client, task) = server(vec![(
                200,
                String::new(),
                HEALTH.replace("test-cluster", "restored-cluster"),
            )])
            .await;
            let context = context(&client);
            assert!(matches!(
                context
                    .execute::<serde_json::Value, ()>(
                        Method::POST,
                        "secret/data/test",
                        None,
                        None,
                        ConsistencyPolicy::Fail
                    )
                    .await,
                Err(Error::OpenBaoCompatibilityProbe(_))
            ));
            let requests = task.await.unwrap_or_else(|_| panic!("server failed"));
            assert_eq!(requests.len(), 1);
        }

        #[tokio::test]
        async fn oversized_response_still_uses_the_client_limit() {
            let (mut client, task) = server(vec![
                (200, String::new(), HEALTH.into()),
                (200, String::new(), format!("\"{}\"", "x".repeat(2048))),
            ])
            .await;
            client.config.max_response_bytes = 1024;
            let context = context(&client);
            assert!(
                context
                    .execute::<serde_json::Value, ()>(
                        Method::GET,
                        "secret/data/test",
                        None,
                        None,
                        ConsistencyPolicy::Fail
                    )
                    .await
                    .is_err()
            );
            task.await.unwrap_or_else(|_| panic!("server failed"));
        }

        #[tokio::test]
        async fn write_429_does_not_retry_or_expose_server_body() {
            let (client, task) = server(vec![
                (200, String::new(), HEALTH.into()),
                (
                    429,
                    "retry-after: 0\r\n".into(),
                    "sensitive-server-error".into(),
                ),
            ])
            .await;
            let context = context(&client);
            let result = context
                .execute::<serde_json::Value, ()>(
                    Method::POST,
                    "secret/data/test",
                    None,
                    None,
                    ConsistencyPolicy::Fail,
                )
                .await;
            assert!(
                matches!(result, Err(Error::Api { status: StatusCode::TOO_MANY_REQUESTS, ref errors }) if errors.is_empty())
            );
            let requests = task.await.unwrap_or_else(|_| panic!("server failed"));
            assert_eq!(requests.len(), 2);
        }

        #[tokio::test]
        async fn invalid_health_never_reaches_the_authenticated_operation() {
            for health in [
                HEALTH.replace("2.7.0", "2.7.1"),
                HEALTH.replace("\"sealed\":false", "\"sealed\":true"),
                HEALTH.replace("\"initialized\":true", "\"initialized\":false"),
                HEALTH.replace("test-cluster", ""),
                HEALTH.replace(
                    "\"cluster_id\":",
                    "\"cluster_id\":\"duplicate\",\"cluster_id\":",
                ),
            ] {
                let (client, task) = server(vec![(200, String::new(), health)]).await;
                let context = context(&client);
                assert!(
                    context
                        .execute::<serde_json::Value, ()>(
                            Method::POST,
                            "secret/data/test",
                            None,
                            None,
                            ConsistencyPolicy::Fail
                        )
                        .await
                        .is_err()
                );
                assert_eq!(
                    task.await.unwrap_or_else(|_| panic!("server failed")).len(),
                    1
                );
            }
        }

        #[tokio::test]
        async fn timeout_and_cancellation_after_transport_begins_do_not_retry() {
            for cancel in [false, true] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .unwrap_or_else(|_| panic!("bind failed"));
                let address = listener
                    .local_addr()
                    .unwrap_or_else(|_| panic!("address failed"));
                let (started, notification) = tokio::sync::oneshot::channel();
                let server = tokio::spawn(async move {
                    for attempt in 0..2 {
                        let (mut stream, _) =
                            tokio::time::timeout(Duration::from_secs(5), listener.accept())
                                .await
                                .unwrap_or_else(|_| panic!("accept timed out"))
                                .unwrap_or_else(|_| panic!("accept failed"));
                        let mut request = Vec::new();
                        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                            let mut buf = [0; 1024];
                            let count =
                                tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
                                    .await
                                    .unwrap_or_else(|_| panic!("read timed out"))
                                    .unwrap_or_else(|_| panic!("read failed"));
                            assert!(count > 0 && request.len() < 16384);
                            request.extend_from_slice(&buf[..count]);
                        }
                        if attempt == 0 {
                            let reply = format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{HEALTH}",
                                HEALTH.len()
                            );
                            stream
                                .write_all(reply.as_bytes())
                                .await
                                .unwrap_or_else(|_| panic!("health write failed"));
                        } else {
                            // Start a response body, then keep it incomplete until the client drops.
                            stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 1000\r\nconnection: close\r\n\r\n{").await
                                .unwrap_or_else(|_| panic!("response write failed"));
                            let _ = started.send(());
                            let mut byte = [0];
                            let closed = tokio::time::timeout(
                                Duration::from_secs(5),
                                stream.read(&mut byte),
                            )
                            .await
                            .unwrap_or_else(|_| panic!("connection not cancelled"));
                            assert!(matches!(closed, Ok(0) | Err(_)));
                            break;
                        }
                    }
                });
                let config = OpenBaoConfig::new(format!("http://{address}"))
                    .and_then(OpenBaoConfig::allow_sensitive_local_http_for_tests)
                    .and_then(|config| config.timeout(Duration::from_secs(1)))
                    .unwrap_or_else(|_| panic!("config failed"));
                let client = Client::from_config(config)
                    .and_then(|client| {
                        client.try_with_token(SecretString::from("synthetic-test-token"))
                    })
                    .unwrap_or_else(|_| panic!("client failed"));
                let operation = tokio::spawn(async move {
                    context(&client)
                        .execute::<serde_json::Value, ()>(
                            Method::POST,
                            "secret/data/test",
                            None,
                            None,
                            ConsistencyPolicy::Fail,
                        )
                        .await
                });
                tokio::time::timeout(Duration::from_secs(5), notification)
                    .await
                    .unwrap_or_else(|_| panic!("operation did not start"))
                    .unwrap_or_else(|_| panic!("start notification failed"));
                if cancel {
                    operation.abort();
                    assert!(operation.await.is_err_and(|error| error.is_cancelled()));
                } else {
                    assert!(
                        operation
                            .await
                            .unwrap_or_else(|_| panic!("operation panicked"))
                            .is_err()
                    );
                }
                server.await.unwrap_or_else(|_| panic!("server failed"));
            }
        }
    }
}
