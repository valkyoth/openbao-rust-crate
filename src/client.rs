//! OpenBao client construction and raw request helpers.

use core::{fmt, marker::PhantomData, time::Duration};
use std::net::IpAddr;

use reqwest::{
    Certificate, Method, StatusCode, Url,
    header::{ACCEPT, CONTENT_TYPE, HeaderName, HeaderValue},
    redirect, tls,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    path::{validate_mount_path, validate_secret_path},
    response::ErrorEnvelope,
};

const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(300);

/// Marker state for clients that do not yet have an authentication token.
#[derive(Clone, Copy, Debug)]
pub struct Unauthenticated;

/// Marker state for clients that carry an authentication token.
#[derive(Clone, Copy, Debug)]
pub struct Authenticated;

/// Backwards-friendly public name for the OpenBao client.
pub type OpenBao<State = Unauthenticated> = Client<State>;

/// Policy for non-TLS HTTP base URLs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpPolicy {
    /// Require `https://` for all OpenBao endpoints.
    HttpsOnly,
    /// Permit plain HTTP only for numeric loopback IPs such as `127.0.0.1` and `[::1]`.
    LocalhostHttpAllowed,
}

/// Authentication header strategy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderMode {
    /// Use the officially documented `X-Vault-Token` header.
    VaultToken,
    /// Use `Authorization: Bearer <token>`.
    Bearer,
}

/// TLS trust root handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootCertificateMode {
    /// Trust platform/built-in roots plus any configured extra roots.
    MergeWithSystem,
    /// Trust only the explicitly configured roots.
    OnlyConfigured,
}

/// Validated OpenBao client configuration.
#[derive(Clone)]
pub struct OpenBaoConfig {
    base_url: Url,
    timeout: Duration,
    connect_timeout: Duration,
    user_agent: String,
    namespace: Option<String>,
    http_policy: HttpPolicy,
    header_mode: HeaderMode,
    min_tls_version: tls::Version,
    root_certificates: Vec<Certificate>,
    root_certificate_mode: RootCertificateMode,
}

impl OpenBaoConfig {
    /// Creates a secure-by-default configuration for an OpenBao server.
    ///
    /// The URL must use HTTPS unless [`Self::allow_localhost_http`] is called.
    pub fn new(base_url: impl AsRef<str>) -> Result<Self> {
        let url = Url::parse(base_url.as_ref())
            .map_err(|error| Error::InvalidBaseUrl(error.to_string()))?;
        Ok(Self {
            base_url: url,
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(5),
            user_agent: "openbao-rust-client".to_owned(),
            namespace: None,
            http_policy: HttpPolicy::HttpsOnly,
            header_mode: HeaderMode::VaultToken,
            min_tls_version: tls::Version::TLS_1_3,
            root_certificates: Vec::new(),
            root_certificate_mode: RootCertificateMode::MergeWithSystem,
        })
    }

    /// Allows plain HTTP only for numeric loopback IP development and tests.
    ///
    /// Hostnames such as `localhost` are intentionally rejected to avoid DNS,
    /// hosts-file, and proxy ambiguity.
    pub fn allow_localhost_http(mut self) -> Result<Self> {
        self.http_policy = HttpPolicy::LocalhostHttpAllowed;
        self.validate()?;
        Ok(self)
    }

    /// Sets a request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            return Err(Error::InvalidTimeout("request timeout must be non-zero"));
        }
        if timeout > MAX_REQUEST_TIMEOUT {
            return Err(Error::InvalidTimeout(
                "request timeout exceeds maximum allowed value",
            ));
        }
        self.timeout = timeout;
        Ok(self)
    }

    /// Sets the TCP/TLS connection establishment timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            return Err(Error::InvalidTimeout("connect timeout must be non-zero"));
        }
        if timeout > MAX_CONNECT_TIMEOUT {
            return Err(Error::InvalidTimeout(
                "connect timeout exceeds maximum allowed value",
            ));
        }
        self.connect_timeout = timeout;
        Ok(self)
    }

    /// Sets the user agent sent to OpenBao.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Sets the `X-Vault-Namespace` header value.
    pub fn namespace(mut self, namespace: impl AsRef<str>) -> Result<Self> {
        self.namespace = Some(validate_mount_path(namespace.as_ref())?.join("/"));
        Ok(self)
    }

    /// Sets the token header strategy.
    pub fn header_mode(mut self, header_mode: HeaderMode) -> Self {
        self.header_mode = header_mode;
        self
    }

    /// Sets the minimum TLS protocol version.
    ///
    /// The default is TLS 1.3. Use [`Self::min_tls_12`] only for audited legacy servers.
    pub fn min_tls_version(mut self, version: tls::Version) -> Self {
        self.min_tls_version = version;
        self
    }

    /// Explicitly permits TLS 1.2 for legacy OpenBao deployments.
    pub fn min_tls_12(self) -> Self {
        self.min_tls_version(tls::Version::TLS_1_2)
    }

    /// Adds a trusted root certificate while keeping platform/built-in roots.
    pub fn add_root_certificate(mut self, certificate: Certificate) -> Self {
        self.root_certificates.push(certificate);
        self.root_certificate_mode = RootCertificateMode::MergeWithSystem;
        self
    }

    /// Uses only the provided root certificates and disables system roots.
    pub fn only_root_certificates(mut self, certificates: Vec<Certificate>) -> Result<Self> {
        if certificates.is_empty() {
            return Err(Error::InvalidTlsConfig(
                "at least one root certificate is required when system roots are disabled".into(),
            ));
        }
        self.root_certificates = certificates;
        self.root_certificate_mode = RootCertificateMode::OnlyConfigured;
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        match self.base_url.scheme() {
            "https" => Ok(()),
            "http"
                if self.http_policy == HttpPolicy::LocalhostHttpAllowed
                    && is_loopback_url(&self.base_url) =>
            {
                Ok(())
            }
            "http" => Err(Error::InvalidBaseUrl(
                "plain HTTP is only allowed for explicit numeric loopback development".into(),
            )),
            scheme => Err(Error::InvalidBaseUrl(format!(
                "unsupported URL scheme `{scheme}`"
            ))),
        }
    }
}

impl fmt::Debug for OpenBaoConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenBaoConfig")
            .field("base_url", &self.base_url)
            .field("timeout", &self.timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("user_agent", &self.user_agent)
            .field("has_namespace", &self.namespace.is_some())
            .field("http_policy", &self.http_policy)
            .field("header_mode", &self.header_mode)
            .field("min_tls_version", &self.min_tls_version)
            .field("root_certificate_count", &self.root_certificates.len())
            .field("root_certificate_mode", &self.root_certificate_mode)
            .finish()
    }
}

/// Builder for [`Client`].
#[derive(Debug)]
pub struct ClientBuilder {
    config: OpenBaoConfig,
}

impl ClientBuilder {
    /// Creates a builder from validated configuration.
    pub fn new(config: OpenBaoConfig) -> Self {
        Self { config }
    }

    /// Builds an unauthenticated OpenBao client.
    pub fn build(self) -> Result<Client<Unauthenticated>> {
        self.config.validate()?;
        let mut builder = reqwest::Client::builder()
            .timeout(self.config.timeout)
            .connect_timeout(self.config.connect_timeout)
            .user_agent(self.config.user_agent.clone())
            .https_only(self.config.http_policy == HttpPolicy::HttpsOnly)
            .redirect(redirect::Policy::none())
            .tls_version_min(self.config.min_tls_version);

        builder = match self.config.root_certificate_mode {
            RootCertificateMode::MergeWithSystem => {
                builder.tls_certs_merge(self.config.root_certificates.clone())
            }
            RootCertificateMode::OnlyConfigured => {
                builder.tls_certs_only(self.config.root_certificates.clone())
            }
        };

        let http = builder.build()?;

        Ok(Client {
            config: self.config,
            http,
            token: None,
            _state: PhantomData,
        })
    }
}

/// Typed OpenBao HTTP client.
pub struct Client<State = Unauthenticated> {
    pub(crate) config: OpenBaoConfig,
    pub(crate) http: reqwest::Client,
    pub(crate) token: Option<SecretString>,
    pub(crate) _state: PhantomData<State>,
}

impl Client<Unauthenticated> {
    /// Creates an unauthenticated client with secure defaults.
    pub fn new(base_url: impl AsRef<str>) -> Result<Self> {
        ClientBuilder::new(OpenBaoConfig::new(base_url)?).build()
    }

    /// Creates an unauthenticated client from explicit configuration.
    pub fn from_config(config: OpenBaoConfig) -> Result<Self> {
        ClientBuilder::new(config).build()
    }

    /// Converts the client into an authenticated client using a known token.
    pub fn with_token(self, token: SecretString) -> Client<Authenticated> {
        Client {
            config: self.config,
            http: self.http,
            token: Some(token),
            _state: PhantomData,
        }
    }
}

impl<State> Client<State> {
    /// Returns the validated base URL.
    pub fn base_url(&self) -> &Url {
        &self.config.base_url
    }

    /// Sends a raw authenticated or unauthenticated JSON request.
    ///
    /// `path` is relative to `/v1`. It is validated and joined as URL path
    /// segments, so callers should pass values such as `sys/health` or
    /// `secret/data/app`.
    pub async fn request_json<T, B>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.request_json_accepting(
            method,
            path,
            body,
            &[StatusCode::OK, StatusCode::NO_CONTENT],
        )
        .await
    }

    pub(crate) async fn request_json_accepting<T, B>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        accepted_statuses: &[StatusCode],
    ) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.request_json_query_accepting(method, path, &[], body, accepted_statuses)
            .await
    }

    #[cfg_attr(not(any(feature = "sys", feature = "kv2")), allow(dead_code))]
    pub(crate) async fn request_json_headers_accepting<T, B>(
        &self,
        method: Method,
        path: &str,
        headers: &[(HeaderName, HeaderValue)],
        body: Option<&B>,
        accepted_statuses: &[StatusCode],
    ) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.request_json_query_headers_accepting(
            method,
            path,
            &[],
            headers,
            body,
            accepted_statuses,
        )
        .await
    }

    pub(crate) async fn request_json_query_accepting<T, B>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&B>,
        accepted_statuses: &[StatusCode],
    ) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.request_json_query_headers_accepting(method, path, query, &[], body, accepted_statuses)
            .await
    }

    async fn request_json_query_headers_accepting<T, B>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        headers: &[(HeaderName, HeaderValue)],
        body: Option<&B>,
        accepted_statuses: &[StatusCode],
    ) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let mut url = self.url_for_path(path)?;
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }
        let mut request = self
            .http
            .request(method, url)
            .header(ACCEPT, "application/json")
            .header("X-Vault-Request", "true");
        for (name, value) in headers {
            request = request.header(name, value);
        }

        if let Some(namespace) = self.config.namespace.as_deref() {
            request = request.header("X-Vault-Namespace", sensitive_header_value(namespace)?);
        }
        if let Some(token) = self.token.as_ref() {
            request = match self.config.header_mode {
                HeaderMode::VaultToken => request.header(
                    "X-Vault-Token",
                    sensitive_header_value(token.expose_secret())?,
                ),
                HeaderMode::Bearer => {
                    let mut bearer = Zeroizing::new(String::with_capacity(
                        "Bearer ".len() + token.expose_secret().len(),
                    ));
                    bearer.push_str("Bearer ");
                    bearer.push_str(token.expose_secret());
                    let value = sensitive_header_value(&bearer)
                        .map_err(|error| Error::InvalidHeader(error.to_string()))?;
                    request.header(reqwest::header::AUTHORIZATION, value)
                }
            };
        }
        if let Some(payload) = body {
            let encoded = Zeroizing::new(
                serde_json::to_vec(payload).map_err(|error| Error::Decode(error.to_string()))?,
            );
            let has_content_type = headers.iter().any(|(name, _value)| *name == CONTENT_TYPE);
            if !has_content_type {
                request = request.header(CONTENT_TYPE, "application/json");
            }
            // SECURITY: this copy is intentionally non-zeroing because
            // reqwest::Body does not accept a Zeroize-on-drop body buffer.
            // The Zeroizing serialization buffer above is cleared; reqwest,
            // TLS, kernel, and device buffers are documented residual risks.
            request = request.body(Vec::from(&encoded[..]));
        }

        let response = request.send().await?;
        let status = response.status();
        if !accepted_statuses.contains(&status) {
            let error = read_json_response::<ErrorEnvelope>(response)
                .await
                .map(|envelope| envelope.errors)
                .unwrap_or_default();
            return Err(Error::Api {
                status,
                errors: error,
            });
        }
        if status == StatusCode::NO_CONTENT {
            return serde_json::from_str("{}").map_err(|error| Error::Decode(error.to_string()));
        }
        read_json_response(response).await
    }

    pub(crate) fn url_for_path(&self, path: &str) -> Result<Url> {
        let mut url = self.config.base_url.clone();
        {
            let mut segments = url.path_segments_mut().map_err(|_| {
                Error::InvalidBaseUrl("base URL cannot be a cannot-be-a-base URL".into())
            })?;
            segments.clear();
            segments.push("v1");
            for segment in validate_secret_path(path)? {
                segments.push(&segment);
            }
        }
        Ok(url)
    }
}

impl<State> fmt::Debug for Client<State> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Client")
            .field("config", &self.config)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

fn is_loopback_url(url: &Url) -> bool {
    match url.host_str() {
        Some(host) => host.parse::<IpAddr>().is_ok_and(|addr| addr.is_loopback()),
        None => false,
    }
}

async fn read_json_response<T>(mut response: reqwest::Response) -> Result<T>
where
    T: DeserializeOwned,
{
    validate_json_content_type(&response)?;

    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(Error::Decode(
            "OpenBao response exceeds 32 MiB limit".into(),
        ));
    }

    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(Error::Decode(
                "OpenBao response exceeds 32 MiB limit".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }

    serde_json::from_slice(&body).map_err(|error| Error::Decode(error.to_string()))
}

fn validate_json_content_type(response: &reqwest::Response) -> Result<()> {
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .ok_or_else(|| Error::Decode("missing content-type header".into()))?;
    let content_type = content_type
        .to_str()
        .map_err(|error| Error::Decode(format!("invalid content-type header: {error}")))?;
    if !content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(Error::Decode(
            "unexpected content-type: expected application/json".into(),
        ));
    }
    Ok(())
}

fn sensitive_header_value(value: &str) -> Result<HeaderValue> {
    let mut header =
        HeaderValue::from_str(value).map_err(|error| Error::InvalidHeader(error.to_string()))?;
    header.set_sensitive(true);
    Ok(header)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::SecretString;

    use super::{Client, OpenBaoConfig};

    #[test]
    fn rejects_http_by_default() {
        assert!(Client::new("http://127.0.0.1:8200").is_err());
    }

    #[test]
    fn allows_explicit_loopback_http() {
        let config = OpenBaoConfig::new("http://127.0.0.1:8200")
            .and_then(OpenBaoConfig::allow_localhost_http)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(Client::from_config(config).is_ok());
    }

    #[test]
    fn allows_full_loopback_range_for_local_http() {
        let config = OpenBaoConfig::new("http://127.0.0.2:8200")
            .and_then(OpenBaoConfig::allow_localhost_http)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(Client::from_config(config).is_ok());
    }

    #[test]
    fn rejects_localhost_hostname_for_local_http() {
        let result = OpenBaoConfig::new("http://localhost:8200")
            .and_then(OpenBaoConfig::allow_localhost_http);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_zero_timeouts() {
        let result = OpenBaoConfig::new("https://bao.example.com")
            .and_then(|config| config.timeout(core::time::Duration::ZERO));
        assert!(result.is_err());

        let result = OpenBaoConfig::new("https://bao.example.com")
            .and_then(|config| config.connect_timeout(core::time::Duration::ZERO));
        assert!(result.is_err());
    }

    #[test]
    fn rejects_excessive_timeouts() {
        let result = OpenBaoConfig::new("https://bao.example.com")
            .and_then(|config| config.timeout(core::time::Duration::from_secs(301)));
        assert!(result.is_err());

        let result = OpenBaoConfig::new("https://bao.example.com")
            .and_then(|config| config.connect_timeout(core::time::Duration::from_secs(301)));
        assert!(result.is_err());
    }

    #[test]
    fn rejects_empty_custom_root_only_store() {
        let result = OpenBaoConfig::new("https://bao.example.com")
            .and_then(|config| config.only_root_certificates(Vec::new()));
        assert!(result.is_err());
    }

    #[test]
    fn debug_redacts_token() {
        let config = OpenBaoConfig::new("http://127.0.0.1:8200")
            .and_then(OpenBaoConfig::allow_localhost_http)
            .unwrap_or_else(|error| panic!("{error}"));
        let client = Client::from_config(config)
            .unwrap_or_else(|error| panic!("{error}"))
            .with_token(SecretString::from("root-token"));
        let debug = format!("{client:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("root-token"));
    }

    #[test]
    fn debug_redacts_namespace() {
        let config = OpenBaoConfig::new("https://bao.example.com")
            .and_then(|config| config.namespace("finance/trading-desk/prod"))
            .unwrap_or_else(|error| panic!("{error}"));
        let debug = format!("{config:?}");
        assert!(debug.contains("has_namespace"));
        assert!(debug.contains("true"));
        assert!(!debug.contains("finance"));
    }
}
