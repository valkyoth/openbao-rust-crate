//! OpenBao client construction and raw request helpers.

use core::{fmt, marker::PhantomData, time::Duration};
use std::{env, fs, net::IpAddr};

use reqwest::{
    Certificate, Identity, Method, StatusCode, Url,
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
const MIN_RESPONSE_BYTES: usize = 1024;
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(300);
const ADDRESS_ENV_KEYS: &[&str] = &["OPENBAO_ADDR", "BAO_ADDR", "VAULT_ADDR"];
const TOKEN_ENV_KEYS: &[&str] = &["OPENBAO_TOKEN", "BAO_TOKEN", "VAULT_TOKEN"];
const NAMESPACE_ENV_KEYS: &[&str] = &["OPENBAO_NAMESPACE", "BAO_NAMESPACE", "VAULT_NAMESPACE"];
const CA_CERT_ENV_KEYS: &[&str] = &["OPENBAO_CACERT", "BAO_CACERT", "VAULT_CACERT"];
const ROOTS_ONLY_ENV_KEYS: &[&str] = &[
    "OPENBAO_ONLY_ROOT_CERTIFICATES",
    "OPENBAO_TLS_ROOTS_ONLY",
    "BAO_ONLY_ROOT_CERTIFICATES",
    "BAO_TLS_ROOTS_ONLY",
    "VAULT_ONLY_ROOT_CERTIFICATES",
    "VAULT_TLS_ROOTS_ONLY",
];
const LOCAL_HTTP_ENV_KEYS: &[&str] = &[
    "OPENBAO_ALLOW_LOCALHOST_HTTP",
    "BAO_ALLOW_LOCALHOST_HTTP",
    "VAULT_ALLOW_LOCALHOST_HTTP",
];

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
    /// Permit plain HTTP only for the numeric IPv4 `127.0.0.0/8` loopback
    /// block and the numeric IPv6 `::1` loopback address.
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
    max_response_bytes: usize,
    user_agent: String,
    namespace: Option<String>,
    http_policy: HttpPolicy,
    header_mode: HeaderMode,
    min_tls_version: tls::Version,
    root_certificates: Vec<Certificate>,
    root_certificate_mode: RootCertificateMode,
    client_identity: Option<Identity>,
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
            max_response_bytes: MAX_RESPONSE_BYTES,
            user_agent: "openbao-rust-client".to_owned(),
            namespace: None,
            http_policy: HttpPolicy::HttpsOnly,
            header_mode: HeaderMode::VaultToken,
            min_tls_version: tls::Version::TLS_1_3,
            root_certificates: Vec::new(),
            root_certificate_mode: RootCertificateMode::MergeWithSystem,
            client_identity: None,
        })
    }

    /// Creates a client configuration from common OpenBao/Vault environment variables.
    ///
    /// Supported aliases:
    ///
    /// - address: `OPENBAO_ADDR`, `BAO_ADDR`, `VAULT_ADDR`;
    /// - namespace: `OPENBAO_NAMESPACE`, `BAO_NAMESPACE`, `VAULT_NAMESPACE`;
    /// - CA PEM file: `OPENBAO_CACERT`, `BAO_CACERT`, `VAULT_CACERT`;
    /// - root-only trust: `OPENBAO_ONLY_ROOT_CERTIFICATES`,
    ///   `OPENBAO_TLS_ROOTS_ONLY`, `BAO_ONLY_ROOT_CERTIFICATES`,
    ///   `BAO_TLS_ROOTS_ONLY`, `VAULT_ONLY_ROOT_CERTIFICATES`,
    ///   `VAULT_TLS_ROOTS_ONLY`;
    /// - local HTTP opt-in: `OPENBAO_ALLOW_LOCALHOST_HTTP`,
    ///   `BAO_ALLOW_LOCALHOST_HTTP`, `VAULT_ALLOW_LOCALHOST_HTTP`.
    ///
    /// Plain HTTP still requires an explicit local HTTP opt-in and a numeric
    /// loopback host in the `127.0.0.0/8` range or `::1`.
    pub fn from_env() -> Result<Self> {
        openbao_config_from_env_lookup(|key| env::var(key).ok())
    }

    /// Returns the validated base URL.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Allows plain HTTP only for numeric loopback IP development and tests.
    ///
    /// This permits the entire IPv4 `127.0.0.0/8` loopback block and the IPv6
    /// `::1` loopback address. All other hosts still require HTTPS.
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

    /// Sets the maximum decoded OpenBao response body size.
    ///
    /// The default is 32 MiB. Lower this for clients that only call endpoints
    /// with small responses, such as health, token lookup, or narrowly scoped
    /// service configuration reads.
    pub fn max_response_bytes(mut self, bytes: usize) -> Result<Self> {
        if bytes < MIN_RESPONSE_BYTES {
            return Err(Error::InvalidParameter(
                "maximum response size must be at least 1024 bytes".into(),
            ));
        }
        if bytes > MAX_RESPONSE_BYTES {
            return Err(Error::InvalidParameter(
                "maximum response size cannot exceed 32 MiB".into(),
            ));
        }
        self.max_response_bytes = bytes;
        Ok(self)
    }

    /// Sets the user agent sent to OpenBao.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Result<Self> {
        let user_agent = user_agent.into();
        validate_user_agent(&user_agent)?;
        self.user_agent = user_agent;
        Ok(self)
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

    /// Sets the client certificate identity used for mutual TLS.
    ///
    /// TLS certificate auth requires OpenBao's listener to request/verify a
    /// client certificate. Prefer identities loaded from tightly permissioned
    /// files and avoid logging certificate/key parsing errors that include
    /// secret paths.
    pub fn client_identity(mut self, identity: Identity) -> Self {
        self.client_identity = Some(identity);
        self
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
            .field("max_response_bytes", &self.max_response_bytes)
            .field("user_agent", &self.user_agent)
            .field("has_namespace", &self.namespace.is_some())
            .field("http_policy", &self.http_policy)
            .field("header_mode", &self.header_mode)
            .field("min_tls_version", &self.min_tls_version)
            .field("root_certificate_count", &self.root_certificates.len())
            .field("root_certificate_mode", &self.root_certificate_mode)
            .field("has_client_identity", &self.client_identity.is_some())
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
        if let Some(identity) = self.config.client_identity.clone() {
            builder = builder.identity(identity);
        }

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

    /// Creates an unauthenticated client from common OpenBao/Vault environment variables.
    ///
    /// See [`OpenBaoConfig::from_env`] for supported configuration variables.
    pub fn from_env() -> Result<Self> {
        ClientBuilder::new(OpenBaoConfig::from_env()?).build()
    }

    /// Creates an authenticated client from common OpenBao/Vault environment variables.
    ///
    /// The token is read from `OPENBAO_TOKEN`, `BAO_TOKEN`, or `VAULT_TOKEN`,
    /// in that order, and is stored as [`SecretString`].
    pub fn from_env_with_token() -> Result<Client<Authenticated>> {
        let client = Self::from_env()?;
        let token = openbao_token_from_env_lookup(|key| env::var(key).ok())?;
        Ok(client.with_token(token))
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

    #[cfg(any(
        feature = "approle",
        feature = "cert-auth",
        feature = "kubernetes-auth"
    ))]
    pub(crate) fn clone_without_state(&self) -> Client<Unauthenticated> {
        Client {
            config: self.config.clone(),
            http: self.http.clone(),
            token: None,
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
            let error =
                read_json_response::<ErrorEnvelope>(response, self.config.max_response_bytes)
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
        read_json_response(response, self.config.max_response_bytes).await
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

fn validate_user_agent(user_agent: &str) -> Result<()> {
    if user_agent.is_empty() {
        return Err(Error::InvalidParameter(
            "user agent must not be empty".into(),
        ));
    }
    if user_agent.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(Error::InvalidParameter(
            "user agent must not contain control characters".into(),
        ));
    }
    Ok(())
}

fn openbao_config_from_env_lookup<F>(mut lookup: F) -> Result<OpenBaoConfig>
where
    F: FnMut(&str) -> Option<String>,
{
    let (_key, address) = first_env_value(&mut lookup, ADDRESS_ENV_KEYS).ok_or_else(|| {
        Error::InvalidBaseUrl("missing OPENBAO_ADDR, BAO_ADDR, or VAULT_ADDR".into())
    })?;
    let mut config = OpenBaoConfig::new(address)?;

    if env_bool(&mut lookup, LOCAL_HTTP_ENV_KEYS)? {
        config = config.allow_localhost_http()?;
    }

    if let Some((_key, namespace)) = first_env_value(&mut lookup, NAMESPACE_ENV_KEYS) {
        config = config.namespace(namespace)?;
    }

    let cert = match first_env_value(&mut lookup, CA_CERT_ENV_KEYS) {
        Some((_key, path)) => {
            let pem = fs::read(&path).map_err(|error| {
                Error::InvalidTlsConfig(format!(
                    "failed to read configured CA certificate: {error}"
                ))
            })?;
            Some(Certificate::from_pem(&pem).map_err(|error| {
                Error::InvalidTlsConfig(format!(
                    "failed to parse configured CA certificate: {error}"
                ))
            })?)
        }
        None => None,
    };

    if env_bool(&mut lookup, ROOTS_ONLY_ENV_KEYS)? {
        let cert = cert.ok_or_else(|| {
            Error::InvalidTlsConfig(
                "root-only trust requires OPENBAO_CACERT, BAO_CACERT, or VAULT_CACERT".into(),
            )
        })?;
        config = config.only_root_certificates(vec![cert])?;
    } else if let Some(cert) = cert {
        config = config.add_root_certificate(cert);
    }

    config.validate()?;
    Ok(config)
}

fn openbao_token_from_env_lookup<F>(mut lookup: F) -> Result<SecretString>
where
    F: FnMut(&str) -> Option<String>,
{
    first_env_value(&mut lookup, TOKEN_ENV_KEYS)
        .map(|(_key, token)| SecretString::from(token))
        .ok_or(Error::MissingToken)
}

fn first_env_value<F>(lookup: &mut F, keys: &[&'static str]) -> Option<(&'static str, String)>
where
    F: FnMut(&str) -> Option<String>,
{
    keys.iter().find_map(|key| {
        lookup(key)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .map(|value| (*key, value))
    })
}

fn env_bool<F>(lookup: &mut F, keys: &[&'static str]) -> Result<bool>
where
    F: FnMut(&str) -> Option<String>,
{
    let Some((key, value)) = first_env_value(lookup, keys) else {
        return Ok(false);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(Error::InvalidParameter(format!(
            "{key} must be one of 1, true, yes, on, 0, false, no, or off"
        ))),
    }
}

async fn read_json_response<T>(
    mut response: reqwest::Response,
    max_response_bytes: usize,
) -> Result<T>
where
    T: DeserializeOwned,
{
    validate_json_content_type(&response)?;

    if response
        .content_length()
        .is_some_and(|length| length > max_response_bytes as u64)
    {
        return Err(Error::Decode(
            "OpenBao response exceeds client limit".into(),
        ));
    }

    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > max_response_bytes {
            return Err(Error::Decode(
                "OpenBao response exceeds client limit".into(),
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

    use std::collections::BTreeMap;

    use secrecy::{ExposeSecret, SecretString};

    use crate::Error;

    use super::{
        Client, OpenBaoConfig, env_bool, openbao_config_from_env_lookup,
        openbao_token_from_env_lookup, validate_user_agent,
    };

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
    fn response_size_limit_is_bounded() {
        assert!(
            OpenBaoConfig::new("https://bao.example.com")
                .and_then(|config| config.max_response_bytes(1024))
                .is_ok()
        );
        assert!(
            OpenBaoConfig::new("https://bao.example.com")
                .and_then(|config| config.max_response_bytes(0))
                .is_err()
        );
        assert!(
            OpenBaoConfig::new("https://bao.example.com")
                .and_then(|config| config.max_response_bytes(super::MAX_RESPONSE_BYTES + 1))
                .is_err()
        );
    }

    #[test]
    fn user_agent_rejects_control_characters() {
        assert!(validate_user_agent("openbao-rust-client").is_ok());
        assert!(validate_user_agent("").is_err());
        assert!(validate_user_agent("good\r\nX-Injected: bad").is_err());
        assert!(
            OpenBaoConfig::new("https://bao.example.com")
                .and_then(|config| config.user_agent("good\nbad"))
                .is_err()
        );
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

    #[test]
    fn env_config_prefers_openbao_address_and_supports_namespace() {
        let env = env_map([
            ("VAULT_ADDR", "https://vault.example.com"),
            ("OPENBAO_ADDR", "https://bao.example.com"),
            ("OPENBAO_NAMESPACE", "team/app"),
        ]);
        let config = openbao_config_from_env_lookup(|key| env.get(key).cloned())
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(config.base_url().as_str(), "https://bao.example.com/");
        let debug = format!("{config:?}");
        assert!(debug.contains("has_namespace"));
        assert!(!debug.contains("team/app"));
    }

    #[test]
    fn env_config_requires_address() {
        let env = env_map([]);
        let error = match openbao_config_from_env_lookup(|key| env.get(key).cloned()) {
            Ok(_) => panic!("missing env address unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::InvalidBaseUrl(_)));
    }

    #[test]
    fn env_config_requires_explicit_loopback_http_opt_in() {
        let env = env_map([("OPENBAO_ADDR", "http://127.0.0.1:9940")]);
        assert!(openbao_config_from_env_lookup(|key| env.get(key).cloned()).is_err());

        let env = env_map([
            ("OPENBAO_ADDR", "http://127.0.0.1:9940"),
            ("OPENBAO_ALLOW_LOCALHOST_HTTP", "true"),
        ]);
        let config = openbao_config_from_env_lookup(|key| env.get(key).cloned())
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(config.base_url().as_str(), "http://127.0.0.1:9940/");
    }

    #[test]
    fn env_config_rejects_invalid_boolean_values() {
        let env = env_map([("OPENBAO_ALLOW_LOCALHOST_HTTP", "maybe")]);
        let error = match env_bool(&mut |key| env.get(key).cloned(), super::LOCAL_HTTP_ENV_KEYS) {
            Ok(_) => panic!("invalid boolean unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::InvalidParameter(_)));
    }

    #[test]
    fn env_token_is_secret_and_prefers_openbao_alias() {
        let env = env_map([
            ("VAULT_TOKEN", "vault-token"),
            ("OPENBAO_TOKEN", "openbao-token"),
        ]);
        let token = openbao_token_from_env_lookup(|key| env.get(key).cloned())
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(token.expose_secret(), "openbao-token");
        assert!(!format!("{token:?}").contains("openbao-token"));
    }

    fn env_map<const N: usize>(
        pairs: [(&'static str, &'static str); N],
    ) -> BTreeMap<String, String> {
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect()
    }
}
