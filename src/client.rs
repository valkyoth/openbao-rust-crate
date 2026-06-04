//! OpenBao client construction and raw request helpers.

use core::{fmt, marker::PhantomData, time::Duration};
use std::{
    env, fs,
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "rustls-tls")]
use reqwest::tls::CertificateRevocationList;
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
    path::{validate_endpoint_path, validate_mount_path},
    response::ErrorEnvelope,
};

const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const MIN_RESPONSE_BYTES: usize = 1024;
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_RETRY_ATTEMPTS: usize = 8;
const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);
const DEFAULT_RETRY_JITTER_PERCENT: u8 = 20;
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

/// Authenticated client wrapped in [`std::sync::Arc`] for sharing across tasks.
pub type SharedClient = std::sync::Arc<Client<Authenticated>>;

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

/// Explicit retry policy for caller-approved idempotent requests.
///
/// OpenBao requests are single-shot by default. Use this policy only at call
/// sites where the application has decided retrying is safe, such as
/// read-only requests, idempotent bootstrap convergence, or startup probes.
/// The retry decision is limited to [`Error::is_temporary`]: transport
/// failures, rate limiting, service unavailability, and server errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    max_attempts: usize,
    initial_delay: Duration,
    max_delay: Duration,
    jitter_percent: u8,
}

/// HTTP methods that are safe to use with [`Client::request_json_with_retry`].
///
/// This intentionally excludes write verbs such as `POST`, `PUT`, `PATCH`, and
/// `DELETE`. Retrying OpenBao writes can create duplicate credentials or repeat
/// destructive operations when the server completed the first request but the
/// connection failed before the response reached the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryableMethod {
    /// HTTP `GET`.
    Get,
    /// HTTP `HEAD`.
    Head,
    /// OpenBao's custom `LIST` method.
    List,
}

impl RetryableMethod {
    fn as_method(self) -> Result<Method> {
        Ok(match self {
            Self::Get => Method::GET,
            Self::Head => Method::HEAD,
            Self::List => Method::from_bytes(b"LIST")
                .map_err(|error| Error::InvalidHeader(error.to_string()))?,
        })
    }
}

impl RetryPolicy {
    /// Creates an exponential backoff policy.
    ///
    /// `max_attempts` includes the first request. A value of `1` is valid and
    /// means no retry. Delays are capped at `max_delay` and both durations must
    /// be non-zero. Retry delays include OS-random bounded jitter so many
    /// clients do not retry in synchronized waves after a temporary OpenBao
    /// outage.
    pub fn exponential(
        max_attempts: usize,
        initial_delay: Duration,
        max_delay: Duration,
    ) -> Result<Self> {
        if max_attempts == 0 {
            return Err(Error::InvalidParameter(
                "retry attempts must be greater than zero".into(),
            ));
        }
        if max_attempts > MAX_RETRY_ATTEMPTS {
            return Err(Error::InvalidParameter(
                "retry attempts exceed maximum allowed value".into(),
            ));
        }
        if initial_delay.is_zero() || max_delay.is_zero() {
            return Err(Error::InvalidParameter(
                "retry delays must be greater than zero".into(),
            ));
        }
        if initial_delay > MAX_RETRY_DELAY || max_delay > MAX_RETRY_DELAY {
            return Err(Error::InvalidParameter(
                "retry delays exceed maximum allowed value".into(),
            ));
        }
        if initial_delay > max_delay {
            return Err(Error::InvalidParameter(
                "initial retry delay must not exceed maximum retry delay".into(),
            ));
        }
        Ok(Self {
            max_attempts,
            initial_delay,
            max_delay,
            jitter_percent: DEFAULT_RETRY_JITTER_PERCENT,
        })
    }

    /// Returns a copy of this policy with jitter disabled.
    ///
    /// This is intended for deterministic tests and tightly controlled
    /// single-client maintenance tooling. Production multi-client deployments
    /// should keep the default jitter.
    #[must_use]
    pub fn without_jitter(mut self) -> Self {
        self.jitter_percent = 0;
        self
    }

    /// Maximum number of attempts, including the first request.
    #[must_use]
    pub fn max_attempts(&self) -> usize {
        self.max_attempts
    }

    /// Initial delay before the first retry.
    #[must_use]
    pub fn initial_delay(&self) -> Duration {
        self.initial_delay
    }

    /// Maximum delay between retry attempts.
    #[must_use]
    pub fn max_delay(&self) -> Duration {
        self.max_delay
    }

    /// Jitter percentage added to each retry delay.
    #[must_use]
    pub fn jitter_percent(&self) -> u8 {
        self.jitter_percent
    }

    fn delay_for_retry(&self, retry_index: usize) -> Duration {
        let shift = retry_index.min(u32::BITS as usize - 1) as u32;
        let multiplier = 1_u32.checked_shl(shift).unwrap_or(u32::MAX);
        let base = self
            .initial_delay
            .saturating_mul(multiplier)
            .min(self.max_delay);
        self.add_jitter(base, retry_index)
    }

    fn add_jitter(&self, base: Duration, retry_index: usize) -> Duration {
        if self.jitter_percent == 0 || base.is_zero() {
            return base;
        }
        let max_jitter = base.mul_f64(f64::from(self.jitter_percent) / 100.0);
        if max_jitter.is_zero() {
            return base;
        }
        let max_nanos = duration_to_saturating_nanos(max_jitter);
        if max_nanos == 0 {
            return base;
        }
        let jitter_nanos = retry_jitter_nanos(max_nanos, retry_index);
        base.saturating_add(Duration::from_nanos(jitter_nanos))
            .min(self.max_delay)
    }
}

static RETRY_JITTER_COUNTER: AtomicU64 = AtomicU64::new(0);

fn retry_jitter_nanos(max_nanos: u64, retry_index: usize) -> u64 {
    let modulus = max_nanos.saturating_add(1);
    let seed = getrandom::u64().unwrap_or_else(|_| {
        #[cfg(feature = "tracing")]
        tracing::warn!(
            target: "openbao::client",
            "getrandom failed for retry jitter; falling back to a time-based non-security seed; check the OS entropy source"
        );
        retry_jitter_fallback_seed(retry_index)
    });
    seed % modulus
}

// Fallback only for platforms where OS randomness is unavailable. Retry jitter
// is observable through network timing and must not be reused for
// security-sensitive randomness.
fn retry_jitter_fallback_seed(retry_index: usize) -> u64 {
    let counter = RETRY_JITTER_COUNTER.fetch_add(1, Ordering::Relaxed);
    // Non-security retry jitter only. If OS randomness is unavailable on a
    // production OpenBao client host, that target is outside the hardened
    // deployment profile; retry timing predictability is a residual concern
    // rather than a cryptographic control.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    nanos ^ counter.rotate_left(17) ^ (retry_index as u64).rotate_left(31)
}

fn duration_to_saturating_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
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
    crl_pem_bundles: Vec<Vec<u8>>,
    client_identity: Option<Identity>,
    #[cfg(feature = "sensitive-http-test-only")]
    allow_sensitive_local_http_for_tests: bool,
}

impl OpenBaoConfig {
    /// Creates a secure-by-default configuration for an OpenBao server.
    ///
    /// The URL must use HTTPS unless [`Self::allow_localhost_http`] is called.
    /// Requests carrying credentials, namespaces, custom headers, or request
    /// bodies still require HTTPS.
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
            crl_pem_bundles: Vec::new(),
            client_identity: None,
            #[cfg(feature = "sensitive-http-test-only")]
            allow_sensitive_local_http_for_tests: false,
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
    /// `OPENBAO_CACERT` together with `OPENBAO_TLS_ROOTS_ONLY=true` is the
    /// environment equivalent of [`OpenBaoConfig::only_root_certificates`].
    /// Use that pattern when you want the client to trust only your internal
    /// OpenBao CA or a self-signed OpenBao certificate and reject every
    /// platform/public CA root.
    ///
    /// Default crate builds intentionally use HTTP/1.1 only because `reqwest`
    /// default features are disabled. Enable the crate's `http2` feature when
    /// a high-throughput deployment wants TLS ALPN to negotiate HTTP/2 where
    /// the OpenBao server supports it. There is no runtime HTTP/2 knob.
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
    /// Requests carrying credentials, namespaces, custom headers, or request
    /// bodies still require HTTPS.
    ///
    /// Hostnames such as `localhost` are intentionally rejected to avoid DNS,
    /// hosts-file, and proxy ambiguity.
    pub fn allow_localhost_http(mut self) -> Result<Self> {
        self.http_policy = HttpPolicy::LocalhostHttpAllowed;
        self.validate()?;
        Ok(self)
    }

    /// Allows credential-bearing HTTP requests only for numeric loopback test
    /// servers when the `sensitive-http-test-only` feature is enabled.
    ///
    /// This method exists solely for this crate's local HTTP mock tests. It is
    /// unavailable unless explicitly compiled in and should not be used by
    /// applications.
    #[cfg(feature = "sensitive-http-test-only")]
    #[doc(hidden)]
    pub fn allow_sensitive_local_http_for_tests(mut self) -> Result<Self> {
        self = self.allow_localhost_http()?;
        self.allow_sensitive_local_http_for_tests = true;
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
    /// The default is TLS 1.3. Passing TLS 1.2 is a legacy compatibility
    /// downgrade. High-assurance builds should reject TLS 1.2 in downstream CI
    /// unless the deployment has explicitly enabled `tls12-acknowledged`.
    pub fn min_tls_version(mut self, version: tls::Version) -> Self {
        self.min_tls_version = version;
        self
    }

    /// Explicitly permits TLS 1.2 for legacy OpenBao deployments.
    ///
    /// This method is only available with the `tls12-acknowledged` feature so
    /// accidental use is visible in the downstream build graph. TLS 1.3 remains
    /// the default and the recommended floor.
    #[cfg(feature = "tls12-acknowledged")]
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
    ///
    /// This is the crate's supported answer for deployments that would
    /// otherwise ask for certificate or public-key pinning. Supplying your
    /// internal OpenBao CA as the only trusted root rejects every platform or
    /// public CA while still allowing ordinary server-certificate rotation
    /// under that CA. If the OpenBao listener uses a self-signed certificate,
    /// pass that certificate directly as the sole trusted root.
    ///
    /// Leaf-certificate and SPKI pinning are intentionally not exposed because
    /// they are brittle during certificate or key rotation and `reqwest` does
    /// not provide a portable pinning API across TLS backends.
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

    /// Adds one PEM-encoded certificate revocation list for server certificate checks.
    ///
    /// Static CRL enforcement is available only with the crate's `rustls-tls`
    /// backend and requires [`Self::only_root_certificates`]. This matches
    /// `reqwest`/rustls behavior: CRLs are enforced only when verification uses
    /// a configured root-only trust store rather than the native verifier or a
    /// merged platform/public root store.
    ///
    /// The caller is responsible for refreshing CRL material and rebuilding the
    /// client before the CRL expires. The crate does not fetch CRL distribution
    /// points and does not perform OCSP.
    #[cfg(feature = "rustls-tls")]
    pub fn add_certificate_revocation_list_pem(mut self, pem: impl AsRef<[u8]>) -> Result<Self> {
        let pem = pem.as_ref();
        CertificateRevocationList::from_pem(pem)?;
        self.crl_pem_bundles.push(pem.to_vec());
        self.validate()?;
        Ok(self)
    }

    /// Adds a PEM bundle containing one or more certificate revocation lists.
    ///
    /// See [`Self::add_certificate_revocation_list_pem`] for the trust-store and
    /// refresh requirements.
    #[cfg(feature = "rustls-tls")]
    pub fn add_certificate_revocation_list_pem_bundle(
        mut self,
        pem_bundle: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let pem_bundle = pem_bundle.as_ref();
        if CertificateRevocationList::from_pem_bundle(pem_bundle)?.is_empty() {
            return Err(Error::InvalidTlsConfig(
                "certificate revocation list bundle must contain at least one CRL".into(),
            ));
        }
        self.crl_pem_bundles.push(pem_bundle.to_vec());
        self.validate()?;
        Ok(self)
    }

    /// Sets the client certificate identity used for mutual TLS.
    ///
    /// TLS certificate auth requires OpenBao's listener to request/verify a
    /// client certificate. Prefer identities loaded from tightly permissioned
    /// files and avoid logging certificate/key parsing errors that include
    /// secret paths.
    ///
    /// Static CRL enforcement for the OpenBao server certificate is available
    /// through [`Self::add_certificate_revocation_list_pem`] when using
    /// [`Self::only_root_certificates`]. The crate does not fetch CRL
    /// distribution points and does not perform OCSP.
    pub fn client_identity(mut self, identity: Identity) -> Self {
        self.client_identity = Some(identity);
        self
    }

    fn validate(&self) -> Result<()> {
        if !self.crl_pem_bundles.is_empty()
            && self.root_certificate_mode != RootCertificateMode::OnlyConfigured
        {
            return Err(Error::InvalidTlsConfig(
                "certificate revocation lists require only_root_certificates".into(),
            ));
        }
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
            .field("crl_bundle_count", &self.crl_pem_bundles.len())
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
        let http = build_http_client(
            &self.config,
            self.config.http_policy == HttpPolicy::HttpsOnly,
        )?;
        let sensitive_http = build_http_client(&self.config, true)?;

        Ok(Client {
            config: self.config,
            http,
            sensitive_http,
            token: None,
            _state: PhantomData,
        })
    }
}

fn build_http_client(config: &OpenBaoConfig, https_only: bool) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(config.timeout)
        .connect_timeout(config.connect_timeout)
        .user_agent(config.user_agent.clone())
        .https_only(https_only)
        .redirect(redirect::Policy::none())
        .tls_version_min(config.min_tls_version);

    builder = match config.root_certificate_mode {
        RootCertificateMode::MergeWithSystem => {
            builder.tls_certs_merge(config.root_certificates.clone())
        }
        RootCertificateMode::OnlyConfigured => {
            builder.tls_certs_only(config.root_certificates.clone())
        }
    };
    #[cfg(feature = "rustls-tls")]
    if !config.crl_pem_bundles.is_empty() {
        let mut crls = Vec::new();
        for pem_bundle in &config.crl_pem_bundles {
            crls.extend(CertificateRevocationList::from_pem_bundle(pem_bundle)?);
        }
        builder = builder.tls_crls_only(crls);
    }
    if let Some(identity) = config.client_identity.clone() {
        builder = builder.identity(identity);
    }

    Ok(builder.build()?)
}

/// Typed OpenBao HTTP client.
pub struct Client<State = Unauthenticated> {
    pub(crate) config: OpenBaoConfig,
    pub(crate) http: reqwest::Client,
    pub(crate) sensitive_http: reqwest::Client,
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
        client.try_with_token(token)
    }

    /// Creates an unauthenticated client from explicit configuration.
    pub fn from_config(config: OpenBaoConfig) -> Result<Self> {
        ClientBuilder::new(config).build()
    }

    fn with_token_deferred_validation(self, token: SecretString) -> Client<Authenticated> {
        Client {
            config: self.config,
            http: self.http,
            sensitive_http: self.sensitive_http,
            token: Some(token),
            _state: PhantomData,
        }
    }

    #[cfg(test)]
    #[allow(clippy::panic)]
    pub(crate) fn with_token(self, token: SecretString) -> Client<Authenticated> {
        self.try_with_token(token)
            .unwrap_or_else(|error| panic!("{error}"))
    }

    /// Converts the client into an authenticated client after validating that
    /// the token can be represented safely in the configured auth header.
    pub fn try_with_token(self, token: SecretString) -> Result<Client<Authenticated>> {
        validate_token_for_header(&token, self.config.header_mode)?;
        Ok(self.with_token_deferred_validation(token))
    }

    #[cfg(any(
        feature = "approle",
        feature = "cert-auth",
        feature = "jwt-auth",
        feature = "kubernetes-auth",
        feature = "ldap-auth",
        feature = "radius-auth",
        feature = "userpass"
    ))]
    pub(crate) fn clone_without_state(&self) -> Client<Unauthenticated> {
        Client {
            config: self.config.clone(),
            http: self.http.clone(),
            sensitive_http: self.sensitive_http.clone(),
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

    /// Sends a retryable raw JSON request with caller-approved exponential retry.
    ///
    /// Normal crate requests are single-shot. This helper retries only when
    /// the returned [`Error`] is temporary and only when the caller explicitly
    /// supplies a [`RetryPolicy`] and async delay function. The method is a
    /// [`RetryableMethod`] so this helper cannot be used for write verbs such
    /// as `POST`, `PATCH`, or `DELETE`.
    ///
    /// The delay function keeps this API runtime-neutral. For Tokio callers,
    /// pass `tokio::time::sleep`.
    pub async fn request_json_with_retry<T, B, F, Fut>(
        &self,
        method: RetryableMethod,
        path: &str,
        body: Option<&B>,
        policy: RetryPolicy,
        mut delay: F,
    ) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
        F: FnMut(Duration) -> Fut,
        Fut: core::future::Future<Output = ()>,
    {
        let mut attempt = 1;
        let mut retry_index = 0;
        loop {
            match self.request_json(method.as_method()?, path, body).await {
                Ok(response) => return Ok(response),
                Err(error) if attempt < policy.max_attempts && error.is_temporary() => {
                    delay(policy.delay_for_retry(retry_index)).await;
                    attempt += 1;
                    retry_index += 1;
                }
                Err(error) => return Err(error),
            }
        }
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

    /// Sends a raw byte request and returns a capped zeroizing byte buffer.
    ///
    /// `path` is relative to `/v1` and is validated like [`Self::request_json`].
    /// This escape hatch is intended for OpenBao endpoints whose payloads are
    /// binary protocols or non-JSON documents, such as OCSP, certificates, CRLs,
    /// snapshots, or diagnostic output. Prefer typed helpers where this crate
    /// provides them.
    ///
    /// When `body` is present and no explicit `Content-Type` header is supplied,
    /// OpenBao receives `application/octet-stream`.
    pub async fn request_bytes_accepting(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        accept: Option<HeaderValue>,
        body: Option<&[u8]>,
        accepted_statuses: &[StatusCode],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut headers = Vec::new();
        if let Some(accept) = accept {
            headers.push((ACCEPT, accept));
        }
        self.request_bytes_headers_accepting(method, path, query, &headers, body, accepted_statuses)
            .await
    }

    /// Sends a raw byte request with explicit headers.
    ///
    /// Use this for binary protocols that require a specific request or
    /// response MIME type. Header values are validated by `reqwest`; token and
    /// namespace headers are still managed by the client.
    pub async fn request_bytes_headers_accepting(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        headers: &[(HeaderName, HeaderValue)],
        body: Option<&[u8]>,
        accepted_statuses: &[StatusCode],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut url = self.url_for_path(path)?;
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }

        let response = self
            .send_sensitive_bytes_request(method, url, headers, body)
            .await?;
        let status = response.status();
        if !accepted_statuses.contains(&status) {
            let error =
                read_json_response::<ErrorEnvelope>(response, self.config.max_response_bytes)
                    .await
                    .map(|envelope| envelope.errors)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|error| crate::error::sanitize_api_error(&error))
                    .collect();
            return Err(Error::Api {
                status,
                errors: error,
            });
        }

        if let Some((_name, expected_content_type)) =
            headers.iter().find(|(name, _value)| *name == ACCEPT)
        {
            validate_bytes_content_type(&response, expected_content_type)?;
        }
        read_response_bytes(response, self.config.max_response_bytes).await
    }

    pub(crate) async fn request_json_query_headers_accepting<T, B>(
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
        let is_sensitive = self.token.is_some()
            || self.config.namespace.is_some()
            || !query.is_empty()
            || !headers.is_empty()
            || body.is_some();
        let response = if is_sensitive {
            self.send_sensitive_json_request(method, url, headers, body)
                .await?
        } else {
            self.send_non_sensitive_json_request(method, url).await?
        };
        let status = response.status();
        if !accepted_statuses.contains(&status) {
            let error =
                read_json_response::<ErrorEnvelope>(response, self.config.max_response_bytes)
                    .await
                    .map(|envelope| envelope.errors)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|error| crate::error::sanitize_api_error(&error))
                    .collect();
            return Err(Error::Api {
                status,
                errors: error,
            });
        }
        if status == StatusCode::NO_CONTENT {
            return serde_json::from_str("{}").map_err(|_| {
                Error::Decode("OpenBao response did not match expected schema".into())
            });
        }
        read_json_response(response, self.config.max_response_bytes).await
    }

    async fn send_non_sensitive_json_request(
        &self,
        method: Method,
        url: Url,
    ) -> Result<reqwest::Response> {
        let mut request = reqwest::Request::new(method, url);
        request
            .headers_mut()
            .insert(ACCEPT, HeaderValue::from_static("application/json"));
        request.headers_mut().insert(
            HeaderName::from_static("x-vault-request"),
            HeaderValue::from_static("true"),
        );

        execute_openbao_http_request(&self.http, request).await
    }

    async fn send_sensitive_json_request<B>(
        &self,
        method: Method,
        url: Url,
        headers: &[(HeaderName, HeaderValue)],
        body: Option<&B>,
    ) -> Result<reqwest::Response>
    where
        B: Serialize + ?Sized,
    {
        self.require_encrypted_transport_for_sensitive_request(&url)?;
        let http = self.http_for_sensitive_request();

        let mut request = reqwest::Request::new(method, url);
        request
            .headers_mut()
            .insert(ACCEPT, HeaderValue::from_static("application/json"));
        request.headers_mut().insert(
            HeaderName::from_static("x-vault-request"),
            HeaderValue::from_static("true"),
        );
        for (name, value) in headers {
            request.headers_mut().insert(name.clone(), value.clone());
        }

        if let Some(namespace) = self.config.namespace.as_deref() {
            request.headers_mut().insert(
                HeaderName::from_static("x-vault-namespace"),
                sensitive_header_value(namespace)?,
            );
        }
        if let Some(token) = self.token.as_ref() {
            let (name, value) = token_header_for(token, self.config.header_mode)?;
            request.headers_mut().insert(name, value);
        }
        if let Some(payload) = body {
            let encoded = Zeroizing::new(
                serde_json::to_vec(payload)
                    .map_err(|_| Error::Decode("OpenBao request could not be encoded".into()))?,
            );
            let has_content_type = headers.iter().any(|(name, _value)| *name == CONTENT_TYPE);
            if !has_content_type {
                request
                    .headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            }
            // SECURITY: this copy is intentionally non-zeroing because
            // reqwest::Body does not accept a Zeroize-on-drop body buffer.
            // The Zeroizing serialization buffer above is cleared; reqwest,
            // TLS, kernel, and device buffers are documented residual risks.
            *request.body_mut() = Some(Vec::from(&encoded[..]).into());
        }

        execute_openbao_http_request(http, request).await
    }

    async fn send_sensitive_bytes_request(
        &self,
        method: Method,
        url: Url,
        headers: &[(HeaderName, HeaderValue)],
        body: Option<&[u8]>,
    ) -> Result<reqwest::Response> {
        self.require_encrypted_transport_for_sensitive_request(&url)?;
        let http = self.http_for_sensitive_request();

        let mut request = reqwest::Request::new(method, url);
        for (name, value) in headers {
            request.headers_mut().insert(name.clone(), value.clone());
        }
        request.headers_mut().insert(
            HeaderName::from_static("x-vault-request"),
            HeaderValue::from_static("true"),
        );

        if let Some(namespace) = self.config.namespace.as_deref() {
            request.headers_mut().insert(
                HeaderName::from_static("x-vault-namespace"),
                sensitive_header_value(namespace)?,
            );
        }
        if let Some(token) = self.token.as_ref() {
            let (name, value) = token_header_for(token, self.config.header_mode)?;
            request.headers_mut().insert(name, value);
        }
        if let Some(body) = body {
            if !request.headers().contains_key(CONTENT_TYPE) {
                request.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                );
            }
            // SECURITY: reqwest takes ownership of a normal body buffer. The
            // caller-provided slice is not retained by this crate, but lower
            // transport layers may hold transient copies during the request.
            *request.body_mut() = Some(body.to_vec().into());
        }

        execute_openbao_http_request(http, request).await
    }

    pub(crate) fn url_for_path(&self, path: &str) -> Result<Url> {
        let mut url = self.config.base_url.clone();
        {
            let mut segments = url.path_segments_mut().map_err(|_| {
                Error::InvalidBaseUrl("base URL cannot be a cannot-be-a-base URL".into())
            })?;
            segments.clear();
            segments.push("v1");
            for segment in validate_endpoint_path(path)? {
                segments.push(&segment);
            }
        }
        Ok(url)
    }

    fn http_for_sensitive_request(&self) -> &reqwest::Client {
        #[cfg(feature = "sensitive-http-test-only")]
        if self.config.allow_sensitive_local_http_for_tests {
            return &self.http;
        }

        &self.sensitive_http
    }

    fn require_encrypted_transport_for_sensitive_request(&self, url: &Url) -> Result<()> {
        #[cfg(feature = "sensitive-http-test-only")]
        if self.config.allow_sensitive_local_http_for_tests && is_loopback_url(url) {
            return Ok(());
        }

        if is_cleartext_url(url) {
            return Err(Error::InvalidBaseUrl(
                "refusing to send credentials or request bodies over plain HTTP".into(),
            ));
        }
        Ok(())
    }
}

impl Client<Authenticated> {
    /// Creates a response-wrapping context for JSON requests.
    ///
    /// Requests sent through the returned context include `X-Vault-Wrap-TTL`.
    /// OpenBao stores the original response body in cubbyhole storage and
    /// returns only single-use wrapping token metadata. This crate does not add
    /// background delivery, retry, or token forwarding policy; callers decide
    /// who receives and unwraps the token.
    #[cfg(feature = "sys")]
    pub fn wrapping(&self, ttl: &str) -> Result<crate::sys::WrappingContext<'_>> {
        crate::sys::WrappingContext::new(self, ttl)
    }

    /// Wraps this authenticated client in an [`std::sync::Arc`] for sharing
    /// across async tasks without cloning token material.
    #[must_use]
    pub fn into_shared(self) -> SharedClient {
        std::sync::Arc::new(self)
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

async fn execute_openbao_http_request(
    http: &reqwest::Client,
    outgoing: reqwest::Request,
) -> Result<reqwest::Response> {
    #[cfg(feature = "tracing")]
    let trace_method = outgoing.method().clone();
    #[cfg(feature = "tracing")]
    let trace_path = span_safe_path(outgoing.url().path());

    let pending = reqwest::RequestBuilder::from_parts(http.clone(), outgoing).send();

    #[cfg(feature = "tracing")]
    let trace_span = tracing::debug_span!(
        "openbao.request",
        method = %trace_method,
        path = %trace_path
    );
    #[cfg(feature = "tracing")]
    tracing::debug!(parent: &trace_span, "OpenBao request");

    #[cfg(feature = "tracing")]
    let result = {
        use tracing::Instrument as _;
        pending.instrument(trace_span.clone()).await
    };
    #[cfg(not(feature = "tracing"))]
    let result = pending.await;

    match result {
        Ok(response) => {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                parent: &trace_span,
                status = %response.status(),
                "OpenBao response"
            );
            Ok(response)
        }
        Err(error) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(parent: &trace_span, "OpenBao transport error");
            Err(crate::error::http_transport_error(error))
        }
    }
}

fn validate_user_agent(user_agent: &str) -> Result<()> {
    if user_agent.is_empty() {
        return Err(Error::InvalidParameter(
            "user agent must not be empty".into(),
        ));
    }
    if !user_agent.is_ascii() {
        return Err(Error::InvalidParameter(
            "user agent must contain only ASCII characters".into(),
        ));
    }
    if user_agent.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(Error::InvalidParameter(
            "user agent must not contain control characters".into(),
        ));
    }
    Ok(())
}

fn validate_token_for_header(token: &SecretString, header_mode: HeaderMode) -> Result<()> {
    token_header_for(token, header_mode).map(|_| ())
}

fn token_header_for(
    token: &SecretString,
    header_mode: HeaderMode,
) -> Result<(HeaderName, HeaderValue)> {
    let token_value = token.expose_secret();
    let trimmed = token_value.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidHeader(
            "authentication token must not be empty".into(),
        ));
    }
    if trimmed.len() != token_value.len() {
        return Err(Error::InvalidHeader(
            "authentication token must not contain leading or trailing whitespace".into(),
        ));
    }
    match header_mode {
        HeaderMode::VaultToken => Ok((
            HeaderName::from_static("x-vault-token"),
            sensitive_header_value(token_value)?,
        )),
        HeaderMode::Bearer => {
            let mut bearer =
                Zeroizing::new(String::with_capacity("Bearer ".len() + token_value.len()));
            bearer.push_str("Bearer ");
            bearer.push_str(token_value);
            let value = sensitive_header_value(&bearer).map_err(|_| {
                Error::InvalidHeader("token must be valid for Authorization header use".into())
            })?;
            Ok((reqwest::header::AUTHORIZATION, value))
        }
    }
}

fn is_cleartext_url(url: &Url) -> bool {
    url.scheme() != "https"
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
            let pem = fs::read(&path).map_err(|_| {
                Error::InvalidTlsConfig("failed to read the configured CA certificate file".into())
            })?;
            Some(Certificate::from_pem(&pem).map_err(|_| {
                Error::InvalidTlsConfig("failed to parse the configured CA certificate file".into())
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

async fn read_json_response<T>(response: reqwest::Response, max_response_bytes: usize) -> Result<T>
where
    T: DeserializeOwned,
{
    validate_json_content_type(&response)?;
    let body = read_response_bytes(response, max_response_bytes).await?;

    serde_json::from_slice(&body)
        .map_err(|_| Error::Decode("OpenBao response did not match expected schema".into()))
}

async fn read_response_bytes(
    mut response: reqwest::Response,
    max_response_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>> {
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

    Ok(body)
}

#[cfg(feature = "tracing")]
fn span_safe_path(path: &str) -> String {
    let mut segments = path.trim_start_matches('/').split('/');
    let Some(version) = segments.next() else {
        return "/<redacted>".to_owned();
    };
    let Some(mount) = segments.next() else {
        return format!("/{version}");
    };
    let Some(operation) = segments.next() else {
        return format!("/{version}/{mount}");
    };
    if segments.next().is_none() {
        return format!("/{version}/{mount}/{operation}");
    }
    format!("/{version}/{mount}/{operation}/<redacted>")
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

fn validate_bytes_content_type(
    response: &reqwest::Response,
    expected_content_type: &HeaderValue,
) -> Result<()> {
    let expected = header_media_type(expected_content_type, "expected binary content-type")?;
    if expected == "*/*" {
        return Ok(());
    }
    let actual = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .ok_or_else(|| Error::Decode("missing content-type header".into()))?;
    let actual = header_media_type(actual, "binary response content-type")?;
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(Error::Decode(format!(
            "unexpected content-type: expected {expected}"
        )));
    }
    Ok(())
}

fn header_media_type<'a>(value: &'a HeaderValue, label: &'static str) -> Result<&'a str> {
    let value = value
        .to_str()
        .map_err(|error| Error::Decode(format!("invalid {label} header: {error}")))?;
    let media_type = value
        .split(',')
        .next()
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::Decode(format!("missing {label} header")))?;
    Ok(media_type)
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
    #![allow(deprecated)]

    use std::collections::BTreeMap;

    use secrecy::{ExposeSecret, SecretString};

    use crate::Error;

    use super::{
        Client, OpenBaoConfig, env_bool, is_cleartext_url, openbao_config_from_env_lookup,
        openbao_token_from_env_lookup, validate_token_for_header, validate_user_agent,
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
    fn cleartext_url_detection_is_strict() {
        let http = reqwest::Url::parse("http://127.0.0.1:8200/v1/sys/health")
            .unwrap_or_else(|error| panic!("{error}"));
        let https = reqwest::Url::parse("https://bao.example.com/v1/secret/data/app")
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(is_cleartext_url(&http));
        assert!(!is_cleartext_url(&https));
    }

    #[cfg(feature = "tracing")]
    #[test]
    fn tracing_path_sanitizer_redacts_secret_identifiers() {
        assert_eq!(
            super::span_safe_path("/v1/transit/encrypt/classified-payload-key"),
            "/v1/transit/encrypt/<redacted>"
        );
        assert_eq!(
            super::span_safe_path("/v1/secret/data/compartment-alpha/credentials"),
            "/v1/secret/data/<redacted>"
        );
        assert_eq!(super::span_safe_path("/v1/sys/health"), "/v1/sys/health");
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
        assert!(
            OpenBaoConfig::new("https://bao.example.com")
                .and_then(|config| config.user_agent("déjà-vu"))
                .is_err()
        );
    }

    #[test]
    fn token_header_validation_rejects_invalid_values() {
        assert!(
            validate_token_for_header(
                &SecretString::from("token-value"),
                super::HeaderMode::VaultToken
            )
            .is_ok()
        );
        assert!(
            validate_token_for_header(
                &SecretString::from("token\nvalue"),
                super::HeaderMode::VaultToken
            )
            .is_err()
        );
        assert!(
            validate_token_for_header(
                &SecretString::from(" token-value"),
                super::HeaderMode::VaultToken
            )
            .is_err()
        );
        assert!(
            validate_token_for_header(
                &SecretString::from("token-value "),
                super::HeaderMode::Bearer
            )
            .is_err()
        );
        assert!(
            validate_token_for_header(&SecretString::from("  "), super::HeaderMode::VaultToken)
                .is_err()
        );
        assert!(
            Client::new("https://bao.example.com")
                .and_then(|client| client.try_with_token(SecretString::from("token\rvalue")))
                .is_err()
        );
    }

    #[test]
    fn rejects_empty_custom_root_only_store() {
        let result = OpenBaoConfig::new("https://bao.example.com")
            .and_then(|config| config.only_root_certificates(Vec::new()));
        assert!(result.is_err());
    }

    #[cfg(feature = "rustls-tls")]
    #[test]
    fn certificate_revocation_lists_require_root_only_trust() {
        let crl = b"-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n";
        let result = OpenBaoConfig::new("https://bao.example.com")
            .and_then(|config| config.add_certificate_revocation_list_pem(crl));

        assert!(
            matches!(result, Err(Error::InvalidTlsConfig(message)) if message.contains("only_root_certificates"))
        );
    }

    #[cfg(feature = "rustls-tls")]
    #[test]
    fn certificate_revocation_list_bundles_must_contain_crls() {
        let result = OpenBaoConfig::new("https://bao.example.com")
            .and_then(|config| config.add_certificate_revocation_list_pem_bundle(b""));

        assert!(
            matches!(result, Err(Error::InvalidTlsConfig(message)) if message.contains("at least one CRL"))
        );
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
    fn env_ca_errors_do_not_echo_filesystem_path() {
        let env = env_map([
            ("OPENBAO_ADDR", "https://bao.example.com"),
            ("OPENBAO_CACERT", "/sensitive/topology/openbao-ca.pem"),
        ]);
        let error = match openbao_config_from_env_lookup(|key| env.get(key).cloned()) {
            Ok(_) => panic!("missing CA file unexpectedly succeeded"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(message.contains("configured CA certificate file"));
        assert!(!message.contains("/sensitive/topology"));
        assert!(!message.contains("openbao-ca.pem"));
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
