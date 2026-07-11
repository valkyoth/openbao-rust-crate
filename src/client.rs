//! OpenBao client construction and raw request helpers.

use core::{
    fmt,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};
use std::{
    env, fs,
    net::IpAddr,
    sync::{Arc, Mutex},
};
#[cfg(feature = "allow-weak-jitter-fallback-acknowledged")]
use std::{
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
use sanitization::{SecretVec, SecureSanitize};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    Error, Result,
    compatibility::{
        OpenBaoCapabilityAvailability, OpenBaoCompatibilityFailure, OpenBaoCompatibilityPolicy,
        OpenBaoCompatibilityReport, OpenBaoEndpointSpec, OpenBaoHttpMethod, OpenBaoOperation,
        OpenBaoOperationDisposition, OpenBaoVersion, is_generated_profile,
        latest_generated_profile, openbao_operation, openbao_profile_versions,
    },
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
const MAX_USER_AGENT_BYTES: usize = 512;
const MAX_COMPATIBILITY_HEALTH_BYTES: usize = 64 * 1024;
const MAX_COMPATIBILITY_WAITERS: usize = 4096;
const MAX_ENDPOINT_ID_BYTES: usize = 192;
const MAX_ENDPOINT_VARIANTS: usize = 16;
const MAX_OPTIONAL_ROUTE_EXPANSIONS: usize = 8;
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
        let Some(jitter_nanos) = retry_jitter_nanos(max_nanos, retry_index) else {
            return base;
        };
        base.saturating_add(Duration::from_nanos(jitter_nanos))
            .min(self.max_delay)
    }
}

#[cfg(feature = "allow-weak-jitter-fallback-acknowledged")]
static RETRY_JITTER_COUNTER: AtomicU64 = AtomicU64::new(0);

fn retry_jitter_nanos(max_nanos: u64, retry_index: usize) -> Option<u64> {
    #[cfg(not(feature = "allow-weak-jitter-fallback-acknowledged"))]
    let _ = retry_index;
    let modulus = max_nanos.saturating_add(1);
    let seed = match getrandom::u64() {
        Ok(seed) => seed,
        Err(_) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                target: "openbao::client",
                "getrandom failed for retry jitter; check the OS entropy source"
            );
            #[cfg(feature = "allow-weak-jitter-fallback-acknowledged")]
            {
                retry_jitter_fallback_seed(retry_index)
            }
            #[cfg(not(feature = "allow-weak-jitter-fallback-acknowledged"))]
            {
                return None;
            }
        }
    };
    Some(seed % modulus)
}

// Fallback only for platforms where OS randomness is unavailable. Retry jitter
// is observable through network timing and must not be reused for
// security-sensitive randomness.
#[cfg(feature = "allow-weak-jitter-fallback-acknowledged")]
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
    compatibility_policy: Option<OpenBaoCompatibilityPolicy>,
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
        validate_base_url_components(&url)?;
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
            compatibility_policy: None,
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

    /// Selects a server-version compatibility policy for this client.
    ///
    /// Verified policies issue one public, token-free, namespace-free
    /// `/sys/health` request before the first SDK request and cache the result
    /// for this client instance. [`OpenBaoCompatibilityPolicy::assume`] performs
    /// no network probe and is always reported as assumed rather than verified.
    pub fn compatibility_policy(mut self, policy: OpenBaoCompatibilityPolicy) -> Self {
        self.compatibility_policy = Some(policy);
        self
    }

    /// Sets the minimum TLS protocol version.
    ///
    /// The default is TLS 1.3. Passing TLS 1.2 is a legacy compatibility
    /// downgrade. High-assurance builds should reject TLS 1.2 in downstream CI
    /// unless the deployment has explicitly enabled `tls12-acknowledged`.
    /// TLS versions below 1.2 are rejected when the client is built.
    /// TLS 1.2 is also rejected at build time unless the crate was compiled
    /// with the `tls12-acknowledged` feature.
    pub fn min_tls_version(mut self, version: tls::Version) -> Self {
        self.min_tls_version = version;
        self
    }

    /// Explicitly permits TLS 1.2 for legacy OpenBao deployments.
    ///
    /// # High-assurance TLS 1.2 configuration
    ///
    /// If TLS 1.2 is required, configure the OpenBao server and any
    /// terminating proxy to disable NULL, EXPORT, anonymous, DES/3DES, RC4,
    /// and CBC-mode cipher suites. Prefer AEAD suites such as
    /// `ECDHE-ECDSA-AES256-GCM-SHA384` or `ECDHE-RSA-AES256-GCM-SHA384`.
    ///
    /// This method is only available with the `tls12-acknowledged` feature so
    /// accidental use is visible in the downstream build graph. TLS 1.3 remains
    /// the default and the recommended floor.
    #[cfg(feature = "tls12-acknowledged")]
    pub fn min_tls_12(self) -> Self {
        self.min_tls_version(tls::Version::TLS_1_2)
    }

    /// Adds a trusted root certificate.
    ///
    /// In the default trust mode this certificate is merged with platform roots.
    /// If [`Self::only_root_certificates`] has already been used, this appends
    /// to that configured root-only trust store and does not re-enable platform
    /// roots.
    pub fn add_root_certificate(mut self, certificate: Certificate) -> Self {
        self.root_certificates.push(certificate);
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
        validate_base_url_components(&self.base_url)?;
        validate_min_tls_version(self.min_tls_version)?;
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

fn validate_min_tls_version(version: tls::Version) -> Result<()> {
    if version == tls::Version::TLS_1_0 || version == tls::Version::TLS_1_1 {
        return Err(Error::InvalidTlsConfig(
            "TLS versions below 1.2 are not supported by this crate".into(),
        ));
    }
    #[cfg(not(feature = "tls12-acknowledged"))]
    if version == tls::Version::TLS_1_2 {
        return Err(Error::InvalidTlsConfig(
            "TLS 1.2 requires the tls12-acknowledged feature".into(),
        ));
    }
    Ok(())
}

fn validate_base_url_components(url: &Url) -> Result<()> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::InvalidBaseUrl(
            "base URL must not contain user credentials".into(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Error::InvalidBaseUrl(
            "base URL must not contain a query or fragment".into(),
        ));
    }
    if !matches!(url.path(), "" | "/") {
        return Err(Error::InvalidBaseUrl(
            "base URL must not contain an application path".into(),
        ));
    }
    Ok(())
}

pub(crate) const fn ensure_public_raw_api_enabled() -> Result<()> {
    #[cfg(all(feature = "raw-api", feature = "raw-api-acknowledged"))]
    {
        Ok(())
    }
    #[cfg(not(all(feature = "raw-api", feature = "raw-api-acknowledged")))]
    {
        Err(Error::RawApiDisabled)
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
            .field(
                "compatibility_policy",
                &self
                    .compatibility_policy
                    .map(OpenBaoCompatibilityPolicy::kind),
            )
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
enum CachedCompatibilityFailure {
    Policy(OpenBaoCompatibilityFailure),
    Probe(&'static str),
}

type CachedCompatibilityResult =
    core::result::Result<OpenBaoCompatibilityReport, CachedCompatibilityFailure>;

enum CompatibilityVerificationState {
    Pending,
    Running(Vec<CompatibilityWaiter>),
    Complete(CachedCompatibilityResult),
}

struct CompatibilityWaiter {
    token: Arc<()>,
    waker: Waker,
}

struct ClientCompatibility {
    policy: Option<OpenBaoCompatibilityPolicy>,
    verification: Mutex<CompatibilityVerificationState>,
}

impl ClientCompatibility {
    fn new(policy: Option<OpenBaoCompatibilityPolicy>) -> Self {
        let verification = match policy {
            None => CompatibilityVerificationState::Complete(Ok(
                OpenBaoCompatibilityReport::unverified(),
            )),
            Some(policy) => match policy.immediate_report() {
                Some(report) => CompatibilityVerificationState::Complete(Ok(report)),
                None => CompatibilityVerificationState::Pending,
            },
        };
        Self {
            policy,
            verification: Mutex::new(verification),
        }
    }
}

enum CompatibilityWaitOutcome {
    Complete(CachedCompatibilityResult),
    Retry,
    TooManyWaiters,
}

struct CompatibilityWait<'a> {
    compatibility: &'a ClientCompatibility,
    token: Arc<()>,
}

impl Future for CompatibilityWait<'_> {
    type Output = CompatibilityWaitOutcome;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let Ok(mut state) = self.compatibility.verification.lock() else {
            return Poll::Ready(CompatibilityWaitOutcome::Complete(Err(
                CachedCompatibilityFailure::Probe("compatibility cache lock failed"),
            )));
        };
        match &mut *state {
            CompatibilityVerificationState::Complete(result) => {
                Poll::Ready(CompatibilityWaitOutcome::Complete(*result))
            }
            CompatibilityVerificationState::Pending => Poll::Ready(CompatibilityWaitOutcome::Retry),
            CompatibilityVerificationState::Running(waiters) => {
                if let Some(waiter) = waiters
                    .iter_mut()
                    .find(|waiter| Arc::ptr_eq(&waiter.token, &self.token))
                {
                    if !waiter.waker.will_wake(context.waker()) {
                        waiter.waker = context.waker().clone();
                    }
                    return Poll::Pending;
                }
                if waiters.len() >= MAX_COMPATIBILITY_WAITERS {
                    return Poll::Ready(CompatibilityWaitOutcome::TooManyWaiters);
                }
                waiters.push(CompatibilityWaiter {
                    token: Arc::clone(&self.token),
                    waker: context.waker().clone(),
                });
                Poll::Pending
            }
        }
    }
}

impl Drop for CompatibilityWait<'_> {
    fn drop(&mut self) {
        let Ok(mut state) = self.compatibility.verification.lock() else {
            return;
        };
        if let CompatibilityVerificationState::Running(waiters) = &mut *state {
            waiters.retain(|waiter| !Arc::ptr_eq(&waiter.token, &self.token));
        }
    }
}

struct CompatibilityLeader<'a> {
    compatibility: &'a ClientCompatibility,
    completed: bool,
}

#[derive(Deserialize)]
struct CompatibilityHealth {
    version: String,
}

enum CompatibilityAction<'a> {
    Complete(CachedCompatibilityResult),
    Wait(CompatibilityWait<'a>),
    Lead(CompatibilityLeader<'a>),
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct ResolvedOpenBaoEndpoint {
    endpoint: &'static str,
    operation: OpenBaoOperation,
    method: Method,
}

#[allow(dead_code)]
impl ResolvedOpenBaoEndpoint {
    pub(crate) const fn endpoint(&self) -> &'static str {
        self.endpoint
    }

    pub(crate) const fn operation(&self) -> OpenBaoOperation {
        self.operation
    }

    pub(crate) fn method(&self) -> Method {
        self.method.clone()
    }
}

impl CompatibilityLeader<'_> {
    fn complete(mut self, result: CachedCompatibilityResult) {
        let waiters = if let Ok(mut state) = self.compatibility.verification.lock() {
            match core::mem::replace(
                &mut *state,
                CompatibilityVerificationState::Complete(result),
            ) {
                CompatibilityVerificationState::Running(waiters) => waiters,
                _ => Vec::new(),
            }
        } else {
            Vec::new()
        };
        self.completed = true;
        for waiter in waiters {
            waiter.waker.wake();
        }
    }
}

impl Drop for CompatibilityLeader<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let waiters = if let Ok(mut state) = self.compatibility.verification.lock() {
            match core::mem::replace(&mut *state, CompatibilityVerificationState::Pending) {
                CompatibilityVerificationState::Running(waiters) => waiters,
                previous => {
                    *state = previous;
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        for waiter in waiters {
            waiter.waker.wake();
        }
    }
}

/// Builder for [`Client`].
#[derive(Debug)]
pub struct ClientBuilder {
    config: OpenBaoConfig,
}

/// TLS implementation selected for an OpenBao client.
///
/// Selection follows this crate's feature policy rather than reqwest's unified
/// dependency features. This lets applications audit which backend OpenBao
/// requests actually use when another dependency enables additional reqwest
/// TLS features.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsBackend {
    /// The Rustls TLS implementation.
    Rustls,
    /// The platform native TLS implementation.
    Native,
}

impl ClientBuilder {
    /// Creates a builder from validated configuration.
    pub fn new(config: OpenBaoConfig) -> Self {
        Self { config }
    }

    /// Builds an unauthenticated OpenBao client.
    pub fn build(self) -> Result<Client<Unauthenticated>> {
        self.config.validate()?;
        let (http, tls_backend) = build_http_client(
            &self.config,
            self.config.http_policy == HttpPolicy::HttpsOnly,
        )?;
        let (sensitive_http, sensitive_tls_backend) = build_http_client(&self.config, true)?;
        if tls_backend != sensitive_tls_backend {
            return Err(Error::Internal(
                "OpenBao HTTP clients selected different TLS backends",
            ));
        }

        let compatibility = Arc::new(ClientCompatibility::new(self.config.compatibility_policy));
        Ok(Client {
            config: self.config,
            http,
            sensitive_http,
            tls_backend,
            token: None,
            compatibility,
            _state: PhantomData,
        })
    }
}

fn build_http_client(
    config: &OpenBaoConfig,
    https_only: bool,
) -> Result<(reqwest::Client, TlsBackend)> {
    let mut builder = reqwest::Client::builder()
        .timeout(config.timeout)
        .connect_timeout(config.connect_timeout)
        .user_agent(config.user_agent.clone())
        .https_only(https_only)
        .redirect(redirect::Policy::none())
        .tls_version_min(config.min_tls_version);

    // Apply and record the backend in one operation so dependency feature
    // unification cannot make the reported backend diverge from the builder.
    #[cfg(feature = "native-tls")]
    let (selected_builder, tls_backend) = (builder.tls_backend_native(), TlsBackend::Native);
    #[cfg(all(not(feature = "native-tls"), feature = "rustls-tls"))]
    let (selected_builder, tls_backend) = (builder.tls_backend_rustls(), TlsBackend::Rustls);
    builder = selected_builder;

    if !config.crl_pem_bundles.is_empty() && tls_backend != TlsBackend::Rustls {
        return Err(Error::InvalidTlsConfig(
            "certificate revocation lists require the selected Rustls TLS backend".into(),
        ));
    }

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

    Ok((builder.build()?, tls_backend))
}

/// Typed OpenBao HTTP client.
pub struct Client<State = Unauthenticated> {
    pub(crate) config: OpenBaoConfig,
    pub(crate) http: reqwest::Client,
    pub(crate) sensitive_http: reqwest::Client,
    pub(crate) tls_backend: TlsBackend,
    pub(crate) token: Option<SecretString>,
    compatibility: Arc<ClientCompatibility>,
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
            tls_backend: self.tls_backend,
            token: Some(token),
            compatibility: self.compatibility,
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
        feature = "sys",
        feature = "userpass"
    ))]
    pub(crate) fn clone_without_state(&self) -> Client<Unauthenticated> {
        Client {
            config: self.config.clone(),
            http: self.http.clone(),
            sensitive_http: self.sensitive_http.clone(),
            tls_backend: self.tls_backend,
            token: None,
            compatibility: Arc::clone(&self.compatibility),
            _state: PhantomData,
        }
    }
}

impl<State> Client<State> {
    /// Returns the validated base URL.
    pub fn base_url(&self) -> &Url {
        &self.config.base_url
    }

    /// Returns the TLS backend selected when this client was built.
    #[must_use]
    pub const fn tls_backend(&self) -> TlsBackend {
        self.tls_backend
    }

    /// Verifies and returns this client's secret-free compatibility report.
    ///
    /// Verified policies perform at most one public `/sys/health` probe per
    /// client instance. Concurrent callers share that result. Assumed mode
    /// performs no probe, and clients without a selected policy return an
    /// `Unverified` report while preserving the pre-2.0 request behavior.
    pub async fn compatibility_report(&self) -> Result<OpenBaoCompatibilityReport> {
        self.ensure_compatibility().await
    }

    async fn ensure_compatibility(&self) -> Result<OpenBaoCompatibilityReport> {
        loop {
            let action = {
                let mut verification = self
                    .compatibility
                    .verification
                    .lock()
                    .map_err(|_| Error::Internal("compatibility cache lock failed"))?;
                match &*verification {
                    CompatibilityVerificationState::Complete(result) => {
                        CompatibilityAction::Complete(*result)
                    }
                    CompatibilityVerificationState::Running(_) => {
                        CompatibilityAction::Wait(CompatibilityWait {
                            compatibility: &self.compatibility,
                            token: Arc::new(()),
                        })
                    }
                    CompatibilityVerificationState::Pending => {
                        *verification = CompatibilityVerificationState::Running(Vec::new());
                        CompatibilityAction::Lead(CompatibilityLeader {
                            compatibility: &self.compatibility,
                            completed: false,
                        })
                    }
                }
            };

            match action {
                CompatibilityAction::Complete(result) => {
                    return result.map_err(compatibility_error);
                }
                CompatibilityAction::Wait(wait) => match wait.await {
                    CompatibilityWaitOutcome::Complete(result) => {
                        return result.map_err(compatibility_error);
                    }
                    CompatibilityWaitOutcome::Retry => continue,
                    CompatibilityWaitOutcome::TooManyWaiters => {
                        return Err(Error::OpenBaoCompatibilityProbe(
                            "too many concurrent compatibility waiters",
                        ));
                    }
                },
                CompatibilityAction::Lead(leader) => {
                    let result = self.evaluate_compatibility_policy().await;
                    leader.complete(result);
                    return result.map_err(compatibility_error);
                }
            }
        }
    }

    async fn evaluate_compatibility_policy(&self) -> CachedCompatibilityResult {
        let Some(policy) = self.compatibility.policy else {
            return Ok(OpenBaoCompatibilityReport::unverified());
        };
        if let Some(report) = policy.immediate_report() {
            return Ok(report);
        }
        let detected = self.probe_openbao_version().await?;
        policy
            .evaluate_detected(detected)
            .map_err(CachedCompatibilityFailure::Policy)
    }

    async fn probe_openbao_version(
        &self,
    ) -> core::result::Result<OpenBaoVersion, CachedCompatibilityFailure> {
        let url = self
            .url_for_path("sys/health")
            .map_err(|_| CachedCompatibilityFailure::Probe("health URL could not be built"))?;
        let response = self
            .send_non_sensitive_json_request(Method::GET, url)
            .await
            .map_err(|_| {
                CachedCompatibilityFailure::Probe("health request could not be completed")
            })?;
        if !compatibility_health_status_is_accepted(response.status()) {
            return Err(CachedCompatibilityFailure::Probe(
                "health endpoint returned an unexpected status",
            ));
        }
        let health = read_json_response::<CompatibilityHealth>(
            response,
            self.config
                .max_response_bytes
                .min(MAX_COMPATIBILITY_HEALTH_BYTES),
        )
        .await
        .map_err(|_| {
            CachedCompatibilityFailure::Probe("health response did not match the expected schema")
        })?;
        health.version.parse().map_err(|_| {
            CachedCompatibilityFailure::Probe(
                "health response contained an invalid stable server version",
            )
        })
    }

    #[allow(dead_code)]
    pub(crate) async fn resolve_openbao_endpoint<Q, K>(
        &self,
        endpoint: OpenBaoEndpointSpec,
        path: &str,
        query: &[(K, Q)],
    ) -> Result<ResolvedOpenBaoEndpoint>
    where
        Q: AsRef<str>,
        K: AsRef<str>,
    {
        let path_segments = validate_endpoint_path(path)?;
        validate_endpoint_spec(endpoint)?;
        let report = self.ensure_compatibility().await?;
        let version = match report.profile_version() {
            Some(version) => version,
            None if report.status()
                == crate::compatibility::OpenBaoCompatibilityStatus::Unverified =>
            {
                latest_generated_profile().ok_or(Error::Internal(
                    "OpenBao compatibility profile inventory is empty",
                ))?
            }
            None => {
                return Err(Error::Internal(
                    "OpenBao compatibility report has no routing profile",
                ));
            }
        };
        if !is_generated_profile(version) {
            return Err(Error::UnsupportedOpenBaoVersion(version));
        }

        let mut selected = endpoint
            .variants()
            .iter()
            .copied()
            .filter(|variant| variant.contains(version));
        let Some(variant) = selected.next() else {
            return Err(Error::UnsupportedOpenBaoCapability {
                endpoint: endpoint.id(),
                version,
            });
        };
        if selected.next().is_some() {
            return Err(Error::Internal(
                "OpenBao endpoint variants overlap for the selected profile",
            ));
        }
        let operation = openbao_operation(variant.operation_id()).ok_or(Error::Internal(
            "OpenBao endpoint references an unknown registry operation",
        ))?;
        match operation.availability(version) {
            Some(OpenBaoCapabilityAvailability::DocumentedRoute) => {}
            Some(
                OpenBaoCapabilityAvailability::NotDocumented
                | OpenBaoCapabilityAvailability::SecurityBlocked,
            ) => {
                return Err(Error::UnsupportedOpenBaoCapability {
                    endpoint: endpoint.id(),
                    version,
                });
            }
            None => return Err(Error::UnsupportedOpenBaoVersion(version)),
        }
        if !matches!(
            operation.disposition(),
            OpenBaoOperationDisposition::LegacyTypedClaim
                | OpenBaoOperationDisposition::LegacyTypedGatedClaim
        ) {
            return Err(Error::UnsupportedOpenBaoCapability {
                endpoint: endpoint.id(),
                version,
            });
        }
        if !route_template_matches(operation.path_template(), &path_segments, query)? {
            return Err(Error::InvalidPath(
                "request path or query does not match the selected OpenBao endpoint".into(),
            ));
        }
        Ok(ResolvedOpenBaoEndpoint {
            endpoint: endpoint.id(),
            operation,
            method: reqwest_method(operation.method())?,
        })
    }

    #[allow(dead_code)]
    pub(crate) async fn request_endpoint_json_query_headers_accepting<T, B, Q, K>(
        &self,
        endpoint: OpenBaoEndpointSpec,
        path: &str,
        query: &[(K, Q)],
        headers: &[(HeaderName, HeaderValue)],
        body: Option<&B>,
        accepted_statuses: &[StatusCode],
    ) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
        Q: AsRef<str>,
        K: AsRef<str>,
    {
        let resolved = self.resolve_openbao_endpoint(endpoint, path, query).await?;
        let normalized_query = query
            .iter()
            .map(|(key, value)| (key.as_ref(), value.as_ref()))
            .collect::<Vec<_>>();
        self.request_json_query_headers_accepting(
            resolved.method(),
            path,
            &normalized_query,
            headers,
            body,
            accepted_statuses,
        )
        .await
    }

    #[allow(dead_code)]
    pub(crate) async fn request_endpoint_bytes_headers_accepting<Q, K>(
        &self,
        endpoint: OpenBaoEndpointSpec,
        path: &str,
        query: &[(K, Q)],
        headers: &[(HeaderName, HeaderValue)],
        body: Option<&[u8]>,
        accepted_statuses: &[StatusCode],
    ) -> Result<SecretVec>
    where
        Q: AsRef<str>,
        K: AsRef<str>,
    {
        let resolved = self.resolve_openbao_endpoint(endpoint, path, query).await?;
        let normalized_query = query
            .iter()
            .map(|(key, value)| (key.as_ref(), value.as_ref().to_owned()))
            .collect::<Vec<_>>();
        self.request_bytes_headers_accepting_internal(
            resolved.method(),
            path,
            &normalized_query,
            headers,
            body,
            accepted_statuses,
        )
        .await
    }

    async fn resolve_registered_openbao_endpoint<Q, K>(
        &self,
        scope_prefix: &'static str,
        requested_method: &Method,
        path: &str,
        query: &[(K, Q)],
    ) -> Result<ResolvedOpenBaoEndpoint>
    where
        Q: AsRef<str>,
        K: AsRef<str>,
    {
        let path_segments = validate_endpoint_path(path)?;
        let report = self.ensure_compatibility().await?;
        let version = report.profile_version().or_else(|| {
            (report.status() == crate::compatibility::OpenBaoCompatibilityStatus::Unverified)
                .then(latest_generated_profile)
                .flatten()
        });
        let version = version.ok_or(Error::Internal(
            "OpenBao compatibility report has no routing profile",
        ))?;
        if !is_generated_profile(version) {
            return Err(Error::UnsupportedOpenBaoVersion(version));
        }

        let mut matches = Vec::new();
        for operation in crate::compatibility::openbao_operations()
            .iter()
            .copied()
            .filter(|operation| operation.path_template().starts_with(scope_prefix))
        {
            let method = match reqwest_method(operation.method()) {
                Ok(method) => method,
                Err(_) => continue,
            };
            if method != *requested_method
                || !route_template_matches(operation.path_template(), &path_segments, query)?
            {
                continue;
            }
            matches.push((
                route_template_specificity(operation.path_template()),
                operation,
            ));
        }
        let Some(maximum_specificity) = matches.iter().map(|(score, _)| *score).max() else {
            return Err(Error::Internal(
                "typed OpenBao request has no matching registry operation",
            ));
        };
        let mut selected = matches
            .into_iter()
            .filter(|(score, _)| *score == maximum_specificity)
            .map(|(_, operation)| operation);
        let operation = selected.next().ok_or(Error::Internal(
            "typed OpenBao request has no matching registry operation",
        ))?;
        if selected.next().is_some() {
            return Err(Error::Internal(
                "typed OpenBao request matches multiple registry operations",
            ));
        }
        if !matches!(
            operation.availability(version),
            Some(OpenBaoCapabilityAvailability::DocumentedRoute)
        ) || !matches!(
            operation.disposition(),
            OpenBaoOperationDisposition::LegacyTypedClaim
                | OpenBaoOperationDisposition::LegacyTypedGatedClaim
        ) {
            return Err(Error::UnsupportedOpenBaoCapability {
                endpoint: operation.id(),
                version,
            });
        }
        Ok(ResolvedOpenBaoEndpoint {
            endpoint: operation.id(),
            operation,
            method: reqwest_method(operation.method())?,
        })
    }

    pub(crate) async fn request_sys_json_internal<T, B>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.request_sys_json_accepting(
            method,
            path,
            body,
            &[StatusCode::OK, StatusCode::NO_CONTENT],
        )
        .await
    }

    pub(crate) async fn request_sys_json_accepting<T, B>(
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
        self.request_sys_json_query_headers_accepting(
            method,
            path,
            &[] as &[(&str, String)],
            &[],
            body,
            accepted_statuses,
        )
        .await
    }

    pub(crate) async fn request_sys_json_headers_accepting<T, B>(
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
        self.request_sys_json_query_headers_accepting(
            method,
            path,
            &[] as &[(&str, String)],
            headers,
            body,
            accepted_statuses,
        )
        .await
    }

    pub(crate) async fn request_sys_json_query_accepting<T, B>(
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
        self.request_sys_json_query_headers_accepting(
            method,
            path,
            query,
            &[],
            body,
            accepted_statuses,
        )
        .await
    }

    async fn request_sys_json_query_headers_accepting<T, B, Q, K>(
        &self,
        method: Method,
        path: &str,
        query: &[(K, Q)],
        headers: &[(HeaderName, HeaderValue)],
        body: Option<&B>,
        accepted_statuses: &[StatusCode],
    ) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
        Q: AsRef<str>,
        K: AsRef<str>,
    {
        let resolved = self
            .resolve_registered_openbao_endpoint("/sys/", &method, path, query)
            .await?;
        let normalized_query = query
            .iter()
            .map(|(key, value)| (key.as_ref(), value.as_ref()))
            .collect::<Vec<_>>();
        self.request_json_query_headers_accepting(
            resolved.method(),
            path,
            &normalized_query,
            headers,
            body,
            accepted_statuses,
        )
        .await
    }

    pub(crate) async fn request_sys_bytes_accepting_internal(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        accept: Option<HeaderValue>,
        body: Option<&[u8]>,
        accepted_statuses: &[StatusCode],
    ) -> Result<SecretVec> {
        let mut headers = Vec::new();
        if let Some(accept) = accept {
            headers.push((ACCEPT, accept));
        }
        let resolved = self
            .resolve_registered_openbao_endpoint("/sys/", &method, path, query)
            .await?;
        self.request_bytes_headers_accepting_internal(
            resolved.method(),
            path,
            query,
            &headers,
            body,
            accepted_statuses,
        )
        .await
    }

    /// Sends a raw authenticated or unauthenticated JSON request.
    ///
    /// `path` is relative to `/v1`. It is validated and joined as URL path
    /// segments, so callers should pass values such as `sys/health` or
    /// `secret/data/app`.
    ///
    /// This escape hatch requires both `raw-api` and `raw-api-acknowledged`
    /// because raw calls bypass typed endpoint validation and operation-specific
    /// feature gates. Prefer typed helpers whenever one exists.
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
        ensure_public_raw_api_enabled()?;
        self.request_json_internal(method, path, body).await
    }

    pub(crate) async fn request_json_internal<T, B>(
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
    /// This escape hatch requires `raw-api` and `raw-api-acknowledged`.
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
            &[] as &[(&str, String)],
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

    #[cfg(feature = "oidc-get-callback-acknowledged")]
    pub(crate) async fn request_json_secret_query_accepting<T, B>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
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

    /// Sends a raw byte request and returns a capped sanitizing byte buffer.
    ///
    /// `path` is relative to `/v1` and is validated like [`Self::request_json`].
    /// This escape hatch is intended for OpenBao endpoints whose payloads are
    /// binary protocols or non-JSON documents, such as OCSP, certificates, CRLs,
    /// snapshots, or diagnostic output. Prefer typed helpers where this crate
    /// provides them.
    ///
    /// When `body` is present and no explicit `Content-Type` header is supplied,
    /// OpenBao receives `application/octet-stream`.
    /// This escape hatch requires `raw-api` and `raw-api-acknowledged`.
    pub async fn request_bytes_accepting(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        accept: Option<HeaderValue>,
        body: Option<&[u8]>,
        accepted_statuses: &[StatusCode],
    ) -> Result<SecretVec> {
        ensure_public_raw_api_enabled()?;
        self.request_bytes_accepting_internal(method, path, query, accept, body, accepted_statuses)
            .await
    }

    pub(crate) async fn request_bytes_accepting_internal(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        accept: Option<HeaderValue>,
        body: Option<&[u8]>,
        accepted_statuses: &[StatusCode],
    ) -> Result<SecretVec> {
        let mut headers = Vec::new();
        if let Some(accept) = accept {
            headers.push((ACCEPT, accept));
        }
        self.request_bytes_headers_accepting_internal(
            method,
            path,
            query,
            &headers,
            body,
            accepted_statuses,
        )
        .await
    }

    /// Sends a raw byte request with explicit headers.
    ///
    /// Use this for binary protocols that require a specific request or
    /// response MIME type. Header values are validated by `reqwest`; token and
    /// namespace headers are still managed by the client.
    /// This escape hatch requires `raw-api` and `raw-api-acknowledged`.
    pub async fn request_bytes_headers_accepting(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        headers: &[(HeaderName, HeaderValue)],
        body: Option<&[u8]>,
        accepted_statuses: &[StatusCode],
    ) -> Result<SecretVec> {
        ensure_public_raw_api_enabled()?;
        self.request_bytes_headers_accepting_internal(
            method,
            path,
            query,
            headers,
            body,
            accepted_statuses,
        )
        .await
    }

    async fn request_bytes_headers_accepting_internal(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        headers: &[(HeaderName, HeaderValue)],
        body: Option<&[u8]>,
        accepted_statuses: &[StatusCode],
    ) -> Result<SecretVec> {
        self.ensure_compatibility().await?;
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

    pub(crate) async fn request_json_query_headers_accepting<T, B, Q>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, Q)],
        headers: &[(HeaderName, HeaderValue)],
        body: Option<&B>,
        accepted_statuses: &[StatusCode],
    ) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
        Q: AsRef<str>,
    {
        self.ensure_compatibility().await?;
        let mut url = self.url_for_path(path)?;
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value.as_ref());
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
            let encoded = SecretVec::from_vec(
                serde_json::to_vec(payload)
                    .map_err(|_| Error::Decode("OpenBao request could not be encoded".into()))?,
            );
            let has_content_type = headers.iter().any(|(name, _value)| *name == CONTENT_TYPE);
            if !has_content_type {
                request
                    .headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            }
            // SECURITY: this copy is intentionally non-sanitizing because
            // reqwest::Body does not accept a sanitize-on-drop body buffer.
            // The SecretVec serialization buffer above is cleared; reqwest,
            // TLS, kernel, and device buffers are documented residual risks.
            *request.body_mut() = Some(encoded.with_secret(|bytes| Vec::from(bytes)).into());
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

fn compatibility_error(failure: CachedCompatibilityFailure) -> Error {
    match failure {
        CachedCompatibilityFailure::Policy(OpenBaoCompatibilityFailure::VersionMismatch {
            detected,
            requirement,
        }) => Error::OpenBaoVersionMismatch {
            detected,
            requirement,
        },
        CachedCompatibilityFailure::Policy(OpenBaoCompatibilityFailure::UnknownVersion(
            version,
        )) => Error::UnknownOpenBaoVersion(version),
        CachedCompatibilityFailure::Probe(message) => Error::OpenBaoCompatibilityProbe(message),
    }
}

fn compatibility_health_status_is_accepted(status: StatusCode) -> bool {
    matches!(status.as_u16(), 200 | 429 | 472 | 473 | 501 | 503)
}

fn validate_endpoint_spec(endpoint: OpenBaoEndpointSpec) -> Result<()> {
    let id = endpoint.id();
    if id.is_empty()
        || id.len() > MAX_ENDPOINT_ID_BYTES
        || !id.is_ascii()
        || !id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(Error::Internal("OpenBao endpoint identifier is invalid"));
    }
    let variants = endpoint.variants();
    if variants.is_empty() || variants.len() > MAX_ENDPOINT_VARIANTS {
        return Err(Error::Internal("OpenBao endpoint variant count is invalid"));
    }
    for (index, variant) in variants.iter().copied().enumerate() {
        if variant.minimum() > variant.maximum()
            || !is_generated_profile(variant.minimum())
            || !is_generated_profile(variant.maximum())
        {
            return Err(Error::Internal("OpenBao endpoint variant range is invalid"));
        }
        let operation = openbao_operation(variant.operation_id()).ok_or(Error::Internal(
            "OpenBao endpoint references an unknown registry operation",
        ))?;
        for version in openbao_profile_versions()
            .iter()
            .copied()
            .filter(|version| variant.contains(*version))
        {
            if !matches!(
                operation.availability(version),
                Some(OpenBaoCapabilityAvailability::DocumentedRoute)
                    | Some(OpenBaoCapabilityAvailability::SecurityBlocked)
            ) {
                return Err(Error::Internal(
                    "OpenBao endpoint variant exceeds registry evidence",
                ));
            }
        }
        if variants[..index].iter().copied().any(|previous| {
            previous.minimum() <= variant.maximum() && variant.minimum() <= previous.maximum()
        }) {
            return Err(Error::Internal("OpenBao endpoint variants overlap"));
        }
    }
    Ok(())
}

fn reqwest_method(method: OpenBaoHttpMethod) -> Result<Method> {
    match method {
        OpenBaoHttpMethod::Delete => Ok(Method::DELETE),
        OpenBaoHttpMethod::Get => Ok(Method::GET),
        OpenBaoHttpMethod::Head => Ok(Method::HEAD),
        OpenBaoHttpMethod::List => Method::from_bytes(b"LIST")
            .map_err(|_| Error::Internal("generated LIST method is invalid")),
        OpenBaoHttpMethod::Patch => Ok(Method::PATCH),
        OpenBaoHttpMethod::Post => Ok(Method::POST),
        OpenBaoHttpMethod::Put => Ok(Method::PUT),
        OpenBaoHttpMethod::Scan => Method::from_bytes(b"SCAN")
            .map_err(|_| Error::Internal("generated SCAN method is invalid")),
        OpenBaoHttpMethod::Acme => Err(Error::Internal(
            "ACME protocol operations cannot use typed HTTP dispatch",
        )),
    }
}

fn route_template_matches<Q, K>(
    template: &str,
    path_segments: &[String],
    query: &[(K, Q)],
) -> Result<bool>
where
    Q: AsRef<str>,
    K: AsRef<str>,
{
    let (path_template, query_template) = match template.split_once('?') {
        Some((path, query_template)) if !query_template.contains('?') => {
            (path, Some(query_template))
        }
        Some(_) => return Err(Error::Internal("OpenBao route template query is invalid")),
        None => (template, None),
    };
    let path_matches = expand_optional_route_templates(path_template)?
        .iter()
        .any(|expanded| route_path_matches(expanded, path_segments));
    if !path_matches {
        return Ok(false);
    }
    let Some(query_template) = query_template else {
        return Ok(true);
    };
    for expected in query_template.split('&') {
        let Some((expected_key, expected_value)) = expected.split_once('=') else {
            return Err(Error::Internal("OpenBao route template query is invalid"));
        };
        if expected_key.is_empty() || expected_value.is_empty() {
            return Err(Error::Internal("OpenBao route template query is invalid"));
        }
        let mut values = query
            .iter()
            .filter(|(key, _)| key.as_ref() == expected_key)
            .map(|(_, value)| value.as_ref());
        let Some(value) = values.next() else {
            return Ok(false);
        };
        if values.next().is_some()
            || (expected_value.starts_with(':') && value.is_empty())
            || (!expected_value.starts_with(':') && value != expected_value)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn route_template_specificity(template: &str) -> usize {
    let (path, query) = template
        .split_once('?')
        .map_or((template, None), |(path, query)| (path, Some(query)));
    let static_segments = path
        .split('/')
        .filter(|segment| {
            !segment.is_empty() && !segment.starts_with(':') && !segment.starts_with("(/:")
        })
        .count();
    let total_segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .count();
    query.map_or(0, |value| value.split('&').count() * 10_000)
        + static_segments * 100
        + total_segments
}

fn expand_optional_route_templates(template: &str) -> Result<Vec<String>> {
    let mut expansions = vec![template.to_owned()];
    loop {
        let mut changed = false;
        let mut next = Vec::new();
        for expansion in expansions {
            let Some(start) = expansion.find("(/") else {
                next.push(expansion);
                continue;
            };
            let Some(relative_end) = expansion[start..].find(')') else {
                return Err(Error::Internal(
                    "OpenBao optional route template is invalid",
                ));
            };
            let end = start + relative_end;
            let before = &expansion[..start];
            let optional = &expansion[start + 1..end];
            let after = &expansion[end + 1..];
            next.push(format!("{before}{after}"));
            next.push(format!("{before}{optional}{after}"));
            changed = true;
        }
        if next.len() > MAX_OPTIONAL_ROUTE_EXPANSIONS {
            return Err(Error::Internal(
                "OpenBao optional route expansion limit exceeded",
            ));
        }
        if !changed {
            return Ok(next);
        }
        expansions = next;
    }
}

fn route_path_matches(template: &str, path_segments: &[String]) -> bool {
    if !template.starts_with('/') {
        return false;
    }
    let template_segments = template
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    route_segments_match(&template_segments, path_segments)
}

fn route_segments_match(template: &[&str], actual: &[String]) -> bool {
    let mut memo = vec![vec![None; actual.len() + 1]; template.len() + 1];
    route_segments_match_at(template, actual, 0, 0, &mut memo)
}

fn route_segments_match_at(
    template: &[&str],
    actual: &[String],
    template_index: usize,
    actual_index: usize,
    memo: &mut [Vec<Option<bool>>],
) -> bool {
    if let Some(result) = memo[template_index][actual_index] {
        return result;
    }
    let result = if template_index == template.len() {
        actual_index == actual.len()
    } else {
        let expected = template[template_index];
        if route_placeholder_is_multi_segment(expected) {
            ((actual_index + 1)..=actual.len()).any(|next_actual| {
                route_segments_match_at(template, actual, template_index + 1, next_actual, memo)
            })
        } else if expected.starts_with(':') {
            actual_index < actual.len()
                && route_segments_match_at(
                    template,
                    actual,
                    template_index + 1,
                    actual_index + 1,
                    memo,
                )
        } else if actual_index == actual.len() {
            false
        } else {
            let actual_segment = actual[actual_index].as_str();
            let segment_matches = if expected.starts_with('(') && expected.ends_with(')') {
                expected[1..expected.len() - 1]
                    .split('|')
                    .any(|alternative| !alternative.is_empty() && alternative == actual_segment)
            } else {
                expected == actual_segment
            };
            segment_matches
                && route_segments_match_at(
                    template,
                    actual,
                    template_index + 1,
                    actual_index + 1,
                    memo,
                )
        }
    };
    memo[template_index][actual_index] = Some(result);
    result
}

fn route_placeholder_is_multi_segment(segment: &str) -> bool {
    matches!(segment, ":path" | ":prefix")
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
    if user_agent.len() > MAX_USER_AGENT_BYTES {
        return Err(Error::InvalidParameter(
            "user agent exceeds maximum allowed length".into(),
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
            let mut bearer = String::with_capacity("Bearer ".len() + token_value.len());
            bearer.push_str("Bearer ");
            bearer.push_str(token_value);
            let value = sensitive_header_value(&bearer).map_err(|_| {
                Error::InvalidHeader("token must be valid for Authorization header use".into())
            });
            bearer.secure_sanitize();
            let value = value?;
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
    for key in TOKEN_ENV_KEYS {
        let Some(value) = lookup(key) else {
            continue;
        };
        let token = SecretString::from(value);
        if !token.expose_secret().trim().is_empty() {
            return Ok(token);
        }
    }
    Err(Error::MissingToken)
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

    body.with_secret(|bytes| {
        serde_json::from_slice(bytes)
            .map_err(|_| Error::Decode("OpenBao response did not match expected schema".into()))
    })
}

async fn read_response_bytes(
    mut response: reqwest::Response,
    max_response_bytes: usize,
) -> Result<SecretVec> {
    if response
        .content_length()
        .is_some_and(|length| length > max_response_bytes as u64)
    {
        return Err(Error::Decode(
            "OpenBao response exceeds client limit".into(),
        ));
    }

    let mut body = SecretVec::empty();
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

    use std::{
        collections::BTreeMap,
        io::{Read, Write},
        net::TcpListener,
        sync::atomic::{AtomicBool, Ordering},
        thread,
    };

    use secrecy::{ExposeSecret, SecretString};
    use serde::{Serialize, Serializer};

    use crate::{Empty, Error, OpenBaoCompatibilityPolicy, OpenBaoVersion};

    use super::{
        Client, OpenBaoConfig, env_bool, is_cleartext_url, openbao_config_from_env_lookup,
        openbao_token_from_env_lookup, route_template_matches, validate_token_for_header,
        validate_user_agent,
    };
    use crate::compatibility::{OpenBaoEndpointSpec, OpenBaoEndpointVariant};

    const HEALTH_ENDPOINT: OpenBaoEndpointSpec = OpenBaoEndpointSpec::new(
        "sys.health",
        &[OpenBaoEndpointVariant::new(
            "openbao.get.sys.health.e507fdd0e65b1259",
            OpenBaoVersion::new(2, 0, 0),
            OpenBaoVersion::new(2, 5, 5),
        )],
    );

    const CEL_ROLE_DELETE_ENDPOINT: OpenBaoEndpointSpec = OpenBaoEndpointSpec::new(
        "pki.cel.role.delete",
        &[OpenBaoEndpointVariant::new(
            "openbao.delete.pki.cel.roles.name.1388a4e7ce4223e8",
            OpenBaoVersion::new(2, 4, 0),
            OpenBaoVersion::new(2, 5, 5),
        )],
    );

    const VERSIONED_PROBE_ENDPOINT: OpenBaoEndpointSpec = OpenBaoEndpointSpec::new(
        "test.versioned.probe",
        &[
            OpenBaoEndpointVariant::new(
                "openbao.get.sys.seal.status.21c9eeaaf2f76755",
                OpenBaoVersion::new(2, 0, 0),
                OpenBaoVersion::new(2, 4, 4),
            ),
            OpenBaoEndpointVariant::new(
                "openbao.get.sys.health.e507fdd0e65b1259",
                OpenBaoVersion::new(2, 5, 0),
                OpenBaoVersion::new(2, 5, 5),
            ),
        ],
    );

    const SECURITY_BLOCKED_ENDPOINT: OpenBaoEndpointSpec = OpenBaoEndpointSpec::new(
        "sys.monitor.blocked",
        &[OpenBaoEndpointVariant::new(
            "openbao.get.sys.monitor.31691ac3a18a5972",
            OpenBaoVersion::new(2, 0, 0),
            OpenBaoVersion::new(2, 5, 5),
        )],
    );

    const OVERLAPPING_ENDPOINT: OpenBaoEndpointSpec = OpenBaoEndpointSpec::new(
        "test.overlap",
        &[
            OpenBaoEndpointVariant::new(
                "openbao.get.sys.health.e507fdd0e65b1259",
                OpenBaoVersion::new(2, 0, 0),
                OpenBaoVersion::new(2, 5, 0),
            ),
            OpenBaoEndpointVariant::new(
                "openbao.get.sys.health.e507fdd0e65b1259",
                OpenBaoVersion::new(2, 5, 0),
                OpenBaoVersion::new(2, 5, 5),
            ),
        ],
    );

    struct SerializationSentinel<'a>(&'a AtomicBool);

    impl Serialize for SerializationSentinel<'_> {
        fn serialize<S>(&self, _serializer: S) -> core::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            self.0.store(true, Ordering::SeqCst);
            Err(serde::ser::Error::custom(
                "serialization sentinel must not be called",
            ))
        }
    }

    async fn versioned_probe_response(
        status_line: &'static str,
        body: &'static str,
    ) -> crate::Result<Empty> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
            let mut request = [0_u8; 2048];
            let count = stream
                .read(&mut request)
                .unwrap_or_else(|error| panic!("{error}"));
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(request.starts_with("GET /v1/sys/health HTTP/1.1"));
            let response = format!(
                "HTTP/1.1 {status_line}\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .unwrap_or_else(|error| panic!("{error}"));
        });
        let policy = OpenBaoCompatibilityPolicy::assume(OpenBaoVersion::new(2, 5, 5))
            .unwrap_or_else(|error| panic!("{error}"));
        let config = OpenBaoConfig::new(format!("http://{address}"))
            .and_then(OpenBaoConfig::allow_localhost_http)
            .map(|config| config.compatibility_policy(policy))
            .unwrap_or_else(|error| panic!("{error}"));
        let client = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));
        let result = client
            .request_endpoint_json_query_headers_accepting::<Empty, Empty, &str, &str>(
                VERSIONED_PROBE_ENDPOINT,
                "sys/health",
                &[],
                &[],
                None,
                &[reqwest::StatusCode::OK],
            )
            .await;
        server.join().unwrap_or_else(|error| panic!("{error:?}"));
        result
    }

    #[test]
    fn rejects_http_by_default() {
        assert!(Client::new("http://127.0.0.1:8200").is_err());
    }

    #[test]
    fn reports_the_tls_backend_selected_by_crate_features() {
        let client = Client::new("https://bao.example.com")
            .unwrap_or_else(|error| panic!("failed to build client: {error}"));

        #[cfg(feature = "native-tls")]
        assert_eq!(client.tls_backend(), super::TlsBackend::Native);
        #[cfg(all(not(feature = "native-tls"), feature = "rustls-tls"))]
        assert_eq!(client.tls_backend(), super::TlsBackend::Rustls);
    }

    #[test]
    fn base_url_rejects_credentials_query_fragment_and_application_path() {
        for base_url in [
            "https://user:password@bao.example.com",
            "https://bao.example.com?token=query-secret",
            "https://bao.example.com#fragment-secret",
            "https://bao.example.com/openbao",
        ] {
            let error = match OpenBaoConfig::new(base_url) {
                Ok(_) => panic!("unsafe base URL unexpectedly accepted"),
                Err(error) => error,
            };
            let display = error.to_string();
            assert!(matches!(error, Error::InvalidBaseUrl(_)));
            assert!(!display.contains("password"));
            assert!(!display.contains("query-secret"));
            assert!(!display.contains("fragment-secret"));
        }
    }

    #[cfg(not(feature = "raw-api"))]
    #[test]
    fn public_raw_api_is_disabled_without_acknowledgement() {
        assert!(matches!(
            super::ensure_public_raw_api_enabled(),
            Err(Error::RawApiDisabled)
        ));
    }

    #[cfg(all(feature = "raw-api", feature = "raw-api-acknowledged"))]
    #[test]
    fn public_raw_api_is_enabled_only_by_acknowledged_feature_pair() {
        assert!(super::ensure_public_raw_api_enabled().is_ok());
    }

    #[tokio::test]
    async fn unsupported_endpoint_fails_before_body_serialization() {
        let policy = OpenBaoCompatibilityPolicy::assume(OpenBaoVersion::new(2, 0, 0))
            .unwrap_or_else(|error| panic!("{error}"));
        let config = OpenBaoConfig::new("https://bao.example.com")
            .map(|config| config.compatibility_policy(policy))
            .unwrap_or_else(|error| panic!("{error}"));
        let client = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));
        let serialized = AtomicBool::new(false);
        let payload = SerializationSentinel(&serialized);

        let result = client
            .request_endpoint_json_query_headers_accepting::<Empty, _, &str, &str>(
                CEL_ROLE_DELETE_ENDPOINT,
                "pki/cel/roles/example",
                &[],
                &[],
                Some(&payload),
                &[reqwest::StatusCode::NO_CONTENT],
            )
            .await;

        assert!(matches!(
            result,
            Err(Error::UnsupportedOpenBaoCapability {
                endpoint: "pki.cel.role.delete",
                version
            }) if version == OpenBaoVersion::new(2, 0, 0)
        ));
        assert!(!serialized.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn endpoint_dispatch_derives_method_and_rejects_route_substitution() {
        let policy = OpenBaoCompatibilityPolicy::assume(OpenBaoVersion::new(2, 5, 5))
            .unwrap_or_else(|error| panic!("{error}"));
        let config = OpenBaoConfig::new("https://bao.example.com")
            .map(|config| config.compatibility_policy(policy))
            .unwrap_or_else(|error| panic!("{error}"));
        let client = Client::from_config(config).unwrap_or_else(|error| panic!("{error}"));

        let resolved = client
            .resolve_openbao_endpoint(HEALTH_ENDPOINT, "sys/health", &[] as &[(&str, &str)])
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(resolved.method(), reqwest::Method::GET);
        assert_eq!(resolved.endpoint(), "sys.health");
        assert_eq!(resolved.operation().path_template(), "/sys/health");

        let substituted = client
            .resolve_openbao_endpoint(
                HEALTH_ENDPOINT,
                "sys/secret-route-marker",
                &[] as &[(&str, &str)],
            )
            .await;
        let substituted = match substituted {
            Ok(_) => panic!("substituted endpoint route unexpectedly resolved"),
            Err(error) => error,
        };
        assert!(matches!(substituted, Error::InvalidPath(_)));
        assert!(!substituted.to_string().contains("secret-route-marker"));

        let blocked = client
            .resolve_openbao_endpoint(
                SECURITY_BLOCKED_ENDPOINT,
                "sys/monitor",
                &[] as &[(&str, &str)],
            )
            .await;
        assert!(matches!(
            blocked,
            Err(Error::UnsupportedOpenBaoCapability {
                endpoint: "sys.monitor.blocked",
                version
            }) if version == OpenBaoVersion::new(2, 5, 5)
        ));

        let overlap = client
            .resolve_openbao_endpoint(OVERLAPPING_ENDPOINT, "sys/health", &[] as &[(&str, &str)])
            .await;
        assert!(matches!(overlap, Err(Error::Internal(_))));
    }

    #[test]
    fn route_template_matching_handles_optional_alternative_and_query_segments() {
        let transit = vec![
            "transit".to_owned(),
            "export".to_owned(),
            "encryption-key".to_owned(),
            "service-key".to_owned(),
            "3".to_owned(),
        ];
        assert!(
            route_template_matches::<&str, &str>(
                "/transit/export/:key_type/:name(/:version)",
                &transit,
                &[],
            )
            .unwrap_or_else(|error| panic!("{error}"))
        );
        let rotate = vec![
            "sys".to_owned(),
            "rotate".to_owned(),
            "recovery".to_owned(),
            "verify".to_owned(),
        ];
        assert!(
            route_template_matches::<&str, &str>(
                "/sys/rotate/(root|recovery)/verify",
                &rotate,
                &[],
            )
            .unwrap_or_else(|error| panic!("{error}"))
        );
        let plugin = vec![
            "sys".to_owned(),
            "plugins".to_owned(),
            "catalog".to_owned(),
            "secret".to_owned(),
            "example".to_owned(),
        ];
        assert!(
            route_template_matches(
                "/sys/plugins/catalog/:type/:name?version=:version",
                &plugin,
                &[("version", "1.2.3")],
            )
            .unwrap_or_else(|error| panic!("{error}"))
        );
        assert!(
            !route_template_matches(
                "/sys/plugins/catalog/:type/:name?version=:version",
                &plugin,
                &[("version", "")],
            )
            .unwrap_or_else(|error| panic!("{error}"))
        );

        let extra_name_segment = vec![
            "sys".to_owned(),
            "policies".to_owned(),
            "password".to_owned(),
            "team".to_owned(),
            "app".to_owned(),
            "generate".to_owned(),
        ];
        assert!(
            !route_template_matches::<&str, &str>(
                "/sys/policies/password/:name/generate",
                &extra_name_segment,
                &[],
            )
            .unwrap_or_else(|error| panic!("{error}"))
        );
        let multi_segment_path = vec![
            "sys".to_owned(),
            "mounts".to_owned(),
            "team".to_owned(),
            "approle".to_owned(),
            "tune".to_owned(),
        ];
        assert!(
            route_template_matches::<&str, &str>(
                "/sys/mounts/:path/tune",
                &multi_segment_path,
                &[],
            )
            .unwrap_or_else(|error| panic!("{error}"))
        );
    }

    #[test]
    fn cancelled_compatibility_waiter_removes_its_registration() {
        let compatibility = super::ClientCompatibility::new(None);
        *compatibility
            .verification
            .lock()
            .unwrap_or_else(|error| panic!("{error}")) =
            super::CompatibilityVerificationState::Running(Vec::new());
        let wait = super::CompatibilityWait {
            compatibility: &compatibility,
            token: std::sync::Arc::new(()),
        };
        let mut wait = Box::pin(wait);
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        assert!(matches!(
            core::future::Future::poll(wait.as_mut(), &mut context),
            core::task::Poll::Pending
        ));
        assert_eq!(
            match &*compatibility
                .verification
                .lock()
                .unwrap_or_else(|error| panic!("{error}"))
            {
                super::CompatibilityVerificationState::Running(waiters) => waiters.len(),
                _ => 0,
            },
            1
        );
        drop(wait);
        assert!(matches!(
            &*compatibility
                .verification
                .lock()
                .unwrap_or_else(|error| panic!("{error}")),
            super::CompatibilityVerificationState::Running(waiters) if waiters.is_empty()
        ));
    }

    #[tokio::test]
    async fn endpoint_dispatch_does_not_fallback_after_http_failure() {
        for (status_line, expected) in [
            ("404 Not Found", reqwest::StatusCode::NOT_FOUND),
            (
                "405 Method Not Allowed",
                reqwest::StatusCode::METHOD_NOT_ALLOWED,
            ),
        ] {
            let result = versioned_probe_response(status_line, r#"{"errors":["missing"]}"#).await;
            assert!(matches!(
                result,
                Err(Error::Api { status, .. }) if status == expected
            ));
        }

        let decode = versioned_probe_response("200 OK", "not-json").await;
        assert!(matches!(decode, Err(Error::Decode(_))));
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
    fn tls_floor_rejects_versions_below_12() {
        assert!(matches!(
            super::validate_min_tls_version(reqwest::tls::Version::TLS_1_0),
            Err(Error::InvalidTlsConfig(message)) if message.contains("below 1.2")
        ));
        assert!(matches!(
            super::validate_min_tls_version(reqwest::tls::Version::TLS_1_1),
            Err(Error::InvalidTlsConfig(message)) if message.contains("below 1.2")
        ));
    }

    #[cfg(not(feature = "tls12-acknowledged"))]
    #[test]
    fn tls_12_requires_acknowledgement_feature() {
        assert!(matches!(
            super::validate_min_tls_version(reqwest::tls::Version::TLS_1_2),
            Err(Error::InvalidTlsConfig(message)) if message.contains("tls12-acknowledged")
        ));
        assert!(super::validate_min_tls_version(reqwest::tls::Version::TLS_1_3).is_ok());
    }

    #[cfg(feature = "tls12-acknowledged")]
    #[test]
    fn tls_12_is_allowed_when_acknowledged() {
        assert!(super::validate_min_tls_version(reqwest::tls::Version::TLS_1_2).is_ok());
        assert!(super::validate_min_tls_version(reqwest::tls::Version::TLS_1_3).is_ok());
    }

    #[test]
    fn user_agent_rejects_control_characters() {
        assert!(validate_user_agent("openbao-rust-client").is_ok());
        assert!(validate_user_agent("").is_err());
        assert!(validate_user_agent(&"a".repeat(super::MAX_USER_AGENT_BYTES)).is_ok());
        assert!(validate_user_agent(&"a".repeat(super::MAX_USER_AGENT_BYTES + 1)).is_err());
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

    #[cfg(all(feature = "rustls-tls", feature = "native-tls"))]
    #[test]
    fn certificate_revocation_lists_fail_when_native_tls_is_selected() {
        let root =
            crate::Certificate::from_pem(include_bytes!("../tests/fixtures/tls_test_ca.pem"))
                .unwrap_or_else(|error| panic!("failed to parse test certificate: {error}"));
        let crl = include_bytes!("../tests/fixtures/tls_test_ca.crl.pem");
        let config = OpenBaoConfig::new("https://bao.example.com")
            .and_then(|config| config.only_root_certificates(vec![root]))
            .and_then(|config| config.add_certificate_revocation_list_pem(crl))
            .unwrap_or_else(|error| panic!("failed to prepare CRL configuration: {error}"));
        let result = super::ClientBuilder::new(config).build();

        assert!(
            matches!(result, Err(Error::InvalidTlsConfig(message)) if message.contains("selected Rustls TLS backend"))
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

    #[test]
    fn env_token_ingestion_moves_and_preserves_non_empty_values() {
        let env = env_map([
            ("OPENBAO_TOKEN", "   "),
            ("BAO_TOKEN", " token-with-spaces "),
        ]);
        let token = openbao_token_from_env_lookup(|key| env.get(key).cloned())
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(token.expose_secret(), " token-with-spaces ");
        assert!(
            validate_token_for_header(&token, super::HeaderMode::VaultToken).is_err(),
            "environment token whitespace must not be silently normalized"
        );
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
