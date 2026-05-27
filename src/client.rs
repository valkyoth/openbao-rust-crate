//! OpenBao client construction and raw request helpers.

use core::{fmt, marker::PhantomData, time::Duration};

use reqwest::{
    Method, StatusCode, Url,
    header::{ACCEPT, CONTENT_TYPE, HeaderValue},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroize;

use crate::{
    Error, Result,
    path::{validate_mount_path, validate_secret_path},
    response::ErrorEnvelope,
};

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
    /// Permit `http://127.0.0.1`, `http://[::1]`, and `http://localhost`.
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

/// Validated OpenBao client configuration.
#[derive(Clone)]
pub struct OpenBaoConfig {
    base_url: Url,
    timeout: Duration,
    user_agent: String,
    namespace: Option<String>,
    http_policy: HttpPolicy,
    header_mode: HeaderMode,
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
            user_agent: concat!("openbao-rust/", env!("CARGO_PKG_VERSION")).to_owned(),
            namespace: None,
            http_policy: HttpPolicy::HttpsOnly,
            header_mode: HeaderMode::VaultToken,
        })
    }

    /// Allows plain HTTP only for loopback development and tests.
    pub fn allow_localhost_http(mut self) -> Result<Self> {
        self.http_policy = HttpPolicy::LocalhostHttpAllowed;
        self.validate()?;
        Ok(self)
    }

    /// Sets a request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
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
                "plain HTTP is only allowed for explicit localhost development".into(),
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
            .field("user_agent", &self.user_agent)
            .field("namespace", &self.namespace)
            .field("http_policy", &self.http_policy)
            .field("header_mode", &self.header_mode)
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
        let http = reqwest::Client::builder()
            .timeout(self.config.timeout)
            .user_agent(self.config.user_agent.clone())
            .https_only(self.config.http_policy == HttpPolicy::HttpsOnly)
            .build()?;

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
        let url = self.url_for_path(path)?;
        let mut request = self
            .http
            .request(method, url)
            .header(ACCEPT, "application/json")
            .header("X-Vault-Request", "true");

        if let Some(namespace) = self.config.namespace.as_deref() {
            request = request.header("X-Vault-Namespace", namespace);
        }
        if let Some(token) = self.token.as_ref() {
            request = match self.config.header_mode {
                HeaderMode::VaultToken => request.header(
                    "X-Vault-Token",
                    sensitive_header_value(token.expose_secret())?,
                ),
                HeaderMode::Bearer => {
                    let mut bearer =
                        String::with_capacity("Bearer ".len() + token.expose_secret().len());
                    bearer.push_str("Bearer ");
                    bearer.push_str(token.expose_secret());
                    let value = sensitive_header_value(&bearer)
                        .map_err(|error| Error::InvalidHeader(error.to_string()))?;
                    bearer.zeroize();
                    request.header(reqwest::header::AUTHORIZATION, value)
                }
            };
        }
        if let Some(payload) = body {
            request = request
                .header(CONTENT_TYPE, "application/json")
                .json(payload);
        }

        let response = request.send().await?;
        let status = response.status();
        if !accepted_statuses.contains(&status) {
            let error = response
                .json::<ErrorEnvelope>()
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
        response.json::<T>().await.map_err(Error::Http)
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
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
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
}
