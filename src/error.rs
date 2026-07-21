//! Error types returned by the OpenBao SDK.

use core::fmt;

use reqwest::StatusCode;

use crate::compatibility::{OpenBaoVersion, OpenBaoVersionRequirement};

/// Result alias used by this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors returned by OpenBao client operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Base URL parsing or validation failed.
    InvalidBaseUrl(String),
    /// The caller attempted to use a path that could change request meaning.
    InvalidPath(String),
    /// An HTTP header value could not be represented safely.
    InvalidHeader(String),
    /// TLS configuration is internally inconsistent.
    InvalidTlsConfig(String),
    /// Timeout configuration is invalid.
    InvalidTimeout(&'static str),
    /// A request parameter is invalid.
    InvalidParameter(String),
    /// A stable OpenBao server version is malformed or non-canonical.
    ///
    /// The static reason never contains the rejected input.
    InvalidOpenBaoVersion(&'static str),
    /// An exact or inclusive OpenBao version requirement is invalid.
    ///
    /// The static reason never contains the rejected input.
    InvalidOpenBaoVersionRequirement(&'static str),
    /// The detected server version did not satisfy the selected requirement.
    OpenBaoVersionMismatch {
        /// Stable version returned by the public health endpoint.
        detected: OpenBaoVersion,
        /// Exact or closed range selected by the caller.
        requirement: OpenBaoVersionRequirement,
    },
    /// The detected stable server version has no immutable compatibility profile.
    UnknownOpenBaoVersion(OpenBaoVersion),
    /// The public health compatibility probe failed without retaining sensitive context.
    OpenBaoCompatibilityProbe(&'static str),
    /// No immutable routing profile exists for the selected server version.
    UnsupportedOpenBaoVersion(OpenBaoVersion),
    /// A typed SDK endpoint is unavailable for the selected server profile.
    UnsupportedOpenBaoCapability {
        /// Stable, secret-free logical endpoint identifier.
        endpoint: &'static str,
        /// Exact compatibility profile used for dispatch.
        version: OpenBaoVersion,
    },
    /// A caller-selected request field is unavailable on the selected profile.
    UnsupportedOpenBaoRequestField {
        /// Stable, secret-free logical endpoint identifier.
        endpoint: &'static str,
        /// Public Rust/JSON field name.
        field: &'static str,
        /// Exact compatibility profile used for validation.
        version: OpenBaoVersion,
    },
    /// A public raw request was attempted without explicit acknowledgement.
    RawApiDisabled,
    /// Development bootstrap was attempted through the retired default API.
    DevBootstrapDisabled,
    /// A crate invariant was violated.
    Internal(&'static str),
    /// Bootstrap convergence detected that a concurrent writer changed the
    /// target during read-compare-write.
    BootstrapContention(&'static str),
    /// Bootstrap found an existing security-sensitive configuration that it
    /// cannot safely replace while preserving unmanaged fields.
    UnsafeBootstrapConfiguration(&'static str),
    /// The request failed before an OpenBao response could be decoded.
    ///
    /// Transport errors intentionally avoid retaining the underlying HTTP
    /// error because lower layers may attach request URLs to loggable error
    /// chains.
    Transport(&'static str),
    /// A response body could not be decoded into the expected type.
    Decode(String),
    /// OpenBao returned an error status and optional API error list.
    Api {
        /// HTTP status code.
        status: reqwest::StatusCode,
        /// OpenBao error messages, if present.
        errors: Vec<String>,
    },
    /// A successful response did not contain the expected field.
    MissingField(&'static str),
    /// An authenticated-only operation was attempted without a token.
    MissingToken,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseUrl(message) => {
                write!(formatter, "invalid OpenBao base URL: {message}")
            }
            Self::InvalidPath(message) => write!(formatter, "invalid OpenBao path: {message}"),
            Self::InvalidHeader(message) => write!(formatter, "invalid OpenBao header: {message}"),
            Self::InvalidTlsConfig(message) => {
                write!(formatter, "invalid OpenBao TLS configuration: {message}")
            }
            Self::InvalidTimeout(message) => {
                write!(
                    formatter,
                    "invalid OpenBao timeout configuration: {message}"
                )
            }
            Self::InvalidParameter(message) => {
                write!(formatter, "invalid OpenBao request parameter: {message}")
            }
            Self::InvalidOpenBaoVersion(message) => {
                write!(formatter, "invalid OpenBao version: {message}")
            }
            Self::InvalidOpenBaoVersionRequirement(message) => {
                write!(formatter, "invalid OpenBao version requirement: {message}")
            }
            Self::OpenBaoVersionMismatch {
                detected,
                requirement,
            } => write!(
                formatter,
                "OpenBao server version {detected} does not satisfy compatibility requirement {requirement}"
            ),
            Self::UnknownOpenBaoVersion(version) => write!(
                formatter,
                "OpenBao server version {version} has no locked compatibility profile"
            ),
            Self::OpenBaoCompatibilityProbe(message) => {
                write!(formatter, "OpenBao compatibility probe failed: {message}")
            }
            Self::UnsupportedOpenBaoVersion(version) => write!(
                formatter,
                "OpenBao server version {version} is unsupported for typed endpoint dispatch"
            ),
            Self::UnsupportedOpenBaoCapability { endpoint, version } => write!(
                formatter,
                "OpenBao capability {endpoint} is unsupported for server version {version}"
            ),
            Self::UnsupportedOpenBaoRequestField {
                endpoint,
                field,
                version,
            } => write!(
                formatter,
                "OpenBao request field {endpoint}.{field} is unsupported for server version {version}"
            ),
            Self::RawApiDisabled => write!(
                formatter,
                "OpenBao raw request APIs require raw-api and raw-api-acknowledged"
            ),
            Self::DevBootstrapDisabled => write!(
                formatter,
                "OpenBao development bootstrap requires dev-bootstrap, dev-bootstrap-acknowledged, and the explicitly acknowledged API"
            ),
            Self::Internal(message) => write!(formatter, "internal OpenBao SDK error: {message}"),
            Self::BootstrapContention(message) => {
                write!(
                    formatter,
                    "OpenBao bootstrap contention detected: {message}"
                )
            }
            Self::UnsafeBootstrapConfiguration(message) => {
                write!(
                    formatter,
                    "unsafe OpenBao bootstrap configuration: {message}"
                )
            }
            Self::Transport(message) => write!(formatter, "OpenBao transport error: {message}"),
            Self::Decode(error) => write!(formatter, "OpenBao decode error: {error}"),
            Self::Api { status, errors } if errors.is_empty() => {
                write!(formatter, "OpenBao API returned {status}")
            }
            Self::Api { status, errors } => {
                write!(formatter, "OpenBao API returned {status}: ")?;
                for (index, error) in errors.iter().enumerate() {
                    if index > 0 {
                        write!(formatter, "; ")?;
                    }
                    write!(formatter, "{}", sanitize_api_error(error))?;
                }
                Ok(())
            }
            Self::MissingField(field) => {
                write!(formatter, "OpenBao response missing field `{field}`")
            }
            Self::MissingToken => write!(
                formatter,
                "OpenBao client is missing an authentication token"
            ),
        }
    }
}

impl Error {
    /// HTTP status when the failure was an OpenBao API error.
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Api { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Returns true when OpenBao reported the requested path or value as absent.
    pub fn is_not_found(&self) -> bool {
        self.status() == Some(StatusCode::NOT_FOUND)
    }

    /// Returns true when OpenBao rejected the caller's token or policy.
    pub fn is_forbidden(&self) -> bool {
        self.status() == Some(StatusCode::FORBIDDEN)
    }

    /// Returns true when OpenBao reported a malformed or invalid request.
    pub fn is_bad_request(&self) -> bool {
        self.status() == Some(StatusCode::BAD_REQUEST)
    }

    /// Returns true when bootstrap convergence detected a concurrent writer.
    pub fn is_bootstrap_contention(&self) -> bool {
        matches!(self, Self::BootstrapContention(_))
    }

    /// Returns true when bootstrap refused to replace an existing security
    /// configuration because doing so could discard unmanaged fields.
    pub fn is_unsafe_bootstrap_configuration(&self) -> bool {
        matches!(self, Self::UnsafeBootstrapConfiguration(_))
    }

    /// Returns true when OpenBao rate-limited the request.
    pub fn is_rate_limited(&self) -> bool {
        self.status() == Some(StatusCode::TOO_MANY_REQUESTS)
    }

    /// Returns true when OpenBao is sealed or temporarily unavailable.
    pub fn is_sealed(&self) -> bool {
        self.status() == Some(StatusCode::SERVICE_UNAVAILABLE)
    }

    /// Returns true when retrying later may reasonably succeed.
    ///
    /// This includes rate limiting, service unavailability, server errors, and
    /// transport failures before an OpenBao response was decoded. It does not
    /// treat sealed OpenBao as definitively recoverable for every application;
    /// callers with strict startup behavior should check [`Self::is_sealed`]
    /// separately.
    pub fn is_temporary(&self) -> bool {
        match self {
            Self::Transport(_) => true,
            Self::Api { status, .. } => {
                *status == StatusCode::TOO_MANY_REQUESTS
                    || *status == StatusCode::SERVICE_UNAVAILABLE
                    || (status.is_server_error()
                        && *status != StatusCode::NOT_IMPLEMENTED
                        && *status != StatusCode::HTTP_VERSION_NOT_SUPPORTED)
            }
            _ => false,
        }
    }

    /// Returns true when OpenBao reported an authentication or authorization failure.
    ///
    /// This returns true for HTTP 403 responses and for API errors whose
    /// message contains `permission denied`, which OpenBao can return outside
    /// HTTP 403 in some policy-check paths. It is a superset of
    /// [`Self::is_forbidden`].
    pub fn is_permission_denied(&self) -> bool {
        self.status() == Some(StatusCode::FORBIDDEN)
            || matches!(
                self,
                Self::Api { errors, .. }
                    if errors.iter().any(|message| message
                        .to_ascii_lowercase()
                        .contains("permission denied"))
            )
    }

    /// Returns true when a create operation lost an idempotent creation race.
    ///
    /// OpenBao sometimes reports duplicate mounts and keys as HTTP 400 with
    /// textual `already exists`/`already in use` messages rather than HTTP 409.
    pub fn is_conflict(&self) -> bool {
        match self {
            Self::Api { status, .. } if *status == StatusCode::CONFLICT => true,
            Self::Api { status, errors } if *status == StatusCode::BAD_REQUEST => {
                errors.iter().any(|message| {
                    let message = message.to_ascii_lowercase();
                    message.contains("already in use")
                        || message.contains("already exists")
                        || message.contains("existing key")
                })
            }
            _ => false,
        }
    }
}

pub(crate) fn sanitize_api_error(error: &str) -> String {
    const MAX_API_ERROR_BYTES: usize = 512;

    let mut sanitized = String::new();
    for character in error
        .chars()
        .filter(|character| !is_display_control(*character))
    {
        let next_len = sanitized.len() + character.len_utf8();
        if next_len > MAX_API_ERROR_BYTES {
            break;
        }
        sanitized.push(character);
    }
    sanitized
}

fn is_display_control(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

impl std::error::Error for Error {}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        http_transport_error(error)
    }
}

pub(crate) fn http_transport_error(error: reqwest::Error) -> Error {
    Error::Transport(classify_http_transport_error(&error))
}

fn classify_http_transport_error(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "request timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_redirect() {
        "redirect failed"
    } else if error.is_body() {
        "request or response body failed"
    } else if error.is_decode() {
        "response body could not be decoded"
    } else if error.is_request() {
        "request could not be sent"
    } else {
        "request failed before an OpenBao response was received"
    }
}

#[cfg(test)]
mod tests {
    use reqwest::StatusCode;

    use super::{Error, sanitize_api_error};

    #[test]
    fn display_sanitizes_api_errors() {
        let error = Error::Api {
            status: StatusCode::BAD_REQUEST,
            errors: vec![format!("bad\nmessage\r{}", "x".repeat(600))],
        };

        let message = error.to_string();
        assert!(!message.contains('\n'));
        assert!(!message.contains('\r'));
        assert!(message.len() < 600);
    }

    #[test]
    fn api_error_sanitizer_truncates_by_bytes() {
        let sanitized = sanitize_api_error(&"💣".repeat(200));

        assert!(sanitized.len() <= 512);
        assert!(sanitized.is_char_boundary(sanitized.len()));
    }

    #[test]
    fn api_error_helpers_expose_status() {
        let error = Error::Api {
            status: StatusCode::NOT_FOUND,
            errors: Vec::new(),
        };

        assert_eq!(error.status(), Some(StatusCode::NOT_FOUND));
        assert!(error.is_not_found());
        assert!(!Error::MissingToken.is_not_found());
    }

    #[test]
    fn unsafe_bootstrap_configuration_has_a_dedicated_helper() {
        let error = Error::UnsafeBootstrapConfiguration(
            "state-preserving remediation is required before bootstrap",
        );

        assert!(error.is_unsafe_bootstrap_configuration());
        assert!(!error.is_bootstrap_contention());
        assert!(
            error
                .to_string()
                .starts_with("unsafe OpenBao bootstrap configuration:")
        );
    }

    #[test]
    fn api_error_helpers_cover_common_statuses() {
        let forbidden = Error::Api {
            status: StatusCode::FORBIDDEN,
            errors: Vec::new(),
        };
        assert!(forbidden.is_forbidden());

        let sealed = Error::Api {
            status: StatusCode::SERVICE_UNAVAILABLE,
            errors: Vec::new(),
        };
        assert!(sealed.is_sealed());

        let bad_request = Error::Api {
            status: StatusCode::BAD_REQUEST,
            errors: Vec::new(),
        };
        assert!(bad_request.is_bad_request());

        let rate_limited = Error::Api {
            status: StatusCode::TOO_MANY_REQUESTS,
            errors: Vec::new(),
        };
        assert!(rate_limited.is_rate_limited());
        assert!(rate_limited.is_temporary());

        let not_implemented = Error::Api {
            status: StatusCode::NOT_IMPLEMENTED,
            errors: Vec::new(),
        };
        assert!(!not_implemented.is_temporary());

        let permission_denied = Error::Api {
            status: StatusCode::BAD_REQUEST,
            errors: vec!["permission denied".to_owned()],
        };
        assert!(permission_denied.is_permission_denied());
        assert!(!permission_denied.is_forbidden());

        let duplicate = Error::Api {
            status: StatusCode::BAD_REQUEST,
            errors: vec!["path is already in use".to_owned()],
        };
        assert!(duplicate.is_conflict());
    }
}
