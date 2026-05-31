//! Error types returned by the OpenBao SDK.

use core::fmt;

use reqwest::StatusCode;

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
    /// A crate invariant was violated.
    Internal(&'static str),
    /// The request failed before an OpenBao response could be decoded.
    Http(reqwest::Error),
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
            Self::Internal(message) => write!(formatter, "internal OpenBao SDK error: {message}"),
            Self::Http(error) => write!(formatter, "OpenBao HTTP error: {error}"),
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

    /// Returns true when OpenBao is sealed or temporarily unavailable.
    pub fn is_sealed(&self) -> bool {
        self.status() == Some(StatusCode::SERVICE_UNAVAILABLE)
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

fn sanitize_api_error(error: &str) -> String {
    error
        .chars()
        .filter(|character| !character.is_control())
        .take(512)
        .collect()
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Http(error) => Some(error),
            _ => None,
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Self::Http(error)
    }
}

#[cfg(test)]
mod tests {
    use reqwest::StatusCode;

    use super::Error;

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

        let duplicate = Error::Api {
            status: StatusCode::BAD_REQUEST,
            errors: vec!["path is already in use".to_owned()],
        };
        assert!(duplicate.is_conflict());
    }
}
