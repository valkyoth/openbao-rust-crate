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
}
