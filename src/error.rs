//! Error types returned by the OpenBao SDK.

use core::fmt;

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
            Self::Http(error) => write!(formatter, "OpenBao HTTP error: {error}"),
            Self::Decode(error) => write!(formatter, "OpenBao decode error: {error}"),
            Self::Api { status, errors } if errors.is_empty() => {
                write!(formatter, "OpenBao API returned {status}")
            }
            Self::Api { status, errors } => {
                write!(
                    formatter,
                    "OpenBao API returned {status}: {}",
                    errors.join("; ")
                )
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
