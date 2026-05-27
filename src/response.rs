//! Shared OpenBao response envelopes.

use core::fmt;

use secrecy::SecretString;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{IgnoredAny, SeqAccess, Visitor},
};

const MAX_API_ERRORS: usize = 16;

/// Empty JSON payload used for endpoints that do not require a body.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct Empty {}

/// Standard OpenBao response envelope for endpoints that return `data`.
#[derive(Clone, Deserialize)]
pub struct ResponseEnvelope<T> {
    /// Endpoint-specific response data.
    pub data: T,
    /// Lease identifier, when the endpoint returns one.
    #[serde(default = "empty_secret")]
    pub lease_id: SecretString,
    /// Lease duration in seconds.
    #[serde(default)]
    pub lease_duration: u64,
    /// Whether the lease is renewable.
    #[serde(default)]
    pub renewable: bool,
    /// Warnings emitted by OpenBao.
    #[serde(default)]
    pub warnings: Option<Vec<String>>,
}

impl<T: fmt::Debug> fmt::Debug for ResponseEnvelope<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseEnvelope")
            .field("data", &self.data)
            .field("lease_id", &"<redacted>")
            .field("lease_duration", &self.lease_duration)
            .field("renewable", &self.renewable)
            .field("warnings", &self.warnings)
            .finish()
    }
}

fn empty_secret() -> SecretString {
    SecretString::from(String::new())
}

#[derive(Debug, Deserialize)]
pub(crate) struct ErrorEnvelope {
    #[serde(default, deserialize_with = "deserialize_error_list")]
    pub(crate) errors: Vec<String>,
}

fn deserialize_error_list<'de, D>(deserializer: D) -> core::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(ErrorListVisitor)
}

struct ErrorListVisitor;

impl<'de> Visitor<'de> for ErrorListVisitor {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded list of OpenBao API errors")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut errors = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX_API_ERRORS));
        while errors.len() < MAX_API_ERRORS {
            let Some(error) = seq.next_element::<String>()? else {
                return Ok(errors);
            };
            errors.push(error);
        }
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(errors)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::SecretString;

    use super::ResponseEnvelope;

    #[test]
    fn response_debug_redacts_lease_id() {
        let envelope = ResponseEnvelope {
            data: "ok",
            lease_id: SecretString::from("secret-lease"),
            lease_duration: 30,
            renewable: true,
            warnings: None,
        };

        let debug = format!("{envelope:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-lease"));
    }

    #[test]
    fn error_envelope_caps_error_count() {
        let json = format!(
            r#"{{"errors":[{}]}}"#,
            (0..32)
                .map(|index| format!(r#""error-{index}""#))
                .collect::<Vec<_>>()
                .join(",")
        );

        let envelope: super::ErrorEnvelope =
            serde_json::from_str(&json).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(envelope.errors.len(), 16);
        assert_eq!(envelope.errors[15], "error-15");
    }
}
