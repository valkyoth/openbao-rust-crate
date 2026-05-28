//! Shared OpenBao response envelopes.

use core::fmt;

use secrecy::SecretString;
use serde::de::Error as DeError;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{IgnoredAny, MapAccess, SeqAccess, Visitor},
};

use std::collections::BTreeMap;

const MAX_API_ERRORS: usize = 16;
pub(crate) const MAX_RESPONSE_STRINGS: usize = 4096;

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
    #[serde(default, deserialize_with = "deserialize_optional_bounded_string_vec")]
    pub warnings: Option<Vec<String>>,
    /// Response wrapping metadata, when OpenBao returns a wrapped response.
    #[serde(default)]
    pub wrap_info: Option<WrapInfo>,
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
            .field("wrap_info", &self.wrap_info)
            .finish()
    }
}

/// Metadata for a response-wrapping token.
#[derive(Clone, Deserialize)]
pub struct WrapInfo {
    /// Wrapping token. Treat as secret material.
    pub token: SecretString,
    /// Token accessor, when returned. Treat as secret material.
    #[serde(default)]
    pub accessor: Option<SecretString>,
    /// Wrapping token TTL in seconds.
    #[serde(default)]
    pub ttl: u64,
    /// Wrapped response creation time.
    #[serde(default)]
    pub creation_time: Option<String>,
    /// Wrapped response creation path.
    #[serde(default)]
    pub creation_path: Option<String>,
}

impl fmt::Debug for WrapInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WrapInfo")
            .field("token", &"<redacted>")
            .field("accessor", &self.accessor.as_ref().map(|_| "<redacted>"))
            .field("ttl", &self.ttl)
            .field("creation_time", &self.creation_time)
            .field("creation_path", &self.creation_path)
            .finish()
    }
}

fn empty_secret() -> SecretString {
    SecretString::from(String::new())
}

pub(crate) fn deserialize_bounded_string_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedStringListVisitor::<MAX_RESPONSE_STRINGS>)
}

pub(crate) fn deserialize_optional_bounded_string_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<BoundedStringList>::deserialize(deserializer).map(|value| value.map(|value| value.0))
}

#[allow(dead_code)]
pub(crate) fn deserialize_bounded_string_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(BoundedStringMapVisitor::<MAX_RESPONSE_STRINGS>)
}

#[allow(dead_code)]
pub(crate) fn deserialize_optional_bounded_string_map<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<BTreeMap<String, String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<BoundedStringMap>::deserialize(deserializer).map(|value| value.map(|value| value.0))
}

#[allow(dead_code)]
pub(crate) fn deserialize_bounded_string_map_or_default<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<BoundedStringMap>::deserialize(deserializer)?
        .map(|value| value.0)
        .unwrap_or_default())
}

#[derive(Deserialize)]
struct BoundedStringList(#[serde(deserialize_with = "deserialize_bounded_string_vec")] Vec<String>);

#[derive(Deserialize)]
#[allow(dead_code)]
struct BoundedStringMap(
    #[serde(deserialize_with = "deserialize_bounded_string_map")] BTreeMap<String, String>,
);

#[allow(dead_code)]
pub(crate) fn deserialize_bounded_secret_string_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<SecretString>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedSecretStringListVisitor::<MAX_RESPONSE_STRINGS>)
}

struct BoundedStringListVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedStringListVisitor<MAX> {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a list of at most {MAX} strings")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while values.len() < MAX {
            let Some(value) = seq.next_element::<String>()? else {
                return Ok(values);
            };
            values.push(value);
        }
        if seq.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("OpenBao string list exceeds item limit"));
        }
        Ok(values)
    }
}

#[allow(dead_code)]
struct BoundedStringMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedStringMapVisitor<MAX> {
    type Value = BTreeMap<String, String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} string pairs")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while values.len() < MAX {
            let Some((key, value)) = map.next_entry::<String, String>()? else {
                return Ok(values);
            };
            values.insert(key, value);
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("OpenBao string map exceeds item limit"));
        }
        Ok(values)
    }
}

#[allow(dead_code)]
struct BoundedSecretStringListVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for BoundedSecretStringListVisitor<MAX> {
    type Value = Vec<SecretString>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a list of at most {MAX} secret strings")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while values.len() < MAX {
            let Some(value) = seq.next_element::<String>()? else {
                return Ok(values);
            };
            values.push(SecretString::from(value));
        }
        if seq.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(
                "OpenBao secret string list exceeds item limit",
            ));
        }
        Ok(values)
    }
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
            wrap_info: None,
        };

        let debug = format!("{envelope:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-lease"));
    }

    #[test]
    fn response_debug_redacts_wrap_info() {
        let envelope = ResponseEnvelope {
            data: "ok",
            lease_id: SecretString::from(""),
            lease_duration: 0,
            renewable: false,
            warnings: None,
            wrap_info: Some(super::WrapInfo {
                token: SecretString::from("wrap-token"),
                accessor: Some(SecretString::from("wrap-accessor")),
                ttl: 60,
                creation_time: None,
                creation_path: None,
            }),
        };

        let debug = format!("{envelope:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("wrap-token"));
        assert!(!debug.contains("wrap-accessor"));
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

    #[test]
    fn response_warnings_are_bounded() {
        let mut warnings = Vec::new();
        for index in 0..=super::MAX_RESPONSE_STRINGS {
            warnings.push(format!("warning-{index}"));
        }
        let value = serde_json::json!({ "data": "ok", "warnings": warnings });
        let error = match serde_json::from_value::<ResponseEnvelope<String>>(value) {
            Ok(_) => panic!("oversized warning list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }
}
