use core::fmt;

use sanitization::SecretVec;
use secrecy::{ExposeSecret, SecretString};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor},
    ser::{Error as _, SerializeMap},
};
use serde_json::value::RawValue;

use crate::{Error, Result};

const MAX_BYTES: usize = 256 * 1024;
const MAX_DEPTH: usize = 8;
const MAX_NODES: usize = 2048;
const MAX_MEMBERS: usize = 64;
const MAX_STRING: usize = 64 * 1024;

/// Acknowledges that custom provider options are not a validated provider schema.
///
/// Custom options can change remote endpoints, credentials, TLS checks and
/// hardware behavior. Audit the installed provider and all supplied options.
/// This is a call-site acknowledgement, not an authorization or sandbox boundary.
pub struct ExternalKeyCustomOptionsAcknowledgement(());

impl ExternalKeyCustomOptionsAcknowledgement {
    /// Confirms review of the provider and its security-sensitive option semantics.
    pub fn acknowledge_unvalidated_provider() -> Self {
        Self(())
    }
}

/// Bounded JSON provider options held in sanitizing storage.
///
/// Supports objects, arrays and JSON scalar values, including null for PATCH
/// deletion. Limits: 256 KiB encoded bytes, eight nested containers, 2048 value
/// nodes, 64 members per object and 64 KiB per decoded string. Duplicate object
/// keys are rejected at every depth. Top-level option names are bounded ASCII
/// identifiers. `plugin`, `verify`, `config`, `key` and `mount` are reserved.
///
/// Validation does not establish that a provider accepts these options or that
/// its configuration is secure. Serde's temporary parser storage remains a
/// dependency-owned memory residual, including decoded escaped strings.
pub struct ExternalKeyOptions {
    contents: SecretVec,
}

impl ExternalKeyOptions {
    /// Validates and retains a secret JSON object without ordinary value copies.
    pub fn from_json(contents: SecretVec) -> Result<Self> {
        validate(&contents, true)?;
        Ok(Self { contents })
    }

    /// Serializes into bounded sanitizing storage, then validates the object.
    /// Callers remain responsible for any allocations owned by `value`.
    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Result<Self> {
        Self::from_json(crate::client::encode_bounded_json(value, MAX_BYTES)?)
    }

    /// Borrows the JSON bytes for explicit secret-aware inspection.
    pub fn with_json_bytes<T>(&self, inspect: impl FnOnce(&[u8]) -> T) -> T {
        self.contents.with_secret(inspect)
    }

    pub(super) fn entries<M: SerializeMap>(
        &self,
        map: &mut M,
    ) -> core::result::Result<(), M::Error> {
        // Values remain borrowed encoded JSON, including escaped secret strings.
        // The temporary keys are bounded public option identifiers, not values.
        self.contents.with_secret(|bytes| {
            let fields: std::collections::BTreeMap<String, &RawValue> =
                serde_json::from_slice(bytes)
                    .map_err(|_| M::Error::custom("invalid external-key options"))?;
            for (key, value) in fields {
                map.serialize_entry(&key, value)?;
            }
            Ok(())
        })
    }
}

impl fmt::Debug for ExternalKeyOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalKeyOptions").finish_non_exhaustive()
    }
}

impl Serialize for ExternalKeyOptions {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        self.entries(&mut map)?;
        map.end()
    }
}

/// Secret-aware, bounded provider parameters returned by a config/key read.
///
/// Do not assume the server redacted every sensitive option. Unknown plugin
/// parameters remain in sanitizing storage and Debug reveals no fields.
/// The root object permits 65 fields, allowing 64 options plus `plugin`;
/// nested objects retain the 64-member bound and the total byte/node limits.
/// Responses are not request builders: returned redaction markers must not be
/// written back as credentials. Explicit byte inspection is required.
pub struct ExternalKeyParameters {
    contents: SecretVec,
}

impl ExternalKeyParameters {
    pub(super) fn from_envelope(body: SecretVec) -> Result<Self> {
        body.with_secret(|bytes| {
            #[derive(Deserialize)]
            struct Envelope<'a> {
                #[serde(borrow)]
                data: &'a RawValue,
            }
            let envelope: Envelope<'_> = serde_json::from_slice(bytes)
                .map_err(|_| Error::Decode("invalid external-key response envelope".into()))?;
            if envelope.data.get().len() > MAX_BYTES {
                return Err(Error::Decode(
                    "external-key parameters exceed byte limit".into(),
                ));
            }
            let contents = SecretVec::from_slice(envelope.data.get().as_bytes());
            validate(&contents, false)
                .map_err(|_| Error::Decode("invalid external-key provider parameters".into()))?;
            Ok(Self { contents })
        })
    }

    /// Borrows provider parameters; treat all values as potentially sensitive.
    pub fn with_json_bytes<T>(&self, inspect: impl FnOnce(&[u8]) -> T) -> T {
        self.contents.with_secret(inspect)
    }
}

impl fmt::Debug for ExternalKeyParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalKeyParameters")
            .finish_non_exhaustive()
    }
}

fn validate(contents: &SecretVec, request: bool) -> Result<()> {
    if contents.len() > MAX_BYTES {
        return Err(super::invalid("external-key options exceed byte limit"));
    }
    contents.with_secret(|bytes| {
        let mut budget = MAX_NODES;
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        decoder
            .deserialize_map(Check {
                budget: &mut budget,
                depth: 0,
                request,
            })
            .and_then(|()| decoder.end())
            .map_err(|_| {
                super::invalid("external-key options must be a bounded, duplicate-free JSON object")
            })
    })
}

struct Check<'a> {
    budget: &'a mut usize,
    depth: usize,
    request: bool,
}

impl Check<'_> {
    fn node<E: serde::de::Error>(&mut self) -> core::result::Result<(), E> {
        if *self.budget == 0 {
            return Err(E::custom("external-key node limit exceeded"));
        }
        *self.budget -= 1;
        Ok(())
    }

    fn string<E: serde::de::Error>(value: &str) -> core::result::Result<(), E> {
        if value.len() > MAX_STRING {
            return Err(E::custom("external-key string limit exceeded"));
        }
        Ok(())
    }
}

impl<'de> DeserializeSeed<'de> for Check<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> core::result::Result<(), D::Error> {
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Check<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded provider JSON")
    }
    fn visit_bool<E: serde::de::Error>(mut self, _: bool) -> core::result::Result<(), E> {
        self.node()
    }
    fn visit_i64<E: serde::de::Error>(mut self, _: i64) -> core::result::Result<(), E> {
        self.node()
    }
    fn visit_u64<E: serde::de::Error>(mut self, _: u64) -> core::result::Result<(), E> {
        self.node()
    }
    fn visit_f64<E: serde::de::Error>(mut self, _: f64) -> core::result::Result<(), E> {
        self.node()
    }
    fn visit_unit<E: serde::de::Error>(mut self) -> core::result::Result<(), E> {
        self.node()
    }
    fn visit_str<E: serde::de::Error>(mut self, value: &str) -> core::result::Result<(), E> {
        self.node()?;
        Self::string(value)
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> core::result::Result<(), A::Error> {
        self.node()?;
        if self.depth >= MAX_DEPTH {
            return Err(A::Error::custom("external-key depth limit exceeded"));
        }
        while *self.budget > 0 {
            if seq
                .next_element_seed(Check {
                    budget: self.budget,
                    depth: self.depth + 1,
                    request: self.request,
                })?
                .is_none()
            {
                return Ok(());
            }
        }
        seq.next_element_seed(crate::response::RejectOverflow::new(
            "external-key node limit exceeded",
        ))?;
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(mut self, mut map: A) -> core::result::Result<(), A::Error> {
        self.node()?;
        if self.depth >= MAX_DEPTH {
            return Err(A::Error::custom("external-key depth limit exceeded"));
        }
        let mut keys: Vec<SecretString> = Vec::new();
        let members = MAX_MEMBERS + usize::from(self.depth == 0 && !self.request);
        while keys.len() < members && *self.budget > 0 {
            let Some(key) = map.next_key::<SecretString>()? else {
                return Ok(());
            };
            let text = key.expose_secret();
            Self::string(text)?;
            if self.depth == 0
                && (text.is_empty()
                    || text.len() > 256
                    || !text
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                    || (self.request
                        && matches!(text, "plugin" | "verify" | "config" | "key" | "mount")))
            {
                return Err(A::Error::custom(
                    "invalid or reserved external-key option name",
                ));
            }
            if keys.iter().any(|seen| seen.expose_secret() == text) {
                return Err(A::Error::custom("duplicate external-key option"));
            }
            keys.push(key);
            map.next_value_seed(Check {
                budget: self.budget,
                depth: self.depth + 1,
                request: self.request,
            })?;
        }
        map.next_key_seed(crate::response::RejectOverflow::new(
            "external-key object limit exceeded",
        ))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    use super::*;

    fn parse(text: &str) -> Result<ExternalKeyOptions> {
        ExternalKeyOptions::from_json(SecretVec::from_slice(text.as_bytes()))
    }

    #[test]
    fn options_preserve_nested_values_and_redact_debug() {
        let text = r#"{"nested":{"array":[true,false,null,1,-2,1.5,"esc\u0061ped"]},"empty":{}}"#;
        let options = parse(text).unwrap_or_else(|_| panic!("valid fixture rejected"));
        options.with_json_bytes(|bytes| assert!(bytes == text.as_bytes()));
        let output = crate::client::encode_bounded_json(&options, MAX_BYTES)
            .unwrap_or_else(|_| panic!("serialization failed"));
        assert!(
            output.with_secret(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).is_ok())
        );
        assert!(!format!("{options:?}").contains("nested"));
    }

    #[test]
    fn rejects_reserved_duplicate_and_invalid_names_at_all_depths() {
        for text in [
            r#"{"plugin":"transit"}"#,
            r#"{"verify":false}"#,
            r#"{"config":"other"}"#,
            r#"{"key":"other"}"#,
            r#"{"mount":"other"}"#,
            r#"{"ver\u0069fy":false}"#,
            r#"{"x":1,"x":2}"#,
            r#"{"a":{"x":1,"\u0078":2}}"#,
            r#"{"a":[{"x":1,"x":2}]}"#,
            r#"{"":1}"#,
            r#"{"x\ny":1}"#,
            r#"{"x/y":1}"#,
            "null",
            "[]",
            "{} {}",
            "{",
            r#"{"a":NaN}"#,
        ] {
            assert!(parse(text).is_err());
        }
        assert!(parse(r#"{"nested":{"plugin":"provider-private"}}"#).is_ok());
        assert!(parse(&format!("{{\"{}\":0}}", "x".repeat(256))).is_ok());
        assert!(parse(&format!("{{\"{}\":0}}", "x".repeat(257))).is_err());
    }

    #[test]
    fn enforces_exact_byte_string_depth_node_and_member_bounds() {
        let exact = format!("{{}}{}", " ".repeat(MAX_BYTES - 2));
        assert!(parse(&exact).is_ok());
        assert!(parse(&(exact + " ")).is_err());
        assert!(parse(&format!("{{\"value\":\"{}\"}}", "x".repeat(MAX_STRING))).is_ok());
        assert!(parse(&format!("{{\"value\":\"{}\"}}", "x".repeat(MAX_STRING + 1))).is_err());
        for (count, valid) in [(MAX_MEMBERS, true), (MAX_MEMBERS + 1, false)] {
            let entries = (0..count)
                .map(|n| format!("\"k{n}\":0"))
                .collect::<Vec<_>>()
                .join(",");
            assert_eq!(parse(&format!("{{{entries}}}")).is_ok(), valid);
        }
        for (arrays, valid) in [(MAX_DEPTH - 1, true), (MAX_DEPTH, false)] {
            let text = format!("{{\"a\":{}0{}}}", "[".repeat(arrays), "]".repeat(arrays));
            assert_eq!(parse(&text).is_ok(), valid);
        }
        for (nodes, valid) in [(MAX_NODES - 2, true), (MAX_NODES - 1, false)] {
            let text = format!("{{\"a\":[{}]}}", vec!["0"; nodes].join(","));
            assert_eq!(parse(&text).is_ok(), valid);
        }
    }

    #[test]
    fn response_parameters_are_secret_bounded_and_not_request_options() {
        let response = SecretVec::from_slice(
            br#"{"data":{"plugin":"transit","token":"fixture-value","unknown":{"flag":true}}}"#,
        );
        let parameters = ExternalKeyParameters::from_envelope(response)
            .unwrap_or_else(|_| panic!("valid response rejected"));
        assert!(!format!("{parameters:?}").contains("fixture-value"));
        parameters.with_json_bytes(|bytes| {
            assert!(parse(core::str::from_utf8(bytes).unwrap_or_default()).is_err())
        });
        for text in [
            r#"{"data":{"a":1,"a":2}}"#,
            r#"{"data":{},"data":{}}"#,
            r#"{"data":[]}"#,
            r#"{"data":null}"#,
            r#"{}"#,
            r#"{"data":{"a":{"x":1,"x":2}}}"#,
        ] {
            assert!(
                ExternalKeyParameters::from_envelope(SecretVec::from_slice(text.as_bytes()))
                    .is_err()
            );
        }
        let over = format!("{{\"data\":{{\"a\":\"{}\"}}}}", "x".repeat(MAX_BYTES));
        assert!(
            ExternalKeyParameters::from_envelope(SecretVec::from_slice(over.as_bytes())).is_err()
        );
        for (count, valid) in [(MAX_MEMBERS, true), (MAX_MEMBERS + 1, false)] {
            let entries = (0..count)
                .map(|n| format!("\"k{n}\":0"))
                .collect::<Vec<_>>()
                .join(",");
            let body = format!("{{\"data\":{{\"plugin\":\"custom\",{entries}}}}}");
            assert_eq!(
                ExternalKeyParameters::from_envelope(SecretVec::from_slice(body.as_bytes()))
                    .is_ok(),
                valid
            );
        }
    }

    #[test]
    fn failures_do_not_echo_values_and_serialization_remains_bounded() {
        let marker = ["fixture", "private-value"].join("-");
        let invalid = format!("{{\"a\":\"{marker}\",\"a\":null}}");
        let Err(error) = parse(&invalid) else {
            panic!("duplicate accepted")
        };
        assert!(!format!("{error} {error:?}").contains(&marker));
        let options = parse(&format!("{{\"a\":\"{marker}\"}}"))
            .unwrap_or_else(|_| panic!("valid fixture rejected"));
        assert!(crate::client::encode_bounded_json(&options, 8).is_err());
        assert!(ExternalKeyOptions::from_serializable(&vec![0]).is_err());
    }
}
