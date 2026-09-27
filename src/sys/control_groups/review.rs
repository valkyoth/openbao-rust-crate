use core::fmt;
use sanitization::SecretVec;
use secrecy::{ExposeSecret, SecretString};
use serde::{
    Deserialize, Deserializer,
    de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor},
};
use serde_json::value::RawValue;

use crate::{Error, Result, response::RejectOverflow};

const MAX_BYTES: usize = 512 * 1024;
const MAX_DEPTH: usize = 16;
const MAX_NODES: usize = 4096;
const MAX_ITEMS: usize = 256;
const MAX_STRING: usize = 64 * 1024;

fn invalid() -> Error {
    Error::Decode("invalid or oversized control-group review response".into())
}

/// Saved JSON request or identity metadata in sanitizing storage.
///
/// Values are retained as encoded JSON, without an ordinary `JsonValue` tree.
/// Use explicit inspection and avoid logging or copying sensitive contents.
/// Request data can be JSON null when the original request had no payload.
/// Serde's escaped-string scratch space and HTTP/TLS buffers remain dependency
/// memory residuals; this does not guarantee complete process-memory erasure.
pub struct ControlGroupRequestData {
    contents: SecretVec,
}

impl ControlGroupRequestData {
    /// Borrows the encoded JSON bytes for deliberate secret-aware inspection.
    pub fn with_json_bytes<T>(&self, inspect: impl FnOnce(&[u8]) -> T) -> T {
        self.contents.with_secret(inspect)
    }
}

impl fmt::Debug for ControlGroupRequestData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlGroupRequestData")
            .finish_non_exhaustive()
    }
}

/// Identity associated with a recorded authorization, not proof it remains valid.
#[derive(Deserialize)]
pub struct ControlGroupAuthorization {
    /// Authorizing entity identifier; sensitive correlation metadata.
    pub entity_id: SecretString,
    /// Authorizing entity name; do not log it.
    pub entity_name: SecretString,
}

impl fmt::Debug for ControlGroupAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlGroupAuthorization")
            .finish_non_exhaustive()
    }
}

/// Bounded review of an original deferred request. This does not authorize it.
///
/// Decoding the complete response envelope is limited to 512 KiB, 16 nested containers,
/// 4096 value nodes, 256 items per container and 64 KiB per decoded string/key.
/// Duplicate keys are rejected at every depth, including unknown fields.
/// All fields except the approval boolean use secret-aware storage. Unknown
/// requester identity fields are preserved, including aliases and metadata.
/// Transport collection remains subject to the client's response-byte limit;
/// the smaller review-byte limit is checked before JSON decoding.
pub struct ControlGroupRequest {
    /// Current server-reported approval state, not a transferable capability.
    pub approved: bool,
    /// Original OpenBao operation, retained as sensitive metadata.
    pub request_operation: SecretString,
    /// Original path, retained as sensitive metadata.
    pub request_path: SecretString,
    /// Original payload object, or null for a request without data.
    pub request_data: ControlGroupRequestData,
    /// Complete requester entity object, including server-specific metadata.
    pub request_entity: ControlGroupRequestData,
    /// Recorded authorizations; entries may no longer satisfy current policy.
    pub authorizations: Vec<ControlGroupAuthorization>,
}

impl fmt::Debug for ControlGroupRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlGroupRequest")
            .finish_non_exhaustive()
    }
}

impl ControlGroupRequest {
    pub(super) fn from_envelope(body: SecretVec) -> Result<Self> {
        if body.len() > MAX_BYTES {
            return Err(invalid());
        }
        body.with_secret(|bytes| {
            validate(bytes).map_err(|_| invalid())?;
            #[derive(Deserialize)]
            struct Envelope<'a> {
                #[serde(borrow)]
                data: Review<'a>,
            }
            #[derive(Deserialize)]
            struct Review<'a> {
                approved: bool,
                request_operation: SecretString,
                request_path: SecretString,
                #[serde(borrow)]
                request_data: &'a RawValue,
                #[serde(borrow)]
                request_entity: &'a RawValue,
                authorizations: Vec<ControlGroupAuthorization>,
            }
            let envelope: Envelope<'_> = serde_json::from_slice(bytes).map_err(|_| invalid())?;
            let data = envelope.data;
            let payload = data.request_data.get();
            let entity = data.request_entity.get();
            if !(payload.starts_with('{') || payload == "null") || !entity.starts_with('{') {
                return Err(invalid());
            }
            Ok(Self {
                approved: data.approved,
                request_operation: data.request_operation,
                request_path: data.request_path,
                request_data: ControlGroupRequestData {
                    contents: SecretVec::from_slice(payload.as_bytes()),
                },
                request_entity: ControlGroupRequestData {
                    contents: SecretVec::from_slice(entity.as_bytes()),
                },
                authorizations: data.authorizations,
            })
        })
    }
}

// First pass validates all fields without constructing a plain secret-bearing
// value tree. Temporary duplicate-detection keys have sanitizing ownership.
fn validate(bytes: &[u8]) -> core::result::Result<(), serde_json::Error> {
    let mut budget = MAX_NODES;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    Check {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut decoder)?;
    decoder.end()
}

struct Check<'a> {
    budget: &'a mut usize,
    depth: usize,
}

impl Check<'_> {
    fn node<E: serde::de::Error>(&mut self) -> core::result::Result<(), E> {
        if *self.budget == 0 {
            return Err(E::custom("control-group node limit"));
        }
        *self.budget -= 1;
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
        f.write_str("bounded control-group JSON")
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
        if value.len() > MAX_STRING {
            return Err(E::custom("control-group string limit"));
        }
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> core::result::Result<(), A::Error> {
        self.node()?;
        if self.depth >= MAX_DEPTH {
            return Err(A::Error::custom("control-group depth limit"));
        }
        for _ in 0..MAX_ITEMS {
            if *self.budget == 0 {
                break;
            }
            if seq
                .next_element_seed(Check {
                    budget: self.budget,
                    depth: self.depth + 1,
                })?
                .is_none()
            {
                return Ok(());
            }
        }
        seq.next_element_seed(RejectOverflow::new("control-group array or node limit"))?;
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(mut self, mut map: A) -> core::result::Result<(), A::Error> {
        self.node()?;
        if self.depth >= MAX_DEPTH {
            return Err(A::Error::custom("control-group depth limit"));
        }
        let mut keys: Vec<SecretString> = Vec::new();
        while keys.len() < MAX_ITEMS && *self.budget > 0 {
            let Some(key) = map.next_key::<SecretString>()? else {
                return Ok(());
            };
            if key.expose_secret().len() > MAX_STRING {
                return Err(A::Error::custom("control-group key limit"));
            }
            if keys
                .iter()
                .any(|seen| seen.expose_secret() == key.expose_secret())
            {
                return Err(A::Error::custom("duplicate control-group key"));
            }
            keys.push(key);
            map.next_value_seed(Check {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
        }
        map.next_key_seed(RejectOverflow::new("control-group object or node limit"))?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    fn fixture(payload: &str, entity: &str) -> String {
        format!(
            r#"{{"data":{{"approved":false,"request_operation":"read","request_path":"private/path","request_data":{payload},"request_entity":{entity},"authorizations":[{{"entity_id":"reviewer-id","entity_name":"reviewer-name"}}]}}}}"#
        )
    }

    fn decode(bytes: &[u8]) -> Result<ControlGroupRequest> {
        ControlGroupRequest::from_envelope(SecretVec::from_slice(bytes))
    }

    fn rejected(bytes: &[u8]) {
        let error = decode(bytes)
            .err()
            .unwrap_or_else(|| panic!("accepted invalid review"));
        assert!(
            matches!(&error, Error::Decode(message) if message == "invalid or oversized control-group review response")
        );
    }

    #[test]
    fn review_preserves_secret_json_and_redacts_diagnostics() {
        let payload = r#"{"escaped":"private\u002dvalue","nested":[null,true,1,-1,1.5]}"#;
        let entity =
            r#"{"ID":"requester-id","metadata":{"private":"identity-value"},"aliases":[]}"#;
        let response = decode(fixture(payload, entity).as_bytes())
            .unwrap_or_else(|_| panic!("valid review rejected"));
        assert!(!response.approved);
        assert!(response.request_operation.expose_secret() == "read");
        assert!(response.request_path.expose_secret() == "private/path");
        assert!(
            response
                .request_data
                .with_json_bytes(|value| value == payload.as_bytes())
        );
        assert!(
            response
                .request_entity
                .with_json_bytes(|value| value == entity.as_bytes())
        );
        assert!(response.authorizations[0].entity_id.expose_secret() == "reviewer-id");
        assert!(response.authorizations[0].entity_name.expose_secret() == "reviewer-name");
        let debug = format!(
            "{response:?} {:?} {:?} {:?}",
            response.request_data, response.request_entity, response.authorizations
        );
        for marker in [
            "private",
            "requester-id",
            "identity-value",
            "reviewer-id",
            "reviewer-name",
        ] {
            assert!(
                !debug.contains(marker),
                "review diagnostics exposed metadata"
            );
        }
        assert!(decode(fixture(" null ", " {} ").as_bytes()).is_ok());
    }

    #[test]
    fn review_rejects_wrong_shapes_and_malformed_input() {
        for payload in ["[]", "true", "1", "\"value\""] {
            rejected(fixture(payload, "{}").as_bytes());
        }
        for entity in ["null", "[]", "false", "\"value\""] {
            rejected(fixture("{}", entity).as_bytes());
        }
        let valid = fixture("{}", "{}");
        for field in [
            "approved",
            "request_operation",
            "request_path",
            "request_data",
            "request_entity",
            "authorizations",
        ] {
            let mut value: serde_json::Value =
                serde_json::from_str(&valid).unwrap_or_else(|_| panic!("fixture failed"));
            value["data"]
                .as_object_mut()
                .unwrap_or_else(|| panic!("fixture failed"))
                .remove(field);
            rejected(value.to_string().as_bytes());
        }
        for (from, to) in [
            ("false", "null"),
            ("false", "\"false\""),
            ("\"reviewer-id\"", "null"),
            ("\"read\"", "[]"),
        ] {
            rejected(valid.replace(from, to).as_bytes());
        }
        rejected(&valid.as_bytes()[..valid.len() - 1]);
        rejected(format!("{valid} trailing-private-value").as_bytes());
        rejected(b"\xff");
        rejected(fixture(r#"{"number":1e999}"#, "{}").as_bytes());
    }

    #[test]
    fn review_rejects_duplicate_keys_at_every_depth() {
        for payload in [
            r#"{"x":1,"x":2}"#,
            r#"{"x":1,"\u0078":2}"#,
            r#"{"nested":{"x":1,"x":2}}"#,
        ] {
            rejected(fixture(payload, "{}").as_bytes());
            rejected(fixture("{}", payload).as_bytes());
        }
        let valid = fixture("{}", "{}");
        rejected(
            valid
                .replace("\"approved\":false", "\"approved\":false,\"approved\":true")
                .as_bytes(),
        );
        rejected(
            valid
                .replace("\"reviewer-id\"", "\"reviewer-id\",\"entity_id\":\"other\"")
                .as_bytes(),
        );
        rejected(
            valid
                .replacen('{', "{\"unknown\":{\"x\":1,\"x\":2},", 1)
                .as_bytes(),
        );
        rejected(valid.replacen('{', "{\"data\":{},", 1).as_bytes());
    }

    #[test]
    fn review_applies_limits_to_authorizations_and_unknown_fields() {
        for count in [MAX_ITEMS, MAX_ITEMS + 1] {
            let authorizations =
                vec![r#"{"entity_id":"id","entity_name":"name"}"#; count].join(",");
            let body = fixture("{}", "{}").replace(
                r#"{"entity_id":"reviewer-id","entity_name":"reviewer-name"}"#,
                &authorizations,
            );
            assert!(decode(body.as_bytes()).is_ok() == (count == MAX_ITEMS));
        }
        let oversized = format!("\"{}\"", "x".repeat(MAX_STRING + 1));
        rejected(fixture(&format!("{{\"value\":{oversized}}}"), "{}").as_bytes());
        rejected(
            fixture("{}", "{}")
                .replacen('{', &format!("{{\"unknown\":{oversized},"), 1)
                .as_bytes(),
        );
        let escaped = format!("\"{}\"", "\\u0061".repeat(MAX_STRING + 1));
        rejected(fixture(&format!("{{\"value\":{escaped}}}"), "{}").as_bytes());
    }

    #[test]
    fn overflow_is_rejected_before_parsing_the_extra_value() {
        let array = format!("[{},malformed]", vec!["null"; MAX_ITEMS].join(","));
        let error = validate(array.as_bytes())
            .err()
            .unwrap_or_else(|| panic!("overflow accepted"));
        assert!(
            error
                .to_string()
                .starts_with("control-group array or node limit")
        );
        let object = format!(
            "{{{},\"overflow\":malformed}}",
            (0..MAX_ITEMS)
                .map(|i| format!("\"{i}\":null"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let error = validate(object.as_bytes())
            .err()
            .unwrap_or_else(|| panic!("overflow accepted"));
        assert!(
            error
                .to_string()
                .starts_with("control-group object or node limit")
        );
    }

    #[test]
    fn json_limits_accept_exact_bounds_and_reject_overflow() {
        for size in [MAX_STRING, MAX_STRING + 1] {
            let text = "a".repeat(size);
            assert!(validate(format!("\"{text}\"").as_bytes()).is_ok() == (size == MAX_STRING));
            assert!(
                validate(format!("{{\"{text}\":null}}").as_bytes()).is_ok() == (size == MAX_STRING)
            );
        }
        for count in [MAX_ITEMS, MAX_ITEMS + 1] {
            let array = format!("[{}]", vec!["null"; count].join(","));
            let object = format!(
                "{{{}}}",
                (0..count)
                    .map(|i| format!("\"{i}\":null"))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            assert!(validate(array.as_bytes()).is_ok() == (count == MAX_ITEMS));
            assert!(validate(object.as_bytes()).is_ok() == (count == MAX_ITEMS));
        }
        for depth in [MAX_DEPTH, MAX_DEPTH + 1] {
            let nested = format!("{}null{}", "[".repeat(depth), "]".repeat(depth));
            assert!(validate(nested.as_bytes()).is_ok() == (depth == MAX_DEPTH));
        }
        // Root + 16 child arrays + 4079/4080 scalar values = 4096/4097 nodes.
        for extra in [0, 1] {
            let mut groups = vec![format!("[{}]", vec!["null"; 255].join(",")); 15];
            groups.push(format!("[{}]", vec!["null"; 254 + extra].join(",")));
            assert!(validate(format!("[{}]", groups.join(",")).as_bytes()).is_ok() == (extra == 0));
        }
        let mut envelope = fixture("{}", "{}");
        envelope.extend(core::iter::repeat_n(' ', MAX_BYTES - envelope.len()));
        assert!(decode(envelope.as_bytes()).is_ok());
        envelope.push(' ');
        rejected(envelope.as_bytes());
    }
}
