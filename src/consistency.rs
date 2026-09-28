//! Bounded OpenBao consistency-header values (opt-in `consistency` feature).
//!
//! Raw index types parse metadata only. [`ConsistencyContext`] binds captured
//! indices to one client context and rechecks cluster identity before transport.
//! No consistency guarantee or profile promotion follows from header support.

pub use crate::client::consistency::{
    ConsistencyContext, ConsistencyResponse, ScopedConsistencyIndex,
};

use core::fmt;
use reqwest::header::{HeaderMap, HeaderValue};
use sanitization::SecretVec;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::{Error, Result};

const MAX_INDEX_HEADER_BYTES: usize = 4096;

/// An opaque storage index with the cluster identity supplied by OpenBao.
///
/// Input is bounded to 4096 encoded bytes. Neither parsing nor a matching
/// cluster string authenticates the server. Do not move indices between client
/// namespaces or clusters. Storage values are opaque: do not numerically order
/// indices or assume the last response to arrive represents the latest write.
/// Debug redacts both the encoded value and cluster identity.
pub struct ConsistencyIndex {
    encoded: SecretString,
    cluster: SecretString,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexPayload {
    cluster: SecretString,
    value: SecretString,
}

fn invalid_index() -> Error {
    Error::Decode("invalid OpenBao consistency index".into())
}

impl ConsistencyIndex {
    /// Validates a standard Base64-encoded OpenBao cluster/value JSON envelope.
    ///
    /// Rejects unknown/duplicate fields, missing/empty fields, control bytes and
    /// oversized values. No input contents are included in errors. Decoded
    /// SDK-owned bytes sanitize on drop; dependency parser scratch is not covered.
    pub fn from_encoded(encoded: SecretString) -> Result<Self> {
        let wire = encoded.expose_secret().as_bytes();
        if wire.is_empty() || wire.len() > MAX_INDEX_HEADER_BYTES {
            return Err(invalid_index());
        }
        let decoded = base64_ng::ct::STANDARD
            .decode_secret(wire)
            .map_err(|_| invalid_index())?;
        let exposed = decoded.into_exposed_vec();
        let decoded =
            SecretVec::from_vec(exposed.into_exposed_unprotected_vec_caller_must_zeroize());
        let payload: IndexPayload = decoded
            .with_secret(|bytes| serde_json::from_slice(bytes).map_err(|_| invalid_index()))?;
        for (value, limit) in [(&payload.cluster, 256), (&payload.value, 2048)] {
            let value = value.expose_secret();
            if value.is_empty()
                || value.len() > limit
                || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
            {
                return Err(invalid_index());
            }
        }
        Ok(Self {
            encoded,
            cluster: payload.cluster,
        })
    }

    /// Captures at most one `X-Vault-Index` header. Absence is normal for reads.
    /// Duplicate or empty headers fail rather than selecting an arbitrary value.
    /// This does not bind the result to a client or prove server version support.
    pub fn from_headers(headers: &HeaderMap) -> Result<Option<Self>> {
        let mut values = headers.get_all("x-vault-index").iter();
        let Some(value) = values.next() else {
            return Ok(None);
        };
        if values.next().is_some() || value.as_bytes().len() > MAX_INDEX_HEADER_BYTES {
            return Err(invalid_index());
        }
        let value = value.to_str().map_err(|_| invalid_index())?;
        Self::from_encoded(SecretString::from(value.to_owned())).map(Some)
    }

    /// Compares the claimed cluster identity. This is not authentication or
    /// namespace validation; the caller must establish the expected cluster.
    #[must_use]
    pub fn matches_cluster(&self, expected: &str) -> bool {
        self.cluster.expose_secret() == expected
    }

    /// Explicitly copies this index into a sensitive-marked HTTP header value.
    /// HTTP-stack header allocations are not guaranteed to sanitize on drop.
    /// Setting this alone does not establish scoped or version-gated transport.
    pub fn to_header_value(&self) -> Result<HeaderValue> {
        let mut value =
            HeaderValue::from_str(self.encoded.expose_secret()).map_err(|_| invalid_index())?;
        value.set_sensitive(true);
        Ok(value)
    }
}

impl fmt::Debug for ConsistencyIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsistencyIndex").finish_non_exhaustive()
    }
}

/// Explicit behavior after the server-side await-state deadline expires.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsistencyFallback {
    /// Reject inconsistent requests (HTTP 429), without enabling SDK retries.
    Fail,
    /// Ask the server to forward to its active node, not follow an HTTP redirect.
    ForwardActiveNode,
}

/// Explicit inconsistency behavior, with no background state or automatic retry.
/// Await-state wait duration is server-configured; use a client request timeout
/// to bound overall latency. A timeout cannot establish rollback of a write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsistencyPolicy {
    /// Fail immediately on an unseen index.
    Fail,
    /// Forward an inconsistent request to the active node.
    ForwardActiveNode,
    /// Wait on the server, then use an explicit fallback instead of its default.
    AwaitState(ConsistencyFallback),
}

impl ConsistencyPolicy {
    /// Ordered values for separate `X-Vault-Inconsistent` header occurrences.
    /// Append each value separately; comma-joining is not equivalent in 2.7.0.
    /// This method does not send requests or bypass SDK compatibility policies.
    #[must_use]
    pub const fn header_values(self) -> &'static [&'static str] {
        match self {
            Self::Fail => &["fail"],
            Self::ForwardActiveNode => &["forward-active-node"],
            Self::AwaitState(ConsistencyFallback::Fail) => &["await-state", "fail"],
            Self::AwaitState(ConsistencyFallback::ForwardActiveNode) => {
                &["await-state", "forward-active-node"]
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    fn encoded(json: &str) -> SecretString {
        let encoded = base64_ng::STANDARD
            .encode_secret(json.as_bytes())
            .unwrap_or_else(|_| panic!("fixture encoding failed"));
        let exposed = encoded
            .try_into_exposed_string()
            .unwrap_or_else(|_| panic!("fixture utf8 failed"));
        SecretString::from(exposed.into_exposed_unprotected_string_caller_must_zeroize())
    }

    #[test]
    fn round_trip_and_redaction() {
        let wire = encoded(r#"{"cluster":"synthetic-cluster","value":"opaque:123"}"#);
        let index =
            ConsistencyIndex::from_encoded(wire).unwrap_or_else(|_| panic!("valid index rejected"));
        assert!(index.matches_cluster("synthetic-cluster"));
        assert!(!index.matches_cluster("other"));
        let header = index
            .to_header_value()
            .unwrap_or_else(|_| panic!("header failed"));
        assert!(header.is_sensitive());
        let debug = format!("{index:?} {header:?}");
        assert!(!debug.contains("synthetic-cluster"));
        assert!(!debug.contains("opaque:123"));
        assert!(!debug.contains(index.encoded.expose_secret()));
        let mut headers = HeaderMap::new();
        headers.insert("x-vault-index", header);
        assert!(ConsistencyIndex::from_headers(&headers).is_ok_and(|value| value.is_some()));
    }

    #[test]
    fn malformed_envelopes_are_rejected_without_echoing_input() {
        for json in [
            "null",
            "[]",
            "{}",
            r#"{"cluster":"a"}"#,
            r#"{"cluster":"a","value":""}"#,
            r#"{"cluster":"","value":"b"}"#,
            r#"{"cluster":"a","cluster":"b","value":"c"}"#,
            r#"{"cluster":"a","\u0063luster":"b","value":"c"}"#,
            r#"{"cluster":"a","value":"b","value":"c"}"#,
            r#"{"cluster":"a","value":"b","extra":1}"#,
            r#"{"cluster":"a","value":"synthetic\nprivate"}"#,
            r#"{"cluster":1,"value":"b"}"#,
            r#"{"cluster":"a","value":"\u00e9"}"#,
            r#"{"cluster":"a","value":"b"}{}"#,
        ] {
            let error = ConsistencyIndex::from_encoded(encoded(json))
                .err()
                .unwrap_or_else(|| panic!("invalid index accepted"));
            assert!(
                matches!(error, Error::Decode(ref message) if message == "invalid OpenBao consistency index")
            );
        }
        for wire in ["", "%%%", "e30=\r\n", "e30=,e30="] {
            assert!(ConsistencyIndex::from_encoded(SecretString::from(wire)).is_err());
        }
    }

    #[test]
    fn exact_bounds_and_header_cardinality() {
        let mut json = format!(
            r#"{{"cluster":"{}","value":"{}"}}"#,
            "c".repeat(256),
            "v".repeat(2048)
        );
        json.push_str(&" ".repeat(3072 - json.len()));
        let wire = encoded(&json);
        assert_eq!(wire.expose_secret().len(), MAX_INDEX_HEADER_BYTES);
        assert!(ConsistencyIndex::from_encoded(wire).is_ok());
        assert!(ConsistencyIndex::from_encoded(SecretString::from("A".repeat(4097))).is_err());
        for (cluster, value) in [(257, 1), (1, 2049)] {
            assert!(
                ConsistencyIndex::from_encoded(encoded(&format!(
                    r#"{{"cluster":"{}","value":"{}"}}"#,
                    "c".repeat(cluster),
                    "v".repeat(value)
                )))
                .is_err()
            );
        }
        let mut headers = HeaderMap::new();
        assert!(ConsistencyIndex::from_headers(&headers).is_ok_and(|value| value.is_none()));
        headers.append("x-vault-index", HeaderValue::from_static("e30="));
        headers.append("x-vault-index", HeaderValue::from_static("e30="));
        assert!(ConsistencyIndex::from_headers(&headers).is_err());
    }

    #[test]
    fn invalid_header_values_are_rejected() {
        for bytes in [b"".as_slice(), b"e30=,e30=", &[0xff], &vec![b'A'; 4097]] {
            let mut headers = HeaderMap::new();
            let value =
                HeaderValue::from_bytes(bytes).unwrap_or_else(|_| panic!("invalid HTTP fixture"));
            headers.insert("x-vault-index", value);
            assert!(ConsistencyIndex::from_headers(&headers).is_err());
        }
    }

    #[test]
    fn policies_have_exact_ordered_wire_values() {
        assert_eq!(ConsistencyPolicy::Fail.header_values(), &["fail"]);
        assert_eq!(
            ConsistencyPolicy::ForwardActiveNode.header_values(),
            &["forward-active-node"]
        );
        assert_eq!(
            ConsistencyPolicy::AwaitState(ConsistencyFallback::Fail).header_values(),
            &["await-state", "fail"]
        );
        assert_eq!(
            ConsistencyPolicy::AwaitState(ConsistencyFallback::ForwardActiveNode).header_values(),
            &["await-state", "forward-active-node"]
        );
    }
}
