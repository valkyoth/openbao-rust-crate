use core::fmt;
use sanitization::SecretVec;
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::{Error, Result};

/// Complete request-inspection JSON envelope, including sensitive unknown fields.
///
/// This privileged endpoint may return raw tokens, headers and identity metadata.
/// Storage is sanitizing and diagnostics are redacted. No implicit serialization,
/// cloning or conversion to an ordinary JSON tree is provided. A callback can
/// still copy or disclose bytes; the caller is responsible for such copies.
///
/// Validation is limited to 512 KiB, 16 nested containers, 4096 value nodes,
/// 256 entries per container and 64 KiB per decoded string/key. Duplicate keys
/// are rejected, including escaped equivalents and unknown nested fields.
/// HTTP/TLS buffers and serde escaped-string scratch space remain dependency
/// memory residuals, not a complete process-memory erasure guarantee.
pub struct InternalRequestInspection {
    contents: SecretVec,
}

impl InternalRequestInspection {
    /// Explicitly borrows the complete JSON envelope, not only its `data` field.
    pub fn with_json_bytes<T>(&self, inspect: impl FnOnce(&[u8]) -> T) -> T {
        self.contents.with_secret(inspect)
    }

    pub(super) fn from_envelope(contents: SecretVec) -> Result<Self> {
        let invalid = || Error::Decode("invalid or oversized request inspection response".into());
        if contents.len() > 512 * 1024 {
            return Err(invalid());
        }
        contents.with_secret(|bytes| {
            super::control_groups::review::validate(bytes).map_err(|_| invalid())?;
            #[derive(Deserialize)]
            struct Envelope<'a> {
                #[serde(borrow)]
                data: &'a RawValue,
            }
            let envelope: Envelope<'_> = serde_json::from_slice(bytes).map_err(|_| invalid())?;
            if !envelope.data.get().starts_with('{') {
                return Err(invalid());
            }
            Ok(())
        })?;
        Ok(Self { contents })
    }
}

impl fmt::Debug for InternalRequestInspection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InternalRequestInspection")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn inspection_preserves_full_envelope_and_redacts_debug() {
        let bytes = br#"{"data":{"client_token":"fixture-private","headers":{"x":"escaped\u002dvalue"}},"unknown":"metadata"}"#;
        let response = InternalRequestInspection::from_envelope(SecretVec::from_slice(bytes))
            .unwrap_or_else(|_| panic!("valid inspection rejected"));
        assert!(response.with_json_bytes(|actual| actual == bytes));
        assert_eq!(format!("{response:?}"), "InternalRequestInspection { .. }");
    }

    #[test]
    fn inspection_rejects_malformed_shapes_duplicates_and_limits_without_echoing() {
        let mut invalid = vec![
            "{}".to_owned(),
            "{\"data\":null}".to_owned(),
            "{\"data\":[]}".to_owned(),
            "{\"data\":{},\"data\":{}}".to_owned(),
            r#"{"data":{"x":1,"\u0078":2}}"#.to_owned(),
            r#"{"data":{},"unknown":{"x":1,"x":2}}"#.to_owned(),
            r#"{"data":{}} trailing-private"#.to_owned(),
            format!("{{\"data\":{{\"x\":\"{}\"}}}}", "a".repeat(65537)),
            format!(
                "{{\"data\":{{\"x\":{}null{}}}}}",
                "[".repeat(16),
                "]".repeat(16)
            ),
            format!("{{\"data\":{{\"x\":[{}]}}}}", vec!["null"; 257].join(",")),
        ];
        invalid.push(format!("{{\"data\":{{}}}}{}", " ".repeat(512 * 1024)));
        for bytes in invalid {
            let result =
                InternalRequestInspection::from_envelope(SecretVec::from_slice(bytes.as_bytes()));
            assert!(
                matches!(result, Err(Error::Decode(message)) if message == "invalid or oversized request inspection response")
            );
        }
        let padded = format!("{{\"data\":{{}}}}{}", " ".repeat(512 * 1024 - 11));
        assert!(
            InternalRequestInspection::from_envelope(SecretVec::from_slice(padded.as_bytes()))
                .is_ok()
        );
    }
}
