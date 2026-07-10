//! TOTP secrets engine support.
//!
//! Generated TOTP codes, generated OTP URLs, QR barcodes, imported OTP URLs,
//! and imported root keys are treated as secret material and are redacted from
//! debug output.

use core::fmt;

use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};

use crate::{
    Authenticated, Client, Error, Result,
    path::{validate_endpoint_path, validate_mount_path},
    response::{Empty, ListEntries, ListPageOptions, deserialize_bounded_string_vec},
};

/// Handle for a mounted TOTP secrets engine.
#[derive(Debug)]
pub struct Totp<'a> {
    client: &'a Client<Authenticated>,
    mount: Vec<String>,
}

/// Hash algorithm used by a TOTP key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TotpAlgorithm {
    /// SHA-1, the OpenBao default for TOTP compatibility.
    ///
    /// SHA-1 in HMAC-TOTP is retained for RFC 4226 and legacy authenticator
    /// compatibility. Prefer [`TotpAlgorithm::Sha256`] or
    /// [`TotpAlgorithm::Sha512`] for new deployments.
    #[deprecated(
        since = "0.11.0",
        note = "SHA-1 in TOTP is retained for RFC 4226 compatibility; prefer SHA256 or SHA512 for new deployments"
    )]
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl TotpAlgorithm {
    fn as_str(self) -> &'static str {
        match self {
            #[allow(deprecated)]
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

impl Serialize for TotpAlgorithm {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TotpAlgorithm {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            #[allow(deprecated)]
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(D::Error::custom("unsupported TOTP algorithm")),
        }
    }
}

/// TOTP period accepted by OpenBao.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TotpPeriod {
    /// Period in whole seconds.
    Seconds(u64),
    /// OpenBao duration string such as `30s` or `1m`.
    Duration(String),
}

impl TotpPeriod {
    /// Creates a seconds-based TOTP period.
    #[must_use]
    pub fn seconds(seconds: u64) -> Self {
        Self::Seconds(seconds)
    }

    /// Creates a duration-string TOTP period.
    #[must_use]
    pub fn duration(duration: impl Into<String>) -> Self {
        Self::Duration(duration.into())
    }
}

impl Serialize for TotpPeriod {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Seconds(seconds) => serializer.serialize_u64(*seconds),
            Self::Duration(duration) => serializer.serialize_str(duration),
        }
    }
}

impl<'de> Deserialize<'de> for TotpPeriod {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(TotpPeriodVisitor)
    }
}

struct TotpPeriodVisitor;

impl serde::de::Visitor<'_> for TotpPeriodVisitor {
    type Value = TotpPeriod;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a non-negative second count or an OpenBao duration string")
    }

    fn visit_u64<E>(self, value: u64) -> core::result::Result<Self::Value, E> {
        Ok(TotpPeriod::Seconds(value))
    }

    fn visit_i64<E>(self, value: i64) -> core::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        u64::try_from(value)
            .map(TotpPeriod::Seconds)
            .map_err(|_| E::custom("TOTP period seconds must not be negative"))
    }

    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(TotpPeriod::Duration(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E> {
        Ok(TotpPeriod::Duration(value))
    }
}

/// TOTP key create/update request.
#[derive(Clone, Default)]
pub struct TotpKeyCreateRequest {
    /// Whether OpenBao should generate a new key.
    pub generate: Option<bool>,
    /// Whether OpenBao should return a QR barcode and OTP URL for a generated key.
    pub exported: Option<bool>,
    /// Generated key size in bytes.
    pub key_size: Option<u64>,
    /// Imported OTP URL. Treat as secret material because it contains the TOTP secret.
    pub url: Option<SecretString>,
    /// Imported root key. Treat as secret material.
    pub key: Option<SecretString>,
    /// Issuing organization.
    pub issuer: Option<String>,
    /// Account name associated with the key.
    pub account_name: Option<String>,
    /// TOTP period.
    pub period: Option<TotpPeriod>,
    /// TOTP hash algorithm.
    pub algorithm: Option<TotpAlgorithm>,
    /// Number of generated digits. OpenBao accepts 6 or 8.
    pub digits: Option<u8>,
    /// Number of delay periods allowed during validation.
    pub skew: Option<u8>,
    /// Generated QR image size in pixels.
    pub qr_size: Option<u64>,
}

impl fmt::Debug for TotpKeyCreateRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TotpKeyCreateRequest")
            .field("generate", &self.generate)
            .field("exported", &self.exported)
            .field("key_size", &self.key_size)
            .field("url", &self.url.as_ref().map(|_| "<redacted>"))
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .field("issuer", &self.issuer)
            .field("account_name", &self.account_name)
            .field("period", &self.period)
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("skew", &self.skew)
            .field("qr_size", &self.qr_size)
            .finish()
    }
}

impl TotpKeyCreateRequest {
    /// Creates a request for an OpenBao-generated exported key.
    pub fn generated(issuer: impl Into<String>, account_name: impl Into<String>) -> Self {
        Self {
            generate: Some(true),
            exported: Some(true),
            issuer: Some(issuer.into()),
            account_name: Some(account_name.into()),
            ..Self::default()
        }
    }

    /// Creates a request from an existing OTP URL.
    pub fn from_url(url: SecretString) -> Self {
        Self {
            url: Some(url),
            ..Self::default()
        }
    }

    /// Creates a request from an existing root key.
    pub fn from_key(key: SecretString) -> Self {
        Self {
            key: Some(key),
            ..Self::default()
        }
    }

    /// Sets the TOTP algorithm.
    #[must_use]
    pub fn with_algorithm(mut self, algorithm: TotpAlgorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// Sets the number of generated digits.
    #[must_use]
    pub fn with_digits(mut self, digits: u8) -> Self {
        self.digits = Some(digits);
        self
    }
}

/// TOTP key create response.
#[derive(Clone, Default, Deserialize)]
pub struct TotpKeyCreateResponse {
    /// Base64-encoded QR barcode image. Treat as secret material.
    #[serde(default)]
    pub barcode: Option<SecretString>,
    /// OTP URL. Treat as secret material because it contains the TOTP secret.
    #[serde(default)]
    pub url: Option<SecretString>,
}

impl fmt::Debug for TotpKeyCreateResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TotpKeyCreateResponse")
            .field("barcode", &self.barcode.as_ref().map(|_| "<redacted>"))
            .field("url", &self.url.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// TOTP key read response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TotpKeyInfo {
    /// Account name associated with the key.
    #[serde(default)]
    pub account_name: Option<String>,
    /// Hash algorithm used by the key.
    #[serde(default)]
    pub algorithm: Option<TotpAlgorithm>,
    /// Number of generated digits.
    #[serde(default)]
    pub digits: Option<u8>,
    /// Issuing organization.
    #[serde(default)]
    pub issuer: Option<String>,
    /// TOTP period.
    #[serde(default)]
    pub period: Option<TotpPeriod>,
}

/// TOTP key list response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TotpKeyList {
    /// Key names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for TotpKeyList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// TOTP code generate response.
#[derive(Clone, Deserialize)]
pub struct TotpCode {
    /// Generated TOTP code. Treat as secret material.
    pub code: SecretString,
}

impl fmt::Debug for TotpCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TotpCode")
            .field("code", &"<redacted>")
            .finish()
    }
}

/// TOTP code validation request.
#[derive(Clone)]
pub struct TotpValidateRequest {
    /// TOTP code to validate. OpenBao requires this verbatim.
    pub code: SecretString,
}

impl fmt::Debug for TotpValidateRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TotpValidateRequest")
            .field("code", &"<redacted>")
            .finish()
    }
}

impl TotpValidateRequest {
    /// Creates a TOTP validation request.
    pub fn new(code: SecretString) -> Self {
        Self { code }
    }
}

/// TOTP code validation response.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct TotpValidateResponse {
    /// Whether OpenBao accepted the code.
    pub valid: bool,
}

#[derive(Deserialize)]
struct OptionalDataEnvelope<T> {
    #[serde(default)]
    data: Option<T>,
}

#[derive(Serialize)]
struct TotpKeyCreatePayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    generate: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    period: Option<&'a TotpPeriod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    algorithm: Option<TotpAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    digits: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skew: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    qr_size: Option<u64>,
}

#[derive(Serialize)]
struct TotpValidatePayload<'a> {
    code: &'a str,
}

impl Client<Authenticated> {
    /// Uses the TOTP engine mounted at `mount`.
    pub fn totp(&self, mount: impl Into<String>) -> Result<Totp<'_>> {
        let mount = mount.into();
        Ok(Totp {
            client: self,
            mount: validate_mount_path(&mount)?,
        })
    }
}

impl Totp<'_> {
    /// Creates or updates a TOTP key.
    pub async fn create_key(
        &self,
        name: &str,
        request: &TotpKeyCreateRequest,
    ) -> Result<TotpKeyCreateResponse> {
        let payload = TotpKeyCreatePayload {
            generate: request.generate,
            exported: request.exported,
            key_size: request.key_size,
            url: request.url.as_ref().map(SecretString::expose_secret),
            key: request.key.as_ref().map(SecretString::expose_secret),
            issuer: request.issuer.as_deref(),
            account_name: request.account_name.as_deref(),
            period: request.period.as_ref(),
            algorithm: request.algorithm,
            digits: request.digits,
            skew: request.skew,
            qr_size: request.qr_size,
        };
        let envelope: OptionalDataEnvelope<TotpKeyCreateResponse> = self
            .client
            .request_json_accepting(
                Method::POST,
                &self.path("keys", name)?,
                Some(&payload),
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await?;
        Ok(envelope.data.unwrap_or_default())
    }

    /// Reads a TOTP key definition.
    pub async fn read_key(&self, name: &str) -> Result<TotpKeyInfo> {
        let envelope: crate::ResponseEnvelope<TotpKeyInfo> = self
            .client
            .request_json_internal(
                Method::GET,
                &self.path("keys", name)?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists TOTP key names.
    pub async fn list_keys(&self) -> Result<TotpKeyList> {
        self.list_keys_after(None, None).await
    }

    /// Lists TOTP key names with optional OpenBao pagination parameters.
    pub async fn list_keys_after(
        &self,
        after: Option<&str>,
        limit: Option<u64>,
    ) -> Result<TotpKeyList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let query = ListPageOptions::from_after_limit(after, limit)?.query_pairs();
        let envelope: crate::ResponseEnvelope<TotpKeyList> = self
            .client
            .request_json_query_accepting(
                method,
                &self.path("keys", "")?,
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a TOTP key definition.
    pub async fn delete_key(&self, name: &str) -> Result<Empty> {
        self.client
            .request_json_internal(
                Method::DELETE,
                &self.path("keys", name)?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Generates a TOTP code from a named key.
    pub async fn generate_code(&self, name: &str) -> Result<TotpCode> {
        let envelope: crate::ResponseEnvelope<TotpCode> = self
            .client
            .request_json_internal(
                Method::GET,
                &self.path("code", name)?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Validates a TOTP code against a named key.
    pub async fn validate_code(
        &self,
        name: &str,
        request: &TotpValidateRequest,
    ) -> Result<TotpValidateResponse> {
        let payload = TotpValidatePayload {
            code: request.code.expose_secret(),
        };
        let envelope: crate::ResponseEnvelope<TotpValidateResponse> = self
            .client
            .request_json_internal(Method::POST, &self.path("code", name)?, Some(&payload))
            .await?;
        Ok(envelope.data)
    }

    fn path(&self, operation: &str, name: &str) -> Result<String> {
        let mut segments = self.mount.clone();
        segments.extend(validate_mount_path(operation)?);
        segments.extend(validate_endpoint_path(name)?);
        Ok(segments.join("/"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(deprecated)]

    use secrecy::SecretString;

    use crate::{Client, OpenBaoConfig};

    use super::{TotpKeyCreateRequest, TotpKeyCreateResponse, TotpKeyList, TotpValidateRequest};

    #[test]
    fn totp_paths_are_validated() {
        let config = OpenBaoConfig::new("http://127.0.0.1:8200")
            .and_then(OpenBaoConfig::allow_localhost_http)
            .unwrap_or_else(|error| panic!("{error}"));
        let client = Client::from_config(config)
            .unwrap_or_else(|error| panic!("{error}"))
            .with_token(SecretString::from("token"));
        let totp = client
            .totp("totp")
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            totp.path("keys", "app/user")
                .unwrap_or_else(|error| panic!("{error}")),
            "totp/keys/app/user"
        );
        assert!(totp.path("keys", "../user").is_err());
    }

    #[test]
    fn totp_list_keys_are_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("key-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<TotpKeyList>(value) {
            Ok(_) => panic!("oversized TOTP key list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn totp_debug_redacts_secret_fields() {
        let request = TotpKeyCreateRequest::from_url(SecretString::from("otpauth://secret"));
        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains("otpauth"));
        assert!(request_debug.contains("redacted"));

        let validate = TotpValidateRequest::new(SecretString::from("123456"));
        let validate_debug = format!("{validate:?}");
        assert!(!validate_debug.contains("123456"));
        assert!(validate_debug.contains("redacted"));

        let response = TotpKeyCreateResponse {
            barcode: Some(SecretString::from("png-secret")),
            url: Some(SecretString::from("url-secret")),
        };
        let response_debug = format!("{response:?}");
        assert!(!response_debug.contains("png-secret"));
        assert!(!response_debug.contains("url-secret"));
        assert!(response_debug.contains("redacted"));
    }
}
