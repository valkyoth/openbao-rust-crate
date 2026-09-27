//! Provider schemas for OpenBao 2.7 external-key administration.
//!
//! Requires `operator-ops` and `operator-ops-acknowledged`. These types describe
//! server-side providers, not local cryptographic implementations. The Transit
//! provider sends data to another trusted OpenBao server over TLS; it does not
//! establish a hardware key boundary. PKCS#11 requires a separately installed
//! server plugin (v0.2.0 or newer) and an operator-configured library alias.
//!
//! This is checkpoint 04a of the staged 2.7 onboarding. Administration methods,
//! custom-provider options, PATCH semantics and live delegation verification
//! are still pending. These schemas do not enable a 2.7 compatibility profile.
//!
//! Serialization deliberately exposes credentials to the serializer. Use the
//! SDK's sanitizing request transport, not ordinary JSON strings or logging.

use core::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Serialize, Serializer};

use crate::{Error, Result, path::validate_mount_path, validation::validate_https_endpoint};

const MAX_PROVIDER_TEXT_BYTES: usize = 64 * 1024;
const MAX_PROVIDER_NAME_BYTES: usize = 256;

fn invalid(message: &'static str) -> Error {
    Error::InvalidParameter(message.into())
}

fn validate_text(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_PROVIDER_TEXT_BYTES {
        return Err(invalid(
            "external-key value is empty or exceeds its byte limit",
        ));
    }
    Ok(())
}

fn validate_name(value: &str) -> Result<()> {
    if value.len() > MAX_PROVIDER_NAME_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || validate_mount_path(value)?.len() != 1
    {
        return Err(invalid(
            "external-key name must be one bounded path segment",
        ));
    }
    Ok(())
}

fn serialize_secret<S: Serializer>(
    value: &SecretString,
    serializer: S,
) -> core::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(value.expose_secret())
}

fn serialize_optional_secret<S: Serializer>(
    value: &Option<SecretString>,
    serializer: S,
) -> core::result::Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_some(value.expose_secret()),
        None => serializer.serialize_none(),
    }
}

/// Built-in Transit provider configuration with mandatory verified HTTPS.
///
/// The token must be scoped to the remote Transit key operations required by
/// the consuming mount. Avoid delegation loops between Transit mounts. Server
/// verification of a config is separate from TLS verification; these settings
/// never enable `tls_skip_verify`.
#[derive(Serialize)]
pub struct TransitExternalKeyConfig {
    address: String,
    #[serde(serialize_with = "serialize_secret")]
    token: SecretString,
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace: Option<String>,
    mount_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_server_name: Option<String>,
    tls_skip_verify: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_ca_cert_bytes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_client_cert_bytes: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_secret"
    )]
    tls_client_key_bytes: Option<SecretString>,
}

impl TransitExternalKeyConfig {
    /// Creates a verified-HTTPS provider targeting the `transit` mount.
    ///
    /// Rejects credentials in the URL, query strings, fragments and invalid
    /// authentication header bytes. Neither errors nor Debug expose the token.
    pub fn new(address: impl Into<String>, token: SecretString) -> Result<Self> {
        let address = address.into();
        validate_https_endpoint(&address, "external-key Transit address")?;
        if address.contains('?') {
            return Err(invalid(
                "external-key Transit address must not contain a query",
            ));
        }
        validate_text(token.expose_secret())?;
        if token
            .expose_secret()
            .bytes()
            .any(|byte| !(0x21..=0x7e).contains(&byte))
        {
            return Err(invalid(
                "external-key Transit token must contain visible ASCII only",
            ));
        }
        Ok(Self {
            address,
            token,
            namespace: None,
            mount_path: "transit".into(),
            tls_server_name: None,
            tls_skip_verify: false,
            tls_ca_cert_bytes: None,
            tls_client_cert_bytes: None,
            tls_client_key_bytes: None,
        })
    }

    /// Selects a validated remote mount path; leading/trailing slashes normalize.
    pub fn with_mount_path(mut self, path: &str) -> Result<Self> {
        self.mount_path = validate_mount_path(path)?.join("/");
        Ok(self)
    }

    /// Selects a validated remote namespace path.
    pub fn with_namespace(mut self, namespace: &str) -> Result<Self> {
        self.namespace = Some(validate_mount_path(namespace)?.join("/"));
        Ok(self)
    }

    /// Sets a DNS name or IP address for server-side TLS verification.
    pub fn with_tls_server_name(mut self, name: &str) -> Result<Self> {
        if name.is_empty()
            || name.len() > 253
            || !name.is_ascii()
            || name.bytes().any(|byte| {
                !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']'))
            })
            || url::Host::parse(name).is_err()
        {
            return Err(invalid(
                "external-key TLS server name must be a bounded host name",
            ));
        }
        self.tls_server_name = Some(name.to_owned());
        Ok(self)
    }

    /// Supplies a bounded PEM CA chain. The server validates certificate syntax.
    pub fn with_ca_certificate(mut self, pem: String) -> Result<Self> {
        validate_text(&pem)?;
        self.tls_ca_cert_bytes = Some(pem);
        Ok(self)
    }

    /// Supplies a bounded client certificate and secret key together.
    ///
    /// The remote provider validates PEM syntax and whether the pair matches.
    /// This transfers the private key to the OpenBao server hosting the provider.
    pub fn with_client_identity(mut self, certificate: String, key: SecretString) -> Result<Self> {
        validate_text(&certificate)?;
        validate_text(key.expose_secret())?;
        self.tls_client_cert_bytes = Some(certificate);
        self.tls_client_key_bytes = Some(key);
        Ok(self)
    }
}

impl fmt::Debug for TransitExternalKeyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransitExternalKeyConfig")
            .finish_non_exhaustive()
    }
}

/// Mapping to one explicit remote Transit key version.
///
/// On rotation create a new mapping rather than redirecting an existing mapping
/// to different key material. Disabling prehashing sends full signature inputs
/// to the remote server and changes the data available to its audit facilities.
#[derive(Debug, Serialize)]
pub struct TransitExternalKey {
    name: String,
    version: u32,
    disable_prehashing: bool,
}

impl TransitExternalKey {
    /// Selects a single key name and a nonzero, Go-int32-compatible key version.
    pub fn new(name: impl Into<String>, version: u32) -> Result<Self> {
        let name = name.into();
        validate_name(&name)?;
        if version == 0 || version > i32::MAX as u32 {
            return Err(invalid(
                "external-key Transit version must be in 1..=2147483647",
            ));
        }
        Ok(Self {
            name,
            version,
            disable_prehashing: false,
        })
    }

    /// Chooses whether full signing inputs, rather than prehashes, are forwarded.
    pub fn with_disable_prehashing(mut self, disable: bool) -> Self {
        self.disable_prehashing = disable;
        self
    }
}

/// PKCS#11 provider configuration. Only registered aliases, never library paths.
///
/// At least one token selector is required. Multiple selectors are conjunctive,
/// not fallbacks. PINs and Debug output remain secret-aware. These schemas do
/// not attest to HSM behavior or require that encryption stays in hardware;
/// select `with_disable_software_encryption(true)` when that is required.
#[derive(Serialize)]
pub struct Pkcs11ExternalKeyConfig {
    lib: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    slot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_label: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_secret"
    )]
    pin: Option<SecretString>,
    disable_software_encryption: bool,
}

/// PKCS#11 token selection. Slot numbers are serialized as strings, not JSON numbers.
#[derive(Debug)]
#[non_exhaustive]
pub enum Pkcs11TokenSelector {
    /// Exact unsigned slot number; formatted as a decimal string on the wire.
    Slot(u64),
    /// Exact token serial number.
    Serial(String),
    /// Exact token label.
    Label(String),
}

impl Pkcs11ExternalKeyConfig {
    /// Creates a provider configuration with one mandatory token selector.
    pub fn new(library_alias: impl Into<String>, selector: Pkcs11TokenSelector) -> Result<Self> {
        let lib = library_alias.into();
        validate_name(&lib)?;
        Self {
            lib,
            slot: None,
            serial: None,
            token_label: None,
            pin: None,
            disable_software_encryption: false,
        }
        .with_selector(selector)
    }

    /// Adds or replaces a selector of the same kind; different kinds must all match.
    pub fn with_selector(mut self, selector: Pkcs11TokenSelector) -> Result<Self> {
        match selector {
            Pkcs11TokenSelector::Slot(slot) => self.slot = Some(slot.to_string()),
            Pkcs11TokenSelector::Serial(serial) => {
                validate_text(&serial)?;
                self.serial = Some(serial);
            }
            Pkcs11TokenSelector::Label(label) => {
                validate_text(&label)?;
                self.token_label = Some(label);
            }
        }
        Ok(self)
    }

    /// Sets a bounded PIN for CKU_USER login, transmitted to the OpenBao server.
    pub fn with_pin(mut self, pin: SecretString) -> Result<Self> {
        validate_text(pin.expose_secret())?;
        self.pin = Some(pin);
        Ok(self)
    }

    /// Requires public-key encryption through PKCS#11 instead of software.
    pub fn with_disable_software_encryption(mut self, disable: bool) -> Self {
        self.disable_software_encryption = disable;
        self
    }
}

impl fmt::Debug for Pkcs11ExternalKeyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11ExternalKeyConfig")
            .finish_non_exhaustive()
    }
}

/// Mechanisms documented for the OpenBao 2.7 PKCS#11 external-key provider.
#[derive(Clone, Copy, Debug, Serialize)]
#[non_exhaustive]
pub enum Pkcs11Mechanism {
    /// ECDSA signatures.
    #[serde(rename = "CKM_ECDSA")]
    Ecdsa,
    /// AES-GCM encryption.
    #[serde(rename = "CKM_AES_GCM")]
    AesGcm,
    /// RSA-PSS signatures.
    #[serde(rename = "CKM_RSA_PKCS_PSS")]
    RsaPss,
    /// RSA-OAEP encryption.
    #[serde(rename = "CKM_RSA_PKCS_OAEP")]
    RsaOaep,
}

/// Hash selection for the server's PKCS#11 RSA-OAEP operations.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Pkcs11OaepHash {
    /// Legacy interoperability only; prefer SHA-256 or stronger.
    Sha1,
    /// SHA-224.
    Sha224,
    /// SHA-256 (the server default).
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

/// Mapping to a PKCS#11 key, identified by at least one explicit selector.
#[derive(Debug, Serialize)]
pub struct Pkcs11ExternalKey {
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mechanism: Option<Pkcs11Mechanism>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rsa_oaep_hash: Option<Pkcs11OaepHash>,
}

impl Pkcs11ExternalKey {
    /// Selects by CKA_LABEL. The server determines uniqueness and availability.
    pub fn by_label(label: impl Into<String>) -> Result<Self> {
        let label = label.into();
        validate_text(&label)?;
        Ok(Self {
            label: Some(label),
            id: None,
            mechanism: None,
            rsa_oaep_hash: None,
        })
    }

    /// Selects by CKA_ID: bounded, nonempty hex octets with an optional `0x` prefix.
    pub fn by_id(id: &str) -> Result<Self> {
        Self {
            label: None,
            id: None,
            mechanism: None,
            rsa_oaep_hash: None,
        }
        .with_id(id)
    }

    /// Adds or replaces CKA_ID. A supplied label must also match.
    pub fn with_id(mut self, id: &str) -> Result<Self> {
        let hex = id.strip_prefix("0x").unwrap_or(id);
        if hex.is_empty()
            || hex.len() > 4096
            || !hex.len().is_multiple_of(2)
            || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid(
                "external-key PKCS#11 ID must contain bounded hex octets",
            ));
        }
        self.id = Some(format!("0x{hex}"));
        Ok(self)
    }

    /// Constrains the server to one documented mechanism.
    pub fn with_mechanism(mut self, mechanism: Pkcs11Mechanism) -> Self {
        self.mechanism = Some(mechanism);
        self
    }

    /// Selects the hash used when the provider performs RSA-OAEP operations.
    pub fn with_rsa_oaep_hash(mut self, hash: Pkcs11OaepHash) -> Self {
        self.rsa_oaep_hash = Some(hash);
        self
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::*;
    use serde_json::{Value, json};

    fn secret() -> SecretString {
        SecretString::from(["fixture", "credential", "not-live"].join("-"))
    }

    fn ok<T>(result: Result<T>) -> T {
        result.unwrap_or_else(|error| panic!("unexpected validation failure: {error}"))
    }

    fn wire(value: &impl Serialize) -> Value {
        serde_json::to_value(value).unwrap_or_else(|_| panic!("fixture serialization failed"))
    }

    #[test]
    fn transit_defaults_match_provider_contract() {
        let config = ok(TransitExternalKeyConfig::new(
            "https://bao.example",
            secret(),
        ));
        let encoded = wire(&config);
        assert_eq!(encoded["address"], "https://bao.example");
        assert_eq!(encoded["mount_path"], "transit");
        assert_eq!(encoded["tls_skip_verify"], false);
        assert!(encoded["token"].as_str() == Some(secret().expose_secret()));
        assert_eq!(encoded.as_object().map(|map| map.len()), Some(4));
        // Credentials are intentionally absent from assertion diagnostics.
        assert!(!format!("{config:?}").contains(secret().expose_secret()));
    }

    #[test]
    fn transit_rejects_unsafe_addresses_and_header_bytes() {
        for address in [
            "http://bao.example",
            "https://user:pass@bao.example",
            "https://bao.example?x=y",
            "https://bao.example#fragment",
            "https://bao.example:0",
            "https://bao.example\\other",
            "https://bao.example\n",
        ] {
            assert!(TransitExternalKeyConfig::new(address, secret()).is_err());
        }
        for token in ["", "value\r\nheader", "value value", "value\0", "\u{80}"] {
            assert!(
                TransitExternalKeyConfig::new("https://bao.example", SecretString::from(token))
                    .is_err()
            );
        }
    }

    #[test]
    fn transit_normalizes_paths_and_serializes_all_tls_fields() {
        let config = ok(TransitExternalKeyConfig::new(
            "https://bao.example",
            secret(),
        ));
        let config = ok(config.with_namespace("/team/child/"));
        let config = ok(config.with_mount_path("/nested/transit/"));
        let config = ok(config.with_tls_server_name("tls.example"));
        let config = ok(config.with_ca_certificate("CA fixture".into()));
        let config = ok(config.with_client_identity("certificate fixture".into(), secret()));
        let encoded = wire(&config);
        assert_eq!(encoded["namespace"], "team/child");
        assert_eq!(encoded["mount_path"], "nested/transit");
        assert_eq!(encoded["tls_server_name"], "tls.example");
        assert_eq!(encoded["tls_ca_cert_bytes"], "CA fixture");
        assert_eq!(encoded["tls_client_cert_bytes"], "certificate fixture");
        assert!(encoded["tls_client_key_bytes"].as_str() == Some(secret().expose_secret()));
        assert!(!format!("{config:?}").contains(secret().expose_secret()));
    }

    #[test]
    fn transit_rejects_path_and_sni_injection() {
        for path in [
            "", "../child", "x//child", "x/%2f", "x?y", "x#y", "x\r\n", "x.",
        ] {
            let config = ok(TransitExternalKeyConfig::new(
                "https://bao.example",
                secret(),
            ));
            assert!(config.with_mount_path(path).is_err());
            let config = ok(TransitExternalKeyConfig::new(
                "https://bao.example",
                secret(),
            ));
            assert!(config.with_namespace(path).is_err());
        }
        for name in [
            "", "foo/path", "foo:8200", "foo\n", "user@foo", "*.foo", "foo%2e",
        ] {
            let config = ok(TransitExternalKeyConfig::new(
                "https://bao.example",
                secret(),
            ));
            assert!(config.with_tls_server_name(name).is_err());
        }
    }

    #[test]
    fn transit_key_version_is_explicit_and_bounded() {
        for version in [0, i32::MAX as u32 + 1, u32::MAX] {
            assert!(TransitExternalKey::new("key", version).is_err());
        }
        for version in [1, i32::MAX as u32] {
            let key = ok(TransitExternalKey::new("key", version)).with_disable_prehashing(true);
            assert_eq!(
                wire(&key),
                json!({"name":"key", "version":version, "disable_prehashing":true})
            );
        }
        assert_eq!(
            wire(&ok(TransitExternalKey::new("key", 1)))["disable_prehashing"],
            false
        );
    }

    #[test]
    fn names_and_aliases_cannot_be_paths() {
        for name in [
            "",
            "../key",
            "/key",
            "key/",
            "key/child",
            "key?x",
            "key%2f",
            "key.",
        ] {
            assert!(TransitExternalKey::new(name, 1).is_err());
            assert!(Pkcs11ExternalKeyConfig::new(name, Pkcs11TokenSelector::Slot(1)).is_err());
        }
        assert!(TransitExternalKey::new("x".repeat(MAX_PROVIDER_NAME_BYTES), 1).is_ok());
        assert!(TransitExternalKey::new("x".repeat(MAX_PROVIDER_NAME_BYTES + 1), 1).is_err());
    }

    #[test]
    fn pkcs11_slot_is_a_lossless_string() {
        for slot in [0, 2_305_843_009_213_693_953, u64::MAX] {
            let config = ok(Pkcs11ExternalKeyConfig::new(
                "hsm",
                Pkcs11TokenSelector::Slot(slot),
            ));
            assert_eq!(
                wire(&config),
                json!({"lib":"hsm", "slot":slot.to_string(), "disable_software_encryption":false})
            );
        }
    }

    #[test]
    fn pkcs11_combines_selectors_and_keeps_pin_secret() {
        let config = ok(Pkcs11ExternalKeyConfig::new(
            "hsm",
            Pkcs11TokenSelector::Slot(1),
        ));
        let config = ok(config.with_selector(Pkcs11TokenSelector::Serial("serial".into())));
        let config = ok(config.with_selector(Pkcs11TokenSelector::Label("label".into())));
        let config = ok(config.with_selector(Pkcs11TokenSelector::Slot(2)));
        let config = ok(config.with_pin(secret())).with_disable_software_encryption(true);
        let encoded = wire(&config);
        assert_eq!(encoded["slot"], "2");
        assert_eq!(encoded["serial"], "serial");
        assert_eq!(encoded["token_label"], "label");
        assert_eq!(encoded["disable_software_encryption"], true);
        assert!(encoded["pin"].as_str() == Some(secret().expose_secret()));
        assert!(!format!("{config:?}").contains(secret().expose_secret()));
    }

    #[test]
    fn pkcs11_key_selectors_and_algorithms_match_wire_contract() {
        let key = ok(Pkcs11ExternalKey::by_label("key-label"));
        let key = ok(key.with_id("00abcd"))
            .with_mechanism(Pkcs11Mechanism::RsaOaep)
            .with_rsa_oaep_hash(Pkcs11OaepHash::Sha256);
        assert_eq!(
            wire(&key),
            json!({"label":"key-label", "id":"0x00abcd", "mechanism":"CKM_RSA_PKCS_OAEP", "rsa_oaep_hash":"sha256"})
        );
        assert_eq!(
            wire(&ok(Pkcs11ExternalKey::by_id("0x00ff"))),
            json!({"id":"0x00ff"})
        );
        for id in ["", "0x", "0", "0x0", "-1", "0xzz", "xx", "00\n", "0x00/ff"] {
            assert!(Pkcs11ExternalKey::by_id(id).is_err());
        }
        assert!(Pkcs11ExternalKey::by_id(&"ab".repeat(2048)).is_ok());
        assert!(Pkcs11ExternalKey::by_id(&"ab".repeat(2049)).is_err());
        for (mechanism, expected) in [
            (Pkcs11Mechanism::Ecdsa, "CKM_ECDSA"),
            (Pkcs11Mechanism::AesGcm, "CKM_AES_GCM"),
            (Pkcs11Mechanism::RsaPss, "CKM_RSA_PKCS_PSS"),
            (Pkcs11Mechanism::RsaOaep, "CKM_RSA_PKCS_OAEP"),
        ] {
            assert_eq!(wire(&mechanism), expected);
        }
        for (hash, expected) in [
            (Pkcs11OaepHash::Sha1, "sha1"),
            (Pkcs11OaepHash::Sha224, "sha224"),
            (Pkcs11OaepHash::Sha256, "sha256"),
            (Pkcs11OaepHash::Sha384, "sha384"),
            (Pkcs11OaepHash::Sha512, "sha512"),
        ] {
            assert_eq!(wire(&hash), expected);
        }
    }

    #[test]
    fn provider_text_limits_apply_before_storage() {
        for length in [0, MAX_PROVIDER_TEXT_BYTES, MAX_PROVIDER_TEXT_BYTES + 1] {
            let text = "x".repeat(length);
            let valid = length == MAX_PROVIDER_TEXT_BYTES;
            assert_eq!(Pkcs11ExternalKey::by_label(text.clone()).is_ok(), valid);
            assert_eq!(
                Pkcs11ExternalKeyConfig::new("hsm", Pkcs11TokenSelector::Serial(text.clone()))
                    .is_ok(),
                valid
            );
            assert_eq!(
                Pkcs11ExternalKeyConfig::new("hsm", Pkcs11TokenSelector::Label(text.clone()))
                    .is_ok(),
                valid
            );
            let config = ok(Pkcs11ExternalKeyConfig::new(
                "hsm",
                Pkcs11TokenSelector::Slot(1),
            ));
            assert_eq!(
                config.with_pin(SecretString::from(text.clone())).is_ok(),
                valid
            );
            assert_eq!(
                TransitExternalKeyConfig::new(
                    "https://bao.example",
                    SecretString::from(text.clone())
                )
                .is_ok(),
                valid
            );
            let config = ok(TransitExternalKeyConfig::new(
                "https://bao.example",
                secret(),
            ));
            assert_eq!(config.with_ca_certificate(text.clone()).is_ok(), valid);
            let config = ok(TransitExternalKeyConfig::new(
                "https://bao.example",
                secret(),
            ));
            assert_eq!(
                config.with_client_identity(text.clone(), secret()).is_ok(),
                valid
            );
            let config = ok(TransitExternalKeyConfig::new(
                "https://bao.example",
                secret(),
            ));
            assert_eq!(
                config
                    .with_client_identity("cert".into(), SecretString::from(text))
                    .is_ok(),
                valid
            );
        }
    }

    #[test]
    fn validation_errors_do_not_echo_sensitive_input() {
        let marker = ["fixture", "rejected", "credential"].join("-");
        let value = SecretString::from(format!("{marker}\n"));
        let result = TransitExternalKeyConfig::new("https://bao.example", value);
        let Err(error) = result else {
            panic!("invalid credential accepted")
        };
        assert!(!error.to_string().contains(&marker));
        assert!(!format!("{error:?}").contains(&marker));
    }
}
