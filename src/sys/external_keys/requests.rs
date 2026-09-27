use core::fmt;
use serde::Serialize;

use super::{
    ExternalKeyCustomOptionsAcknowledgement, ExternalKeyOptions, Pkcs11ExternalKey,
    Pkcs11ExternalKeyConfig, TransitExternalKey, TransitExternalKeyConfig, validate_name,
};
use crate::Result;

/// Explicit acknowledgement of disabling the server's provider verification.
///
/// Invalid or unavailable providers may be persisted and fail only when used.
/// This does not disable TLS validation in the typed Transit configuration.
pub struct ExternalKeyVerificationBypass(());

impl ExternalKeyVerificationBypass {
    /// Acknowledges deferred validation and potentially unusable key mappings.
    pub fn acknowledge_deferred_validation() -> Self {
        Self(())
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum ConfigProvider {
    Transit(TransitExternalKeyConfig),
    Pkcs11(Pkcs11ExternalKeyConfig),
    Custom(ExternalKeyOptions),
}

#[derive(Serialize)]
#[serde(untagged)]
enum KeyProvider {
    Transit(TransitExternalKey),
    Pkcs11(Pkcs11ExternalKey),
    Custom(ExternalKeyOptions),
}

/// Full replacement of an external-key provider config. Verification defaults on.
/// Omitted options are removed on the server; this is not a merge operation.
#[derive(Serialize)]
pub struct ExternalKeyConfigRequest {
    plugin: String,
    verify: bool,
    #[serde(flatten)]
    provider: ConfigProvider,
}

impl ExternalKeyConfigRequest {
    /// Uses the built-in Transit provider and its validated HTTPS schema.
    pub fn transit(config: TransitExternalKeyConfig) -> Self {
        Self {
            plugin: "transit".into(),
            verify: true,
            provider: ConfigProvider::Transit(config),
        }
    }

    /// Uses an operator-registered PKCS#11 plugin name and validated schema.
    /// The SDK cannot attest that the installed plugin actually implements PKCS#11.
    pub fn pkcs11(plugin: &str, config: Pkcs11ExternalKeyConfig) -> Result<Self> {
        validate_name(plugin)?;
        Ok(Self {
            plugin: plugin.into(),
            verify: true,
            provider: ConfigProvider::Pkcs11(config),
        })
    }

    /// Uses explicitly reviewed custom provider options, without schema validation.
    pub fn custom(
        plugin: &str,
        options: ExternalKeyOptions,
        _: ExternalKeyCustomOptionsAcknowledgement,
    ) -> Result<Self> {
        validate_name(plugin)?;
        Ok(Self {
            plugin: plugin.into(),
            verify: true,
            provider: ConfigProvider::Custom(options),
        })
    }

    /// Disables server verification for this write only, with acknowledgement.
    pub fn without_verification(mut self, _: ExternalKeyVerificationBypass) -> Self {
        self.verify = false;
        self
    }
}

/// Full replacement of provider parameters for one key mapping.
/// Does not change key material in the remote provider.
#[derive(Serialize)]
pub struct ExternalKeyKeyRequest {
    verify: bool,
    #[serde(flatten)]
    provider: KeyProvider,
}

impl ExternalKeyKeyRequest {
    /// Maps a Transit key. The containing config must use the Transit provider.
    pub fn transit(key: TransitExternalKey) -> Self {
        Self {
            verify: true,
            provider: KeyProvider::Transit(key),
        }
    }
    /// Maps a PKCS#11 key. The containing config must use the matching provider.
    pub fn pkcs11(key: Pkcs11ExternalKey) -> Self {
        Self {
            verify: true,
            provider: KeyProvider::Pkcs11(key),
        }
    }
    /// Maps a custom provider key after explicit review of the options.
    pub fn custom(options: ExternalKeyOptions, _: ExternalKeyCustomOptionsAcknowledgement) -> Self {
        Self {
            verify: true,
            provider: KeyProvider::Custom(options),
        }
    }
    /// Disables server verification for this write only, with acknowledgement.
    pub fn without_verification(mut self, _: ExternalKeyVerificationBypass) -> Self {
        self.verify = false;
        self
    }
}

/// JSON Merge Patch for provider configuration.
///
/// Omitted fields remain unchanged; JSON null deletes provider fields. A patch
/// is not a validated complete configuration: deleting a TLS option or changing
/// a plugin can change trust and credential handling. Custom-option review is
/// required, and server verification remains enabled unless explicitly bypassed.
#[derive(Serialize)]
pub struct ExternalKeyConfigPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    plugin: Option<String>,
    verify: bool,
    #[serde(flatten)]
    options: ExternalKeyOptions,
}

impl ExternalKeyConfigPatch {
    /// Builds a reviewed merge patch with server verification enabled.
    pub fn new(options: ExternalKeyOptions, _: ExternalKeyCustomOptionsAcknowledgement) -> Self {
        Self {
            plugin: None,
            verify: true,
            options,
        }
    }
    /// Changes the plugin separately from provider-option merge semantics.
    /// Does not remove incompatible options left over from the previous provider.
    pub fn with_plugin(mut self, plugin: &str) -> Result<Self> {
        validate_name(plugin)?;
        self.plugin = Some(plugin.into());
        Ok(self)
    }
    /// Disables server verification for this patch only, with acknowledgement.
    pub fn without_verification(mut self, _: ExternalKeyVerificationBypass) -> Self {
        self.verify = false;
        self
    }
}

/// JSON Merge Patch for a key mapping. Omission preserves; null removes.
/// Review provider-specific effects before constructing this request.
#[derive(Serialize)]
pub struct ExternalKeyKeyPatch {
    verify: bool,
    #[serde(flatten)]
    options: ExternalKeyOptions,
}

impl ExternalKeyKeyPatch {
    /// Builds a reviewed merge patch with server verification enabled.
    pub fn new(options: ExternalKeyOptions, _: ExternalKeyCustomOptionsAcknowledgement) -> Self {
        Self {
            verify: true,
            options,
        }
    }
    /// Disables server verification for this patch only, with acknowledgement.
    pub fn without_verification(mut self, _: ExternalKeyVerificationBypass) -> Self {
        self.verify = false;
        self
    }
}

macro_rules! redacted_debug {
    ($($ty:ident),+ $(,)?) => {$(
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($ty)).finish_non_exhaustive()
            }
        }
    )+};
}
redacted_debug!(
    ExternalKeyConfigRequest,
    ExternalKeyKeyRequest,
    ExternalKeyConfigPatch,
    ExternalKeyKeyPatch
);

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    use super::*;
    use sanitization::SecretVec;
    use secrecy::SecretString;
    use serde_json::json;

    fn options(text: &str) -> ExternalKeyOptions {
        ExternalKeyOptions::from_json(SecretVec::from_slice(text.as_bytes()))
            .unwrap_or_else(|_| panic!("invalid fixture options"))
    }
    fn ack() -> ExternalKeyCustomOptionsAcknowledgement {
        ExternalKeyCustomOptionsAcknowledgement::acknowledge_unvalidated_provider()
    }
    fn bypass() -> ExternalKeyVerificationBypass {
        ExternalKeyVerificationBypass::acknowledge_deferred_validation()
    }
    fn wire(value: &impl Serialize) -> serde_json::Value {
        serde_json::to_value(value).unwrap_or_else(|_| panic!("fixture serialization failed"))
    }

    #[test]
    fn config_and_key_requests_flatten_provider_options_and_default_to_verification() {
        let config = TransitExternalKeyConfig::new(
            "https://bao.example",
            SecretString::from(["fixture", "token"].join("-")),
        )
        .unwrap_or_else(|_| panic!("invalid fixture config"));
        let request = ExternalKeyConfigRequest::transit(config);
        let value = wire(&request);
        assert_eq!(value["plugin"], "transit");
        assert_eq!(value["verify"], true);
        assert_eq!(value["tls_skip_verify"], false);
        assert!(value.get("provider").is_none());
        assert!(!format!("{request:?}").contains("fixture"));
        assert_eq!(
            wire(&request.without_verification(bypass()))["verify"],
            false
        );
        let key =
            TransitExternalKey::new("remote", 3).unwrap_or_else(|_| panic!("invalid fixture key"));
        let request = ExternalKeyKeyRequest::transit(key);
        assert_eq!(
            wire(&request),
            json!({"name":"remote","version":3,"disable_prehashing":false,"verify":true})
        );
        assert_eq!(
            wire(&request.without_verification(bypass()))["verify"],
            false
        );
        let config =
            Pkcs11ExternalKeyConfig::new("alias", super::super::Pkcs11TokenSelector::Slot(1))
                .unwrap_or_else(|_| panic!("invalid fixture selector"));
        let request = ExternalKeyConfigRequest::pkcs11("installed-hsm", config)
            .unwrap_or_else(|_| panic!("invalid fixture plugin"));
        assert_eq!(
            wire(&request),
            json!({"plugin":"installed-hsm","verify":true,"lib":"alias","slot":"1","disable_software_encryption":false})
        );
        let key =
            Pkcs11ExternalKey::by_label("key").unwrap_or_else(|_| panic!("invalid fixture label"));
        assert_eq!(
            wire(&ExternalKeyKeyRequest::pkcs11(key)),
            json!({"label":"key","verify":true})
        );
    }

    #[test]
    fn patches_preserve_null_omit_unchanged_fields_and_separate_verification() {
        let patch = ExternalKeyConfigPatch::new(
            options(r#"{"token":null,"nested":{"remove":null}}"#),
            ack(),
        );
        assert_eq!(
            wire(&patch),
            json!({"token":null,"nested":{"remove":null},"verify":true})
        );
        let patch = patch
            .with_plugin("transit")
            .unwrap_or_else(|_| panic!("invalid fixture plugin"))
            .without_verification(bypass());
        assert_eq!(wire(&patch)["plugin"], "transit");
        assert_eq!(wire(&patch)["verify"], false);
        let patch = ExternalKeyKeyPatch::new(options(r#"{"label":null}"#), ack());
        assert_eq!(wire(&patch), json!({"label":null,"verify":true}));
        assert_eq!(wire(&patch.without_verification(bypass()))["verify"], false);
        assert_eq!(
            wire(&ExternalKeyConfigPatch::new(options("{}"), ack())),
            json!({"verify":true})
        );
    }

    #[test]
    fn custom_payloads_are_flattened_redacted_and_names_validated() {
        let request = ExternalKeyConfigRequest::custom(
            "provider",
            options(r#"{"credential":"fixture-value"}"#),
            ack(),
        )
        .unwrap_or_else(|_| panic!("invalid fixture config"));
        assert!(!format!("{request:?}").contains("fixture-value"));
        let request =
            ExternalKeyKeyRequest::custom(options(r#"{"credential":"fixture-value"}"#), ack());
        assert!(!format!("{request:?}").contains("fixture-value"));
        assert!(wire(&request).get("credential").is_some());
        for name in ["", "../provider", "provider/child", "provider?query"] {
            assert!(ExternalKeyConfigRequest::custom(name, options("{}"), ack()).is_err());
            assert!(
                ExternalKeyConfigPatch::new(options("{}"), ack())
                    .with_plugin(name)
                    .is_err()
            );
        }
    }
}
