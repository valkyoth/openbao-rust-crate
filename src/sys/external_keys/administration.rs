use reqwest::{
    Method, StatusCode,
    header::{CONTENT_TYPE, HeaderValue},
};
use serde::{Deserialize, Serialize};

use super::{
    ExternalKeyConfigPatch, ExternalKeyConfigRequest, ExternalKeyKeyPatch, ExternalKeyKeyRequest,
    ExternalKeyParameters, validate_name,
};
use crate::{
    Authenticated, Error, Result,
    compatibility::{OpenBaoVersion, latest_routable_profile},
    path::{validate_endpoint_path, validate_mount_path},
    response::{
        Empty, ListEntries, ListPageOptions, ResponseEnvelope, deserialize_bounded_string_vec,
    },
    sys::Sys,
};

/// Bounded names or mount paths returned by external-key LIST operations.
#[derive(Debug, Deserialize)]
pub struct ExternalKeyList {
    /// Config names, key names or normalized granted mount paths.
    #[serde(deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for ExternalKeyList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

fn config_path(config: &str) -> Result<String> {
    validate_name(config)?;
    Ok(format!("sys/external-keys/configs/{config}"))
}

fn key_path(config: &str, key: &str) -> Result<String> {
    validate_name(key)?;
    Ok(format!("{}/keys/{key}", config_path(config)?))
}

fn grant_path(config: &str, key: &str, mount: &str) -> Result<String> {
    let mount = validate_mount_path(mount)?.join("/");
    let path = format!("{}/grants/{mount}", key_path(config, key)?);
    validate_endpoint_path(&path)?;
    Ok(path)
}

impl Sys<'_, Authenticated> {
    // Do not infer support from the detected version when routing selected an
    // older fallback. Registry dispatch remains mandatory after this precheck.
    async fn require_external_keys(&self) -> Result<()> {
        let report = self.client.compatibility_report().await?;
        let version = report
            .profile_version()
            .or_else(latest_routable_profile)
            .ok_or(Error::Internal("no external-key compatibility profile"))?;
        if version < OpenBaoVersion::new(2, 7, 0) {
            return Err(Error::UnsupportedOpenBaoCapability {
                endpoint: "sys.external-keys",
                version,
            });
        }
        Ok(())
    }

    async fn external_key_list(
        &self,
        path: &str,
        options: &ListPageOptions,
    ) -> Result<ExternalKeyList> {
        self.require_external_keys().await?;
        let method =
            Method::from_bytes(b"LIST").map_err(|_| Error::Internal("invalid LIST method"))?;
        let envelope: ResponseEnvelope<ExternalKeyList> = self
            .client
            .request_sys_json_query_accepting(
                method,
                path,
                &options.query_pairs(),
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    async fn external_key_read(&self, path: &str) -> Result<ExternalKeyParameters> {
        self.require_external_keys().await?;
        let body = self
            .client
            .request_registered_secret_json_accepting(
                "/sys/",
                Method::GET,
                path,
                path,
                &[] as &[(&str, &str)],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        ExternalKeyParameters::from_envelope(body)
    }

    async fn external_key_write<B: Serialize + ?Sized>(
        &self,
        path: &str,
        method: Method,
        body: Option<&B>,
    ) -> Result<Empty> {
        self.require_external_keys().await?;
        let headers = if method == Method::PATCH {
            vec![(
                CONTENT_TYPE,
                HeaderValue::from_static("application/merge-patch+json"),
            )]
        } else {
            Vec::new()
        };
        self.client
            .request_sys_json_headers_accepting(
                method,
                path,
                &headers,
                body,
                &[StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Lists external-key configs in the selected namespace (OpenBao 2.7+).
    /// Requires both operator feature gates; unpromoted profiles fail closed.
    pub async fn list_external_key_configs(
        &self,
        options: &ListPageOptions,
    ) -> Result<ExternalKeyList> {
        self.external_key_list("sys/external-keys/configs", options)
            .await
    }

    /// Reads provider parameters, retaining all values in secret-aware storage.
    pub async fn read_external_key_config(&self, config: &str) -> Result<ExternalKeyParameters> {
        self.external_key_read(&config_path(config)?).await
    }

    /// Replaces a config, including credentials. Omitted provider options are removed.
    /// This does not install the plugin or create remote KMS key material.
    pub async fn write_external_key_config(
        &self,
        config: &str,
        request: &ExternalKeyConfigRequest,
    ) -> Result<Empty> {
        self.external_key_write(&config_path(config)?, Method::POST, Some(request))
            .await
    }

    /// Applies a reviewed JSON Merge Patch. Null deletes; omission preserves.
    pub async fn patch_external_key_config(
        &self,
        config: &str,
        patch: &ExternalKeyConfigPatch,
    ) -> Result<Empty> {
        self.external_key_write(&config_path(config)?, Method::PATCH, Some(patch))
            .await
    }

    /// Deletes a config and all its mappings/grants, not underlying KMS keys.
    /// Existing consumers can lose access immediately. There is no rollback or CAS.
    pub async fn delete_external_key_config(&self, config: &str) -> Result<Empty> {
        self.external_key_write(
            &config_path(config)?,
            Method::DELETE,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Lists key mappings in one config, with bounded pagination options.
    pub async fn list_external_keys(
        &self,
        config: &str,
        options: &ListPageOptions,
    ) -> Result<ExternalKeyList> {
        self.external_key_list(&format!("{}/keys", config_path(config)?), options)
            .await
    }

    /// Reads potentially sensitive provider key parameters, not remote key material.
    pub async fn read_external_key(
        &self,
        config: &str,
        key: &str,
    ) -> Result<ExternalKeyParameters> {
        self.external_key_read(&key_path(config, key)?).await
    }

    /// Replaces a mapping's provider options. Create a new mapping for rotated material.
    /// The containing config selects the actual provider; the server verifies the match.
    pub async fn write_external_key(
        &self,
        config: &str,
        key: &str,
        request: &ExternalKeyKeyRequest,
    ) -> Result<Empty> {
        self.external_key_write(&key_path(config, key)?, Method::POST, Some(request))
            .await
    }

    /// Patches provider key parameters. Null deletes; omission preserves.
    pub async fn patch_external_key(
        &self,
        config: &str,
        key: &str,
        patch: &ExternalKeyKeyPatch,
    ) -> Result<Empty> {
        self.external_key_write(&key_path(config, key)?, Method::PATCH, Some(patch))
            .await
    }

    /// Deletes a mapping and its grants, without deleting the underlying KMS key.
    /// Existing consumers can lose access immediately; this is not key revocation.
    pub async fn delete_external_key(&self, config: &str, key: &str) -> Result<Empty> {
        self.external_key_write(
            &key_path(config, key)?,
            Method::DELETE,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Lists grants (normalized mount paths). This endpoint has no pagination contract.
    pub async fn list_external_key_grants(
        &self,
        config: &str,
        key: &str,
    ) -> Result<ExternalKeyList> {
        self.external_key_list(
            &format!("{}/grants", key_path(config, key)?),
            &ListPageOptions::new(),
        )
        .await
    }

    /// Grants one same-namespace mount path access to the key. Privileged delegation.
    ///
    /// Grants are tied to paths, not mount identities. They persist after unmounting
    /// and can authorize a replacement mount. A nonexistent path can be granted.
    /// The server does not verify the provider during grant changes.
    pub async fn grant_external_key(&self, config: &str, key: &str, mount: &str) -> Result<Empty> {
        self.external_key_write(
            &grant_path(config, key, mount)?,
            Method::POST,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Removes one mount-path grant. Does not delete the key or revoke issued artifacts.
    /// A missing grant is a server-side no-op; consumers may lose access immediately.
    pub async fn delete_external_key_grant(
        &self,
        config: &str,
        key: &str,
        mount: &str,
    ) -> Result<Empty> {
        self.external_key_write(
            &grant_path(config, key, mount)?,
            Method::DELETE,
            Option::<&Empty>::None,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    use super::*;

    #[test]
    fn external_key_paths_preserve_component_boundaries() {
        assert_eq!(
            config_path("provider").ok().as_deref(),
            Some("sys/external-keys/configs/provider")
        );
        assert_eq!(
            key_path("provider", "key").ok().as_deref(),
            Some("sys/external-keys/configs/provider/keys/key")
        );
        assert_eq!(
            grant_path("provider", "key", "/auth/nested/")
                .ok()
                .as_deref(),
            Some("sys/external-keys/configs/provider/keys/key/grants/auth/nested")
        );
        for name in [
            "", "/other", "../other", "a/b", "a?b", "a%2fb", "a#b", "a\nb", "a.", "a:b", "a!b",
            ".name", "-name", "name-", "name.",
        ] {
            assert!(config_path(name).is_err());
            assert!(key_path("provider", name).is_err());
            assert!(grant_path("provider", name, "nested/mount").is_err());
        }
        for mount in ["", "../other", "a//b", "a?b", "a%2fb", "a#b", "a\nb"] {
            assert!(grant_path("provider", "key", mount).is_err());
        }
        assert!(grant_path("provider", "key", &"x".repeat(4096)).is_err());
    }

    #[test]
    fn lists_reject_duplicate_fields_and_overflow() {
        assert!(serde_json::from_str::<ExternalKeyList>(r#"{"keys":[],"keys":[]}"#).is_err());
        let over = format!(
            "{{\"keys\":[{}]}}",
            vec!["\"k\""; crate::response::MAX_RESPONSE_STRINGS + 1].join(",")
        );
        assert!(serde_json::from_str::<ExternalKeyList>(&over).is_err());
        let list = serde_json::from_str::<ExternalKeyList>(r#"{"keys":["nested/mount/"]}"#)
            .unwrap_or_else(|_| panic!("valid list rejected"));
        assert_eq!(list.entries(), &["nested/mount/"]);
    }
}
