//! Kubernetes secrets engine support.
//!
//! This engine generates Kubernetes service account credentials. The generated
//! service account token is treated as secret material and redacted from debug
//! output.

use core::fmt;
use std::collections::BTreeMap;

use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor, ser::SerializeMap};

use crate::{
    Authenticated, Client, Error, Result,
    path::{validate_endpoint_path, validate_mount_path},
    response::{
        Empty, ListEntries, ListPageOptions, ResponseEnvelope,
        deserialize_bounded_string_map_or_default, deserialize_bounded_string_vec,
    },
};

/// Handle for a mounted Kubernetes secrets engine.
#[derive(Debug)]
pub struct KubernetesSecrets<'a> {
    client: &'a Client<Authenticated>,
    mount: Vec<String>,
}

/// Kubernetes secrets engine configuration.
#[derive(Clone, Default, Deserialize)]
pub struct KubernetesSecretsConfig {
    /// Kubernetes API URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_host: Option<String>,
    /// PEM-encoded Kubernetes API CA certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_ca_cert: Option<String>,
    /// Service account JWT used by OpenBao to manage Kubernetes credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_jwt: Option<SecretString>,
    /// Disable local pod CA and service account JWT discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_local_ca_jwt: Option<bool>,
}

impl fmt::Debug for KubernetesSecretsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesSecretsConfig")
            .field("kubernetes_host", &self.kubernetes_host)
            .field("kubernetes_ca_cert", &self.kubernetes_ca_cert)
            .field(
                "service_account_jwt",
                &self.service_account_jwt.as_ref().map(|_| "<redacted>"),
            )
            .field("disable_local_ca_jwt", &self.disable_local_ca_jwt)
            .finish()
    }
}

/// Kubernetes secrets engine role.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KubernetesSecretsRole {
    /// Role name returned by OpenBao.
    #[serde(default, skip_serializing)]
    pub name: Option<String>,
    /// Namespaces this OpenBao role may generate credentials in.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_kubernetes_namespaces: Vec<String>,
    /// Kubernetes namespace label selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_kubernetes_namespace_selector: Option<String>,
    /// Maximum generated token TTL.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_max_ttl: Option<String>,
    /// Default generated token TTL.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_default_ttl: Option<String>,
    /// Default generated token audiences, as OpenBao expects a comma-separated string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_default_audiences: Option<String>,
    /// Existing service account to generate tokens for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_name: Option<String>,
    /// Existing Kubernetes Role or ClusterRole to bind to generated service accounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_role_name: Option<String>,
    /// Kubernetes role type, usually `Role` or `ClusterRole`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_role_type: Option<String>,
    /// YAML or JSON role rules used when OpenBao should generate a Kubernetes role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_role_rules: Option<String>,
    /// Name template for generated Kubernetes objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_template: Option<String>,
    /// Additional annotations for generated Kubernetes objects.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub extra_annotations: BTreeMap<String, String>,
    /// Additional labels for generated Kubernetes objects.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub extra_labels: BTreeMap<String, String>,
    /// Metadata returned by some OpenBao versions.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default",
        skip_serializing
    )]
    pub additional_metadata: BTreeMap<String, String>,
}

impl KubernetesSecretsRole {
    /// Creates a role that generates tokens for an existing service account.
    pub fn for_service_account(service_account_name: impl Into<String>) -> Self {
        Self {
            service_account_name: Some(service_account_name.into()),
            ..Self::default()
        }
    }

    /// Creates a role that creates service accounts and binds an existing
    /// Kubernetes Role or ClusterRole.
    pub fn for_kubernetes_role(kubernetes_role_name: impl Into<String>) -> Self {
        Self {
            kubernetes_role_name: Some(kubernetes_role_name.into()),
            ..Self::default()
        }
    }

    /// Creates a role that lets OpenBao generate Kubernetes RBAC rules from
    /// YAML or JSON.
    pub fn for_generated_role_rules(generated_role_rules: impl Into<String>) -> Self {
        Self {
            generated_role_rules: Some(generated_role_rules.into()),
            ..Self::default()
        }
    }

    /// Adds an allowed Kubernetes namespace.
    #[must_use]
    pub fn with_allowed_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.allowed_kubernetes_namespaces.push(namespace.into());
        self
    }

    /// Sets `token_default_ttl` after validating OpenBao duration syntax.
    pub fn with_token_default_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        validate_duration_or_seconds(&ttl, "kubernetes secrets token_default_ttl", true)?;
        self.token_default_ttl = Some(ttl);
        Ok(self)
    }

    /// Sets `token_default_ttl` from a Rust duration.
    pub fn with_token_default_ttl_duration(self, ttl: std::time::Duration) -> Result<Self> {
        self.with_token_default_ttl(crate::duration::nonzero_duration_to_bao_string(
            ttl,
            "kubernetes secrets token_default_ttl",
        )?)
    }

    /// Sets `token_max_ttl` after validating OpenBao duration syntax.
    pub fn with_token_max_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        validate_duration_or_seconds(&ttl, "kubernetes secrets token_max_ttl", true)?;
        self.token_max_ttl = Some(ttl);
        Ok(self)
    }

    /// Sets `token_max_ttl` from a Rust duration.
    pub fn with_token_max_ttl_duration(self, ttl: std::time::Duration) -> Result<Self> {
        self.with_token_max_ttl(crate::duration::nonzero_duration_to_bao_string(
            ttl,
            "kubernetes secrets token_max_ttl",
        )?)
    }

    fn validate(&self) -> Result<()> {
        let mode_count = usize::from(self.service_account_name.is_some())
            + usize::from(self.kubernetes_role_name.is_some())
            + usize::from(self.generated_role_rules.is_some());
        if mode_count != 1 {
            return Err(Error::InvalidParameter(
                "exactly one Kubernetes secrets role mode must be set".into(),
            ));
        }
        if let Some(ttl) = &self.token_default_ttl {
            validate_duration_or_seconds(ttl, "kubernetes secrets token_default_ttl", true)?;
        }
        if let Some(ttl) = &self.token_max_ttl {
            validate_duration_or_seconds(ttl, "kubernetes secrets token_max_ttl", true)?;
        }
        Ok(())
    }
}

/// Kubernetes secrets role list.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KubernetesSecretsRoleList {
    /// Role names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for KubernetesSecretsRoleList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Request for generated Kubernetes service account credentials.
#[derive(Clone, Debug, Default, Serialize)]
pub struct KubernetesCredentialsRequest {
    /// Kubernetes namespace to generate credentials in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_namespace: Option<String>,
    /// Generate a ClusterRoleBinding instead of a namespaced RoleBinding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_role_binding: Option<bool>,
    /// Requested generated token TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    /// Requested generated token audiences, as a comma-separated string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audiences: Option<String>,
}

impl KubernetesCredentialsRequest {
    /// Creates an empty credentials request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the target Kubernetes namespace.
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.kubernetes_namespace = Some(namespace.into());
        self
    }

    /// Requests a ClusterRoleBinding.
    #[must_use]
    pub fn with_cluster_role_binding(mut self, enabled: bool) -> Self {
        self.cluster_role_binding = Some(enabled);
        self
    }

    /// Sets the requested generated token TTL.
    pub fn with_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        validate_duration_or_seconds(&ttl, "kubernetes secrets credential ttl", false)?;
        self.ttl = Some(ttl);
        Ok(self)
    }

    /// Sets the requested generated token TTL from a Rust duration.
    pub fn with_ttl_duration(self, ttl: std::time::Duration) -> Result<Self> {
        self.with_ttl(crate::duration::nonzero_duration_to_bao_string(
            ttl,
            "kubernetes secrets credential ttl",
        )?)
    }
}

/// Generated Kubernetes service account credentials.
#[derive(Clone, Deserialize)]
pub struct KubernetesCredentials {
    /// Generated service account name.
    pub service_account_name: String,
    /// Generated service account namespace.
    pub service_account_namespace: String,
    /// Generated service account token.
    pub service_account_token: SecretString,
    /// Lease ID for revocation/renewal.
    pub lease_id: SecretString,
    /// Lease duration in seconds.
    pub lease_duration: u64,
    /// Whether the lease is renewable.
    pub renewable: bool,
}

impl fmt::Debug for KubernetesCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KubernetesCredentials")
            .field("service_account_name", &self.service_account_name)
            .field("service_account_namespace", &self.service_account_namespace)
            .field("service_account_token", &"<redacted>")
            .field("lease_id", &"<redacted>")
            .field("lease_duration", &self.lease_duration)
            .field("renewable", &self.renewable)
            .finish()
    }
}

#[derive(Deserialize)]
struct KubernetesCredentialData {
    service_account_name: String,
    service_account_namespace: String,
    service_account_token: SecretString,
}

impl Client<Authenticated> {
    /// Uses the Kubernetes secrets engine mounted at `kubernetes`.
    pub fn kubernetes_secrets(&self) -> Result<KubernetesSecrets<'_>> {
        self.kubernetes_secrets_at("kubernetes")
    }

    /// Uses the Kubernetes secrets engine mounted at `mount`.
    pub fn kubernetes_secrets_at(&self, mount: impl Into<String>) -> Result<KubernetesSecrets<'_>> {
        let mount = mount.into();
        Ok(KubernetesSecrets {
            client: self,
            mount: validate_mount_path(&mount)?,
        })
    }
}

impl KubernetesSecrets<'_> {
    /// Creates or updates the Kubernetes secrets engine configuration.
    pub async fn write_config(&self, config: &KubernetesSecretsConfig) -> Result<Empty> {
        self.request(Method::POST, &self.path(&["config"])?, Some(config))
            .await
    }

    /// Reads the Kubernetes secrets engine configuration.
    pub async fn read_config(&self) -> Result<KubernetesSecretsConfig> {
        let envelope: ResponseEnvelope<KubernetesSecretsConfig> = self
            .request(
                Method::GET,
                &self.path(&["config"])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes the Kubernetes secrets engine configuration.
    pub async fn delete_config(&self) -> Result<Empty> {
        self.request_accepting(
            Method::DELETE,
            &self.path(&["config"])?,
            Option::<&Empty>::None,
            &[StatusCode::OK, StatusCode::NO_CONTENT],
        )
        .await
    }

    /// Creates or updates a Kubernetes secrets engine role.
    pub async fn write_role(&self, name: &str, role: &KubernetesSecretsRole) -> Result<Empty> {
        role.validate()?;
        self.request(Method::POST, &self.path(&["roles", name])?, Some(role))
            .await
    }

    /// Reads a Kubernetes secrets engine role.
    pub async fn read_role(&self, name: &str) -> Result<KubernetesSecretsRole> {
        let envelope: ResponseEnvelope<KubernetesSecretsRole> = self
            .request(
                Method::GET,
                &self.path(&["roles", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists Kubernetes secrets engine role names.
    pub async fn list_roles(&self) -> Result<KubernetesSecretsRoleList> {
        self.list_roles_after(None, None).await
    }

    /// Lists Kubernetes secrets engine role names with optional pagination.
    pub async fn list_roles_after(
        &self,
        after: Option<&str>,
        limit: Option<u64>,
    ) -> Result<KubernetesSecretsRoleList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let query = ListPageOptions::from_after_limit(after, limit)?.query_pairs();
        let envelope: ResponseEnvelope<KubernetesSecretsRoleList> = self
            .request_query(
                method,
                &self.path(&["roles"])?,
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a Kubernetes secrets engine role.
    pub async fn delete_role(&self, name: &str) -> Result<Empty> {
        self.request_accepting(
            Method::DELETE,
            &self.path(&["roles", name])?,
            Option::<&Empty>::None,
            &[StatusCode::OK, StatusCode::NO_CONTENT],
        )
        .await
    }

    /// Generates Kubernetes service account credentials for a role.
    pub async fn credentials(
        &self,
        role: &str,
        request: &KubernetesCredentialsRequest,
    ) -> Result<KubernetesCredentials> {
        if let Some(ttl) = &request.ttl {
            validate_duration_or_seconds(ttl, "kubernetes secrets credential ttl", false)?;
        }
        let envelope: ResponseEnvelope<KubernetesCredentialData> = self
            .request(Method::POST, &self.path(&["creds", role])?, Some(request))
            .await?;
        Ok(kubernetes_credentials_from_envelope(envelope))
    }

    async fn request<T, B>(&self, method: Method, path: &str, body: Option<&B>) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.client
            .request_secret_json_internal(
                "/kubernetes/",
                "kubernetes",
                &self.mount.join("/"),
                method,
                path,
                body,
            )
            .await
    }

    async fn request_accepting<T, B>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        accepted_statuses: &[StatusCode],
    ) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.client
            .request_secret_json_accepting(
                "/kubernetes/",
                "kubernetes",
                &self.mount.join("/"),
                method,
                path,
                body,
                accepted_statuses,
            )
            .await
    }

    async fn request_query<T, B>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&B>,
        accepted_statuses: &[StatusCode],
    ) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.client
            .request_secret_json_query_headers_accepting(
                "/kubernetes/",
                "kubernetes",
                &self.mount.join("/"),
                method,
                path,
                query,
                &[],
                body,
                accepted_statuses,
            )
            .await
    }

    fn path(&self, tail: &[&str]) -> Result<String> {
        let mut segments = self.mount.clone();
        for segment in tail {
            segments.extend(validate_endpoint_path(segment)?);
        }
        Ok(segments.join("/"))
    }
}

impl Serialize for KubernetesSecretsConfig {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut count = 0;
        count += usize::from(self.kubernetes_host.is_some());
        count += usize::from(self.kubernetes_ca_cert.is_some());
        count += usize::from(self.service_account_jwt.is_some());
        count += usize::from(self.disable_local_ca_jwt.is_some());

        let mut map = serializer.serialize_map(Some(count))?;
        if let Some(kubernetes_host) = self.kubernetes_host.as_ref() {
            map.serialize_entry("kubernetes_host", kubernetes_host)?;
        }
        if let Some(kubernetes_ca_cert) = self.kubernetes_ca_cert.as_ref() {
            map.serialize_entry("kubernetes_ca_cert", kubernetes_ca_cert)?;
        }
        if let Some(service_account_jwt) = self.service_account_jwt.as_ref() {
            map.serialize_entry("service_account_jwt", service_account_jwt.expose_secret())?;
        }
        if let Some(disable_local_ca_jwt) = self.disable_local_ca_jwt {
            map.serialize_entry("disable_local_ca_jwt", &disable_local_ca_jwt)?;
        }
        map.end()
    }
}

fn kubernetes_credentials_from_envelope(
    envelope: ResponseEnvelope<KubernetesCredentialData>,
) -> KubernetesCredentials {
    KubernetesCredentials {
        service_account_name: envelope.data.service_account_name,
        service_account_namespace: envelope.data.service_account_namespace,
        service_account_token: envelope.data.service_account_token,
        lease_id: envelope.lease_id,
        lease_duration: envelope.lease_duration,
        renewable: envelope.renewable,
    }
}

fn validate_duration_or_seconds(value: &str, field: &'static str, allow_zero: bool) -> Result<()> {
    if value
        .parse::<u64>()
        .is_ok_and(|seconds| allow_zero || seconds > 0)
        || crate::validation::validate_duration_string(value, allow_zero)
    {
        return Ok(());
    }
    Err(Error::InvalidParameter(format!(
        "{field} must be a duration such as 30s, 5m, or 1h or an unsigned second count"
    )))
}

fn deserialize_bounded_string_or_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(StringOrListVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

struct StringOrListVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for StringOrListVisitor<MAX> {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a comma-separated string or a list of at most {MAX} strings"
        )
    }

    fn visit_unit<E>(self) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Vec::new())
    }

    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.trim().is_empty() {
            return Ok(Vec::new());
        }
        let values: Vec<String> = value
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect();
        if values.len() > MAX {
            return Err(E::custom("OpenBao string list exceeds item limit"));
        }
        Ok(values)
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while values.len() < MAX {
            let Some(value) = seq.next_element::<String>()? else {
                return Ok(values);
            };
            values.push(value);
        }
        while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
        Err(serde::de::Error::custom(
            "OpenBao string list exceeds item limit",
        ))
    }
}

fn deserialize_optional_string_or_u64<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(OptionalStringOrU64Visitor)
}

struct OptionalStringOrU64Visitor;

impl<'de> Visitor<'de> for OptionalStringOrU64Visitor {
    type Value = Option<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string, an unsigned integer, or null")
    }

    fn visit_none<E>(self) -> core::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E>(self) -> core::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> core::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(Self)
    }

    fn visit_u64<E>(self, value: u64) -> core::result::Result<Self::Value, E> {
        Ok(Some(value.to_string()))
    }

    fn visit_i64<E>(self, value: i64) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let value =
            u64::try_from(value).map_err(|_| E::custom("duration seconds must not be negative"))?;
        Ok(Some(value.to_string()))
    }

    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E> {
        Ok(Some(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E> {
        Ok(Some(value))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::{ExposeSecret, SecretString};

    use crate::{Client, OpenBaoConfig};

    use super::{
        KubernetesCredentials, KubernetesSecretsConfig, KubernetesSecretsRole,
        KubernetesSecretsRoleList,
    };

    #[test]
    fn kubernetes_secrets_paths_are_validated() {
        let config = OpenBaoConfig::new("http://127.0.0.1:8200")
            .and_then(OpenBaoConfig::allow_localhost_http)
            .unwrap_or_else(|error| panic!("{error}"));
        let client = Client::from_config(config)
            .and_then(|client| client.try_with_token(SecretString::from("token")))
            .unwrap_or_else(|error| panic!("{error}"));
        let kubernetes = client
            .kubernetes_secrets()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            kubernetes
                .path(&["roles", "app"])
                .unwrap_or_else(|error| panic!("{error}")),
            "kubernetes/roles/app"
        );
        assert!(kubernetes.path(&["roles", "../app"]).is_err());
        assert!(client.kubernetes_secrets_at("../kubernetes").is_err());
    }

    #[test]
    fn kubernetes_secrets_role_mode_is_validated() {
        assert!(
            KubernetesSecretsRole::for_service_account("default")
                .validate()
                .is_ok()
        );
        let mut role = KubernetesSecretsRole::for_service_account("default");
        role.kubernetes_role_name = Some("viewer".to_owned());
        assert!(role.validate().is_err());
        assert!(KubernetesSecretsRole::default().validate().is_err());
    }

    #[test]
    fn kubernetes_secrets_role_ttls_are_validated() {
        assert!(
            KubernetesSecretsRole::for_service_account("default")
                .with_token_default_ttl("30m")
                .is_ok()
        );
        assert!(
            KubernetesSecretsRole::for_service_account("default")
                .with_token_max_ttl("forever")
                .is_err()
        );
    }

    #[test]
    fn kubernetes_secrets_lists_are_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("role-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<KubernetesSecretsRoleList>(value) {
            Ok(_) => panic!("oversized Kubernetes role list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn kubernetes_secrets_config_and_credentials_redact_tokens() {
        let config = KubernetesSecretsConfig {
            service_account_jwt: Some(SecretString::from("jwt-token")),
            ..Default::default()
        };
        assert!(!format!("{config:?}").contains("jwt-token"));

        let credentials: KubernetesCredentials = serde_json::from_str(
            r#"{"service_account_name":"app","service_account_namespace":"default","service_account_token":"generated-token","lease_id":"kubernetes/creds/app/lease","lease_duration":3600,"renewable":false}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            credentials.service_account_token.expose_secret(),
            "generated-token"
        );
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("generated-token"));
        assert!(!debug.contains("kubernetes/creds/app/lease"));
    }
}
