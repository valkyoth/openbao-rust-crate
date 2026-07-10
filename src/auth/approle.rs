//! AppRole authentication support.

use std::collections::BTreeMap;

use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};

use crate::{
    Authenticated, Client, Error, Result, Unauthenticated,
    path::validate_mount_path,
    response::{
        Empty, ListEntries, ResponseEnvelope, deserialize_bounded_string_map_or_default,
        deserialize_bounded_string_vec,
    },
};

/// Handle for the AppRole auth method at a configured mount.
#[derive(Debug)]
pub struct AppRole<'a> {
    client: &'a Client<Unauthenticated>,
    mount: String,
}

/// Handle for AppRole auth administration at a configured mount.
#[derive(Debug)]
pub struct AppRoleAdmin<'a> {
    client: &'a Client<Authenticated>,
    mount: String,
}

/// AppRole role create/update request.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AppRoleRoleRequest {
    /// Require a SecretID during login.
    ///
    /// Security: setting this to `false` allows login using only the RoleID.
    /// RoleIDs are often distributed more broadly than SecretIDs. Disable
    /// SecretID binding only when the RoleID is itself protected and other
    /// controls, such as CIDR binding, provide equivalent restriction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_secret_id: Option<bool>,
    /// CIDRs allowed to use generated SecretIDs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secret_id_bound_cidrs: Vec<String>,
    /// Uses allowed for generated SecretIDs. Zero means unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_id_num_uses: Option<u64>,
    /// SecretID TTL such as `30m`. Zero duration means no expiry.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub secret_id_ttl: Option<String>,
    /// Whether generated SecretIDs are local to the cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_secret_ids: Option<bool>,
    /// Token TTL such as `30m`.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_ttl: Option<String>,
    /// Token max TTL such as `2h`.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_max_ttl: Option<String>,
    /// Token policies attached to generated tokens.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_policies: Vec<String>,
    /// CIDRs allowed to use generated tokens.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_bound_cidrs: Vec<String>,
    /// Bind generated tokens to the source IP used during login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_strictly_bind_ip: Option<bool>,
    /// Explicit max TTL for generated tokens.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_explicit_max_ttl: Option<String>,
    /// Omit the default policy from generated tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_no_default_policy: Option<bool>,
    /// Maximum uses for generated tokens. Zero means unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_num_uses: Option<u64>,
    /// Periodic token period.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub token_period: Option<String>,
    /// Generated token type, such as `service`, `batch`, or `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

impl AppRoleRoleRequest {
    /// Creates an empty AppRole role request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a generated-token policy.
    #[must_use]
    pub fn with_token_policy(mut self, policy: impl Into<String>) -> Self {
        self.token_policies.push(policy.into());
        self
    }

    /// Sets the generated-token TTL.
    pub fn with_token_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        crate::validation::validate_duration_parameter(&ttl, "approle token_ttl")?;
        self.token_ttl = Some(ttl);
        Ok(self)
    }

    /// Sets the generated-token TTL from a Rust duration.
    pub fn with_token_ttl_duration(self, ttl: std::time::Duration) -> Result<Self> {
        self.with_token_ttl(crate::duration::nonzero_duration_to_bao_string(
            ttl,
            "approle token_ttl",
        )?)
    }

    /// Sets the generated SecretID TTL.
    pub fn with_secret_id_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        crate::validation::validate_duration_parameter(&ttl, "approle secret_id_ttl")?;
        self.secret_id_ttl = Some(ttl);
        Ok(self)
    }

    /// Sets the generated SecretID TTL from a Rust duration.
    pub fn with_secret_id_ttl_duration(self, ttl: std::time::Duration) -> Result<Self> {
        self.with_secret_id_ttl(crate::duration::nonzero_duration_to_bao_string(
            ttl,
            "approle secret_id_ttl",
        )?)
    }

    fn validate(&self) -> Result<()> {
        validate_string_list_len(&self.token_policies, "approle token_policies")?;
        validate_string_list_len(&self.secret_id_bound_cidrs, "approle secret_id_bound_cidrs")?;
        validate_string_list_len(&self.token_bound_cidrs, "approle token_bound_cidrs")?;
        crate::validation::validate_cidr_list(
            &self.secret_id_bound_cidrs,
            "approle secret_id_bound_cidrs",
        )?;
        crate::validation::validate_cidr_list(&self.token_bound_cidrs, "approle token_bound_cidrs")
    }
}

/// AppRole role list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct AppRoleRoleList {
    /// Role names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for AppRoleRoleList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// AppRole RoleID response.
#[derive(Clone, Deserialize)]
pub struct AppRoleRoleId {
    /// RoleID value. Treat as secret material.
    pub role_id: SecretString,
}

impl core::fmt::Debug for AppRoleRoleId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AppRoleRoleId")
            .field("role_id", &"<redacted>")
            .finish()
    }
}

/// SecretID generation request.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AppRoleSecretIdRequest {
    /// Metadata JSON string attached to the SecretID and emitted to audit logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    /// CIDRs allowed to use this SecretID.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cidr_list: Vec<String>,
    /// CIDRs allowed to use tokens generated from this SecretID.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_bound_cidrs: Vec<String>,
    /// Number of allowed uses for this SecretID. Zero means unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub num_uses: Option<u64>,
    /// TTL for this SecretID.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub ttl: Option<String>,
}

impl AppRoleSecretIdRequest {
    /// Creates an empty SecretID generation request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the SecretID TTL.
    pub fn with_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        crate::validation::validate_duration_parameter(&ttl, "approle secret_id ttl")?;
        self.ttl = Some(ttl);
        Ok(self)
    }

    /// Sets the SecretID TTL from a Rust duration.
    pub fn with_ttl_duration(self, ttl: std::time::Duration) -> Result<Self> {
        self.with_ttl(crate::duration::nonzero_duration_to_bao_string(
            ttl,
            "approle secret_id ttl",
        )?)
    }

    /// Sets the SecretID metadata JSON object string.
    ///
    /// OpenBao emits this metadata to audit logs. The value must be a JSON
    /// object string such as `{"service":"payments"}`.
    pub fn with_metadata(mut self, metadata: impl Into<String>) -> Result<Self> {
        let metadata = metadata.into();
        crate::validation::validate_json_object_string(&metadata, "approle secret_id metadata")?;
        self.metadata = Some(metadata);
        Ok(self)
    }

    /// Adds a CIDR restriction for this SecretID.
    pub fn with_cidr(mut self, cidr: impl Into<String>) -> Result<Self> {
        let cidr = cidr.into();
        crate::validation::validate_cidr(&cidr, "approle secret_id cidr_list")?;
        self.cidr_list.push(cidr);
        Ok(self)
    }

    /// Adds a CIDR restriction for tokens generated from this SecretID.
    pub fn with_token_bound_cidr(mut self, cidr: impl Into<String>) -> Result<Self> {
        let cidr = cidr.into();
        crate::validation::validate_cidr(&cidr, "approle secret_id token_bound_cidrs")?;
        self.token_bound_cidrs.push(cidr);
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        if let Some(metadata) = &self.metadata {
            crate::validation::validate_json_object_string(metadata, "approle secret_id metadata")?;
        }
        crate::validation::validate_cidr_list(&self.cidr_list, "approle secret_id cidr_list")?;
        crate::validation::validate_cidr_list(
            &self.token_bound_cidrs,
            "approle secret_id token_bound_cidrs",
        )?;
        if let Some(ttl) = &self.ttl {
            crate::validation::validate_duration_parameter(ttl, "approle secret_id ttl")?;
        }
        Ok(())
    }
}

/// Custom SecretID assignment request.
#[derive(Clone, Default, Deserialize)]
pub struct AppRoleCustomSecretIdRequest {
    /// Caller-provided SecretID. Treat as secret material.
    pub secret_id: SecretString,
    /// Metadata JSON string attached to the SecretID and emitted to audit logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    /// CIDRs allowed to use this SecretID.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cidr_list: Vec<String>,
    /// CIDRs allowed to use tokens generated from this SecretID.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_bound_cidrs: Vec<String>,
    /// Number of allowed uses for this SecretID. Zero means unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub num_uses: Option<u64>,
    /// TTL for this SecretID.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_string_or_u64",
        skip_serializing_if = "Option::is_none"
    )]
    pub ttl: Option<String>,
}

#[derive(Serialize)]
struct AppRoleCustomSecretIdPayload<'a> {
    secret_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cidr_list: Vec<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    token_bound_cidrs: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_uses: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<&'a str>,
}

impl AppRoleCustomSecretIdRequest {
    /// Creates a custom SecretID assignment request.
    pub fn new(secret_id: SecretString) -> Self {
        Self {
            secret_id,
            ..Self::default()
        }
    }

    /// Sets the custom SecretID metadata JSON object string.
    ///
    /// OpenBao emits this metadata to audit logs. The value must be a JSON
    /// object string such as `{"service":"payments"}`.
    pub fn with_metadata(mut self, metadata: impl Into<String>) -> Result<Self> {
        let metadata = metadata.into();
        crate::validation::validate_json_object_string(
            &metadata,
            "approle custom secret_id metadata",
        )?;
        self.metadata = Some(metadata);
        Ok(self)
    }

    /// Adds a CIDR restriction for this custom SecretID.
    pub fn with_cidr(mut self, cidr: impl Into<String>) -> Result<Self> {
        let cidr = cidr.into();
        crate::validation::validate_cidr(&cidr, "approle custom secret_id cidr_list")?;
        self.cidr_list.push(cidr);
        Ok(self)
    }

    /// Adds a CIDR restriction for tokens generated from this custom SecretID.
    pub fn with_token_bound_cidr(mut self, cidr: impl Into<String>) -> Result<Self> {
        let cidr = cidr.into();
        crate::validation::validate_cidr(&cidr, "approle custom secret_id token_bound_cidrs")?;
        self.token_bound_cidrs.push(cidr);
        Ok(self)
    }

    /// Sets the custom SecretID TTL.
    pub fn with_ttl(mut self, ttl: impl Into<String>) -> Result<Self> {
        let ttl = ttl.into();
        crate::validation::validate_duration_parameter(&ttl, "approle custom secret_id ttl")?;
        self.ttl = Some(ttl);
        Ok(self)
    }

    /// Sets the custom SecretID TTL from a Rust duration.
    pub fn with_ttl_duration(self, ttl: std::time::Duration) -> Result<Self> {
        self.with_ttl(crate::duration::nonzero_duration_to_bao_string(
            ttl,
            "approle custom secret_id ttl",
        )?)
    }

    fn validate(&self) -> Result<()> {
        if let Some(metadata) = &self.metadata {
            crate::validation::validate_json_object_string(
                metadata,
                "approle custom secret_id metadata",
            )?;
        }
        crate::validation::validate_cidr_list(
            &self.cidr_list,
            "approle custom secret_id cidr_list",
        )?;
        crate::validation::validate_cidr_list(
            &self.token_bound_cidrs,
            "approle custom secret_id token_bound_cidrs",
        )?;
        if let Some(ttl) = &self.ttl {
            crate::validation::validate_duration_parameter(ttl, "approle custom secret_id ttl")?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for AppRoleCustomSecretIdRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AppRoleCustomSecretIdRequest")
            .field("secret_id", &"<redacted>")
            .field("metadata", &self.metadata)
            .field("cidr_list", &self.cidr_list)
            .field("token_bound_cidrs", &self.token_bound_cidrs)
            .field("num_uses", &self.num_uses)
            .field("ttl", &self.ttl)
            .finish()
    }
}

/// Generated or assigned SecretID response.
#[derive(Clone, Deserialize)]
pub struct AppRoleSecretId {
    /// SecretID value. Treat as secret material.
    pub secret_id: SecretString,
    /// SecretID accessor. Treat as secret material because it can destroy or
    /// look up SecretID metadata.
    pub secret_id_accessor: SecretString,
    /// SecretID TTL in seconds.
    #[serde(default)]
    pub secret_id_ttl: u64,
    /// SecretID use count limit.
    #[serde(default)]
    pub secret_id_num_uses: u64,
}

impl core::fmt::Debug for AppRoleSecretId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AppRoleSecretId")
            .field("secret_id", &"<redacted>")
            .field("secret_id_accessor", &"<redacted>")
            .field("secret_id_ttl", &self.secret_id_ttl)
            .field("secret_id_num_uses", &self.secret_id_num_uses)
            .finish()
    }
}

/// SecretID metadata returned by lookup endpoints.
#[derive(Clone, Deserialize)]
pub struct AppRoleSecretIdInfo {
    /// CIDRs allowed to use this SecretID.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub cidr_list: Vec<String>,
    /// SecretID creation timestamp.
    #[serde(default)]
    pub creation_time: Option<String>,
    /// SecretID expiration timestamp.
    #[serde(default)]
    pub expiration_time: Option<String>,
    /// Last update timestamp.
    #[serde(default)]
    pub last_updated_time: Option<String>,
    /// Metadata attached to the SecretID.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    pub metadata: BTreeMap<String, String>,
    /// SecretID accessor. Treat as secret material.
    #[serde(default)]
    pub secret_id_accessor: Option<SecretString>,
    /// SecretID use count limit.
    #[serde(default)]
    pub secret_id_num_uses: u64,
    /// SecretID TTL in seconds.
    #[serde(default)]
    pub secret_id_ttl: u64,
    /// CIDRs allowed to use tokens generated from this SecretID.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub token_bound_cidrs: Vec<String>,
}

impl core::fmt::Debug for AppRoleSecretIdInfo {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AppRoleSecretIdInfo")
            .field("cidr_list", &self.cidr_list)
            .field("creation_time", &self.creation_time)
            .field("expiration_time", &self.expiration_time)
            .field("last_updated_time", &self.last_updated_time)
            .field("metadata", &self.metadata)
            .field(
                "secret_id_accessor",
                &self.secret_id_accessor.as_ref().map(|_| "<redacted>"),
            )
            .field("secret_id_num_uses", &self.secret_id_num_uses)
            .field("secret_id_ttl", &self.secret_id_ttl)
            .field("token_bound_cidrs", &self.token_bound_cidrs)
            .finish()
    }
}

/// SecretID accessor list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct AppRoleSecretIdAccessorList {
    /// SecretID accessors. Treat returned values as sensitive.
    #[serde(
        default,
        deserialize_with = "crate::response::deserialize_bounded_secret_string_vec"
    )]
    pub keys: Vec<SecretString>,
}

/// Metadata returned after a successful login.
#[derive(Debug, Deserialize)]
pub struct LoginMetadata {
    /// Token accessor. Accessors can revoke or look up token metadata, so they
    /// are treated as secret material.
    pub accessor: SecretString,
    /// Policies attached to the token.
    #[serde(
        default,
        deserialize_with = "crate::response::deserialize_bounded_string_vec"
    )]
    pub policies: Vec<String>,
    /// Token lease duration in seconds.
    #[serde(default)]
    pub lease_duration: u64,
    /// Whether the token is renewable.
    #[serde(default)]
    pub renewable: bool,
}

#[derive(Serialize)]
struct LoginRequest<'a> {
    role_id: &'a str,
    secret_id: &'a str,
}

#[derive(Deserialize)]
struct LoginResponse {
    auth: Option<LoginAuth>,
}

#[derive(Deserialize)]
struct LoginAuth {
    #[serde(deserialize_with = "deserialize_secret")]
    client_token: SecretString,
    #[serde(deserialize_with = "deserialize_secret")]
    accessor: SecretString,
    #[serde(
        default,
        deserialize_with = "crate::response::deserialize_bounded_string_vec"
    )]
    policies: Vec<String>,
    #[serde(default)]
    lease_duration: u64,
    #[serde(default)]
    renewable: bool,
}

#[derive(Serialize)]
struct RoleIdRequest<'a> {
    role_id: &'a str,
}

#[derive(Serialize)]
struct SecretIdLookupRequest<'a> {
    secret_id: &'a str,
}

#[derive(Serialize)]
struct SecretIdAccessorLookupRequest<'a> {
    secret_id_accessor: &'a str,
}

#[derive(Deserialize)]
struct BindSecretIdProperty {
    bind_secret_id: bool,
}

#[derive(Serialize)]
struct BindSecretIdPayload {
    bind_secret_id: bool,
}

#[derive(Deserialize)]
struct StringListProperty {
    #[serde(
        default,
        alias = "policies",
        alias = "secret_id_bound_cidrs",
        alias = "token_bound_cidrs",
        alias = "token_policies",
        deserialize_with = "deserialize_bounded_string_vec"
    )]
    values: Vec<String>,
}

#[derive(Serialize)]
struct PoliciesPayload<'a> {
    token_policies: &'a [String],
}

#[derive(Serialize)]
struct SecretIdBoundCidrsPayload<'a> {
    secret_id_bound_cidrs: &'a [String],
}

#[derive(Serialize)]
struct TokenBoundCidrsPayload<'a> {
    token_bound_cidrs: &'a [String],
}

#[derive(Deserialize)]
struct U64Property {
    #[serde(alias = "secret_id_num_uses")]
    value: u64,
}

#[derive(Serialize)]
struct SecretIdNumUsesPayload {
    secret_id_num_uses: u64,
}

#[derive(Deserialize)]
struct DurationProperty {
    #[serde(
        alias = "secret_id_ttl",
        alias = "token_ttl",
        alias = "token_max_ttl",
        alias = "period",
        alias = "token_period",
        deserialize_with = "deserialize_string_or_u64"
    )]
    value: String,
}

#[derive(Serialize)]
struct SecretIdTtlPayload<'a> {
    secret_id_ttl: &'a str,
}

#[derive(Serialize)]
struct TokenTtlPayload<'a> {
    token_ttl: &'a str,
}

#[derive(Serialize)]
struct TokenMaxTtlPayload<'a> {
    token_max_ttl: &'a str,
}

#[derive(Serialize)]
struct TokenPeriodPayload<'a> {
    period: &'a str,
}

impl Client<Unauthenticated> {
    /// Uses the AppRole auth method mounted at `auth/approle`.
    pub fn approle(&self) -> Result<AppRole<'_>> {
        self.approle_at("approle")
    }

    /// Uses the AppRole auth method mounted at `auth/{mount}`.
    pub fn approle_at(&self, mount: impl Into<String>) -> Result<AppRole<'_>> {
        let mount = mount.into();
        let mount = validate_mount_path(&mount)?.join("/");
        Ok(AppRole {
            client: self,
            mount,
        })
    }

    /// Logs in with AppRole at `auth/approle` and returns an authenticated client.
    pub async fn login_approle(
        self,
        role_id: SecretString,
        secret_id: SecretString,
    ) -> Result<(Client<Authenticated>, LoginMetadata)> {
        let response = self
            .approle()?
            .login_response(&role_id, &secret_id)
            .await?
            .auth
            .ok_or(Error::MissingField("auth"))?;
        let (token, metadata) = split_login_auth(response);
        Ok((self.try_with_token(token)?, metadata))
    }
}

impl Client<Authenticated> {
    /// Administers the AppRole auth method mounted at `auth/approle`.
    pub fn approle_admin(&self) -> Result<AppRoleAdmin<'_>> {
        self.approle_admin_at("approle")
    }

    /// Administers the AppRole auth method mounted at `auth/{mount}`.
    pub fn approle_admin_at(&self, mount: impl Into<String>) -> Result<AppRoleAdmin<'_>> {
        Ok(AppRoleAdmin {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }
}

impl AppRole<'_> {
    /// Logs in and returns token metadata plus an authenticated client.
    pub async fn login(
        self,
        role_id: SecretString,
        secret_id: SecretString,
    ) -> Result<(Client<Authenticated>, LoginMetadata)> {
        let response = self
            .login_response(&role_id, &secret_id)
            .await?
            .auth
            .ok_or(Error::MissingField("auth"))?;
        let (token, metadata) = split_login_auth(response);
        Ok((
            self.client.clone_without_state().try_with_token(token)?,
            metadata,
        ))
    }

    async fn login_response(
        &self,
        role_id: &SecretString,
        secret_id: &SecretString,
    ) -> Result<LoginResponse> {
        let request = LoginRequest {
            role_id: role_id.expose_secret(),
            secret_id: secret_id.expose_secret(),
        };
        self.client
            .request_json_internal(
                reqwest::Method::POST,
                &format!("auth/{}/login", self.mount),
                Some(&request),
            )
            .await
    }
}

impl AppRoleAdmin<'_> {
    /// Lists AppRole role names.
    pub async fn list_roles(&self) -> Result<AppRoleRoleList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<AppRoleRoleList> = self
            .client
            .request_json_internal(
                method,
                &format!("auth/{}/role", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Creates or updates an AppRole role.
    pub async fn write_role(&self, name: &str, role: &AppRoleRoleRequest) -> Result<Empty> {
        role.validate()?;
        let name = validate_mount_path(name)?.join("/");
        self.client
            .request_json_internal(
                Method::POST,
                &format!("auth/{}/role/{name}", self.mount),
                Some(role),
            )
            .await
    }

    /// Reads an AppRole role.
    pub async fn read_role(&self, name: &str) -> Result<AppRoleRoleRequest> {
        let name = validate_mount_path(name)?.join("/");
        let envelope: ResponseEnvelope<AppRoleRoleRequest> = self
            .client
            .request_json_internal(
                Method::GET,
                &format!("auth/{}/role/{name}", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Reads generated-token policies for an AppRole role through the
    /// delegated `policies` endpoint.
    pub async fn read_token_policies(&self, role_name: &str) -> Result<Vec<String>> {
        Ok(self
            .read_role_property::<StringListProperty>(role_name, "policies")
            .await?
            .values)
    }

    /// Updates generated-token policies for an AppRole role through the
    /// delegated `policies` endpoint.
    pub async fn write_token_policies<I, P>(&self, role_name: &str, policies: I) -> Result<Empty>
    where
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        let policies = collect_string_list(policies, "approle token_policies")?;
        self.write_role_property(
            role_name,
            "policies",
            &PoliciesPayload {
                token_policies: &policies,
            },
        )
        .await
    }

    /// Resets generated-token policies for an AppRole role through the
    /// delegated `policies` endpoint.
    pub async fn delete_token_policies(&self, role_name: &str) -> Result<Empty> {
        self.delete_role_property(role_name, "policies").await
    }

    /// Reads the generated SecretID use-count limit for an AppRole role.
    pub async fn read_secret_id_num_uses(&self, role_name: &str) -> Result<u64> {
        Ok(self
            .read_role_property::<U64Property>(role_name, "secret-id-num-uses")
            .await?
            .value)
    }

    /// Updates the generated SecretID use-count limit for an AppRole role.
    pub async fn write_secret_id_num_uses(&self, role_name: &str, uses: u64) -> Result<Empty> {
        self.write_role_property(
            role_name,
            "secret-id-num-uses",
            &SecretIdNumUsesPayload {
                secret_id_num_uses: uses,
            },
        )
        .await
    }

    /// Resets the generated SecretID use-count limit for an AppRole role.
    pub async fn delete_secret_id_num_uses(&self, role_name: &str) -> Result<Empty> {
        self.delete_role_property(role_name, "secret-id-num-uses")
            .await
    }

    /// Reads the generated SecretID TTL for an AppRole role.
    pub async fn read_secret_id_ttl(&self, role_name: &str) -> Result<String> {
        Ok(self
            .read_role_property::<DurationProperty>(role_name, "secret-id-ttl")
            .await?
            .value)
    }

    /// Updates the generated SecretID TTL for an AppRole role.
    pub async fn write_secret_id_ttl(&self, role_name: &str, ttl: &str) -> Result<Empty> {
        crate::validation::validate_duration_parameter(ttl, "approle secret_id_ttl")?;
        self.write_role_property(
            role_name,
            "secret-id-ttl",
            &SecretIdTtlPayload { secret_id_ttl: ttl },
        )
        .await
    }

    /// Resets the generated SecretID TTL for an AppRole role.
    pub async fn delete_secret_id_ttl(&self, role_name: &str) -> Result<Empty> {
        self.delete_role_property(role_name, "secret-id-ttl").await
    }

    /// Reads the generated-token TTL for an AppRole role.
    pub async fn read_token_ttl(&self, role_name: &str) -> Result<String> {
        Ok(self
            .read_role_property::<DurationProperty>(role_name, "token-ttl")
            .await?
            .value)
    }

    /// Updates the generated-token TTL for an AppRole role.
    pub async fn write_token_ttl(&self, role_name: &str, ttl: &str) -> Result<Empty> {
        crate::validation::validate_duration_parameter(ttl, "approle token_ttl")?;
        self.write_role_property(role_name, "token-ttl", &TokenTtlPayload { token_ttl: ttl })
            .await
    }

    /// Resets the generated-token TTL for an AppRole role.
    pub async fn delete_token_ttl(&self, role_name: &str) -> Result<Empty> {
        self.delete_role_property(role_name, "token-ttl").await
    }

    /// Reads the generated-token max TTL for an AppRole role.
    pub async fn read_token_max_ttl(&self, role_name: &str) -> Result<String> {
        Ok(self
            .read_role_property::<DurationProperty>(role_name, "token-max-ttl")
            .await?
            .value)
    }

    /// Updates the generated-token max TTL for an AppRole role.
    pub async fn write_token_max_ttl(&self, role_name: &str, ttl: &str) -> Result<Empty> {
        crate::validation::validate_duration_parameter(ttl, "approle token_max_ttl")?;
        self.write_role_property(
            role_name,
            "token-max-ttl",
            &TokenMaxTtlPayload { token_max_ttl: ttl },
        )
        .await
    }

    /// Resets the generated-token max TTL for an AppRole role.
    pub async fn delete_token_max_ttl(&self, role_name: &str) -> Result<Empty> {
        self.delete_role_property(role_name, "token-max-ttl").await
    }

    /// Reads whether an AppRole role requires SecretIDs during login.
    pub async fn read_bind_secret_id(&self, role_name: &str) -> Result<bool> {
        Ok(self
            .read_role_property::<BindSecretIdProperty>(role_name, "bind-secret-id")
            .await?
            .bind_secret_id)
    }

    /// Updates whether an AppRole role requires SecretIDs during login.
    pub async fn write_bind_secret_id(&self, role_name: &str, bind: bool) -> Result<Empty> {
        self.write_role_property(
            role_name,
            "bind-secret-id",
            &BindSecretIdPayload {
                bind_secret_id: bind,
            },
        )
        .await
    }

    /// Resets whether an AppRole role requires SecretIDs during login.
    pub async fn delete_bind_secret_id(&self, role_name: &str) -> Result<Empty> {
        self.delete_role_property(role_name, "bind-secret-id").await
    }

    /// Reads CIDRs allowed to use generated SecretIDs for an AppRole role.
    pub async fn read_secret_id_bound_cidrs(&self, role_name: &str) -> Result<Vec<String>> {
        Ok(self
            .read_role_property::<StringListProperty>(role_name, "secret-id-bound-cidrs")
            .await?
            .values)
    }

    /// Updates CIDRs allowed to use generated SecretIDs for an AppRole role.
    pub async fn write_secret_id_bound_cidrs<I, P>(
        &self,
        role_name: &str,
        cidrs: I,
    ) -> Result<Empty>
    where
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        let cidrs = collect_string_list(cidrs, "approle secret_id_bound_cidrs")?;
        crate::validation::validate_cidr_list(&cidrs, "approle secret_id_bound_cidrs")?;
        self.write_role_property(
            role_name,
            "secret-id-bound-cidrs",
            &SecretIdBoundCidrsPayload {
                secret_id_bound_cidrs: &cidrs,
            },
        )
        .await
    }

    /// Resets CIDRs allowed to use generated SecretIDs for an AppRole role.
    pub async fn delete_secret_id_bound_cidrs(&self, role_name: &str) -> Result<Empty> {
        self.delete_role_property(role_name, "secret-id-bound-cidrs")
            .await
    }

    /// Reads CIDRs allowed to use generated tokens for an AppRole role.
    pub async fn read_token_bound_cidrs(&self, role_name: &str) -> Result<Vec<String>> {
        Ok(self
            .read_role_property::<StringListProperty>(role_name, "token-bound-cidrs")
            .await?
            .values)
    }

    /// Updates CIDRs allowed to use generated tokens for an AppRole role.
    pub async fn write_token_bound_cidrs<I, P>(&self, role_name: &str, cidrs: I) -> Result<Empty>
    where
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        let cidrs = collect_string_list(cidrs, "approle token_bound_cidrs")?;
        crate::validation::validate_cidr_list(&cidrs, "approle token_bound_cidrs")?;
        self.write_role_property(
            role_name,
            "token-bound-cidrs",
            &TokenBoundCidrsPayload {
                token_bound_cidrs: &cidrs,
            },
        )
        .await
    }

    /// Resets CIDRs allowed to use generated tokens for an AppRole role.
    pub async fn delete_token_bound_cidrs(&self, role_name: &str) -> Result<Empty> {
        self.delete_role_property(role_name, "token-bound-cidrs")
            .await
    }

    /// Reads the generated periodic-token period for an AppRole role.
    pub async fn read_token_period(&self, role_name: &str) -> Result<String> {
        Ok(self
            .read_role_property::<DurationProperty>(role_name, "period")
            .await?
            .value)
    }

    /// Updates the generated periodic-token period for an AppRole role.
    pub async fn write_token_period(&self, role_name: &str, period: &str) -> Result<Empty> {
        crate::validation::validate_duration_parameter(period, "approle token_period")?;
        self.write_role_property(role_name, "period", &TokenPeriodPayload { period })
            .await
    }

    /// Resets the generated periodic-token period for an AppRole role.
    pub async fn delete_token_period(&self, role_name: &str) -> Result<Empty> {
        self.delete_role_property(role_name, "period").await
    }

    /// Deletes an AppRole role.
    pub async fn delete_role(&self, name: &str) -> Result<Empty> {
        let name = validate_mount_path(name)?.join("/");
        self.client
            .request_json_accepting(
                Method::DELETE,
                &format!("auth/{}/role/{name}", self.mount),
                Option::<&Empty>::None,
                &[reqwest::StatusCode::OK, reqwest::StatusCode::NO_CONTENT],
            )
            .await
    }

    async fn read_role_property<T>(&self, role_name: &str, segment: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let path = self.role_property_path(role_name, segment)?;
        let envelope: ResponseEnvelope<T> = self
            .client
            .request_json_internal(Method::GET, &path, Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    async fn write_role_property<P>(
        &self,
        role_name: &str,
        segment: &str,
        payload: &P,
    ) -> Result<Empty>
    where
        P: Serialize,
    {
        let path = self.role_property_path(role_name, segment)?;
        self.client
            .request_json_internal(Method::POST, &path, Some(payload))
            .await
    }

    async fn delete_role_property(&self, role_name: &str, segment: &str) -> Result<Empty> {
        let path = self.role_property_path(role_name, segment)?;
        self.client
            .request_json_accepting(
                Method::DELETE,
                &path,
                Option::<&Empty>::None,
                &[reqwest::StatusCode::OK, reqwest::StatusCode::NO_CONTENT],
            )
            .await
    }

    fn role_property_path(&self, role_name: &str, segment: &str) -> Result<String> {
        let role_name = validate_mount_path(role_name)?.join("/");
        Ok(format!("auth/{}/role/{role_name}/{segment}", self.mount))
    }

    /// Reads the RoleID for an AppRole role.
    pub async fn read_role_id(&self, name: &str) -> Result<AppRoleRoleId> {
        let name = validate_mount_path(name)?.join("/");
        let envelope: ResponseEnvelope<AppRoleRoleId> = self
            .client
            .request_json_internal(
                Method::GET,
                &format!("auth/{}/role/{name}/role-id", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Updates the RoleID for an AppRole role.
    pub async fn write_role_id(&self, name: &str, role_id: &SecretString) -> Result<AppRoleRoleId> {
        let name = validate_mount_path(name)?.join("/");
        let request = RoleIdRequest {
            role_id: role_id.expose_secret(),
        };
        let envelope: ResponseEnvelope<AppRoleRoleId> = self
            .client
            .request_json_internal(
                Method::POST,
                &format!("auth/{}/role/{name}/role-id", self.mount),
                Some(&request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Generates a new SecretID for an AppRole role.
    pub async fn generate_secret_id(
        &self,
        role_name: &str,
        request: &AppRoleSecretIdRequest,
    ) -> Result<AppRoleSecretId> {
        request.validate()?;
        let role_name = validate_mount_path(role_name)?.join("/");
        let envelope: ResponseEnvelope<AppRoleSecretId> = self
            .client
            .request_json_internal(
                Method::POST,
                &format!("auth/{}/role/{role_name}/secret-id", self.mount),
                Some(request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists SecretID accessors for an AppRole role.
    pub async fn list_secret_id_accessors(
        &self,
        role_name: &str,
    ) -> Result<AppRoleSecretIdAccessorList> {
        let role_name = validate_mount_path(role_name)?.join("/");
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<AppRoleSecretIdAccessorList> = self
            .client
            .request_json_internal(
                method,
                &format!("auth/{}/role/{role_name}/secret-id", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Looks up SecretID metadata using the SecretID value.
    pub async fn lookup_secret_id(
        &self,
        role_name: &str,
        secret_id: &SecretString,
    ) -> Result<AppRoleSecretIdInfo> {
        let role_name = validate_mount_path(role_name)?.join("/");
        let request = SecretIdLookupRequest {
            secret_id: secret_id.expose_secret(),
        };
        let envelope: ResponseEnvelope<AppRoleSecretIdInfo> = self
            .client
            .request_json_internal(
                Method::POST,
                &format!("auth/{}/role/{role_name}/secret-id/lookup", self.mount),
                Some(&request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Destroys a SecretID using the SecretID value.
    pub async fn destroy_secret_id(
        &self,
        role_name: &str,
        secret_id: &SecretString,
    ) -> Result<Empty> {
        let role_name = validate_mount_path(role_name)?.join("/");
        let request = SecretIdLookupRequest {
            secret_id: secret_id.expose_secret(),
        };
        self.client
            .request_json_internal(
                Method::POST,
                &format!("auth/{}/role/{role_name}/secret-id/destroy", self.mount),
                Some(&request),
            )
            .await
    }

    /// Looks up SecretID metadata using the SecretID accessor.
    pub async fn lookup_secret_id_accessor(
        &self,
        role_name: &str,
        accessor: &SecretString,
    ) -> Result<AppRoleSecretIdInfo> {
        let role_name = validate_mount_path(role_name)?.join("/");
        let request = SecretIdAccessorLookupRequest {
            secret_id_accessor: accessor.expose_secret(),
        };
        let envelope: ResponseEnvelope<AppRoleSecretIdInfo> = self
            .client
            .request_json_internal(
                Method::POST,
                &format!(
                    "auth/{}/role/{role_name}/secret-id-accessor/lookup",
                    self.mount
                ),
                Some(&request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Destroys a SecretID using the SecretID accessor.
    pub async fn destroy_secret_id_accessor(
        &self,
        role_name: &str,
        accessor: &SecretString,
    ) -> Result<Empty> {
        let role_name = validate_mount_path(role_name)?.join("/");
        let request = SecretIdAccessorLookupRequest {
            secret_id_accessor: accessor.expose_secret(),
        };
        self.client
            .request_json_internal(
                Method::POST,
                &format!(
                    "auth/{}/role/{role_name}/secret-id-accessor/destroy",
                    self.mount
                ),
                Some(&request),
            )
            .await
    }

    /// Assigns a custom SecretID to an AppRole role.
    pub async fn create_custom_secret_id(
        &self,
        role_name: &str,
        request: &AppRoleCustomSecretIdRequest,
    ) -> Result<AppRoleSecretId> {
        request.validate()?;
        let role_name = validate_mount_path(role_name)?.join("/");
        let payload = AppRoleCustomSecretIdPayload {
            secret_id: request.secret_id.expose_secret(),
            metadata: request.metadata.as_deref(),
            cidr_list: request.cidr_list.iter().map(String::as_str).collect(),
            token_bound_cidrs: request
                .token_bound_cidrs
                .iter()
                .map(String::as_str)
                .collect(),
            num_uses: request.num_uses,
            ttl: request.ttl.as_deref(),
        };
        let envelope: ResponseEnvelope<AppRoleSecretId> = self
            .client
            .request_json_internal(
                Method::POST,
                &format!("auth/{}/role/{role_name}/custom-secret-id", self.mount),
                Some(&payload),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Starts AppRole SecretID tidy maintenance.
    pub async fn tidy_secret_ids(&self) -> Result<Empty> {
        self.client
            .request_json_internal(
                Method::POST,
                &format!("auth/{}/tidy/secret-id", self.mount),
                Option::<&Empty>::None,
            )
            .await
    }
}

fn split_login_auth(auth: LoginAuth) -> (SecretString, LoginMetadata) {
    let LoginAuth {
        client_token,
        accessor,
        policies,
        lease_duration,
        renewable,
    } = auth;
    let metadata = LoginMetadata {
        accessor,
        policies,
        lease_duration,
        renewable,
    };
    (client_token, metadata)
}

fn deserialize_secret<'de, D>(deserializer: D) -> core::result::Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    Ok(SecretString::from(value))
}

fn collect_string_list<I, P>(values: I, field: &'static str) -> Result<Vec<String>>
where
    I: IntoIterator<Item = P>,
    P: Into<String>,
{
    let values = values.into_iter().map(Into::into).collect::<Vec<_>>();
    validate_string_list_len(&values, field)?;
    Ok(values)
}

fn validate_string_list_len(values: &[String], field: &'static str) -> Result<()> {
    if values.len() > crate::response::MAX_RESPONSE_STRINGS {
        return Err(Error::InvalidParameter(format!(
            "{field} exceeds item limit"
        )));
    }
    Ok(())
}

fn deserialize_string_or_u64<'de, D>(deserializer: D) -> core::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Value {
        String(String),
        U64(u64),
    }

    Ok(match Value::deserialize(deserializer)? {
        Value::String(value) => value,
        Value::U64(value) => value.to_string(),
    })
}

fn deserialize_optional_string_or_u64<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Value {
        String(String),
        U64(u64),
    }

    Ok(
        Option::<Value>::deserialize(deserializer)?.map(|value| match value {
            Value::String(value) => value,
            Value::U64(value) => value.to_string(),
        }),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::{ExposeSecret, SecretString};

    use super::{
        AppRoleCustomSecretIdRequest, AppRoleRoleRequest, AppRoleSecretIdRequest, LoginResponse,
        StringListProperty, collect_string_list,
    };

    #[test]
    fn login_auth_deserializes_secrets_into_secret_strings() {
        let response: LoginResponse = serde_json::from_str(
            r#"{"auth":{"client_token":"token-value","accessor":"accessor-value"}}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let auth = response.auth.unwrap_or_else(|| panic!("auth missing"));

        assert_eq!(auth.client_token.expose_secret(), "token-value");
        assert_eq!(auth.accessor.expose_secret(), "accessor-value");
    }

    #[test]
    fn approle_policies_are_bounded() {
        let mut policies = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            policies.push(format!("policy-{index}"));
        }
        let value = serde_json::json!({ "auth": { "client_token": "token", "accessor": "accessor", "policies": policies } });
        let error = match serde_json::from_value::<LoginResponse>(value) {
            Ok(_) => panic!("oversized AppRole policy list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn approle_property_policies_are_bounded() {
        let mut policies = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            policies.push(format!("policy-{index}"));
        }
        let value = serde_json::json!({ "policies": policies });
        let error = match serde_json::from_value::<StringListProperty>(value) {
            Ok(_) => panic!("oversized AppRole property policy list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));

        let values =
            (0..=crate::response::MAX_RESPONSE_STRINGS).map(|index| format!("policy-{index}"));
        let error = match collect_string_list(values, "approle token_policies") {
            Ok(_) => panic!("oversized AppRole property policy list unexpectedly accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn approle_requests_validate_cidrs_and_metadata() {
        let role = AppRoleRoleRequest {
            token_bound_cidrs: vec!["192.0.2.0/33".to_owned()],
            ..AppRoleRoleRequest::new()
        };
        assert!(role.validate().is_err());

        let request = AppRoleSecretIdRequest::new()
            .with_metadata(r#"{"service":"api"}"#)
            .unwrap_or_else(|error| panic!("{error}"))
            .with_cidr("192.0.2.0/24")
            .unwrap_or_else(|error| panic!("{error}"))
            .with_token_bound_cidr("2001:db8::/32")
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(request.validate().is_ok());
        assert!(
            AppRoleSecretIdRequest::new()
                .with_metadata("[\"not-object\"]")
                .is_err()
        );

        let custom = AppRoleCustomSecretIdRequest::new(SecretString::from("secret-id"))
            .with_cidr("bad-cidr")
            .err()
            .unwrap_or_else(|| panic!("invalid custom SecretID CIDR was accepted"));
        assert!(custom.to_string().contains("cidr"));
    }
}
