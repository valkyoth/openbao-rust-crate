//! Identity secrets engine support.
//!
//! The identity engine manages OpenBao entities, groups, and aliases. These
//! helpers cover the core lifecycle endpoints and keep returned lists and
//! metadata maps bounded before allocation can grow without limit.

use std::collections::BTreeMap;
use std::fmt;

use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{
    Authenticated, Client, Error, Result,
    path::{validate_endpoint_path, validate_mount_path},
    response::{
        Empty, ListEntries, ResponseEnvelope, deserialize_bounded_string_map_or_default,
        deserialize_bounded_string_vec, deserialize_optional_bounded_string_vec,
    },
    validation::validate_duration_parameter,
};

const IDENTITY_LIST_LIMIT: usize = crate::response::MAX_RESPONSE_STRINGS;

/// Handle for the identity secrets engine.
#[derive(Debug)]
pub struct Identity<'a> {
    client: &'a Client<Authenticated>,
    mount: Vec<String>,
}

/// Entity create/update request.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IdentityEntityRequest {
    /// Entity name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Entity metadata.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
    /// Entity policies.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    /// Whether the entity is disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,
}

impl IdentityEntityRequest {
    /// Creates an entity request with a name.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::default()
        }
    }

    /// Adds a policy.
    #[must_use]
    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.policies.push(policy.into());
        self
    }

    /// Adds a metadata key/value pair.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    fn validate(&self) -> Result<()> {
        validate_string_count(self.policies.len(), "identity entity policies")?;
        validate_string_count(self.metadata.len(), "identity entity metadata")?;
        Ok(())
    }
}

/// Entity information returned by OpenBao.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityEntityInfo {
    /// Entity ID.
    #[serde(default)]
    pub id: String,
    /// Entity name.
    #[serde(default)]
    pub name: Option<String>,
    /// Entity metadata.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    pub metadata: BTreeMap<String, String>,
    /// Entity policies.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub policies: Vec<String>,
    /// Direct group IDs that contain this entity.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub direct_group_ids: Vec<String>,
    /// Inherited group IDs for this entity.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub inherited_group_ids: Vec<String>,
    /// Whether the entity is disabled.
    #[serde(default)]
    pub disabled: bool,
}

/// Entity create/update response.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityEntityUpsert {
    /// Entity ID.
    #[serde(default)]
    pub id: String,
    /// Entity name, when returned.
    #[serde(default)]
    pub name: Option<String>,
}

/// Entity list response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IdentityEntityList {
    /// Entity IDs or names returned by OpenBao.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for IdentityEntityList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Request to delete multiple entities by ID.
#[derive(Clone, Debug, Default, Serialize)]
pub struct IdentityEntityBatchDeleteRequest {
    /// Entity IDs to delete.
    pub entity_ids: Vec<String>,
}

impl IdentityEntityBatchDeleteRequest {
    /// Creates a batch delete request.
    pub fn new(entity_ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            entity_ids: entity_ids.into_iter().map(Into::into).collect(),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.entity_ids.is_empty() {
            return Err(Error::InvalidParameter(
                "identity entity batch delete requires at least one entity ID".into(),
            ));
        }
        validate_string_count(self.entity_ids.len(), "identity entity IDs")?;
        Ok(())
    }
}

/// Entity lookup request.
#[derive(Clone, Debug, Default, Serialize)]
pub struct IdentityEntityLookupRequest {
    /// Entity ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Entity name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Alias ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias_id: Option<String>,
    /// Alias name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias_name: Option<String>,
    /// Alias mount accessor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias_mount_accessor: Option<String>,
}

impl IdentityEntityLookupRequest {
    /// Looks up an entity by ID.
    pub fn by_id(id: impl Into<String>) -> Self {
        Self {
            id: Some(id.into()),
            ..Self::default()
        }
    }

    /// Looks up an entity by name.
    pub fn by_name(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::default()
        }
    }

    /// Looks up an entity by alias name and mount accessor.
    pub fn by_alias(
        alias_name: impl Into<String>,
        alias_mount_accessor: impl Into<String>,
    ) -> Self {
        Self {
            alias_name: Some(alias_name.into()),
            alias_mount_accessor: Some(alias_mount_accessor.into()),
            ..Self::default()
        }
    }

    fn validate(&self) -> Result<()> {
        let identifiers = [
            self.id.as_ref(),
            self.name.as_ref(),
            self.alias_id.as_ref(),
            self.alias_name.as_ref(),
        ]
        .into_iter()
        .flatten()
        .count();
        if identifiers == 0 {
            return Err(Error::InvalidParameter(
                "identity entity lookup requires an id, name, alias_id, or alias_name".into(),
            ));
        }
        if [
            self.id.as_ref(),
            self.name.as_ref(),
            self.alias_id.as_ref(),
            self.alias_name.as_ref(),
            self.alias_mount_accessor.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| value.trim().is_empty())
        {
            return Err(Error::InvalidParameter(
                "identity entity lookup fields must not be empty".into(),
            ));
        }
        if self.alias_name.is_some() && self.alias_mount_accessor.is_none() {
            return Err(Error::InvalidParameter(
                "identity alias lookup requires alias_mount_accessor".into(),
            ));
        }
        Ok(())
    }
}

/// Entity merge request.
#[derive(Clone, Debug, Default, Serialize)]
pub struct IdentityEntityMergeRequest {
    /// Entity ID that remains after merge.
    pub to_entity_id: String,
    /// Entity IDs merged into `to_entity_id`.
    pub from_entity_ids: Vec<String>,
    /// Whether conflicting aliases are forced into the target entity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force: Option<bool>,
}

impl IdentityEntityMergeRequest {
    /// Creates an entity merge request.
    pub fn new(
        to_entity_id: impl Into<String>,
        from_entity_ids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            to_entity_id: to_entity_id.into(),
            from_entity_ids: from_entity_ids.into_iter().map(Into::into).collect(),
            force: None,
        }
    }

    /// Forces the merge when OpenBao allows it.
    #[must_use]
    pub fn force(mut self) -> Self {
        self.force = Some(true);
        self
    }

    fn validate(&self) -> Result<()> {
        if self.to_entity_id.trim().is_empty() {
            return Err(Error::InvalidParameter(
                "identity merge target entity ID must not be empty".into(),
            ));
        }
        if self.from_entity_ids.is_empty() {
            return Err(Error::InvalidParameter(
                "identity merge requires at least one source entity ID".into(),
            ));
        }
        validate_string_count(
            self.from_entity_ids.len(),
            "identity merge source entity IDs",
        )
    }
}

/// Identity group type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityGroupType {
    /// Internal group.
    Internal,
    /// External group.
    External,
}

impl IdentityGroupType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::External => "external",
        }
    }
}

impl Serialize for IdentityGroupType {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for IdentityGroupType {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "internal" => Ok(Self::Internal),
            "external" => Ok(Self::External),
            _ => Err(serde::de::Error::custom("unsupported identity group type")),
        }
    }
}

/// Group create/update request.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IdentityGroupRequest {
    /// Group name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Group type.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub group_type: Option<IdentityGroupType>,
    /// Group policies.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    /// Member entity IDs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub member_entity_ids: Vec<String>,
    /// Member group IDs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub member_group_ids: Vec<String>,
    /// Group metadata.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl IdentityGroupRequest {
    /// Creates a named internal group request.
    pub fn internal(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            group_type: Some(IdentityGroupType::Internal),
            ..Self::default()
        }
    }

    /// Creates a named external group request.
    pub fn external(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            group_type: Some(IdentityGroupType::External),
            ..Self::default()
        }
    }

    /// Adds a policy.
    #[must_use]
    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.policies.push(policy.into());
        self
    }

    /// Adds a member entity ID.
    #[must_use]
    pub fn with_member_entity_id(mut self, entity_id: impl Into<String>) -> Self {
        self.member_entity_ids.push(entity_id.into());
        self
    }

    /// Adds a metadata key/value pair.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    fn validate(&self) -> Result<()> {
        validate_string_count(self.policies.len(), "identity group policies")?;
        validate_string_count(
            self.member_entity_ids.len(),
            "identity group member entity IDs",
        )?;
        validate_string_count(
            self.member_group_ids.len(),
            "identity group member group IDs",
        )?;
        validate_string_count(self.metadata.len(), "identity group metadata")?;
        Ok(())
    }
}

/// Group information returned by OpenBao.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityGroupInfo {
    /// Group ID.
    #[serde(default)]
    pub id: String,
    /// Group name.
    #[serde(default)]
    pub name: Option<String>,
    /// Group type.
    #[serde(default, rename = "type")]
    pub group_type: Option<IdentityGroupType>,
    /// Group policies.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub policies: Vec<String>,
    /// Member entity IDs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub member_entity_ids: Vec<String>,
    /// Member group IDs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub member_group_ids: Vec<String>,
    /// Parent group IDs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub parent_group_ids: Vec<String>,
    /// Group metadata.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    pub metadata: BTreeMap<String, String>,
}

/// Group create/update response.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityGroupUpsert {
    /// Group ID.
    #[serde(default)]
    pub id: String,
    /// Group name, when returned.
    #[serde(default)]
    pub name: Option<String>,
}

/// Group list response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IdentityGroupList {
    /// Group IDs or names returned by OpenBao.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

/// Group lookup request.
#[derive(Clone, Debug, Default, Serialize)]
pub struct IdentityGroupLookupRequest {
    /// Group ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Group name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Alias ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias_id: Option<String>,
    /// Alias name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias_name: Option<String>,
    /// Alias mount accessor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias_mount_accessor: Option<String>,
}

impl IdentityGroupLookupRequest {
    /// Looks up a group by ID.
    pub fn by_id(id: impl Into<String>) -> Self {
        Self {
            id: Some(id.into()),
            ..Self::default()
        }
    }

    /// Looks up a group by name.
    pub fn by_name(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::default()
        }
    }

    /// Looks up a group by alias name and mount accessor.
    pub fn by_alias(
        alias_name: impl Into<String>,
        alias_mount_accessor: impl Into<String>,
    ) -> Self {
        Self {
            alias_name: Some(alias_name.into()),
            alias_mount_accessor: Some(alias_mount_accessor.into()),
            ..Self::default()
        }
    }

    fn validate(&self) -> Result<()> {
        let identifiers = [
            self.id.as_ref(),
            self.name.as_ref(),
            self.alias_id.as_ref(),
            self.alias_name.as_ref(),
        ]
        .into_iter()
        .flatten()
        .count();
        if identifiers == 0 {
            return Err(Error::InvalidParameter(
                "identity group lookup requires an id, name, alias_id, or alias_name".into(),
            ));
        }
        if [
            self.id.as_ref(),
            self.name.as_ref(),
            self.alias_id.as_ref(),
            self.alias_name.as_ref(),
            self.alias_mount_accessor.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| value.trim().is_empty())
        {
            return Err(Error::InvalidParameter(
                "identity group lookup fields must not be empty".into(),
            ));
        }
        if self.alias_name.is_some() && self.alias_mount_accessor.is_none() {
            return Err(Error::InvalidParameter(
                "identity group alias lookup requires alias_mount_accessor".into(),
            ));
        }
        Ok(())
    }
}

impl ListEntries for IdentityGroupList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Entity alias create/update request.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IdentityEntityAliasRequest {
    /// Alias name.
    pub name: String,
    /// Canonical entity ID.
    pub canonical_id: String,
    /// Auth mount accessor.
    pub mount_accessor: String,
    /// Alias ID when updating an existing alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Alias custom metadata.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub custom_metadata: BTreeMap<String, String>,
}

impl IdentityEntityAliasRequest {
    /// Creates an entity alias request.
    pub fn new(
        name: impl Into<String>,
        canonical_id: impl Into<String>,
        mount_accessor: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            canonical_id: canonical_id.into(),
            mount_accessor: mount_accessor.into(),
            id: None,
            custom_metadata: BTreeMap::new(),
        }
    }

    /// Sets the alias ID for updates.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Adds alias custom metadata.
    #[must_use]
    pub fn with_custom_metadata(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.custom_metadata.insert(key.into(), value.into());
        self
    }

    fn validate(&self) -> Result<()> {
        validate_string_count(self.custom_metadata.len(), "identity entity alias metadata")?;
        Ok(())
    }
}

/// Group alias create/update request.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IdentityGroupAliasRequest {
    /// Alias name.
    pub name: String,
    /// Canonical group ID.
    pub canonical_id: String,
    /// Auth mount accessor.
    pub mount_accessor: String,
    /// Alias ID when updating an existing alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl IdentityGroupAliasRequest {
    /// Creates a group alias request.
    pub fn new(
        name: impl Into<String>,
        canonical_id: impl Into<String>,
        mount_accessor: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            canonical_id: canonical_id.into(),
            mount_accessor: mount_accessor.into(),
            id: None,
        }
    }

    /// Sets the alias ID for updates.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }
}

/// Alias information returned by OpenBao.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityAliasInfo {
    /// Alias ID.
    #[serde(default)]
    pub id: String,
    /// Alias name.
    #[serde(default)]
    pub name: Option<String>,
    /// Canonical entity or group ID.
    #[serde(default)]
    pub canonical_id: Option<String>,
    /// Auth mount accessor.
    #[serde(default)]
    pub mount_accessor: Option<String>,
    /// Auth mount path.
    #[serde(default)]
    pub mount_path: Option<String>,
    /// Auth mount type.
    #[serde(default)]
    pub mount_type: Option<String>,
    /// Entity alias custom metadata.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    pub custom_metadata: BTreeMap<String, String>,
}

/// Alias create/update response.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityAliasUpsert {
    /// Alias ID.
    #[serde(default)]
    pub id: String,
}

/// Alias list response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IdentityAliasList {
    /// Alias IDs returned by OpenBao.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for IdentityAliasList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Identity OIDC token backend configuration request.
#[derive(Clone, Debug, Default, Serialize)]
pub struct IdentityOidcConfigRequest {
    /// Issuer URL used in the `iss` claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

impl IdentityOidcConfigRequest {
    /// Creates an OIDC config request.
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: Some(issuer.into()),
        }
    }
}

/// Identity OIDC token backend configuration.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityOidcConfig {
    /// Issuer URL used in the `iss` claim.
    #[serde(default)]
    pub issuer: Option<String>,
}

/// Request to create or update an Identity OIDC signing key.
#[derive(Clone, Debug, Default, Serialize)]
pub struct IdentityOidcKeyRequest {
    /// Signing-key rotation period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_period: Option<String>,
    /// Public verification key lifetime after rotation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_ttl: Option<String>,
    /// Role client IDs allowed to use this key. Use `"*"` to allow all clients.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_client_ids: Vec<String>,
    /// Signing algorithm, such as `RS256`, `ES256`, or `EdDSA`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
}

impl IdentityOidcKeyRequest {
    /// Creates an empty OIDC signing-key request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the signing-key rotation period.
    #[must_use]
    pub fn with_rotation_period(mut self, rotation_period: impl Into<String>) -> Self {
        self.rotation_period = Some(rotation_period.into());
        self
    }

    /// Sets the public verification key lifetime after rotation.
    #[must_use]
    pub fn with_verification_ttl(mut self, verification_ttl: impl Into<String>) -> Self {
        self.verification_ttl = Some(verification_ttl.into());
        self
    }

    /// Adds an allowed client ID.
    #[must_use]
    pub fn with_allowed_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.allowed_client_ids.push(client_id.into());
        self
    }

    /// Sets the signing algorithm.
    #[must_use]
    pub fn with_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.algorithm = Some(algorithm.into());
        self
    }

    fn validate(&self) -> Result<()> {
        if let Some(rotation_period) = &self.rotation_period {
            validate_duration_parameter(rotation_period, "identity OIDC key rotation_period")?;
        }
        if let Some(verification_ttl) = &self.verification_ttl {
            validate_duration_parameter(verification_ttl, "identity OIDC key verification_ttl")?;
        }
        validate_string_count(
            self.allowed_client_ids.len(),
            "identity OIDC allowed client IDs",
        )
    }
}

/// Identity OIDC signing-key rotation request.
#[derive(Clone, Debug, Default, Serialize)]
pub struct IdentityOidcKeyRotateRequest {
    /// Optional verification lifetime override for the rotated key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_ttl: Option<String>,
}

impl IdentityOidcKeyRotateRequest {
    /// Creates a key-rotation request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the verification TTL override for this rotation.
    #[must_use]
    pub fn with_verification_ttl(mut self, verification_ttl: impl Into<String>) -> Self {
        self.verification_ttl = Some(verification_ttl.into());
        self
    }

    fn validate(&self) -> Result<()> {
        if let Some(verification_ttl) = &self.verification_ttl {
            validate_duration_parameter(
                verification_ttl,
                "identity OIDC key rotation verification_ttl",
            )?;
        }
        Ok(())
    }
}

/// Identity OIDC signing-key information.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityOidcKeyInfo {
    /// Signing algorithm.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Signing-key rotation period in seconds.
    #[serde(default)]
    pub rotation_period: Option<u64>,
    /// Public verification key lifetime in seconds.
    #[serde(default)]
    pub verification_ttl: Option<u64>,
    /// Role client IDs allowed to use this key.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub allowed_client_ids: Vec<String>,
}

/// Identity OIDC signing-key list response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IdentityOidcKeyList {
    /// OIDC signing-key names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for IdentityOidcKeyList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Request to create or update an Identity OIDC role.
#[derive(Clone, Debug, Default, Serialize)]
pub struct IdentityOidcRoleRequest {
    /// Configured named key used to sign generated ID tokens.
    pub key: String,
    /// Optional token template string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// Optional client ID. OpenBao generates one when omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Token TTL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
}

impl IdentityOidcRoleRequest {
    /// Creates an OIDC role request for the given signing key.
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            ..Self::default()
        }
    }

    /// Sets the token template.
    #[must_use]
    pub fn with_template(mut self, template: impl Into<String>) -> Self {
        self.template = Some(template.into());
        self
    }

    /// Sets the client ID.
    #[must_use]
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Sets the token TTL.
    #[must_use]
    pub fn with_ttl(mut self, ttl: impl Into<String>) -> Self {
        self.ttl = Some(ttl.into());
        self
    }

    fn validate(&self) -> Result<()> {
        if self.key.trim().is_empty() {
            return Err(Error::InvalidParameter(
                "identity OIDC role key must not be empty".into(),
            ));
        }
        if let Some(ttl) = &self.ttl {
            validate_duration_parameter(ttl, "identity OIDC role ttl")?;
        }
        Ok(())
    }
}

/// Identity OIDC role information.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityOidcRoleInfo {
    /// Client ID.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Signing key name.
    #[serde(default)]
    pub key: Option<String>,
    /// Token template.
    #[serde(default)]
    pub template: Option<String>,
    /// Token TTL in seconds.
    #[serde(default)]
    pub ttl: Option<u64>,
}

/// Identity OIDC role list response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IdentityOidcRoleList {
    /// OIDC role names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for IdentityOidcRoleList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Signed Identity OIDC token generated by OpenBao.
#[derive(Clone, Deserialize)]
pub struct IdentityOidcToken {
    /// Client ID associated with the generated token.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Signed OIDC ID token.
    pub token: SecretString,
    /// Token TTL in seconds.
    #[serde(default)]
    pub ttl: Option<u64>,
}

impl fmt::Debug for IdentityOidcToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityOidcToken")
            .field("client_id", &self.client_id)
            .field("token", &"<redacted>")
            .field("ttl", &self.ttl)
            .finish()
    }
}

/// Request to introspect a signed Identity OIDC token.
#[derive(Clone)]
pub struct IdentityOidcIntrospectRequest {
    /// Signed OIDC token to verify.
    pub token: SecretString,
    /// Optional audience/client ID requirement.
    pub client_id: Option<String>,
}

impl IdentityOidcIntrospectRequest {
    /// Creates an introspection request.
    pub fn new(token: SecretString) -> Self {
        Self {
            token,
            client_id: None,
        }
    }

    /// Requires the token audience to match `client_id`.
    #[must_use]
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }
}

impl fmt::Debug for IdentityOidcIntrospectRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityOidcIntrospectRequest")
            .field("token", &"<redacted>")
            .field("client_id", &self.client_id)
            .finish()
    }
}

/// Identity OIDC introspection response.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityOidcIntrospection {
    /// Whether OpenBao considers the token active.
    #[serde(default)]
    pub active: bool,
    /// Additional RFC 7662/OpenBao claims returned by the endpoint.
    #[serde(flatten)]
    pub extra: BTreeMap<String, JsonValue>,
}

/// OIDC discovery metadata returned by OpenBao.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityOidcDiscovery {
    /// Issuer URL.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Authorization endpoint.
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    /// Token endpoint.
    #[serde(default)]
    pub token_endpoint: Option<String>,
    /// JWKS URI.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Supported response types.
    #[serde(default, deserialize_with = "deserialize_optional_bounded_string_vec")]
    pub response_types_supported: Option<Vec<String>>,
    /// Supported subject types.
    #[serde(default, deserialize_with = "deserialize_optional_bounded_string_vec")]
    pub subject_types_supported: Option<Vec<String>>,
    /// Supported ID-token signing algorithms.
    #[serde(default, deserialize_with = "deserialize_optional_bounded_string_vec")]
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    /// Supported scopes.
    #[serde(default, deserialize_with = "deserialize_optional_bounded_string_vec")]
    pub scopes_supported: Option<Vec<String>>,
    /// Supported token endpoint authentication methods.
    #[serde(default, deserialize_with = "deserialize_optional_bounded_string_vec")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// Supported claims.
    #[serde(default, deserialize_with = "deserialize_optional_bounded_string_vec")]
    pub claims_supported: Option<Vec<String>>,
    /// Additional provider metadata claims.
    #[serde(flatten)]
    pub extra: BTreeMap<String, JsonValue>,
}

/// OIDC JSON Web Key Set returned by OpenBao.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityOidcJwks {
    /// Public JWK entries.
    #[serde(default, deserialize_with = "deserialize_bounded_json_vec")]
    pub keys: Vec<JsonValue>,
}

impl Client<Authenticated> {
    /// Uses the identity engine mounted at `identity`.
    pub fn identity(&self) -> Result<Identity<'_>> {
        self.identity_at("identity")
    }

    /// Uses the identity engine mounted at `mount`.
    pub fn identity_at(&self, mount: impl Into<String>) -> Result<Identity<'_>> {
        let mount = mount.into();
        Ok(Identity {
            client: self,
            mount: validate_mount_path(&mount)?,
        })
    }
}

impl Identity<'_> {
    /// Creates or updates an entity.
    pub async fn write_entity(
        &self,
        request: &IdentityEntityRequest,
    ) -> Result<IdentityEntityUpsert> {
        request.validate()?;
        let envelope: ResponseEnvelope<IdentityEntityUpsert> = self
            .client
            .request_json(Method::POST, &self.path(&["entity"])?, Some(request))
            .await?;
        Ok(envelope.data)
    }

    /// Reads an entity by ID.
    pub async fn read_entity_by_id(&self, id: &str) -> Result<IdentityEntityInfo> {
        let envelope: ResponseEnvelope<IdentityEntityInfo> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["entity", "id", id])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Updates an entity by ID.
    pub async fn update_entity_by_id(
        &self,
        id: &str,
        request: &IdentityEntityRequest,
    ) -> Result<IdentityEntityUpsert> {
        request.validate()?;
        let envelope: ResponseEnvelope<IdentityEntityUpsert> = self
            .client
            .request_json(
                Method::POST,
                &self.path(&["entity", "id", id])?,
                Some(request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes an entity by ID.
    pub async fn delete_entity_by_id(&self, id: &str) -> Result<Empty> {
        self.delete_at(&["entity", "id", id]).await
    }

    /// Deletes multiple entities by ID.
    pub async fn batch_delete_entities(
        &self,
        request: &IdentityEntityBatchDeleteRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.client
            .request_json(
                Method::POST,
                &self.path(&["entity", "batch-delete"])?,
                Some(request),
            )
            .await
    }

    /// Looks up an entity by ID, name, or alias fields.
    pub async fn lookup_entity(
        &self,
        request: &IdentityEntityLookupRequest,
    ) -> Result<IdentityEntityInfo> {
        request.validate()?;
        let envelope: ResponseEnvelope<IdentityEntityInfo> = self
            .client
            .request_json(
                Method::POST,
                &self.path(&["lookup", "entity"])?,
                Some(request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Merges one or more source entities into a target entity.
    pub async fn merge_entities(&self, request: &IdentityEntityMergeRequest) -> Result<Empty> {
        request.validate()?;
        self.client
            .request_json(
                Method::POST,
                &self.path(&["entity", "merge"])?,
                Some(request),
            )
            .await
    }

    /// Lists entity IDs.
    pub async fn list_entity_ids(&self) -> Result<IdentityEntityList> {
        self.list_at(&["entity", "id"]).await
    }

    /// Creates or updates an entity by name.
    pub async fn write_entity_by_name(
        &self,
        name: &str,
        request: &IdentityEntityRequest,
    ) -> Result<IdentityEntityUpsert> {
        request.validate()?;
        let envelope: ResponseEnvelope<IdentityEntityUpsert> = self
            .client
            .request_json(
                Method::POST,
                &self.path(&["entity", "name", name])?,
                Some(request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Reads an entity by name.
    pub async fn read_entity_by_name(&self, name: &str) -> Result<IdentityEntityInfo> {
        let envelope: ResponseEnvelope<IdentityEntityInfo> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["entity", "name", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes an entity by name.
    pub async fn delete_entity_by_name(&self, name: &str) -> Result<Empty> {
        self.delete_at(&["entity", "name", name]).await
    }

    /// Lists entity names.
    pub async fn list_entity_names(&self) -> Result<IdentityEntityList> {
        self.list_at(&["entity", "name"]).await
    }

    /// Creates or updates a group.
    pub async fn write_group(&self, request: &IdentityGroupRequest) -> Result<IdentityGroupUpsert> {
        request.validate()?;
        let envelope: ResponseEnvelope<IdentityGroupUpsert> = self
            .client
            .request_json(Method::POST, &self.path(&["group"])?, Some(request))
            .await?;
        Ok(envelope.data)
    }

    /// Reads a group by ID.
    pub async fn read_group_by_id(&self, id: &str) -> Result<IdentityGroupInfo> {
        let envelope: ResponseEnvelope<IdentityGroupInfo> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["group", "id", id])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Updates a group by ID.
    pub async fn update_group_by_id(
        &self,
        id: &str,
        request: &IdentityGroupRequest,
    ) -> Result<IdentityGroupUpsert> {
        request.validate()?;
        let envelope: ResponseEnvelope<IdentityGroupUpsert> = self
            .client
            .request_json(
                Method::POST,
                &self.path(&["group", "id", id])?,
                Some(request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a group by ID.
    pub async fn delete_group_by_id(&self, id: &str) -> Result<Empty> {
        self.delete_at(&["group", "id", id]).await
    }

    /// Lists group IDs.
    pub async fn list_group_ids(&self) -> Result<IdentityGroupList> {
        self.list_at(&["group", "id"]).await
    }

    /// Looks up a group by ID, name, or alias fields.
    pub async fn lookup_group(
        &self,
        request: &IdentityGroupLookupRequest,
    ) -> Result<IdentityGroupInfo> {
        request.validate()?;
        let envelope: ResponseEnvelope<IdentityGroupInfo> = self
            .client
            .request_json(
                Method::POST,
                &self.path(&["lookup", "group"])?,
                Some(request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Creates or updates a group by name.
    pub async fn write_group_by_name(
        &self,
        name: &str,
        request: &IdentityGroupRequest,
    ) -> Result<IdentityGroupUpsert> {
        request.validate()?;
        let envelope: ResponseEnvelope<IdentityGroupUpsert> = self
            .client
            .request_json(
                Method::POST,
                &self.path(&["group", "name", name])?,
                Some(request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Reads a group by name.
    pub async fn read_group_by_name(&self, name: &str) -> Result<IdentityGroupInfo> {
        let envelope: ResponseEnvelope<IdentityGroupInfo> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["group", "name", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a group by name.
    pub async fn delete_group_by_name(&self, name: &str) -> Result<Empty> {
        self.delete_at(&["group", "name", name]).await
    }

    /// Lists group names.
    pub async fn list_group_names(&self) -> Result<IdentityGroupList> {
        self.list_at(&["group", "name"]).await
    }

    /// Creates or updates an entity alias.
    pub async fn write_entity_alias(
        &self,
        request: &IdentityEntityAliasRequest,
    ) -> Result<IdentityAliasUpsert> {
        request.validate()?;
        let envelope: ResponseEnvelope<IdentityAliasUpsert> = self
            .client
            .request_json(Method::POST, &self.path(&["entity-alias"])?, Some(request))
            .await?;
        Ok(envelope.data)
    }

    /// Reads an entity alias by ID.
    pub async fn read_entity_alias_by_id(&self, id: &str) -> Result<IdentityAliasInfo> {
        let envelope: ResponseEnvelope<IdentityAliasInfo> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["entity-alias", "id", id])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes an entity alias by ID.
    pub async fn delete_entity_alias_by_id(&self, id: &str) -> Result<Empty> {
        self.delete_at(&["entity-alias", "id", id]).await
    }

    /// Lists entity alias IDs.
    pub async fn list_entity_alias_ids(&self) -> Result<IdentityAliasList> {
        self.list_at(&["entity-alias", "id"]).await
    }

    /// Creates or updates a group alias.
    pub async fn write_group_alias(
        &self,
        request: &IdentityGroupAliasRequest,
    ) -> Result<IdentityAliasUpsert> {
        let envelope: ResponseEnvelope<IdentityAliasUpsert> = self
            .client
            .request_json(Method::POST, &self.path(&["group-alias"])?, Some(request))
            .await?;
        Ok(envelope.data)
    }

    /// Reads a group alias by ID.
    pub async fn read_group_alias_by_id(&self, id: &str) -> Result<IdentityAliasInfo> {
        let envelope: ResponseEnvelope<IdentityAliasInfo> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["group-alias", "id", id])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a group alias by ID.
    pub async fn delete_group_alias_by_id(&self, id: &str) -> Result<Empty> {
        self.delete_at(&["group-alias", "id", id]).await
    }

    /// Lists group alias IDs.
    pub async fn list_group_alias_ids(&self) -> Result<IdentityAliasList> {
        self.list_at(&["group-alias", "id"]).await
    }

    /// Writes Identity OIDC token backend configuration.
    pub async fn write_oidc_config(&self, request: &IdentityOidcConfigRequest) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                &self.path(&["oidc", "config"])?,
                Some(request),
            )
            .await
    }

    /// Reads Identity OIDC token backend configuration.
    pub async fn read_oidc_config(&self) -> Result<IdentityOidcConfig> {
        let envelope: ResponseEnvelope<IdentityOidcConfig> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["oidc", "config"])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Creates or updates an Identity OIDC signing key.
    pub async fn write_oidc_key(
        &self,
        name: &str,
        request: &IdentityOidcKeyRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.client
            .request_json(
                Method::POST,
                &self.path(&["oidc", "key", name])?,
                Some(request),
            )
            .await
    }

    /// Reads an Identity OIDC signing key.
    pub async fn read_oidc_key(&self, name: &str) -> Result<IdentityOidcKeyInfo> {
        let envelope: ResponseEnvelope<IdentityOidcKeyInfo> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["oidc", "key", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes an Identity OIDC signing key.
    pub async fn delete_oidc_key(&self, name: &str) -> Result<Empty> {
        self.delete_at(&["oidc", "key", name]).await
    }

    /// Lists Identity OIDC signing keys.
    pub async fn list_oidc_keys(&self) -> Result<IdentityOidcKeyList> {
        self.list_at(&["oidc", "key"]).await
    }

    /// Rotates an Identity OIDC signing key.
    pub async fn rotate_oidc_key(
        &self,
        name: &str,
        request: &IdentityOidcKeyRotateRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.client
            .request_json(
                Method::POST,
                &self.path(&["oidc", "key", name, "rotate"])?,
                Some(request),
            )
            .await
    }

    /// Creates or updates an Identity OIDC role.
    pub async fn write_oidc_role(
        &self,
        name: &str,
        request: &IdentityOidcRoleRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.client
            .request_json(
                Method::POST,
                &self.path(&["oidc", "role", name])?,
                Some(request),
            )
            .await
    }

    /// Reads an Identity OIDC role.
    pub async fn read_oidc_role(&self, name: &str) -> Result<IdentityOidcRoleInfo> {
        let envelope: ResponseEnvelope<IdentityOidcRoleInfo> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["oidc", "role", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes an Identity OIDC role.
    pub async fn delete_oidc_role(&self, name: &str) -> Result<Empty> {
        self.delete_at(&["oidc", "role", name]).await
    }

    /// Lists Identity OIDC roles.
    pub async fn list_oidc_roles(&self) -> Result<IdentityOidcRoleList> {
        self.list_at(&["oidc", "role"]).await
    }

    /// Generates a signed Identity OIDC ID token for `name`.
    pub async fn generate_oidc_token(&self, name: &str) -> Result<IdentityOidcToken> {
        let envelope: ResponseEnvelope<IdentityOidcToken> = self
            .client
            .request_json(
                Method::GET,
                &self.path(&["oidc", "token", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Introspects a signed Identity OIDC token.
    ///
    /// The token is exposed only while serializing the request body.
    pub async fn introspect_oidc_token(
        &self,
        request: &IdentityOidcIntrospectRequest,
    ) -> Result<IdentityOidcIntrospection> {
        let payload = IdentityOidcIntrospectPayload {
            token: request.token.expose_secret(),
            client_id: request.client_id.as_deref(),
        };
        self.client
            .request_json(
                Method::POST,
                &self.path(&["oidc", "introspect"])?,
                Some(&payload),
            )
            .await
    }

    /// Reads OIDC provider discovery metadata for the identity token backend.
    ///
    /// OpenBao serves this as a plain OIDC response, not a `data` envelope.
    pub async fn read_oidc_discovery(&self) -> Result<IdentityOidcDiscovery> {
        self.client
            .request_json(
                Method::GET,
                &self.path(&["oidc", ".well-known", "openid-configuration"])?,
                Option::<&Empty>::None,
            )
            .await
    }

    /// Reads public OIDC JSON Web Keys for the identity token backend.
    ///
    /// The returned keys are public verification material. The list is still
    /// bounded during deserialization to avoid disproportionate allocations.
    pub async fn read_oidc_jwks(&self) -> Result<IdentityOidcJwks> {
        self.client
            .request_json(
                Method::GET,
                &self.path(&["oidc", ".well-known", "keys"])?,
                Option::<&Empty>::None,
            )
            .await
    }

    async fn list_at<T>(&self, tail: &[&str]) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<T> = self
            .client
            .request_json_query_accepting(
                method,
                &self.path(tail)?,
                &[],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    async fn delete_at(&self, tail: &[&str]) -> Result<Empty> {
        self.client
            .request_json_accepting(
                Method::DELETE,
                &self.path(tail)?,
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
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

fn validate_string_count(count: usize, field: &'static str) -> Result<()> {
    if count <= IDENTITY_LIST_LIMIT {
        return Ok(());
    }
    Err(Error::InvalidParameter(format!(
        "{field} exceeds maximum item count"
    )))
}

#[derive(Serialize)]
struct IdentityOidcIntrospectPayload<'a> {
    token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<&'a str>,
}

fn deserialize_bounded_json_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<JsonValue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<JsonValue>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded JSON array")
        }

        fn visit_none<E>(self) -> core::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Vec::new())
        }

        fn visit_unit<E>(self) -> core::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Vec::new())
        }

        fn visit_some<D>(self, deserializer: D) -> core::result::Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_seq(self)
        }

        fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while values.len() < IDENTITY_LIST_LIMIT {
                let Some(value) = seq.next_element::<JsonValue>()? else {
                    return Ok(values);
                };
                values.push(value);
            }
            while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
            Err(serde::de::Error::custom(
                "identity OIDC JWKS key list exceeds item limit",
            ))
        }
    }

    deserializer.deserialize_option(Visitor)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(deprecated)]

    use secrecy::SecretString;

    use crate::{Client, OpenBaoConfig};

    use super::{
        IdentityAliasList, IdentityEntityBatchDeleteRequest, IdentityEntityList,
        IdentityEntityRequest, IdentityGroupList, IdentityGroupRequest,
        IdentityOidcIntrospectRequest, IdentityOidcJwks, IdentityOidcKeyList, IdentityOidcRoleList,
        IdentityOidcToken,
    };

    #[test]
    fn identity_paths_are_validated() {
        let config = OpenBaoConfig::new("http://127.0.0.1:8200")
            .and_then(OpenBaoConfig::allow_localhost_http)
            .unwrap_or_else(|error| panic!("{error}"));
        let client = Client::from_config(config)
            .unwrap_or_else(|error| panic!("{error}"))
            .with_token(SecretString::from("token"));
        let identity = client
            .identity_at("identity")
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            identity
                .path(&["entity", "name", "app"])
                .unwrap_or_else(|error| panic!("{error}")),
            "identity/entity/name/app"
        );
        assert!(client.identity_at("../identity").is_err());
        assert!(identity.path(&["entity", "name", "../app"]).is_err());
    }

    #[test]
    fn identity_lists_are_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("identity-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });

        assert!(serde_json::from_value::<IdentityEntityList>(value.clone()).is_err());
        assert!(serde_json::from_value::<IdentityGroupList>(value.clone()).is_err());
        assert!(serde_json::from_value::<IdentityAliasList>(value).is_err());
    }

    #[test]
    fn identity_request_counts_are_bounded() {
        let mut entity = IdentityEntityRequest::named("app");
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            entity.policies.push(format!("policy-{index}"));
        }
        assert!(entity.validate().is_err());

        let mut group = IdentityGroupRequest::internal("app");
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            group.member_entity_ids.push(format!("entity-{index}"));
        }
        assert!(group.validate().is_err());

        let batch = IdentityEntityBatchDeleteRequest::new(Vec::<String>::new());
        assert!(batch.validate().is_err());
    }

    #[test]
    fn identity_oidc_secret_debug_is_redacted() {
        let token = IdentityOidcToken {
            client_id: Some("client-id".to_owned()),
            token: SecretString::from("signed-id-token"),
            ttl: Some(3600),
        };
        let debug = format!("{token:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("signed-id-token"));

        let request = IdentityOidcIntrospectRequest::new(SecretString::from("signed-id-token"))
            .with_client_id("client-id");
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("signed-id-token"));
    }

    #[test]
    fn identity_oidc_lists_are_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("identity-oidc-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });

        assert!(serde_json::from_value::<IdentityOidcKeyList>(value.clone()).is_err());
        assert!(serde_json::from_value::<IdentityOidcRoleList>(value).is_err());

        let mut jwks = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            jwks.push(serde_json::json!({ "kid": format!("key-{index}") }));
        }
        assert!(
            serde_json::from_value::<IdentityOidcJwks>(serde_json::json!({
                "keys": jwks
            }))
            .is_err()
        );
    }
}
