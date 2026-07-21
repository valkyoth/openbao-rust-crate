//! Identity secrets engine support.
//!
//! The identity engine manages OpenBao entities, groups, and aliases. These
//! helpers cover the core lifecycle endpoints and keep returned lists and
//! metadata maps bounded before allocation can grow without limit.

use std::collections::BTreeMap;
use std::fmt;

use reqwest::{
    Method, StatusCode,
    header::{AUTHORIZATION, HeaderName, HeaderValue},
};
use sanitization::{SecretVec, SecureSanitize};
use secrecy::{ExposeSecret, SecretString};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value as JsonValue;

use crate::{
    Authenticated, Client, Error, Result, Unauthenticated,
    path::{validate_endpoint_path, validate_mount_path},
    response::{
        BoundedJsonValueSeed, Empty, JsonValueBudget, ListEntries, RejectOverflow,
        ResponseEnvelope, deserialize_bounded_string_map_or_default,
        deserialize_bounded_string_vec,
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

/// Authenticated OIDC authorization handle for a named Identity provider mount.
///
/// OpenBao resolves the requesting entity and provider assignments from the
/// attached OpenBao token, so authorization cannot use a token-free client.
#[derive(Debug)]
pub struct IdentityOidcAuthorization<'a> {
    client: &'a Client<Authenticated>,
    mount: Vec<String>,
}

/// Unauthenticated OIDC token and userinfo handle for an Identity provider.
///
/// This handle deliberately cannot carry an OpenBao token. Provider token and
/// userinfo operations use OAuth client or bearer credentials instead.
#[derive(Debug)]
pub struct IdentityOidcProvider<'a> {
    client: &'a Client<Unauthenticated>,
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
    /// Conflicting alias IDs that should remain attached to the target entity.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub conflicting_alias_ids_to_keep: Vec<String>,
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
            conflicting_alias_ids_to_keep: Vec::new(),
        }
    }

    /// Forces the merge when OpenBao allows it.
    #[must_use]
    pub fn force(mut self) -> Self {
        self.force = Some(true);
        self
    }

    /// Selects conflicting aliases that should remain after the merge.
    #[must_use]
    pub fn keep_conflicting_aliases(
        mut self,
        alias_ids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.conflicting_alias_ids_to_keep = alias_ids.into_iter().map(Into::into).collect();
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
        )?;
        if self.from_entity_ids.iter().any(|id| id.trim().is_empty()) {
            return Err(Error::InvalidParameter(
                "identity merge source entity IDs must not be empty".into(),
            ));
        }
        validate_string_count(
            self.conflicting_alias_ids_to_keep.len(),
            "identity merge conflicting alias IDs",
        )?;
        if self
            .conflicting_alias_ids_to_keep
            .iter()
            .any(|id| id.trim().is_empty())
        {
            return Err(Error::InvalidParameter(
                "identity merge conflicting alias IDs must not be empty".into(),
            ));
        }
        Ok(())
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

/// Identity OIDC provider authorization request.
#[derive(Clone)]
pub struct IdentityOidcAuthorizeRequest {
    /// Space-delimited scopes. The `openid` scope is required by OpenBao.
    pub scope: String,
    /// OIDC client identifier.
    pub client_id: String,
    /// Registered redirect URI.
    pub redirect_uri: String,
    /// Opaque caller state returned with the authorization code.
    pub state: Option<SecretString>,
    /// Replay-resistant nonce included in the resulting ID token.
    pub nonce: Option<SecretString>,
    /// Maximum elapsed seconds since active authentication.
    pub max_age: Option<u64>,
    /// PKCE code challenge.
    pub code_challenge: Option<String>,
    /// PKCE challenge method (`S256` or `plain`).
    pub code_challenge_method: Option<String>,
}

impl IdentityOidcAuthorizeRequest {
    /// Creates an authorization-code request.
    pub fn new(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            scope: scope.into(),
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            state: None,
            nonce: None,
            max_age: None,
            code_challenge: None,
            code_challenge_method: None,
        }
    }

    /// Sets opaque request state.
    #[must_use]
    pub fn with_state(mut self, state: impl Into<SecretString>) -> Self {
        self.state = Some(state.into());
        self
    }

    /// Sets the ID-token nonce.
    #[must_use]
    pub fn with_nonce(mut self, nonce: impl Into<SecretString>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Sets the maximum authentication age in seconds.
    #[must_use]
    pub const fn with_max_age(mut self, max_age: u64) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Enables PKCE with the supplied challenge and method.
    #[must_use]
    pub fn with_pkce(mut self, challenge: impl Into<String>, method: impl Into<String>) -> Self {
        self.code_challenge = Some(challenge.into());
        self.code_challenge_method = Some(method.into());
        self
    }

    fn validate(&self) -> Result<()> {
        if self.client_id.trim().is_empty()
            || self.redirect_uri.trim().is_empty()
            || !self
                .scope
                .split_ascii_whitespace()
                .any(|scope| scope == "openid")
        {
            return Err(Error::InvalidParameter(
                "identity OIDC authorization requires client_id, redirect_uri, and openid scope"
                    .into(),
            ));
        }
        if self.code_challenge.is_some() != self.code_challenge_method.is_some() {
            return Err(Error::InvalidParameter(
                "identity OIDC PKCE challenge and method must be supplied together".into(),
            ));
        }
        if let Some(method) = &self.code_challenge_method
            && !matches!(method.as_str(), "S256" | "plain")
        {
            return Err(Error::InvalidParameter(
                "identity OIDC PKCE method must be S256 or plain".into(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for IdentityOidcAuthorizeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityOidcAuthorizeRequest")
            .field("scope", &self.scope)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("has_state", &self.state.is_some())
            .field("has_nonce", &self.nonce.is_some())
            .field("max_age", &self.max_age)
            .field("code_challenge", &self.code_challenge)
            .field("code_challenge_method", &self.code_challenge_method)
            .finish()
    }
}

impl Serialize for IdentityOidcAuthorizeRequest {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("response_type", "code")?;
        map.serialize_entry("client_id", &self.client_id)?;
        map.serialize_entry("redirect_uri", &self.redirect_uri)?;
        map.serialize_entry("scope", &self.scope)?;
        serialize_optional_entry(
            &mut map,
            "state",
            self.state.as_ref().map(ExposeSecret::expose_secret),
        )?;
        serialize_optional_entry(
            &mut map,
            "nonce",
            self.nonce.as_ref().map(ExposeSecret::expose_secret),
        )?;
        if let Some(max_age) = self.max_age {
            map.serialize_entry("max_age", &max_age)?;
        }
        serialize_optional_entry(&mut map, "code_challenge", self.code_challenge.as_deref())?;
        serialize_optional_entry(
            &mut map,
            "code_challenge_method",
            self.code_challenge_method.as_deref(),
        )?;
        map.end()
    }
}

/// Authorization code and caller state returned by an Identity OIDC provider.
#[derive(Clone, Deserialize)]
pub struct IdentityOidcAuthorizeResponse {
    /// Single-use authorization code.
    pub code: SecretString,
    /// Opaque caller state, when supplied in the request.
    #[serde(default)]
    pub state: Option<SecretString>,
}

impl fmt::Debug for IdentityOidcAuthorizeResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityOidcAuthorizeResponse")
            .field("code", &"<redacted>")
            .field("state", &self.state.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentityOidcGrantType {
    AuthorizationCode,
    ClientCredentials,
}

/// Identity OIDC provider token request.
#[derive(Clone)]
pub struct IdentityOidcProviderTokenRequest {
    grant_type: IdentityOidcGrantType,
    code: Option<SecretString>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<SecretString>,
    code_verifier: Option<SecretString>,
    scope: Option<String>,
    basic_auth: bool,
}

impl IdentityOidcProviderTokenRequest {
    /// Creates an authorization-code exchange request.
    pub fn authorization_code(code: SecretString, redirect_uri: impl Into<String>) -> Self {
        Self {
            grant_type: IdentityOidcGrantType::AuthorizationCode,
            code: Some(code),
            redirect_uri: Some(redirect_uri.into()),
            client_id: None,
            client_secret: None,
            code_verifier: None,
            scope: None,
            basic_auth: false,
        }
    }

    /// Creates a client-credentials request for a space-delimited scope list.
    ///
    /// The provider token `scope` field requires OpenBao 2.5 or later.
    pub fn client_credentials(scope: impl Into<String>) -> Self {
        Self {
            grant_type: IdentityOidcGrantType::ClientCredentials,
            code: None,
            redirect_uri: None,
            client_id: None,
            client_secret: None,
            code_verifier: None,
            scope: Some(scope.into()),
            basic_auth: false,
        }
    }

    /// Supplies public-client or `client_secret_post` credentials.
    #[must_use]
    pub fn with_post_credentials(
        mut self,
        client_id: impl Into<String>,
        client_secret: Option<SecretString>,
    ) -> Self {
        self.client_id = Some(client_id.into());
        self.client_secret = client_secret;
        self.basic_auth = false;
        self
    }

    /// Supplies confidential-client `client_secret_basic` credentials.
    #[must_use]
    pub fn with_basic_credentials(
        mut self,
        client_id: impl Into<String>,
        client_secret: SecretString,
    ) -> Self {
        self.client_id = Some(client_id.into());
        self.client_secret = Some(client_secret);
        self.basic_auth = true;
        self
    }

    /// Supplies a PKCE verifier for an authorization-code exchange.
    #[must_use]
    pub fn with_code_verifier(mut self, verifier: SecretString) -> Self {
        self.code_verifier = Some(verifier);
        self
    }

    fn validate(&self) -> Result<()> {
        match self.grant_type {
            IdentityOidcGrantType::AuthorizationCode
                if self
                    .code
                    .as_ref()
                    .is_none_or(|value| value.expose_secret().is_empty())
                    || self.redirect_uri.as_deref().is_none_or(str::is_empty) =>
            {
                return Err(Error::InvalidParameter(
                    "identity OIDC authorization_code requires code and redirect_uri".into(),
                ));
            }
            IdentityOidcGrantType::ClientCredentials
                if self.scope.as_deref().is_none_or(|scope| {
                    !scope
                        .split_ascii_whitespace()
                        .any(|value| value == "openid")
                }) =>
            {
                return Err(Error::InvalidParameter(
                    "identity OIDC client_credentials requires openid scope".into(),
                ));
            }
            _ => {}
        }
        if self.basic_auth
            && (self.client_id.as_deref().is_none_or(str::is_empty)
                || self
                    .client_secret
                    .as_ref()
                    .is_none_or(|secret| secret.expose_secret().is_empty()))
        {
            return Err(Error::InvalidParameter(
                "identity OIDC Basic authentication requires client ID and secret".into(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for IdentityOidcProviderTokenRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityOidcProviderTokenRequest")
            .field("grant_type", &self.grant_type)
            .field("has_code", &self.code.is_some())
            .field("redirect_uri", &self.redirect_uri)
            .field("client_id", &self.client_id)
            .field("has_client_secret", &self.client_secret.is_some())
            .field("has_code_verifier", &self.code_verifier.is_some())
            .field("scope", &self.scope)
            .field("basic_auth", &self.basic_auth)
            .finish()
    }
}

/// Tokens returned by an Identity OIDC provider token exchange.
#[derive(Clone, Deserialize)]
pub struct IdentityOidcProviderTokenResponse {
    /// OAuth access token for the provider's userinfo endpoint.
    pub access_token: SecretString,
    /// Signed OIDC ID token.
    pub id_token: SecretString,
    /// Access-token lifetime in seconds.
    pub expires_in: u64,
    /// Token type, normally `Bearer`.
    pub token_type: String,
}

impl fmt::Debug for IdentityOidcProviderTokenResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityOidcProviderTokenResponse")
            .field("access_token", &"<redacted>")
            .field("id_token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .field("token_type", &self.token_type)
            .finish()
    }
}

/// Claims returned by an Identity OIDC provider userinfo operation.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityOidcUserInfo {
    /// Stable subject identifier.
    #[serde(default)]
    pub sub: Option<String>,
    /// Entity username claim.
    #[serde(default)]
    pub username: Option<String>,
    /// Entity group names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub groups: Vec<String>,
    /// Contact claims, such as email and phone number.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    pub contact: BTreeMap<String, String>,
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
#[derive(Clone, Default)]
pub struct IdentityOidcIntrospection {
    /// Whether OpenBao considers the token active.
    pub active: bool,
    /// Additional RFC 7662/OpenBao claims returned by the endpoint.
    pub extra: BTreeMap<String, JsonValue>,
}

impl fmt::Debug for IdentityOidcIntrospection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityOidcIntrospection")
            .field("active", &self.active)
            .field("claim_count", &self.extra.len())
            .finish()
    }
}

impl<'de> Deserialize<'de> for IdentityOidcIntrospection {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut extra = deserialize_bounded_json_map(deserializer)?;
        let active = extra
            .remove("active")
            .map(serde_json::from_value::<bool>)
            .transpose()
            .map_err(serde::de::Error::custom)?
            .unwrap_or(false);
        Ok(Self { active, extra })
    }
}

/// OIDC discovery metadata returned by OpenBao.
#[derive(Clone, Debug, Default)]
pub struct IdentityOidcDiscovery {
    /// Issuer URL.
    pub issuer: Option<String>,
    /// Authorization endpoint.
    pub authorization_endpoint: Option<String>,
    /// Token endpoint.
    pub token_endpoint: Option<String>,
    /// JWKS URI.
    pub jwks_uri: Option<String>,
    /// Supported response types.
    pub response_types_supported: Option<Vec<String>>,
    /// Supported subject types.
    pub subject_types_supported: Option<Vec<String>>,
    /// Supported ID-token signing algorithms.
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    /// Supported scopes.
    pub scopes_supported: Option<Vec<String>>,
    /// Supported token endpoint authentication methods.
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// Supported claims.
    pub claims_supported: Option<Vec<String>>,
    /// Additional provider metadata claims.
    pub extra: BTreeMap<String, JsonValue>,
}

impl<'de> Deserialize<'de> for IdentityOidcDiscovery {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut extra = deserialize_bounded_json_map(deserializer)?;
        Ok(Self {
            issuer: take_optional_string::<D::Error>(&mut extra, "issuer")?,
            authorization_endpoint: take_optional_string::<D::Error>(
                &mut extra,
                "authorization_endpoint",
            )?,
            token_endpoint: take_optional_string::<D::Error>(&mut extra, "token_endpoint")?,
            jwks_uri: take_optional_string::<D::Error>(&mut extra, "jwks_uri")?,
            response_types_supported: take_optional_string_vec::<D::Error>(
                &mut extra,
                "response_types_supported",
            )?,
            subject_types_supported: take_optional_string_vec::<D::Error>(
                &mut extra,
                "subject_types_supported",
            )?,
            id_token_signing_alg_values_supported: take_optional_string_vec::<D::Error>(
                &mut extra,
                "id_token_signing_alg_values_supported",
            )?,
            scopes_supported: take_optional_string_vec::<D::Error>(&mut extra, "scopes_supported")?,
            token_endpoint_auth_methods_supported: take_optional_string_vec::<D::Error>(
                &mut extra,
                "token_endpoint_auth_methods_supported",
            )?,
            claims_supported: take_optional_string_vec::<D::Error>(&mut extra, "claims_supported")?,
            extra,
        })
    }
}

/// OIDC JSON Web Key Set returned by OpenBao.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityOidcJwks {
    /// Public JWK entries.
    #[serde(default, deserialize_with = "deserialize_bounded_json_vec")]
    pub keys: Vec<JsonValue>,
}

/// Request to create or update an Identity OIDC provider.
#[derive(Clone, Debug, Default, Serialize)]
pub struct IdentityOidcProviderRequest {
    /// Issuer URL override for provider-issued tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Client IDs permitted to use the provider. Use `"*"` to allow all clients.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_client_ids: Vec<String>,
    /// Scopes available for requesting on the provider.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes_supported: Vec<String>,
}

impl IdentityOidcProviderRequest {
    /// Creates an empty provider request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the issuer URL override.
    #[must_use]
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Adds an allowed client ID.
    #[must_use]
    pub fn with_allowed_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.allowed_client_ids.push(client_id.into());
        self
    }

    /// Adds a supported scope.
    #[must_use]
    pub fn with_scope_supported(mut self, scope: impl Into<String>) -> Self {
        self.scopes_supported.push(scope.into());
        self
    }

    fn validate(&self) -> Result<()> {
        validate_string_count(
            self.allowed_client_ids.len(),
            "identity OIDC provider allowed client IDs",
        )?;
        validate_string_count(
            self.scopes_supported.len(),
            "identity OIDC provider supported scopes",
        )
    }
}

/// Identity OIDC provider information.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityOidcProviderInfo {
    /// Issuer URL override.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Client IDs permitted to use the provider.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub allowed_client_ids: Vec<String>,
    /// Scopes available for requesting on the provider.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub scopes_supported: Vec<String>,
}

/// Identity OIDC provider list response.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityOidcProviderList {
    /// Provider names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
    /// Provider metadata keyed by provider name.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_oidc_provider_info_map"
    )]
    pub key_info: BTreeMap<String, IdentityOidcProviderInfo>,
}

impl ListEntries for IdentityOidcProviderList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Request to create or update an Identity OIDC scope.
#[derive(Clone, Debug, Default, Serialize)]
pub struct IdentityOidcScopeRequest {
    /// JSON or base64-encoded JSON template for the scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// Human-readable scope description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl IdentityOidcScopeRequest {
    /// Creates an empty scope request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the scope template.
    #[must_use]
    pub fn with_template(mut self, template: impl Into<String>) -> Self {
        self.template = Some(template.into());
        self
    }

    /// Sets the scope description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// Identity OIDC scope information.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityOidcScopeInfo {
    /// Scope template.
    #[serde(default)]
    pub template: Option<String>,
    /// Scope description.
    #[serde(default)]
    pub description: Option<String>,
}

/// Identity OIDC scope list response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IdentityOidcScopeList {
    /// Scope names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for IdentityOidcScopeList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Identity OIDC client type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityOidcClientType {
    /// Confidential client with a client secret.
    Confidential,
    /// Public client requiring PKCE for authorization-code flow.
    Public,
}

impl IdentityOidcClientType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Confidential => "confidential",
            Self::Public => "public",
        }
    }
}

impl Serialize for IdentityOidcClientType {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for IdentityOidcClientType {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "confidential" => Ok(Self::Confidential),
            "public" => Ok(Self::Public),
            _ => Err(serde::de::Error::custom(
                "unsupported identity OIDC client type",
            )),
        }
    }
}

/// Request to create or update an Identity OIDC client.
#[derive(Clone, Debug, Default, Serialize)]
pub struct IdentityOidcClientRequest {
    /// Signing key name. OpenBao defaults to `default` when omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Redirect URIs accepted by the client.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<String>,
    /// Assignment resources associated with the client.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub assignments: Vec<String>,
    /// Client type. This cannot be modified after creation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_type: Option<IdentityOidcClientType>,
    /// ID token TTL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_ttl: Option<String>,
    /// Access token TTL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_ttl: Option<String>,
}

impl IdentityOidcClientRequest {
    /// Creates an empty client request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the signing key.
    #[must_use]
    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    /// Adds a redirect URI.
    #[must_use]
    pub fn with_redirect_uri(mut self, redirect_uri: impl Into<String>) -> Self {
        self.redirect_uris.push(redirect_uri.into());
        self
    }

    /// Adds an assignment name.
    #[must_use]
    pub fn with_assignment(mut self, assignment: impl Into<String>) -> Self {
        self.assignments.push(assignment.into());
        self
    }

    /// Sets the client type.
    #[must_use]
    pub fn with_client_type(mut self, client_type: IdentityOidcClientType) -> Self {
        self.client_type = Some(client_type);
        self
    }

    /// Sets the ID token TTL.
    #[must_use]
    pub fn with_id_token_ttl(mut self, ttl: impl Into<String>) -> Self {
        self.id_token_ttl = Some(ttl.into());
        self
    }

    /// Sets the access token TTL.
    #[must_use]
    pub fn with_access_token_ttl(mut self, ttl: impl Into<String>) -> Self {
        self.access_token_ttl = Some(ttl.into());
        self
    }

    fn validate(&self) -> Result<()> {
        validate_string_count(
            self.redirect_uris.len(),
            "identity OIDC client redirect URIs",
        )?;
        validate_string_count(self.assignments.len(), "identity OIDC client assignments")?;
        if let Some(ttl) = &self.id_token_ttl {
            validate_duration_parameter(ttl, "identity OIDC client id_token_ttl")?;
        }
        if let Some(ttl) = &self.access_token_ttl {
            validate_duration_parameter(ttl, "identity OIDC client access_token_ttl")?;
        }
        Ok(())
    }
}

/// Identity OIDC client information.
#[derive(Clone, Default, Deserialize)]
pub struct IdentityOidcClientInfo {
    /// Access token TTL in seconds.
    #[serde(default)]
    pub access_token_ttl: Option<u64>,
    /// Client assignments.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub assignments: Vec<String>,
    /// Generated client ID.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Generated client secret for confidential clients.
    #[serde(default)]
    pub client_secret: Option<SecretString>,
    /// Client type.
    #[serde(default)]
    pub client_type: Option<IdentityOidcClientType>,
    /// ID token TTL in seconds.
    #[serde(default)]
    pub id_token_ttl: Option<u64>,
    /// Signing key name.
    #[serde(default)]
    pub key: Option<String>,
    /// Redirect URIs accepted by the client.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub redirect_uris: Vec<String>,
}

impl fmt::Debug for IdentityOidcClientInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityOidcClientInfo")
            .field("access_token_ttl", &self.access_token_ttl)
            .field("assignments", &self.assignments)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("client_type", &self.client_type)
            .field("id_token_ttl", &self.id_token_ttl)
            .field("key", &self.key)
            .field("redirect_uris", &self.redirect_uris)
            .finish()
    }
}

/// Identity OIDC client list response.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityOidcClientList {
    /// Client names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
    /// Client metadata keyed by client name.
    #[serde(default, deserialize_with = "deserialize_bounded_oidc_client_info_map")]
    pub key_info: BTreeMap<String, IdentityOidcClientInfo>,
}

impl ListEntries for IdentityOidcClientList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Request to create or update an Identity OIDC assignment.
#[derive(Clone, Debug, Default, Serialize)]
pub struct IdentityOidcAssignmentRequest {
    /// Entity IDs allowed by the assignment.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub entity_ids: Vec<String>,
    /// Group IDs allowed by the assignment.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub group_ids: Vec<String>,
}

impl IdentityOidcAssignmentRequest {
    /// Creates an empty assignment request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an entity ID.
    #[must_use]
    pub fn with_entity_id(mut self, entity_id: impl Into<String>) -> Self {
        self.entity_ids.push(entity_id.into());
        self
    }

    /// Adds a group ID.
    #[must_use]
    pub fn with_group_id(mut self, group_id: impl Into<String>) -> Self {
        self.group_ids.push(group_id.into());
        self
    }

    fn validate(&self) -> Result<()> {
        validate_string_count(self.entity_ids.len(), "identity OIDC assignment entity IDs")?;
        validate_string_count(self.group_ids.len(), "identity OIDC assignment group IDs")
    }
}

/// Identity OIDC assignment information.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityOidcAssignmentInfo {
    /// Entity IDs allowed by the assignment.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub entity_ids: Vec<String>,
    /// Group IDs allowed by the assignment.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub group_ids: Vec<String>,
}

/// Identity OIDC assignment list response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IdentityOidcAssignmentList {
    /// Assignment names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for IdentityOidcAssignmentList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Request to create or update a Duo MFA method.
#[derive(Clone)]
pub struct IdentityMfaDuoMethodRequest {
    /// Unique method name.
    pub method_name: String,
    /// Identity username template.
    pub username_format: Option<String>,
    /// Duo secret key.
    pub secret_key: SecretString,
    /// Duo integration key.
    pub integration_key: SecretString,
    /// Duo API hostname.
    pub api_hostname: String,
    /// Duo push information.
    pub push_info: Option<String>,
    /// Whether passcode validation is used.
    pub use_passcode: Option<bool>,
}

impl IdentityMfaDuoMethodRequest {
    /// Creates a Duo MFA method request.
    pub fn new(
        method_name: impl Into<String>,
        secret_key: SecretString,
        integration_key: SecretString,
        api_hostname: impl Into<String>,
    ) -> Self {
        Self {
            method_name: method_name.into(),
            username_format: None,
            secret_key,
            integration_key,
            api_hostname: api_hostname.into(),
            push_info: None,
            use_passcode: None,
        }
    }

    /// Sets the Identity username template.
    #[must_use]
    pub fn with_username_format(mut self, username_format: impl Into<String>) -> Self {
        self.username_format = Some(username_format.into());
        self
    }

    /// Sets Duo push information.
    #[must_use]
    pub fn with_push_info(mut self, push_info: impl Into<String>) -> Self {
        self.push_info = Some(push_info.into());
        self
    }

    /// Sets whether passcode validation is used.
    #[must_use]
    pub fn with_use_passcode(mut self, use_passcode: bool) -> Self {
        self.use_passcode = Some(use_passcode);
        self
    }

    fn validate(&self) -> Result<()> {
        validate_required(&self.method_name, "identity MFA Duo method_name")?;
        validate_required(&self.api_hostname, "identity MFA Duo api_hostname")
    }
}

impl fmt::Debug for IdentityMfaDuoMethodRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityMfaDuoMethodRequest")
            .field("method_name", &self.method_name)
            .field("username_format", &self.username_format)
            .field("secret_key", &"<redacted>")
            .field("integration_key", &"<redacted>")
            .field("api_hostname", &self.api_hostname)
            .field("push_info", &self.push_info)
            .field("use_passcode", &self.use_passcode)
            .finish()
    }
}

impl Serialize for IdentityMfaDuoMethodRequest {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("method_name", &self.method_name)?;
        serialize_optional_entry(&mut map, "username_format", self.username_format.as_deref())?;
        map.serialize_entry("secret_key", self.secret_key.expose_secret())?;
        map.serialize_entry("integration_key", self.integration_key.expose_secret())?;
        map.serialize_entry("api_hostname", &self.api_hostname)?;
        serialize_optional_entry(&mut map, "push_info", self.push_info.as_deref())?;
        if let Some(use_passcode) = self.use_passcode {
            map.serialize_entry("use_passcode", &use_passcode)?;
        }
        map.end()
    }
}

/// Duo MFA method information.
#[derive(Clone, Deserialize)]
pub struct IdentityMfaDuoMethodInfo {
    /// Method ID.
    #[serde(default)]
    pub id: Option<String>,
    /// Method name.
    #[serde(default, alias = "name")]
    pub method_name: Option<String>,
    /// Identity username template.
    #[serde(default)]
    pub username_format: Option<String>,
    /// Duo secret key.
    #[serde(default)]
    pub secret_key: Option<SecretString>,
    /// Duo integration key.
    #[serde(default)]
    pub integration_key: Option<SecretString>,
    /// Duo API hostname.
    #[serde(default)]
    pub api_hostname: Option<String>,
    /// Duo push information.
    #[serde(default, alias = "pushinfo")]
    pub push_info: Option<String>,
    /// Whether passcode validation is used.
    #[serde(default)]
    pub use_passcode: Option<bool>,
    /// Method type.
    #[serde(default, rename = "type")]
    pub method_type: Option<String>,
}

impl fmt::Debug for IdentityMfaDuoMethodInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityMfaDuoMethodInfo")
            .field("id", &self.id)
            .field("method_name", &self.method_name)
            .field("username_format", &self.username_format)
            .field(
                "secret_key",
                &self.secret_key.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "integration_key",
                &self.integration_key.as_ref().map(|_| "<redacted>"),
            )
            .field("api_hostname", &self.api_hostname)
            .field("push_info", &self.push_info)
            .field("use_passcode", &self.use_passcode)
            .field("method_type", &self.method_type)
            .finish()
    }
}

/// Request to create or update an Okta MFA method.
#[derive(Clone)]
pub struct IdentityMfaOktaMethodRequest {
    /// Unique method name.
    pub method_name: String,
    /// Identity username template.
    pub username_format: Option<String>,
    /// Okta organization name.
    pub org_name: String,
    /// Okta API token.
    pub api_token: SecretString,
    /// Okta base URL.
    pub base_url: Option<String>,
    /// Whether usernames must match primary email.
    pub primary_email: Option<bool>,
}

impl IdentityMfaOktaMethodRequest {
    /// Creates an Okta MFA method request.
    pub fn new(
        method_name: impl Into<String>,
        org_name: impl Into<String>,
        api_token: SecretString,
    ) -> Self {
        Self {
            method_name: method_name.into(),
            username_format: None,
            org_name: org_name.into(),
            api_token,
            base_url: None,
            primary_email: None,
        }
    }

    /// Sets the Identity username template.
    #[must_use]
    pub fn with_username_format(mut self, username_format: impl Into<String>) -> Self {
        self.username_format = Some(username_format.into());
        self
    }

    /// Sets the Okta base URL.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    /// Sets whether primary email matching is required.
    #[must_use]
    pub fn with_primary_email(mut self, primary_email: bool) -> Self {
        self.primary_email = Some(primary_email);
        self
    }

    fn validate(&self) -> Result<()> {
        validate_required(&self.method_name, "identity MFA Okta method_name")?;
        validate_required(&self.org_name, "identity MFA Okta org_name")
    }
}

impl fmt::Debug for IdentityMfaOktaMethodRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityMfaOktaMethodRequest")
            .field("method_name", &self.method_name)
            .field("username_format", &self.username_format)
            .field("org_name", &self.org_name)
            .field("api_token", &"<redacted>")
            .field("base_url", &self.base_url)
            .field("primary_email", &self.primary_email)
            .finish()
    }
}

impl Serialize for IdentityMfaOktaMethodRequest {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("method_name", &self.method_name)?;
        serialize_optional_entry(&mut map, "username_format", self.username_format.as_deref())?;
        map.serialize_entry("org_name", &self.org_name)?;
        map.serialize_entry("api_token", self.api_token.expose_secret())?;
        serialize_optional_entry(&mut map, "base_url", self.base_url.as_deref())?;
        if let Some(primary_email) = self.primary_email {
            map.serialize_entry("primary_email", &primary_email)?;
        }
        map.end()
    }
}

/// Okta MFA method information.
#[derive(Clone, Deserialize)]
pub struct IdentityMfaOktaMethodInfo {
    /// Method ID.
    #[serde(default)]
    pub id: Option<String>,
    /// Method name.
    #[serde(default, alias = "name")]
    pub method_name: Option<String>,
    /// Identity username template.
    #[serde(default)]
    pub username_format: Option<String>,
    /// Okta organization name.
    #[serde(default)]
    pub org_name: Option<String>,
    /// Okta API token.
    #[serde(default)]
    pub api_token: Option<SecretString>,
    /// Okta base URL.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Whether usernames must match primary email.
    #[serde(default)]
    pub primary_email: Option<bool>,
    /// Method type.
    #[serde(default, rename = "type")]
    pub method_type: Option<String>,
}

impl fmt::Debug for IdentityMfaOktaMethodInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityMfaOktaMethodInfo")
            .field("id", &self.id)
            .field("method_name", &self.method_name)
            .field("username_format", &self.username_format)
            .field("org_name", &self.org_name)
            .field("api_token", &self.api_token.as_ref().map(|_| "<redacted>"))
            .field("base_url", &self.base_url)
            .field("primary_email", &self.primary_email)
            .field("method_type", &self.method_type)
            .finish()
    }
}

/// Request to create or update a PingID MFA method.
#[derive(Clone)]
pub struct IdentityMfaPingIdMethodRequest {
    /// Unique method name.
    pub method_name: String,
    /// Identity username template.
    pub username_format: Option<String>,
    /// Base64-encoded PingID settings file.
    pub settings_file_base64: SecretString,
}

impl IdentityMfaPingIdMethodRequest {
    /// Creates a PingID MFA method request.
    pub fn new(method_name: impl Into<String>, settings_file_base64: SecretString) -> Self {
        Self {
            method_name: method_name.into(),
            username_format: None,
            settings_file_base64,
        }
    }

    /// Sets the Identity username template.
    #[must_use]
    pub fn with_username_format(mut self, username_format: impl Into<String>) -> Self {
        self.username_format = Some(username_format.into());
        self
    }

    fn validate(&self) -> Result<()> {
        validate_required(&self.method_name, "identity MFA PingID method_name")
    }
}

impl fmt::Debug for IdentityMfaPingIdMethodRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityMfaPingIdMethodRequest")
            .field("method_name", &self.method_name)
            .field("username_format", &self.username_format)
            .field("settings_file_base64", &"<redacted>")
            .finish()
    }
}

impl Serialize for IdentityMfaPingIdMethodRequest {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("method_name", &self.method_name)?;
        serialize_optional_entry(&mut map, "username_format", self.username_format.as_deref())?;
        map.serialize_entry(
            "settings_file_base64",
            self.settings_file_base64.expose_secret(),
        )?;
        map.end()
    }
}

/// PingID MFA method information.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityMfaPingIdMethodInfo {
    /// Method ID.
    #[serde(default)]
    pub id: Option<String>,
    /// Method name.
    #[serde(default, alias = "name")]
    pub method_name: Option<String>,
    /// Identity username template.
    #[serde(default)]
    pub username_format: Option<String>,
    /// PingID identity provider URL.
    #[serde(default)]
    pub idp_url: Option<String>,
    /// PingID admin URL.
    #[serde(default)]
    pub admin_url: Option<String>,
    /// PingID authenticator URL.
    #[serde(default)]
    pub authenticator_url: Option<String>,
    /// PingID organization alias.
    #[serde(default)]
    pub org_alias: Option<String>,
    /// Whether signatures are used.
    #[serde(default)]
    pub use_signature: Option<bool>,
    /// Method type.
    #[serde(default, rename = "type")]
    pub method_type: Option<String>,
}

/// Request to create or update a TOTP MFA method.
#[derive(Clone, Debug, Default, Serialize)]
pub struct IdentityMfaTotpMethodRequest {
    /// Unique method name.
    pub method_name: String,
    /// TOTP issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// TOTP period in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,
    /// Generated key size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size: Option<u64>,
    /// QR code size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qr_size: Option<u64>,
    /// Hash algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// Number of TOTP digits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digits: Option<u64>,
    /// Accepted skew.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skew: Option<u64>,
    /// Maximum validation attempts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_validation_attempts: Option<u64>,
}

impl IdentityMfaTotpMethodRequest {
    /// Creates a TOTP MFA method request.
    pub fn new(method_name: impl Into<String>) -> Self {
        Self {
            method_name: method_name.into(),
            ..Self::default()
        }
    }

    /// Sets the TOTP issuer.
    #[must_use]
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    fn validate(&self) -> Result<()> {
        validate_required(&self.method_name, "identity MFA TOTP method_name")
    }
}

/// TOTP MFA method information.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityMfaTotpMethodInfo {
    /// Method ID.
    #[serde(default)]
    pub id: Option<String>,
    /// Method name.
    #[serde(default, alias = "name")]
    pub method_name: Option<String>,
    /// TOTP issuer.
    #[serde(default)]
    pub issuer: Option<String>,
    /// TOTP period in seconds.
    #[serde(default)]
    pub period: Option<u64>,
    /// Generated key size.
    #[serde(default)]
    pub key_size: Option<u64>,
    /// QR code size.
    #[serde(default)]
    pub qr_size: Option<u64>,
    /// Hash algorithm.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Number of TOTP digits.
    #[serde(default)]
    pub digits: Option<u64>,
    /// Accepted skew.
    #[serde(default)]
    pub skew: Option<u64>,
    /// Maximum validation attempts.
    #[serde(default)]
    pub max_validation_attempts: Option<u64>,
    /// Method type.
    #[serde(default, rename = "type")]
    pub method_type: Option<String>,
}

/// Identity MFA method list response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IdentityMfaMethodList {
    /// MFA method IDs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for IdentityMfaMethodList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Request to generate a TOTP MFA secret.
#[derive(Clone, Debug, Serialize)]
pub struct IdentityMfaTotpGenerateRequest {
    /// TOTP MFA method ID.
    pub method_id: String,
}

impl IdentityMfaTotpGenerateRequest {
    /// Creates a TOTP generation request.
    pub fn new(method_id: impl Into<String>) -> Self {
        Self {
            method_id: method_id.into(),
        }
    }

    fn validate(&self) -> Result<()> {
        validate_required(&self.method_id, "identity MFA TOTP method_id")
    }
}

/// Request to administratively generate or destroy a TOTP MFA secret.
#[derive(Clone, Debug, Serialize)]
pub struct IdentityMfaTotpAdminRequest {
    /// TOTP MFA method ID.
    pub method_id: String,
    /// Entity ID whose TOTP secret is managed.
    pub entity_id: String,
}

impl IdentityMfaTotpAdminRequest {
    /// Creates an administrative TOTP request.
    pub fn new(method_id: impl Into<String>, entity_id: impl Into<String>) -> Self {
        Self {
            method_id: method_id.into(),
            entity_id: entity_id.into(),
        }
    }

    fn validate(&self) -> Result<()> {
        validate_required(&self.method_id, "identity MFA TOTP method_id")?;
        validate_required(&self.entity_id, "identity MFA TOTP entity_id")
    }
}

/// Generated TOTP MFA secret material.
#[derive(Clone, Deserialize)]
pub struct IdentityMfaTotpSecret {
    /// Base64-encoded QR barcode image. This embeds the generated TOTP secret.
    pub barcode: SecretString,
    /// otpauth URL. This embeds the generated TOTP secret.
    pub url: SecretString,
}

impl fmt::Debug for IdentityMfaTotpSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityMfaTotpSecret")
            .field("barcode", &"<redacted>")
            .field("url", &"<redacted>")
            .finish()
    }
}

/// Request to create or update an MFA login enforcement.
#[derive(Clone, Debug, Default, Serialize)]
pub struct IdentityMfaLoginEnforcementRequest {
    /// MFA method IDs. Any one listed method can satisfy this enforcement.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mfa_method_ids: Vec<String>,
    /// Auth mount accessors to which this enforcement applies.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub auth_method_accessors: Vec<String>,
    /// Auth method types to which this enforcement applies.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub auth_method_types: Vec<String>,
    /// Identity group IDs to which this enforcement applies.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub identity_group_ids: Vec<String>,
    /// Identity entity IDs to which this enforcement applies.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub identity_entity_ids: Vec<String>,
}

impl IdentityMfaLoginEnforcementRequest {
    /// Creates an empty login-enforcement request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an MFA method ID.
    #[must_use]
    pub fn with_mfa_method_id(mut self, method_id: impl Into<String>) -> Self {
        self.mfa_method_ids.push(method_id.into());
        self
    }

    /// Adds an auth method accessor condition.
    #[must_use]
    pub fn with_auth_method_accessor(mut self, accessor: impl Into<String>) -> Self {
        self.auth_method_accessors.push(accessor.into());
        self
    }

    /// Adds an auth method type condition.
    #[must_use]
    pub fn with_auth_method_type(mut self, method_type: impl Into<String>) -> Self {
        self.auth_method_types.push(method_type.into());
        self
    }

    /// Adds an identity group ID condition.
    #[must_use]
    pub fn with_identity_group_id(mut self, group_id: impl Into<String>) -> Self {
        self.identity_group_ids.push(group_id.into());
        self
    }

    /// Adds an identity entity ID condition.
    #[must_use]
    pub fn with_identity_entity_id(mut self, entity_id: impl Into<String>) -> Self {
        self.identity_entity_ids.push(entity_id.into());
        self
    }

    fn validate(&self) -> Result<()> {
        if self.mfa_method_ids.is_empty() {
            return Err(Error::InvalidParameter(
                "identity MFA login enforcement requires at least one MFA method ID".into(),
            ));
        }
        if self.auth_method_accessors.is_empty()
            && self.auth_method_types.is_empty()
            && self.identity_group_ids.is_empty()
            && self.identity_entity_ids.is_empty()
        {
            return Err(Error::InvalidParameter(
                "identity MFA login enforcement requires at least one auth or identity condition"
                    .into(),
            ));
        }
        validate_string_count(
            self.mfa_method_ids.len(),
            "identity MFA login enforcement method IDs",
        )?;
        validate_string_count(
            self.auth_method_accessors.len(),
            "identity MFA login enforcement auth method accessors",
        )?;
        validate_string_count(
            self.auth_method_types.len(),
            "identity MFA login enforcement auth method types",
        )?;
        validate_string_count(
            self.identity_group_ids.len(),
            "identity MFA login enforcement group IDs",
        )?;
        validate_string_count(
            self.identity_entity_ids.len(),
            "identity MFA login enforcement entity IDs",
        )
    }
}

/// MFA login enforcement information.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct IdentityMfaLoginEnforcementInfo {
    /// Enforcement ID.
    #[serde(default)]
    pub id: Option<String>,
    /// Enforcement name.
    #[serde(default)]
    pub name: Option<String>,
    /// Namespace ID.
    #[serde(default)]
    pub namespace_id: Option<String>,
    /// MFA method IDs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub mfa_method_ids: Vec<String>,
    /// Auth mount accessors.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub auth_method_accessors: Vec<String>,
    /// Auth method types.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub auth_method_types: Vec<String>,
    /// Identity group IDs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub identity_group_ids: Vec<String>,
    /// Identity entity IDs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub identity_entity_ids: Vec<String>,
}

/// Identity MFA login enforcement list response.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct IdentityMfaLoginEnforcementList {
    /// Login-enforcement names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for IdentityMfaLoginEnforcementList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

impl Client<Unauthenticated> {
    /// Uses the token-free OIDC token and userinfo endpoints at `identity`.
    pub fn identity_oidc_provider(&self) -> Result<IdentityOidcProvider<'_>> {
        self.identity_oidc_provider_at("identity")
    }

    /// Uses the token-free OIDC token and userinfo endpoints at `mount`.
    pub fn identity_oidc_provider_at(
        &self,
        mount: impl Into<String>,
    ) -> Result<IdentityOidcProvider<'_>> {
        Ok(IdentityOidcProvider {
            client: self,
            mount: validate_mount_path(&mount.into())?,
        })
    }
}

impl Client<Authenticated> {
    /// Uses the authenticated OIDC authorization endpoint at `identity`.
    pub fn identity_oidc_authorization(&self) -> Result<IdentityOidcAuthorization<'_>> {
        self.identity_oidc_authorization_at("identity")
    }

    /// Uses the authenticated OIDC authorization endpoint at `mount`.
    pub fn identity_oidc_authorization_at(
        &self,
        mount: impl Into<String>,
    ) -> Result<IdentityOidcAuthorization<'_>> {
        Ok(IdentityOidcAuthorization {
            client: self,
            mount: validate_mount_path(&mount.into())?,
        })
    }
}

impl IdentityOidcAuthorization<'_> {
    /// Requests an authorization code using a JSON `POST` body.
    pub async fn authorize(
        &self,
        provider: &str,
        request: &IdentityOidcAuthorizeRequest,
    ) -> Result<IdentityOidcAuthorizeResponse> {
        request.validate()?;
        let path = self.path(provider, "authorize")?;
        let registry_path = self.registry_path(provider, "authorize")?;
        self.client
            .request_registered_json_query_headers_accepting(
                "/identity/",
                Method::POST,
                &registry_path,
                &path,
                &[] as &[(&str, String)],
                &[],
                Some(request),
                &[StatusCode::OK],
            )
            .await
    }

    /// Requests an authorization code through OpenBao's `GET` query variant.
    ///
    /// State and nonce values enter URL buffers and may be recorded by
    /// query-aware intermediaries. This variant therefore requires
    /// `oidc-get-callback-acknowledged`; prefer [`Self::authorize`] otherwise.
    #[cfg(feature = "oidc-get-callback-acknowledged")]
    pub async fn authorize_get(
        &self,
        provider: &str,
        request: &IdentityOidcAuthorizeRequest,
    ) -> Result<IdentityOidcAuthorizeResponse> {
        request.validate()?;
        let max_age = request.max_age.map(|value| value.to_string());
        let mut query = vec![
            ("response_type", "code"),
            ("client_id", request.client_id.as_str()),
            ("redirect_uri", request.redirect_uri.as_str()),
            ("scope", request.scope.as_str()),
        ];
        if let Some(state) = &request.state {
            query.push(("state", state.expose_secret()));
        }
        if let Some(nonce) = &request.nonce {
            query.push(("nonce", nonce.expose_secret()));
        }
        if let Some(value) = max_age.as_deref() {
            query.push(("max_age", value));
        }
        if let Some(challenge) = &request.code_challenge {
            query.push(("code_challenge", challenge));
        }
        if let Some(method) = &request.code_challenge_method {
            query.push(("code_challenge_method", method));
        }
        let path = self.path(provider, "authorize")?;
        let registry_path = self.registry_path(provider, "authorize")?;
        self.client
            .request_registered_json_query_headers_accepting(
                "/identity/",
                Method::GET,
                &registry_path,
                &path,
                &query,
                &[],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await
    }

    fn path(&self, provider: &str, operation: &str) -> Result<String> {
        oidc_provider_path(&self.mount, provider, operation)
    }

    fn registry_path(&self, provider: &str, operation: &str) -> Result<String> {
        oidc_provider_registry_path(provider, operation)
    }
}

impl IdentityOidcProvider<'_> {
    /// Exchanges an authorization code or client credentials for OIDC tokens.
    pub async fn token(
        &self,
        provider: &str,
        request: &IdentityOidcProviderTokenRequest,
    ) -> Result<IdentityOidcProviderTokenResponse> {
        request.validate()?;
        self.client
            .validate_versioned_request_fields(&[(
                &crate::request_compatibility::fields::IDENTITY_PROVIDER_TOKEN_SCOPE,
                request.scope.is_some(),
            )])
            .await?;
        let mut fields = vec![(
            "grant_type",
            match request.grant_type {
                IdentityOidcGrantType::AuthorizationCode => "authorization_code",
                IdentityOidcGrantType::ClientCredentials => "client_credentials",
            },
        )];
        if let Some(code) = &request.code {
            fields.push(("code", code.expose_secret()));
        }
        if let Some(redirect_uri) = &request.redirect_uri {
            fields.push(("redirect_uri", redirect_uri));
        }
        if let Some(verifier) = &request.code_verifier {
            fields.push(("code_verifier", verifier.expose_secret()));
        }
        if let Some(scope) = &request.scope {
            fields.push(("scope", scope));
        }

        let mut headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
        if request.basic_auth {
            headers.push((AUTHORIZATION, oidc_basic_header(request)?));
        } else {
            if let Some(client_id) = &request.client_id {
                fields.push(("client_id", client_id));
            }
            if let Some(client_secret) = &request.client_secret {
                fields.push(("client_secret", client_secret.expose_secret()));
            }
        }
        self.client
            .request_registered_form_json_headers_accepting(
                "/identity/",
                Method::POST,
                &self.registry_path(provider, "token")?,
                &self.path(provider, "token")?,
                &headers,
                &fields,
                &[StatusCode::OK],
            )
            .await
    }

    /// Reads userinfo claims with an OIDC access token.
    pub async fn userinfo(
        &self,
        provider: &str,
        access_token: &SecretString,
    ) -> Result<IdentityOidcUserInfo> {
        let header = oidc_bearer_header(access_token)?;
        self.client
            .request_registered_json_query_headers_accepting(
                "/identity/",
                Method::POST,
                &self.registry_path(provider, "userinfo")?,
                &self.path(provider, "userinfo")?,
                &[] as &[(&str, String)],
                &[(AUTHORIZATION, header)],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await
    }

    fn path(&self, provider: &str, operation: &str) -> Result<String> {
        oidc_provider_path(&self.mount, provider, operation)
    }

    fn registry_path(&self, provider: &str, operation: &str) -> Result<String> {
        oidc_provider_registry_path(provider, operation)
    }
}

fn oidc_provider_path(mount: &[String], provider: &str, operation: &str) -> Result<String> {
    let mut segments = mount.to_vec();
    segments.extend(["oidc".to_owned(), "provider".to_owned()]);
    segments.extend(validate_mount_path(provider)?);
    segments.extend(validate_endpoint_path(operation)?);
    Ok(segments.join("/"))
}

fn oidc_provider_registry_path(provider: &str, operation: &str) -> Result<String> {
    let provider = validate_mount_path(provider)?.join("/");
    let operation = validate_endpoint_path(operation)?.join("/");
    Ok(format!("identity/oidc/provider/{provider}/{operation}"))
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
            .request(Method::POST, &self.path(&["entity"])?, Some(request))
            .await?;
        Ok(envelope.data)
    }

    /// Reads an entity by ID.
    pub async fn read_entity_by_id(&self, id: &str) -> Result<IdentityEntityInfo> {
        let envelope: ResponseEnvelope<IdentityEntityInfo> = self
            .request(
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
            .request(
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
        self.request(
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
            .request(
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
        self.request(
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
            .request(
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
            .request(
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
            .request(Method::POST, &self.path(&["group"])?, Some(request))
            .await?;
        Ok(envelope.data)
    }

    /// Reads a group by ID.
    pub async fn read_group_by_id(&self, id: &str) -> Result<IdentityGroupInfo> {
        let envelope: ResponseEnvelope<IdentityGroupInfo> = self
            .request(
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
            .request(
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
            .request(
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
            .request(
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
            .request(
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
            .request(Method::POST, &self.path(&["entity-alias"])?, Some(request))
            .await?;
        Ok(envelope.data)
    }

    /// Reads an entity alias by ID.
    pub async fn read_entity_alias_by_id(&self, id: &str) -> Result<IdentityAliasInfo> {
        let envelope: ResponseEnvelope<IdentityAliasInfo> = self
            .request(
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
            .request(Method::POST, &self.path(&["group-alias"])?, Some(request))
            .await?;
        Ok(envelope.data)
    }

    /// Reads a group alias by ID.
    pub async fn read_group_alias_by_id(&self, id: &str) -> Result<IdentityAliasInfo> {
        let envelope: ResponseEnvelope<IdentityAliasInfo> = self
            .request(
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
        self.request(
            Method::POST,
            &self.path(&["oidc", "config"])?,
            Some(request),
        )
        .await
    }

    /// Reads Identity OIDC token backend configuration.
    pub async fn read_oidc_config(&self) -> Result<IdentityOidcConfig> {
        let envelope: ResponseEnvelope<IdentityOidcConfig> = self
            .request(
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
        self.request(
            Method::POST,
            &self.path(&["oidc", "key", name])?,
            Some(request),
        )
        .await
    }

    /// Reads an Identity OIDC signing key.
    pub async fn read_oidc_key(&self, name: &str) -> Result<IdentityOidcKeyInfo> {
        let envelope: ResponseEnvelope<IdentityOidcKeyInfo> = self
            .request(
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
        self.request(
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
        self.request(
            Method::POST,
            &self.path(&["oidc", "role", name])?,
            Some(request),
        )
        .await
    }

    /// Reads an Identity OIDC role.
    pub async fn read_oidc_role(&self, name: &str) -> Result<IdentityOidcRoleInfo> {
        let envelope: ResponseEnvelope<IdentityOidcRoleInfo> = self
            .request(
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
            .request(
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
        self.request(
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
        self.request(
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
        self.request(
            Method::GET,
            &self.path(&["oidc", ".well-known", "keys"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Creates or updates an Identity OIDC provider.
    pub async fn write_oidc_provider(
        &self,
        name: &str,
        request: &IdentityOidcProviderRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.request(
            Method::POST,
            &self.path(&["oidc", "provider", name])?,
            Some(request),
        )
        .await
    }

    /// Reads an Identity OIDC provider.
    pub async fn read_oidc_provider(&self, name: &str) -> Result<IdentityOidcProviderInfo> {
        let envelope: ResponseEnvelope<IdentityOidcProviderInfo> = self
            .request(
                Method::GET,
                &self.path(&["oidc", "provider", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists Identity OIDC providers.
    pub async fn list_oidc_providers(&self) -> Result<IdentityOidcProviderList> {
        self.list_oidc_providers_with_client_id(None).await
    }

    /// Lists Identity OIDC providers available to `client_id`.
    pub async fn list_oidc_providers_for_client_id(
        &self,
        client_id: &str,
    ) -> Result<IdentityOidcProviderList> {
        if client_id.trim().is_empty() {
            return Err(Error::InvalidParameter(
                "identity OIDC provider client_id must not be empty".into(),
            ));
        }
        self.list_oidc_providers_with_client_id(Some(client_id))
            .await
    }

    /// Deletes an Identity OIDC provider.
    pub async fn delete_oidc_provider(&self, name: &str) -> Result<Empty> {
        self.delete_at(&["oidc", "provider", name]).await
    }

    /// Creates or updates an Identity OIDC scope.
    pub async fn write_oidc_scope(
        &self,
        name: &str,
        request: &IdentityOidcScopeRequest,
    ) -> Result<Empty> {
        self.request(
            Method::POST,
            &self.path(&["oidc", "scope", name])?,
            Some(request),
        )
        .await
    }

    /// Reads an Identity OIDC scope.
    pub async fn read_oidc_scope(&self, name: &str) -> Result<IdentityOidcScopeInfo> {
        let envelope: ResponseEnvelope<IdentityOidcScopeInfo> = self
            .request(
                Method::GET,
                &self.path(&["oidc", "scope", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists Identity OIDC scopes.
    pub async fn list_oidc_scopes(&self) -> Result<IdentityOidcScopeList> {
        self.list_at(&["oidc", "scope"]).await
    }

    /// Deletes an Identity OIDC scope.
    pub async fn delete_oidc_scope(&self, name: &str) -> Result<Empty> {
        self.delete_at(&["oidc", "scope", name]).await
    }

    /// Creates or updates an Identity OIDC client.
    pub async fn write_oidc_client(
        &self,
        name: &str,
        request: &IdentityOidcClientRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.request(
            Method::POST,
            &self.path(&["oidc", "client", name])?,
            Some(request),
        )
        .await
    }

    /// Reads an Identity OIDC client.
    pub async fn read_oidc_client(&self, name: &str) -> Result<IdentityOidcClientInfo> {
        let envelope: ResponseEnvelope<IdentityOidcClientInfo> = self
            .request(
                Method::GET,
                &self.path(&["oidc", "client", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists Identity OIDC clients.
    pub async fn list_oidc_clients(&self) -> Result<IdentityOidcClientList> {
        self.list_at(&["oidc", "client"]).await
    }

    /// Deletes an Identity OIDC client.
    pub async fn delete_oidc_client(&self, name: &str) -> Result<Empty> {
        self.delete_at(&["oidc", "client", name]).await
    }

    /// Creates or updates an Identity OIDC assignment.
    pub async fn write_oidc_assignment(
        &self,
        name: &str,
        request: &IdentityOidcAssignmentRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.request(
            Method::POST,
            &self.path(&["oidc", "assignment", name])?,
            Some(request),
        )
        .await
    }

    /// Reads an Identity OIDC assignment.
    pub async fn read_oidc_assignment(&self, name: &str) -> Result<IdentityOidcAssignmentInfo> {
        let envelope: ResponseEnvelope<IdentityOidcAssignmentInfo> = self
            .request(
                Method::GET,
                &self.path(&["oidc", "assignment", name])?,
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists Identity OIDC assignments.
    pub async fn list_oidc_assignments(&self) -> Result<IdentityOidcAssignmentList> {
        self.list_at(&["oidc", "assignment"]).await
    }

    /// Deletes an Identity OIDC assignment.
    pub async fn delete_oidc_assignment(&self, name: &str) -> Result<Empty> {
        self.delete_at(&["oidc", "assignment", name]).await
    }

    /// Reads OIDC discovery metadata for a named provider.
    ///
    /// The named-provider `/authorize`, `/token`, and `/userinfo` protocol
    /// flows are intentionally outside this SDK; pass this metadata to a real
    /// OIDC client library for browser-based flows.
    pub async fn read_oidc_provider_discovery(&self, name: &str) -> Result<IdentityOidcDiscovery> {
        self.request(
            Method::GET,
            &self.path(&[
                "oidc",
                "provider",
                name,
                ".well-known",
                "openid-configuration",
            ])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Reads public OIDC JSON Web Keys for a named provider.
    pub async fn read_oidc_provider_jwks(&self, name: &str) -> Result<IdentityOidcJwks> {
        self.request(
            Method::GET,
            &self.path(&["oidc", "provider", name, ".well-known", "keys"])?,
            Option::<&Empty>::None,
        )
        .await
    }

    /// Creates a Duo MFA method with a generated method ID.
    pub async fn create_mfa_duo_method(
        &self,
        request: &IdentityMfaDuoMethodRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.post_empty(&["mfa", "method", "duo"], request).await
    }

    /// Creates or updates a Duo MFA method by method ID.
    pub async fn write_mfa_duo_method(
        &self,
        method_id: &str,
        request: &IdentityMfaDuoMethodRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.post_empty(&["mfa", "method", "duo", method_id], request)
            .await
    }

    /// Reads a Duo MFA method by ID.
    pub async fn read_mfa_duo_method(&self, id: &str) -> Result<IdentityMfaDuoMethodInfo> {
        self.read_at(&["mfa", "method", "duo", id]).await
    }

    /// Deletes a Duo MFA method by ID.
    pub async fn delete_mfa_duo_method(&self, id: &str) -> Result<Empty> {
        self.delete_at(&["mfa", "method", "duo", id]).await
    }

    /// Lists Duo MFA methods.
    pub async fn list_mfa_duo_methods(&self) -> Result<IdentityMfaMethodList> {
        self.list_at(&["mfa", "method", "duo"]).await
    }

    /// Creates an Okta MFA method with a generated method ID.
    pub async fn create_mfa_okta_method(
        &self,
        request: &IdentityMfaOktaMethodRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.post_empty(&["mfa", "method", "okta"], request).await
    }

    /// Creates or updates an Okta MFA method by method ID.
    pub async fn write_mfa_okta_method(
        &self,
        method_id: &str,
        request: &IdentityMfaOktaMethodRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.post_empty(&["mfa", "method", "okta", method_id], request)
            .await
    }

    /// Reads an Okta MFA method by ID.
    pub async fn read_mfa_okta_method(&self, id: &str) -> Result<IdentityMfaOktaMethodInfo> {
        self.read_at(&["mfa", "method", "okta", id]).await
    }

    /// Deletes an Okta MFA method by ID.
    pub async fn delete_mfa_okta_method(&self, id: &str) -> Result<Empty> {
        self.delete_at(&["mfa", "method", "okta", id]).await
    }

    /// Lists Okta MFA methods.
    pub async fn list_mfa_okta_methods(&self) -> Result<IdentityMfaMethodList> {
        self.list_at(&["mfa", "method", "okta"]).await
    }

    /// Creates a PingID MFA method with a generated method ID.
    pub async fn create_mfa_pingid_method(
        &self,
        request: &IdentityMfaPingIdMethodRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.post_empty(&["mfa", "method", "pingid"], request).await
    }

    /// Creates or updates a PingID MFA method by method ID.
    pub async fn write_mfa_pingid_method(
        &self,
        method_id: &str,
        request: &IdentityMfaPingIdMethodRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.post_empty(&["mfa", "method", "pingid", method_id], request)
            .await
    }

    /// Reads a PingID MFA method by ID.
    pub async fn read_mfa_pingid_method(&self, id: &str) -> Result<IdentityMfaPingIdMethodInfo> {
        self.read_at(&["mfa", "method", "pingid", id]).await
    }

    /// Deletes a PingID MFA method by ID.
    pub async fn delete_mfa_pingid_method(&self, id: &str) -> Result<Empty> {
        self.delete_at(&["mfa", "method", "pingid", id]).await
    }

    /// Lists PingID MFA methods.
    pub async fn list_mfa_pingid_methods(&self) -> Result<IdentityMfaMethodList> {
        self.list_at(&["mfa", "method", "pingid"]).await
    }

    /// Creates a TOTP MFA method with a generated method ID.
    pub async fn create_mfa_totp_method(
        &self,
        request: &IdentityMfaTotpMethodRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.post_empty(&["mfa", "method", "totp"], request).await
    }

    /// Creates or updates a TOTP MFA method by method ID.
    pub async fn write_mfa_totp_method(
        &self,
        method_id: &str,
        request: &IdentityMfaTotpMethodRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.post_empty(&["mfa", "method", "totp", method_id], request)
            .await
    }

    /// Reads a TOTP MFA method by ID.
    pub async fn read_mfa_totp_method(&self, id: &str) -> Result<IdentityMfaTotpMethodInfo> {
        self.read_at(&["mfa", "method", "totp", id]).await
    }

    /// Deletes a TOTP MFA method by ID.
    pub async fn delete_mfa_totp_method(&self, id: &str) -> Result<Empty> {
        self.delete_at(&["mfa", "method", "totp", id]).await
    }

    /// Lists TOTP MFA methods.
    pub async fn list_mfa_totp_methods(&self) -> Result<IdentityMfaMethodList> {
        self.list_at(&["mfa", "method", "totp"]).await
    }

    /// Generates a TOTP MFA secret for the calling token entity.
    pub async fn generate_mfa_totp_secret(
        &self,
        request: &IdentityMfaTotpGenerateRequest,
    ) -> Result<IdentityMfaTotpSecret> {
        request.validate()?;
        self.post_data(&["mfa", "method", "totp", "generate"], request)
            .await
    }

    /// Administratively generates a TOTP MFA secret for an entity.
    pub async fn admin_generate_mfa_totp_secret(
        &self,
        request: &IdentityMfaTotpAdminRequest,
    ) -> Result<IdentityMfaTotpSecret> {
        request.validate()?;
        self.post_data(&["mfa", "method", "totp", "admin-generate"], request)
            .await
    }

    /// Administratively destroys a TOTP MFA secret for an entity.
    pub async fn admin_destroy_mfa_totp_secret(
        &self,
        request: &IdentityMfaTotpAdminRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.post_empty(&["mfa", "method", "totp", "admin-destroy"], request)
            .await
    }

    /// Creates or updates an MFA login enforcement.
    pub async fn write_mfa_login_enforcement(
        &self,
        name: &str,
        request: &IdentityMfaLoginEnforcementRequest,
    ) -> Result<Empty> {
        request.validate()?;
        self.post_empty(&["mfa", "login-enforcement", name], request)
            .await
    }

    /// Reads an MFA login enforcement by name.
    pub async fn read_mfa_login_enforcement(
        &self,
        name: &str,
    ) -> Result<IdentityMfaLoginEnforcementInfo> {
        self.read_at(&["mfa", "login-enforcement", name]).await
    }

    /// Deletes an MFA login enforcement by name.
    pub async fn delete_mfa_login_enforcement(&self, name: &str) -> Result<Empty> {
        self.delete_at(&["mfa", "login-enforcement", name]).await
    }

    /// Lists MFA login enforcements.
    pub async fn list_mfa_login_enforcements(&self) -> Result<IdentityMfaLoginEnforcementList> {
        self.list_at(&["mfa", "login-enforcement"]).await
    }

    async fn read_at<T>(&self, tail: &[&str]) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let envelope: ResponseEnvelope<T> = self
            .request(Method::GET, &self.path(tail)?, Option::<&Empty>::None)
            .await?;
        Ok(envelope.data)
    }

    async fn post_empty<T>(&self, tail: &[&str], request: &T) -> Result<Empty>
    where
        T: Serialize + ?Sized,
    {
        self.request(Method::POST, &self.path(tail)?, Some(request))
            .await
    }

    async fn post_data<T, U>(&self, tail: &[&str], request: &T) -> Result<U>
    where
        T: Serialize + ?Sized,
        U: serde::de::DeserializeOwned,
    {
        let envelope: ResponseEnvelope<U> = self
            .request(Method::POST, &self.path(tail)?, Some(request))
            .await?;
        Ok(envelope.data)
    }

    async fn list_at<T>(&self, tail: &[&str]) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<T> = self
            .request_query(
                method,
                &self.path(tail)?,
                &[],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    async fn list_oidc_providers_with_client_id(
        &self,
        client_id: Option<&str>,
    ) -> Result<IdentityOidcProviderList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let mut query = Vec::new();
        if let Some(client_id) = client_id {
            query.push(("allowed_client_id", client_id.to_owned()));
        }
        let envelope: ResponseEnvelope<IdentityOidcProviderList> = self
            .request_query(
                method,
                &self.path(&["oidc", "provider"])?,
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    async fn delete_at(&self, tail: &[&str]) -> Result<Empty> {
        self.request_accepting(
            Method::DELETE,
            &self.path(tail)?,
            Option::<&Empty>::None,
            &[StatusCode::OK, StatusCode::NO_CONTENT],
        )
        .await
    }

    async fn request<T, B>(&self, method: Method, path: &str, body: Option<&B>) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.client
            .request_secret_json_internal(
                "/identity/",
                "identity",
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
                "/identity/",
                "identity",
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
                "/identity/",
                "identity",
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

fn validate_string_count(count: usize, field: &'static str) -> Result<()> {
    if count <= IDENTITY_LIST_LIMIT {
        return Ok(());
    }
    Err(Error::InvalidParameter(format!(
        "{field} exceeds maximum item count"
    )))
}

fn oidc_basic_header(request: &IdentityOidcProviderTokenRequest) -> Result<HeaderValue> {
    let client_id = request.client_id.as_deref().ok_or(Error::Internal(
        "validated OIDC Basic request has no client ID",
    ))?;
    let client_secret = request.client_secret.as_ref().ok_or(Error::Internal(
        "validated OIDC Basic request has no client secret",
    ))?;
    let mut credentials = SecretVec::empty();
    append_oidc_form_component(&mut credentials, client_id);
    credentials.extend_from_slice(b":");
    append_oidc_form_component(&mut credentials, client_secret.expose_secret());
    let encoded = credentials
        .with_secret(|bytes| base64_ng::STANDARD.encode_secret(bytes))
        .map_err(|_| Error::InvalidParameter("OIDC Basic credentials are too large".into()))?;
    let exposed = encoded
        .try_into_exposed_string()
        .map_err(|_| Error::Internal("base64-ng produced invalid Basic authentication text"))?;
    let mut encoded = exposed.into_exposed_unprotected_string_caller_must_zeroize();
    let mut value = String::with_capacity("Basic ".len().saturating_add(encoded.len()));
    value.push_str("Basic ");
    value.push_str(&encoded);
    encoded.secure_sanitize();
    let result = sensitive_oidc_header(&value);
    value.secure_sanitize();
    result
}

fn oidc_bearer_header(access_token: &SecretString) -> Result<HeaderValue> {
    if access_token.expose_secret().is_empty() {
        return Err(Error::InvalidParameter(
            "identity OIDC access token must not be empty".into(),
        ));
    }
    let mut value = String::with_capacity(
        "Bearer "
            .len()
            .saturating_add(access_token.expose_secret().len()),
    );
    value.push_str("Bearer ");
    value.push_str(access_token.expose_secret());
    let result = sensitive_oidc_header(&value);
    value.secure_sanitize();
    result
}

fn sensitive_oidc_header(value: &str) -> Result<HeaderValue> {
    let mut header =
        HeaderValue::from_str(value).map_err(|error| Error::InvalidHeader(error.to_string()))?;
    header.set_sensitive(true);
    Ok(header)
}

fn append_oidc_form_component(output: &mut SecretVec, value: &str) {
    for character in url::form_urlencoded::byte_serialize(value.as_bytes()) {
        output.extend_from_slice(character.as_bytes());
    }
}

fn validate_required(value: &str, field: &'static str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::InvalidParameter(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn serialize_optional_entry<S>(
    map: &mut S,
    key: &'static str,
    value: Option<&str>,
) -> core::result::Result<(), S::Error>
where
    S: SerializeMap,
{
    if let Some(value) = value {
        map.serialize_entry(key, value)?;
    }
    Ok(())
}

fn take_optional_string<E>(
    map: &mut BTreeMap<String, JsonValue>,
    key: &'static str,
) -> core::result::Result<Option<String>, E>
where
    E: serde::de::Error,
{
    match map.remove(key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(value) => serde_json::from_value::<String>(value)
            .map(Some)
            .map_err(E::custom),
    }
}

fn take_optional_string_vec<E>(
    map: &mut BTreeMap<String, JsonValue>,
    key: &'static str,
) -> core::result::Result<Option<Vec<String>>, E>
where
    E: serde::de::Error,
{
    let Some(value) = map.remove(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let JsonValue::Array(values) = value else {
        return Err(E::custom(format!("expected array for field {key}")));
    };
    if values.len() > IDENTITY_LIST_LIMIT {
        return Err(E::custom(
            "identity OIDC discovery string list exceeds item limit",
        ));
    }
    values
        .into_iter()
        .map(serde_json::from_value::<String>)
        .collect::<core::result::Result<Vec<_>, _>>()
        .map(Some)
        .map_err(E::custom)
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
            let mut budget = JsonValueBudget::new();
            budget.take_node::<A::Error>()?;
            while values.len() < IDENTITY_LIST_LIMIT {
                let Some(value) =
                    seq.next_element_seed(BoundedJsonValueSeed::new(&mut budget, 1))?
                else {
                    return Ok(values);
                };
                values.push(value);
            }
            if seq
                .next_element_seed(RejectOverflow::new(
                    "identity OIDC JWKS key list exceeds item limit",
                ))?
                .is_some()
            {
                return Err(serde::de::Error::custom(
                    "overflow rejection seed unexpectedly accepted a value",
                ));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_option(Visitor)
}

fn deserialize_bounded_json_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, JsonValue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, JsonValue>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded JSON object")
        }

        fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            let mut budget = JsonValueBudget::new();
            budget.take_node::<A::Error>()?;
            while values.len() < IDENTITY_LIST_LIMIT {
                let Some(key) = map.next_key::<String>()? else {
                    return Ok(values);
                };
                budget.take_string::<A::Error>(key.len())?;
                let value = map.next_value_seed(BoundedJsonValueSeed::new(&mut budget, 1))?;
                if values.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom(
                        "identity OIDC JSON object contains a duplicate key",
                    ));
                }
            }
            if map
                .next_key_seed(RejectOverflow::new(
                    "identity OIDC JSON object exceeds item limit",
                ))?
                .is_some()
            {
                return Err(serde::de::Error::custom(
                    "overflow rejection seed unexpectedly accepted a key",
                ));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_map(Visitor)
}

fn deserialize_bounded_oidc_provider_info_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, IdentityOidcProviderInfo>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, IdentityOidcProviderInfo>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded Identity OIDC provider info map")
        }

        fn visit_none<E>(self) -> core::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(BTreeMap::new())
        }

        fn visit_unit<E>(self) -> core::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(BTreeMap::new())
        }

        fn visit_some<D>(self, deserializer: D) -> core::result::Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_map(self)
        }

        fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            while values.len() < IDENTITY_LIST_LIMIT {
                let Some((key, value)) = map.next_entry::<String, IdentityOidcProviderInfo>()?
                else {
                    return Ok(values);
                };
                if values.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom(
                        "identity OIDC provider info map contains a duplicate key",
                    ));
                }
            }
            if map
                .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                .is_some()
            {
                return Err(serde::de::Error::custom(
                    "identity OIDC provider info map exceeds item limit",
                ));
            }
            Ok(values)
        }
    }

    deserializer.deserialize_option(Visitor)
}

fn deserialize_bounded_oidc_client_info_map<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, IdentityOidcClientInfo>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, IdentityOidcClientInfo>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded Identity OIDC client info map")
        }

        fn visit_none<E>(self) -> core::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(BTreeMap::new())
        }

        fn visit_unit<E>(self) -> core::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(BTreeMap::new())
        }

        fn visit_some<D>(self, deserializer: D) -> core::result::Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_map(self)
        }

        fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            while values.len() < IDENTITY_LIST_LIMIT {
                let Some((key, value)) = map.next_entry::<String, IdentityOidcClientInfo>()? else {
                    return Ok(values);
                };
                if values.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom(
                        "identity OIDC client info map contains a duplicate key",
                    ));
                }
            }
            if map
                .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                .is_some()
            {
                return Err(serde::de::Error::custom(
                    "identity OIDC client info map exceeds item limit",
                ));
            }
            Ok(values)
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
        IdentityEntityMergeRequest, IdentityEntityRequest, IdentityGroupList, IdentityGroupRequest,
        IdentityMfaDuoMethodInfo, IdentityMfaDuoMethodRequest, IdentityMfaLoginEnforcementList,
        IdentityMfaLoginEnforcementRequest, IdentityMfaMethodList, IdentityMfaOktaMethodInfo,
        IdentityMfaOktaMethodRequest, IdentityMfaPingIdMethodRequest, IdentityMfaTotpSecret,
        IdentityOidcAssignmentList, IdentityOidcClientInfo, IdentityOidcClientList,
        IdentityOidcDiscovery, IdentityOidcIntrospectRequest, IdentityOidcIntrospection,
        IdentityOidcJwks, IdentityOidcKeyList, IdentityOidcProviderList, IdentityOidcRoleList,
        IdentityOidcScopeList, IdentityOidcToken,
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
    fn identity_merge_serializes_conflicting_alias_selection() {
        let request = IdentityEntityMergeRequest::new("target", ["source"])
            .keep_conflicting_aliases(["alias-a", "alias-b"]);
        let value = serde_json::to_value(request).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            value["conflicting_alias_ids_to_keep"],
            serde_json::json!(["alias-a", "alias-b"])
        );
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

        let client = IdentityOidcClientInfo {
            client_secret: Some(SecretString::from("client-secret")),
            ..IdentityOidcClientInfo::default()
        };
        let debug = format!("{client:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("client-secret"));

        let introspection =
            serde_json::from_value::<IdentityOidcIntrospection>(serde_json::json!({
                "active": true,
                "email": "private@example.com",
                "groups": ["security-admins"]
            }))
            .unwrap_or_else(|error| panic!("{error}"));
        let debug = format!("{introspection:?}");
        assert!(debug.contains("claim_count: 2"));
        assert!(!debug.contains("private@example.com"));
        assert!(!debug.contains("security-admins"));
    }

    #[test]
    fn identity_mfa_secret_debug_is_redacted_and_validated() {
        let duo = IdentityMfaDuoMethodRequest::new(
            "duo-main",
            SecretString::from("fixture-a"),
            SecretString::from("fixture-b"),
            "api.example.com",
        );
        let debug = format!("{duo:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("fixture-a"));
        assert!(!debug.contains("fixture-b"));

        let okta = IdentityMfaOktaMethodRequest::new(
            "okta-main",
            "dev-org",
            SecretString::from("fixture-c"),
        );
        let debug = format!("{okta:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("fixture-c"));

        let ping =
            IdentityMfaPingIdMethodRequest::new("ping-main", SecretString::from("fixture-d"));
        let debug = format!("{ping:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("fixture-d"));

        let duo_info = serde_json::from_value::<IdentityMfaDuoMethodInfo>(serde_json::json!({
            "secret_key": "fixture-a",
            "integration_key": "fixture-b"
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        let debug = format!("{duo_info:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("fixture-a"));
        assert!(!debug.contains("fixture-b"));

        let okta_info = serde_json::from_value::<IdentityMfaOktaMethodInfo>(serde_json::json!({
            "api_token": "fixture-c"
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        let debug = format!("{okta_info:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("fixture-c"));

        let totp_secret = serde_json::from_value::<IdentityMfaTotpSecret>(serde_json::json!({
            "barcode": "barcode-data",
            "url": "otpauth://totp/example?secret=value"
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        let debug = format!("{totp_secret:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("barcode-data"));
        assert!(!debug.contains("value"));

        assert!(
            IdentityMfaLoginEnforcementRequest::new()
                .with_mfa_method_id("totp-id")
                .validate()
                .is_err()
        );
        assert!(
            IdentityMfaLoginEnforcementRequest::new()
                .with_mfa_method_id("totp-id")
                .with_auth_method_accessor("auth-userpass")
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn identity_oidc_lists_are_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("identity-oidc-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });

        assert!(serde_json::from_value::<IdentityOidcKeyList>(value.clone()).is_err());
        assert!(serde_json::from_value::<IdentityOidcRoleList>(value.clone()).is_err());
        assert!(
            serde_json::from_value::<IdentityOidcProviderList>(serde_json::json!({
                "keys": value["keys"].clone(),
                "key_info": {}
            }))
            .is_err()
        );

        assert!(serde_json::from_value::<IdentityOidcScopeList>(value.clone()).is_err());
        assert!(serde_json::from_value::<IdentityOidcClientList>(value.clone()).is_err());
        assert!(serde_json::from_value::<IdentityOidcAssignmentList>(value).is_err());

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

        let mut key_info = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            key_info.insert(format!("client-{index}"), serde_json::json!({}));
        }
        assert!(
            serde_json::from_value::<IdentityOidcClientList>(serde_json::json!({
                "keys": [],
                "key_info": key_info
            }))
            .is_err()
        );
    }

    #[test]
    fn identity_oidc_extra_maps_are_bounded() {
        let mut extra = serde_json::Map::new();
        extra.insert("active".to_owned(), serde_json::json!(true));
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            extra.insert(format!("claim-{index}"), serde_json::json!("value"));
        }
        assert!(serde_json::from_value::<IdentityOidcIntrospection>(extra.clone().into()).is_err());
        assert!(serde_json::from_value::<IdentityOidcDiscovery>(extra.into()).is_err());

        let mut nested = serde_json::Value::Null;
        for _ in 0..=64 {
            nested = serde_json::json!([nested]);
        }
        assert!(
            serde_json::from_value::<IdentityOidcIntrospection>(serde_json::json!({
                "active": true,
                "nested": nested.clone()
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<IdentityOidcDiscovery>(serde_json::json!({
                "nested": nested
            }))
            .is_err()
        );
    }

    #[test]
    fn identity_oidc_discovery_string_lists_are_bounded() {
        let values = (0..=crate::response::MAX_RESPONSE_STRINGS)
            .map(|index| serde_json::json!(format!("claim-{index}")))
            .collect::<Vec<_>>();
        assert!(
            serde_json::from_value::<IdentityOidcDiscovery>(serde_json::json!({
                "claims_supported": values
            }))
            .is_err()
        );
    }

    #[test]
    fn identity_oidc_jwks_exact_limit_is_accepted() {
        let mut keys = Vec::new();
        for index in 0..crate::response::MAX_RESPONSE_STRINGS {
            keys.push(serde_json::json!({ "kid": format!("key-{index}") }));
        }
        let jwks = serde_json::from_value::<IdentityOidcJwks>(serde_json::json!({
            "keys": keys
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(jwks.keys.len(), crate::response::MAX_RESPONSE_STRINGS);

        let mut nested = serde_json::Value::Null;
        for _ in 0..=64 {
            nested = serde_json::json!([nested]);
        }
        assert!(
            serde_json::from_value::<IdentityOidcJwks>(serde_json::json!({
                "keys": [nested]
            }))
            .is_err()
        );
    }

    #[test]
    fn identity_oidc_jwks_rejects_overflow_before_parsing_value() {
        let mut payload = String::from("{\"keys\":[");
        for index in 0..crate::response::MAX_RESPONSE_STRINGS {
            if index != 0 {
                payload.push(',');
            }
            payload.push_str("null");
        }
        payload.push(',');
        payload.push_str(&"[".repeat(66));
        payload.push_str("null");
        payload.push_str(&"]".repeat(66));
        payload.push_str("]}");

        let error = match serde_json::from_str::<IdentityOidcJwks>(&payload) {
            Ok(_) => panic!("an excess JWKS value was accepted"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("identity OIDC JWKS key list exceeds item limit")
        );
    }

    #[test]
    fn identity_mfa_lists_are_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("identity-mfa-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });

        assert!(serde_json::from_value::<IdentityMfaMethodList>(value.clone()).is_err());
        assert!(serde_json::from_value::<IdentityMfaLoginEnforcementList>(value).is_err());
    }
}
