//! Identity secrets engine support.
//!
//! The identity engine manages OpenBao entities, groups, and aliases. These
//! helpers cover the core lifecycle endpoints and keep returned lists and
//! metadata maps bounded before allocation can grow without limit.

use std::collections::BTreeMap;

use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use crate::{
    Authenticated, Client, Error, Result,
    path::{validate_endpoint_path, validate_mount_path},
    response::{
        Empty, ListEntries, ResponseEnvelope, deserialize_bounded_string_map_or_default,
        deserialize_bounded_string_vec,
    },
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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(deprecated)]

    use secrecy::SecretString;

    use crate::{Client, OpenBaoConfig};

    use super::{
        IdentityAliasList, IdentityEntityBatchDeleteRequest, IdentityEntityList,
        IdentityEntityRequest, IdentityGroupList, IdentityGroupRequest,
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
}
