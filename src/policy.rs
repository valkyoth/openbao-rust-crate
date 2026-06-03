//! Helpers for building small OpenBao ACL policy documents.
//!
//! The builder intentionally supports a narrow, typed subset of ACL policy HCL:
//! path rules with known OpenBao capabilities. Use [`crate::sys::PolicyWriteRequest`]
//! directly for advanced policy features such as parameter constraints.

use core::fmt;

use crate::{
    Error, Result,
    path::{validate_endpoint_path, validate_mount_path},
};

const MAX_POLICY_RULES: usize = 128;
const MAX_POLICY_BYTES: usize = 16 * 1024;

/// OpenBao ACL capabilities supported by [`AclPolicyBuilder`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AclCapability {
    /// Allows creation when the key does not already exist.
    Create,
    /// Allows reading existing values or metadata.
    Read,
    /// Allows updating existing values.
    Update,
    /// Allows deleting values.
    Delete,
    /// Allows listing path children.
    List,
    /// Allows patch-style partial updates.
    Patch,
    /// Allows privileged system operations on paths that require sudo.
    Sudo,
    /// Denies access. Must not be mixed with other capabilities in one rule.
    Deny,
}

impl AclCapability {
    fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Patch => "patch",
            Self::Sudo => "sudo",
            Self::Deny => "deny",
        }
    }
}

impl fmt::Display for AclCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AclRule {
    path: String,
    capabilities: Vec<AclCapability>,
}

/// Builder for bounded, typed OpenBao ACL policy documents.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AclPolicyBuilder {
    rules: Vec<AclRule>,
}

impl AclPolicyBuilder {
    /// Creates an empty ACL policy builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a path rule with explicit capabilities.
    ///
    /// The path is validated with the same traversal and URL-injection checks
    /// used by request paths. Wildcard segments such as `*` and `+` are allowed
    /// for ACL policy use.
    pub fn allow_path<I>(&mut self, path: impl AsRef<str>, capabilities: I) -> Result<&mut Self>
    where
        I: IntoIterator<Item = AclCapability>,
    {
        self.push_rule(path.as_ref(), capabilities)
    }

    /// Adds a deny rule for a path.
    pub fn deny_path(&mut self, path: impl AsRef<str>) -> Result<&mut Self> {
        self.push_rule(path.as_ref(), [AclCapability::Deny])
    }

    /// Allows KV v2 read/list access below a literal prefix.
    ///
    /// For `mount = "secret"` and `prefix = "app"`, this emits rules for
    /// `secret/data/app/*` and `secret/metadata/app/*`. The metadata rule is
    /// list-only so read-only secret policies do not automatically expose
    /// version history or custom metadata; add an explicit metadata `Read`
    /// rule with [`AclPolicyBuilder::allow_path`] when that is desired.
    pub fn allow_kv2_read_prefix(
        &mut self,
        mount: impl AsRef<str>,
        prefix: impl AsRef<str>,
    ) -> Result<&mut Self> {
        let data_path = prefixed_engine_path(mount.as_ref(), "data", prefix.as_ref())?;
        let metadata_path = prefixed_engine_path(mount.as_ref(), "metadata", prefix.as_ref())?;
        self.push_rule(&data_path, [AclCapability::Read])?;
        self.push_rule(&metadata_path, [AclCapability::List])
    }

    /// Allows KV v2 read/write/list/delete access below a literal prefix.
    pub fn allow_kv2_read_write_prefix(
        &mut self,
        mount: impl AsRef<str>,
        prefix: impl AsRef<str>,
    ) -> Result<&mut Self> {
        let data_path = prefixed_engine_path(mount.as_ref(), "data", prefix.as_ref())?;
        let metadata_path = prefixed_engine_path(mount.as_ref(), "metadata", prefix.as_ref())?;
        self.push_rule(
            &data_path,
            [
                AclCapability::Create,
                AclCapability::Read,
                AclCapability::Update,
                AclCapability::Patch,
                AclCapability::Delete,
            ],
        )?;
        self.push_rule(
            &metadata_path,
            [
                AclCapability::Read,
                AclCapability::Update,
                AclCapability::Delete,
                AclCapability::List,
            ],
        )
    }

    /// Allows Transit encrypt/decrypt access for one key.
    pub fn allow_transit_encrypt_decrypt(
        &mut self,
        mount: impl AsRef<str>,
        key: impl AsRef<str>,
    ) -> Result<&mut Self> {
        self.push_rule(
            &engine_key_path(mount.as_ref(), "encrypt", key.as_ref())?,
            [AclCapability::Update],
        )?;
        self.push_rule(
            &engine_key_path(mount.as_ref(), "decrypt", key.as_ref())?,
            [AclCapability::Update],
        )
    }

    /// Allows Transit sign/verify access for one key.
    pub fn allow_transit_sign_verify(
        &mut self,
        mount: impl AsRef<str>,
        key: impl AsRef<str>,
    ) -> Result<&mut Self> {
        self.push_rule(
            &engine_key_path(mount.as_ref(), "sign", key.as_ref())?,
            [AclCapability::Update],
        )?;
        self.push_rule(
            &engine_key_path(mount.as_ref(), "verify", key.as_ref())?,
            [AclCapability::Update],
        )
    }

    /// Renders the policy document.
    pub fn build(&self) -> Result<String> {
        let mut document = String::new();
        for rule in &self.rules {
            push_rule(&mut document, rule);
            if document.len() > MAX_POLICY_BYTES {
                return Err(Error::InvalidParameter(
                    "ACL policy document exceeds maximum allowed length".into(),
                ));
            }
        }
        Ok(document)
    }

    #[cfg(feature = "sys")]
    /// Renders the policy as a sys policy write request.
    pub fn build_write_request(&self) -> Result<crate::sys::PolicyWriteRequest> {
        Ok(crate::sys::PolicyWriteRequest::new(self.build()?))
    }

    fn push_rule<I>(&mut self, path: &str, capabilities: I) -> Result<&mut Self>
    where
        I: IntoIterator<Item = AclCapability>,
    {
        if self.rules.len() >= MAX_POLICY_RULES {
            return Err(Error::InvalidParameter(
                "ACL policy rule count exceeds maximum allowed length".into(),
            ));
        }
        let capabilities = validate_capabilities(capabilities)?;
        let path = validate_policy_path(path)?;
        self.rules.push(AclRule { path, capabilities });
        Ok(self)
    }
}

fn validate_capabilities<I>(capabilities: I) -> Result<Vec<AclCapability>>
where
    I: IntoIterator<Item = AclCapability>,
{
    let capabilities = capabilities.into_iter().collect::<Vec<_>>();
    if capabilities.is_empty() {
        return Err(Error::InvalidParameter(
            "ACL policy rule must include at least one capability".into(),
        ));
    }
    if capabilities.contains(&AclCapability::Deny) && capabilities.len() > 1 {
        return Err(Error::InvalidParameter(
            "ACL deny capability must not be mixed with other capabilities".into(),
        ));
    }
    Ok(capabilities)
}

fn validate_policy_path(path: &str) -> Result<String> {
    Ok(validate_mount_path(path)?.join("/"))
}

fn validate_literal_path(path: &str) -> Result<Vec<String>> {
    validate_literal_segments(validate_endpoint_path(path)?)
}

fn validate_literal_mount_path(path: &str) -> Result<Vec<String>> {
    validate_literal_segments(validate_mount_path(path)?)
}

fn validate_literal_segments(segments: Vec<String>) -> Result<Vec<String>> {
    if segments
        .iter()
        .any(|segment| segment.contains('*') || segment.contains('+'))
    {
        return Err(Error::InvalidPath(
            "helper-generated ACL paths require literal mount, prefix, and key values".into(),
        ));
    }
    Ok(segments)
}

fn prefixed_engine_path(mount: &str, endpoint: &str, prefix: &str) -> Result<String> {
    let mut segments = validate_literal_mount_path(mount)?;
    segments.push(endpoint.to_owned());
    segments.extend(validate_literal_path(prefix)?);
    segments.push("*".to_owned());
    Ok(segments.join("/"))
}

fn engine_key_path(mount: &str, endpoint: &str, key: &str) -> Result<String> {
    let mut segments = validate_literal_mount_path(mount)?;
    segments.push(endpoint.to_owned());
    segments.extend(validate_literal_mount_path(key)?);
    Ok(segments.join("/"))
}

fn push_rule(document: &mut String, rule: &AclRule) {
    document.push_str("path \"");
    push_hcl_string(document, &rule.path);
    document.push_str("\" {\n  capabilities = [");
    for (index, capability) in rule.capabilities.iter().enumerate() {
        if index > 0 {
            document.push_str(", ");
        }
        document.push('"');
        document.push_str(capability.as_str());
        document.push('"');
    }
    document.push_str("]\n}\n");
}

fn push_hcl_string(output: &mut String, value: &str) {
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '$' if characters.peek() == Some(&'{') => {
                characters.next();
                output.push_str("$${");
            }
            '%' if characters.peek() == Some(&'{') => {
                characters.next();
                output.push_str("%%{");
            }
            _ => output.push(character),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::{AclCapability, AclPolicyBuilder};

    #[test]
    fn builds_kv2_prefix_policy() {
        let mut builder = AclPolicyBuilder::new();
        let result = builder
            .allow_kv2_read_prefix("secret", "app")
            .and_then(|builder| builder.build());
        let policy = match result {
            Ok(policy) => policy,
            Err(error) => panic!("{error}"),
        };

        assert!(policy.contains("path \"secret/data/app/*\""));
        assert!(policy.contains("path \"secret/metadata/app/*\""));
        assert!(policy.contains("capabilities = [\"read\"]"));
        assert!(policy.contains("capabilities = [\"list\"]"));
    }

    #[test]
    fn policy_hcl_strings_escape_template_sequences() {
        let mut builder = AclPolicyBuilder::new();
        let policy = builder
            .allow_path("secret/data/app-${env}/%{literal}", [AclCapability::Read])
            .and_then(|builder| builder.build())
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(policy.contains(r#"secret/data/app-$${env}/%%{literal}"#));
    }

    #[test]
    fn rejects_deny_mixed_with_other_capabilities() {
        let mut builder = AclPolicyBuilder::new();
        assert!(
            builder
                .allow_path(
                    "secret/data/app/*",
                    [AclCapability::Deny, AclCapability::Read]
                )
                .is_err()
        );
    }

    #[test]
    fn raw_policy_paths_are_escaped() {
        let mut builder = AclPolicyBuilder::new();
        let result = builder
            .allow_path("secret/data/app\"name", [AclCapability::Read])
            .and_then(|builder| builder.build());
        let policy = match result {
            Ok(policy) => policy,
            Err(error) => panic!("{error}"),
        };

        assert!(policy.contains("path \"secret/data/app\\\"name\""));
    }

    #[test]
    fn helper_paths_reject_wildcard_inputs() {
        let mut builder = AclPolicyBuilder::new();
        assert!(builder.allow_kv2_read_prefix("secret", "app/*").is_err());
    }
}
