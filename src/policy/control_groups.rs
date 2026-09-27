use core::{fmt, time::Duration};

use super::{AclCapability, push_hcl_string};
use crate::{Error, Result};

const MAX_FACTORS: usize = 8;
const MAX_GROUPS: usize = 16;

fn invalid() -> Error {
    Error::InvalidParameter("invalid or oversized control-group policy requirement".into())
}

/// Identity approval factor for the narrow typed control-group policy builder.
///
/// Group names resolve within the policy's server namespace. The server must
/// verify membership; construction cannot establish that groups exist or contain
/// enough independent approvers. One entity may satisfy multiple factors.
#[derive(Clone, Eq, PartialEq)]
pub struct ControlGroupFactor {
    name: String,
    groups: Vec<String>,
    approvals: u32,
}

impl ControlGroupFactor {
    /// Creates a factor requiring 1..=128 distinct approving identities.
    ///
    /// Accepts 1..=16 unique group names (1..=128 ASCII bytes each). Names begin
    /// with an alphanumeric character and otherwise contain alphanumerics,
    /// spaces, `.`, `_` or `-`. Factor labels are 1..=64 bytes using the same
    /// alphabet. This intentionally excludes templates and HCL metacharacters;
    /// use audited opaque HCL for naming schemes outside this subset.
    pub fn new<I, S>(name: &str, groups: I, approvals: u32) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if !valid_name(name, 64) || !(1..=128).contains(&approvals) {
            return Err(invalid());
        }
        let mut names = Vec::new();
        for group in groups {
            if names.len() == MAX_GROUPS {
                return Err(invalid());
            }
            let value = group.as_ref();
            if !valid_name(value, 128) || names.iter().any(|seen| seen == value) {
                return Err(invalid());
            }
            names.push(value.to_owned());
        }
        if names.is_empty() {
            return Err(invalid());
        }
        Ok(Self {
            name: name.to_owned(),
            groups: names,
            approvals,
        })
    }
}

/// Positive TTL and bounded identity factors, with self-approval disabled.
///
/// Every factor applies to every operation granted by its rule. An entity in
/// several named groups can contribute to several factors; this does not promise
/// disjoint approver populations. Membership and policy changes remain operator
/// responsibilities. No automatic approver or self-approval option is provided.
#[derive(Clone, Eq, PartialEq)]
pub struct ControlGroupRequirement {
    ttl_seconds: u64,
    factors: Vec<ControlGroupFactor>,
}

impl ControlGroupRequirement {
    /// Requires a whole-second TTL of 1..=86400 seconds and 1..=8 factors with
    /// unique labels. These are SDK scope bounds, not OpenBao's maximum limits.
    pub fn new<I>(ttl: Duration, factors: I) -> Result<Self>
    where
        I: IntoIterator<Item = ControlGroupFactor>,
    {
        if ttl.subsec_nanos() != 0 || !(1..=86400).contains(&ttl.as_secs()) {
            return Err(invalid());
        }
        let mut checked: Vec<ControlGroupFactor> = Vec::new();
        for factor in factors {
            if checked.len() == MAX_FACTORS || checked.iter().any(|seen| seen.name == factor.name) {
                return Err(invalid());
            }
            checked.push(factor);
        }
        if checked.is_empty() {
            return Err(invalid());
        }
        Ok(Self {
            ttl_seconds: ttl.as_secs(),
            factors: checked,
        })
    }

    pub(super) fn write_hcl(&self, output: &mut String, capabilities: &[AclCapability]) {
        output.push_str("  control_group = {\n    ttl = \"");
        output.push_str(&self.ttl_seconds.to_string());
        output.push_str("s\"\n    self_auth_allowed = false\n");
        for factor in &self.factors {
            output.push_str("    factor \"");
            push_hcl_string(output, &factor.name);
            output.push_str("\" {\n      controlled_capabilities = [");
            for (index, capability) in capabilities.iter().enumerate() {
                if index != 0 {
                    output.push_str(", ");
                }
                output.push('"');
                output.push_str(capability.as_str());
                output.push('"');
            }
            output.push_str("]\n      identity {\n        group_names = [");
            for (index, name) in factor.groups.iter().enumerate() {
                if index != 0 {
                    output.push_str(", ");
                }
                output.push('"');
                push_hcl_string(output, name);
                output.push('"');
            }
            output.push_str("]\n        approvals = ");
            output.push_str(&factor.approvals.to_string());
            output.push_str("\n      }\n    }\n");
        }
        output.push_str("  }\n");
    }
}

fn valid_name(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'.' | b'_' | b'-'))
}

pub(super) fn validate_operations<I>(operations: I) -> Result<Vec<AclCapability>>
where
    I: IntoIterator<Item = AclCapability>,
{
    let mut checked = Vec::new();
    for operation in operations {
        if checked.len() == 6
            || matches!(operation, AclCapability::Deny | AclCapability::Sudo)
            || checked.contains(&operation)
        {
            return Err(invalid());
        }
        checked.push(operation);
    }
    if checked.is_empty() {
        return Err(invalid());
    }
    Ok(checked)
}

impl fmt::Debug for ControlGroupFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlGroupFactor").finish_non_exhaustive()
    }
}
impl fmt::Debug for ControlGroupRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlGroupRequirement")
            .finish_non_exhaustive()
    }
}

/// Opaque policy request accepted by `Sys::write_control_group_policy`.
///
/// Created only by `AclPolicyBuilder::build_control_group_write_request`.
/// Debug redacts policy contents. Sending through the dedicated writer requires
/// a promoted 2.7+ profile, including when newer-server fallback is enabled.
#[cfg(feature = "sys")]
pub struct ControlGroupPolicyWriteRequest {
    pub(crate) request: crate::sys::PolicyWriteRequest,
}

#[cfg(feature = "sys")]
impl fmt::Debug for ControlGroupPolicyWriteRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlGroupPolicyWriteRequest")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::policy::AclPolicyBuilder;

    fn factor(name: &str) -> ControlGroupFactor {
        ControlGroupFactor::new(name, ["operators"], 2).unwrap_or_else(|_| panic!("factor failed"))
    }

    fn requirement() -> ControlGroupRequirement {
        ControlGroupRequirement::new(Duration::from_secs(300), [factor("approval")])
            .unwrap_or_else(|_| panic!("requirement failed"))
    }

    #[test]
    fn live_fixture_uses_exact_builder_output() {
        let expected = include_str!("../../compat/onboarding/2.7.0/control-group-policy.hcl");
        for seconds in [300, 3] {
            let factors = [
                ControlGroupFactor::new("operators", ["operators"], 2),
                ControlGroupFactor::new("security", ["security"], 1),
            ]
            .into_iter()
            .map(|factor| factor.unwrap_or_else(|_| panic!("factor failed")));
            let requirement = ControlGroupRequirement::new(Duration::from_secs(seconds), factors)
                .unwrap_or_else(|_| panic!("requirement failed"));
            let mut builder = AclPolicyBuilder::new();
            builder
                .allow_path_with_control_group(
                    "fixture-kv/data/record",
                    [AclCapability::Read, AclCapability::Update],
                    requirement,
                )
                .unwrap_or_else(|_| panic!("rule failed"));
            assert_eq!(
                builder.build().unwrap_or_else(|_| panic!("render failed")),
                expected.replace("ttl = \"300s\"", &format!("ttl = \"{seconds}s\""))
            );
        }
    }

    #[test]
    fn renders_exact_parser_keys_and_explicit_operations() {
        let mut builder = AclPolicyBuilder::new();
        builder
            .allow_path_with_control_group(
                "secret/data/app",
                [AclCapability::Read, AclCapability::Update],
                requirement(),
            )
            .unwrap_or_else(|_| panic!("rule failed"));
        let document = builder.build().unwrap_or_else(|_| panic!("render failed"));
        assert_eq!(
            document,
            concat!(
                "path \"secret/data/app\" {\n",
                "  capabilities = [\"read\", \"update\"]\n",
                "  control_group = {\n",
                "    ttl = \"300s\"\n",
                "    self_auth_allowed = false\n",
                "    factor \"approval\" {\n",
                "      controlled_capabilities = [\"read\", \"update\"]\n",
                "      identity {\n",
                "        group_names = [\"operators\"]\n",
                "        approvals = 2\n",
                "      }\n",
                "    }\n",
                "  }\n",
                "}\n",
            )
        );
        #[cfg(feature = "sys")]
        {
            assert!(builder.build_write_request().is_err());
            let request = builder
                .build_control_group_write_request()
                .unwrap_or_else(|_| panic!("typed request failed"));
            assert!(request.request.policy == document);
            assert!(!format!("{request:?}").contains("operators"));
            assert!(
                AclPolicyBuilder::new()
                    .build_control_group_write_request()
                    .is_err()
            );
        }
    }

    #[test]
    fn rejects_unsafe_names_and_bounds_before_collecting() {
        for name in [
            "",
            "bad\nname",
            "bad\rname",
            "bad\tname",
            "bad\0name",
            "bad\"name",
            "bad\\name",
            "${name}",
            "%{name}",
            "{{name}}",
            "bad/name",
            "non-ascii-\u{e9}",
        ] {
            assert!(ControlGroupFactor::new(name, ["operators"], 1).is_err());
            assert!(ControlGroupFactor::new("label", [name], 1).is_err());
        }
        for approvals in [0, 129, u32::MAX] {
            assert!(ControlGroupFactor::new("label", ["operators"], approvals).is_err());
        }
        for approvals in [1, 128] {
            assert!(
                ControlGroupFactor::new(&"x".repeat(64), [&"g".repeat(128)], approvals).is_ok()
            );
        }
        assert!(ControlGroupFactor::new(&"x".repeat(65), ["group"], 1).is_err());
        assert!(ControlGroupFactor::new("label", [&"x".repeat(129)], 1).is_err());
        assert!(ControlGroupFactor::new("label", core::iter::empty::<&str>(), 1).is_err());
        assert!(ControlGroupFactor::new("label", ["same", "same"], 1).is_err());
        assert!(
            ControlGroupFactor::new("label", (0..MAX_GROUPS).map(|i| format!("group-{i}")), 1)
                .is_ok()
        );
        let mut visited = 0;
        assert!(
            ControlGroupFactor::new(
                "label",
                (0..).map(|i| {
                    visited += 1;
                    format!("group-{i}")
                }),
                1
            )
            .is_err()
        );
        assert_eq!(visited, MAX_GROUPS + 1);
    }

    #[test]
    fn ttl_and_factor_limits_are_explicit() {
        for ttl in [
            Duration::ZERO,
            Duration::from_millis(1),
            Duration::from_millis(1500),
            Duration::from_secs(86401),
            Duration::MAX,
        ] {
            assert!(ControlGroupRequirement::new(ttl, [factor("approval")]).is_err());
        }
        for ttl in [1, 86400] {
            assert!(
                ControlGroupRequirement::new(
                    Duration::from_secs(ttl),
                    (0..MAX_FACTORS).map(|i| factor(&format!("factor-{i}")))
                )
                .is_ok()
            );
        }
        assert!(ControlGroupRequirement::new(Duration::from_secs(1), []).is_err());
        assert!(
            ControlGroupRequirement::new(Duration::from_secs(1), [factor("same"), factor("same")])
                .is_err()
        );
        let mut visited = 0;
        assert!(
            ControlGroupRequirement::new(
                Duration::from_secs(1),
                (0..).map(|i| {
                    visited += 1;
                    factor(&format!("factor-{i}"))
                })
            )
            .is_err()
        );
        assert_eq!(visited, MAX_FACTORS + 1);
        assert!(
            !format!("{:?} {:?}", factor("private-label"), requirement()).contains("private-label")
        );
    }

    #[test]
    fn failed_rules_are_atomic_and_collisions_fail_in_both_orders() {
        let mut builder = AclPolicyBuilder::new();
        builder
            .allow_path("unrelated/path", [AclCapability::Read])
            .unwrap_or_else(|_| panic!("rule failed"));
        let before = builder.clone();
        for capabilities in [
            vec![],
            vec![AclCapability::Sudo],
            vec![AclCapability::Deny],
            vec![AclCapability::Read; 2],
        ] {
            assert!(
                builder
                    .allow_path_with_control_group("secret/path", capabilities, requirement())
                    .is_err()
            );
            assert_eq!(builder, before);
        }
        assert!(
            builder
                .allow_path_with_control_group(
                    "unrelated/path",
                    [AclCapability::Read],
                    requirement()
                )
                .is_err()
        );
        assert!(
            builder
                .allow_path_with_control_group("../path", [AclCapability::Read], requirement())
                .is_err()
        );
        assert_eq!(builder, before);
        builder
            .allow_path_with_control_group("secret/path", [AclCapability::Read], requirement())
            .unwrap_or_else(|_| panic!("rule failed"));
        let before = builder.clone();
        assert!(
            builder
                .allow_path("secret/path", [AclCapability::Read])
                .is_err()
        );
        assert!(
            builder
                .allow_path_with_wrapping("secret/path", [AclCapability::Read], Some("1m"), None)
                .is_err()
        );
        assert_eq!(builder, before);
        assert!(
            validate_operations([
                AclCapability::Create,
                AclCapability::Read,
                AclCapability::Update,
                AclCapability::Delete,
                AclCapability::List,
                AclCapability::Patch
            ])
            .is_ok()
        );
    }

    #[test]
    fn document_and_rule_limits_still_apply() {
        let mut builder = AclPolicyBuilder::new();
        for i in 0..super::super::MAX_POLICY_RULES {
            builder
                .allow_path_with_control_group(
                    format!("secret/path-{i}"),
                    [AclCapability::Read],
                    requirement(),
                )
                .unwrap_or_else(|_| panic!("rule failed"));
        }
        let before = builder.clone();
        assert!(
            builder
                .allow_path_with_control_group(
                    "secret/overflow",
                    [AclCapability::Read],
                    requirement()
                )
                .is_err()
        );
        assert_eq!(builder, before);
        assert!(builder.build().is_err());
    }
}
