//! OpenBao server-version compatibility value types.
//!
//! These types model stable OpenBao releases. They deliberately reject
//! prerelease and build metadata so a compatibility profile always selects an
//! exact reviewed server release.
//!
//! This module also exposes a generated read-only registry of secret-free route
//! templates across the 21 locked OpenBao releases plus the staged 2.6.0
//! profile. Registry evidence reports what exact tagged documentation contains.
//! Staged profiles are available for capability introspection but cannot drive
//! policy verification or runtime dispatch until their security contract is
//! promoted. Client compatibility policies can verify and cache the stable
//! version returned by `/sys/health`, or explicitly select an assumed promoted
//! profile where probing is unavailable. The internal typed dispatcher binds
//! logical SDK endpoints to reviewed operation variants; endpoint families
//! adopt that dispatcher in the ordered migration commits.

use core::{fmt, str::FromStr};

use crate::{Error, Result};

const MAX_VERSION_BYTES: usize = 64;
const MAX_REQUIREMENT_BYTES: usize = (MAX_VERSION_BYTES * 2) + 3;

/// High-level compatibility policy selected for one client instance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OpenBaoCompatibilityPolicy {
    value: OpenBaoCompatibilityPolicyValue,
}

/// Public classification of an OpenBao compatibility policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum OpenBaoCompatibilityPolicyKind {
    /// Detect the server and require one exact runtime-approved release.
    Exact,
    /// Detect the server and require a release inside one approved closed range.
    Range,
    /// Detect the server and require any exact runtime-approved release.
    AutomaticStrict,
    /// Select one exact runtime-approved profile without querying the server.
    Assumed,
    /// Detect the server and explicitly tolerate a version newer than the registry.
    AcknowledgedUnknownNewer,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum OpenBaoCompatibilityPolicyValue {
    Exact(OpenBaoVersion),
    Range(OpenBaoVersionRequirement),
    AutomaticStrict,
    Assumed(OpenBaoVersion),
    AcknowledgedUnknownNewer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpenBaoCompatibilityFailure {
    VersionMismatch {
        detected: OpenBaoVersion,
        requirement: OpenBaoVersionRequirement,
    },
    UnknownVersion(OpenBaoVersion),
}

/// Explicit acknowledgement required to tolerate an unknown newer server.
///
/// This policy uses the newest reviewed compatibility profile when the server
/// reports a later stable version. It cannot prove that removed or changed
/// operations remain compatible. Prefer strict mode and add a reviewed release
/// profile instead.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UnknownNewerOpenBaoAcknowledgement(());

impl UnknownNewerOpenBaoAcknowledgement {
    /// Acknowledges the compatibility risk of using the newest known profile.
    #[must_use]
    pub const fn acknowledge() -> Self {
        Self(())
    }
}

/// Verification state reported for one client instance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum OpenBaoCompatibilityStatus {
    /// No compatibility policy was selected and no server version was checked.
    Unverified,
    /// The server version was detected and matched a runtime-approved profile.
    Verified,
    /// A runtime-approved profile was explicitly selected without a server probe.
    Assumed,
    /// A newer server was detected and the caller acknowledged using the latest profile.
    AcknowledgedUnknownNewer,
}

/// Secret-free compatibility result for one client instance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OpenBaoCompatibilityReport {
    status: OpenBaoCompatibilityStatus,
    policy: Option<OpenBaoCompatibilityPolicyKind>,
    requirement: Option<OpenBaoVersionRequirement>,
    detected_version: Option<OpenBaoVersion>,
    profile_version: Option<OpenBaoVersion>,
}

impl OpenBaoCompatibilityReport {
    /// Verification state for this report.
    pub const fn status(self) -> OpenBaoCompatibilityStatus {
        self.status
    }

    /// Selected policy classification, or `None` for an unverified client.
    pub const fn policy(self) -> Option<OpenBaoCompatibilityPolicyKind> {
        self.policy
    }

    /// Exact or closed version requirement selected by the policy, when applicable.
    pub const fn requirement(self) -> Option<OpenBaoVersionRequirement> {
        self.requirement
    }

    /// Stable version returned by `/sys/health`, when a probe was performed.
    pub const fn detected_version(self) -> Option<OpenBaoVersion> {
        self.detected_version
    }

    /// Exact immutable profile selected for request compatibility decisions.
    pub const fn profile_version(self) -> Option<OpenBaoVersion> {
        self.profile_version
    }

    pub(crate) const fn unverified() -> Self {
        Self {
            status: OpenBaoCompatibilityStatus::Unverified,
            policy: None,
            requirement: None,
            detected_version: None,
            profile_version: None,
        }
    }

    pub(crate) const fn verified(
        policy: OpenBaoCompatibilityPolicyKind,
        detected_version: OpenBaoVersion,
        requirement: Option<OpenBaoVersionRequirement>,
    ) -> Self {
        Self {
            status: OpenBaoCompatibilityStatus::Verified,
            policy: Some(policy),
            requirement,
            detected_version: Some(detected_version),
            profile_version: Some(detected_version),
        }
    }

    pub(crate) const fn assumed(version: OpenBaoVersion) -> Self {
        Self {
            status: OpenBaoCompatibilityStatus::Assumed,
            policy: Some(OpenBaoCompatibilityPolicyKind::Assumed),
            requirement: Some(OpenBaoVersionRequirement::exact(version)),
            detected_version: None,
            profile_version: Some(version),
        }
    }

    pub(crate) const fn acknowledged_unknown_newer(
        detected_version: OpenBaoVersion,
        profile_version: OpenBaoVersion,
    ) -> Self {
        Self {
            status: OpenBaoCompatibilityStatus::AcknowledgedUnknownNewer,
            policy: Some(OpenBaoCompatibilityPolicyKind::AcknowledgedUnknownNewer),
            requirement: None,
            detected_version: Some(detected_version),
            profile_version: Some(profile_version),
        }
    }
}

/// Exact stable OpenBao server version.
///
/// Text parsing accepts only canonical `major.minor.patch` syntax with ASCII
/// decimal components. Prefixes such as `v`, leading zeroes, whitespace,
/// prerelease identifiers, and build metadata are rejected.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OpenBaoVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl OpenBaoVersion {
    /// Creates an exact stable version from numeric components.
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Major version component.
    pub const fn major(self) -> u32 {
        self.major
    }

    /// Minor version component.
    pub const fn minor(self) -> u32 {
        self.minor
    }

    /// Patch version component.
    pub const fn patch(self) -> u32 {
        self.patch
    }
}

impl fmt::Display for OpenBaoVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for OpenBaoVersion {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(invalid_version("version must not be empty"));
        }
        if input.len() > MAX_VERSION_BYTES {
            return Err(invalid_version("version exceeds the input limit"));
        }
        if !input.is_ascii() {
            return Err(invalid_version(
                "version must contain only ASCII digits and dots",
            ));
        }

        let mut components = input.split('.');
        let major = components
            .next()
            .ok_or_else(|| invalid_version("version must contain three components"))?;
        let minor = components
            .next()
            .ok_or_else(|| invalid_version("version must contain three components"))?;
        let patch = components
            .next()
            .ok_or_else(|| invalid_version("version must contain three components"))?;
        if components.next().is_some() {
            return Err(invalid_version("version must contain three components"));
        }

        Ok(Self::new(
            parse_component(major)?,
            parse_component(minor)?,
            parse_component(patch)?,
        ))
    }
}

/// Permitted OpenBao server version or inclusive rolling-upgrade range.
///
/// String parsing accepts either an exact version such as `2.5.5` or a closed
/// range such as `2.4.0..=2.5.5`. Open-ended ranges are intentionally not
/// supported because they cannot provide a fail-closed compatibility bound.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OpenBaoVersionRequirement {
    /// One exact OpenBao release.
    Exact(OpenBaoVersion),
    /// Closed range including both endpoints.
    Inclusive {
        /// Oldest permitted release.
        minimum: OpenBaoVersion,
        /// Newest permitted release.
        maximum: OpenBaoVersion,
    },
}

impl OpenBaoVersionRequirement {
    /// Requires one exact OpenBao release.
    pub const fn exact(version: OpenBaoVersion) -> Self {
        Self::Exact(version)
    }

    /// Requires a non-empty inclusive release range.
    pub fn inclusive(minimum: OpenBaoVersion, maximum: OpenBaoVersion) -> Result<Self> {
        if minimum > maximum {
            return Err(invalid_requirement(
                "minimum version must not exceed maximum version",
            ));
        }
        Ok(Self::Inclusive { minimum, maximum })
    }

    /// Oldest version accepted by this requirement.
    pub const fn minimum(self) -> OpenBaoVersion {
        match self {
            Self::Exact(version) => version,
            Self::Inclusive { minimum, .. } => minimum,
        }
    }

    /// Newest version accepted by this requirement.
    pub const fn maximum(self) -> OpenBaoVersion {
        match self {
            Self::Exact(version) => version,
            Self::Inclusive { maximum, .. } => maximum,
        }
    }

    /// Returns whether `version` is inside the permitted closed range.
    pub fn contains(self, version: OpenBaoVersion) -> bool {
        version_in_closed_interval(version, self.minimum(), self.maximum())
    }
}

pub(crate) fn version_in_closed_interval(
    version: OpenBaoVersion,
    minimum: OpenBaoVersion,
    maximum: OpenBaoVersion,
) -> bool {
    version >= minimum && version <= maximum
}

impl fmt::Display for OpenBaoVersionRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(version) => version.fmt(formatter),
            Self::Inclusive { minimum, maximum } => {
                write!(formatter, "{minimum}..={maximum}")
            }
        }
    }
}

impl FromStr for OpenBaoVersionRequirement {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(invalid_requirement("requirement must not be empty"));
        }
        if input.len() > MAX_REQUIREMENT_BYTES {
            return Err(invalid_requirement("requirement exceeds the input limit"));
        }

        if let Some((minimum, maximum)) = input.split_once("..=") {
            if minimum.is_empty() || maximum.is_empty() || maximum.contains("..=") {
                return Err(invalid_requirement(
                    "requirement must be an exact version or one inclusive range",
                ));
            }
            return Self::inclusive(
                parse_requirement_version(minimum)?,
                parse_requirement_version(maximum)?,
            );
        }

        Ok(Self::exact(parse_requirement_version(input)?))
    }
}

impl OpenBaoCompatibilityPolicy {
    /// Detects the server and requires one exact runtime-approved release.
    pub fn exact(version: OpenBaoVersion) -> Result<Self> {
        require_routable_profile(version)?;
        Ok(Self {
            value: OpenBaoCompatibilityPolicyValue::Exact(version),
        })
    }

    /// Detects the server and requires a version inside an approved closed range.
    ///
    /// Both range endpoints must be exact releases in the runtime-approved inventory.
    pub fn range(requirement: OpenBaoVersionRequirement) -> Result<Self> {
        require_routable_profile(requirement.minimum())?;
        require_routable_profile(requirement.maximum())?;
        Ok(Self {
            value: OpenBaoCompatibilityPolicyValue::Range(requirement),
        })
    }

    /// Detects the server and rejects versions absent from the approved inventory.
    #[must_use]
    pub const fn automatic_strict() -> Self {
        Self {
            value: OpenBaoCompatibilityPolicyValue::AutomaticStrict,
        }
    }

    /// Selects one runtime-approved profile without querying `/sys/health`.
    ///
    /// Reports produced by this policy are always marked `Assumed`, never
    /// `Verified`. Use this only where an authenticated proxy blocks the public
    /// health endpoint and deployment configuration supplies the exact version.
    pub fn assume(version: OpenBaoVersion) -> Result<Self> {
        require_routable_profile(version)?;
        Ok(Self {
            value: OpenBaoCompatibilityPolicyValue::Assumed(version),
        })
    }

    /// Detects the server and tolerates versions newer than the approved inventory.
    ///
    /// Unknown older versions and unpublished versions inside the approved
    /// range still fail closed. Newer versions select the latest promoted
    /// profile and are reported as acknowledged rather than verified.
    #[must_use]
    pub const fn automatic_allow_unknown_newer(
        _acknowledgement: UnknownNewerOpenBaoAcknowledgement,
    ) -> Self {
        Self {
            value: OpenBaoCompatibilityPolicyValue::AcknowledgedUnknownNewer,
        }
    }

    /// Public classification of this policy.
    pub const fn kind(self) -> OpenBaoCompatibilityPolicyKind {
        match self.value {
            OpenBaoCompatibilityPolicyValue::Exact(_) => OpenBaoCompatibilityPolicyKind::Exact,
            OpenBaoCompatibilityPolicyValue::Range(_) => OpenBaoCompatibilityPolicyKind::Range,
            OpenBaoCompatibilityPolicyValue::AutomaticStrict => {
                OpenBaoCompatibilityPolicyKind::AutomaticStrict
            }
            OpenBaoCompatibilityPolicyValue::Assumed(_) => OpenBaoCompatibilityPolicyKind::Assumed,
            OpenBaoCompatibilityPolicyValue::AcknowledgedUnknownNewer => {
                OpenBaoCompatibilityPolicyKind::AcknowledgedUnknownNewer
            }
        }
    }

    /// Exact or closed version requirement carried by this policy.
    pub const fn requirement(self) -> Option<OpenBaoVersionRequirement> {
        match self.value {
            OpenBaoCompatibilityPolicyValue::Exact(version)
            | OpenBaoCompatibilityPolicyValue::Assumed(version) => {
                Some(OpenBaoVersionRequirement::exact(version))
            }
            OpenBaoCompatibilityPolicyValue::Range(requirement) => Some(requirement),
            OpenBaoCompatibilityPolicyValue::AutomaticStrict
            | OpenBaoCompatibilityPolicyValue::AcknowledgedUnknownNewer => None,
        }
    }

    pub(crate) fn immediate_report(self) -> Option<OpenBaoCompatibilityReport> {
        match self.value {
            OpenBaoCompatibilityPolicyValue::Assumed(version) => {
                Some(OpenBaoCompatibilityReport::assumed(version))
            }
            _ => None,
        }
    }

    pub(crate) fn evaluate_detected(
        self,
        detected: OpenBaoVersion,
    ) -> core::result::Result<OpenBaoCompatibilityReport, OpenBaoCompatibilityFailure> {
        match self.value {
            OpenBaoCompatibilityPolicyValue::Exact(expected) => {
                if detected != expected {
                    return Err(OpenBaoCompatibilityFailure::VersionMismatch {
                        detected,
                        requirement: OpenBaoVersionRequirement::exact(expected),
                    });
                }
                Ok(OpenBaoCompatibilityReport::verified(
                    self.kind(),
                    detected,
                    self.requirement(),
                ))
            }
            OpenBaoCompatibilityPolicyValue::Range(requirement) => {
                if !requirement.contains(detected) {
                    return Err(OpenBaoCompatibilityFailure::VersionMismatch {
                        detected,
                        requirement,
                    });
                }
                if !is_routable_profile(detected) {
                    return Err(OpenBaoCompatibilityFailure::UnknownVersion(detected));
                }
                Ok(OpenBaoCompatibilityReport::verified(
                    self.kind(),
                    detected,
                    self.requirement(),
                ))
            }
            OpenBaoCompatibilityPolicyValue::AutomaticStrict => {
                if !is_routable_profile(detected) {
                    return Err(OpenBaoCompatibilityFailure::UnknownVersion(detected));
                }
                Ok(OpenBaoCompatibilityReport::verified(
                    self.kind(),
                    detected,
                    self.requirement(),
                ))
            }
            OpenBaoCompatibilityPolicyValue::Assumed(version) => {
                Ok(OpenBaoCompatibilityReport::assumed(version))
            }
            OpenBaoCompatibilityPolicyValue::AcknowledgedUnknownNewer => {
                if is_routable_profile(detected) {
                    return Ok(OpenBaoCompatibilityReport::verified(
                        self.kind(),
                        detected,
                        self.requirement(),
                    ));
                }
                let Some(latest) = latest_routable_profile() else {
                    return Err(OpenBaoCompatibilityFailure::UnknownVersion(detected));
                };
                if detected > latest {
                    return Ok(OpenBaoCompatibilityReport::acknowledged_unknown_newer(
                        detected, latest,
                    ));
                }
                Err(OpenBaoCompatibilityFailure::UnknownVersion(detected))
            }
        }
    }
}

/// HTTP or protocol method recorded for a documented OpenBao operation.
///
/// `Acme` and `Scan` are documentation-level protocol operations rather than
/// methods accepted by `reqwest::Method`. This registry reports evidence only;
/// it does not transmit requests.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OpenBaoHttpMethod {
    /// ACME protocol flow rooted at an OpenBao directory URL.
    Acme,
    /// HTTP `DELETE`.
    Delete,
    /// HTTP `GET`.
    Get,
    /// HTTP `HEAD`.
    Head,
    /// OpenBao `LIST` method.
    List,
    /// HTTP `PATCH`.
    Patch,
    /// HTTP `POST`.
    Post,
    /// HTTP `PUT`.
    Put,
    /// OpenBao `SCAN` method.
    Scan,
}

impl OpenBaoHttpMethod {
    /// Returns the documented method spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Acme => "ACME",
            Self::Delete => "DELETE",
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::List => "LIST",
            Self::Patch => "PATCH",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Scan => "SCAN",
        }
    }
}

/// Current crate implementation disposition attached to a stable operation identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OpenBaoOperationDisposition {
    /// The operation has an ungated typed helper.
    Typed,
    /// The operation has a typed helper behind its documented feature gate.
    TypedGated,
    /// Crate security policy blocks this operation regardless of server documentation.
    SecurityBlocked,
}

/// Immutable evidence supporting one exact-release capability range.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OpenBaoCapabilityEvidence {
    /// The route is not documented in this exact-release range.
    None,
    /// The route appears in exact tagged OpenBao API documentation.
    TaggedDocumentation,
    /// The route appears in an immutable exact-release OpenAPI snapshot.
    LockedOpenApi,
    /// The route is present in the corrected exact 2.5.5 contract extraction.
    CorrectedCurrentContract,
}

/// SDK reporting result for one operation on one exact compatibility profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OpenBaoCapabilityAvailability {
    /// Exact tagged evidence documents the route. This does not by itself prove SDK support.
    DocumentedRoute,
    /// The route is not documented for this exact locked release.
    NotDocumented,
    /// The server documents the route, but crate security policy blocks its use.
    SecurityBlocked,
}

/// One complete, non-overlapping exact-release range for an operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OpenBaoCapabilityRange {
    minimum: OpenBaoVersion,
    maximum: OpenBaoVersion,
    evidence: OpenBaoCapabilityEvidence,
}

impl OpenBaoCapabilityRange {
    pub(crate) const fn generated(
        minimum: OpenBaoVersion,
        maximum: OpenBaoVersion,
        evidence: OpenBaoCapabilityEvidence,
    ) -> Self {
        Self {
            minimum,
            maximum,
            evidence,
        }
    }

    /// Oldest exact release covered by this range.
    pub const fn minimum(self) -> OpenBaoVersion {
        self.minimum
    }

    /// Newest exact release covered by this range.
    pub const fn maximum(self) -> OpenBaoVersion {
        self.maximum
    }

    /// Evidence attached to this range.
    pub const fn evidence(self) -> OpenBaoCapabilityEvidence {
        self.evidence
    }

    fn contains(self, version: OpenBaoVersion) -> bool {
        version_in_closed_interval(version, self.minimum, self.maximum)
    }
}

/// Stable, secret-free identity and route template for one OpenBao operation.
///
/// Path values are documentation templates such as `/sys/health` or
/// `/:secret-mount-path/data/:path`. They never contain a caller's concrete
/// mount, secret path, lease identifier, token accessor, or query value.
#[derive(Clone, Copy, Debug)]
pub struct OpenBaoOperation {
    id: &'static str,
    method: OpenBaoHttpMethod,
    path_template: &'static str,
    disposition: OpenBaoOperationDisposition,
    ranges: &'static [OpenBaoCapabilityRange],
}

impl OpenBaoOperation {
    const fn generated(
        id: &'static str,
        method: OpenBaoHttpMethod,
        path_template: &'static str,
        disposition: OpenBaoOperationDisposition,
        ranges: &'static [OpenBaoCapabilityRange],
    ) -> Self {
        Self {
            id,
            method,
            path_template,
            disposition,
            ranges,
        }
    }

    /// Stable generated operation identifier.
    pub const fn id(self) -> &'static str {
        self.id
    }

    /// Documented method for this route identity.
    pub const fn method(self) -> OpenBaoHttpMethod {
        self.method
    }

    /// Secret-free documented route template.
    pub const fn path_template(self) -> &'static str {
        self.path_template
    }

    /// Current crate review disposition.
    pub const fn disposition(self) -> OpenBaoOperationDisposition {
        self.disposition
    }

    /// Complete exact-release range partition for this operation.
    pub const fn ranges(self) -> &'static [OpenBaoCapabilityRange] {
        self.ranges
    }

    /// Reports availability for one locked exact-release profile.
    ///
    /// Returns `None` for versions outside the immutable profile inventory,
    /// including unpublished patch numbers that happen to fall numerically
    /// between two locked releases.
    pub fn availability(self, version: OpenBaoVersion) -> Option<OpenBaoCapabilityAvailability> {
        if !is_generated_profile(version) {
            return None;
        }
        let range = select_capability_range(self.ranges, version)?;
        if range.evidence == OpenBaoCapabilityEvidence::None {
            return Some(OpenBaoCapabilityAvailability::NotDocumented);
        }
        if self.disposition == OpenBaoOperationDisposition::SecurityBlocked {
            return Some(OpenBaoCapabilityAvailability::SecurityBlocked);
        }
        Some(OpenBaoCapabilityAvailability::DocumentedRoute)
    }

    /// Returns the evidence for one locked exact-release profile.
    pub fn evidence(self, version: OpenBaoVersion) -> Option<OpenBaoCapabilityEvidence> {
        if !is_generated_profile(version) {
            return None;
        }
        select_capability_range(self.ranges, version).map(OpenBaoCapabilityRange::evidence)
    }
}

pub(crate) fn select_capability_range(
    ranges: &[OpenBaoCapabilityRange],
    version: OpenBaoVersion,
) -> Option<OpenBaoCapabilityRange> {
    ranges.iter().copied().find(|range| range.contains(version))
}

/// Read-only operation status in one exact OpenBao profile.
#[derive(Clone, Copy, Debug)]
pub struct OpenBaoCapabilityStatus {
    operation: OpenBaoOperation,
    availability: OpenBaoCapabilityAvailability,
    evidence: OpenBaoCapabilityEvidence,
}

impl OpenBaoCapabilityStatus {
    /// Operation identity and route template.
    pub const fn operation(self) -> OpenBaoOperation {
        self.operation
    }

    /// Server-route availability after crate security policy is applied.
    pub const fn availability(self) -> OpenBaoCapabilityAvailability {
        self.availability
    }

    /// Immutable evidence for this exact profile cell.
    pub const fn evidence(self) -> OpenBaoCapabilityEvidence {
        self.evidence
    }
}

/// Read-only capability report for one exact locked OpenBao release.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OpenBaoCapabilityProfile {
    version: OpenBaoVersion,
}

/// Internal logical SDK endpoint with one or more versioned route variants.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OpenBaoEndpointSpec {
    id: &'static str,
    variants: &'static [OpenBaoEndpointVariant],
}

impl OpenBaoEndpointSpec {
    #[allow(dead_code)]
    pub(crate) const fn new(id: &'static str, variants: &'static [OpenBaoEndpointVariant]) -> Self {
        Self { id, variants }
    }

    pub(crate) const fn id(self) -> &'static str {
        self.id
    }

    pub(crate) const fn variants(self) -> &'static [OpenBaoEndpointVariant] {
        self.variants
    }
}

/// One immutable registry operation selected over an inclusive release range.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OpenBaoEndpointVariant {
    operation_id: &'static str,
    minimum: OpenBaoVersion,
    maximum: OpenBaoVersion,
}

impl OpenBaoEndpointVariant {
    #[allow(dead_code)]
    pub(crate) const fn new(
        operation_id: &'static str,
        minimum: OpenBaoVersion,
        maximum: OpenBaoVersion,
    ) -> Self {
        Self {
            operation_id,
            minimum,
            maximum,
        }
    }

    pub(crate) const fn operation_id(self) -> &'static str {
        self.operation_id
    }

    pub(crate) const fn minimum(self) -> OpenBaoVersion {
        self.minimum
    }

    pub(crate) const fn maximum(self) -> OpenBaoVersion {
        self.maximum
    }

    pub(crate) fn contains(self, version: OpenBaoVersion) -> bool {
        version >= self.minimum && version <= self.maximum
    }
}

impl OpenBaoCapabilityProfile {
    /// Selects an exact evidence profile, including staged candidates.
    pub fn for_version(version: OpenBaoVersion) -> Option<Self> {
        is_generated_profile(version).then_some(Self { version })
    }

    /// Exact OpenBao release represented by this profile.
    pub const fn version(self) -> OpenBaoVersion {
        self.version
    }

    /// Reports one operation by stable identifier.
    pub fn operation(self, id: &str) -> Option<OpenBaoCapabilityStatus> {
        let operation = openbao_operation(id)?;
        capability_status(operation, self.version)
    }

    /// Iterates every operation and its status for this profile.
    pub fn operations(self) -> impl Iterator<Item = OpenBaoCapabilityStatus> {
        generated::GENERATED_OPERATIONS
            .iter()
            .copied()
            .filter_map(move |operation| capability_status(operation, self.version))
    }
}

/// Returns every stable generated operation in identifier order.
pub fn openbao_operations() -> &'static [OpenBaoOperation] {
    generated::GENERATED_OPERATIONS
}

/// Looks up a stable operation identifier.
pub fn openbao_operation(id: &str) -> Option<OpenBaoOperation> {
    generated::GENERATED_OPERATIONS
        .binary_search_by_key(&id, |operation| operation.id())
        .ok()
        .map(|index| generated::GENERATED_OPERATIONS[index])
}

/// Returns all exact OpenBao releases represented by generated evidence profiles.
///
/// This includes staged candidates that cannot yet drive runtime policies or
/// request dispatch.
pub fn openbao_profile_versions() -> &'static [OpenBaoVersion] {
    generated::GENERATED_PROFILE_VERSIONS
}

pub(crate) fn is_generated_profile(version: OpenBaoVersion) -> bool {
    generated::GENERATED_PROFILE_VERSIONS
        .binary_search(&version)
        .is_ok()
}

pub(crate) fn is_routable_profile(version: OpenBaoVersion) -> bool {
    generated::GENERATED_ROUTABLE_PROFILE_VERSIONS
        .binary_search(&version)
        .is_ok()
}

pub(crate) fn latest_routable_profile() -> Option<OpenBaoVersion> {
    generated::GENERATED_ROUTABLE_PROFILE_VERSIONS
        .last()
        .copied()
}

fn require_routable_profile(version: OpenBaoVersion) -> Result<()> {
    if is_routable_profile(version) {
        Ok(())
    } else {
        Err(invalid_requirement(
            "compatibility policy version is absent from the runtime-approved release inventory",
        ))
    }
}

fn capability_status(
    operation: OpenBaoOperation,
    version: OpenBaoVersion,
) -> Option<OpenBaoCapabilityStatus> {
    Some(OpenBaoCapabilityStatus {
        availability: operation.availability(version)?,
        evidence: operation.evidence(version)?,
        operation,
    })
}

pub(crate) mod generated {
    use super::{
        OpenBaoCapabilityEvidence, OpenBaoCapabilityRange, OpenBaoEndpointSpec,
        OpenBaoEndpointVariant, OpenBaoHttpMethod, OpenBaoOperation, OpenBaoOperationDisposition,
        OpenBaoVersion,
    };

    include!("generated/openbao_capabilities.rs");
}

fn parse_component(component: &str) -> Result<u32> {
    if component.is_empty() {
        return Err(invalid_version("version components must not be empty"));
    }
    if component.len() > 1 && component.starts_with('0') {
        return Err(invalid_version(
            "version components must use canonical decimal form",
        ));
    }
    if !component.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_version(
            "version components must be decimal integers",
        ));
    }
    component
        .parse::<u32>()
        .map_err(|_| invalid_version("version component exceeds u32"))
}

fn parse_requirement_version(input: &str) -> Result<OpenBaoVersion> {
    input
        .parse()
        .map_err(|_| invalid_requirement("requirement contains an invalid stable OpenBao version"))
}

const fn invalid_version(reason: &'static str) -> Error {
    Error::InvalidOpenBaoVersion(reason)
}

const fn invalid_requirement(reason: &'static str) -> Error {
    Error::InvalidOpenBaoVersionRequirement(reason)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use core::str::FromStr;

    use super::{
        OpenBaoCapabilityAvailability, OpenBaoCapabilityEvidence, OpenBaoCapabilityProfile,
        OpenBaoCompatibilityFailure, OpenBaoCompatibilityPolicy, OpenBaoCompatibilityPolicyKind,
        OpenBaoCompatibilityStatus, OpenBaoHttpMethod, OpenBaoOperationDisposition, OpenBaoVersion,
        OpenBaoVersionRequirement, UnknownNewerOpenBaoAcknowledgement, is_routable_profile,
        latest_routable_profile, openbao_operation, openbao_operations, openbao_profile_versions,
    };
    use crate::{Error, Result};

    #[test]
    fn exact_version_parsing_is_canonical_and_ordered() -> Result<()> {
        let version = OpenBaoVersion::from_str("2.5.5")?;

        assert_eq!(version.major(), 2);
        assert_eq!(version.minor(), 5);
        assert_eq!(version.patch(), 5);
        assert_eq!(version.to_string(), "2.5.5");
        assert!(OpenBaoVersion::new(2, 5, 4) < version);
        assert!(version < OpenBaoVersion::new(3, 0, 0));
        Ok(())
    }

    #[test]
    fn compatibility_policies_require_runtime_approved_profiles() -> Result<()> {
        let known = OpenBaoVersion::new(2, 5, 5);
        let staged = OpenBaoVersion::new(2, 6, 0);
        let unpublished = OpenBaoVersion::new(2, 4, 2);

        assert_eq!(
            OpenBaoCompatibilityPolicy::exact(known)?.kind(),
            OpenBaoCompatibilityPolicyKind::Exact
        );
        assert!(OpenBaoCompatibilityPolicy::exact(staged).is_err());
        assert!(OpenBaoCompatibilityPolicy::assume(staged).is_err());
        let staged_range = OpenBaoVersionRequirement::inclusive(known, staged)?;
        assert!(OpenBaoCompatibilityPolicy::range(staged_range).is_err());
        assert!(OpenBaoCompatibilityPolicy::exact(unpublished).is_err());
        assert!(OpenBaoCompatibilityPolicy::assume(unpublished).is_err());
        assert!(
            OpenBaoCompatibilityPolicy::range(OpenBaoVersionRequirement::inclusive(
                OpenBaoVersion::new(2, 4, 1),
                unpublished,
            )?)
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn strict_and_unknown_newer_policies_fail_closed_or_report_acknowledgement() -> Result<()> {
        let strict = OpenBaoCompatibilityPolicy::automatic_strict();
        let unknown = OpenBaoVersion::new(2, 6, 0);
        assert_eq!(
            strict.evaluate_detected(unknown),
            Err(OpenBaoCompatibilityFailure::UnknownVersion(unknown))
        );

        let acknowledged = OpenBaoCompatibilityPolicy::automatic_allow_unknown_newer(
            UnknownNewerOpenBaoAcknowledgement::acknowledge(),
        )
        .evaluate_detected(unknown)
        .map_err(|_| Error::Internal("acknowledged newer policy rejected a newer version"))?;
        assert_eq!(
            acknowledged.status(),
            OpenBaoCompatibilityStatus::AcknowledgedUnknownNewer
        );
        assert_eq!(acknowledged.detected_version(), Some(unknown));
        assert_eq!(
            acknowledged.profile_version(),
            Some(OpenBaoVersion::new(2, 5, 5))
        );
        Ok(())
    }

    #[test]
    fn assumed_policy_is_never_reported_as_verified() -> Result<()> {
        let version = OpenBaoVersion::new(2, 2, 0);
        let report = OpenBaoCompatibilityPolicy::assume(version)?
            .immediate_report()
            .ok_or(Error::Internal("assumed policy did not produce a report"))?;
        assert_eq!(report.status(), OpenBaoCompatibilityStatus::Assumed);
        assert_eq!(report.detected_version(), None);
        assert_eq!(report.profile_version(), Some(version));
        assert_eq!(
            report.requirement(),
            Some(OpenBaoVersionRequirement::exact(version))
        );
        Ok(())
    }

    #[test]
    fn version_components_accept_the_full_u32_range() -> Result<()> {
        let maximum = OpenBaoVersion::from_str("4294967295.4294967295.4294967295")?;

        assert_eq!(maximum, OpenBaoVersion::new(u32::MAX, u32::MAX, u32::MAX));
        Ok(())
    }

    #[test]
    fn malformed_versions_are_rejected() {
        for input in [
            "",
            "2",
            "2.5",
            "2.5.5.0",
            "v2.5.5",
            "2.5.5 ",
            " 2.5.5",
            "02.5.5",
            "2.05.5",
            "2.5.05",
            "2..5",
            "2.5.-1",
            "2.5.5-rc1",
            "2.5.5+vendor",
            "２.５.５",
            "4294967296.0.0",
        ] {
            assert!(
                input.parse::<OpenBaoVersion>().is_err(),
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn version_input_is_bounded_and_errors_do_not_echo_it() {
        let hostile = format!("2.5.5\n{}", "9".repeat(128));
        let result = hostile.parse::<OpenBaoVersion>();
        assert!(result.is_err());
        let Err(error) = result else {
            return;
        };
        let display = error.to_string();

        assert!(matches!(error, Error::InvalidOpenBaoVersion(_)));
        assert!(!display.contains('\n'));
        assert!(!display.contains(&hostile));
        assert!(display.len() < 128);
    }

    #[test]
    fn exact_requirement_matches_only_one_release() {
        let version = OpenBaoVersion::new(2, 5, 5);
        let requirement = OpenBaoVersionRequirement::exact(version);

        assert!(requirement.contains(version));
        assert!(!requirement.contains(OpenBaoVersion::new(2, 5, 4)));
        assert_eq!(requirement.minimum(), version);
        assert_eq!(requirement.maximum(), version);
        assert_eq!(requirement.to_string(), "2.5.5");
    }

    #[test]
    fn inclusive_requirement_matches_both_boundaries() -> Result<()> {
        let minimum = OpenBaoVersion::new(2, 4, 0);
        let maximum = OpenBaoVersion::new(2, 5, 5);
        let requirement = OpenBaoVersionRequirement::inclusive(minimum, maximum)?;

        assert!(requirement.contains(minimum));
        assert!(requirement.contains(OpenBaoVersion::new(2, 5, 0)));
        assert!(requirement.contains(maximum));
        assert!(!requirement.contains(OpenBaoVersion::new(2, 3, 2)));
        assert!(!requirement.contains(OpenBaoVersion::new(2, 5, 6)));
        assert_eq!(requirement.to_string(), "2.4.0..=2.5.5");
        Ok(())
    }

    #[test]
    fn requirement_parser_round_trips_exact_and_range_values() -> Result<()> {
        for input in ["2.5.5", "2.0.0..=2.5.5", "2.5.5..=2.5.5"] {
            let requirement = input.parse::<OpenBaoVersionRequirement>()?;
            assert_eq!(requirement.to_string(), input);
        }
        Ok(())
    }

    #[test]
    fn malformed_requirements_are_rejected_without_echoing_input() {
        for input in [
            "",
            "2.5",
            "v2.5.5",
            "2.5.5-rc1",
            "2.5.5..",
            "..=2.5.5",
            "2.5.5..=",
            "2.5.5..=2.5.5..=2.6.0",
            "2.5.5..=2.5.4",
            ">=2.5.5",
            "2.5.5..2.6.0",
        ] {
            let result = input.parse::<OpenBaoVersionRequirement>();
            assert!(
                matches!(result, Err(Error::InvalidOpenBaoVersionRequirement(_))),
                "wrong result for {input:?}"
            );
            if let Err(error) = result {
                assert!(input.is_empty() || !error.to_string().contains(input));
            }
        }
    }

    #[test]
    fn requirement_input_is_bounded() {
        let input = "1".repeat(132);
        let result = input.parse::<OpenBaoVersionRequirement>();

        assert!(matches!(
            result,
            Err(Error::InvalidOpenBaoVersionRequirement(
                "requirement exceeds the input limit"
            ))
        ));
    }

    #[test]
    fn generated_capability_registry_is_complete_and_lookup_is_stable() {
        let operations = openbao_operations();
        let versions = openbao_profile_versions();

        assert_eq!(operations.len(), 690);
        assert_eq!(versions.len(), 22);
        assert_eq!(versions[0], OpenBaoVersion::new(2, 0, 0));
        assert_eq!(versions[20], OpenBaoVersion::new(2, 5, 5));
        assert_eq!(versions[21], OpenBaoVersion::new(2, 6, 0));
        assert_eq!(
            latest_routable_profile(),
            Some(OpenBaoVersion::new(2, 5, 5))
        );
        assert!(is_routable_profile(OpenBaoVersion::new(2, 5, 5)));
        assert!(!is_routable_profile(OpenBaoVersion::new(2, 6, 0)));
        assert!(OpenBaoCapabilityProfile::for_version(OpenBaoVersion::new(2, 6, 0)).is_some());
        assert!(OpenBaoCapabilityProfile::for_version(OpenBaoVersion::new(2, 4, 2)).is_none());

        let mut previous = None;
        for operation in operations {
            assert!(operation.path_template().starts_with('/'));
            assert!(!operation.path_template().chars().any(char::is_control));
            if let Some(previous) = previous {
                assert!(previous < operation.id());
            }
            previous = Some(operation.id());
            assert_eq!(
                openbao_operation(operation.id()).map(|value| value.id()),
                Some(operation.id())
            );
            for version in versions {
                assert!(operation.availability(*version).is_some());
                assert!(operation.evidence(*version).is_some());
            }
        }

        let openapi_only = operations
            .iter()
            .find(|operation| operation.path_template() == "/identity/oidc/.well-known/keys")
            .unwrap_or_else(|| panic!("missing locked OpenAPI-only Identity JWKS route"));
        assert_eq!(
            openapi_only.evidence(OpenBaoVersion::new(2, 5, 5)),
            Some(OpenBaoCapabilityEvidence::LockedOpenApi)
        );

        for (method, path, disposition) in [
            (
                OpenBaoHttpMethod::Delete,
                "/auth/jwt/cel/role/:name",
                OpenBaoOperationDisposition::Typed,
            ),
            (
                OpenBaoHttpMethod::Get,
                "/auth/jwt/cel/role/:name",
                OpenBaoOperationDisposition::Typed,
            ),
            (
                OpenBaoHttpMethod::List,
                "/auth/jwt/cel/role",
                OpenBaoOperationDisposition::Typed,
            ),
            (
                OpenBaoHttpMethod::Patch,
                "/auth/jwt/cel/role/:name",
                OpenBaoOperationDisposition::SecurityBlocked,
            ),
            (
                OpenBaoHttpMethod::Post,
                "/auth/jwt/cel/login",
                OpenBaoOperationDisposition::Typed,
            ),
            (
                OpenBaoHttpMethod::Post,
                "/auth/jwt/cel/role/:name",
                OpenBaoOperationDisposition::Typed,
            ),
            (
                OpenBaoHttpMethod::Delete,
                "/sys/namespaces/:path/delete-sealed",
                OpenBaoOperationDisposition::TypedGated,
            ),
            (
                OpenBaoHttpMethod::Get,
                "/sys/namespaces/:path/seal-status",
                OpenBaoOperationDisposition::Typed,
            ),
            (
                OpenBaoHttpMethod::Post,
                "/sys/namespaces/:path/seal",
                OpenBaoOperationDisposition::TypedGated,
            ),
            (
                OpenBaoHttpMethod::Post,
                "/sys/namespaces/:path/unseal",
                OpenBaoOperationDisposition::TypedGated,
            ),
        ] {
            let operation = operations
                .iter()
                .copied()
                .find(|operation| operation.method() == method && operation.path_template() == path)
                .unwrap_or_else(|| {
                    panic!("missing staged OpenBao 2.6 operation {method:?} {path}")
                });
            assert_eq!(operation.disposition(), disposition);
            assert_eq!(
                operation.availability(OpenBaoVersion::new(2, 5, 5)),
                Some(OpenBaoCapabilityAvailability::NotDocumented)
            );
            let expected = if disposition == OpenBaoOperationDisposition::SecurityBlocked {
                OpenBaoCapabilityAvailability::SecurityBlocked
            } else {
                OpenBaoCapabilityAvailability::DocumentedRoute
            };
            assert_eq!(
                operation.availability(OpenBaoVersion::new(2, 6, 0)),
                Some(expected)
            );
        }
    }

    #[test]
    fn generated_root_token_routes_are_gapless_and_profile_specific() {
        let endpoints = [
            super::generated::GENERATED_SYS_GENERATE_ROOT_CANCEL,
            super::generated::GENERATED_SYS_GENERATE_ROOT_START,
            super::generated::GENERATED_SYS_GENERATE_ROOT_STATUS,
            super::generated::GENERATED_SYS_GENERATE_ROOT_UPDATE,
        ];

        for endpoint in endpoints {
            let variants = endpoint.variants();
            assert_eq!(variants.len(), 2);
            assert_eq!(variants[0].minimum(), OpenBaoVersion::new(2, 0, 0));
            assert_eq!(variants[0].maximum(), OpenBaoVersion::new(2, 5, 5));
            assert_eq!(variants[1].minimum(), OpenBaoVersion::new(2, 6, 0));
            assert_eq!(variants[1].maximum(), OpenBaoVersion::new(2, 6, 0));
            assert_ne!(variants[0].operation_id(), variants[1].operation_id());
            for (variant, version) in [
                (variants[0], OpenBaoVersion::new(2, 5, 5)),
                (variants[1], OpenBaoVersion::new(2, 6, 0)),
            ] {
                let operation = openbao_operation(variant.operation_id())
                    .unwrap_or_else(|| panic!("missing root-generation operation"));
                assert_eq!(
                    operation.availability(version),
                    Some(OpenBaoCapabilityAvailability::DocumentedRoute)
                );
            }
        }
    }

    #[test]
    fn generated_profiles_preserve_removed_and_feature_gated_routes() {
        let historical = openbao_operations()
            .iter()
            .copied()
            .find(|operation| operation.path_template() == "/sys/internal/ui/feature-flags")
            .unwrap_or_else(|| panic!("missing historical feature-flags operation"));
        assert_eq!(historical.method(), OpenBaoHttpMethod::Get);
        assert_eq!(
            historical.availability(OpenBaoVersion::new(2, 4, 4)),
            Some(OpenBaoCapabilityAvailability::DocumentedRoute)
        );
        assert_eq!(
            historical.evidence(OpenBaoVersion::new(2, 4, 4)),
            Some(OpenBaoCapabilityEvidence::TaggedDocumentation)
        );
        assert_eq!(
            historical.availability(OpenBaoVersion::new(2, 5, 5)),
            Some(OpenBaoCapabilityAvailability::NotDocumented)
        );
        assert_eq!(
            historical.disposition(),
            OpenBaoOperationDisposition::TypedGated
        );

        let monitor = openbao_operations()
            .iter()
            .copied()
            .find(|operation| {
                operation.method() == OpenBaoHttpMethod::Get
                    && operation.path_template() == "/sys/monitor"
            })
            .unwrap_or_else(|| panic!("missing monitor operation"));
        assert_eq!(
            monitor.availability(OpenBaoVersion::new(2, 5, 5)),
            Some(OpenBaoCapabilityAvailability::DocumentedRoute)
        );
        assert_eq!(
            monitor.disposition(),
            OpenBaoOperationDisposition::TypedGated
        );
    }

    #[test]
    fn profile_reporting_contains_every_operation_without_support_inference() {
        let profile = OpenBaoCapabilityProfile::for_version(OpenBaoVersion::new(2, 5, 5))
            .unwrap_or_else(|| panic!("missing current capability profile"));
        let statuses = profile.operations().collect::<Vec<_>>();

        assert_eq!(statuses.len(), openbao_operations().len());
        assert_eq!(profile.version(), OpenBaoVersion::new(2, 5, 5));
        assert!(statuses.iter().any(|status| {
            status.operation().disposition() == OpenBaoOperationDisposition::Typed
                && status.availability() == OpenBaoCapabilityAvailability::DocumentedRoute
                && status.evidence() != OpenBaoCapabilityEvidence::None
        }));
    }
}
