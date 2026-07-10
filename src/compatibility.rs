//! OpenBao server-version compatibility value types.
//!
//! These types model stable OpenBao releases. They deliberately reject
//! prerelease and build metadata so a compatibility profile always selects an
//! exact reviewed server release.

use core::{fmt, str::FromStr};

use crate::{Error, Result};

const MAX_VERSION_BYTES: usize = 64;
const MAX_REQUIREMENT_BYTES: usize = (MAX_VERSION_BYTES * 2) + 3;

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
        version >= self.minimum() && version <= self.maximum()
    }
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
    use core::str::FromStr;

    use super::{OpenBaoVersion, OpenBaoVersionRequirement};
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
}
