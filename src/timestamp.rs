//! Optional RFC3339 timestamp parsing helpers.
//!
//! OpenBao returns many timestamps as RFC3339 strings, and some "not set"
//! timestamp fields as empty strings. This module keeps the default response
//! types stable while giving applications a typed parser behind the opt-in
//! `time` feature.

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{Error, Result};

/// Parses a non-empty RFC3339 timestamp returned by OpenBao.
///
/// The error message intentionally does not echo the provided value because
/// timestamp-bearing envelopes can be adjacent to secret-bearing response
/// payloads in application logs.
pub fn parse_rfc3339_timestamp(value: &str) -> Result<OffsetDateTime> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::InvalidParameter(
            "timestamp must be a non-empty RFC3339 value".to_owned(),
        ));
    }

    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| Error::InvalidParameter("timestamp must be a valid RFC3339 value".to_owned()))
}

/// Parses an optional RFC3339 timestamp returned by OpenBao.
///
/// `None`, an empty string, or a whitespace-only string is treated as an absent
/// timestamp. This matches OpenBao fields such as KV v2 `deletion_time`, which
/// commonly use an empty string when no timestamp exists.
pub fn parse_optional_rfc3339_timestamp(value: Option<&str>) -> Result<Option<OffsetDateTime>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };

    parse_rfc3339_timestamp(value).map(Some)
}

/// Extension trait for parsing OpenBao RFC3339 timestamp strings.
pub trait TimestampExt {
    /// Parses this string as a non-empty RFC3339 timestamp.
    fn parse_openbao_timestamp(&self) -> Result<OffsetDateTime>;
}

impl TimestampExt for str {
    fn parse_openbao_timestamp(&self) -> Result<OffsetDateTime> {
        parse_rfc3339_timestamp(self)
    }
}

impl TimestampExt for String {
    fn parse_openbao_timestamp(&self) -> Result<OffsetDateTime> {
        self.as_str().parse_openbao_timestamp()
    }
}

/// Extension trait for optional OpenBao RFC3339 timestamp strings.
pub trait OptionalTimestampExt {
    /// Parses this value as an optional RFC3339 timestamp.
    fn parse_optional_openbao_timestamp(&self) -> Result<Option<OffsetDateTime>>;
}

impl OptionalTimestampExt for Option<&str> {
    fn parse_optional_openbao_timestamp(&self) -> Result<Option<OffsetDateTime>> {
        parse_optional_rfc3339_timestamp(*self)
    }
}

impl OptionalTimestampExt for Option<String> {
    fn parse_optional_openbao_timestamp(&self) -> Result<Option<OffsetDateTime>> {
        parse_optional_rfc3339_timestamp(self.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use time::UtcOffset;

    use crate::{Error, Result};

    use super::{
        OptionalTimestampExt, TimestampExt, parse_optional_rfc3339_timestamp,
        parse_rfc3339_timestamp,
    };

    #[test]
    fn parses_rfc3339_timestamp() -> Result<()> {
        let parsed = parse_rfc3339_timestamp("2026-05-28T00:00:00Z")?;

        assert_eq!(parsed.date().year(), 2026);
        assert_eq!(parsed.offset(), UtcOffset::UTC);
        Ok(())
    }

    #[test]
    fn parses_offset_timestamp() -> Result<()> {
        let parsed = "2026-05-28T02:30:00+02:00".parse_openbao_timestamp()?;

        assert_eq!(parsed.date().year(), 2026);
        assert_eq!(parsed.offset().whole_hours(), 2);
        Ok(())
    }

    #[test]
    fn treats_empty_optional_timestamp_as_absent() -> Result<()> {
        assert_eq!(parse_optional_rfc3339_timestamp(None)?, None);
        assert_eq!(Some("").parse_optional_openbao_timestamp()?, None);
        Ok(())
    }

    #[test]
    fn rejects_invalid_timestamp_without_echoing_value() -> Result<()> {
        let error = match parse_rfc3339_timestamp("not-a-timestamp") {
            Ok(_) => return Err(Error::Internal("invalid timestamp unexpectedly parsed")),
            Err(error) => error.to_string(),
        };

        assert!(!error.contains("not-a-timestamp"));
        assert!(error.contains("RFC3339"));
        Ok(())
    }
}
