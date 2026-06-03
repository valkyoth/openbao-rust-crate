//! Helpers for OpenBao duration strings.

use std::time::Duration;

use crate::{Error, Result};

/// Renewal timing guidance for application-owned token or lease renewal loops.
///
/// This type does not start background tasks and does not decide what happens
/// when renewal fails. Applications own the loop, shutdown signal, and
/// re-fetch/error policy. The hint only captures the common OpenBao convention:
/// renew after roughly two thirds of the current TTL has elapsed, and request
/// the original TTL again to avoid shortening the renewal window over time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewalHint {
    /// How long the caller should wait before attempting renewal.
    ///
    /// `None` means the token or lease is not renewable or has no usable TTL.
    pub sleep_before_renew: Option<Duration>,
    /// Renewal increment as an OpenBao duration string, suitable for token APIs.
    ///
    /// This is the original TTL represented as seconds, for example `3600s`.
    pub increment: Option<String>,
    /// Renewal increment in seconds, suitable for lease APIs.
    pub increment_seconds: Option<u64>,
}

impl RenewalHint {
    /// Builds a renewal hint from OpenBao's TTL and renewable fields.
    ///
    /// ```
    /// use std::time::Duration;
    ///
    /// let hint = openbao::RenewalHint::from_ttl(3600, true);
    /// assert_eq!(hint.sleep_before_renew, Some(Duration::from_secs(2400)));
    /// assert_eq!(hint.increment.as_deref(), Some("3600s"));
    /// assert_eq!(hint.increment_seconds, Some(3600));
    /// ```
    #[must_use]
    pub fn from_ttl(lease_duration_secs: u64, renewable: bool) -> Self {
        if !renewable || lease_duration_secs == 0 {
            return Self {
                sleep_before_renew: None,
                increment: None,
                increment_seconds: None,
            };
        }

        let sleep_secs =
            ((u128::from(lease_duration_secs) * 2) / 3).min(u128::from(u64::MAX)) as u64;

        Self {
            sleep_before_renew: Some(Duration::from_secs(sleep_secs)),
            increment: Some(format!("{lease_duration_secs}s")),
            increment_seconds: Some(lease_duration_secs),
        }
    }
}

/// Converts a Rust [`Duration`] into an OpenBao duration string.
///
/// OpenBao accepts strings such as `30s`, `5m`, and `1h30m`. Fractional
/// seconds are rounded up so a non-zero subsecond duration does not become
/// `0s`.
///
/// ```
/// use std::time::Duration;
///
/// assert_eq!(openbao::duration_to_bao_string(Duration::from_secs(90)), "1m30s");
/// assert_eq!(openbao::duration_to_bao_string(Duration::from_millis(1)), "1s");
/// ```
#[must_use]
pub fn duration_to_bao_string(duration: Duration) -> String {
    let mut total_seconds = duration.as_secs();
    if duration.subsec_nanos() > 0 {
        total_seconds = total_seconds.saturating_add(1);
    }
    if total_seconds == 0 {
        return "0s".to_owned();
    }

    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    let mut output = String::new();
    if hours > 0 {
        output.push_str(&hours.to_string());
        output.push('h');
    }
    if minutes > 0 {
        output.push_str(&minutes.to_string());
        output.push('m');
    }
    if seconds > 0 {
        output.push_str(&seconds.to_string());
        output.push('s');
    }
    output
}

pub(crate) fn nonzero_duration_to_bao_string(
    duration: Duration,
    field: &'static str,
) -> Result<String> {
    if duration.is_zero() {
        return Err(Error::InvalidParameter(format!(
            "{field} duration must be non-zero"
        )));
    }
    Ok(duration_to_bao_string(duration))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{RenewalHint, duration_to_bao_string, nonzero_duration_to_bao_string};

    #[test]
    fn converts_duration_to_openbao_string() {
        assert_eq!(duration_to_bao_string(Duration::ZERO), "0s");
        assert_eq!(duration_to_bao_string(Duration::from_secs(30)), "30s");
        assert_eq!(duration_to_bao_string(Duration::from_secs(90)), "1m30s");
        assert_eq!(duration_to_bao_string(Duration::from_secs(3661)), "1h1m1s");
        assert_eq!(duration_to_bao_string(Duration::from_millis(1)), "1s");
    }

    #[test]
    fn nonzero_duration_conversion_rejects_zero() {
        assert!(nonzero_duration_to_bao_string(Duration::ZERO, "test ttl").is_err());
        assert!(matches!(
            nonzero_duration_to_bao_string(Duration::from_secs(1), "test ttl").as_deref(),
            Ok("1s")
        ));
    }

    #[test]
    fn builds_renewal_hint_from_ttl() {
        let hint = RenewalHint::from_ttl(3600, true);
        assert_eq!(hint.sleep_before_renew, Some(Duration::from_secs(2400)));
        assert_eq!(hint.increment.as_deref(), Some("3600s"));
        assert_eq!(hint.increment_seconds, Some(3600));

        let non_renewable = RenewalHint::from_ttl(3600, false);
        assert_eq!(non_renewable.sleep_before_renew, None);
        assert_eq!(non_renewable.increment, None);
        assert_eq!(non_renewable.increment_seconds, None);

        let zero_ttl = RenewalHint::from_ttl(0, true);
        assert_eq!(zero_ttl.sleep_before_renew, None);
        assert_eq!(zero_ttl.increment, None);
        assert_eq!(zero_ttl.increment_seconds, None);
    }
}
