//! Helpers for OpenBao duration strings.

use std::time::Duration;

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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::duration_to_bao_string;

    #[test]
    fn converts_duration_to_openbao_string() {
        assert_eq!(duration_to_bao_string(Duration::ZERO), "0s");
        assert_eq!(duration_to_bao_string(Duration::from_secs(30)), "30s");
        assert_eq!(duration_to_bao_string(Duration::from_secs(90)), "1m30s");
        assert_eq!(duration_to_bao_string(Duration::from_secs(3661)), "1h1m1s");
        assert_eq!(duration_to_bao_string(Duration::from_millis(1)), "1s");
    }
}
