//! Shared request-parameter validation helpers.

use crate::{Error, Result};

const MAX_DURATION_COMPONENT: u64 = 8_760_000;

pub(crate) fn validate_duration_parameter(value: &str, field: &'static str) -> Result<()> {
    if validate_duration_string(value, false) {
        return Ok(());
    }
    Err(Error::InvalidParameter(format!(
        "{field} must be a positive duration such as 30s, 5m, or 1h"
    )))
}

pub(crate) fn validate_duration_string(value: &str, allow_zero: bool) -> bool {
    if value.is_empty() {
        return false;
    }

    let bytes = value.as_bytes();
    let mut index = 0;
    let mut last_unit_order = None;
    while index < bytes.len() {
        let digit_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if digit_start == index {
            return false;
        }
        let Ok(component) = core::str::from_utf8(&bytes[digit_start..index])
            .unwrap_or("")
            .parse::<u64>()
        else {
            return false;
        };
        if component > MAX_DURATION_COMPONENT {
            return false;
        }
        if !allow_zero && component == 0 {
            return false;
        }
        if index >= bytes.len() {
            return false;
        }
        let unit_order = match bytes[index] {
            b'h' => 0,
            b'm' => 1,
            b's' => 2,
            _ => return false,
        };
        if last_unit_order.is_some_and(|previous| unit_order <= previous) {
            return false;
        }
        last_unit_order = Some(unit_order);
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::validate_duration_string;

    #[test]
    fn duration_strings_are_validated() {
        assert!(validate_duration_string("30s", false));
        assert!(validate_duration_string("5m", false));
        assert!(validate_duration_string("1h", false));
        assert!(validate_duration_string("1h30m", false));
        assert!(!validate_duration_string("", false));
        assert!(!validate_duration_string("0s", false));
        assert!(!validate_duration_string("1h1h", false));
        assert!(!validate_duration_string("1m1h", false));
        assert!(!validate_duration_string("999999999999h", false));
        assert!(!validate_duration_string("-1h", false));
        assert!(!validate_duration_string("forever", false));
        assert!(!validate_duration_string("1h0m", false));
    }
}
