//! Shared request-parameter validation helpers.

use std::net::IpAddr;

use crate::{Error, Result};

/// Loose client-side sanity cap. OpenBao deployment TTL limits still apply.
const MAX_DURATION_COMPONENT: u64 = 8_760_000;
pub(crate) const MAX_JSON_OBJECT_BYTES: usize = 4 * 1024;

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
    let mut last_unit_scale = None;
    while index < bytes.len() {
        let digit_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if digit_start == index {
            return false;
        }
        let digits = &value[digit_start..index];
        let Ok(component) = digits.parse::<u64>() else {
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
        let unit_scale = match bytes[index] {
            b'h' => 0,
            b'm' => 1,
            b's' => 2,
            _ => return false,
        };
        if last_unit_scale.is_some_and(|previous| unit_scale <= previous) {
            return false;
        }
        last_unit_scale = Some(unit_scale);
        index += 1;
    }
    true
}

pub(crate) fn validate_optional_ldap_tls_version(
    value: &Option<String>,
    field: &'static str,
) -> Result<()> {
    if let Some(value) = value {
        match value.as_str() {
            "tls12" | "tls13" => {}
            "tls10" | "tls11" => {
                return Err(Error::InvalidParameter(format!(
                    "{field} value {value:?} is deprecated; use tls12 or tls13"
                )));
            }
            _ => {
                return Err(Error::InvalidParameter(format!(
                    "{field} must be tls12 or tls13"
                )));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_cidr_list(values: &[String], field: &'static str) -> Result<()> {
    for value in values {
        validate_cidr(value, field)?;
    }
    Ok(())
}

pub(crate) fn validate_cidr(value: &str, field: &'static str) -> Result<()> {
    let Some((ip, prefix)) = value.split_once('/') else {
        return Err(Error::InvalidParameter(format!(
            "{field} must contain CIDR values such as 192.0.2.0/24"
        )));
    };
    if ip.is_empty() || prefix.is_empty() || prefix.contains('/') {
        return Err(Error::InvalidParameter(format!(
            "{field} contains malformed CIDR value"
        )));
    }

    let ip = ip
        .parse::<IpAddr>()
        .map_err(|_| Error::InvalidParameter(format!("{field} contains invalid CIDR address")))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| Error::InvalidParameter(format!("{field} contains invalid CIDR prefix")))?;
    let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        return Err(Error::InvalidParameter(format!(
            "{field} CIDR prefix exceeds /{max_prefix}"
        )));
    }
    let host_bits_are_zero = match ip {
        IpAddr::V4(ip) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(ip) & !mask == 0
        }
        IpAddr::V6(ip) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(ip) & !mask == 0
        }
    };
    if !host_bits_are_zero {
        return Err(Error::InvalidParameter(format!(
            "{field} CIDR value must be a network address with host bits zeroed"
        )));
    }
    Ok(())
}

pub(crate) fn validate_json_object_string(value: &str, field: &'static str) -> Result<()> {
    if value.len() > MAX_JSON_OBJECT_BYTES {
        return Err(Error::InvalidParameter(format!(
            "{field} JSON object string exceeds maximum allowed size"
        )));
    }
    let value = serde_json::from_str::<serde_json::Value>(value).map_err(|_| {
        Error::InvalidParameter(format!("{field} must be a valid JSON object string"))
    })?;
    if value.is_object() {
        return Ok(());
    }
    Err(Error::InvalidParameter(format!(
        "{field} must be a JSON object string"
    )))
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_JSON_OBJECT_BYTES, validate_cidr, validate_duration_string, validate_json_object_string,
    };

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

    #[test]
    fn cidr_values_are_validated() {
        assert!(validate_cidr("192.0.2.0/24", "test cidr").is_ok());
        assert!(validate_cidr("2001:db8::/32", "test cidr").is_ok());
        assert!(validate_cidr("192.0.2.0/33", "test cidr").is_err());
        assert!(validate_cidr("2001:db8::/129", "test cidr").is_err());
        assert!(validate_cidr("192.0.2.5/24", "test cidr").is_err());
        assert!(validate_cidr("2001:db8::1/32", "test cidr").is_err());
        assert!(validate_cidr("not-a-cidr", "test cidr").is_err());
        assert!(validate_cidr("192.0.2.0/24/extra", "test cidr").is_err());
    }

    #[test]
    fn json_object_strings_are_validated() {
        assert!(validate_json_object_string(r#"{"service":"payments"}"#, "metadata").is_ok());
        assert!(validate_json_object_string(r#"["not","object"]"#, "metadata").is_err());
        assert!(validate_json_object_string("{not-json", "metadata").is_err());
        let oversized = format!(r#"{{"value":"{}"}}"#, "a".repeat(MAX_JSON_OBJECT_BYTES));
        assert!(validate_json_object_string(&oversized, "metadata").is_err());
    }
}
