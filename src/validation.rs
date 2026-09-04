//! Shared request-parameter validation helpers.

use std::net::IpAddr;

use url::Url;

use crate::{Error, Result};

/// Loose client-side sanity cap. OpenBao deployment TTL limits still apply.
const MAX_DURATION_COMPONENT: u64 = 8_760_000;
const MAX_EXTERNAL_ENDPOINT_BYTES: usize = 4 * 1024;
pub(crate) const MAX_JSON_OBJECT_BYTES: usize = 4 * 1024;

pub(crate) fn validate_https_endpoint(value: &str, field: &'static str) -> Result<()> {
    if value.len() > MAX_EXTERNAL_ENDPOINT_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || value.contains('\\')
    {
        return Err(Error::InvalidParameter(format!(
            "{field} exceeds the endpoint length limit"
        )));
    }
    let endpoint = Url::parse(value)
        .map_err(|_| Error::InvalidParameter(format!("{field} must be an absolute HTTPS URL")))?;
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || endpoint.port() == Some(0)
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(Error::InvalidParameter(format!(
            "{field} must be an HTTPS URL without credentials or a fragment"
        )));
    }
    Ok(())
}

pub(crate) fn validate_secret_https_endpoint(value: &str, field: &'static str) -> Result<()> {
    if value.len() > MAX_EXTERNAL_ENDPOINT_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || value.contains(['\\', '#'])
    {
        return Err(Error::InvalidParameter(format!(
            "{field} must be a bounded HTTPS URL"
        )));
    }
    let Some(scheme_end) = value.find("://") else {
        return Err(Error::InvalidParameter(format!(
            "{field} must be an absolute HTTPS URL"
        )));
    };
    if !value[..scheme_end].eq_ignore_ascii_case("https") {
        return Err(Error::InvalidParameter(format!("{field} must use HTTPS")));
    }
    let remainder = &value[scheme_end + 3..];
    let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() || authority.contains('@') || !valid_https_authority(authority) {
        return Err(Error::InvalidParameter(format!(
            "{field} must contain a valid host without credentials"
        )));
    }
    Ok(())
}

fn valid_https_authority(authority: &str) -> bool {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((host, suffix)) = bracketed.split_once(']') else {
            return false;
        };
        return !host.is_empty()
            && !host.contains(['[', ']'])
            && (suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_endpoint_port));
    }
    if authority.contains(['[', ']', '%']) {
        return false;
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => !host.is_empty() && !host.contains(':') && valid_endpoint_port(port),
        None => !authority.is_empty(),
    }
}

fn valid_endpoint_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|port| port != 0)
}

pub(crate) fn validate_ldap_urls_use_encrypted_transport(
    urls: &Option<String>,
    starttls: Option<bool>,
    label: &'static str,
) -> Result<()> {
    if starttls == Some(true) {
        return Ok(());
    }
    let Some(urls) = urls else {
        return Err(Error::InvalidParameter(format!(
            "{label} URL must use ldaps:// or starttls=true"
        )));
    };
    let mut found = false;
    for value in urls.split(',') {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        found = true;
        if value.len() > MAX_EXTERNAL_ENDPOINT_BYTES {
            return Err(Error::InvalidParameter(format!(
                "{label} URL exceeds the endpoint length limit"
            )));
        }
        let endpoint = Url::parse(value).map_err(|_| {
            Error::InvalidParameter(format!("{label} URL must be an absolute LDAP URL"))
        })?;
        if endpoint.scheme() != "ldaps"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(Error::InvalidParameter(format!(
                "{label} URL must use ldaps:// without credentials or a fragment, or starttls=true"
            )));
        }
    }
    if !found {
        return Err(Error::InvalidParameter(format!(
            "{label} URL must not be empty"
        )));
    }
    Ok(())
}

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
        let Some(component) = parse_duration_component(&bytes[digit_start..index]) else {
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

pub(crate) fn parse_duration_component(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        return None;
    }

    let mut component = 0u64;
    for digit in digits {
        if !digit.is_ascii_digit() {
            return None;
        }
        let value = u64::from(*digit - b'0');
        component = component.checked_mul(10)?.checked_add(value)?;
        if component > MAX_DURATION_COMPONENT {
            return None;
        }
    }
    Some(component)
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
        MAX_EXTERNAL_ENDPOINT_BYTES, MAX_JSON_OBJECT_BYTES, validate_cidr,
        validate_duration_string, validate_https_endpoint, validate_json_object_string,
        validate_ldap_urls_use_encrypted_transport, validate_secret_https_endpoint,
    };

    #[test]
    fn external_https_endpoints_are_strictly_validated() {
        for endpoint in [
            "https://service.example.test",
            "https://service.example.test:8443/api?mode=ready",
            "https://[2001:db8::1]:8443/api",
        ] {
            assert!(validate_https_endpoint(endpoint, "endpoint").is_ok());
            assert!(validate_secret_https_endpoint(endpoint, "endpoint").is_ok());
        }
        for endpoint in [
            "http://service.example.test",
            "https://service.example.test/api#fragment",
            "https://",
            "https://service.example.test:0",
            "https://service.example.test:65536",
            "https://service.example.test\\path",
        ] {
            assert!(validate_https_endpoint(endpoint, "endpoint").is_err());
            assert!(validate_secret_https_endpoint(endpoint, "endpoint").is_err());
        }
        let credential_endpoint = format!(
            "https://{}:{}@service.example.test",
            ["test", "-user"].concat(),
            ["test", "-password"].concat()
        );
        assert!(validate_https_endpoint(&credential_endpoint, "endpoint").is_err());
        assert!(validate_secret_https_endpoint(&credential_endpoint, "endpoint").is_err());
        let oversized = format!(
            "https://{}.example.test",
            "a".repeat(MAX_EXTERNAL_ENDPOINT_BYTES)
        );
        assert!(validate_https_endpoint(&oversized, "endpoint").is_err());
        assert!(validate_secret_https_endpoint(&oversized, "endpoint").is_err());
    }

    #[test]
    fn ldap_endpoints_require_ldaps_or_starttls() {
        for urls in [
            Some("ldaps://ldap.example.test".to_owned()),
            Some("ldaps://ldap-a.example.test, ldaps://ldap-b.example.test:636".to_owned()),
        ] {
            assert!(
                validate_ldap_urls_use_encrypted_transport(&urls, None, "LDAP endpoint").is_ok()
            );
        }
        assert!(
            validate_ldap_urls_use_encrypted_transport(
                &Some("ldap://ldap.example.test".to_owned()),
                Some(true),
                "LDAP endpoint",
            )
            .is_ok()
        );
        for urls in [
            None,
            Some(String::new()),
            Some("ldap://ldap.example.test".to_owned()),
            Some("ldaps://ldap.example.test/#fragment".to_owned()),
        ] {
            assert!(
                validate_ldap_urls_use_encrypted_transport(&urls, None, "LDAP endpoint").is_err()
            );
        }
        let credential_url = format!(
            "ldaps://{}:{}@ldap.example.test",
            ["test", "-user"].concat(),
            ["test", "-password"].concat()
        );
        assert!(
            validate_ldap_urls_use_encrypted_transport(
                &Some(credential_url),
                None,
                "LDAP endpoint"
            )
            .is_err()
        );
    }

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
