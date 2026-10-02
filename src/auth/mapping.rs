//! Bounded encoding for legacy comma-delimited authorization mappings.

use crate::{Error, Result};

pub(super) const MAX_MAPPING_ITEMS: usize = 4096;
pub(super) const MAX_MAPPING_BYTES: usize = 1024 * 1024;

pub(super) fn validate_name(value: &str, field: &'static str) -> Result<()> {
    if value.len() > MAX_MAPPING_BYTES {
        return Err(Error::InvalidParameter(format!(
            "{field} exceeds the byte limit"
        )));
    }
    if value.trim().is_empty()
        || value.contains(',')
        || value.as_bytes().iter().any(u8::is_ascii_control)
    {
        return Err(Error::InvalidParameter(format!(
            "{field} contains an invalid name"
        )));
    }
    Ok(())
}

pub(super) fn encoded_length(values: &[String], field: &'static str) -> Result<usize> {
    if values.len() > MAX_MAPPING_ITEMS {
        return Err(Error::InvalidParameter(format!(
            "{field} exceeds the item limit"
        )));
    }
    let mut length = values.len().saturating_sub(1);
    // Bound the complete allocation and scan budget before inspecting names.
    for value in values {
        length = length
            .checked_add(value.len())
            .filter(|length| *length <= MAX_MAPPING_BYTES)
            .ok_or_else(|| Error::InvalidParameter(format!("{field} exceeds the byte limit")))?;
    }
    for value in values {
        validate_name(value, field)?;
    }
    Ok(length)
}

pub(super) fn encode_values(values: &[String], field: &'static str) -> Result<String> {
    let length = encoded_length(values, field)?;
    let mut output = String::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| Error::InvalidParameter(format!("{field} allocation failed")))?;
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str(value);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::*;

    #[test]
    fn encoding_preserves_valid_names_order_and_empty_clear() {
        for values in [
            vec![],
            vec!["reader".into()],
            vec!["reader".into(), "Team A".into(), "\u{e9}quipe".into()],
        ] {
            let encoded = encode_values(&values, "test mapping")
                .unwrap_or_else(|_| panic!("valid mapping rejected"));
            assert_eq!(encoded, values.join(","));
            assert_eq!(
                encoded.len(),
                encoded_length(&values, "test mapping").unwrap_or_default()
            );
        }
    }

    #[test]
    fn encoding_rejects_delimiters_and_controls_without_echoing_names() {
        for value in [
            "",
            " ",
            "\u{2003}",
            "marker,root",
            "marker\nroot",
            "marker\rroot",
            "marker\0root",
            "marker\troot",
            "marker\u{7f}root",
        ] {
            let error = encode_values(&[value.into()], "test mapping")
                .err()
                .unwrap_or_else(|| panic!("invalid mapping accepted"));
            assert!(!format!("{error:?} {error}").contains("marker"));
        }
    }

    #[test]
    fn encoding_bounds_count_and_bytes_including_separators() {
        assert!(encode_values(&vec!["p".into(); MAX_MAPPING_ITEMS], "test mapping").is_ok());
        assert!(encode_values(&vec!["p".into(); MAX_MAPPING_ITEMS + 1], "test mapping").is_err());
        assert!(encode_values(&["p".repeat(MAX_MAPPING_BYTES)], "test mapping").is_ok());
        assert!(encode_values(&["p".repeat(MAX_MAPPING_BYTES + 1)], "test mapping").is_err());
        let first = "p".repeat(MAX_MAPPING_BYTES - 2);
        assert!(encode_values(&[first.clone(), "p".into()], "test mapping").is_ok());
        assert!(encode_values(&[first, "pp".into()], "test mapping").is_err());
        let unicode = "\u{e9}".repeat(MAX_MAPPING_BYTES / 2);
        assert!(encode_values(core::slice::from_ref(&unicode), "test mapping").is_ok());
        assert!(encode_values(&[unicode + "p"], "test mapping").is_err());
        // Size rejection precedes name scans and allocation of the output.
        let error = encoded_length(&[",".repeat(MAX_MAPPING_BYTES + 1)], "test mapping")
            .err()
            .unwrap_or_else(|| panic!("oversized mapping accepted"));
        assert!(error.to_string().contains("byte limit"));
    }
}
