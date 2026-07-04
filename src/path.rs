use crate::{Error, Result};

const MAX_PATH_BYTES: usize = 4096;
const MAX_PATH_SEGMENTS: usize = 64;

pub(crate) fn path_byte_is_forbidden(byte: u8) -> bool {
    byte.is_ascii_control() || matches!(byte, b' ' | b'%' | b'\\' | b'?' | b'#')
}

/// Validates an OpenBao mount-style path and returns normalized path segments.
///
/// Mount paths must be non-empty, below the crate path length and segment
/// limits, and free of ambiguous path characters such as control characters,
/// backslashes, query/fragment markers, empty segments, relative segments, and
/// trailing periods.
pub fn validate_mount_path(value: &str) -> Result<Vec<String>> {
    validate_path(value, false)
}

/// Validates an OpenBao endpoint-style path and returns normalized segments.
///
/// Unlike [`validate_mount_path`], an empty path is accepted. This is useful for
/// wrappers that need to validate caller-provided endpoint tails before joining
/// them to a mount path.
pub fn validate_endpoint_path(value: &str) -> Result<Vec<String>> {
    validate_path(value, true)
}

fn validate_path(value: &str, allow_empty: bool) -> Result<Vec<String>> {
    if value.len() > MAX_PATH_BYTES {
        return Err(Error::InvalidPath(
            "path exceeds maximum allowed length".into(),
        ));
    }
    if !value.is_ascii() {
        return Err(Error::InvalidPath(
            "non-ASCII characters are not allowed in OpenBao paths".into(),
        ));
    }
    if value.bytes().any(path_byte_is_forbidden) {
        if value.as_bytes().iter().any(u8::is_ascii_control) {
            return Err(Error::InvalidPath(
                "control characters are not allowed".into(),
            ));
        }
        if value.contains('%') {
            return Err(Error::InvalidPath(
                "percent characters are not allowed in OpenBao paths".into(),
            ));
        }
        if value.bytes().any(|byte| byte == b' ') {
            return Err(Error::InvalidPath(
                "space characters are not allowed".into(),
            ));
        }
        if value.contains('\\') || value.contains('?') || value.contains('#') {
            return Err(Error::InvalidPath(
                "backslash, query, and fragment characters are not allowed".into(),
            ));
        }
    }
    let trimmed = value.trim_matches('/');
    if trimmed.is_empty() {
        if allow_empty {
            return Ok(Vec::new());
        }
        return Err(Error::InvalidPath("path must not be empty".into()));
    }
    if trimmed.ends_with('.') {
        return Err(Error::InvalidPath(
            "OpenBao path parameters must not end in periods".into(),
        ));
    }

    let mut segments = Vec::new();
    for segment in trimmed.split('/') {
        if segments.len() >= MAX_PATH_SEGMENTS {
            return Err(Error::InvalidPath(
                "path exceeds maximum segment count".into(),
            ));
        }
        if segment.is_empty() {
            return Err(Error::InvalidPath(
                "empty path segments are not allowed".into(),
            ));
        }
        if segment == "." || segment == ".." {
            return Err(Error::InvalidPath(
                "relative path segments are not allowed".into(),
            ));
        }
        if segment.ends_with('.') {
            return Err(Error::InvalidPath(
                "OpenBao path segments must not end in periods".into(),
            ));
        }
        segments.push(segment.to_owned());
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::{MAX_PATH_BYTES, MAX_PATH_SEGMENTS, validate_endpoint_path, validate_mount_path};

    #[test]
    fn rejects_ambiguous_paths() {
        assert!(validate_mount_path("../secret").is_err());
        assert!(validate_mount_path("secret//nested").is_err());
        assert!(validate_mount_path("secret?x=1").is_err());
        assert!(validate_mount_path("secret.").is_err());
        assert!(validate_mount_path("secret path").is_err());
        assert!(validate_mount_path("secret/%2e%2e").is_err());
        assert!(validate_mount_path("secret/\u{202e}hidden").is_err());
        assert!(validate_mount_path(&"a".repeat(MAX_PATH_BYTES + 1)).is_err());
        assert!(validate_endpoint_path(&vec!["a"; MAX_PATH_SEGMENTS + 1].join("/")).is_err());
    }

    #[test]
    fn accepts_root_endpoint_path() {
        let path = validate_endpoint_path("").unwrap_or_else(|error| panic!("{error}"));
        assert!(path.is_empty());
    }
}
