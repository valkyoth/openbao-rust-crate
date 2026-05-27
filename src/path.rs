use crate::{Error, Result};

pub(crate) fn validate_mount_path(value: &str) -> Result<Vec<String>> {
    validate_path(value, false)
}

pub(crate) fn validate_secret_path(value: &str) -> Result<Vec<String>> {
    validate_path(value, true)
}

fn validate_path(value: &str, allow_empty: bool) -> Result<Vec<String>> {
    if value.as_bytes().iter().any(u8::is_ascii_control) {
        return Err(Error::InvalidPath(
            "control characters are not allowed".into(),
        ));
    }
    if value.contains('\\') || value.contains('?') || value.contains('#') {
        return Err(Error::InvalidPath(
            "backslash, query, and fragment characters are not allowed".into(),
        ));
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

    use super::{validate_mount_path, validate_secret_path};

    #[test]
    fn rejects_ambiguous_paths() {
        assert!(validate_mount_path("../secret").is_err());
        assert!(validate_mount_path("secret//nested").is_err());
        assert!(validate_mount_path("secret?x=1").is_err());
        assert!(validate_mount_path("secret.").is_err());
    }

    #[test]
    fn accepts_root_secret_path() {
        let path = validate_secret_path("").unwrap_or_else(|error| panic!("{error}"));
        assert!(path.is_empty());
    }
}
