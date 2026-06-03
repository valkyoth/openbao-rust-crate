//! Safe building blocks for typed custom OpenBao plugin wrappers.

use crate::{
    Authenticated, Client, Result,
    path::{validate_endpoint_path, validate_mount_path},
};

/// Validated mount handle for deployment-specific OpenBao plugin wrappers.
///
/// This is intentionally not a plugin trait. OpenBao plugins do not share a
/// schema shape that the crate can abstract over safely. `PluginMount` only
/// provides the same validated mount-plus-tail path construction pattern used
/// by built-in engine handles.
#[derive(Clone, Debug)]
pub struct PluginMount<'a> {
    client: &'a Client<Authenticated>,
    mount: Vec<String>,
}

impl<'a> PluginMount<'a> {
    /// Creates a validated plugin mount handle.
    pub fn new(client: &'a Client<Authenticated>, mount: &str) -> Result<Self> {
        let mount = validate_mount_path(mount)?;
        Ok(Self { client, mount })
    }

    /// Returns the authenticated client used by this plugin wrapper.
    #[must_use]
    pub const fn client(&self) -> &'a Client<Authenticated> {
        self.client
    }

    /// Returns the validated mount path as normalized segments.
    #[must_use]
    pub fn mount_segments(&self) -> &[String] {
        &self.mount
    }

    /// Builds a validated `/v1`-relative path under this plugin mount.
    pub fn path(&self, tail: &[&str]) -> Result<String> {
        let mut segments = self.mount.clone();
        for segment in tail {
            segments.extend(validate_endpoint_path(segment)?);
        }
        Ok(segments.join("/"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::SecretString;

    use crate::{Client, PluginMount};

    #[test]
    fn plugin_mount_builds_validated_paths() {
        let client = Client::new("https://bao.example.com:8200")
            .unwrap_or_else(|error| panic!("{error}"))
            .try_with_token(SecretString::from("test-token"))
            .unwrap_or_else(|error| panic!("{error}"));
        let mount =
            PluginMount::new(&client, "custom/plugin").unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            mount
                .path(&["creds", "readonly"])
                .unwrap_or_else(|error| panic!("{error}")),
            "custom/plugin/creds/readonly"
        );
        assert!(PluginMount::new(&client, "custom//plugin").is_err());
        assert!(mount.path(&["creds?role=readonly"]).is_err());
    }
}
