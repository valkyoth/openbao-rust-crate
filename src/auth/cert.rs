//! TLS certificate authentication support.

use core::fmt;
use std::collections::BTreeMap;

use reqwest::{Method, StatusCode};
use secrecy::SecretString;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{IgnoredAny, MapAccess, SeqAccess, Visitor},
};

use crate::{
    Authenticated, Client, Error, Result, Unauthenticated,
    path::validate_mount_path,
    response::{Empty, ResponseEnvelope, deserialize_bounded_string_map_or_default},
};

/// Handle for TLS certificate auth login at a configured mount.
#[derive(Debug)]
pub struct CertAuth<'a> {
    client: &'a Client<Unauthenticated>,
    mount: String,
}

/// Handle for TLS certificate auth administration at a configured mount.
#[derive(Debug)]
pub struct CertAuthAdmin<'a> {
    client: &'a Client<Authenticated>,
    mount: String,
}

/// TLS certificate auth method configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CertAuthConfig {
    /// Skips matching the renewed token to the certificate identity used at login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_binding: Option<bool>,
    /// Stores certificate metadata on the identity alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_identity_alias_metadata: Option<bool>,
    /// OCSP response cache size for all configured certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsp_cache_size: Option<u64>,
}

/// CA certificate role configuration for the TLS certificate auth method.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CertRole {
    /// PEM-format CA certificate.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub certificate: String,
    /// Deprecated combined name constraint.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub allowed_names: String,
    /// Allowed Common Name patterns.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_common_names: Vec<String>,
    /// Allowed DNS SAN patterns.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_dns_sans: Vec<String>,
    /// Allowed email SAN patterns.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_email_sans: Vec<String>,
    /// Allowed URI SAN patterns.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_uri_sans: Vec<String>,
    /// Allowed organizational unit patterns.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_organizational_units: Vec<String>,
    /// Required custom extension OID/value patterns.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub required_extensions: Vec<String>,
    /// Metadata extension OIDs to copy into the auth alias.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_metadata_extensions: Vec<String>,
    /// Enables OCSP revocation checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsp_enabled: Option<bool>,
    /// Base64 encoded PEM CA certificates for OCSP response verification.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ocsp_ca_certificates: String,
    /// OCSP responder override URLs.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ocsp_servers_override: Vec<String>,
    /// Whether OCSP lookup errors should allow login to continue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsp_fail_open: Option<bool>,
    /// Requires all OCSP responders to agree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsp_query_all_servers: Option<bool>,
    /// Token display name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub display_name: String,
    /// Deprecated policy field.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    /// Policies attached to generated tokens.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_policies: Vec<String>,
    /// CIDR blocks allowed for login and token use.
    #[serde(default, deserialize_with = "deserialize_bounded_string_or_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_bound_cidrs: Vec<String>,
    /// Bind the generated token to the source IP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_strictly_bind_ip: Option<bool>,
    /// Token TTL such as `30m`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    /// Token max TTL such as `2h`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
    /// Token explicit max TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_explicit_max_ttl: Option<String>,
    /// Excludes the default policy from generated tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_no_default_policy: Option<bool>,
    /// Maximum use count for generated tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_num_uses: Option<u64>,
    /// Periodic token period.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_period: Option<String>,
    /// Generated token type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

/// Certificate role list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct CertRoleList {
    /// Role names.
    #[serde(
        default,
        deserialize_with = "crate::response::deserialize_bounded_string_vec"
    )]
    pub keys: Vec<String>,
}

/// CRL configuration for the TLS certificate auth method.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CertCrl {
    /// PEM-format CRL. If `crl` and `url` are both set, OpenBao uses `crl`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub crl: String,
    /// URL for a CRL distribution point.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
}

/// CRL name list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct CertCrlList {
    /// CRL names.
    #[serde(
        default,
        deserialize_with = "crate::response::deserialize_bounded_string_vec"
    )]
    pub keys: Vec<String>,
}

/// CRL serial-number information.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct CertCrlInfo {
    /// Revoked certificate serial numbers.
    #[serde(default, deserialize_with = "deserialize_bounded_serial_map")]
    pub serials: Vec<String>,
}

/// Metadata returned after a successful TLS certificate login.
#[derive(Debug, Deserialize)]
pub struct CertLoginMetadata {
    /// Token accessor. Accessors can revoke or look up token metadata, so they
    /// are treated as secret material when present.
    #[serde(default)]
    pub accessor: Option<SecretString>,
    /// Policies attached to the token.
    #[serde(
        default,
        deserialize_with = "crate::response::deserialize_bounded_string_vec"
    )]
    pub policies: Vec<String>,
    /// Token lease duration in seconds.
    #[serde(default)]
    pub lease_duration: u64,
    /// Whether the token is renewable.
    #[serde(default)]
    pub renewable: bool,
    /// Metadata returned by OpenBao for the certificate identity.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct CertLoginRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
}

#[derive(Deserialize)]
struct CertLoginResponse {
    auth: Option<CertLoginAuth>,
}

#[derive(Deserialize)]
struct CertLoginAuth {
    client_token: SecretString,
    #[serde(default)]
    accessor: Option<SecretString>,
    #[serde(
        default,
        deserialize_with = "crate::response::deserialize_bounded_string_vec"
    )]
    policies: Vec<String>,
    #[serde(default)]
    lease_duration: u64,
    #[serde(default)]
    renewable: bool,
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    metadata: BTreeMap<String, String>,
}

impl Client<Unauthenticated> {
    /// Uses the TLS certificate auth method mounted at `auth/cert`.
    pub fn cert(&self) -> Result<CertAuth<'_>> {
        self.cert_at("cert")
    }

    /// Uses the TLS certificate auth method mounted at `auth/{mount}`.
    pub fn cert_at(&self, mount: impl Into<String>) -> Result<CertAuth<'_>> {
        Ok(CertAuth {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }

    /// Logs in with TLS certificate auth at `auth/cert`.
    ///
    /// The client configuration must include a mutual TLS client identity.
    pub async fn login_cert(
        self,
        role: Option<&str>,
    ) -> Result<(Client<Authenticated>, CertLoginMetadata)> {
        let response = self.cert()?.login_response(role).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((self.try_with_token(token)?, metadata))
    }
}

impl Client<Authenticated> {
    /// Administers the TLS certificate auth method mounted at `auth/cert`.
    pub fn cert_admin(&self) -> Result<CertAuthAdmin<'_>> {
        self.cert_admin_at("cert")
    }

    /// Administers the TLS certificate auth method mounted at `auth/{mount}`.
    pub fn cert_admin_at(&self, mount: impl Into<String>) -> Result<CertAuthAdmin<'_>> {
        Ok(CertAuthAdmin {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }
}

impl CertAuth<'_> {
    /// Logs in and returns token metadata plus an authenticated client.
    ///
    /// The client configuration must include a mutual TLS client identity.
    pub async fn login(
        self,
        role: Option<&str>,
    ) -> Result<(Client<Authenticated>, CertLoginMetadata)> {
        let response = self.login_response(role).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((
            self.client.clone_without_state().try_with_token(token)?,
            metadata,
        ))
    }

    async fn login_response(&self, role: Option<&str>) -> Result<CertLoginAuth> {
        let role = match role {
            Some(role) => Some(validate_mount_path(role)?.join("/")),
            None => None,
        };
        let request = CertLoginRequest {
            name: role.as_deref(),
        };
        let response: CertLoginResponse = self
            .client
            .request_json(
                Method::POST,
                &format!("auth/{}/login", self.mount),
                Some(&request),
            )
            .await?;
        response.auth.ok_or(Error::MissingField("auth"))
    }
}

impl CertAuthAdmin<'_> {
    /// Configures the TLS certificate auth method.
    pub async fn configure(&self, config: &CertAuthConfig) -> Result<Empty> {
        self.client
            .request_json(
                Method::POST,
                &format!("auth/{}/config", self.mount),
                Some(config),
            )
            .await
    }

    /// Creates or updates a CA certificate role.
    pub async fn write_role(&self, name: &str, role: &CertRole) -> Result<Empty> {
        let name = validate_mount_path(name)?.join("/");
        self.client
            .request_json(
                Method::POST,
                &format!("auth/{}/certs/{name}", self.mount),
                Some(role),
            )
            .await
    }

    /// Reads a CA certificate role.
    pub async fn read_role(&self, name: &str) -> Result<CertRole> {
        let name = validate_mount_path(name)?.join("/");
        let envelope: ResponseEnvelope<CertRole> = self
            .client
            .request_json(
                Method::GET,
                &format!("auth/{}/certs/{name}", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists CA certificate role names.
    pub async fn list_roles(
        &self,
        after: Option<&str>,
        limit: Option<u64>,
    ) -> Result<CertRoleList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let mut query = Vec::new();
        if let Some(after) = after {
            query.push(("after", validate_mount_path(after)?.join("/")));
        }
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        let envelope: ResponseEnvelope<CertRoleList> = self
            .client
            .request_json_query_accepting(
                method,
                &format!("auth/{}/certs", self.mount),
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a CA certificate role.
    pub async fn delete_role(&self, name: &str) -> Result<Empty> {
        let name = validate_mount_path(name)?.join("/");
        self.client
            .request_json_accepting(
                Method::DELETE,
                &format!("auth/{}/certs/{name}", self.mount),
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Creates or updates a named CRL.
    pub async fn write_crl(&self, name: &str, crl: &CertCrl) -> Result<Empty> {
        let name = validate_mount_path(name)?.join("/");
        self.client
            .request_json(
                Method::POST,
                &format!("auth/{}/crls/{name}", self.mount),
                Some(crl),
            )
            .await
    }

    /// Reads CRL serial-number information.
    pub async fn read_crl(&self, name: &str) -> Result<CertCrlInfo> {
        let name = validate_mount_path(name)?.join("/");
        let envelope: ResponseEnvelope<CertCrlInfo> = self
            .client
            .request_json(
                Method::GET,
                &format!("auth/{}/crls/{name}", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists CRL names.
    pub async fn list_crls(&self, after: Option<&str>, limit: Option<u64>) -> Result<CertCrlList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let mut query = Vec::new();
        if let Some(after) = after {
            query.push(("after", validate_mount_path(after)?.join("/")));
        }
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        let envelope: ResponseEnvelope<CertCrlList> = self
            .client
            .request_json_query_accepting(
                method,
                &format!("auth/{}/crls", self.mount),
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a CRL.
    pub async fn delete_crl(&self, name: &str) -> Result<Empty> {
        let name = validate_mount_path(name)?.join("/");
        self.client
            .request_json_accepting(
                Method::DELETE,
                &format!("auth/{}/crls/{name}", self.mount),
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }
}

fn split_login_auth(auth: CertLoginAuth) -> (SecretString, CertLoginMetadata) {
    let CertLoginAuth {
        client_token,
        accessor,
        policies,
        lease_duration,
        renewable,
        metadata,
    } = auth;
    let metadata = CertLoginMetadata {
        accessor,
        policies,
        lease_duration,
        renewable,
        metadata,
    };
    (client_token, metadata)
}

fn deserialize_bounded_string_or_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(StringOrListVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

struct StringOrListVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for StringOrListVisitor<MAX> {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a comma-separated string or a list of at most {MAX} strings"
        )
    }

    fn visit_unit<E>(self) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Vec::new())
    }

    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.trim().is_empty() {
            return Ok(Vec::new());
        }
        let values: Vec<String> = value
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect();
        if values.len() > MAX {
            return Err(E::custom("OpenBao string list exceeds item limit"));
        }
        Ok(values)
    }

    fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&value)
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while values.len() < MAX {
            let Some(value) = seq.next_element::<String>()? else {
                return Ok(values);
            };
            values.push(value);
        }
        if seq.next_element::<IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(
                "OpenBao string list exceeds item limit",
            ));
        }
        Ok(values)
    }
}

fn deserialize_bounded_serial_map<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(SerialMapVisitor::<{ crate::response::MAX_RESPONSE_STRINGS }>)
}

struct SerialMapVisitor<const MAX: usize>;

impl<'de, const MAX: usize> Visitor<'de> for SerialMapVisitor<MAX> {
    type Value = Vec<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a map of at most {MAX} certificate serials")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut serials = Vec::new();
        while serials.len() < MAX {
            let Some((serial, _value)) = map.next_entry::<String, IgnoredAny>()? else {
                return Ok(serials);
            };
            serials.push(serial);
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(
                "OpenBao CRL serial map exceeds item limit",
            ));
        }
        Ok(serials)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::{ExposeSecret, SecretString};

    use super::{CertCrlInfo, CertLoginResponse, CertRole, CertRoleList};

    #[test]
    fn cert_login_auth_deserializes_secret_token_fields() {
        let response: CertLoginResponse = serde_json::from_str(
            r#"{"auth":{"client_token":"token-value","accessor":"accessor-value","policies":["web"]}}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let auth = response.auth.unwrap_or_else(|| panic!("auth missing"));

        assert_eq!(auth.client_token.expose_secret(), "token-value");
        assert_eq!(
            auth.accessor.as_ref().map(SecretString::expose_secret),
            Some("accessor-value")
        );
        assert_eq!(auth.policies, ["web"]);
    }

    #[test]
    fn cert_role_accepts_string_and_array_lists() {
        let role: CertRole = serde_json::from_str(
            r#"{"certificate":"pem","allowed_dns_sans":"a.example,b.example","token_policies":["web"]}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(role.allowed_dns_sans, ["a.example", "b.example"]);
        assert_eq!(role.token_policies, ["web"]);
    }

    #[test]
    fn cert_role_list_is_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("cert-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<CertRoleList>(value) {
            Ok(_) => panic!("oversized cert role list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn cert_crl_serial_map_is_bounded() {
        let mut serials = serde_json::Map::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            serials.insert(index.to_string(), serde_json::json!({}));
        }
        let value = serde_json::json!({ "serials": serials });
        let error = match serde_json::from_value::<CertCrlInfo>(value) {
            Ok(_) => panic!("oversized cert CRL serial map unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }
}
