//! LDAP authentication support.

use core::fmt;
use std::collections::BTreeMap;

use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, de::Visitor};

use crate::{
    Authenticated, Client, Error, Result, Unauthenticated,
    path::validate_mount_path,
    response::{
        Empty, ListEntries, ResponseEnvelope, deserialize_bounded_string_map_or_default,
        deserialize_bounded_string_vec,
    },
    validation::{validate_duration_string, validate_optional_ldap_tls_version},
};

/// Handle for LDAP auth login at a configured mount.
#[derive(Debug)]
pub struct LdapAuth<'a> {
    client: &'a Client<Unauthenticated>,
    mount: String,
}

/// Handle for LDAP auth administration at a configured mount.
#[derive(Debug)]
pub struct LdapAuthAdmin<'a> {
    client: &'a Client<Authenticated>,
    mount: String,
}

/// LDAP auth method configuration.
#[derive(Clone, Default, Deserialize)]
pub struct LdapAuthConfig {
    /// LDAP server URL or comma-separated URL list.
    #[serde(default)]
    pub url: Option<String>,
    /// Whether local user/group policy mapping names are case-sensitive.
    #[serde(default)]
    pub case_sensitive_names: Option<bool>,
    /// Connection timeout as seconds or OpenBao duration string.
    #[serde(default, deserialize_with = "deserialize_optional_string_or_u64")]
    pub connection_timeout: Option<String>,
    /// Request timeout as seconds or OpenBao duration string.
    #[serde(default, deserialize_with = "deserialize_optional_string_or_u64")]
    pub request_timeout: Option<String>,
    /// Whether to issue StartTLS after connecting.
    #[serde(default)]
    pub starttls: Option<bool>,
    /// Minimum LDAP TLS version.
    #[serde(default)]
    pub tls_min_version: Option<String>,
    /// Maximum LDAP TLS version.
    #[serde(default)]
    pub tls_max_version: Option<String>,
    /// Whether to skip LDAP TLS certificate verification.
    #[serde(default)]
    pub insecure_tls: Option<bool>,
    /// CA certificate used to verify the LDAP server.
    #[serde(default)]
    pub certificate: Option<String>,
    /// Client certificate presented to the LDAP server.
    #[serde(default)]
    pub client_tls_cert: Option<String>,
    /// Client private key presented to the LDAP server.
    #[serde(default)]
    pub client_tls_key: Option<SecretString>,
    /// Bind DN used by OpenBao for LDAP searches.
    #[serde(default)]
    pub binddn: Option<String>,
    /// Bind password used by OpenBao for LDAP searches.
    #[serde(default)]
    pub bindpass: Option<SecretString>,
    /// Base DN for user search.
    #[serde(default)]
    pub userdn: Option<String>,
    /// User attribute matched during login.
    #[serde(default)]
    pub userattr: Option<String>,
    /// Whether to discover the user DN with anonymous bind.
    #[serde(default)]
    pub discoverdn: Option<bool>,
    /// Whether empty passwords are rejected before LDAP bind.
    #[serde(default)]
    pub deny_null_bind: Option<bool>,
    /// UPN domain used for Active Directory login binds.
    #[serde(default)]
    pub upndomain: Option<String>,
    /// LDAP user search filter template.
    #[serde(default)]
    pub userfilter: Option<String>,
    /// Whether group searches use anonymous binds.
    #[serde(default)]
    pub anonymous_group_search: Option<bool>,
    /// LDAP group search filter template.
    #[serde(default)]
    pub groupfilter: Option<String>,
    /// Base DN for group search.
    #[serde(default)]
    pub groupdn: Option<String>,
    /// LDAP group attribute to enumerate.
    #[serde(default)]
    pub groupattr: Option<String>,
    /// Whether username is used as the entity alias.
    #[serde(default)]
    pub username_as_alias: Option<bool>,
    /// LDAP alias dereference behavior.
    #[serde(default)]
    pub dereference_aliases: Option<String>,
    /// LDAP paged search maximum page size.
    #[serde(default)]
    pub max_page_size: Option<u64>,
    /// Whether Active Directory tokenGroups is used for group membership.
    #[serde(default)]
    pub use_token_groups: Option<bool>,
    /// Policies attached to generated tokens.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub token_policies: Vec<String>,
    /// Deprecated policy field retained for older OpenBao 2.x compatibility.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub policies: Vec<String>,
    /// Generated token CIDR restrictions.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub token_bound_cidrs: Vec<String>,
    /// Whether generated tokens are bound to the login source IP.
    #[serde(default)]
    pub token_strictly_bind_ip: Option<bool>,
    /// Token TTL such as `30m`.
    #[serde(default, deserialize_with = "deserialize_optional_string_or_u64")]
    pub token_ttl: Option<String>,
    /// Token max TTL such as `2h`.
    #[serde(default, deserialize_with = "deserialize_optional_string_or_u64")]
    pub token_max_ttl: Option<String>,
    /// Token explicit max TTL.
    #[serde(default, deserialize_with = "deserialize_optional_string_or_u64")]
    pub token_explicit_max_ttl: Option<String>,
    /// Whether to omit the default policy.
    #[serde(default)]
    pub token_no_default_policy: Option<bool>,
    /// Number of allowed token uses.
    #[serde(default)]
    pub token_num_uses: Option<u64>,
    /// Periodic token period.
    #[serde(default, deserialize_with = "deserialize_optional_string_or_u64")]
    pub token_period: Option<String>,
    /// Generated token type.
    #[serde(default)]
    pub token_type: Option<String>,
}

#[derive(Serialize)]
struct LdapAuthConfigPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    case_sensitive_names: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_timeout: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_timeout: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    starttls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_min_version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_max_version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    insecure_tls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_tls_cert: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_tls_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binddn: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bindpass: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    userdn: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    userattr: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discoverdn: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deny_null_bind: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upndomain: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    userfilter: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    anonymous_group_search: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groupfilter: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groupdn: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groupattr: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username_as_alias: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dereference_aliases: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_page_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    use_token_groups: Option<bool>,
    #[serde(skip_serializing_if = "is_empty_string_slice")]
    token_policies: &'a [String],
    #[serde(skip_serializing_if = "is_empty_string_slice")]
    policies: &'a [String],
    #[serde(skip_serializing_if = "is_empty_string_slice")]
    token_bound_cidrs: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    token_strictly_bind_ip: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_ttl: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_max_ttl: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_explicit_max_ttl: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_no_default_policy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_num_uses: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_period: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<&'a str>,
}

impl LdapAuthConfig {
    /// Creates an empty LDAP auth config.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the LDAP URL or comma-separated URL list.
    #[must_use]
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Sets the bind DN and password used for LDAP searches.
    #[must_use]
    pub fn with_bind(mut self, binddn: impl Into<String>, bindpass: SecretString) -> Self {
        self.binddn = Some(binddn.into());
        self.bindpass = Some(bindpass);
        self
    }

    /// Adds a generated-token policy.
    #[must_use]
    pub fn with_token_policy(mut self, policy: impl Into<String>) -> Self {
        self.token_policies.push(policy.into());
        self
    }

    /// Adds a generated-token CIDR restriction.
    pub fn with_token_bound_cidr(mut self, cidr: impl Into<String>) -> Result<Self> {
        let cidr = cidr.into();
        crate::validation::validate_cidr(&cidr, "LDAP auth token_bound_cidrs")?;
        self.token_bound_cidrs.push(cidr);
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        #[cfg(not(feature = "insecure-ldap-tls-acknowledged"))]
        if self.insecure_tls == Some(true) {
            return Err(Error::InvalidParameter(
                "LDAP auth insecure_tls=true requires the insecure-ldap-tls-acknowledged Cargo feature because it disables LDAP TLS certificate verification".into(),
            ));
        }
        if self.insecure_tls == Some(true)
            && (self.bindpass.is_some() || self.client_tls_key.is_some())
        {
            return Err(Error::InvalidParameter(
                "LDAP auth insecure_tls=true must not be combined with bindpass or client_tls_key because credentials would cross an unverified TLS connection".into(),
            ));
        }
        #[cfg(not(feature = "insecure-ldap-tls-acknowledged"))]
        validate_ldap_urls_use_encrypted_transport(&self.url, self.starttls, "LDAP auth")?;
        crate::validation::validate_cidr_list(
            &self.token_bound_cidrs,
            "LDAP auth token_bound_cidrs",
        )?;
        if self.token_strictly_bind_ip == Some(true) && !self.token_bound_cidrs.is_empty() {
            return Err(Error::InvalidParameter(
                "LDAP auth token_strictly_bind_ip conflicts with token_bound_cidrs".into(),
            ));
        }
        validate_optional_duration(&self.connection_timeout, "LDAP auth connection_timeout")?;
        validate_optional_duration(&self.request_timeout, "LDAP auth request_timeout")?;
        validate_optional_duration(&self.token_ttl, "LDAP auth token_ttl")?;
        validate_optional_duration(&self.token_max_ttl, "LDAP auth token_max_ttl")?;
        validate_optional_duration(
            &self.token_explicit_max_ttl,
            "LDAP auth token_explicit_max_ttl",
        )?;
        validate_optional_duration(&self.token_period, "LDAP auth token_period")?;
        validate_optional_ldap_tls_version(&self.tls_min_version, "LDAP auth tls_min_version")?;
        validate_optional_ldap_tls_version(&self.tls_max_version, "LDAP auth tls_max_version")?;
        validate_optional_alias_mode(&self.dereference_aliases)?;
        Ok(())
    }
}

impl fmt::Debug for LdapAuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LdapAuthConfig")
            .field("url", &self.url)
            .field("case_sensitive_names", &self.case_sensitive_names)
            .field("connection_timeout", &self.connection_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("starttls", &self.starttls)
            .field("tls_min_version", &self.tls_min_version)
            .field("tls_max_version", &self.tls_max_version)
            .field("insecure_tls", &self.insecure_tls)
            .field(
                "certificate",
                &self.certificate.as_ref().map(|_| "<redacted-pem>"),
            )
            .field(
                "client_tls_cert",
                &self.client_tls_cert.as_ref().map(|_| "<redacted-pem>"),
            )
            .field(
                "client_tls_key",
                &self.client_tls_key.as_ref().map(|_| "<redacted>"),
            )
            .field("binddn", &self.binddn)
            .field("bindpass", &self.bindpass.as_ref().map(|_| "<redacted>"))
            .field("userdn", &self.userdn)
            .field("userattr", &self.userattr)
            .field("discoverdn", &self.discoverdn)
            .field("deny_null_bind", &self.deny_null_bind)
            .field("upndomain", &self.upndomain)
            .field("userfilter", &self.userfilter)
            .field("anonymous_group_search", &self.anonymous_group_search)
            .field("groupfilter", &self.groupfilter)
            .field("groupdn", &self.groupdn)
            .field("groupattr", &self.groupattr)
            .field("username_as_alias", &self.username_as_alias)
            .field("dereference_aliases", &self.dereference_aliases)
            .field("max_page_size", &self.max_page_size)
            .field("use_token_groups", &self.use_token_groups)
            .field("token_policies", &self.token_policies)
            .field("token_bound_cidrs", &self.token_bound_cidrs)
            .field("token_strictly_bind_ip", &self.token_strictly_bind_ip)
            .field("token_ttl", &self.token_ttl)
            .field("token_max_ttl", &self.token_max_ttl)
            .field("token_explicit_max_ttl", &self.token_explicit_max_ttl)
            .field("token_no_default_policy", &self.token_no_default_policy)
            .field("token_num_uses", &self.token_num_uses)
            .field("token_period", &self.token_period)
            .field("token_type", &self.token_type)
            .finish()
    }
}

/// LDAP auth local user or group policy mapping.
#[derive(Clone, Debug, Default)]
pub struct LdapAuthMappingRequest {
    /// Policies mapped to this LDAP user or group.
    pub policies: Vec<String>,
    /// LDAP groups additionally mapped to this LDAP user.
    pub groups: Vec<String>,
}

impl LdapAuthMappingRequest {
    /// Creates a mapping request with one policy.
    pub fn new(policy: impl Into<String>) -> Self {
        Self {
            policies: vec![policy.into()],
            groups: Vec::new(),
        }
    }

    /// Adds a policy.
    #[must_use]
    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.policies.push(policy.into());
        self
    }

    /// Adds a group mapping for LDAP users.
    #[must_use]
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.groups.push(group.into());
        self
    }
}

#[derive(Serialize)]
struct LdapAuthMappingPayload {
    policies: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    groups: String,
}

/// LDAP auth user or group policy mapping returned by OpenBao.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct LdapAuthMappingInfo {
    /// Policies mapped to this LDAP user or group.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub policies: Vec<String>,
    /// Comma-separated group mapping returned for LDAP users.
    #[serde(default)]
    pub groups: Option<String>,
}

/// LDAP auth user or group list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct LdapAuthList {
    /// Names returned by OpenBao.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for LdapAuthList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Metadata returned after a successful LDAP login.
#[derive(Debug, Deserialize)]
pub struct LdapAuthLoginMetadata {
    /// Token accessor, when returned by OpenBao.
    #[serde(default)]
    pub accessor: Option<SecretString>,
    /// Policies attached to the token.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub policies: Vec<String>,
    /// Token lease duration in seconds.
    #[serde(default)]
    pub lease_duration: u64,
    /// Whether the token is renewable.
    #[serde(default)]
    pub renewable: bool,
    /// Metadata returned by OpenBao, usually including the username.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct LdapAuthLoginRequest<'a> {
    password: &'a str,
}

#[derive(Deserialize)]
struct LdapAuthLoginResponse {
    auth: Option<LdapAuthLoginAuth>,
}

#[derive(Deserialize)]
struct LdapAuthLoginAuth {
    client_token: SecretString,
    #[serde(default)]
    accessor: Option<SecretString>,
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
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
    /// Uses the LDAP auth method mounted at `auth/ldap`.
    pub fn ldap_auth(&self) -> Result<LdapAuth<'_>> {
        self.ldap_auth_at("ldap")
    }

    /// Uses the LDAP auth method mounted at `auth/{mount}`.
    pub fn ldap_auth_at(&self, mount: impl Into<String>) -> Result<LdapAuth<'_>> {
        Ok(LdapAuth {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }

    /// Logs in with LDAP auth at `auth/ldap`.
    pub async fn login_ldap(
        self,
        username: &str,
        password: SecretString,
    ) -> Result<(Client<Authenticated>, LdapAuthLoginMetadata)> {
        let response = self
            .ldap_auth()?
            .login_response(username, &password)
            .await?;
        let (token, metadata) = split_login_auth(response);
        Ok((self.try_with_token(token)?, metadata))
    }
}

impl Client<Authenticated> {
    /// Administers the LDAP auth method mounted at `auth/ldap`.
    pub fn ldap_auth_admin(&self) -> Result<LdapAuthAdmin<'_>> {
        self.ldap_auth_admin_at("ldap")
    }

    /// Administers the LDAP auth method mounted at `auth/{mount}`.
    pub fn ldap_auth_admin_at(&self, mount: impl Into<String>) -> Result<LdapAuthAdmin<'_>> {
        Ok(LdapAuthAdmin {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }
}

impl LdapAuth<'_> {
    /// Logs in and returns token metadata plus an authenticated client.
    pub async fn login(
        self,
        username: &str,
        password: SecretString,
    ) -> Result<(Client<Authenticated>, LdapAuthLoginMetadata)> {
        let response = self.login_response(username, &password).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((
            self.client.clone_without_state().try_with_token(token)?,
            metadata,
        ))
    }

    async fn login_response(
        &self,
        username: &str,
        password: &SecretString,
    ) -> Result<LdapAuthLoginAuth> {
        let username = validate_ldap_path_name(username)?;
        let request = LdapAuthLoginRequest {
            password: password.expose_secret(),
        };
        let response: LdapAuthLoginResponse = self
            .client
            .request_auth_json_internal(
                "ldap",
                &self.mount,
                Method::POST,
                &format!("auth/{}/login/{username}", self.mount),
                Some(&request),
            )
            .await?;
        response.auth.ok_or(Error::MissingField("auth"))
    }
}

impl LdapAuthAdmin<'_> {
    /// Configures the LDAP auth method.
    pub async fn configure(&self, config: &LdapAuthConfig) -> Result<Empty> {
        config.validate()?;
        let payload = LdapAuthConfigPayload {
            url: config.url.as_deref(),
            case_sensitive_names: config.case_sensitive_names,
            connection_timeout: config.connection_timeout.as_deref(),
            request_timeout: config.request_timeout.as_deref(),
            starttls: config.starttls,
            tls_min_version: config.tls_min_version.as_deref(),
            tls_max_version: config.tls_max_version.as_deref(),
            insecure_tls: config.insecure_tls,
            certificate: config.certificate.as_deref(),
            client_tls_cert: config.client_tls_cert.as_deref(),
            client_tls_key: config
                .client_tls_key
                .as_ref()
                .map(SecretString::expose_secret),
            binddn: config.binddn.as_deref(),
            bindpass: config.bindpass.as_ref().map(SecretString::expose_secret),
            userdn: config.userdn.as_deref(),
            userattr: config.userattr.as_deref(),
            discoverdn: config.discoverdn,
            deny_null_bind: config.deny_null_bind,
            upndomain: config.upndomain.as_deref(),
            userfilter: config.userfilter.as_deref(),
            anonymous_group_search: config.anonymous_group_search,
            groupfilter: config.groupfilter.as_deref(),
            groupdn: config.groupdn.as_deref(),
            groupattr: config.groupattr.as_deref(),
            username_as_alias: config.username_as_alias,
            dereference_aliases: config.dereference_aliases.as_deref(),
            max_page_size: config.max_page_size,
            use_token_groups: config.use_token_groups,
            token_policies: &config.token_policies,
            policies: &config.policies,
            token_bound_cidrs: &config.token_bound_cidrs,
            token_strictly_bind_ip: config.token_strictly_bind_ip,
            token_ttl: config.token_ttl.as_deref(),
            token_max_ttl: config.token_max_ttl.as_deref(),
            token_explicit_max_ttl: config.token_explicit_max_ttl.as_deref(),
            token_no_default_policy: config.token_no_default_policy,
            token_num_uses: config.token_num_uses,
            token_period: config.token_period.as_deref(),
            token_type: config.token_type.as_deref(),
        };
        self.client
            .request_auth_json_internal(
                "ldap",
                &self.mount,
                Method::POST,
                &format!("auth/{}/config", self.mount),
                Some(&payload),
            )
            .await
    }

    /// Reads the LDAP auth method configuration.
    pub async fn read_config(&self) -> Result<LdapAuthConfig> {
        let envelope: ResponseEnvelope<LdapAuthConfig> = self
            .client
            .request_auth_json_internal(
                "ldap",
                &self.mount,
                Method::GET,
                &format!("auth/{}/config", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Creates or updates an LDAP auth group policy mapping.
    pub async fn write_group(&self, name: &str, group: &LdapAuthMappingRequest) -> Result<Empty> {
        self.write_mapping("groups", name, group).await
    }

    /// Reads an LDAP auth group policy mapping.
    pub async fn read_group(&self, name: &str) -> Result<LdapAuthMappingInfo> {
        self.read_mapping("groups", name).await
    }

    /// Deletes an LDAP auth group policy mapping.
    pub async fn delete_group(&self, name: &str) -> Result<Empty> {
        self.delete_mapping("groups", name).await
    }

    /// Lists LDAP auth group names.
    pub async fn list_groups(&self) -> Result<LdapAuthList> {
        self.list_mapping_names("groups").await
    }

    /// Creates or updates an LDAP auth user policy mapping.
    pub async fn write_user(&self, username: &str, user: &LdapAuthMappingRequest) -> Result<Empty> {
        self.write_mapping("users", username, user).await
    }

    /// Reads an LDAP auth user policy mapping.
    pub async fn read_user(&self, username: &str) -> Result<LdapAuthMappingInfo> {
        self.read_mapping("users", username).await
    }

    /// Deletes an LDAP auth user policy mapping.
    pub async fn delete_user(&self, username: &str) -> Result<Empty> {
        self.delete_mapping("users", username).await
    }

    /// Lists LDAP auth user names.
    pub async fn list_users(&self) -> Result<LdapAuthList> {
        self.list_mapping_names("users").await
    }

    async fn write_mapping(
        &self,
        kind: &str,
        name: &str,
        mapping: &LdapAuthMappingRequest,
    ) -> Result<Empty> {
        let name = validate_ldap_path_name(name)?;
        let payload = LdapAuthMappingPayload {
            policies: mapping.policies.join(","),
            groups: mapping.groups.join(","),
        };
        self.client
            .request_auth_json_internal(
                "ldap",
                &self.mount,
                Method::POST,
                &format!("auth/{}/{kind}/{name}", self.mount),
                Some(&payload),
            )
            .await
    }

    async fn read_mapping(&self, kind: &str, name: &str) -> Result<LdapAuthMappingInfo> {
        let name = validate_ldap_path_name(name)?;
        let envelope: ResponseEnvelope<LdapAuthMappingInfo> = self
            .client
            .request_auth_json_internal(
                "ldap",
                &self.mount,
                Method::GET,
                &format!("auth/{}/{kind}/{name}", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    async fn delete_mapping(&self, kind: &str, name: &str) -> Result<Empty> {
        let name = validate_ldap_path_name(name)?;
        self.client
            .request_auth_json_accepting(
                "ldap",
                &self.mount,
                Method::DELETE,
                &format!("auth/{}/{kind}/{name}", self.mount),
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    async fn list_mapping_names(&self, kind: &str) -> Result<LdapAuthList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<LdapAuthList> = self
            .client
            .request_auth_json_internal(
                "ldap",
                &self.mount,
                method,
                &format!("auth/{}/{kind}", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }
}

fn split_login_auth(auth: LdapAuthLoginAuth) -> (SecretString, LdapAuthLoginMetadata) {
    let LdapAuthLoginAuth {
        client_token,
        accessor,
        policies,
        lease_duration,
        renewable,
        metadata,
    } = auth;
    let metadata = LdapAuthLoginMetadata {
        accessor,
        policies,
        lease_duration,
        renewable,
        metadata,
    };
    (client_token, metadata)
}

fn is_empty_string_slice(values: &&[String]) -> bool {
    values.is_empty()
}

fn validate_optional_duration(value: &Option<String>, field: &'static str) -> Result<()> {
    if let Some(value) = value
        && !duration_or_seconds_is_valid(value, true)
    {
        return Err(Error::InvalidParameter(format!(
            "{field} must be seconds or a duration such as 0s, 30s, 5m, or 1h"
        )));
    }
    Ok(())
}

fn duration_or_seconds_is_valid(value: &str, allow_zero: bool) -> bool {
    value
        .parse::<u64>()
        .is_ok_and(|seconds| allow_zero || seconds > 0)
        || validate_duration_string(value, allow_zero)
}

fn validate_optional_alias_mode(value: &Option<String>) -> Result<()> {
    if let Some(value) = value
        && !matches!(value.as_str(), "never" | "finding" | "searching" | "always")
    {
        return Err(Error::InvalidParameter(
            "LDAP auth dereference_aliases must be never, finding, searching, or always".into(),
        ));
    }
    Ok(())
}

fn validate_ldap_path_name(name: &str) -> Result<&str> {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return Err(Error::InvalidPath(
            "LDAP auth path name must not be empty".into(),
        ));
    }
    if !name.is_ascii() {
        return Err(Error::InvalidPath(
            "LDAP auth path name must contain only ASCII characters".into(),
        ));
    }
    if bytes.iter().any(u8::is_ascii_control) {
        return Err(Error::InvalidPath(
            "LDAP auth path name must not contain control characters".into(),
        ));
    }
    if name.contains(' ') {
        return Err(Error::InvalidPath(
            "LDAP auth path name must not contain spaces".into(),
        ));
    }
    if name.contains(['*', '(', ')']) {
        return Err(Error::InvalidPath(
            "LDAP auth path name must not contain LDAP filter special characters".into(),
        ));
    }
    if name.contains(['\\', '/', '?', '#']) {
        return Err(Error::InvalidPath(
            "LDAP auth path name must not contain slash, backslash, query, or fragment characters"
                .into(),
        ));
    }
    if name == "." || name == ".." || name.ends_with('.') {
        return Err(Error::InvalidPath(
            "LDAP auth path name must not be relative or end in a period".into(),
        ));
    }
    Ok(name)
}

#[cfg(not(feature = "insecure-ldap-tls-acknowledged"))]
fn validate_ldap_urls_use_encrypted_transport(
    urls: &Option<String>,
    starttls: Option<bool>,
    label: &'static str,
) -> Result<()> {
    let Some(urls) = urls else {
        return Ok(());
    };
    if starttls == Some(true) {
        return Ok(());
    }
    for url in urls.split(',') {
        let url = url.trim();
        if url.is_empty() {
            continue;
        }
        if !url
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("ldaps://"))
        {
            return Err(Error::InvalidParameter(format!(
                "{label} URL must use ldaps:// or starttls=true unless insecure LDAP TLS is explicitly acknowledged"
            )));
        }
    }
    Ok(())
}

fn deserialize_optional_string_or_u64<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(OptionalStringOrU64Visitor)
}

struct OptionalStringOrU64Visitor;

impl<'de> Visitor<'de> for OptionalStringOrU64Visitor {
    type Value = Option<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("null, a string duration, or an integer duration")
    }

    fn visit_none<E>(self) -> core::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E>(self) -> core::result::Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> core::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_optional_string_or_u64(deserializer)
    }

    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Some(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E> {
        Ok(Some(value))
    }

    fn visit_u64<E>(self, value: u64) -> core::result::Result<Self::Value, E> {
        Ok(Some(value.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use secrecy::{ExposeSecret, SecretString};

    use super::{
        LdapAuthConfig, LdapAuthList, LdapAuthLoginResponse, LdapAuthMappingRequest,
        validate_ldap_path_name,
    };

    fn test_secret(parts: &[&str]) -> SecretString {
        SecretString::from(parts.concat())
    }

    #[test]
    fn ldap_auth_login_deserializes_secret_token_fields() {
        let response: LdapAuthLoginResponse = serde_json::from_str(
            r#"{"auth":{"client_token":"token-value","accessor":"accessor-value","metadata":{"username":"alice"}}}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let auth = response.auth.unwrap_or_else(|| panic!("auth missing"));

        assert_eq!(auth.client_token.expose_secret(), "token-value");
        assert_eq!(
            auth.accessor.as_ref().map(SecretString::expose_secret),
            Some("accessor-value")
        );
        assert_eq!(
            auth.metadata.get("username").map(String::as_str),
            Some("alice")
        );
    }

    #[test]
    fn ldap_auth_list_is_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("name-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<LdapAuthList>(value) {
            Ok(_) => panic!("oversized LDAP auth list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn ldap_auth_path_name_validation_rejects_ambiguous_values() {
        assert!(validate_ldap_path_name("admins").is_ok());
        assert!(validate_ldap_path_name("").is_err());
        assert!(validate_ldap_path_name(".").is_err());
        assert!(validate_ldap_path_name("..").is_err());
        assert!(validate_ldap_path_name("admins.").is_err());
        assert!(validate_ldap_path_name("admins\u{202e}").is_err());
        assert!(validate_ldap_path_name("Team A").is_err());
        assert!(validate_ldap_path_name("team/admins").is_err());
        assert!(validate_ldap_path_name("admins?x=1").is_err());
        assert!(validate_ldap_path_name("admin*)(uid=*)").is_err());
    }

    #[cfg(not(feature = "insecure-ldap-tls-acknowledged"))]
    #[test]
    fn ldap_auth_config_requires_encrypted_urls() {
        let mut config = LdapAuthConfig::new().with_url("ldap://ldap.example.com");
        assert!(config.validate().is_err());

        config.starttls = Some(true);
        assert!(config.validate().is_ok());

        let config = LdapAuthConfig::new().with_url("ldaps://ldap.example.com");
        assert!(config.validate().is_ok());
    }

    #[cfg(feature = "insecure-ldap-tls-acknowledged")]
    #[test]
    fn ldap_auth_insecure_tls_rejects_bind_credentials() {
        let mut config = LdapAuthConfig::new().with_bind(
            "cn=openbao,dc=example,dc=com",
            test_secret(&["bind", "-pass"]),
        );
        config.insecure_tls = Some(true);

        assert!(config.validate().is_err());
    }

    #[test]
    fn ldap_auth_config_debug_redacts_secret_fields() {
        let mut config = LdapAuthConfig::new().with_bind(
            "cn=openbao,dc=example,dc=com",
            test_secret(&["bind", "-pass"]),
        );
        config.certificate =
            Some("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----".to_owned());
        config.client_tls_cert =
            Some("-----BEGIN CERTIFICATE-----\nclient\n-----END CERTIFICATE-----".to_owned());
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("<redacted-pem>"));
        assert!(!debug.contains("bind-pass"));
        assert!(!debug.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn ldap_auth_config_validates_tls_duration_and_cidr_inputs() {
        let mut config = LdapAuthConfig::new()
            .with_token_bound_cidr("10.0.0.0/8")
            .unwrap_or_else(|error| panic!("{error}"));
        config.tls_min_version = Some("tls12".to_owned());
        config.connection_timeout = Some("30s".to_owned());
        assert!(config.validate().is_ok());

        config.tls_min_version = Some("tls10".to_owned());
        assert!(config.validate().is_err());

        config.tls_min_version = Some("ssl3".to_owned());
        assert!(config.validate().is_err());
    }

    #[test]
    fn ldap_auth_mapping_request_joins_fields() {
        let request = LdapAuthMappingRequest::new("dev")
            .with_policy("prod")
            .with_group("admins");
        assert_eq!(request.policies.join(","), "dev,prod");
        assert_eq!(request.groups.join(","), "admins");
    }

    #[test]
    fn ldap_auth_config_accepts_integer_duration_responses() {
        let config: LdapAuthConfig = serde_json::from_str(
            r#"{"connection_timeout":30,"request_timeout":"90s","token_ttl":0}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(config.connection_timeout.as_deref(), Some("30"));
        assert_eq!(config.request_timeout.as_deref(), Some("90s"));
        assert_eq!(config.token_ttl.as_deref(), Some("0"));
    }
}
