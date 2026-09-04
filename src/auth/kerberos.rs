//! Kerberos authentication support.

use core::fmt;
use std::collections::BTreeMap;

use reqwest::{
    Method, StatusCode,
    header::{AUTHORIZATION, HeaderValue},
};
use sanitization::SecureSanitize;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, de::Visitor};

use crate::{
    Authenticated, Client, Error, Result, Unauthenticated,
    path::validate_mount_path,
    response::{
        Empty, ListEntries, ListPageOptions, ResponseEnvelope,
        deserialize_bounded_string_map_or_default, deserialize_bounded_string_vec,
    },
    validation::{
        validate_duration_string, validate_ldap_urls_use_encrypted_transport,
        validate_optional_ldap_tls_version,
    },
};

/// Handle for Kerberos auth login at a configured mount.
#[derive(Debug)]
pub struct KerberosAuth<'a> {
    client: &'a Client<Unauthenticated>,
    mount: String,
}

/// Handle for Kerberos auth administration at a configured mount.
#[derive(Debug)]
pub struct KerberosAuthAdmin<'a> {
    client: &'a Client<Authenticated>,
    mount: String,
}

/// Kerberos service-account configuration.
#[derive(Clone, Default, Deserialize)]
pub struct KerberosConfig {
    /// Base64-encoded keytab. OpenBao does not return this field on reads.
    #[serde(default)]
    pub keytab: Option<SecretString>,
    /// Service account associated with the keytab entry.
    #[serde(default)]
    pub service_account: String,
    /// Removes instance names from service principal names while parsing the keytab.
    #[serde(default)]
    pub remove_instance_name: Option<bool>,
    /// Adds LDAP groups found for the user as group aliases.
    #[serde(default)]
    pub add_group_aliases: Option<bool>,
}

/// Kerberos configuration readback including OpenBao 2.6 fields.
#[derive(Clone, Default, Deserialize)]
pub struct KerberosConfigDetails {
    /// Configuration fields available across supported OpenBao releases.
    #[serde(flatten)]
    pub config: KerberosConfig,
    /// Whether OpenBao decodes PAC authorization data.
    #[serde(default)]
    pub decode_pac: Option<bool>,
}

impl fmt::Debug for KerberosConfigDetails {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KerberosConfigDetails")
            .field("config", &self.config)
            .field("decode_pac", &self.decode_pac)
            .finish()
    }
}

#[derive(Serialize)]
struct KerberosConfigPayload<'a> {
    keytab: &'a str,
    service_account: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    remove_instance_name: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    add_group_aliases: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decode_pac: Option<bool>,
}

impl KerberosConfig {
    /// Creates a Kerberos service-account config with the required fields.
    pub fn new(service_account: impl Into<String>, keytab: SecretString) -> Self {
        Self {
            keytab: Some(keytab),
            service_account: service_account.into(),
            ..Self::default()
        }
    }

    /// Sets whether OpenBao removes instance names from service principals.
    #[must_use]
    pub fn remove_instance_name(mut self, enabled: bool) -> Self {
        self.remove_instance_name = Some(enabled);
        self
    }

    /// Sets whether OpenBao adds discovered LDAP groups as aliases.
    #[must_use]
    pub fn add_group_aliases(mut self, enabled: bool) -> Self {
        self.add_group_aliases = Some(enabled);
        self
    }

    fn validate(&self) -> Result<()> {
        if self.service_account.trim().is_empty() {
            return Err(Error::InvalidParameter(
                "Kerberos service_account must not be empty".into(),
            ));
        }
        let Some(keytab) = &self.keytab else {
            return Err(Error::InvalidParameter(
                "Kerberos keytab must be provided when writing config".into(),
            ));
        };
        if keytab.expose_secret().trim().is_empty() {
            return Err(Error::InvalidParameter(
                "Kerberos keytab must not be empty".into(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for KerberosConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KerberosConfig")
            .field("keytab", &self.keytab.as_ref().map(|_| "<redacted>"))
            .field("service_account", &self.service_account)
            .field("remove_instance_name", &self.remove_instance_name)
            .field("add_group_aliases", &self.add_group_aliases)
            .finish()
    }
}

/// LDAP configuration used by the Kerberos auth method.
#[derive(Clone, Default, Deserialize)]
pub struct KerberosLdapConfig {
    /// LDAP server URL or comma-separated URL list.
    ///
    /// Use `ldaps://`, or set `starttls=true`. Bind credentials may never be
    /// sent over plaintext or unverified LDAP transport.
    #[serde(default)]
    pub url: Option<String>,
    /// Whether local group policy mapping names are case-sensitive.
    #[serde(default)]
    pub case_sensitive_names: Option<bool>,
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
    /// LDAP group search filter template.
    #[serde(default)]
    pub groupfilter: Option<String>,
    /// Base DN for group search.
    #[serde(default)]
    pub groupdn: Option<String>,
    /// LDAP group attribute to enumerate.
    #[serde(default)]
    pub groupattr: Option<String>,
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
struct KerberosLdapConfigPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    case_sensitive_names: Option<bool>,
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
    groupfilter: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groupdn: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groupattr: Option<&'a str>,
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

impl KerberosLdapConfig {
    /// Creates an empty Kerberos LDAP config.
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
        crate::validation::validate_cidr(&cidr, "Kerberos LDAP token_bound_cidrs")?;
        self.token_bound_cidrs.push(cidr);
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        #[cfg(not(feature = "insecure-ldap-tls-acknowledged"))]
        if self.insecure_tls == Some(true) {
            return Err(Error::InvalidParameter(
                "Kerberos LDAP insecure_tls=true requires the insecure-ldap-tls-acknowledged Cargo feature because it disables LDAP TLS certificate verification".into(),
            ));
        }
        if self.insecure_tls == Some(true) && self.bindpass.is_some() {
            return Err(Error::InvalidParameter(
                "Kerberos LDAP insecure_tls=true must not be combined with bindpass because credentials would cross an unverified TLS connection".into(),
            ));
        }
        if cfg!(not(feature = "insecure-ldap-tls-acknowledged")) || self.bindpass.is_some() {
            validate_ldap_urls_use_encrypted_transport(&self.url, self.starttls, "Kerberos LDAP")?;
        }
        crate::validation::validate_cidr_list(
            &self.token_bound_cidrs,
            "Kerberos LDAP token_bound_cidrs",
        )?;
        if self.token_strictly_bind_ip == Some(true) && !self.token_bound_cidrs.is_empty() {
            return Err(Error::InvalidParameter(
                "Kerberos LDAP token_strictly_bind_ip conflicts with token_bound_cidrs".into(),
            ));
        }
        validate_optional_duration(&self.token_ttl, "Kerberos LDAP token_ttl")?;
        validate_optional_duration(&self.token_max_ttl, "Kerberos LDAP token_max_ttl")?;
        validate_optional_duration(
            &self.token_explicit_max_ttl,
            "Kerberos LDAP token_explicit_max_ttl",
        )?;
        validate_optional_duration(&self.token_period, "Kerberos LDAP token_period")?;
        validate_optional_ldap_tls_version(&self.tls_min_version, "Kerberos LDAP tls_min_version")?;
        validate_optional_ldap_tls_version(&self.tls_max_version, "Kerberos LDAP tls_max_version")?;
        Ok(())
    }
}

impl fmt::Debug for KerberosLdapConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KerberosLdapConfig")
            .field("url", &self.url)
            .field("case_sensitive_names", &self.case_sensitive_names)
            .field("starttls", &self.starttls)
            .field("tls_min_version", &self.tls_min_version)
            .field("tls_max_version", &self.tls_max_version)
            .field("insecure_tls", &self.insecure_tls)
            .field("certificate", &self.certificate)
            .field("binddn", &self.binddn)
            .field("bindpass", &self.bindpass.as_ref().map(|_| "<redacted>"))
            .field("userdn", &self.userdn)
            .field("userattr", &self.userattr)
            .field("discoverdn", &self.discoverdn)
            .field("deny_null_bind", &self.deny_null_bind)
            .field("upndomain", &self.upndomain)
            .field("groupfilter", &self.groupfilter)
            .field("groupdn", &self.groupdn)
            .field("groupattr", &self.groupattr)
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

/// Kerberos LDAP group policy mapping request.
#[derive(Clone, Debug, Default)]
pub struct KerberosGroupRequest {
    /// Policies mapped to this LDAP group.
    pub policies: Vec<String>,
}

impl KerberosGroupRequest {
    /// Creates a group request with one policy.
    pub fn new(policy: impl Into<String>) -> Self {
        Self {
            policies: vec![policy.into()],
        }
    }

    /// Adds a policy.
    #[must_use]
    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.policies.push(policy.into());
        self
    }
}

#[derive(Serialize)]
struct KerberosGroupPayload {
    policies: String,
}

/// Kerberos LDAP group policy mapping returned by OpenBao.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct KerberosGroupInfo {
    /// Policies mapped to this LDAP group.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub policies: Vec<String>,
}

/// Kerberos LDAP group list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct KerberosGroupList {
    /// Group names returned by OpenBao.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for KerberosGroupList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

/// Metadata returned after a successful Kerberos login.
#[derive(Debug, Deserialize)]
pub struct KerberosLoginMetadata {
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

#[derive(Deserialize)]
struct KerberosLoginResponse {
    auth: Option<KerberosLoginAuth>,
}

#[derive(Deserialize)]
struct KerberosLoginAuth {
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
    /// Uses the Kerberos auth method mounted at `auth/kerberos`.
    pub fn kerberos_auth(&self) -> Result<KerberosAuth<'_>> {
        self.kerberos_auth_at("kerberos")
    }

    /// Uses the Kerberos auth method mounted at `auth/{mount}`.
    pub fn kerberos_auth_at(&self, mount: impl Into<String>) -> Result<KerberosAuth<'_>> {
        Ok(KerberosAuth {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }

    /// Logs in with Kerberos auth at `auth/kerberos`.
    pub async fn login_kerberos(
        self,
        spnego_token: SecretString,
    ) -> Result<(Client<Authenticated>, KerberosLoginMetadata)> {
        let response = self.kerberos_auth()?.login_response(&spnego_token).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((self.try_with_token(token)?, metadata))
    }
}

impl Client<Authenticated> {
    /// Administers the Kerberos auth method mounted at `auth/kerberos`.
    pub fn kerberos_auth_admin(&self) -> Result<KerberosAuthAdmin<'_>> {
        self.kerberos_auth_admin_at("kerberos")
    }

    /// Administers the Kerberos auth method mounted at `auth/{mount}`.
    pub fn kerberos_auth_admin_at(
        &self,
        mount: impl Into<String>,
    ) -> Result<KerberosAuthAdmin<'_>> {
        Ok(KerberosAuthAdmin {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }
}

impl KerberosAuth<'_> {
    /// Logs in with a base64-encoded SPNEGO token.
    pub async fn login(
        self,
        spnego_token: SecretString,
    ) -> Result<(Client<Authenticated>, KerberosLoginMetadata)> {
        let response = self.login_response(&spnego_token).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((
            self.client.clone_without_state().try_with_token(token)?,
            metadata,
        ))
    }

    async fn login_response(&self, spnego_token: &SecretString) -> Result<KerberosLoginAuth> {
        let header = negotiate_header(spnego_token)?;
        let response: KerberosLoginResponse = self
            .client
            .request_auth_json_headers_accepting(
                "kerberos",
                &self.mount,
                Method::POST,
                &format!("auth/{}/login", self.mount),
                &[(AUTHORIZATION, header)],
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        response.auth.ok_or(Error::MissingField("auth"))
    }
}

impl KerberosAuthAdmin<'_> {
    /// Configures the Kerberos service account and keytab.
    pub async fn configure(&self, config: &KerberosConfig) -> Result<Empty> {
        config.validate()?;
        let keytab = config
            .keytab
            .as_ref()
            .ok_or(Error::MissingField("keytab"))?
            .expose_secret();
        let payload = KerberosConfigPayload {
            keytab,
            service_account: &config.service_account,
            remove_instance_name: config.remove_instance_name,
            add_group_aliases: config.add_group_aliases,
            decode_pac: None,
        };
        self.client
            .request_auth_json_internal(
                "kerberos",
                &self.mount,
                Method::POST,
                &format!("auth/{}/config", self.mount),
                Some(&payload),
            )
            .await
    }

    /// Configures Kerberos PAC decoding on OpenBao 2.6 or newer.
    pub async fn configure_with_decode_pac(
        &self,
        config: &KerberosConfig,
        decode_pac: bool,
    ) -> Result<Empty> {
        config.validate()?;
        self.client
            .validate_versioned_request_fields(&[(
                &crate::request_compatibility::fields::KERBEROS_CONFIG_DECODE_PAC,
                true,
            )])
            .await?;
        let keytab = config
            .keytab
            .as_ref()
            .ok_or(Error::MissingField("Kerberos keytab"))?;
        let payload = KerberosConfigPayload {
            keytab: keytab.expose_secret(),
            service_account: &config.service_account,
            remove_instance_name: config.remove_instance_name,
            add_group_aliases: config.add_group_aliases,
            decode_pac: Some(decode_pac),
        };
        self.client
            .request_auth_json_internal(
                "kerberos",
                &self.mount,
                Method::POST,
                &format!("auth/{}/config", self.mount),
                Some(&payload),
            )
            .await
    }

    /// Reads the Kerberos service-account configuration.
    pub async fn read_config(&self) -> Result<KerberosConfig> {
        let envelope: ResponseEnvelope<KerberosConfig> = self
            .client
            .request_auth_json_internal(
                "kerberos",
                &self.mount,
                Method::GET,
                &format!("auth/{}/config", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Reads Kerberos configuration with OpenBao 2.6 PAC-decoding state.
    pub async fn read_config_details(&self) -> Result<KerberosConfigDetails> {
        let envelope: ResponseEnvelope<KerberosConfigDetails> = self
            .client
            .request_auth_json_internal(
                "kerberos",
                &self.mount,
                Method::GET,
                &format!("auth/{}/config", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Configures the LDAP settings used by the Kerberos auth method.
    pub async fn configure_ldap(&self, config: &KerberosLdapConfig) -> Result<Empty> {
        config.validate()?;
        let payload = KerberosLdapConfigPayload {
            url: config.url.as_deref(),
            case_sensitive_names: config.case_sensitive_names,
            starttls: config.starttls,
            tls_min_version: config.tls_min_version.as_deref(),
            tls_max_version: config.tls_max_version.as_deref(),
            insecure_tls: config.insecure_tls,
            certificate: config.certificate.as_deref(),
            binddn: config.binddn.as_deref(),
            bindpass: config.bindpass.as_ref().map(SecretString::expose_secret),
            userdn: config.userdn.as_deref(),
            userattr: config.userattr.as_deref(),
            discoverdn: config.discoverdn,
            deny_null_bind: config.deny_null_bind,
            upndomain: config.upndomain.as_deref(),
            groupfilter: config.groupfilter.as_deref(),
            groupdn: config.groupdn.as_deref(),
            groupattr: config.groupattr.as_deref(),
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
                "kerberos",
                &self.mount,
                Method::POST,
                &format!("auth/{}/config/ldap", self.mount),
                Some(&payload),
            )
            .await
    }

    /// Reads the LDAP settings used by the Kerberos auth method.
    pub async fn read_ldap_config(&self) -> Result<KerberosLdapConfig> {
        let envelope: ResponseEnvelope<KerberosLdapConfig> = self
            .client
            .request_auth_json_internal(
                "kerberos",
                &self.mount,
                Method::GET,
                &format!("auth/{}/config/ldap", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Creates or updates a Kerberos LDAP group policy mapping.
    pub async fn write_group(&self, name: &str, group: &KerberosGroupRequest) -> Result<Empty> {
        let name = validate_kerberos_group_name(name)?;
        let payload = KerberosGroupPayload {
            policies: group.policies.join(","),
        };
        self.client
            .request_auth_json_internal(
                "kerberos",
                &self.mount,
                Method::POST,
                &format!("auth/{}/groups/{name}", self.mount),
                Some(&payload),
            )
            .await
    }

    /// Reads a Kerberos LDAP group policy mapping.
    pub async fn read_group(&self, name: &str) -> Result<KerberosGroupInfo> {
        let name = validate_kerberos_group_name(name)?;
        let envelope: ResponseEnvelope<KerberosGroupInfo> = self
            .client
            .request_auth_json_internal(
                "kerberos",
                &self.mount,
                Method::GET,
                &format!("auth/{}/groups/{name}", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a Kerberos LDAP group policy mapping.
    pub async fn delete_group(&self, name: &str) -> Result<Empty> {
        let name = validate_kerberos_group_name(name)?;
        self.client
            .request_auth_json_accepting(
                "kerberos",
                &self.mount,
                Method::DELETE,
                &format!("auth/{}/groups/{name}", self.mount),
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Lists Kerberos LDAP group names.
    pub async fn list_groups(&self) -> Result<KerberosGroupList> {
        self.list_groups_page(None, None).await
    }

    /// Lists Kerberos LDAP group names with OpenBao pagination query parameters.
    pub async fn list_groups_page(
        &self,
        after: Option<&str>,
        limit: Option<u64>,
    ) -> Result<KerberosGroupList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        if let Some(after) = after {
            validate_kerberos_group_name(after)?;
        }
        let query = ListPageOptions::from_after_limit(after, limit)?.query_pairs();
        let envelope: ResponseEnvelope<KerberosGroupList> = self
            .client
            .request_auth_json_query_accepting(
                "kerberos",
                &self.mount,
                method,
                &format!("auth/{}/groups", self.mount),
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }
}

fn split_login_auth(auth: KerberosLoginAuth) -> (SecretString, KerberosLoginMetadata) {
    let KerberosLoginAuth {
        client_token,
        accessor,
        policies,
        lease_duration,
        renewable,
        metadata,
    } = auth;
    let metadata = KerberosLoginMetadata {
        accessor,
        policies,
        lease_duration,
        renewable,
        metadata,
    };
    (client_token, metadata)
}

fn negotiate_header(spnego_token: &SecretString) -> Result<HeaderValue> {
    if spnego_token.expose_secret().trim().is_empty() {
        return Err(Error::InvalidHeader(
            "Kerberos SPNEGO token must not be empty".into(),
        ));
    }
    let mut value = String::with_capacity("Negotiate ".len() + spnego_token.expose_secret().len());
    value.push_str("Negotiate ");
    value.push_str(spnego_token.expose_secret());
    let header =
        HeaderValue::from_str(&value).map_err(|error| Error::InvalidHeader(error.to_string()));
    value.secure_sanitize();
    let mut header = header?;
    header.set_sensitive(true);
    Ok(header)
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

fn validate_kerberos_group_name(name: &str) -> Result<&str> {
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return Err(Error::InvalidPath(
            "Kerberos LDAP group name must not be empty".into(),
        ));
    }
    if bytes.iter().any(u8::is_ascii_control) {
        return Err(Error::InvalidPath(
            "Kerberos LDAP group name must not contain control characters".into(),
        ));
    }
    if name.contains(['\\', '/', '?', '#']) {
        return Err(Error::InvalidPath(
            "Kerberos LDAP group name must not contain slash, backslash, query, or fragment characters"
                .into(),
        ));
    }
    if name == "." || name == ".." || name.ends_with('.') {
        return Err(Error::InvalidPath(
            "Kerberos LDAP group name must not be relative or end in a period".into(),
        ));
    }
    Ok(name)
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
        KerberosConfig, KerberosGroupList, KerberosGroupRequest, KerberosLdapConfig,
        KerberosLoginResponse, negotiate_header, validate_kerberos_group_name,
    };

    fn test_secret(parts: &[&str]) -> SecretString {
        SecretString::from(parts.concat())
    }

    #[test]
    fn kerberos_login_deserializes_secret_token_fields() {
        let response: KerberosLoginResponse = serde_json::from_str(
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
    fn kerberos_group_list_is_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("group-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<KerberosGroupList>(value) {
            Ok(_) => panic!("oversized Kerberos group list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn kerberos_group_name_validation_rejects_ambiguous_values() {
        assert!(validate_kerberos_group_name("admins").is_ok());
        assert!(validate_kerberos_group_name("Team A").is_ok());
        assert!(validate_kerberos_group_name("").is_err());
        assert!(validate_kerberos_group_name(".").is_err());
        assert!(validate_kerberos_group_name("..").is_err());
        assert!(validate_kerberos_group_name("admins.").is_err());
        assert!(validate_kerberos_group_name("team/admins").is_err());
        assert!(validate_kerberos_group_name("admins?x=1").is_err());
    }

    #[test]
    fn kerberos_config_debug_redacts_keytab() {
        let config = KerberosConfig::new(
            "openbao_svc",
            test_secret(&["base64", "-keytab", "-material"]),
        );
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("base64-keytab-material"));
    }

    #[test]
    fn kerberos_ldap_config_debug_redacts_bind_password() {
        let config = KerberosLdapConfig::new().with_bind(
            "cn=openbao,dc=example,dc=com",
            test_secret(&["bind", "-pass"]),
        );
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("bind-pass"));
    }

    #[test]
    fn kerberos_ldap_config_validates_tls_duration_and_cidr_inputs() {
        let mut config = KerberosLdapConfig::new()
            .with_url("ldaps://ldap.example.test")
            .with_token_bound_cidr("10.0.0.0/8")
            .unwrap_or_else(|error| panic!("{error}"));
        config.tls_min_version = Some("tls12".to_owned());
        config.token_ttl = Some("30s".to_owned());
        assert!(config.validate().is_ok());

        config.tls_min_version = Some("tls11".to_owned());
        assert!(config.validate().is_err());

        config.tls_min_version = Some("ssl3".to_owned());
        assert!(config.validate().is_err());
    }

    #[test]
    fn kerberos_ldap_bind_credentials_require_verified_encrypted_transport() {
        let bind_password = || test_secret(&["bind", "-password"]);
        let secure = KerberosLdapConfig::new()
            .with_url("ldaps://ldap.example.test")
            .with_bind("cn=openbao,dc=example,dc=test", bind_password());
        assert!(secure.validate().is_ok());

        let starttls = KerberosLdapConfig::new()
            .with_url("ldap://ldap.example.test")
            .with_bind("cn=openbao,dc=example,dc=test", bind_password());
        let mut starttls = starttls;
        starttls.starttls = Some(true);
        assert!(starttls.validate().is_ok());

        let plaintext = KerberosLdapConfig::new()
            .with_url("ldap://ldap.example.test")
            .with_bind("cn=openbao,dc=example,dc=test", bind_password());
        assert!(plaintext.validate().is_err());

        let mut unverified = KerberosLdapConfig::new()
            .with_url("ldaps://ldap.example.test")
            .with_bind("cn=openbao,dc=example,dc=test", bind_password());
        unverified.insecure_tls = Some(true);
        assert!(unverified.validate().is_err());
    }

    #[test]
    fn kerberos_group_request_joins_policies() {
        let request = KerberosGroupRequest::new("dev").with_policy("prod");
        assert_eq!(request.policies.join(","), "dev,prod");
    }

    #[test]
    fn kerberos_config_read_accepts_missing_keytab() {
        let details: super::KerberosConfigDetails = serde_json::from_str(
            r#"{"service_account":"openbao_svc","remove_instance_name":false,"add_group_aliases":true,"decode_pac":true}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(details.config.keytab.is_none());
        assert_eq!(details.config.service_account, "openbao_svc");
        assert_eq!(details.decode_pac, Some(true));
    }

    #[test]
    fn kerberos_ldap_config_accepts_integer_duration_responses() {
        let config: KerberosLdapConfig =
            serde_json::from_str(r#"{"token_ttl":30,"token_max_ttl":"90s"}"#)
                .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(config.token_ttl.as_deref(), Some("30"));
        assert_eq!(config.token_max_ttl.as_deref(), Some("90s"));
    }

    #[test]
    fn negotiate_header_marks_spnego_token_sensitive() {
        let header = negotiate_header(&test_secret(&["spnego", "-token"]))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(header.is_sensitive());
        assert_eq!(header.to_str().unwrap_or(""), "Negotiate spnego-token");
    }
}
