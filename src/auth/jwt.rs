//! JWT/OIDC authentication support.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use reqwest::{
    Method, StatusCode,
    header::{CONTENT_TYPE, HeaderValue},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{IgnoredAny, MapAccess, SeqAccess, Visitor},
    ser::SerializeMap,
};

use crate::{
    Authenticated, Client, Error, Result, Unauthenticated,
    path::validate_mount_path,
    response::{
        Empty, ListEntries, ListPageOptions, ResponseEnvelope,
        deserialize_bounded_string_map_or_default, deserialize_bounded_string_vec,
    },
};

const MAX_CEL_VARIABLES: usize = 128;
const MAX_CEL_AUDIENCES: usize = crate::MAX_RESPONSE_STRINGS;
const MAX_CEL_IDENTIFIER_BYTES: usize = 256;
const MAX_CEL_EXPRESSION_BYTES: usize = 256 * 1024;
const MAX_CEL_PROGRAM_BYTES: usize = 1024 * 1024;
const MAX_CEL_MESSAGE_BYTES: usize = 64 * 1024;

/// Handle for JWT auth login at a configured mount.
#[derive(Debug)]
pub struct JwtAuth<'a> {
    client: &'a Client<Unauthenticated>,
    mount: String,
}

/// Handle for JWT/OIDC auth administration at a configured mount.
#[derive(Debug)]
pub struct JwtAuthAdmin<'a> {
    client: &'a Client<Authenticated>,
    mount: String,
}

/// JWT/OIDC auth method configuration.
#[derive(Clone, Default, Deserialize)]
pub struct JwtConfig {
    /// OIDC discovery base URL.
    #[serde(default)]
    pub oidc_discovery_url: Option<String>,
    /// PEM CA bundle for the OIDC discovery URL.
    #[serde(default)]
    pub oidc_discovery_ca_pem: Option<String>,
    /// JWKS endpoint URL.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// PEM CA bundle for the JWKS URL.
    #[serde(default)]
    pub jwks_ca_pem: Option<String>,
    /// Static JWT verification public keys.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub jwt_validation_pubkeys: Vec<String>,
    /// Required JWT issuer.
    #[serde(default)]
    pub bound_issuer: Option<String>,
    /// Supported JWT signature algorithms.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub jwt_supported_algs: Vec<String>,
    /// Default role used when the login request omits `role`.
    #[serde(default)]
    pub default_role: Option<String>,
    /// OIDC client identifier.
    #[serde(default)]
    pub oidc_client_id: Option<String>,
    /// OIDC client secret. Treated as secret material and redacted from debug output.
    #[serde(default)]
    pub oidc_client_secret: Option<SecretString>,
    /// OIDC response mode.
    #[serde(default)]
    pub oidc_response_mode: Option<String>,
    /// OIDC response types.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub oidc_response_types: Vec<String>,
    /// Provider-specific string configuration.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    pub provider_config: BTreeMap<String, String>,
    /// TLS server names accepted instead of the URL hostname for OIDC/JWKS (OpenBao 2.4+).
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub override_allowed_server_names: Vec<String>,
    /// Save configuration even when initial JWKS validation fails (OpenBao 2.3.1+).
    #[serde(default)]
    pub skip_jwks_validation: Option<bool>,
    /// Whether namespaces are encoded in OIDC state.
    #[serde(default)]
    pub namespace_in_state: Option<bool>,
}

impl core::fmt::Debug for JwtConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("JwtConfig")
            .field("oidc_discovery_url", &self.oidc_discovery_url)
            .field("oidc_discovery_ca_pem", &self.oidc_discovery_ca_pem)
            .field("jwks_url", &self.jwks_url)
            .field("jwks_ca_pem", &self.jwks_ca_pem)
            .field("jwt_validation_pubkeys", &self.jwt_validation_pubkeys)
            .field("bound_issuer", &self.bound_issuer)
            .field("jwt_supported_algs", &self.jwt_supported_algs)
            .field("default_role", &self.default_role)
            .field("oidc_client_id", &self.oidc_client_id)
            .field(
                "oidc_client_secret",
                &self.oidc_client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("oidc_response_mode", &self.oidc_response_mode)
            .field("oidc_response_types", &self.oidc_response_types)
            .field("provider_config", &self.provider_config)
            .field(
                "override_allowed_server_names",
                &self.override_allowed_server_names,
            )
            .field("skip_jwks_validation", &self.skip_jwks_validation)
            .field("namespace_in_state", &self.namespace_in_state)
            .finish()
    }
}

impl JwtConfig {
    /// Creates a JWT configuration that discovers signing keys from the local
    /// Kubernetes API server service-account environment.
    ///
    /// OpenBao derives the API address from `KUBERNETES_SERVICE_HOST` and
    /// `KUBERNETES_SERVICE_PORT`, then reads the pod service-account token and
    /// CA from their standard mounted paths. OIDC discovery, JWKS, and static
    /// validation keys must not be combined with this provider.
    pub fn kubernetes_provider() -> Self {
        Self {
            provider_config: BTreeMap::from([("provider".into(), "kubernetes".into())]),
            ..Self::default()
        }
    }

    fn uses_kubernetes_provider(&self) -> bool {
        self.provider_config.get("provider").map(String::as_str) == Some("kubernetes")
    }

    fn validate(&self) -> Result<()> {
        if !self.uses_kubernetes_provider() {
            return Ok(());
        }
        if self.provider_config.len() != 1 {
            return Err(Error::InvalidParameter(
                "JWT Kubernetes provider_config accepts only provider=kubernetes".into(),
            ));
        }
        if self.oidc_discovery_url.is_some()
            || self.oidc_discovery_ca_pem.is_some()
            || self.jwks_url.is_some()
            || self.jwks_ca_pem.is_some()
            || !self.jwt_validation_pubkeys.is_empty()
        {
            return Err(Error::InvalidParameter(
                "JWT Kubernetes provider must be the sole signing-key source".into(),
            ));
        }
        Ok(())
    }
}

/// JWT validation leeway.
///
/// OpenBao accepts `-1` to disable a JWT time validation check. That behavior
/// is represented only by the deliberately named
/// [`Self::DisableTimeValidation`] variant so callers do not pass raw strings
/// that silently weaken role validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JwtLeeway {
    /// Leeway in seconds.
    Seconds(u64),
    /// Duration string accepted by OpenBao, such as `60s` or `5m`.
    Duration(String),
    /// Disable the associated JWT time validation check.
    DisableTimeValidation,
}

impl JwtLeeway {
    /// Creates a second-based JWT leeway.
    pub fn seconds(seconds: u64) -> Self {
        Self::Seconds(seconds)
    }

    /// Creates a duration-string JWT leeway.
    pub fn duration(duration: impl Into<String>) -> Self {
        Self::Duration(duration.into())
    }
}

impl Serialize for JwtLeeway {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Seconds(seconds) => serializer.serialize_u64(*seconds),
            Self::Duration(duration) => serializer.serialize_str(duration),
            Self::DisableTimeValidation => serializer.serialize_str("-1"),
        }
    }
}

impl<'de> Deserialize<'de> for JwtLeeway {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(JwtLeewayVisitor)
    }
}

struct JwtLeewayVisitor;

impl<'de> Visitor<'de> for JwtLeewayVisitor {
    type Value = JwtLeeway;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JWT leeway duration, integer seconds, or explicit -1 disable value")
    }

    fn visit_u64<E>(self, value: u64) -> core::result::Result<Self::Value, E> {
        Ok(JwtLeeway::Seconds(value))
    }

    fn visit_i64<E>(self, value: i64) -> core::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value == -1 {
            return Ok(JwtLeeway::DisableTimeValidation);
        }
        let seconds = u64::try_from(value)
            .map_err(|_| E::custom("JWT leeway must be non-negative or exactly -1"))?;
        Ok(JwtLeeway::Seconds(seconds))
    }

    fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E> {
        if value == "-1" {
            return Ok(JwtLeeway::DisableTimeValidation);
        }
        Ok(JwtLeeway::Duration(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E> {
        if value == "-1" {
            return Ok(JwtLeeway::DisableTimeValidation);
        }
        Ok(JwtLeeway::Duration(value))
    }
}

/// JWT/OIDC role configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct JwtRole {
    /// Role type, usually `jwt` or `oidc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_type: Option<String>,
    /// Audiences accepted from the `aud` claim.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bound_audiences: Vec<String>,
    /// Subject accepted from the `sub` claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_subject: Option<String>,
    /// Bound claims matching mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_claims_type: Option<String>,
    /// Claims that must match for login.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub bound_claims: BTreeMap<String, String>,
    /// Claim used to identify the entity alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_claim: Option<String>,
    /// Whether `user_claim` is a JSON pointer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_claim_json_pointer: Option<bool>,
    /// Claim containing groups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups_claim: Option<String>,
    /// Claim mappings copied into alias metadata.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_string_map_or_default"
    )]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub claim_mappings: BTreeMap<String, String>,
    /// Clock skew leeway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_skew_leeway: Option<JwtLeeway>,
    /// Expiration leeway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_leeway: Option<JwtLeeway>,
    /// Not-before leeway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before_leeway: Option<JwtLeeway>,
    /// OIDC callback URLs permitted for this role.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_redirect_uris: Vec<String>,
    /// OIDC scopes requested by this role.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub oidc_scopes: Vec<String>,
    /// OIDC callback mode: `client`, `direct`, or `device` (OpenBao 2.1+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_mode: Option<String>,
    /// Poll interval in seconds for direct and device callback modes (OpenBao 2.1+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll_interval: Option<u64>,
    /// Disables OpenBao's direct-flow confirmation page (OpenBao 2.5.2+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_disable_confirmation: Option<bool>,
    /// Emits received OIDC tokens and claims to debug logs.
    ///
    /// Enabling this can disclose credentials and claims. Keep it disabled in
    /// production and in any environment with centralized debug logging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verbose_oidc_logging: Option<bool>,
    /// Maximum age accepted since the user's active authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<String>,
    /// Allows token policy templates to reference JWT/OIDC claims (OpenBao 2.1+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_policies_template_claims: Option<bool>,
    /// Policies attached to generated tokens.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_policies: Vec<String>,
    /// Deprecated policy field retained for older OpenBao 2.x compatibility.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
    /// Token TTL such as `30m`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_ttl: Option<String>,
    /// Token max TTL such as `2h`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_max_ttl: Option<String>,
    /// Periodic token period.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_period: Option<String>,
    /// Token explicit max TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_explicit_max_ttl: Option<String>,
    /// Generated token type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// CIDR restrictions for generated tokens.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub token_bound_cidrs: Vec<String>,
    /// Number of allowed token uses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_num_uses: Option<u64>,
    /// Whether to omit the default policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_no_default_policy: Option<bool>,
}

impl JwtRole {
    /// Creates a JWT role request with the required user claim.
    pub fn new(user_claim: impl Into<String>) -> Self {
        Self {
            user_claim: Some(user_claim.into()),
            ..Self::default()
        }
    }

    fn validate(&self) -> Result<()> {
        if let Some(max_age) = &self.max_age {
            crate::validation::validate_duration_parameter(max_age, "jwt auth max_age")?;
        }
        if let Some(callback_mode) = &self.callback_mode
            && !matches!(callback_mode.as_str(), "client" | "direct" | "device")
        {
            return Err(Error::InvalidParameter(
                "jwt auth callback_mode must be client, direct, or device".into(),
            ));
        }
        crate::validation::validate_cidr_list(&self.token_bound_cidrs, "jwt auth token_bound_cidrs")
    }
}

/// JWT/OIDC role list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct JwtRoleList {
    /// Role names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

/// One ordered variable in an OpenBao JWT CEL program.
#[derive(Clone, Deserialize, Serialize)]
pub struct JwtCelVariable {
    /// CEL identifier assigned by this variable.
    pub name: String,
    /// CEL expression evaluated to produce the variable value.
    #[serde(
        deserialize_with = "deserialize_cel_secret",
        serialize_with = "serialize_cel_secret"
    )]
    expression: SecretString,
}

impl JwtCelVariable {
    /// Returns the secret-adjacent CEL expression.
    #[must_use]
    pub const fn expression(&self) -> &SecretString {
        &self.expression
    }
}

impl fmt::Debug for JwtCelVariable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwtCelVariable")
            .field("name", &self.name)
            .field("expression", &"<redacted>")
            .finish()
    }
}

/// Bounded CEL program used by a JWT CEL role.
///
/// The SDK validates structural limits only. OpenBao remains responsible for
/// parsing, type-checking, and executing CEL. Restrict CEL role administration
/// to trusted operators because a syntactically valid program can still be
/// computationally expensive.
#[derive(Clone, Serialize)]
pub struct JwtCelProgram {
    /// Ordered variables evaluated before the final expression.
    #[serde(default, deserialize_with = "deserialize_bounded_cel_variables")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub variables: Vec<JwtCelVariable>,
    /// Final CEL expression. A successful auth program returns OpenBao auth data.
    #[serde(serialize_with = "serialize_cel_secret")]
    expression: SecretString,
}

impl<'de> Deserialize<'de> for JwtCelProgram {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ProgramData {
            #[serde(default, deserialize_with = "deserialize_bounded_cel_variables")]
            variables: Vec<JwtCelVariable>,
            #[serde(deserialize_with = "deserialize_cel_secret")]
            expression: SecretString,
        }

        let data = ProgramData::deserialize(deserializer)?;
        let program = Self {
            variables: data.variables,
            expression: data.expression,
        };
        program.validate().map_err(serde::de::Error::custom)?;
        Ok(program)
    }
}

impl JwtCelProgram {
    /// Creates a CEL program with no intermediate variables.
    pub fn new(expression: impl Into<SecretString>) -> Result<Self> {
        let program = Self {
            variables: Vec::new(),
            expression: expression.into(),
        };
        program.validate()?;
        Ok(program)
    }

    /// Adds one ordered CEL variable.
    pub fn with_variable(
        mut self,
        name: impl Into<String>,
        expression: impl Into<SecretString>,
    ) -> Result<Self> {
        self.variables.push(JwtCelVariable {
            name: name.into(),
            expression: expression.into(),
        });
        self.validate()?;
        Ok(self)
    }

    /// Returns the secret-adjacent final CEL expression.
    #[must_use]
    pub const fn expression(&self) -> &SecretString {
        &self.expression
    }

    fn validate(&self) -> Result<()> {
        if self.variables.len() > MAX_CEL_VARIABLES {
            return Err(Error::InvalidParameter(
                "JWT CEL program exceeds variable limit".into(),
            ));
        }
        validate_cel_expression(self.expression.expose_secret())?;
        let mut total = self.expression.expose_secret().len();
        let mut names = BTreeSet::new();
        for variable in &self.variables {
            validate_cel_identifier(&variable.name)?;
            validate_cel_expression(variable.expression.expose_secret())?;
            if !names.insert(variable.name.as_str()) {
                return Err(Error::InvalidParameter(
                    "JWT CEL variable names must be unique".into(),
                ));
            }
            total = total
                .checked_add(variable.name.len())
                .and_then(|total| total.checked_add(variable.expression.expose_secret().len()))
                .ok_or_else(|| Error::InvalidParameter("JWT CEL program is too large".into()))?;
            if total > MAX_CEL_PROGRAM_BYTES {
                return Err(Error::InvalidParameter(
                    "JWT CEL program exceeds total size limit".into(),
                ));
            }
        }
        Ok(())
    }
}

impl fmt::Debug for JwtCelProgram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwtCelProgram")
            .field("variable_count", &self.variables.len())
            .field("expression", &"<redacted>")
            .finish()
    }
}

/// Explicit acknowledgement required before writing a JWT CEL role.
///
/// OpenBao validates a JWT signature but delegates authorization-claim
/// validation to the operator-provided CEL program. In particular,
/// `bound_audiences` filters an `aud` claim when present but does not reject a
/// JWT that omits `aud`. Constructing this value confirms that the CEL program
/// explicitly requires and constrains `aud`, `sub`, and every other claim used
/// to authorize the resulting OpenBao token.
///
/// This acknowledgement does not parse or prove the CEL program. Restrict CEL
/// role administration to trusted operators and review the program itself.
#[derive(Clone, Copy, Debug)]
pub struct JwtCelClaimValidationAcknowledgement {
    _private: (),
}

impl JwtCelClaimValidationAcknowledgement {
    /// Confirms that the CEL program constrains every authorization claim.
    #[must_use]
    pub const fn all_authorization_claims_are_constrained_in_cel() -> Self {
        Self { _private: () }
    }
}

/// Request for creating or replacing a JWT CEL role.
#[derive(Clone, Serialize)]
pub struct JwtCelRoleRequest {
    /// CEL program evaluated after JWT signature and claim-time validation.
    pub cel_program: JwtCelProgram,
    /// Static authentication failure message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Clock-skew validation leeway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_skew_leeway: Option<JwtLeeway>,
    /// Expiration validation leeway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_leeway: Option<JwtLeeway>,
    /// Not-before validation leeway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before_leeway: Option<JwtLeeway>,
    /// Audiences accepted when the JWT contains an `aud` claim.
    ///
    /// OpenBao 2.6 does not reject a JWT that omits `aud` when this list is
    /// populated. The CEL program must explicitly require and constrain the
    /// claim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bound_audiences: Vec<String>,
    #[serde(skip)]
    claim_validation_acknowledged: bool,
}

impl JwtCelRoleRequest {
    /// Creates a JWT CEL role request with its required program.
    pub fn new(cel_program: JwtCelProgram) -> Self {
        Self {
            cel_program,
            message: None,
            clock_skew_leeway: None,
            expiration_leeway: None,
            not_before_leeway: None,
            bound_audiences: Vec::new(),
            claim_validation_acknowledged: false,
        }
    }

    /// Acknowledges that the CEL program validates every authorization claim.
    ///
    /// OpenBao does not reject a missing `aud` claim merely because
    /// [`Self::bound_audiences`] is populated. This method is intentionally
    /// required before [`JwtAuthAdmin::write_cel_role`] will send the request.
    /// The SDK does not inspect CEL source because substring or regular-
    /// expression checks would be bypassable.
    #[must_use]
    pub fn acknowledge_claim_validation(mut self, _: JwtCelClaimValidationAcknowledgement) -> Self {
        self.claim_validation_acknowledged = true;
        self
    }

    fn validate(&self) -> Result<()> {
        if !self.claim_validation_acknowledged {
            return Err(Error::InvalidParameter(
                "OpenBao JWT CEL roles require explicit acknowledgement that the CEL program constrains aud, sub, and every authorization-relevant claim; bound_audiences does not reject a missing aud claim"
                    .into(),
            ));
        }
        self.cel_program.validate()?;
        validate_cel_audiences(&self.bound_audiences)?;
        if self
            .message
            .as_ref()
            .is_some_and(|message| message.len() > MAX_CEL_MESSAGE_BYTES)
        {
            return Err(Error::InvalidParameter(
                "JWT CEL role message exceeds size limit".into(),
            ));
        }
        for leeway in [
            &self.clock_skew_leeway,
            &self.expiration_leeway,
            &self.not_before_leeway,
        ] {
            validate_cel_leeway(leeway.as_ref())?;
        }
        Ok(())
    }
}

impl fmt::Debug for JwtCelRoleRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwtCelRoleRequest")
            .field("cel_program", &self.cel_program)
            .field("message", &self.message)
            .field("clock_skew_leeway", &self.clock_skew_leeway)
            .field("expiration_leeway", &self.expiration_leeway)
            .field("not_before_leeway", &self.not_before_leeway)
            .field("bound_audiences", &self.bound_audiences)
            .finish()
    }
}

/// Partial JWT CEL role update.
///
/// OpenBao 2.6.0 does not preserve audience and leeway constraints in its
/// PATCH handler. The SDK therefore reports this operation as security-blocked
/// for that exact profile; use [`JwtAuthAdmin::write_cel_role`] instead.
#[derive(Clone, Default, Serialize)]
pub struct JwtCelRolePatch {
    /// Replacement CEL program.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cel_program: Option<JwtCelProgram>,
    /// Replacement static failure message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Replacement clock-skew validation leeway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_skew_leeway: Option<JwtLeeway>,
    /// Replacement expiration validation leeway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_leeway: Option<JwtLeeway>,
    /// Replacement not-before validation leeway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before_leeway: Option<JwtLeeway>,
    /// Replacement audiences accepted from the JWT `aud` claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_audiences: Option<Vec<String>>,
}

impl fmt::Debug for JwtCelRolePatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwtCelRolePatch")
            .field("has_cel_program", &self.cel_program.is_some())
            .field("message", &self.message)
            .field("clock_skew_leeway", &self.clock_skew_leeway)
            .field("expiration_leeway", &self.expiration_leeway)
            .field("not_before_leeway", &self.not_before_leeway)
            .field("bound_audiences", &self.bound_audiences)
            .finish()
    }
}

impl JwtCelRolePatch {
    fn validate(&self) -> Result<()> {
        if self.cel_program.is_none()
            && self.message.is_none()
            && self.clock_skew_leeway.is_none()
            && self.expiration_leeway.is_none()
            && self.not_before_leeway.is_none()
            && self.bound_audiences.is_none()
        {
            return Err(Error::InvalidParameter(
                "JWT CEL role patch must select at least one field".into(),
            ));
        }
        if let Some(program) = &self.cel_program {
            program.validate()?;
        }
        if self
            .message
            .as_ref()
            .is_some_and(|message| message.len() > MAX_CEL_MESSAGE_BYTES)
        {
            return Err(Error::InvalidParameter(
                "JWT CEL role message exceeds size limit".into(),
            ));
        }
        for leeway in [
            &self.clock_skew_leeway,
            &self.expiration_leeway,
            &self.not_before_leeway,
        ] {
            validate_cel_leeway(leeway.as_ref())?;
        }
        if let Some(audiences) = &self.bound_audiences {
            validate_cel_audiences(audiences)?;
        }
        Ok(())
    }
}

/// JWT CEL role returned by OpenBao.
#[derive(Clone)]
pub struct JwtCelRole {
    /// Role name.
    pub name: String,
    /// CEL program evaluated by the role.
    pub cel_program: JwtCelProgram,
    /// Static authentication failure message.
    pub message: Option<String>,
    /// Clock-skew validation leeway.
    pub clock_skew_leeway: Option<JwtLeeway>,
    /// Expiration validation leeway.
    pub expiration_leeway: Option<JwtLeeway>,
    /// Not-before validation leeway.
    pub not_before_leeway: Option<JwtLeeway>,
    /// Audiences accepted from the JWT `aud` claim.
    pub bound_audiences: Vec<String>,
}

impl<'de> Deserialize<'de> for JwtCelRole {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RoleData {
            #[serde(default)]
            name: String,
            cel_program: JwtCelProgram,
            #[serde(default)]
            message: Option<String>,
            #[serde(default)]
            clock_skew_leeway: Option<JwtLeeway>,
            #[serde(default)]
            expiration_leeway: Option<JwtLeeway>,
            #[serde(default)]
            not_before_leeway: Option<JwtLeeway>,
            #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
            bound_audiences: Vec<String>,
        }

        let data = RoleData::deserialize(deserializer)?;
        let role = Self {
            name: data.name,
            cel_program: data.cel_program,
            message: data.message,
            clock_skew_leeway: data.clock_skew_leeway,
            expiration_leeway: data.expiration_leeway,
            not_before_leeway: data.not_before_leeway,
            bound_audiences: data.bound_audiences,
        };
        role.validate().map_err(serde::de::Error::custom)?;
        Ok(role)
    }
}

impl JwtCelRole {
    fn validate(&self) -> Result<()> {
        self.cel_program.validate()?;
        if self
            .message
            .as_ref()
            .is_some_and(|message| message.len() > MAX_CEL_MESSAGE_BYTES)
        {
            return Err(Error::InvalidParameter(
                "JWT CEL role message exceeds size limit".into(),
            ));
        }
        for leeway in [
            &self.clock_skew_leeway,
            &self.expiration_leeway,
            &self.not_before_leeway,
        ] {
            validate_cel_leeway(leeway.as_ref())?;
        }
        validate_cel_audiences(&self.bound_audiences)
    }
}

impl fmt::Debug for JwtCelRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwtCelRole")
            .field("name", &self.name)
            .field("cel_program", &self.cel_program)
            .field("message", &self.message)
            .field("clock_skew_leeway", &self.clock_skew_leeway)
            .field("expiration_leeway", &self.expiration_leeway)
            .field("not_before_leeway", &self.not_before_leeway)
            .field("bound_audiences", &self.bound_audiences)
            .finish()
    }
}

/// JWT CEL role list.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct JwtCelRoleList {
    /// CEL role names.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub keys: Vec<String>,
}

impl ListEntries for JwtCelRoleList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

fn deserialize_bounded_cel_variables<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<JwtCelVariable>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedCelVariablesVisitor)
}

struct BoundedCelVariablesVisitor;

impl<'de> Visitor<'de> for BoundedCelVariablesVisitor {
    type Value = Vec<JwtCelVariable>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded list of JWT CEL variables")
    }

    fn visit_seq<A>(self, mut sequence: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while values.len() < MAX_CEL_VARIABLES {
            let Some(value) = sequence.next_element::<JwtCelVariable>()? else {
                return Ok(values);
            };
            values.push(value);
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(
                "JWT CEL variables exceed item limit",
            ));
        }
        Ok(values)
    }
}

fn deserialize_cel_secret<'de, D>(deserializer: D) -> core::result::Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(SecretString::from)
}

fn serialize_cel_secret<S>(
    value: &SecretString,
    serializer: S,
) -> core::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value.expose_secret())
}

fn validate_cel_identifier(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_CEL_IDENTIFIER_BYTES
        || !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        || !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return Err(Error::InvalidParameter(
            "JWT CEL variable name must be a bounded ASCII identifier".into(),
        ));
    }
    Ok(())
}

fn validate_cel_expression(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::InvalidParameter(
            "JWT CEL expression must not be empty".into(),
        ));
    }
    if value.len() > MAX_CEL_EXPRESSION_BYTES {
        return Err(Error::InvalidParameter(
            "JWT CEL expression exceeds size limit".into(),
        ));
    }
    Ok(())
}

fn validate_cel_leeway(leeway: Option<&JwtLeeway>) -> Result<()> {
    if let Some(JwtLeeway::Duration(duration)) = leeway {
        crate::validation::validate_duration_parameter(duration, "JWT CEL leeway")?;
    }
    Ok(())
}

fn validate_cel_audiences(audiences: &[String]) -> Result<()> {
    if audiences.len() > MAX_CEL_AUDIENCES {
        return Err(Error::InvalidParameter(
            "JWT CEL bound_audiences exceeds item limit".into(),
        ));
    }
    Ok(())
}

impl ListEntries for JwtRoleList {
    fn entries(&self) -> &[String] {
        &self.keys
    }
}

#[cfg(any(feature = "oidc-get-callback-acknowledged", test))]
const MAX_OIDC_STATE_BYTES: usize = 4 * 1024;
#[cfg(any(feature = "oidc-get-callback-acknowledged", test))]
const MAX_OIDC_CREDENTIAL_BYTES: usize = 64 * 1024;
const MAX_OIDC_NONCE_BYTES: usize = 4 * 1024;
const MAX_OIDC_REDIRECT_URI_BYTES: usize = 8 * 1024;

/// Request for starting an OIDC browser login flow.
#[derive(Clone, Default)]
pub struct OidcAuthUrlRequest {
    /// Role used for the OIDC login. Defaults to the mount default role when omitted.
    pub role: Option<String>,
    /// Callback URL registered with OpenBao and the OIDC provider.
    pub redirect_uri: Option<String>,
    /// Optional nonce that must match the later callback or poll request.
    pub client_nonce: Option<SecretString>,
}

impl fmt::Debug for OidcAuthUrlRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcAuthUrlRequest")
            .field("role", &self.role)
            .field("redirect_uri", &self.redirect_uri)
            .field("has_client_nonce", &self.client_nonce.is_some())
            .finish()
    }
}

impl Serialize for OidcAuthUrlRequest {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let count = usize::from(self.role.is_some())
            + usize::from(self.redirect_uri.is_some())
            + usize::from(self.client_nonce.is_some());
        let mut map = serializer.serialize_map(Some(count))?;
        if let Some(role) = &self.role {
            map.serialize_entry("role", role)?;
        }
        if let Some(redirect_uri) = &self.redirect_uri {
            map.serialize_entry("redirect_uri", redirect_uri)?;
        }
        if let Some(client_nonce) = &self.client_nonce {
            map.serialize_entry("client_nonce", client_nonce.expose_secret())?;
        }
        map.end()
    }
}

impl OidcAuthUrlRequest {
    /// Creates a browser OIDC authorization URL request for a callback URL.
    pub fn new(redirect_uri: impl Into<String>) -> Self {
        Self {
            redirect_uri: Some(redirect_uri.into()),
            ..Self::default()
        }
    }

    /// Creates a device/direct callback-mode request without a redirect URI.
    pub fn device() -> Self {
        Self::default()
    }

    /// Sets the role used for the OIDC login.
    #[must_use]
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    /// Sets the client nonce used to bind later callback or poll requests.
    #[must_use]
    pub fn with_client_nonce(mut self, client_nonce: impl Into<SecretString>) -> Self {
        self.client_nonce = Some(client_nonce.into());
        self
    }

    fn validate(&self) -> Result<()> {
        if let Some(role) = &self.role {
            validate_mount_path(role)?;
        }
        if let Some(redirect_uri) = &self.redirect_uri {
            validate_oidc_plain_value(
                redirect_uri,
                MAX_OIDC_REDIRECT_URI_BYTES,
                "OIDC redirect_uri must not be empty",
                "OIDC redirect_uri exceeds the maximum length",
            )?;
        }
        if let Some(client_nonce) = &self.client_nonce {
            validate_oidc_secret_value(
                client_nonce,
                MAX_OIDC_NONCE_BYTES,
                "OIDC client_nonce must not be empty",
                "OIDC client_nonce exceeds the maximum length",
            )?;
        }
        Ok(())
    }
}

/// Authorization URL returned by OpenBao for an OIDC login flow.
#[derive(Clone, Debug, Deserialize)]
pub struct OidcAuthUrlResponse {
    /// Authorization URL that the user should visit in a browser.
    pub auth_url: String,
    /// Device-flow user code, when OpenBao returns one.
    #[serde(default)]
    pub user_code: Option<String>,
    /// Poll interval in seconds for direct or device callback modes.
    #[serde(default)]
    pub poll_interval: Option<u64>,
}

/// Request for completing a browser OIDC callback.
#[derive(Clone)]
pub struct OidcCallbackRequest {
    /// Opaque state returned by the OIDC provider.
    pub state: SecretString,
    /// Provider authorization code. Required when `id_token` is omitted.
    pub code: Option<SecretString>,
    /// Provider ID token. Required when `code` is omitted.
    pub id_token: Option<SecretString>,
    /// Client nonce supplied to `oidc_auth_url`, when used.
    pub client_nonce: Option<SecretString>,
    /// Provider error code, when the provider returned no credential.
    pub error: Option<SecretString>,
    /// Provider error description.
    pub error_description: Option<SecretString>,
    /// Provider error documentation URI.
    pub error_uri: Option<SecretString>,
}

impl fmt::Debug for OidcCallbackRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcCallbackRequest")
            .field("state", &"<redacted>")
            .field("has_code", &self.code.is_some())
            .field("has_id_token", &self.id_token.is_some())
            .field("has_client_nonce", &self.client_nonce.is_some())
            .field("has_error", &self.error.is_some())
            .field("has_error_description", &self.error_description.is_some())
            .field("has_error_uri", &self.error_uri.is_some())
            .finish()
    }
}

impl OidcCallbackRequest {
    /// Creates a callback request using an authorization code.
    pub fn with_code(state: impl Into<SecretString>, code: SecretString) -> Self {
        Self {
            state: state.into(),
            code: Some(code),
            id_token: None,
            client_nonce: None,
            error: None,
            error_description: None,
            error_uri: None,
        }
    }

    /// Creates a callback request using an ID token.
    pub fn with_id_token(state: impl Into<SecretString>, id_token: SecretString) -> Self {
        Self {
            state: state.into(),
            code: None,
            id_token: Some(id_token),
            client_nonce: None,
            error: None,
            error_description: None,
            error_uri: None,
        }
    }

    /// Creates a callback carrying an OIDC provider error response.
    pub fn with_provider_error(
        state: impl Into<SecretString>,
        error: impl Into<SecretString>,
    ) -> Self {
        Self {
            state: state.into(),
            code: None,
            id_token: None,
            client_nonce: None,
            error: Some(error.into()),
            error_description: None,
            error_uri: None,
        }
    }

    /// Adds provider error details to an error callback.
    #[must_use]
    pub fn with_provider_error_details(
        mut self,
        description: Option<SecretString>,
        uri: Option<SecretString>,
    ) -> Self {
        self.error_description = description;
        self.error_uri = uri;
        self
    }

    /// Sets the client nonce that must match the authorization URL request.
    #[must_use]
    pub fn with_client_nonce(mut self, client_nonce: impl Into<SecretString>) -> Self {
        self.client_nonce = Some(client_nonce.into());
        self
    }

    #[cfg(any(feature = "oidc-get-callback-acknowledged", test))]
    fn validate(&self) -> Result<()> {
        validate_oidc_secret_value(
            &self.state,
            MAX_OIDC_STATE_BYTES,
            "OIDC state must not be empty",
            "OIDC state exceeds the maximum length",
        )?;
        match (&self.code, &self.id_token, &self.error) {
            (Some(code), None, None) => validate_oidc_credential(code)?,
            (None, Some(id_token), None) => validate_oidc_credential(id_token)?,
            (None, None, Some(error)) => validate_oidc_credential(error)?,
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) | (_, Some(_), Some(_)) => {
                return Err(Error::InvalidParameter(
                    "OIDC callback accepts exactly one of code, id_token, or error".into(),
                ));
            }
            _ => {
                return Err(Error::InvalidParameter(
                    "OIDC callback requires one non-empty credential".into(),
                ));
            }
        }
        if let Some(client_nonce) = &self.client_nonce {
            validate_oidc_secret_value(
                client_nonce,
                MAX_OIDC_NONCE_BYTES,
                "OIDC client_nonce must not be empty",
                "OIDC client_nonce exceeds the maximum length",
            )?;
        }
        for value in [&self.error_description, &self.error_uri]
            .into_iter()
            .flatten()
        {
            validate_oidc_credential(value)?;
        }
        if self.error.is_none() && (self.error_description.is_some() || self.error_uri.is_some()) {
            return Err(Error::InvalidParameter(
                "OIDC callback error details require an error value".into(),
            ));
        }
        Ok(())
    }
}

/// Request for polling an OIDC direct or device callback flow.
#[derive(Clone)]
pub struct OidcPollRequest {
    /// Opaque state returned by the authorization URL request.
    pub state: SecretString,
    /// Client nonce supplied to `oidc_auth_url`, when used.
    pub client_nonce: Option<SecretString>,
}

impl fmt::Debug for OidcPollRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcPollRequest")
            .field("state", &"<redacted>")
            .field("has_client_nonce", &self.client_nonce.is_some())
            .finish()
    }
}

impl Serialize for OidcPollRequest {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map =
            serializer.serialize_map(Some(1 + usize::from(self.client_nonce.is_some())))?;
        map.serialize_entry("state", self.state.expose_secret())?;
        if let Some(client_nonce) = &self.client_nonce {
            map.serialize_entry("client_nonce", client_nonce.expose_secret())?;
        }
        map.end()
    }
}

impl OidcPollRequest {
    /// Creates an OIDC poll request.
    pub fn new(state: impl Into<SecretString>) -> Self {
        Self {
            state: state.into(),
            client_nonce: None,
        }
    }

    /// Sets the client nonce that must match the authorization URL request.
    #[must_use]
    pub fn with_client_nonce(mut self, client_nonce: impl Into<SecretString>) -> Self {
        self.client_nonce = Some(client_nonce.into());
        self
    }

    #[cfg(any(feature = "oidc-get-callback-acknowledged", test))]
    fn validate(&self) -> Result<()> {
        validate_oidc_secret_value(
            &self.state,
            MAX_OIDC_STATE_BYTES,
            "OIDC state must not be empty",
            "OIDC state exceeds the maximum length",
        )?;
        if let Some(client_nonce) = &self.client_nonce {
            validate_oidc_secret_value(
                client_nonce,
                MAX_OIDC_NONCE_BYTES,
                "OIDC client_nonce must not be empty",
                "OIDC client_nonce exceeds the maximum length",
            )?;
        }
        Ok(())
    }
}

fn validate_oidc_plain_value(
    value: &str,
    maximum: usize,
    empty_error: &'static str,
    length_error: &'static str,
) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::InvalidParameter(empty_error.into()));
    }
    if value.len() > maximum {
        return Err(Error::InvalidParameter(length_error.into()));
    }
    Ok(())
}

fn validate_oidc_secret_value(
    value: &SecretString,
    maximum: usize,
    empty_error: &'static str,
    length_error: &'static str,
) -> Result<()> {
    validate_oidc_plain_value(value.expose_secret(), maximum, empty_error, length_error)
}

#[cfg(any(feature = "oidc-get-callback-acknowledged", test))]
fn validate_oidc_credential(value: &SecretString) -> Result<()> {
    let value = value.expose_secret();
    if value.is_empty() {
        return Err(Error::InvalidParameter(
            "OIDC callback requires one non-empty credential".into(),
        ));
    }
    if value.len() > MAX_OIDC_CREDENTIAL_BYTES {
        return Err(Error::InvalidParameter(
            "OIDC callback credential exceeds the maximum length".into(),
        ));
    }
    Ok(())
}

/// Metadata returned after a successful JWT login.
#[derive(Deserialize)]
pub struct JwtLoginMetadata {
    /// Token accessor. Accessors can revoke or look up token metadata, so they
    /// are treated as secret material.
    pub accessor: SecretString,
    /// Policies attached to the token.
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    pub policies: Vec<String>,
    /// Token lease duration in seconds.
    #[serde(default)]
    pub lease_duration: u64,
    /// Whether the token is renewable.
    #[serde(default)]
    pub renewable: bool,
    /// Secret-aware metadata returned by OpenBao.
    ///
    /// With `oauth2_metadata`, values can include OAuth access, ID, and
    /// refresh tokens. `Debug` therefore reports only the number of entries.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_secret_metadata_or_default"
    )]
    pub metadata: BTreeMap<String, SecretString>,
}

impl fmt::Debug for JwtLoginMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwtLoginMetadata")
            .field("accessor", &"<redacted>")
            .field("policies", &self.policies)
            .field("lease_duration", &self.lease_duration)
            .field("renewable", &self.renewable)
            .field("metadata_entry_count", &self.metadata.len())
            .finish()
    }
}

#[derive(Serialize)]
struct JwtConfigPayload<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc_discovery_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc_discovery_ca_pem: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwks_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwks_ca_pem: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    jwt_validation_pubkeys: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bound_issuer: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    jwt_supported_algs: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_role: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc_client_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc_client_secret: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc_response_mode: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    oidc_response_types: Vec<&'a str>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    provider_config: &'a BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    override_allowed_server_names: Vec<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_jwks_validation: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace_in_state: Option<bool>,
}

#[derive(Serialize)]
struct JwtLoginRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<&'a str>,
    jwt: &'a str,
}

#[derive(Deserialize)]
struct JwtLoginResponse {
    auth: Option<JwtLoginAuth>,
}

#[derive(Deserialize)]
struct JwtLoginAuth {
    client_token: SecretString,
    accessor: SecretString,
    #[serde(default, deserialize_with = "deserialize_bounded_string_vec")]
    policies: Vec<String>,
    #[serde(default)]
    lease_duration: u64,
    #[serde(default)]
    renewable: bool,
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_secret_metadata_or_default"
    )]
    metadata: BTreeMap<String, SecretString>,
}

#[derive(Deserialize)]
struct BoundedSecretMetadata(
    #[serde(deserialize_with = "deserialize_bounded_secret_metadata")]
    BTreeMap<String, SecretString>,
);

fn deserialize_bounded_secret_metadata_or_default<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, SecretString>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<BoundedSecretMetadata>::deserialize(deserializer)?
        .map(|metadata| metadata.0)
        .unwrap_or_default())
}

fn deserialize_bounded_secret_metadata<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, SecretString>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(BoundedSecretMetadataVisitor)
}

struct BoundedSecretMetadataVisitor;

impl<'de> Visitor<'de> for BoundedSecretMetadataVisitor {
    type Value = BTreeMap<String, SecretString>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JWT/OIDC metadata object")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        let mut entry_count = 0;
        while entry_count < crate::MAX_RESPONSE_STRINGS {
            let Some((key, value)) = map.next_entry::<String, SecretString>()? else {
                return Ok(values);
            };
            entry_count += 1;
            if values.insert(key, value).is_some() {
                return Err(serde::de::Error::custom(
                    "JWT/OIDC metadata contains a duplicate key",
                ));
            }
        }
        if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(
                "JWT/OIDC metadata exceeds item limit",
            ));
        }
        Ok(values)
    }
}

impl Client<Unauthenticated> {
    /// Uses the JWT/OIDC auth method mounted at `auth/jwt`.
    pub fn jwt(&self) -> Result<JwtAuth<'_>> {
        self.jwt_at("jwt")
    }

    /// Uses the JWT/OIDC auth method mounted at `auth/{mount}`.
    pub fn jwt_at(&self, mount: impl Into<String>) -> Result<JwtAuth<'_>> {
        Ok(JwtAuth {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }

    /// Logs in with JWT auth at `auth/jwt`.
    pub async fn login_jwt(
        self,
        role: Option<&str>,
        jwt: SecretString,
    ) -> Result<(Client<Authenticated>, JwtLoginMetadata)> {
        let response = self.jwt()?.login_response(role, &jwt).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((self.try_with_token(token)?, metadata))
    }

    /// Logs in with an OpenBao 2.6 JWT CEL role at `auth/jwt`.
    pub async fn login_jwt_cel(
        self,
        role: Option<&str>,
        jwt: SecretString,
    ) -> Result<(Client<Authenticated>, JwtLoginMetadata)> {
        let response = self.jwt()?.login_cel_response(role, &jwt).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((self.try_with_token(token)?, metadata))
    }
}

impl Client<Authenticated> {
    /// Administers the JWT/OIDC auth method mounted at `auth/jwt`.
    pub fn jwt_admin(&self) -> Result<JwtAuthAdmin<'_>> {
        self.jwt_admin_at("jwt")
    }

    /// Administers the JWT/OIDC auth method mounted at `auth/{mount}`.
    pub fn jwt_admin_at(&self, mount: impl Into<String>) -> Result<JwtAuthAdmin<'_>> {
        Ok(JwtAuthAdmin {
            client: self,
            mount: validate_mount_path(&mount.into())?.join("/"),
        })
    }
}

impl JwtAuth<'_> {
    /// Obtains an OIDC authorization URL for a browser, direct, or device flow.
    pub async fn oidc_auth_url(&self, request: &OidcAuthUrlRequest) -> Result<OidcAuthUrlResponse> {
        request.validate()?;
        let envelope: ResponseEnvelope<OidcAuthUrlResponse> = self
            .client
            .request_auth_json_internal(
                "jwt",
                &self.mount,
                Method::POST,
                &format!("auth/{}/oidc/auth_url", self.mount),
                Some(request),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Completes an OIDC callback and returns an authenticated client.
    ///
    /// The callback parameters are sent as query values because OpenBao
    /// documents the callback endpoint as a `GET` endpoint. This method is
    /// available only with `oidc-get-callback-acknowledged`: the authorization
    /// code or ID token necessarily enters a non-sanitizing URL buffer and may
    /// be recorded by query-aware access logs. Deployments must disable query
    /// logging on OpenBao and every intermediary before enabling the feature.
    #[cfg(feature = "oidc-get-callback-acknowledged")]
    pub async fn oidc_callback(
        self,
        request: &OidcCallbackRequest,
    ) -> Result<(Client<Authenticated>, JwtLoginMetadata)> {
        let response = self.oidc_callback_response(request).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((
            self.client.clone_without_state().try_with_token(token)?,
            metadata,
        ))
    }

    /// Polls a direct or device OIDC flow and returns an authenticated client on success.
    ///
    /// OpenBao documents this as a `GET` query operation. It therefore shares
    /// the `oidc-get-callback-acknowledged` gate with [`Self::oidc_callback`]:
    /// state and nonce values necessarily enter non-sanitizing URL buffers.
    #[cfg(feature = "oidc-get-callback-acknowledged")]
    pub async fn oidc_poll(
        self,
        request: &OidcPollRequest,
    ) -> Result<(Client<Authenticated>, JwtLoginMetadata)> {
        let response = self.oidc_poll_response(request).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((
            self.client.clone_without_state().try_with_token(token)?,
            metadata,
        ))
    }

    /// Logs in and returns token metadata plus an authenticated client.
    pub async fn login(
        self,
        role: Option<&str>,
        jwt: SecretString,
    ) -> Result<(Client<Authenticated>, JwtLoginMetadata)> {
        let response = self.login_response(role, &jwt).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((
            self.client.clone_without_state().try_with_token(token)?,
            metadata,
        ))
    }

    /// Logs in against an OpenBao 2.6 JWT CEL role.
    ///
    /// CEL is evaluated by OpenBao after JWT validation. Restrict role
    /// administration separately; this login helper only submits the signed
    /// JWT and optional role name.
    pub async fn login_cel(
        self,
        role: Option<&str>,
        jwt: SecretString,
    ) -> Result<(Client<Authenticated>, JwtLoginMetadata)> {
        let response = self.login_cel_response(role, &jwt).await?;
        let (token, metadata) = split_login_auth(response);
        Ok((
            self.client.clone_without_state().try_with_token(token)?,
            metadata,
        ))
    }

    async fn login_response(&self, role: Option<&str>, jwt: &SecretString) -> Result<JwtLoginAuth> {
        let role = role
            .map(|role| validate_mount_path(role).map(|segments| segments.join("/")))
            .transpose()?;
        let request = JwtLoginRequest {
            role: role.as_deref(),
            jwt: jwt.expose_secret(),
        };
        let response: JwtLoginResponse = self
            .client
            .request_auth_json_internal(
                "jwt",
                &self.mount,
                Method::POST,
                &format!("auth/{}/login", self.mount),
                Some(&request),
            )
            .await?;
        response.auth.ok_or(Error::MissingField("auth"))
    }

    async fn login_cel_response(
        &self,
        role: Option<&str>,
        jwt: &SecretString,
    ) -> Result<JwtLoginAuth> {
        let role = role
            .map(|role| validate_mount_path(role).map(|segments| segments.join("/")))
            .transpose()?;
        let request = JwtLoginRequest {
            role: role.as_deref(),
            jwt: jwt.expose_secret(),
        };
        let response: JwtLoginResponse = self
            .client
            .request_auth_secret_json_internal(
                "jwt",
                &self.mount,
                Method::POST,
                &format!("auth/{}/cel/login", self.mount),
                Some(&request),
            )
            .await?;
        response.auth.ok_or(Error::MissingField("auth"))
    }

    #[cfg(feature = "oidc-get-callback-acknowledged")]
    async fn oidc_callback_response(&self, request: &OidcCallbackRequest) -> Result<JwtLoginAuth> {
        request.validate()?;
        // SECURITY: OAuth2 codes and ID tokens are passed as query values
        // because OpenBao documents this callback as GET. The shared client
        // transport treats any query-bearing request as sensitive, so default
        // builds still require HTTPS and sanitized transport errors. Borrowed
        // values avoid an additional ordinary String copy before reqwest owns
        // the unavoidable URL buffer.
        let mut query = vec![("state", request.state.expose_secret())];
        if let Some(code) = &request.code {
            query.push(("code", code.expose_secret()));
        }
        if let Some(id_token) = &request.id_token {
            query.push(("id_token", id_token.expose_secret()));
        }
        if let Some(client_nonce) = &request.client_nonce {
            query.push(("client_nonce", client_nonce.expose_secret()));
        }
        if let Some(error) = &request.error {
            query.push(("error", error.expose_secret()));
        }
        if let Some(description) = &request.error_description {
            query.push(("error_description", description.expose_secret()));
        }
        if let Some(uri) = &request.error_uri {
            query.push(("error_uri", uri.expose_secret()));
        }
        let response: JwtLoginResponse = self
            .client
            .request_auth_json_secret_query_accepting(
                "jwt",
                &self.mount,
                Method::GET,
                &format!("auth/{}/oidc/callback", self.mount),
                &query,
                Option::<&Empty>::None,
                &[reqwest::StatusCode::OK],
            )
            .await?;
        response.auth.ok_or(Error::MissingField("auth"))
    }

    #[cfg(feature = "oidc-get-callback-acknowledged")]
    async fn oidc_poll_response(&self, request: &OidcPollRequest) -> Result<JwtLoginAuth> {
        request.validate()?;
        let mut query = vec![("state", request.state.expose_secret())];
        if let Some(client_nonce) = &request.client_nonce {
            query.push(("client_nonce", client_nonce.expose_secret()));
        }
        let response: JwtLoginResponse = self
            .client
            .request_auth_json_secret_query_accepting(
                "jwt",
                &self.mount,
                Method::GET,
                &format!("auth/{}/oidc/poll", self.mount),
                &query,
                Option::<&Empty>::None,
                &[reqwest::StatusCode::OK],
            )
            .await?;
        response.auth.ok_or(Error::MissingField("auth"))
    }
}

impl JwtAuthAdmin<'_> {
    /// Configures the JWT/OIDC auth method.
    pub async fn configure(&self, config: &JwtConfig) -> Result<Empty> {
        config.validate()?;
        self.client
            .validate_versioned_request_fields(&[
                (
                    &crate::request_compatibility::fields::JWT_CONFIG_SKIP_JWKS_VALIDATION,
                    config.skip_jwks_validation.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::JWT_CONFIG_OVERRIDE_ALLOWED_SERVER_NAMES,
                    !config.override_allowed_server_names.is_empty(),
                ),
                (
                    &crate::request_compatibility::fields::JWT_CONFIG_KUBERNETES_PROVIDER,
                    config.uses_kubernetes_provider(),
                ),
            ])
            .await?;
        let payload = JwtConfigPayload {
            oidc_discovery_url: config.oidc_discovery_url.as_deref(),
            oidc_discovery_ca_pem: config.oidc_discovery_ca_pem.as_deref(),
            jwks_url: config.jwks_url.as_deref(),
            jwks_ca_pem: config.jwks_ca_pem.as_deref(),
            jwt_validation_pubkeys: config
                .jwt_validation_pubkeys
                .iter()
                .map(String::as_str)
                .collect(),
            bound_issuer: config.bound_issuer.as_deref(),
            jwt_supported_algs: config
                .jwt_supported_algs
                .iter()
                .map(String::as_str)
                .collect(),
            default_role: config.default_role.as_deref(),
            oidc_client_id: config.oidc_client_id.as_deref(),
            oidc_client_secret: config
                .oidc_client_secret
                .as_ref()
                .map(SecretString::expose_secret),
            oidc_response_mode: config.oidc_response_mode.as_deref(),
            oidc_response_types: config
                .oidc_response_types
                .iter()
                .map(String::as_str)
                .collect(),
            provider_config: &config.provider_config,
            override_allowed_server_names: config
                .override_allowed_server_names
                .iter()
                .map(String::as_str)
                .collect(),
            skip_jwks_validation: config.skip_jwks_validation,
            namespace_in_state: config.namespace_in_state,
        };
        self.client
            .request_auth_json_internal(
                "jwt",
                &self.mount,
                Method::POST,
                &format!("auth/{}/config", self.mount),
                Some(&payload),
            )
            .await
    }

    /// Reads the JWT/OIDC auth method configuration.
    pub async fn read_config(&self) -> Result<JwtConfig> {
        let envelope: ResponseEnvelope<JwtConfig> = self
            .client
            .request_auth_json_internal(
                "jwt",
                &self.mount,
                Method::GET,
                &format!("auth/{}/config", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Creates or updates a JWT/OIDC auth role.
    pub async fn write_role(&self, name: &str, role: &JwtRole) -> Result<Empty> {
        role.validate()?;
        self.client
            .validate_versioned_request_fields(&[
                (
                    &crate::request_compatibility::fields::JWT_ROLE_CALLBACK_MODE,
                    role.callback_mode.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::JWT_ROLE_POLL_INTERVAL,
                    role.poll_interval.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::JWT_ROLE_TOKEN_POLICY_TEMPLATES,
                    role.token_policies_template_claims.is_some(),
                ),
                (
                    &crate::request_compatibility::fields::JWT_ROLE_DISABLE_CONFIRMATION,
                    role.oidc_disable_confirmation.is_some(),
                ),
            ])
            .await?;
        let name = validate_mount_path(name)?.join("/");
        self.client
            .request_auth_json_internal(
                "jwt",
                &self.mount,
                Method::POST,
                &format!("auth/{}/role/{name}", self.mount),
                Some(role),
            )
            .await
    }

    /// Reads a JWT/OIDC auth role.
    pub async fn read_role(&self, name: &str) -> Result<JwtRole> {
        let name = validate_mount_path(name)?.join("/");
        let envelope: ResponseEnvelope<JwtRole> = self
            .client
            .request_auth_json_internal(
                "jwt",
                &self.mount,
                Method::GET,
                &format!("auth/{}/role/{name}", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists JWT/OIDC auth role names.
    pub async fn list_roles(&self) -> Result<JwtRoleList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        let envelope: ResponseEnvelope<JwtRoleList> = self
            .client
            .request_auth_json_internal(
                "jwt",
                &self.mount,
                method,
                &format!("auth/{}/role", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes a JWT/OIDC auth role.
    pub async fn delete_role(&self, name: &str) -> Result<Empty> {
        let name = validate_mount_path(name)?.join("/");
        self.client
            .request_auth_json_accepting(
                "jwt",
                &self.mount,
                Method::DELETE,
                &format!("auth/{}/role/{name}", self.mount),
                Option::<&Empty>::None,
                &[reqwest::StatusCode::OK, reqwest::StatusCode::NO_CONTENT],
            )
            .await
    }

    /// Creates or replaces an OpenBao 2.6 JWT CEL role.
    ///
    /// CEL program source is redacted from `Debug` but is sent to OpenBao as
    /// secret-adjacent policy material. Grant this endpoint only to trusted
    /// administrators and enforce server-side CPU and request limits. The
    /// request must explicitly acknowledge that its CEL program requires and
    /// constrains every authorization claim; `bound_audiences` alone does not
    /// reject JWTs that omit `aud`.
    pub async fn write_cel_role(&self, name: &str, role: &JwtCelRoleRequest) -> Result<JwtCelRole> {
        role.validate()?;
        let name = validate_mount_path(name)?.join("/");
        let envelope: ResponseEnvelope<JwtCelRole> = self
            .client
            .request_auth_secret_json_internal(
                "jwt",
                &self.mount,
                Method::POST,
                &format!("auth/{}/cel/role/{name}", self.mount),
                Some(role),
            )
            .await?;
        Ok(envelope.data)
    }

    /// Patches an OpenBao JWT CEL role when the selected exact profile is safe.
    ///
    /// Exact OpenBao 2.6.0 is security-blocked because its PATCH handler drops
    /// audience and leeway constraints. Use [`Self::write_cel_role`] for 2.6.0.
    pub async fn patch_cel_role(&self, name: &str, patch: &JwtCelRolePatch) -> Result<JwtCelRole> {
        patch.validate()?;
        let name = validate_mount_path(name)?.join("/");
        let envelope: ResponseEnvelope<JwtCelRole> = self
            .client
            .request_auth_secret_json_headers_accepting(
                "jwt",
                &self.mount,
                Method::PATCH,
                &format!("auth/{}/cel/role/{name}", self.mount),
                &[(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/merge-patch+json"),
                )],
                Some(patch),
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Reads an OpenBao 2.6 JWT CEL role.
    pub async fn read_cel_role(&self, name: &str) -> Result<JwtCelRole> {
        let name = validate_mount_path(name)?.join("/");
        let envelope: ResponseEnvelope<JwtCelRole> = self
            .client
            .request_auth_secret_json_internal(
                "jwt",
                &self.mount,
                Method::GET,
                &format!("auth/{}/cel/role/{name}", self.mount),
                Option::<&Empty>::None,
            )
            .await?;
        Ok(envelope.data)
    }

    /// Lists OpenBao 2.6 JWT CEL role names.
    pub async fn list_cel_roles(&self) -> Result<JwtCelRoleList> {
        self.list_cel_roles_page(None, None).await
    }

    /// Lists OpenBao 2.6 JWT CEL role names with bounded pagination.
    pub async fn list_cel_roles_page(
        &self,
        after: Option<&str>,
        limit: Option<u64>,
    ) -> Result<JwtCelRoleList> {
        let method =
            Method::from_bytes(b"LIST").map_err(|error| Error::InvalidHeader(error.to_string()))?;
        if let Some(after) = after {
            validate_mount_path(after)?;
        }
        let query = ListPageOptions::from_after_limit(after, limit)?.query_pairs();
        let envelope: ResponseEnvelope<JwtCelRoleList> = self
            .client
            .request_auth_json_query_accepting(
                "jwt",
                &self.mount,
                method,
                &format!("auth/{}/cel/role", self.mount),
                &query,
                Option::<&Empty>::None,
                &[StatusCode::OK],
            )
            .await?;
        Ok(envelope.data)
    }

    /// Deletes an OpenBao 2.6 JWT CEL role.
    pub async fn delete_cel_role(&self, name: &str) -> Result<Empty> {
        let name = validate_mount_path(name)?.join("/");
        self.client
            .request_auth_json_accepting(
                "jwt",
                &self.mount,
                Method::DELETE,
                &format!("auth/{}/cel/role/{name}", self.mount),
                Option::<&Empty>::None,
                &[StatusCode::OK, StatusCode::NO_CONTENT],
            )
            .await
    }
}

fn split_login_auth(auth: JwtLoginAuth) -> (SecretString, JwtLoginMetadata) {
    let JwtLoginAuth {
        client_token,
        accessor,
        policies,
        lease_duration,
        renewable,
        metadata,
    } = auth;
    let metadata = JwtLoginMetadata {
        accessor,
        policies,
        lease_duration,
        renewable,
        metadata,
    };
    (client_token, metadata)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use std::collections::BTreeMap;

    use secrecy::{ExposeSecret, SecretString};

    use super::{
        JwtCelClaimValidationAcknowledgement, JwtCelProgram, JwtCelRole, JwtCelRolePatch,
        JwtCelRoleRequest, JwtConfig, JwtLeeway, JwtLoginResponse, JwtRole, JwtRoleList,
    };

    #[test]
    fn jwt_login_auth_deserializes_secret_token_fields() {
        let response: JwtLoginResponse = serde_json::from_str(
            r#"{"auth":{"client_token":"token-value","accessor":"accessor-value","metadata":{"role":"web"}}}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let auth = response.auth.unwrap_or_else(|| panic!("auth missing"));

        assert_eq!(auth.client_token.expose_secret(), "token-value");
        assert_eq!(auth.accessor.expose_secret(), "accessor-value");
        assert_eq!(
            auth.metadata.get("role").map(SecretString::expose_secret),
            Some("web")
        );

        let null_metadata: JwtLoginResponse = serde_json::from_str(
            r#"{"auth":{"client_token":"token-value","accessor":"accessor-value","metadata":null}}"#,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            null_metadata
                .auth
                .unwrap_or_else(|| panic!("auth missing"))
                .metadata
                .is_empty()
        );
    }

    #[test]
    fn jwt_role_list_is_bounded() {
        let mut keys = Vec::new();
        for index in 0..=crate::response::MAX_RESPONSE_STRINGS {
            keys.push(format!("role-{index}"));
        }
        let value = serde_json::json!({ "keys": keys });
        let error = match serde_json::from_value::<JwtRoleList>(value) {
            Ok(_) => panic!("oversized JWT role list unexpectedly decoded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("exceeds item limit"));
    }

    #[test]
    fn jwt_config_debug_redacts_client_secret() {
        let config = JwtConfig {
            oidc_client_secret: Some(SecretString::from("client-secret")),
            ..Default::default()
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("client-secret"));
    }

    #[test]
    fn kubernetes_provider_is_exclusive_and_version_identifiable() {
        let config = JwtConfig::kubernetes_provider();
        assert_eq!(
            config.provider_config.get("provider").map(String::as_str),
            Some("kubernetes")
        );
        assert!(config.validate().is_ok());

        let conflicting = JwtConfig {
            jwks_url: Some("https://keys.example.test/jwks".into()),
            ..JwtConfig::kubernetes_provider()
        };
        assert!(conflicting.validate().is_err());

        let extra = JwtConfig {
            provider_config: BTreeMap::from([
                ("provider".into(), "kubernetes".into()),
                ("unexpected".into(), "value".into()),
            ]),
            ..JwtConfig::default()
        };
        assert!(extra.validate().is_err());
    }

    #[test]
    fn jwt_cel_programs_are_bounded_typed_and_debug_redacted() {
        let program = JwtCelProgram::new("claims.secret == 'cel-secret-literal'")
            .and_then(|program| program.with_variable("has_group", "claims.groups.size() > 0"))
            .unwrap_or_else(|error| panic!("{error}"));
        let unacknowledged = JwtCelRoleRequest::new(program.clone());
        assert!(unacknowledged.validate().is_err());
        let request = unacknowledged.acknowledge_claim_validation(
            JwtCelClaimValidationAcknowledgement::all_authorization_claims_are_constrained_in_cel(),
        );
        let debug = format!("{request:?}");
        assert!(!debug.contains("cel-secret-literal"));
        assert!(request.validate().is_ok());

        let value = serde_json::to_value(&request).unwrap_or_else(|error| panic!("{error}"));
        assert!(value.get("claim_validation_acknowledged").is_none());
        assert_eq!(value["cel_program"]["variables"][0]["name"], "has_group");
        assert_eq!(
            value["cel_program"]["expression"],
            "claims.secret == 'cel-secret-literal'"
        );

        let response: JwtCelRole = serde_json::from_value(serde_json::json!({
            "name": "service",
            "cel_program": value["cel_program"].clone(),
            "bound_audiences": ["service"]
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.name, "service");
        assert_eq!(
            response.cel_program.expression().expose_secret(),
            "claims.secret == 'cel-secret-literal'"
        );
        assert_eq!(
            response.cel_program.variables[0]
                .expression()
                .expose_secret(),
            "claims.groups.size() > 0"
        );
        assert!(!format!("{response:?}").contains("cel-secret-literal"));

        let duplicate = JwtCelProgram {
            variables: vec![
                super::JwtCelVariable {
                    name: "same".into(),
                    expression: "true".into(),
                },
                super::JwtCelVariable {
                    name: "same".into(),
                    expression: "false".into(),
                },
            ],
            expression: "same".into(),
        };
        assert!(duplicate.validate().is_err());
        assert!(JwtCelProgram::new(" ").is_err());
        assert!(JwtCelRolePatch::default().validate().is_err());

        let patch = JwtCelRolePatch {
            bound_audiences: Some(vec!["service".into()]),
            expiration_leeway: Some(JwtLeeway::seconds(30)),
            ..JwtCelRolePatch::default()
        };
        let patch_value = serde_json::to_value(&patch).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(patch_value["bound_audiences"][0], "service");
        assert_eq!(patch_value["expiration_leeway"], 30);
    }

    #[test]
    fn jwt_cel_variable_lists_reject_overflow() {
        let variables = (0..=super::MAX_CEL_VARIABLES)
            .map(|index| serde_json::json!({"name": format!("v{index}"), "expression": "true"}))
            .collect::<Vec<_>>();
        let result = serde_json::from_value::<JwtCelProgram>(serde_json::json!({
            "variables": variables,
            "expression": "true"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn jwt_cel_roles_reject_oversized_enclosing_fields() {
        let oversized_message = serde_json::json!({
            "cel_program": {"expression": "true"},
            "message": "m".repeat(super::MAX_CEL_MESSAGE_BYTES + 1)
        });
        assert!(serde_json::from_value::<JwtCelRole>(oversized_message).is_err());

        let oversized_audiences = serde_json::json!({
            "cel_program": {"expression": "true"},
            "bound_audiences": (0..=super::MAX_CEL_AUDIENCES)
                .map(|index| format!("audience-{index}"))
                .collect::<Vec<_>>()
        });
        assert!(serde_json::from_value::<JwtCelRole>(oversized_audiences).is_err());

        let mut request = JwtCelRoleRequest::new(
            JwtCelProgram::new("true").unwrap_or_else(|error| panic!("{error}")),
        )
        .acknowledge_claim_validation(
            JwtCelClaimValidationAcknowledgement::all_authorization_claims_are_constrained_in_cel(),
        );
        request.bound_audiences = (0..=super::MAX_CEL_AUDIENCES)
            .map(|index| format!("audience-{index}"))
            .collect();
        assert!(request.validate().is_err());
    }

    #[test]
    fn oidc_callback_requires_exactly_one_non_empty_credential() {
        let both = super::OidcCallbackRequest {
            state: "state".into(),
            code: Some(SecretString::from("code")),
            id_token: Some(SecretString::from("id-token")),
            client_nonce: None,
            error: None,
            error_description: None,
            error_uri: None,
        };
        assert!(both.validate().is_err());

        let empty_code =
            super::OidcCallbackRequest::with_code("state", SecretString::from(String::new()));
        assert!(empty_code.validate().is_err());

        let empty_token =
            super::OidcCallbackRequest::with_id_token("state", SecretString::from(String::new()));
        assert!(empty_token.validate().is_err());

        assert!(
            super::OidcCallbackRequest::with_code("state", SecretString::from("code"))
                .validate()
                .is_ok()
        );
        assert!(
            super::OidcCallbackRequest::with_provider_error("state", "access_denied")
                .validate()
                .is_ok()
        );
        assert!(
            super::OidcCallbackRequest::with_id_token("state", SecretString::from("id-token"))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn oidc_correlation_values_are_secret_redacted_and_bounded() {
        let auth = super::OidcAuthUrlRequest::new("https://app.example.com/callback")
            .with_client_nonce("auth-secret-nonce");
        let auth_debug = format!("{auth:?}");
        assert!(!auth_debug.contains("auth-secret-nonce"));
        let auth_json = serde_json::to_value(&auth).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(auth_json["client_nonce"], "auth-secret-nonce");

        let callback = super::OidcCallbackRequest::with_code(
            "callback-secret-state",
            SecretString::from("authorization-code"),
        )
        .with_client_nonce("callback-secret-nonce");
        let callback_debug = format!("{callback:?}");
        assert!(!callback_debug.contains("callback-secret-state"));
        assert!(!callback_debug.contains("callback-secret-nonce"));
        assert!(!callback_debug.contains("authorization-code"));

        let poll =
            super::OidcPollRequest::new("poll-secret-state").with_client_nonce("poll-secret-nonce");
        let poll_debug = format!("{poll:?}");
        assert!(!poll_debug.contains("poll-secret-state"));
        assert!(!poll_debug.contains("poll-secret-nonce"));
        let poll_json = serde_json::to_value(&poll).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(poll_json["state"], "poll-secret-state");
        assert_eq!(poll_json["client_nonce"], "poll-secret-nonce");

        assert!(
            super::OidcCallbackRequest::with_code(
                "s".repeat(super::MAX_OIDC_STATE_BYTES + 1),
                SecretString::from("code"),
            )
            .validate()
            .is_err()
        );
        assert!(
            super::OidcCallbackRequest::with_code(
                "state",
                SecretString::from("c".repeat(super::MAX_OIDC_CREDENTIAL_BYTES + 1)),
            )
            .validate()
            .is_err()
        );
        assert!(
            super::OidcPollRequest::new("state")
                .with_client_nonce("n".repeat(super::MAX_OIDC_NONCE_BYTES + 1))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn jwt_login_metadata_redacts_oauth_values() {
        let metadata: super::JwtLoginMetadata = serde_json::from_value(serde_json::json!({
            "accessor": "accessor-secret-value",
            "policies": ["default"],
            "lease_duration": 60,
            "renewable": true,
            "metadata": {
                "access_token": "oauth-access-token",
                "refresh_token": "oauth-refresh-token"
            }
        }))
        .unwrap_or_else(|error| panic!("{error}"));
        let debug = format!("{metadata:?}");

        assert_eq!(
            metadata.metadata["access_token"].expose_secret(),
            "oauth-access-token"
        );
        assert!(debug.contains("metadata_entry_count"));
        assert!(!debug.contains("oauth-access-token"));
        assert!(!debug.contains("oauth-refresh-token"));
        assert!(!debug.contains("accessor-secret-value"));
    }

    #[test]
    fn jwt_login_metadata_map_is_bounded() {
        let metadata = (0..=crate::MAX_RESPONSE_STRINGS)
            .map(|index| (format!("key-{index}"), serde_json::json!("secret")))
            .collect::<serde_json::Map<_, _>>();
        let result = serde_json::from_value::<super::JwtLoginMetadata>(serde_json::json!({
            "accessor": "accessor",
            "metadata": metadata
        }));

        assert!(result.is_err());
    }

    #[test]
    fn jwt_leeway_requires_explicit_disable_variant() {
        let role = JwtRole {
            clock_skew_leeway: Some(JwtLeeway::seconds(60)),
            expiration_leeway: Some(JwtLeeway::duration("150s")),
            not_before_leeway: Some(JwtLeeway::DisableTimeValidation),
            ..Default::default()
        };
        let json = serde_json::to_string(&role).unwrap_or_else(|error| panic!("{error}"));
        assert!(json.contains(r#""clock_skew_leeway":60"#));
        assert!(json.contains(r#""expiration_leeway":"150s""#));
        assert!(json.contains(r#""not_before_leeway":"-1""#));

        let decoded: JwtRole =
            serde_json::from_str(r#"{"expiration_leeway":-1}"#).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            decoded.expiration_leeway,
            Some(JwtLeeway::DisableTimeValidation)
        );
    }
}
