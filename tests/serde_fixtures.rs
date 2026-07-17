#![cfg(all(
    feature = "identity",
    feature = "kv2",
    feature = "pki",
    feature = "ssh",
    feature = "sys",
    feature = "token",
    feature = "totp"
))]
#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::error::Error;
use std::io;

use openbao::auth::token::TokenAuth;
use openbao::secrets::identity::IdentityEntityInfo;
use openbao::secrets::kv2::Kv2Secret;
use openbao::secrets::pki::PkiCertificateBundle;
use openbao::secrets::pki::PkiRole;
use openbao::secrets::ssh::SshRoleKeyType;
use openbao::secrets::totp::{TotpCode, TotpPeriod};
#[cfg(feature = "operator-ops")]
use openbao::sys::SealableNamespaceCreation;
use openbao::sys::{
    CorsConfig, Health, LeaseLookup, NamespaceSealStatus, PluginInfo, PolicyInfo, PolicyList,
    RateLimitQuotaInfo, RateLimitQuotaList, SealStatus, UnsealStatus, VersionHistoryEntry,
};
use openbao::{ExposeSecret, ResponseEnvelope, SecretString};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FixtureSecret {
    username: String,
    password: SecretString,
}

#[derive(Debug, Deserialize)]
struct TokenAuthFixture {
    auth: Option<TokenAuth>,
}

#[derive(Debug, Deserialize)]
struct VersionedResponseFixtures {
    schema: String,
    snapshot_lock_sha256: String,
    profiles: Vec<VersionedResponseProfile>,
}

#[derive(Debug, Deserialize)]
struct VersionedResponseProfile {
    version: String,
    openapi_sha256: String,
    pki_certificate: serde_json::Value,
    pki_role: serde_json::Value,
    plugin: serde_json::Value,
    policy: serde_json::Value,
    quota: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct OpenBao26SystemFixtures {
    seal_2_5_5: serde_json::Value,
    seal_2_6_0: serde_json::Value,
    unseal_2_5_5: serde_json::Value,
    unseal_2_6_0: serde_json::Value,
    lease_2_5_5: serde_json::Value,
    lease_2_6_0: serde_json::Value,
    cors_2_5_5: serde_json::Value,
    cors_2_6_0: serde_json::Value,
    totp_2_5_5: serde_json::Value,
    totp_2_6_0: serde_json::Value,
    version_2_5_5: serde_json::Value,
    version_2_6_0: serde_json::Value,
    #[cfg(feature = "operator-ops")]
    namespace_creation_2_6_0: serde_json::Value,
    namespace_seal_status_2_6_0: serde_json::Value,
}

#[test]
fn public_response_fixtures_deserialize() -> Result<(), Box<dyn Error>> {
    let health: Health = serde_json::from_str(include_str!("fixtures/health.json"))?;
    assert!(health.initialized);
    assert!(!health.sealed);
    assert_eq!(health.version, "2.5.5");

    let kv2: ResponseEnvelope<Kv2Secret<FixtureSecret>> =
        serde_json::from_str(include_str!("fixtures/kv2_read.json"))?;
    assert_eq!(kv2.data.data.username, "app");
    assert_eq!(kv2.data.data.password.expose_secret(), "fixture-password");
    assert_eq!(kv2.data.metadata.version, 3);
    assert_eq!(
        kv2.warnings
            .as_ref()
            .ok_or_else(|| io::Error::other("warning should exist"))?
            .as_slice(),
        ["fixture warning"]
    );

    let pki: ResponseEnvelope<PkiCertificateBundle> =
        serde_json::from_str(include_str!("fixtures/pki_issue.json"))?;
    assert_eq!(pki.lease_duration, 3600);
    assert!(pki.data.private_key.is_some());
    assert_eq!(pki.data.serial_number.as_deref(), Some("01:02:03"));

    let identity: ResponseEnvelope<IdentityEntityInfo> =
        serde_json::from_str(include_str!("fixtures/identity_entity.json"))?;
    assert_eq!(identity.data.id, "entity-fixture-id");
    assert_eq!(identity.data.name.as_deref(), Some("payments-service"));
    assert_eq!(
        identity.data.metadata.get("owner").map(String::as_str),
        Some("platform")
    );

    let token: TokenAuthFixture = serde_json::from_str(include_str!("fixtures/token_auth.json"))?;
    let auth = token
        .auth
        .ok_or_else(|| io::Error::other("fixture should contain auth"))?;
    assert_eq!(auth.client_token.expose_secret(), "bao-token-fixture");
    assert_eq!(auth.accessor.expose_secret(), "bao-accessor-fixture");
    assert_eq!(
        auth.metadata,
        BTreeMap::from([("role".to_owned(), "fixture".to_owned())])
    );
    assert!(auth.renewable);
    Ok(())
}

#[test]
fn locked_openbao_response_profiles_deserialize() -> Result<(), Box<dyn Error>> {
    let fixtures: VersionedResponseFixtures =
        serde_json::from_str(include_str!("fixtures/openbao_response_profiles.json"))?;
    assert_eq!(fixtures.schema, "openbao-versioned-response-fixtures/v1");
    assert_eq!(fixtures.snapshot_lock_sha256.len(), 64);
    assert_eq!(fixtures.profiles.len(), 21);

    for (index, fixture) in fixtures.profiles.into_iter().enumerate() {
        assert_eq!(fixture.openapi_sha256.len(), 64);

        let certificate: PkiCertificateBundle = serde_json::from_value(fixture.pki_certificate)?;
        assert_eq!(certificate.not_before.is_some(), index >= 4);
        let certificate_debug = format!("{certificate:?}");
        assert!(!certificate_debug.contains("fixture-private-key"));

        let role: PkiRole = serde_json::from_value(fixture.pki_role)?;
        assert_eq!(role.ttl.as_deref(), Some("3600"));
        assert_eq!(role.max_ttl.as_deref(), Some("7200"));
        assert_eq!(role.not_before_duration.as_deref(), Some("30"));
        assert_eq!(!role.allowed_ip_sans_cidr.is_empty(), index >= 15);

        let policy: PolicyInfo = serde_json::from_value(fixture.policy)?;
        assert!(!policy.rules.is_empty());
        assert_eq!(policy.version.is_some(), index >= 9);

        let quota: RateLimitQuotaInfo = serde_json::from_value(fixture.quota)?;
        assert_eq!(quota.inheritable, (index >= 9).then_some(true));

        let plugin: PluginInfo = serde_json::from_value(fixture.plugin)?;
        assert_eq!(plugin.declarative, (index >= 15).then_some(true));
        assert_eq!(plugin.oci, (index >= 15).then_some(true));
        let plugin_debug = format!("{plugin:?}");
        assert!(!plugin_debug.contains("fixture-secret-argument"));
        assert!(!plugin_debug.contains("FIXTURE_SECRET=value"));

        assert!(fixture.version.starts_with("2."));
    }
    Ok(())
}

#[test]
fn openbao_2_6_system_contract_fixtures_preserve_old_responses() -> Result<(), Box<dyn Error>> {
    let fixtures: OpenBao26SystemFixtures =
        serde_json::from_str(include_str!("fixtures/openbao_2_6_system_responses.json"))?;

    let old_seal: SealStatus = serde_json::from_value(fixtures.seal_2_5_5)?;
    let new_seal: SealStatus = serde_json::from_value(fixtures.seal_2_6_0)?;
    assert!(old_seal.build_date.is_some());
    assert!(old_seal.commit_date.is_none());
    assert_eq!(new_seal.recovery_seal_type.as_deref(), Some("shamir"));
    assert!(new_seal.commit_date.is_some());

    let old_unseal: UnsealStatus = serde_json::from_value(fixtures.unseal_2_5_5)?;
    let new_unseal: UnsealStatus = serde_json::from_value(fixtures.unseal_2_6_0)?;
    assert!(old_unseal.build_date.is_some());
    assert!(new_unseal.commit_date.is_some());

    let old_lease: LeaseLookup = serde_json::from_value(fixtures.lease_2_5_5)?;
    let new_lease: LeaseLookup = serde_json::from_value(fixtures.lease_2_6_0)?;
    assert!(old_lease.namespace_path.is_none());
    assert_eq!(new_lease.namespace_path.as_deref(), Some("team/payments/"));
    assert!(!format!("{new_lease:?}").contains("current-lease"));

    let old_cors: CorsConfig = serde_json::from_value(fixtures.cors_2_5_5)?;
    let new_cors: CorsConfig = serde_json::from_value(fixtures.cors_2_6_0)?;
    assert!(!old_cors.allow_credentials);
    assert!(new_cors.allow_credentials);

    let old_totp: TotpCode = serde_json::from_value(fixtures.totp_2_5_5)?;
    let new_totp: TotpCode = serde_json::from_value(fixtures.totp_2_6_0)?;
    assert!(old_totp.generated.is_none());
    assert_eq!(
        new_totp.period,
        Some(TotpPeriod::Duration("30s".to_owned()))
    );
    assert!(!format!("{new_totp:?}").contains("654321"));

    let old_version: VersionHistoryEntry = serde_json::from_value(fixtures.version_2_5_5)?;
    let new_version: VersionHistoryEntry = serde_json::from_value(fixtures.version_2_6_0)?;
    assert!(old_version.build_date.is_some());
    assert!(new_version.commit_date.is_some());

    let namespace_status: NamespaceSealStatus =
        serde_json::from_value(fixtures.namespace_seal_status_2_6_0)?;
    assert!(namespace_status.sealed);
    assert_eq!(namespace_status.progress, 1);

    #[cfg(feature = "operator-ops")]
    {
        let namespace: SealableNamespaceCreation =
            serde_json::from_value(fixtures.namespace_creation_2_6_0)?;
        assert_eq!(namespace.key_shares.len(), 3);
        assert_eq!(
            namespace.key_shares[0].expose_secret(),
            "fixture-namespace-share-one"
        );
        assert!(!format!("{namespace:?}").contains("fixture-namespace-share-one"));
    }
    Ok(())
}

#[test]
fn response_aliases_have_reviewed_precedence_and_maps_reject_duplicates()
-> Result<(), Box<dyn Error>> {
    let policy: PolicyInfo =
        serde_json::from_str(r#"{"name":"fixture","rules":"current","policy":"legacy"}"#)?;
    assert_eq!(policy.rules, "current");
    let policies: PolicyList =
        serde_json::from_str(r#"{"policies":["current"],"keys":["legacy"]}"#)?;
    assert_eq!(policies.policies, ["current"]);
    assert!(
        serde_json::from_str::<RateLimitQuotaList>(
            r#"{"key_info":{"duplicate":{},"duplicate":{}}}"#
        )
        .is_err()
    );
    assert!(serde_json::from_str::<SshRoleKeyType>(r#""future-role-type""#).is_err());
    Ok(())
}
