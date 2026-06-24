#![cfg(all(
    feature = "identity",
    feature = "kv2",
    feature = "pki",
    feature = "sys",
    feature = "token"
))]
#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::error::Error;
use std::io;

use openbao::auth::token::TokenAuth;
use openbao::secrets::identity::IdentityEntityInfo;
use openbao::secrets::kv2::Kv2Secret;
use openbao::secrets::pki::PkiCertificateBundle;
use openbao::sys::Health;
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
