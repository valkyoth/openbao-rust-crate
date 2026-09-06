//! Real OpenBao integration flow.
//!
//! These tests are skipped unless `OPENBAO_INTEGRATION=1` is set. Use
//! `scripts/openbao_integration.sh` to select an exact locked release, start an
//! isolated local TLS instance, verify its version, initialize and unseal it,
//! and run this file.

#![cfg(all(feature = "kv1", feature = "kv2", feature = "sys", feature = "token"))]
#![allow(clippy::panic, clippy::print_stderr)]

use std::{
    collections::BTreeMap,
    env, fs, io, process,
    time::{SystemTime, UNIX_EPOCH},
};

use openbao::{Client, OpenBaoCompatibilityPolicy, OpenBaoConfig, OpenBaoVersion};
#[cfg(feature = "operator-ops")]
use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa, sign::Signer};
use reqwest::Certificate;
#[cfg(any(
    all(feature = "operator-ops", feature = "unauthenticated-workflows"),
    all(feature = "transit", feature = "transit-bytes")
))]
use reqwest::StatusCode;
#[cfg(all(feature = "transit", feature = "transit-bytes"))]
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Deserialize, Serialize)]
struct SecretPayload {
    value: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct WrappedPayload {
    value: String,
}

struct IntegrationEnv {
    addr: String,
    token: SecretString,
    ca_cert: Certificate,
    expected_version: String,
    result_file: String,
}

impl IntegrationEnv {
    fn load() -> Result<Option<Self>, Box<dyn std::error::Error>> {
        if env::var("OPENBAO_INTEGRATION").ok().as_deref() != Some("1") {
            return Ok(None);
        }

        let addr = env::var("BAO_ADDR")?;
        let token = fs::read_to_string(env::var("BAO_TOKEN_FILE")?)?;
        let ca_path = env::var("BAO_CACERT")?;
        let ca_pem = fs::read(ca_path)?;
        let expected_version = env::var("OPENBAO_EXPECTED_VERSION")?;
        let result_file = env::var("OPENBAO_RESULT_FILE")?;

        Ok(Some(Self {
            addr,
            token: SecretString::from(token.trim().to_owned()),
            ca_cert: Certificate::from_pem(&ca_pem)?,
            expected_version,
            result_file,
        }))
    }

    fn clients(
        self,
    ) -> Result<
        (
            openbao::Client<openbao::Authenticated>,
            openbao::Client<openbao::Unauthenticated>,
        ),
        openbao::Error,
    > {
        let version = self.expected_version.parse::<OpenBaoVersion>()?;
        let policy = OpenBaoCompatibilityPolicy::exact(version)?;
        let config = OpenBaoConfig::new(self.addr)?
            .only_root_certificates(vec![self.ca_cert])?
            .compatibility_policy(policy);
        let unauthenticated = Client::from_config(config.clone())?;
        let authenticated = Client::from_config(config)?.try_with_token(self.token)?;
        Ok((authenticated, unauthenticated))
    }
}

#[tokio::test]
async fn real_openbao_default_feature_flow() -> Result<(), Box<dyn std::error::Error>> {
    let Some(env) = IntegrationEnv::load()? else {
        return Ok(());
    };
    let expected_version = env.expected_version.clone();
    let result_file = env.result_file.clone();
    let (client, unauthenticated) = env.clients()?;
    #[cfg(not(feature = "operator-ops"))]
    let _ = &unauthenticated;
    eprintln!("OpenBao integration stage: health");
    assert_eq!(client.sys().health().await?.version, expected_version);
    let suffix = unique_suffix()?;
    let kv1_mount = format!("obrs-kv1-{suffix}");
    let kv2_mount = format!("obrs-kv2-{suffix}");
    let auth_mount = format!("obrs-auth-{suffix}");
    #[cfg(feature = "operator-ops")]
    let jwt_mount = format!("obrs-jwt-{suffix}");
    #[cfg(feature = "operator-ops")]
    let transit_mount = format!("obrs-transit-{suffix}");
    #[cfg(feature = "operator-ops")]
    let pki_mount = format!("obrs-pki-{suffix}");
    let policy_name = format!("obrs-policy-{suffix}");
    #[cfg(feature = "operator-ops")]
    let namespace = format!("obrs-ns-{suffix}");
    #[cfg(feature = "operator-ops")]
    let workflow = format!("obrs-flow-{suffix}");
    #[cfg(feature = "operator-ops")]
    let hashed_user = format!("obrs-user-{suffix}");

    let result = run_flow(&client, &kv1_mount, &kv2_mount, &auth_mount, &policy_name).await;
    #[cfg(feature = "operator-ops")]
    let latest_flow = OpenBao26Flow {
        kv1_mount: &kv1_mount,
        userpass_mount: &auth_mount,
        jwt_mount: &jwt_mount,
        transit_mount: &transit_mount,
        pki_mount: &pki_mount,
        namespace: &namespace,
        workflow: &workflow,
        hashed_user: &hashed_user,
        policy_name: &policy_name,
        expected_version: &expected_version,
    };
    #[cfg(feature = "operator-ops")]
    let latest_result = if result.is_ok() && is_openbao_2_6(&expected_version) {
        run_2_6_flow((&client, &unauthenticated), latest_flow).await
    } else {
        Ok(())
    };
    #[cfg(not(feature = "operator-ops"))]
    let latest_result: Result<(), Box<dyn std::error::Error>> = if is_openbao_2_6(&expected_version)
    {
        Err(io::Error::other("OpenBao 2.6 integration requires the operator-ops feature").into())
    } else {
        Ok(())
    };
    #[cfg(feature = "operator-ops")]
    if is_openbao_2_6(&expected_version) {
        cleanup_2_6_flow(&client, latest_flow).await?;
    }
    cleanup_flow(&client, &kv1_mount, &kv2_mount, &auth_mount, &policy_name).await?;
    result?;
    latest_result?;
    write_core_flow_attestation(&result_file, &expected_version)?;
    Ok(())
}

async fn cleanup_flow(
    client: &Client<openbao::Authenticated>,
    kv1_mount: &str,
    kv2_mount: &str,
    auth_mount: &str,
    policy_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = client.sys().disable_mount(kv1_mount).await;
    let _ = client.sys().disable_mount(kv2_mount).await;
    let _ = client.sys().disable_auth_method(auth_mount).await;
    let _ = client.sys().delete_policy(policy_name).await;

    let mounts = client.sys().list_mounts().await?;
    let auth_methods = client.sys().list_auth_methods().await?;
    let policies = client.sys().list_policies().await?;
    if mounts.contains_key(&format!("{kv1_mount}/"))
        || mounts.contains_key(&format!("{kv2_mount}/"))
        || auth_methods.contains_key(&format!("{auth_mount}/"))
        || policies.policies.iter().any(|policy| policy == policy_name)
    {
        return Err(io::Error::other("OpenBao integration resource cleanup failed").into());
    }
    Ok(())
}

const CORE_OPERATION_IDS: [&str; 14] = [
    "health",
    "mount-management",
    "kv1",
    "kv2",
    "policy",
    "token",
    "capabilities",
    "response-wrapping",
    "root-generation-routing",
    "sealable-namespace",
    "workflow",
    "jwt-cel",
    "userpass-password-hash",
    "changed-response-fields",
];

const OPENBAO_2_6_OPERATION_IDS: [&str; 6] = [
    "root-generation-routing",
    "sealable-namespace",
    "workflow",
    "jwt-cel",
    "userpass-password-hash",
    "changed-response-fields",
];

fn is_openbao_2_6(version: &str) -> bool {
    matches!(version, "2.6.0" | "2.6.1" | "2.6.2")
}

#[derive(Serialize)]
struct CoreFlowAttestation<'a> {
    schema: &'static str,
    version: &'a str,
    executed: Vec<&'static str>,
    skipped: Vec<&'static str>,
}

fn write_core_flow_attestation(
    result_file: &str,
    expected_version: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let is_2_6 = is_openbao_2_6(expected_version);
    let encoded = serde_json::to_vec(&CoreFlowAttestation {
        schema: "openbao-core-flow-attestation/v1",
        version: expected_version,
        executed: if is_2_6 {
            CORE_OPERATION_IDS.to_vec()
        } else {
            CORE_OPERATION_IDS[..8].to_vec()
        },
        skipped: if is_2_6 {
            Vec::new()
        } else {
            OPENBAO_2_6_OPERATION_IDS.to_vec()
        },
    })?;
    fs::write(result_file, encoded)?;
    Ok(())
}

#[cfg(feature = "operator-ops")]
#[derive(Clone, Copy)]
struct OpenBao26Flow<'a> {
    kv1_mount: &'a str,
    userpass_mount: &'a str,
    jwt_mount: &'a str,
    transit_mount: &'a str,
    pki_mount: &'a str,
    namespace: &'a str,
    workflow: &'a str,
    hashed_user: &'a str,
    policy_name: &'a str,
    expected_version: &'a str,
}

#[cfg(feature = "operator-ops")]
async fn run_2_6_flow(
    clients: (
        &Client<openbao::Authenticated>,
        &Client<openbao::Unauthenticated>,
    ),
    flow: OpenBao26Flow<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (client, unauthenticated) = clients;
    let OpenBao26Flow {
        kv1_mount,
        userpass_mount,
        jwt_mount,
        transit_mount,
        pki_mount,
        namespace,
        workflow,
        hashed_user,
        policy_name,
        expected_version,
    } = flow;
    eprintln!("OpenBao integration stage: root-generation-routing");
    assert!(!client.sys().operator_generate_root_status().await?.started);
    let started = client
        .sys()
        .operator_generate_root_start(&openbao::sys::OperatorTokenGenerationStartRequest::new())
        .await?;
    assert!(started.status.started);
    assert!(started.otp.is_some());
    client.sys().operator_generate_root_cancel().await?;
    assert!(!client.sys().operator_generate_root_status().await?.started);

    eprintln!("OpenBao integration stage: sealable-namespace");
    let creation = client
        .sys()
        .create_sealable_namespace(
            namespace,
            &openbao::sys::SealableNamespaceRequest::new(1, 1)?,
        )
        .await?;
    assert_eq!(creation.key_threshold, 1);
    let share = creation
        .key_shares
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::other("sealable namespace returned no unseal share"))?;
    if !client.sys().namespace_seal_status(namespace).await?.sealed {
        client.sys().seal_namespace(namespace).await?;
    }
    assert!(client.sys().namespace_seal_status(namespace).await?.sealed);
    assert!(
        !client
            .sys()
            .unseal_namespace(namespace, &share)
            .await?
            .sealed
    );

    eprintln!("OpenBao integration stage: workflow");
    let definition = openbao::sys::WorkflowWriteRequest::new(SecretString::from(format!(
        "flow \"read\" {{ request \"secret\" {{ operation = \"read\" path = \"{kv1_mount}/app/config\" }} }}"
    )))?;
    eprintln!("OpenBao integration stage: workflow-write");
    let stored = client.sys().write_workflow(workflow, &definition).await?;
    assert_eq!(stored.path, workflow);
    eprintln!("OpenBao integration stage: workflow-list");
    assert!(
        client
            .sys()
            .list_workflows()
            .await?
            .keys
            .iter()
            .any(|key| key == workflow)
    );
    eprintln!("OpenBao integration stage: workflow-execute");
    let _ = client
        .sys()
        .execute_workflow(workflow, &openbao::sys::WorkflowData::empty())
        .await?;

    #[cfg(feature = "unauthenticated-workflows")]
    if expected_version == "2.6.2" {
        eprintln!("OpenBao integration stage: workflow-unauthenticated-regression");
        let unauthenticated_name = format!("{workflow}-unauthed");
        let request = openbao::sys::WorkflowWriteRequest::new(SecretString::from(
            "flow \"check\" { request \"status\" { operation = \"read\" path = \"sys/seal-status\" } }",
        ))?
        .allow_unauthenticated(true);
        client
            .sys()
            .write_workflow(&unauthenticated_name, &request)
            .await?;
        let _ = unauthenticated
            .sys()
            .execute_unauthenticated_workflow(
                &unauthenticated_name,
                &openbao::sys::WorkflowData::empty(),
            )
            .await?;

        eprintln!("OpenBao integration stage: workflow-internal-operation-regression");
        let internal_name = format!("{workflow}-internal");
        let internal_user = format!("{hashed_user}-internal");
        let internal_password = format!("{hashed_user}-password");
        client
            .userpass_admin_at(userpass_mount)?
            .write_user(
                &internal_user,
                &openbao::auth::userpass::UserpassUserRequest::new(SecretString::from(
                    internal_password.clone(),
                )),
            )
            .await?;
        let _ = unauthenticated
            .userpass_at(userpass_mount)?
            .login(
                &internal_user,
                SecretString::from(internal_password.clone()),
            )
            .await?;
        let internal_definition = r#"
flow "authentication" {
  request "login" {
    operation = "alias-lookahead"
    path = "auth/INTEGRATION_MOUNT/login/INTEGRATION_USER"
    data = { password = "INTEGRATION_PASSWORD" }
  }
}
output {
  data = {
    token = {
      eval_type = "string"
      eval_source = "response"
      flow_name = "authentication"
      response_name = "login"
      field_selector = ["auth", "client_token"]
    }
  }
}
"#
        .replace("INTEGRATION_MOUNT", userpass_mount)
        .replace("INTEGRATION_USER", &internal_user)
        .replace("INTEGRATION_PASSWORD", &internal_password);
        let internal_request =
            openbao::sys::WorkflowWriteRequest::new(SecretString::from(internal_definition))?
                .allow_unauthenticated(true);
        client
            .sys()
            .write_workflow(&internal_name, &internal_request)
            .await?;
        let blocked = unauthenticated
            .sys()
            .execute_unauthenticated_workflow(&internal_name, &openbao::sys::WorkflowData::empty())
            .await;
        // OpenBao 2.6.2 maps the core's internal-operation rejection to HTTP 500
        // at the workflow boundary. Require that exact result after proving both
        // the unauthenticated workflow route and target login work independently.
        assert!(
            blocked
                .as_ref()
                .is_err_and(|error| error.status() == Some(StatusCode::INTERNAL_SERVER_ERROR)),
            "OpenBao 2.6.2 did not explicitly reject an unauthenticated internal workflow operation"
        );
    }

    eprintln!("OpenBao integration stage: jwt-cel");
    client
        .sys()
        .enable_auth_method(
            jwt_mount,
            &openbao::sys::AuthEnableRequest {
                backend_type: "jwt".to_owned(),
                description: Some("openbao crate 2.6 integration test".to_owned()),
                config: None,
                local: Some(true),
            },
        )
        .await?;
    let jwt = client.jwt_admin_at(jwt_mount)?;
    let (public_key, accepted_jwt, missing_audience_jwt) = signed_integration_jwts()?;
    eprintln!("OpenBao integration stage: jwt-cel-configure");
    jwt.configure(&openbao::auth::jwt::JwtConfig {
        jwt_validation_pubkeys: vec![public_key],
        bound_issuer: Some("openbao-rust-integration".to_owned()),
        jwt_supported_algs: vec!["RS256".to_owned()],
        ..openbao::auth::jwt::JwtConfig::default()
    })
    .await?;
    let role = openbao::auth::jwt::JwtCelRoleRequest::new(openbao::auth::jwt::JwtCelProgram::new(
        "claims.iss == 'openbao-rust-integration' && claims.sub == 'integration-client' && 'openbao-rust-integration' in claims.aud ? pb.Auth{display_name: 'integration-client'} : false",
    )?)
    .acknowledge_claim_validation(
        openbao::auth::jwt::JwtCelClaimValidationAcknowledgement::all_authorization_claims_are_constrained_in_cel(),
    );
    let mut role = role;
    role.bound_audiences = vec!["openbao-rust-integration".to_owned()];
    role.clock_skew_leeway = Some(openbao::auth::jwt::JwtLeeway::seconds(17));
    role.expiration_leeway = Some(openbao::auth::jwt::JwtLeeway::seconds(23));
    role.not_before_leeway = Some(openbao::auth::jwt::JwtLeeway::seconds(29));
    eprintln!("OpenBao integration stage: jwt-cel-write");
    assert_eq!(jwt.write_cel_role("service", &role).await?.name, "service");
    if matches!(expected_version, "2.6.1" | "2.6.2") {
        eprintln!("OpenBao integration stage: jwt-cel-patch-preservation");
        let patched = jwt
            .patch_cel_role_acknowledged(
                "service",
                &openbao::auth::jwt::JwtCelRolePatch {
                    message: Some("patched without dropping constraints".to_owned()),
                    ..openbao::auth::jwt::JwtCelRolePatch::default()
                },
                openbao::auth::jwt::JwtCelClaimValidationAcknowledgement::all_authorization_claims_are_constrained_in_cel(),
            )
            .await?;
        assert_eq!(
            patched.bound_audiences,
            ["openbao-rust-integration".to_owned()]
        );
        assert_eq!(
            patched.clock_skew_leeway,
            Some(openbao::auth::jwt::JwtLeeway::seconds(17))
        );
        assert_eq!(
            patched.expiration_leeway,
            Some(openbao::auth::jwt::JwtLeeway::seconds(23))
        );
        assert_eq!(
            patched.not_before_leeway,
            Some(openbao::auth::jwt::JwtLeeway::seconds(29))
        );
    }
    eprintln!("OpenBao integration stage: jwt-cel-read-list");
    assert_eq!(jwt.read_cel_role("service").await?.name, "service");
    assert!(
        jwt.list_cel_roles()
            .await?
            .keys
            .iter()
            .any(|name| name == "service")
    );
    eprintln!("OpenBao integration stage: jwt-cel-positive-login");
    let _ = unauthenticated
        .jwt_at(jwt_mount)?
        .login_cel(Some("service"), accepted_jwt)
        .await?;
    eprintln!("OpenBao integration stage: jwt-cel-missing-audience-login");
    let rejected = unauthenticated
        .jwt_at(jwt_mount)?
        .login_cel(Some("service"), missing_audience_jwt)
        .await;
    assert!(
        rejected
            .as_ref()
            .is_err_and(|error| error.is_bad_request() || error.is_permission_denied()),
        "JWT CEL login unexpectedly accepted a validly signed JWT without aud"
    );

    eprintln!("OpenBao integration stage: userpass-password-hash");
    let first_hash = openbao::auth::userpass::UserpassPasswordHash::bcrypt(SecretString::from(
        format!("$2b$10${}", "A".repeat(53)),
    ))?;
    let second_hash = openbao::auth::userpass::UserpassPasswordHash::bcrypt(SecretString::from(
        format!("$2b$10${}", "B".repeat(53)),
    ))?;
    let userpass = client.userpass_admin_at(userpass_mount)?;
    userpass
        .write_hashed_user(
            hashed_user,
            &openbao::auth::userpass::UserpassHashedUserRequest::new(first_hash),
        )
        .await?;
    let _ = userpass.read_user(hashed_user).await?;
    userpass
        .update_password_hash(hashed_user, &second_hash)
        .await?;

    if matches!(expected_version, "2.6.1" | "2.6.2") {
        eprintln!("OpenBao integration stage: acl-policy-patch-preservation");
        let before = client.sys().read_policy(policy_name).await?;
        client
            .sys()
            .patch_policy(
                policy_name,
                &openbao::sys::PolicyPatchRequest {
                    cas_required: Some(true),
                    ..openbao::sys::PolicyPatchRequest::new()
                },
            )
            .await?;
        let after = client.sys().read_policy(policy_name).await?;
        assert_eq!(after.rules, before.rules);
        assert!(after.cas_required);
    }

    #[cfg(all(feature = "transit", feature = "transit-bytes"))]
    if expected_version == "2.6.2" {
        eprintln!("OpenBao integration stage: transit-sensitive-buffer-regression");
        client
            .sys()
            .enable_mount(transit_mount, &kv_request("transit", BTreeMap::new()))
            .await?;
        let transit = client.transit(transit_mount)?;
        transit
            .create_key(
                "sensitive-buffer-regression",
                &openbao::secrets::transit::TransitCreateKeyRequest::default(),
            )
            .await?;
        transit.rotate_key("sensitive-buffer-regression").await?;
        let plaintext = b"openbao-transit-sensitive-buffer-regression";
        let associated_data = b"pawalyze-record-binding";
        let current = transit
            .encrypt(
                "sensitive-buffer-regression",
                &openbao::secrets::transit::TransitEncryptRequest::from_plaintext_bytes(plaintext)?
                    .with_associated_data_bytes(associated_data)?,
            )
            .await?;
        assert_eq!(current.key_version, Some(2));
        let mut encrypt_request =
            openbao::secrets::transit::TransitEncryptRequest::from_plaintext_bytes(plaintext)?
                .with_associated_data_bytes(associated_data)?;
        encrypt_request.key_version = Some(1);
        let encrypted = transit
            .encrypt("sensitive-buffer-regression", &encrypt_request)
            .await?;
        assert_eq!(encrypted.key_version, Some(1));
        let decrypted = transit
            .decrypt(
                "sensitive-buffer-regression",
                &openbao::secrets::transit::TransitDecryptRequest::new(
                    encrypted.ciphertext.clone(),
                )
                .with_associated_data_bytes(associated_data)?,
            )
            .await?;
        let decoded = decrypted.plaintext_bytes()?;
        decoded.with_secret(|bytes| assert_eq!(bytes, plaintext));

        let ciphertext = encrypted.ciphertext.expose_secret();
        let payload_start = ciphertext
            .rfind(':')
            .map(|index| index + 1)
            .ok_or("Transit ciphertext did not contain a payload separator")?;
        let mut tampered_ciphertext = ciphertext.as_bytes().to_vec();
        let original = tampered_ciphertext
            .get_mut(payload_start)
            .ok_or("Transit ciphertext payload was empty")?;
        *original = if *original == b'A' { b'B' } else { b'A' };
        let tampered_ciphertext = String::from_utf8(tampered_ciphertext)?;
        let tampered = transit
            .decrypt(
                "sensitive-buffer-regression",
                &openbao::secrets::transit::TransitDecryptRequest::new(SecretString::from(
                    tampered_ciphertext,
                ))
                .with_associated_data_bytes(associated_data)?,
            )
            .await;
        assert!(matches!(
            tampered,
            Err(openbao::Error::Api { status, .. }) if status == StatusCode::BAD_REQUEST
        ));
        let wrong_associated_data = transit
            .decrypt(
                "sensitive-buffer-regression",
                &openbao::secrets::transit::TransitDecryptRequest::new(
                    encrypted.ciphertext.clone(),
                )
                .with_associated_data_bytes(b"wrong-record-binding")?,
            )
            .await;
        assert!(matches!(
            wrong_associated_data,
            Err(openbao::Error::Api { status, .. }) if status == StatusCode::BAD_REQUEST
        ));
        let valid_after_rejections = transit
            .decrypt(
                "sensitive-buffer-regression",
                &openbao::secrets::transit::TransitDecryptRequest::new(encrypted.ciphertext)
                    .with_associated_data_bytes(associated_data)?,
            )
            .await?;
        valid_after_rejections
            .plaintext_bytes()?
            .with_secret(|bytes| assert_eq!(bytes, plaintext));

        eprintln!("OpenBao integration stage: transit-non-default-hmac-regression");
        transit
            .create_key(
                "hmac-regression",
                &openbao::secrets::transit::TransitCreateKeyRequest::default(),
            )
            .await?;
        let input = b"openbao-2.6.2-hmac-regression";
        let generated = transit
            .hmac(
                "hmac-regression",
                Some(openbao::secrets::transit::TransitHashAlgorithm::Sha2_384),
                &openbao::secrets::transit::TransitHmacRequest::from_input_bytes(input)?,
            )
            .await?;
        let verification = transit
            .verify(
                "hmac-regression",
                Some(openbao::secrets::transit::TransitHashAlgorithm::Sha2_384),
                &openbao::secrets::transit::TransitVerifyRequest::from_input_bytes_with_hmac(
                    input,
                    generated.hmac,
                )?,
            )
            .await?;
        assert!(
            verification.valid,
            "OpenBao 2.6.2 rejected a valid SHA2-384 Transit HMAC"
        );
    }

    #[cfg(feature = "pki")]
    if expected_version == "2.6.2" {
        eprintln!("OpenBao integration stage: pki-csr-ip-san-cidr-regression");
        client
            .sys()
            .enable_mount(pki_mount, &kv_request("pki", BTreeMap::new()))
            .await?;
        let pki = client.pki(pki_mount)?;
        pki.generate_root(
            openbao::secrets::pki::PkiKeyGenerationType::Internal,
            &openbao::secrets::pki::PkiGenerateRootRequest {
                common_name: "OpenBao 2.6.2 integration root".to_owned(),
                ..openbao::secrets::pki::PkiGenerateRootRequest::default()
            },
        )
        .await?;
        pki.write_role(
            "cidr-regression",
            &openbao::secrets::pki::PkiRole {
                allow_any_name: Some(true),
                allow_ip_sans: Some(true),
                allowed_ip_sans_cidr: vec!["192.0.2.0/24".to_owned()],
                ..openbao::secrets::pki::PkiRole::default()
            },
        )
        .await?;
        let signing = pki
            .sign(
                "cidr-regression",
                &openbao::secrets::pki::PkiSignRequest {
                    csr: csr_with_ip_san("cidr-regression.example", "198.51.100.10")?,
                    ..openbao::secrets::pki::PkiSignRequest::default()
                },
            )
            .await;
        assert!(
            signing
                .as_ref()
                .is_err_and(|error| error.is_bad_request() || error.is_permission_denied()),
            "OpenBao 2.6.2 accepted a CSR IP SAN outside allowed_ip_sans_cidr"
        );
    }

    eprintln!("OpenBao integration stage: changed-response-fields");
    let seal = client.sys().seal_status_details().await?;
    assert_eq!(seal.status.version, expected_version);
    assert!(seal.commit_date.is_some());
    Ok(())
}

#[cfg(feature = "operator-ops")]
fn signed_integration_jwts()
-> Result<(String, SecretString, SecretString), Box<dyn std::error::Error>> {
    let rsa = Rsa::generate(2048)?;
    let public_key = String::from_utf8(rsa.public_key_to_pem()?)?;
    let signing_key = PKey::from_rsa(rsa)?;
    let accepted = sign_integration_jwt(&signing_key, true)?;
    let missing_audience = sign_integration_jwt(&signing_key, false)?;
    Ok((public_key, accepted, missing_audience))
}

#[cfg(all(feature = "operator-ops", feature = "pki"))]
fn csr_with_ip_san(common_name: &str, ip_san: &str) -> Result<String, Box<dyn std::error::Error>> {
    let signing_key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut subject = openssl::x509::X509Name::builder()?;
    subject.append_entry_by_text("CN", common_name)?;

    let mut request = openssl::x509::X509Req::builder()?;
    request.set_subject_name(&subject.build())?;
    request.set_pubkey(&signing_key)?;
    let mut extensions = openssl::stack::Stack::new()?;
    extensions.push(
        openssl::x509::extension::SubjectAlternativeName::new()
            .ip(ip_san)
            .build(&request.x509v3_context(None))?,
    )?;
    request.add_extensions(&extensions)?;
    request.sign(&signing_key, MessageDigest::sha256())?;
    Ok(String::from_utf8(request.build().to_pem()?)?)
}

#[cfg(feature = "operator-ops")]
fn sign_integration_jwt(
    signing_key: &PKey<openssl::pkey::Private>,
    include_audience: bool,
) -> Result<SecretString, Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut claims = serde_json::Map::from_iter([
        ("iss".to_owned(), json!("openbao-rust-integration")),
        ("sub".to_owned(), json!("integration-client")),
        ("iat".to_owned(), json!(now)),
        ("exp".to_owned(), json!(now.saturating_add(300))),
    ]);
    if include_audience {
        claims.insert("aud".to_owned(), json!(["openbao-rust-integration"]));
    }

    let encode = |bytes: &[u8]| {
        base64_ng::URL_SAFE_NO_PAD
            .encode_string(bytes)
            .map_err(|error| io::Error::other(format!("JWT base64 encoding failed: {error:?}")))
    };
    let header = encode(br#"{"alg":"RS256","typ":"JWT"}"#)?;
    let payload = encode(&serde_json::to_vec(&claims)?)?;
    let signing_input = format!("{header}.{payload}");
    let mut signer = Signer::new(MessageDigest::sha256(), signing_key)?;
    signer.update(signing_input.as_bytes())?;
    let signature = encode(&signer.sign_to_vec()?)?;
    Ok(SecretString::from(format!("{signing_input}.{signature}")))
}

#[cfg(feature = "operator-ops")]
async fn cleanup_2_6_flow(
    client: &Client<openbao::Authenticated>,
    flow: OpenBao26Flow<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let OpenBao26Flow {
        jwt_mount,
        transit_mount,
        pki_mount,
        namespace,
        workflow,
        userpass_mount,
        hashed_user,
        ..
    } = flow;
    let _ = client.sys().operator_generate_root_cancel().await;
    let _ = client.sys().delete_workflow(workflow).await;
    let _ = client
        .sys()
        .delete_workflow(&format!("{workflow}-unauthed"))
        .await;
    let _ = client
        .sys()
        .delete_workflow(&format!("{workflow}-internal"))
        .await;
    let _ = client
        .jwt_admin_at(jwt_mount)?
        .delete_cel_role("service")
        .await;
    let _ = client
        .userpass_admin_at(userpass_mount)?
        .delete_user(hashed_user)
        .await;
    let _ = client
        .userpass_admin_at(userpass_mount)?
        .delete_user(&format!("{hashed_user}-internal"))
        .await;
    let _ = client.sys().delete_namespace(namespace).await;
    if client
        .sys()
        .list_namespaces()
        .await?
        .keys
        .iter()
        .any(|path| path.trim_end_matches('/') == namespace)
    {
        let _ = client
            .sys()
            .delete_sealed_namespace(namespace, openbao::sys::SealedNamespaceDeletion::confirm())
            .await;
    }
    let _ = client.sys().disable_auth_method(jwt_mount).await;
    let _ = client.sys().disable_mount(transit_mount).await;
    let _ = client.sys().disable_mount(pki_mount).await;
    Ok(())
}

async fn run_flow(
    client: &openbao::Client<openbao::Authenticated>,
    kv1_mount: &str,
    kv2_mount: &str,
    auth_mount: &str,
    policy_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("OpenBao integration stage: health");
    let seal = client.sys().seal_status().await?;
    assert!(seal.initialized);
    assert!(!seal.sealed);

    eprintln!("OpenBao integration stage: mount-management");
    client
        .sys()
        .enable_mount(kv1_mount, &kv_request("kv", BTreeMap::new()))
        .await?;

    let mut kv2_options = BTreeMap::new();
    kv2_options.insert("version".to_owned(), "2".to_owned());
    client
        .sys()
        .enable_mount(kv2_mount, &kv_request("kv", kv2_options))
        .await?;

    let mounts = client.sys().list_mounts().await?;
    assert!(mounts.contains_key(&format!("{kv1_mount}/")));
    assert!(mounts.contains_key(&format!("{kv2_mount}/")));
    assert_eq!(client.sys().read_mount(kv2_mount).await?.backend_type, "kv");

    client
        .sys()
        .enable_auth_method(
            auth_mount,
            &openbao::sys::AuthEnableRequest {
                backend_type: "userpass".to_owned(),
                description: Some("openbao crate integration test".to_owned()),
                config: None,
                local: Some(true),
            },
        )
        .await?;
    let auth_methods = client.sys().list_auth_methods().await?;
    assert!(auth_methods.contains_key(&format!("{auth_mount}/")));
    let auth_tune = client.sys().read_auth_tune(auth_mount).await?;
    client
        .sys()
        .tune_auth_method(auth_mount, &auth_tune)
        .await?;

    eprintln!("OpenBao integration stage: kv1");
    let kv1 = client.kv1(kv1_mount)?;
    kv1.write(
        "app/config",
        SecretPayload {
            value: "kv1".to_owned(),
        },
    )
    .await?;
    let kv1_read: SecretPayload = kv1.read("app/config").await?;
    assert_eq!(kv1_read.value, "kv1");
    assert!(
        kv1.list("app")
            .await?
            .keys
            .iter()
            .any(|key| key == "config")
    );

    eprintln!("OpenBao integration stage: kv2");
    let kv2 = client.kv2(kv2_mount)?;
    eprintln!("OpenBao integration stage: kv2-write");
    assert_eq!(
        kv2.write("app/config", json!({ "value": "one" }))
            .await?
            .version,
        1
    );
    eprintln!("OpenBao integration stage: kv2-patch");
    assert_eq!(
        kv2.patch("app/config", json!({ "extra": "two" }))
            .await?
            .version,
        2
    );
    eprintln!("OpenBao integration stage: kv2-read");
    let kv2_read = kv2.read::<BTreeMap<String, Value>>("app/config").await?;
    assert_eq!(
        kv2_read.data.get("value").and_then(Value::as_str),
        Some("one")
    );
    assert_eq!(
        kv2_read.data.get("extra").and_then(Value::as_str),
        Some("two")
    );
    eprintln!("OpenBao integration stage: kv2-metadata");
    assert_eq!(kv2.metadata("app/config").await?.current_version, 2);
    eprintln!("OpenBao integration stage: kv2-config");
    assert!(kv2.config().await?.max_versions.is_some());

    eprintln!("OpenBao integration stage: token");
    let token_info = client.token().lookup_self().await?;
    assert!(token_info.policies.iter().any(|policy| policy == "root"));

    eprintln!("OpenBao integration stage: policy");
    let capability_path = format!("{kv2_mount}/data/app/config");
    client
        .sys()
        .write_policy(
            policy_name,
            &openbao::sys::PolicyWriteRequest {
                policy: format!("path \"{capability_path}\" {{ capabilities = [\"read\"] }}"),
                expiration: None,
                ttl: None,
                cas: None,
                cas_required: None,
            },
        )
        .await?;
    assert!(
        client
            .sys()
            .list_policies()
            .await?
            .policies
            .iter()
            .any(|policy| policy == policy_name)
    );
    assert!(
        client
            .sys()
            .read_policy(policy_name)
            .await?
            .rules
            .contains(&capability_path)
    );

    eprintln!("OpenBao integration stage: capabilities");
    let self_capabilities = client
        .sys()
        .capabilities_self([capability_path.clone()])
        .await?;
    assert!(
        self_capabilities
            .by_path
            .get(&capability_path)
            .is_some_and(|capabilities| capabilities.iter().any(|capability| capability == "root"))
    );

    let child_token = client
        .token()
        .create(&openbao::auth::token::TokenCreateRequest {
            policies: vec![policy_name.to_owned()],
            ttl: Some("60s".to_owned()),
            renewable: Some(false),
            no_default_policy: Some(true),
            ..Default::default()
        })
        .await?;
    let token_capabilities = client
        .sys()
        .capabilities(&child_token.client_token, [capability_path.clone()])
        .await?;
    assert!(
        token_capabilities
            .by_path
            .get(&capability_path)
            .is_some_and(|capabilities| capabilities.iter().any(|capability| capability == "read"))
    );
    let accessor_capabilities = client
        .sys()
        .capabilities_accessor(&child_token.accessor, [capability_path.clone()])
        .await?;
    assert!(
        accessor_capabilities
            .by_path
            .get(&capability_path)
            .is_some_and(|capabilities| capabilities.iter().any(|capability| capability == "read"))
    );
    client.token().revoke(&child_token.client_token).await?;

    eprintln!("OpenBao integration stage: response-wrapping");
    let wrap_info = client
        .sys()
        .wrapping_wrap(
            "60s",
            &WrappedPayload {
                value: "wrapped".to_owned(),
            },
        )
        .await?;
    assert_eq!(wrap_info.ttl, 60);
    let lookup = client.sys().wrapping_lookup(&wrap_info.token).await?;
    assert_eq!(lookup.creation_ttl, 60);
    let unwrapped: WrappedPayload = client.sys().wrapping_unwrap(Some(&wrap_info.token)).await?;
    assert_eq!(unwrapped.value, "wrapped");

    Ok(())
}

fn kv_request(
    backend_type: &str,
    options: BTreeMap<String, String>,
) -> openbao::sys::MountEnableRequest {
    openbao::sys::MountEnableRequest {
        backend_type: backend_type.to_owned(),
        description: Some("openbao crate integration test".to_owned()),
        config: None,
        options,
        local: Some(true),
        seal_wrap: None,
        external_entropy_access: None,
    }
}

fn unique_suffix() -> Result<String, Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(format!("{}-{nanos}", process::id()))
}
