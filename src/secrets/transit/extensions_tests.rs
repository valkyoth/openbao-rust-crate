#![allow(clippy::panic)]

use super::*;
use serde_json::{Value, json};

fn ok<T>(result: Result<T>) -> T {
    result.unwrap_or_else(|_| panic!("valid synthetic fixture rejected"))
}

fn wire(value: &impl Serialize) -> Value {
    serde_json::to_value(value).unwrap_or_else(|_| panic!("fixture serialization failed"))
}

fn secret() -> SecretString {
    SecretString::from(["synthetic-", "sensitive-marker"].concat())
}

fn mu() -> SecretString {
    encoded(&[42; 64])
}

fn encoded(bytes: &[u8]) -> SecretString {
    let encoded = base64_ng::STANDARD
        .encode_secret(bytes)
        .unwrap_or_else(|_| panic!("base64 fixture failed"));
    let exposed = encoded
        .try_into_exposed_string()
        .unwrap_or_else(|_| panic!("base64 fixture is not UTF-8"));
    SecretString::from(exposed.into_exposed_unprotected_string_caller_must_zeroize())
}

#[test]
fn create_options_cover_all_parameter_sets_without_changing_legacy_types() {
    for (parameters, name) in [
        (MldsaParameterSet::MlDsa44, "mldsa-44"),
        (MldsaParameterSet::MlDsa65, "mldsa-65"),
        (MldsaParameterSet::MlDsa87, "mldsa-87"),
    ] {
        let request = TransitMldsaCreateRequest::new(parameters);
        assert_eq!(
            wire(&request),
            json!({"type":name,"exportable":false,"allow_plaintext_backup":false})
        );
        let request = ok(request
            .exportable()
            .allow_plaintext_backup()
            .with_auto_rotate_period("24h"));
        assert_eq!(wire(&request)["auto_rotate_period"], "24h");
        assert_eq!(wire(&request)["exportable"], true);
        assert_eq!(wire(&request)["allow_plaintext_backup"], true);
    }
    assert!(
        TransitMldsaCreateRequest::new(MldsaParameterSet::MlDsa44)
            .with_auto_rotate_period("bad")
            .is_err()
    );
    assert_eq!(wire(&TransitCreateKeyRequest::default()), json!({}));
}

#[test]
fn external_references_and_hmac_bounds_are_explicit() {
    let reference = ok(TransitExternalKeyReference::new("config.v1", "_key-1"));
    assert_eq!(reference.as_str(), "config.v1:_key-1");
    let request = TransitExternalKeyCreateRequest::new(reference);
    assert_eq!(
        wire(&request),
        json!({"type":"external-key","external_key_ref":"config.v1:_key-1"})
    );
    for bytes in [32, 512] {
        assert_eq!(
            wire(&ok(request.clone().with_hmac_key_size(bytes)))["key_size"],
            bytes
        );
    }
    for bytes in [0, 31, 513, u16::MAX] {
        assert!(request.clone().with_hmac_key_size(bytes).is_err());
    }
    for name in [
        "", "x:y", "../x", "/x", "x/", "x/y", "x%2f", "x?y", "x#y", "x\n", "x!y", "-x", "x-", ".x",
        "x.", "x\u{e9}",
    ] {
        assert!(TransitExternalKeyReference::new(name, "key").is_err());
        assert!(TransitExternalKeyReference::new("config", name).is_err());
    }
    assert!(TransitExternalKeyReference::new(&"a".repeat(256), "_").is_ok());
    assert!(TransitExternalKeyReference::new(&"a".repeat(257), "_").is_err());
}

#[test]
fn mldsa_import_is_secret_aware_and_has_no_derivation_or_external_type() {
    let request = ok(TransitMldsaImportRequest::new(
        MldsaParameterSet::MlDsa87,
        secret(),
    ))
    .with_hash_function(TransitImportHashFunction::Sha256)
    .allow_rotation()
    .exportable()
    .allow_plaintext_backup();
    let request = ok(request.with_auto_rotate_period("24h"));
    let value = wire(&request);
    assert_eq!(value["type"], "mldsa-87");
    assert_eq!(value["hash_function"], "SHA256");
    assert_eq!(value["allow_rotation"], true);
    assert!(value["ciphertext"].as_str() == Some(secret().expose_secret()));
    assert!(value.get("derived").is_none());
    assert!(value.get("public_key").is_none());
    assert!(!format!("{request:?}").contains(secret().expose_secret()));
    assert!(crate::client::encode_bounded_json(&request, 1).is_err());
    let public = ok(TransitMldsaImportRequest::from_public_key(
        MldsaParameterSet::MlDsa44,
        "synthetic-public-key",
    ));
    assert!(wire(&public).get("ciphertext").is_none());
    assert_eq!(wire(&public)["public_key"], "synthetic-public-key");
    assert!(
        TransitMldsaImportRequest::new(MldsaParameterSet::MlDsa44, SecretString::from("")).is_err()
    );
    assert!(TransitMldsaImportRequest::from_public_key(MldsaParameterSet::MlDsa44, "").is_err());
}

#[test]
fn external_mu_requires_exact_canonical_base64_and_64_bytes() {
    let request = ok(TransitMldsaSignRequest::new(
        mu(),
        TransitMldsaSignMode::ExternalMu,
    ));
    let request = ok(request.with_key_version(2));
    let value = wire(&sign_payload(&request));
    assert_eq!(value["hash_algorithm"], "mldsa-mu");
    assert_eq!(value["prehashed"], true);
    assert_eq!(value["key_version"], 2);
    assert!(value["input"].as_str() == Some(mu().expose_secret()));
    assert!(!format!("{request:?}").contains(mu().expose_secret()));
    for len in [0, 63, 65, 66, 128] {
        assert!(
            TransitMldsaSignRequest::new(encoded(&vec![42; len]), TransitMldsaSignMode::ExternalMu)
                .is_err()
        );
    }
    for invalid in [
        "%".repeat(88),
        "A".repeat(88),
        format!("{}B==", "A".repeat(85)),
        format!("{}\n", mu().expose_secret()),
    ] {
        let result = TransitMldsaSignRequest::new(
            SecretString::from(invalid.clone()),
            TransitMldsaSignMode::ExternalMu,
        );
        let error = result
            .err()
            .unwrap_or_else(|| panic!("invalid mu accepted"));
        assert!(!format!("{error:?} {error}").contains(&invalid));
    }
    for version in [0, i32::MAX as u64 + 1, u64::MAX] {
        assert!(request.clone().with_key_version(version).is_err());
    }
    assert!(request.with_key_version(i32::MAX as u64).is_ok());
}

#[test]
fn message_signing_and_verification_never_enable_prehashed_mu() {
    let sign = ok(TransitMldsaSignRequest::new(
        secret(),
        TransitMldsaSignMode::Message,
    ));
    let value = wire(&sign_payload(&sign));
    assert_eq!(value["prehashed"], false);
    assert_eq!(value["hash_algorithm"], "none");
    assert!(value.get("key_version").is_none());
    assert!(!format!("{sign:?}").contains(secret().expose_secret()));
    let verify = ok(TransitMldsaVerifyRequest::new(secret(), secret()));
    assert!(!format!("{verify:?}").contains(secret().expose_secret()));
    assert_eq!(
        wire(&verify_payload(&verify))
            .as_object()
            .map(|map| map.len()),
        Some(2)
    );
    assert!(TransitMldsaVerifyRequest::new(secret(), SecretString::from("")).is_err());
}

#[test]
fn batch_controls_are_at_request_level_and_mixed_values_rejected() {
    let request = ok(ok(TransitMldsaSignRequest::new(
        mu(),
        TransitMldsaSignMode::ExternalMu,
    ))
    .with_key_version(1));
    let batch = [request.clone(), request.clone()];
    let value = wire(&ok(batch_sign_payload(&batch)));
    assert_eq!(value["hash_algorithm"], "mldsa-mu");
    assert_eq!(value["prehashed"], true);
    assert_eq!(value["key_version"], 1);
    assert_eq!(
        value["batch_input"][0].as_object().map(|map| map.len()),
        Some(1)
    );
    let message = ok(TransitMldsaSignRequest::new(
        mu(),
        TransitMldsaSignMode::Message,
    ));
    assert!(batch_sign_payload(&[request.clone(), message]).is_err());
    assert!(
        batch_sign_payload(&[request.clone(), ok(request.clone().with_key_version(2))]).is_err()
    );
    assert!(batch_sign_payload(&[]).is_err());
    assert!(batch_sign_payload(&vec![request.clone(); MAX_TRANSIT_BATCH_ITEMS]).is_ok());
    assert!(batch_sign_payload(&vec![request; MAX_TRANSIT_BATCH_ITEMS + 1]).is_err());
}

fn details(keys: &str) -> core::result::Result<TransitKeyDetails, serde_json::Error> {
    serde_json::from_str(&format!(
        r#"{{"name":"key","type":"mldsa-44","latest_version":1,"keys":{keys}}}"#
    ))
}

#[test]
fn detailed_read_accepts_all_three_key_shapes_and_import_alias() {
    let result = details(r#"{"1":123,"2":"config:key","3":{"name":"mldsa-44","creation_time":"2026-09-27T00:00:00Z","public_key":"public","certificate_chain":""}}"#)
        .unwrap_or_else(|_| panic!("valid key versions rejected"));
    assert!(matches!(
        result.keys.get("1"),
        Some(TransitKeyVersionDetails::Timestamp(123))
    ));
    assert!(matches!(
        result.keys.get("2"),
        Some(TransitKeyVersionDetails::ExternalReference(_))
    ));
    assert!(matches!(
        result.keys.get("3"),
        Some(TransitKeyVersionDetails::Asymmetric { .. })
    ));
    let imported: TransitKeyDetails = serde_json::from_str(r#"{"name":"key","type":"mldsa-44","latest_version":1,"imported_key":true,"imported_key_allow_rotation":true}"#)
        .unwrap_or_else(|_| panic!("import flags rejected"));
    assert!(imported.imported_key && imported.imported_key_allow_rotation);
}

#[test]
fn detailed_read_rejects_duplicates_bad_shapes_and_overflow() {
    for keys in [
        r#"{"1":1,"1":2}"#,
        r#"{"1":null}"#,
        r#"{"1":[]}"#,
        r#"{"1":{"public_key":"missing-fields"}}"#,
        r#"{"1":{"name":"x","name":"y","public_key":"public","creation_time":"now"}}"#,
    ] {
        assert!(details(keys).is_err());
    }
    for (count, valid) in [
        (crate::response::MAX_RESPONSE_STRINGS, true),
        (crate::response::MAX_RESPONSE_STRINGS + 1, false),
    ] {
        let keys = format!(
            "{{{}}}",
            (0..count)
                .map(|n| format!("\"{n}\":1"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(details(&keys).is_ok(), valid);
    }
}

#[test]
fn export_formats_are_closed_and_exact() {
    for (format, expected) in [
        (TransitExportFormat::Default, ""),
        (TransitExportFormat::Raw, "raw"),
        (TransitExportFormat::Der, "der"),
        (TransitExportFormat::Pem, "pem"),
    ] {
        assert_eq!(format.as_str(), expected);
    }
}
