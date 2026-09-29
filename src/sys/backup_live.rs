//! Public SDK backup acceptance without promoting the staged exact profile.

use super::*;
use crate::{OpenBaoCompatibilityStatus, OpenBaoConfig};
use std::{io::Read, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    addresses: [String; 3],
    ca_pem: String,
    token: SecretString,
}

fn checked<T, E>(result: core::result::Result<T, E>) -> T {
    #[allow(clippy::panic)]
    result.unwrap_or_else(|_| panic!("SDK backup fixture assertion failed"))
}

#[tokio::test]
#[ignore = "requires real PGP recovery backup, constrained TLS server and private stdin"]
async fn public_rotation_backup_tls() {
    let fixture: Fixture = checked(serde_json::from_reader(std::io::stdin().lock().take(65536)));
    let address = &fixture.addresses[0];
    assert!(fixture.addresses.iter().all(|other| other == address));
    let url = checked(Url::parse(address));
    assert!(url.scheme() == "https" && url.host_str() == Some("127.0.0.1"));
    assert!(url.username().is_empty() && url.password().is_none());
    assert!(url.path() == "/" && url.query().is_none() && url.fragment().is_none());
    let config = checked(OpenBaoConfig::new(address));
    let config = checked(config.only_root_certificates(vec![checked(
        reqwest::Certificate::from_pem(fixture.ca_pem.as_bytes()),
    )]));
    let config = checked(config.timeout(Duration::from_secs(5)));
    let client = checked(checked(Client::from_config(config)).try_with_token(fixture.token));
    assert!(
        checked(client.compatibility_report().await).status()
            == OpenBaoCompatibilityStatus::Unverified
    );
    let sys = client.sys();
    assert!(checked(sys.health().await).version == "2.7.0");
    let backup = checked(
        sys.operator_rotate_backup_grouped(OperatorRotateTarget::Recovery)
            .await,
    );
    assert!(backup.nonce.is_some());
    assert!(backup.keys.len() == 1 && backup.keys_base64.len() == 1);
    for (fingerprint, shares) in &backup.keys {
        assert!(
            fingerprint.len() == 40
                && fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        let encoded = checked(backup.keys_base64.get(fingerprint).ok_or(()));
        assert!(shares.len() == 1 && encoded.len() == 1);
        // Independent encoding comparison in addition to the production decoder.
        let mut hex_bytes =
            SecretVec::from_vec(Vec::with_capacity(shares[0].expose_secret().len() / 2));
        for pair in shares[0].expose_secret().as_bytes().as_chunks::<2>().0 {
            let high = checked(char::from(pair[0]).to_digit(16).ok_or(()));
            let low = checked(char::from(pair[1]).to_digit(16).ok_or(()));
            hex_bytes.extend_from_slice(&[checked(u8::try_from((high << 4) | low))]);
        }
        let base64 =
            checked(base64_ng::ct::STANDARD.decode_secret(encoded[0].expose_secret().as_bytes()));
        let base64 = SecretVec::from_vec(
            base64
                .into_exposed_vec()
                .into_exposed_unprotected_vec_caller_must_zeroize(),
        );
        assert!(hex_bytes.with_secret(|hex| base64.with_secret(|base64| hex == base64)));
    }
    let singleton = checked(
        sys.operator_rotate_backup(OperatorRotateTarget::Recovery)
            .await,
    );
    assert!(singleton.nonce == backup.nonce);
    for (fingerprint, shares) in &backup.keys {
        assert!(
            checked(singleton.keys.get(fingerprint).ok_or(())).expose_secret()
                == shares[0].expose_secret()
        );
    }
}
