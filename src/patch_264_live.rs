//! Exact 2.6 maintenance-line acceptance through the public SDK over TLS.

use crate::auth::{
    kerberos::KerberosGroupRequest, ldap::LdapAuthMappingRequest, radius::RadiusUserRequest,
};
use crate::patch_271_live::stage;
use crate::secrets::kv2::Kv2ServiceConfig;
use crate::sys::{AuthEnableRequest, MountEnableRequest};
use crate::{ExposeSecret, OpenBaoVersion, SecretString};
use std::collections::BTreeMap;

fn checked<T, E>(result: core::result::Result<T, E>) -> T {
    #[allow(clippy::panic)]
    result.unwrap_or_else(|_| panic!("2.6 patch SDK TLS assertion failed"))
}

fn mount(kind: &str) -> MountEnableRequest {
    MountEnableRequest {
        backend_type: kind.to_owned(),
        description: None,
        config: None,
        options: BTreeMap::new(),
        local: Some(true),
        seal_wrap: None,
        external_entropy_access: None,
    }
}

#[tokio::test]
#[ignore = "requires a constrained exact 2.6.4 TLS server and a candidate registry build"]
async fn public_patch_tls() {
    let client = crate::patch_271_live::run_patch(OpenBaoVersion::new(2, 6, 4)).await;
    stage!("token");
    assert!(
        checked(client.token().lookup_self().await)
            .policies
            .iter()
            .any(|p| p == "root")
    );

    stage!("kv");
    checked(client.sys().enable_mount("patch-kv1", &mount("kv")).await);
    let mut kv2 = mount("kv");
    kv2.options.insert("version".into(), "2".into());
    checked(client.sys().enable_mount("patch-kv2", &kv2).await);
    let value = Kv2ServiceConfig {
        values: BTreeMap::from([(
            "value".to_owned(),
            SecretString::from("disposable-kv-value"),
        )]),
    };
    let kv1 = checked(client.kv1("patch-kv1"));
    checked(kv1.write("entry", &value).await);
    let read: Kv2ServiceConfig = checked(kv1.read("entry").await);
    assert!(checked(read.required("value")).expose_secret() == "disposable-kv-value");
    let kv2 = checked(client.kv2("patch-kv2"));
    assert!(checked(kv2.write("entry", &value).await).version == 1);
    assert!(checked(kv2.patch("entry", &value).await).version == 2);
    let read = checked(kv2.read::<Kv2ServiceConfig>("entry").await);
    assert!(checked(read.data.required("value")).expose_secret() == "disposable-kv-value");
    assert!(checked(kv2.metadata("entry").await).current_version == 2);

    stage!("wrapping");
    let wrapped = checked(client.sys().wrapping_wrap("60s", &value).await);
    let read: Kv2ServiceConfig = checked(client.sys().wrapping_unwrap(Some(&wrapped.token)).await);
    assert!(checked(read.required("value")).expose_secret() == "disposable-kv-value");
    assert!(
        client
            .sys()
            .wrapping_unwrap::<Kv2ServiceConfig>(Some(&wrapped.token))
            .await
            .is_err()
    );

    // Policy mappings need no external directory/KDC/RADIUS server. These
    // checks prove SDK administration, not external authentication behavior.
    stage!("legacy-mounts");
    for kind in ["ldap", "kerberos", "radius"] {
        checked(
            client
                .sys()
                .enable_auth_method(
                    &format!("patch-{kind}"),
                    &AuthEnableRequest {
                        backend_type: kind.to_owned(),
                        description: None,
                        config: None,
                        local: Some(true),
                    },
                )
                .await,
        );
    }
    stage!("ldap-auth");
    let ldap = checked(client.ldap_auth_admin_at("patch-ldap"));
    checked(
        ldap.write_user("fixture", &LdapAuthMappingRequest::new("default"))
            .await,
    );
    assert!(
        checked(ldap.read_user("fixture").await)
            .policies
            .iter()
            .any(|p| p == "default")
    );
    checked(ldap.delete_user("fixture").await);
    stage!("kerberos");
    let kerberos = checked(client.kerberos_auth_admin_at("patch-kerberos"));
    checked(
        kerberos
            .write_group("fixture", &KerberosGroupRequest::new("default"))
            .await,
    );
    assert!(
        checked(kerberos.read_group("fixture").await)
            .policies
            .iter()
            .any(|p| p == "default")
    );
    checked(kerberos.delete_group("fixture").await);
    stage!("radius");
    let radius = checked(client.radius_admin_at("patch-radius"));
    checked(
        radius
            .write_user("fixture", &RadiusUserRequest::new("default"))
            .await,
    );
    assert!(
        checked(radius.read_user("fixture").await)
            .policies
            .split(',')
            .any(|p| p == "default")
    );
    checked(radius.delete_user("fixture").await);
    stage!("ldap-secrets");
    checked(
        client
            .sys()
            .enable_mount("patch-ldap-secrets", &mount("ldap"))
            .await,
    );
    let ldap = checked(client.ldap_at("patch-ldap-secrets"));
    let role = crate::secrets::ldap::LdapDynamicRole::new(
        "dn: cn={{.Username}},dc=fixture,dc=invalid\nchangetype: add\nobjectClass: person\ncn: {{.Username}}\nsn: fixture\n",
        "dn: cn={{.Username}},dc=fixture,dc=invalid\nchangetype: delete\n",
    );
    checked(ldap.write_dynamic_role("fixture", &role).await);
    let read = checked(ldap.read_dynamic_role("fixture").await);
    assert!(read.creation_ldif == role.creation_ldif && read.deletion_ldif == role.deletion_ldif);
    checked(ldap.delete_dynamic_role("fixture").await);

    stage!("cleanup");
    for kind in ["ldap", "kerberos", "radius"] {
        checked(
            client
                .sys()
                .disable_auth_method(&format!("patch-{kind}"))
                .await,
        );
    }
    for name in ["patch-ldap-secrets", "patch-kv1", "patch-kv2"] {
        checked(client.sys().disable_mount(name).await);
    }
    stage!("complete");
}
