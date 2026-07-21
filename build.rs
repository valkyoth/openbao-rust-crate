//! Build-time safety warnings for feature combinations that deserve attention.

fn main() {
    if std::env::var_os("CARGO_FEATURE_TLS12_ACKNOWLEDGED").is_some() {
        println!(
            "cargo:warning=TLS 1.2 support has been acknowledged. TLS 1.3 remains the default and is strongly preferred for high-security OpenBao deployments."
        );
    }
    if std::env::var_os("CARGO_FEATURE_SENSITIVE_HTTP_TEST_ONLY").is_some() {
        println!(
            "cargo:warning=DANGER: sensitive-http-test-only disables HTTPS enforcement for sensitive loopback requests. Never include this feature in production builds."
        );
    }
    if std::env::var_os("CARGO_FEATURE_MEMORY_LOCK").is_some() {
        println!(
            "cargo:warning=memory-lock is enabled. Verify host mlock/VirtualLock limits, swap policy, and failure handling for this deployment."
        );
    }
    if std::env::var_os("CARGO_FEATURE_OIDC_GET_CALLBACK_ACKNOWLEDGED").is_some() {
        println!(
            "cargo:warning=OIDC GET protocol support is enabled. Credentials or correlation values enter URL and HTTP-stack buffers; enforce query-free access logging."
        );
    }
    if std::env::var_os("CARGO_FEATURE_IDENTITY_TEMPLATE_OVERRIDES_ACKNOWLEDGED").is_some() {
        println!(
            "cargo:warning=DANGER: OpenBao identity-template delimiter overrides are enabled. Only use trusted identity metadata and separately audit ACL paths, PKI names, and SSH principals."
        );
    }
    if std::env::var_os("CARGO_FEATURE_WORKFLOW_TRACE").is_some() {
        println!(
            "cargo:warning=DANGER: workflow-trace can return the OpenBao token and complete intermediate workflow values. Never log trace responses."
        );
    }
    if std::env::var_os("CARGO_FEATURE_UNAUTHENTICATED_WORKFLOWS").is_some() {
        println!(
            "cargo:warning=Unauthenticated workflow execution is enabled. Audit server configuration, every exposed workflow, and rate limiting before deployment."
        );
    }
}
