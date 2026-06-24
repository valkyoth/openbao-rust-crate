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
}
