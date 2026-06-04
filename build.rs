//! Build-time safety warnings for feature combinations that deserve attention.

fn main() {
    if std::env::var_os("CARGO_FEATURE_SENSITIVE_HTTP_TEST_ONLY").is_some() {
        println!(
            "cargo:warning=DANGER: sensitive-http-test-only disables HTTPS enforcement for sensitive loopback requests. Never include this feature in production builds."
        );
    }
}
