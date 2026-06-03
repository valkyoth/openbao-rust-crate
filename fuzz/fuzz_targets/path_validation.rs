#![no_main]

use libfuzzer_sys::fuzz_target;
use openbao::{validate_endpoint_path, validate_mount_path};

fuzz_target!(|data: &[u8]| {
    if let Ok(candidate) = core::str::from_utf8(data) {
        let _ = validate_mount_path(candidate);
        let _ = validate_endpoint_path(candidate);
    }
});
