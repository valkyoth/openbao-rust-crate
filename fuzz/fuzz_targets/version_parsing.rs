#![no_main]

use core::str;

use libfuzzer_sys::fuzz_target;
use openbao::{OpenBaoVersion, OpenBaoVersionRequirement};

fuzz_target!(|input: &[u8]| {
    let Ok(input) = str::from_utf8(input) else {
        return;
    };

    if let Ok(version) = input.parse::<OpenBaoVersion>() {
        let rendered = version.to_string();
        assert_eq!(rendered.parse::<OpenBaoVersion>().ok(), Some(version));
    }

    if let Ok(requirement) = input.parse::<OpenBaoVersionRequirement>() {
        let rendered = requirement.to_string();
        assert_eq!(
            rendered.parse::<OpenBaoVersionRequirement>().ok(),
            Some(requirement)
        );
        assert!(requirement.contains(requirement.minimum()));
        assert!(requirement.contains(requirement.maximum()));
    }
});
