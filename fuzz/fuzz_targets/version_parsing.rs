#![no_main]

use core::str;

use libfuzzer_sys::fuzz_target;
use openbao::{OpenBaoVersion, OpenBaoVersionRequirement};

fuzz_target!(|input: &[u8]| {
    let Ok(input) = str::from_utf8(input) else {
        return;
    };

    // Cargo-fuzz seed files conventionally end in a newline. Exercise both
    // the exact parser input and the historical artifact value in that file.
    let seed_value = input.strip_suffix('\n').unwrap_or(input);

    for candidate in [input, seed_value] {
        if let Ok(version) = candidate.parse::<OpenBaoVersion>() {
            let rendered = version.to_string();
            assert_eq!(rendered.parse::<OpenBaoVersion>().ok(), Some(version));
        }

        if let Ok(requirement) = candidate.parse::<OpenBaoVersionRequirement>() {
            let rendered = requirement.to_string();
            assert_eq!(
                rendered.parse::<OpenBaoVersionRequirement>().ok(),
                Some(requirement)
            );
            assert!(requirement.contains(requirement.minimum()));
            assert!(requirement.contains(requirement.maximum()));
        }
    }
});
