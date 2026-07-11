#![no_main]

use libfuzzer_sys::fuzz_target;
use openbao::{
    OpenBaoCapabilityProfile, OpenBaoVersion, openbao_operation, openbao_operations,
};
use serde::Deserialize;

const MAX_INPUT_BYTES: usize = 4 * 1024;

#[derive(Deserialize)]
struct Input {
    version: String,
    operation_id: Option<String>,
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let Ok(input) = serde_json::from_slice::<Input>(data) else {
        return;
    };
    let Ok(version) = input.version.parse::<OpenBaoVersion>() else {
        return;
    };
    let Some(profile) = OpenBaoCapabilityProfile::for_version(version) else {
        return;
    };

    assert_eq!(profile.version(), version);
    assert_eq!(profile.operations().count(), openbao_operations().len());

    if let Some(id) = input.operation_id {
        let Some(operation) = openbao_operation(&id) else {
            return;
        };
        let matching = operation
            .ranges()
            .iter()
            .filter(|range| version >= range.minimum() && version <= range.maximum())
            .count();
        assert_eq!(matching, 1);
        assert!(operation.availability(version).is_some());
        assert!(operation.evidence(version).is_some());
    }
});
