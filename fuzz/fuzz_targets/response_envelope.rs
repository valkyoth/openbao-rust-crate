#![no_main]

use libfuzzer_sys::fuzz_target;
use openbao::{JsonValue, ResponseEnvelope};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<ResponseEnvelope<JsonValue>>(data);
});
