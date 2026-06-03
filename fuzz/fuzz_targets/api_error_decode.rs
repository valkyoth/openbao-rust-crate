#![no_main]

use libfuzzer_sys::fuzz_target;
use openbao::{BoundedStringList, Error, StatusCode};
use serde::Deserialize;

#[derive(Deserialize)]
struct ApiErrorFixture {
    #[serde(default)]
    errors: Option<BoundedStringList>,
}

fuzz_target!(|data: &[u8]| {
    if let Ok(decoded) = serde_json::from_slice::<ApiErrorFixture>(data) {
        let errors = decoded
            .errors
            .map(BoundedStringList::into_vec)
            .unwrap_or_default();
        let error = Error::Api {
            status: StatusCode::BAD_REQUEST,
            errors,
        };
        let _ = error.to_string();
    }
});
