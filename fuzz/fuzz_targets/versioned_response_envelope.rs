#![no_main]

use libfuzzer_sys::fuzz_target;
use openbao::{ResponseEnvelope, auth::token::TokenInfo, secrets::pki};
use openbao::sys::{PluginInfo, PolicyInfo, RateLimitQuotaInfo};

const MAX_INPUT_BYTES: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    if body.len() > MAX_INPUT_BYTES {
        return;
    }

    match selector % 5 {
        0 => {
            let _ = serde_json::from_slice::<ResponseEnvelope<pki::PkiCertificateBundle>>(body);
        }
        1 => {
            let _ = serde_json::from_slice::<ResponseEnvelope<pki::PkiRole>>(body);
        }
        2 => {
            let _ = serde_json::from_slice::<ResponseEnvelope<PolicyInfo>>(body);
        }
        3 => {
            let _ = serde_json::from_slice::<ResponseEnvelope<RateLimitQuotaInfo>>(body);
        }
        _ => {
            let _ = serde_json::from_slice::<ResponseEnvelope<PluginInfo>>(body);
            let _ = serde_json::from_slice::<ResponseEnvelope<TokenInfo>>(body);
        }
    }
});
