#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use vectis::core::canonical;
use vectis::ops::sign;

#[path = "input_common.rs"]
mod input_common;

use input_common::assert_public_error_is_clean;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    match sign::parse_compact_signature_token(value) {
        Ok(token) => {
            let encoded = canonical::canonical_json_v1(&token).expect("token must canonicalize");
            let reparsed: Value =
                serde_json::from_slice(&encoded).expect("canonical token must parse");
            let encoded_again =
                canonical::canonical_json_v1(&reparsed).expect("canonical token must re-encode");

            assert_eq!(encoded, encoded_again);
            assert!(!token.kid.is_empty());
        }
        Err(err) => assert_public_error_is_clean(Err::<(), _>(err)),
    }
});
