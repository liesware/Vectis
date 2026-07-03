#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use vectis::core::canonical;
use vectis::ops::sign;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    if let Ok(token) = sign::parse_timestamp_token(value) {
        let encoded = canonical::canonical_json_v1(&token).expect("token must canonicalize");
        let reparsed: Value = serde_json::from_slice(&encoded).expect("canonical token must parse");
        let encoded_again =
            canonical::canonical_json_v1(&reparsed).expect("canonical token must re-encode");

        assert_eq!(encoded, encoded_again);
        let _ = token.kid();
    }
});
