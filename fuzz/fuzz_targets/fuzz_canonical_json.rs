#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use vectis::core::canonical;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return;
    };

    let Ok(first) = canonical::canonical_json_v1(&value) else {
        return;
    };
    let reparsed: Value = serde_json::from_slice(&first).expect("canonical JSON must parse");
    let second = canonical::canonical_json_v1(&reparsed).expect("canonical JSON must re-encode");

    assert_eq!(first, second);
});
