#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use vectis::ops::sign;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    match sign::parse_sign_input(value) {
        Ok(input) => {
            let _ = sign::validate_sign_input(input);
        }
        Err(err) => {
            let public_error = err.to_string();
            assert!(!public_error.chars().any(char::is_control));
        }
    }
});
