#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use vectis::ops::keys;

fn assert_public_error_is_clean<T, E: std::fmt::Display>(result: Result<T, E>) {
    if let Err(err) = result {
        let text = err.to_string();
        assert!(!text.chars().any(char::is_control));
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    assert_public_error_is_clean(keys::parse_create_keys_input(value.clone()));
    assert_public_error_is_clean(keys::parse_update_lifecycle_input(value));
});
