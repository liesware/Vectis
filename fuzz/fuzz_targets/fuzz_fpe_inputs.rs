#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use vectis::ops::fpe;

#[path = "input_common.rs"]
mod input_common;
use input_common::assert_public_error_is_clean;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    assert_public_error_is_clean(
        fpe::parse_encrypt_input(value.clone()).and_then(fpe::validate_encrypt_input),
    );
    assert_public_error_is_clean(
        fpe::parse_decrypt_input(value.clone()).and_then(fpe::validate_decrypt_input),
    );
    assert_public_error_is_clean(
        fpe::parse_encrypt_batch_input(value.clone()).and_then(fpe::validate_encrypt_batch_input),
    );
    assert_public_error_is_clean(
        fpe::parse_decrypt_batch_input(value).and_then(fpe::validate_decrypt_batch_input),
    );
});
