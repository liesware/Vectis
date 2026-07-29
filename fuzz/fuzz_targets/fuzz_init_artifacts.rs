#![no_main]

use libfuzzer_sys::fuzz_target;
use vectis::ops::init;

#[path = "input_common.rs"]
mod input_common;
use input_common::assert_public_error_is_clean;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };

    assert_public_error_is_clean(init::validate_init_encrypted_artifact_encoding(content));
    assert_public_error_is_clean(init::validate_init_public_artifact_encoding(content));
});
