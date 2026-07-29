#![no_main]

use libfuzzer_sys::fuzz_target;
use vectis::ops::slh_dsa;

#[path = "input_common.rs"]
mod input_common;
use input_common::assert_public_error_is_clean;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };

    assert_public_error_is_clean(slh_dsa::validate_private_key_file_encoding(content));
    assert_public_error_is_clean(slh_dsa::validate_public_key_file_encoding(content));
});
