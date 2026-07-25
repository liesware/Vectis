#![no_main]

use libfuzzer_sys::fuzz_target;
use vectis::core::sharing;

#[path = "input_common.rs"]
mod input_common;
use input_common::assert_public_error_is_clean;

fuzz_target!(|data: &[u8]| {
    let Ok(share) = std::str::from_utf8(data) else {
        return;
    };

    assert_public_error_is_clean(sharing::validate_share_envelope_encoding(share));
});
