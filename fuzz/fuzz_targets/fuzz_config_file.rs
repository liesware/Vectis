#![no_main]

use libfuzzer_sys::fuzz_target;
use vectis::core::config_file;

#[path = "common.rs"]
mod common;
use common::validate_fuzz_config_content;
#[path = "input_common.rs"]
mod input_common;
use input_common::assert_public_error_is_clean;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };

    assert_public_error_is_clean(config_file::canonical_config_json(content));
    assert_public_error_is_clean(validate_fuzz_config_content(content));
});
