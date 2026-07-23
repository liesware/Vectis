#![no_main]

use libfuzzer_sys::fuzz_target;
use vectis::core::config_file;

#[path = "common.rs"]
mod common;
use common::validate_fuzz_config_content;

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };

    let _ = config_file::canonical_config_json(content);
    let _ = validate_fuzz_config_content(content);
});
