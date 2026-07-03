#![no_main]

use libfuzzer_sys::fuzz_target;
use vectis::core::config_file;

#[path = "common.rs"]
mod common;
use common::{fuzz_config, looks_loaded_kid};

fuzz_target!(|data: &[u8]| {
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };

    let _ = config_file::canonical_config_json(content);
    let _ = config_file::validate_config_content(content, &fuzz_config(), looks_loaded_kid);
});
