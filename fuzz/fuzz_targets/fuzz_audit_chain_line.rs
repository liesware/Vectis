#![no_main]

use libfuzzer_sys::fuzz_target;
use vectis::core::audit_chain;

#[path = "input_common.rs"]
mod input_common;
use input_common::assert_public_error_is_clean;

fuzz_target!(|data: &[u8]| {
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };

    assert_public_error_is_clean(audit_chain::validate_audit_jsonl_line_encoding(line));
});
