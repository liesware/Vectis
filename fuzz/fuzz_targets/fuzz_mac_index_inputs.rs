#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use vectis::ops::{indexes, mac};

#[path = "input_common.rs"]
mod input_common;
use input_common::assert_public_error_is_clean;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    assert_public_error_is_clean(
        mac::parse_create_input(value.clone()).and_then(mac::validate_create_input),
    );
    assert_public_error_is_clean(
        mac::parse_verify_input(value.clone()).and_then(mac::validate_verify_input),
    );
    assert_public_error_is_clean(
        mac::parse_create_batch_input(value.clone()).and_then(mac::validate_create_batch_input),
    );
    assert_public_error_is_clean(
        mac::parse_verify_batch_input(value.clone()).and_then(mac::validate_verify_batch_input),
    );

    assert_public_error_is_clean(
        indexes::parse_create_input(value.clone()).and_then(indexes::validate_create_input),
    );
    assert_public_error_is_clean(
        indexes::parse_verify_input(value.clone()).and_then(indexes::validate_verify_input),
    );
    assert_public_error_is_clean(
        indexes::parse_batch_input(value.clone()).and_then(indexes::validate_batch_input),
    );
    assert_public_error_is_clean(
        indexes::parse_verify_batch_input(value).and_then(indexes::validate_verify_batch_input),
    );
});
