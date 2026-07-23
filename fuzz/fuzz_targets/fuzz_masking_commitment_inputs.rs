#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use vectis::ops::{commitments, masking};

#[path = "input_common.rs"]
mod input_common;
use input_common::assert_public_error_is_clean;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    assert_public_error_is_clean(
        masking::parse_mask_input(value.clone()).and_then(masking::validate_mask_input),
    );
    assert_public_error_is_clean(
        masking::parse_mask_batch_input(value.clone()).and_then(masking::validate_mask_batch_input),
    );

    assert_public_error_is_clean(
        commitments::parse_create_input(value.clone()).and_then(commitments::validate_create_input),
    );
    assert_public_error_is_clean(
        commitments::parse_verify_input(value.clone()).and_then(commitments::validate_verify_input),
    );
    assert_public_error_is_clean(
        commitments::parse_create_batch_input(value.clone())
            .and_then(commitments::validate_create_batch_input),
    );
    assert_public_error_is_clean(
        commitments::parse_verify_batch_input(value)
            .and_then(commitments::validate_verify_batch_input),
    );
});
