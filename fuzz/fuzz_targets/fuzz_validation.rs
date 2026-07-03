#![no_main]

use libfuzzer_sys::fuzz_target;
use vectis::core::{config, crypto, validation};

fn assert_public_error_is_clean<T, E: std::fmt::Display>(result: Result<T, E>) {
    if let Err(err) = result {
        let text = err.to_string();
        assert!(!text.chars().any(char::is_control));
    }
}

fn selected_hash_algorithm(data: &[u8]) -> &'static str {
    let index = data.first().copied().unwrap_or_default() as usize % crypto::HASH_ALGORITHMS.len();

    crypto::HASH_ALGORITHMS[index]
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    assert_public_error_is_clean(validation::validate_text_field("field", text));
    assert_public_error_is_clean(validation::validate_hex_field("hex", text));
    assert_public_error_is_clean(validation::validate_hash_hex_field(
        "hash",
        text,
        selected_hash_algorithm(data),
    ));
    assert_public_error_is_clean(validation::validate_host_port("addr", text));
    assert_public_error_is_clean(config::validate_http_path_field("path", text));
    assert_public_error_is_clean(config::validate_bool_field("flag", text));
    assert_public_error_is_clean(config::validate_vectis_mode(text));
    assert_public_error_is_clean(config::validate_http_scheme(text));
});
