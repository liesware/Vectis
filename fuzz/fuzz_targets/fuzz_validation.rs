#![no_main]

use libfuzzer_sys::fuzz_target;
use vectis::core::{config, validation};

#[path = "input_common.rs"]
mod input_common;
use input_common::assert_public_error_is_clean;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    const VALID_CIPHERTEXT: &str = "00000000000000000000000000000000";
    const VALID_NONCE: &str = "000000000000000000000000";
    const VALID_AAD: &str = "type=fuzz";

    assert_public_error_is_clean(validation::validate_text_field("field", text));
    assert_public_error_is_clean(validation::validate_hex_field("hex", text));
    assert_public_error_is_clean(validation::validate_aad_key("aad key", text));
    assert_public_error_is_clean(validation::validate_aad_value("aad.value", text));
    assert_public_error_is_clean(validation::build_validated_aad(&[("field", text)]));
    assert_public_error_is_clean(validation::build_validated_aad(&[(text, "value")]));
    assert_public_error_is_clean(validation::validate_config_name("name", text));
    assert_public_error_is_clean(validation::validate_aad_config_name("profile", text));
    assert_public_error_is_clean(validation::validate_labels(
        "labels",
        text,
        config::CONFIG_NAME_MAX_CHARS,
    ));
    assert_public_error_is_clean(validation::validate_ref(text));
    assert_public_error_is_clean(validation::validate_socket_addr("socket", text));
    assert_public_error_is_clean(validation::validate_host_port("addr", text));
    assert_public_error_is_clean(validation::validate_hostname("hostname", text));
    assert_public_error_is_clean(validation::validate_allowed_value(
        "state",
        text,
        &["active", "disabled"],
    ));
    assert_public_error_is_clean(validation::validate_symmetric_key("key", text, 32));
    assert_public_error_is_clean(validation::validate_encrypted_payload(
        "ciphertext",
        text,
        "nonce",
        VALID_NONCE,
        "aad",
        VALID_AAD,
        config::INTERNAL_KEYS_NONCE_SIZE_BYTES,
    ));
    assert_public_error_is_clean(validation::validate_encrypted_payload(
        "ciphertext",
        VALID_CIPHERTEXT,
        "nonce",
        text,
        "aad",
        VALID_AAD,
        config::INTERNAL_KEYS_NONCE_SIZE_BYTES,
    ));
    assert_public_error_is_clean(validation::validate_encrypted_payload(
        "ciphertext",
        VALID_CIPHERTEXT,
        "nonce",
        VALID_NONCE,
        "aad",
        text,
        config::INTERNAL_KEYS_NONCE_SIZE_BYTES,
    ));
    assert_public_error_is_clean(config::validate_http_path_field("path", text));
    assert_public_error_is_clean(config::validate_bool_field("flag", text));
    assert_public_error_is_clean(config::validate_vectis_mode(text));
    assert_public_error_is_clean(config::validate_http_scheme(text));
});
