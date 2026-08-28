#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use vectis::core::canonical;
use vectis::ops::message;

#[path = "input_common.rs"]
mod input_common;
use input_common::assert_public_error_is_clean;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    assert_public_error_is_clean(
        message::parse_send_message_input(value.clone())
            .and_then(message::validate_send_message_input_encoding),
    );

    match message::parse_message_envelope(value.clone()) {
        Ok(envelope) => {
            assert_public_error_is_clean(message::validate_message_envelope_encoding(&envelope));

            let encoded =
                canonical::canonical_json_v1(&envelope).expect("envelope must canonicalize");
            let reparsed: Value =
                serde_json::from_slice(&encoded).expect("envelope JSON must parse");
            let encoded_again =
                canonical::canonical_json_v1(&reparsed).expect("envelope must re-encode");
            assert_eq!(encoded, encoded_again);

            let _ = envelope.sender_host();
            let _ = envelope.sender_kid();
            let _ = envelope.recipient_kid();
        }
        Err(err) => assert_public_error_is_clean(Err::<(), _>(err)),
    }

    match message::parse_decrypt_message_input(value.clone()) {
        Ok(input) => {
            let validation_input = message::parse_decrypt_message_input(value.clone())
                .expect("the same JSON value must parse consistently");
            assert_public_error_is_clean(message::validate_decrypt_message_input_encoding(
                validation_input,
            ));
            assert_public_error_is_clean(message::decrypt_message_recipient_kid(&input));
        }
        Err(err) => assert_public_error_is_clean(Err::<(), _>(err)),
    }

    assert_public_error_is_clean(
        message::parse_internal_encrypt_message_input(value.clone())
            .and_then(message::validate_internal_encrypt_message_input_encoding),
    );
    assert_public_error_is_clean(
        message::parse_internal_decrypt_message_input(value)
            .and_then(message::validate_internal_decrypt_message_input_encoding),
    );
});
