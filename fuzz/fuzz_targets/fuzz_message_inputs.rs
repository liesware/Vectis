#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use vectis::core::canonical;
use vectis::ops::message;

// The guarantee is that the HTTP boundary sanitizes error messages
// (io/http/error.rs). Asserting clean deep errors here is defense in depth:
// the ops layer should not gratuitously inject control characters.
fn assert_public_error_is_clean<T, E: std::fmt::Display>(result: Result<T, E>) {
    if let Err(err) = result {
        let text = err.to_string();
        assert!(!text.chars().any(char::is_control));
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    assert_public_error_is_clean(message::parse_send_message_input(value.clone()));

    match message::parse_message_envelope(value.clone()) {
        Ok(envelope) => {
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
            assert_public_error_is_clean(message::decrypt_message_recipient_kid(&input));
        }
        Err(err) => assert_public_error_is_clean(Err::<(), _>(err)),
    }

    assert_public_error_is_clean(message::parse_internal_encrypt_message_input(value.clone()));
    assert_public_error_is_clean(message::parse_internal_decrypt_message_input(value));
});
