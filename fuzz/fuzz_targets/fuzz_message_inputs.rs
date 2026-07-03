#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use vectis::core::canonical;
use vectis::ops::message;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    let _ = message::parse_send_message_input(value.clone());

    if let Ok(envelope) = message::parse_message_envelope(value.clone()) {
        let encoded = canonical::canonical_json_v1(&envelope).expect("envelope must canonicalize");
        let reparsed: Value = serde_json::from_slice(&encoded).expect("envelope JSON must parse");
        let encoded_again =
            canonical::canonical_json_v1(&reparsed).expect("envelope must re-encode");
        assert_eq!(encoded, encoded_again);

        let _ = envelope.sender_host();
        let _ = envelope.sender_kid();
        let _ = envelope.recipient_kid();
    }

    if let Ok(input) = message::parse_decrypt_message_input(value.clone()) {
        let _ = message::decrypt_message_recipient_kid(&input);
    }

    let _ = message::parse_internal_encrypt_message_input(value.clone());
    let _ = message::parse_internal_decrypt_message_input(value);
});
