#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};
use std::sync::LazyLock;
use vectis::core::canonical;
use vectis::ops::message;

#[path = "input_common.rs"]
mod input_common;
use input_common::assert_public_error_is_clean;

const VALID_ENVELOPE: &str = r#"{"version":"v1","payload":{"version":"v1","type":"protected-message","created_at":"1","sender":{"host":"127.0.0.1:3000","kid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"recipient":{"kid":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"kem":{"alg":"X25519+ML-KEM-512","xecdh_ephemeral_public":"aa","ml_kem_ciphertext":"aa","ml_kem_salt":"aa","hkdf_salt":"aa"},"cipher":{"alg":"ChaCha20Poly1305","nonce":"aaaaaaaaaaaaaaaaaaaaaaaa","aad":"version=v1;type=protected-message;created_at=1;sender_host=127.0.0.1:3000;sender_kid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;recipient_kid=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;kem_alg=X25519+ML-KEM-512;cipher_alg=ChaCha20Poly1305","ct":"aabb"}},"signatures":{"eddsa":{"alg":"Ed25519","sig":"aa"},"ml-dsa":{"alg":"ML-DSA-44","sig":"aa"}}}"#;

const OTHER_KID_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const OTHER_KID_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

static BASE: LazyLock<Value> =
    LazyLock::new(|| serde_json::from_str(VALID_ENVELOPE).expect("base envelope must be JSON"));

fn tamper(choice: u8) -> (Value, &'static str) {
    let mut m = BASE.clone();
    let label = match choice % 9 {
        0 => {
            m["payload"]["kem"]["ml_kem_ciphertext"] = json!("zz");
            "kem.ml_kem_ciphertext non-hex"
        }
        1 => {
            m["payload"]["kem"]["xecdh_ephemeral_public"] = json!("gg");
            "kem.xecdh_ephemeral_public non-hex"
        }
        2 => {
            m["payload"]["cipher"]["ct"] = json!("xy");
            "cipher.ct non-hex"
        }
        3 => {
            m["payload"]["cipher"]["nonce"] = json!("zz");
            "cipher.nonce non-hex"
        }
        4 => {
            m["signatures"]["eddsa"]["sig"] = json!("!!");
            "eddsa.sig non-hex"
        }
        5 => {
            m["signatures"]["ml-dsa"]["alg"] = json!("ML-DSA-999");
            "ml-dsa.alg not allowed"
        }
        6 => {
            m["payload"]["recipient"]["kid"] = json!(OTHER_KID_C);
            "recipient.kid desyncs aad"
        }
        7 => {
            m["payload"]["sender"]["kid"] = json!(OTHER_KID_D);
            "sender.kid desyncs aad"
        }
        _ => {
            m["payload"]["cipher"]["alg"] = json!("AES-256/GCM");
            "cipher.alg desyncs aad"
        }
    };
    (m, label)
}

fuzz_target!(|data: &[u8]| {
    let envelope = message::parse_message_envelope(BASE.clone()).expect("base envelope must parse");
    message::validate_message_envelope_encoding(&envelope).expect("base envelope must validate");
    let canonical = canonical::canonical_json_v1(&envelope).expect("base must canonicalize");
    let reparsed: Value =
        serde_json::from_slice(&canonical).expect("canonical envelope must be JSON");
    let envelope_again =
        message::parse_message_envelope(reparsed).expect("canonical envelope must reparse");
    message::validate_message_envelope_encoding(&envelope_again)
        .expect("reparsed envelope must still validate");
    let canonical_again =
        canonical::canonical_json_v1(&envelope_again).expect("reparsed must re-canonicalize");
    assert_eq!(
        canonical, canonical_again,
        "protected message canonicalization must be idempotent"
    );

    let choice = data.first().copied().unwrap_or(0);
    let (mutated, label) = tamper(choice);
    let result = message::parse_message_envelope(mutated)
        .and_then(|token| message::validate_message_envelope_encoding(&token));
    assert!(
        result.is_err(),
        "isolated tamper ({label}) must be rejected but was accepted"
    );
    assert_public_error_is_clean(result);

    if let Ok(value) = serde_json::from_slice::<Value>(data) {
        match message::parse_message_envelope(value) {
            Ok(token) => {
                assert_public_error_is_clean(message::validate_message_envelope_encoding(&token))
            }
            Err(err) => assert_public_error_is_clean(Err::<(), _>(err)),
        }
    }
});
