#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use vectis::core::crypto;

// The AEAD primitive behind internal message and token-data encryption. The
// property is a straight round-trip: decrypting our own ciphertext with the same
// key/nonce/AAD returns the exact plaintext. Key secrecy and nonce uniqueness
// are irrelevant to this property, so both are fixed — only the message and AAD
// are fuzzed.
const ALGORITHM: &str = "AES-256/GCM";

static SPEC: LazyLock<crypto::SymmetricCipherSpec> =
    LazyLock::new(|| crypto::symmetric_cipher(ALGORITHM).expect("AES-256/GCM must be supported"));

fuzz_target!(|data: &[u8]| {
    let spec = &*SPEC;
    let key = vec![0x24u8; spec.key_size_bytes];
    let nonce = vec![0x42u8; spec.nonce_size_bytes];

    // Split the bounded input into message and associated data.
    let bounded = &data[..data.len().min(512)];
    let (message_bytes, aad) = bounded.split_at(bounded.len() / 2);
    let message = String::from_utf8_lossy(message_bytes);

    let Ok(ciphertext) = crypto::encrypt_symmetric(ALGORITHM, &message, &key, &nonce, aad) else {
        return;
    };
    let recovered = crypto::decrypt_symmetric(ALGORITHM, &ciphertext, &key, &nonce, aad)
        .expect("decrypt of our own ciphertext must succeed");

    assert_eq!(
        recovered,
        message.as_bytes(),
        "symmetric AEAD round-trip must preserve the message"
    );
});
