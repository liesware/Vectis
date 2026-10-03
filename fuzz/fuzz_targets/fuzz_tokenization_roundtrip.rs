#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::json;
use std::sync::LazyLock;
use vectis::core::config_file::ConfigState;
use vectis::core::tokenization::{self, TokenDataPayload};

#[allow(dead_code)]
#[path = "common.rs"]
mod common;

// One tokenization profile, keyed once per process (deterministic dummy keys via
// `common::validate_fuzz_config_content`). The property under test is that
// encrypting a token-data payload and decrypting it back preserves both the
// plaintext and the metadata verbatim.
const CONFIG: &str = r#"{
  "version": "v1",
  "routes": [],
  "remote_routes": [],
  "permissions": [],
  "fpe_profiles": [],
  "tokenization_profiles": [
    {
      "name": "fuzz-token-roundtrip-v1",
      "kid": "e04daae3fa0ab03ab91e8c80608f176a0010dc4514263c6f02ce78288153bde1",
      "token_prefix": "tok_fuzz",
      "token_len": 32,
      "max_plaintext_len": 16384,
      "one_time": false
    }
  ],
  "mac_profiles": [],
  "masking_profiles": [],
  "commitment_profiles": [],
  "sharing_profiles": []
}"#;

const PROFILE_NAME: &str = "fuzz-token-roundtrip-v1";
// The hashid binds the ciphertext AAD; encrypt and decrypt must agree on it.
const HASHID: &str = "fuzz-token-roundtrip-hashid";

static STATE: LazyLock<ConfigState> = LazyLock::new(|| {
    common::validate_fuzz_config_content(CONFIG).expect("fuzz tokenization config must validate")
});

static SUBJECT_STATE: LazyLock<ConfigState> = LazyLock::new(|| {
    let mut config: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
    config["tokenization_profiles"][0]["subject_mode"] = json!("stored");
    common::validate_fuzz_config_content(&config.to_string())
        .expect("stored fuzz profile must validate")
});

fuzz_target!(|data: &[u8]| {
    let profile = STATE
        .tokenization_profiles
        .get(PROFILE_NAME)
        .expect("tokenization profile must be present");

    // Derive the payload from the fuzz input: the tail is the plaintext (bounded
    // to the profile's max), the leading byte decides whether metadata is
    // present. metadata carries a JSON integer so the round-trip stays stable
    // (no float re-encoding to reason about).
    let (head, body) = data.split_first().unwrap_or((&0, &[]));
    let plaintext =
        String::from_utf8_lossy(&body[..body.len().min(profile.max_plaintext_len())]).into_owned();
    let metadata = if head & 1 == 1 {
        Some(json!({ "len": plaintext.len() }))
    } else {
        None
    };

    let payload = TokenDataPayload {
        profile: profile.name().to_string(),
        plaintext: plaintext.clone(),
        metadata: metadata.clone(),
        created_at: String::from("2026-01-01T00:00:00Z"),
    };

    let recovered = if head & 2 == 2 {
        let profile = SUBJECT_STATE
            .tokenization_profiles
            .get(PROFILE_NAME)
            .unwrap();
        let subject = vectis::core::subjects::subject_id(&profile, "synthetic-fuzz-user").unwrap();
        let envelope = vectis::core::subjects::create_seed(&profile, &subject).unwrap();
        let keys = vectis::core::subjects::open_seed(&profile, &subject, &envelope).unwrap();
        let context = tokenization::TokenContext::with_subject(profile.clone(), keys);
        let token = tokenization::generate_token(&profile).unwrap();
        let hashid = context.hash(&token).unwrap();
        let encoded = context.encrypt(&hashid, &payload).unwrap();
        let other = vectis::core::subjects::subject_id(&profile, "another-fuzz-user").unwrap();
        assert!(vectis::core::subjects::open_seed(&profile, &other, &envelope).is_err());
        let fresh = vectis::core::subjects::create_seed(&profile, &subject).unwrap();
        let fresh_keys = vectis::core::subjects::open_seed(&profile, &subject, &fresh).unwrap();
        let fresh_context = tokenization::TokenContext::with_subject(profile, fresh_keys);
        assert_ne!(
            context.hash(&token).unwrap(),
            fresh_context.hash(&token).unwrap()
        );
        assert!(fresh_context.decrypt(&hashid, &encoded).is_err());
        context
            .decrypt(&hashid, &encoded)
            .expect("subject round trip must succeed")
    } else {
        let encoded = tokenization::encrypt_token_data(&profile, HASHID, &payload).unwrap();
        tokenization::decrypt_token_data(&profile, HASHID, &encoded)
            .expect("legacy round trip must succeed")
    };

    assert_eq!(
        recovered.plaintext, plaintext,
        "token data round-trip must preserve the plaintext"
    );
    assert_eq!(
        recovered.metadata, metadata,
        "token data round-trip must preserve the metadata"
    );
});
