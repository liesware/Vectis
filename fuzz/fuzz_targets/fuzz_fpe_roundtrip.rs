#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use vectis::core::config_file::ConfigState;
use vectis::core::fpe;

#[allow(dead_code)]
#[path = "common.rs"]
mod common;

// A single decimal FPE profile. `common::validate_fuzz_config_content` derives
// the FPE key with a deterministic dummy hook, so the prepared FF1 cipher is
// stable for the whole run. Building it inside a `LazyLock` pays the profile /
// cipher setup exactly once per process instead of once per iteration — FF1 key
// scheduling would otherwise dominate throughput and defeat the fuzzer.
const FPE_CONFIG: &str = r#"{
  "version": "v1",
  "routes": [],
  "remote_routes": [],
  "permissions": [],
  "fpe_profiles": [
    {
      "name": "fuzz-fpe-roundtrip-decimal-v1",
      "fpe_version": "fpe-ff1-2025",
      "alphabet": "0123456789",
      "min_len": 6,
      "max_len": 32,
      "tweak_aad": "tenant=fuzz;field=roundtrip;version=1",
      "kid": "e04daae3fa0ab03ab91e8c80608f176a0010dc4514263c6f02ce78288153bde1"
    }
  ],
  "tokenization_profiles": [],
  "mac_profiles": [],
  "masking_profiles": [],
  "commitment_profiles": [],
  "sharing_profiles": []
}"#;

const PROFILE_NAME: &str = "fuzz-fpe-roundtrip-decimal-v1";

static CONFIG: LazyLock<ConfigState> = LazyLock::new(|| {
    common::validate_fuzz_config_content(FPE_CONFIG).expect("fuzz FPE config must validate")
});

fuzz_target!(|data: &[u8]| {
    let profile = CONFIG
        .fpe_profiles
        .get(PROFILE_NAME)
        .expect("fpe profile must be present");

    // Map arbitrary bytes into a plaintext this profile actually accepts: each
    // byte becomes a decimal digit and the length is clamped to the profile's
    // [min_len, max_len] domain. This keeps the fuzzer exercising the roundtrip
    // property instead of burning iterations on inputs the encoder rejects
    // outright. Inputs shorter than min_len simply carry no usable plaintext.
    let plaintext: String = data
        .iter()
        .take(profile.max_len())
        .map(|byte| char::from(b'0' + (byte % 10)))
        .collect();
    if plaintext.len() < profile.min_len() {
        return;
    }

    // The property: on the success path, decrypting our own ciphertext must
    // return the exact plaintext. A rejection from encrypt is not a bug (the
    // profile legitimately constrains its domain); a failed decrypt or a
    // mismatch is.
    let Ok(ciphertext) = fpe::fpe_encrypt(profile, &plaintext) else {
        return;
    };
    let recovered =
        fpe::fpe_decrypt(profile, &ciphertext).expect("decrypt of our own ciphertext must succeed");
    assert_eq!(recovered, plaintext, "FPE roundtrip must preserve the plaintext");
});
