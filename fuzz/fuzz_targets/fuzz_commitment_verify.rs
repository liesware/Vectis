#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use vectis::core::commitments;
use vectis::core::config_file::ConfigState;

#[allow(dead_code)]
#[path = "common.rs"]
mod common;

// One commitment profile, keyed once per process. A commitment is a keyed tag
// over the canonical (opening, plaintext) payload. Two properties are asserted:
//   * verify  — recomputing with the same opening+plaintext reproduces the tag;
//   * binding — a different plaintext must not reproduce the tag.
const CONFIG: &str = r#"{
  "version": "v1",
  "routes": [],
  "remote_routes": [],
  "permissions": [],
  "fpe_profiles": [],
  "tokenization_profiles": [],
  "mac_profiles": [],
  "masking_profiles": [],
  "commitment_profiles": [
    {
      "name": "fuzz-commit-verify-v1",
      "kid": "e04daae3fa0ab03ab91e8c80608f176a0010dc4514263c6f02ce78288153bde1",
      "context": "tenant=fuzz;field=commit;purpose=commitment;version=1",
      "max_plaintext_len": 128,
      "opening_len": 32
    }
  ],
  "sharing_profiles": []
}"#;

const PROFILE_NAME: &str = "fuzz-commit-verify-v1";

static STATE: LazyLock<ConfigState> = LazyLock::new(|| {
    common::validate_fuzz_config_content(CONFIG).expect("fuzz commitment config must validate")
});

fuzz_target!(|data: &[u8]| {
    let profile = STATE
        .commitment_profiles
        .get(PROFILE_NAME)
        .expect("commitment profile must be present");

    // The opening must be exactly opening_len bytes; the remainder is the
    // plaintext (bounded to the profile max). Inputs too short to carry a full
    // opening carry no case.
    if data.len() < profile.opening_len() {
        return;
    }
    let (opening_bytes, tail) = data.split_at(profile.opening_len());
    let opening = commitments::encode_opening(opening_bytes);
    let plaintext =
        String::from_utf8_lossy(&tail[..tail.len().min(profile.max_plaintext_len())]).into_owned();

    let Ok(commitment) = commitments::compute_commitment(profile, &opening, &plaintext) else {
        return;
    };

    // verify: the commitment is deterministic in its inputs.
    let recomputed = commitments::compute_commitment(profile, &opening, &plaintext)
        .expect("recomputing a valid commitment must succeed");
    assert_eq!(
        commitment, recomputed,
        "commitment must verify: recompute is deterministic"
    );

    // binding: perturbing the plaintext must change the tag.
    let perturbed = format!("{plaintext}\u{0}");
    if let Ok(other) = commitments::compute_commitment(profile, &opening, &perturbed) {
        assert_ne!(
            commitment, other,
            "commitment must bind: a different plaintext must change the tag"
        );
    }
});
