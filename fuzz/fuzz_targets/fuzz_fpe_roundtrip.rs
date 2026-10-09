#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use vectis::core::config_file::ConfigState;
use vectis::core::fpe;

#[allow(dead_code)]
#[path = "common.rs"]
mod common;

// Legacy, preset and Unicode FPE profiles. `common::validate_fuzz_config_content` derives
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
    },
    {
      "name": "formatted-num", "fpe_version": "fpe-ff1-2025", "alphabet_preset": "num",
      "authenticated": true,
      "preserve_characters": "-", "min_len": 6, "max_len": 32,
      "tweak_aad": "tenant=fuzz;field=roundtrip;version=1",
      "kid": "e04daae3fa0ab03ab91e8c80608f176a0010dc4514263c6f02ce78288153bde1"
    },
    {
      "name": "formatted-alpha", "fpe_version": "fpe-ff1-2025", "alphabet_preset": "alpha",
      "letter_case": "mixed", "preserve_characters": "-", "min_len": 6, "max_len": 32,
      "tweak_aad": "tenant=fuzz;field=roundtrip;version=1",
      "kid": "e04daae3fa0ab03ab91e8c80608f176a0010dc4514263c6f02ce78288153bde1"
    },
    {
      "name": "formatted-unicode", "fpe_version": "fpe-ff1-2025", "alphabet": "零一二三四五六七八九",
      "authenticated": true,
      "preserve_characters": "🩺", "min_len": 6, "max_len": 32,
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

const PROFILE_NAMES: &[&str] = &[
    "fuzz-fpe-roundtrip-decimal-v1",
    "formatted-num",
    "formatted-alpha",
    "formatted-unicode",
];

static CONFIG: LazyLock<ConfigState> = LazyLock::new(|| {
    common::validate_fuzz_config_content(FPE_CONFIG).expect("fuzz FPE config must validate")
});

fuzz_target!(|data: &[u8]| {
    if data.len() < 6 {
        return;
    }
    let profile = CONFIG
        .fpe_profiles
        .get(PROFILE_NAMES[usize::from(data[0]) % PROFILE_NAMES.len()])
        .expect("fpe profile must be present");

    // Map arbitrary bytes into a plaintext this profile actually accepts: each
    // byte selects an alphabet character and the length is clamped to the profile's
    // [min_len, max_len] domain. This keeps the fuzzer exercising the roundtrip
    // property instead of burning iterations on inputs the encoder rejects
    // outright. Inputs shorter than min_len simply carry no usable plaintext.
    let alphabet: Vec<_> = profile.alphabet().chars().collect();
    let separator = profile.preserve_characters().chars().next();
    let variable: String = data
        .iter()
        .take(profile.max_len() - if separator.is_some() { 2 } else { 0 })
        .map(|byte| alphabet[usize::from(*byte) % alphabet.len()])
        .collect();
    let plaintext = match separator {
        Some(ch) => format!("{ch}{variable}{ch}"),
        None => variable,
    };

    // The property: on the success path, decrypting our own ciphertext must
    // return the exact plaintext. A rejection from encrypt is not a bug (the
    // profile legitimately constrains its domain); a failed decrypt or a
    // mismatch is.
    let Ok(ciphertext) = fpe::fpe_encrypt(&profile, &plaintext) else {
        return;
    };
    let tag = fpe::generate_auth_tag(&profile, &ciphertext).expect("tag generation must succeed");
    fpe::verify_auth_tag(&profile, &ciphertext, tag.as_deref()).expect("our own tag must verify");
    if let Some(tag) = &tag {
        let mut changed = tag.clone();
        changed.replace_range(..1, if tag.starts_with('0') { "1" } else { "0" });
        assert!(fpe::verify_auth_tag(&profile, &ciphertext, Some(&changed)).is_err());
        assert!(fpe::verify_auth_tag(&profile, &(ciphertext.clone() + "-"), Some(tag)).is_err());
    }
    let recovered = fpe::fpe_decrypt(&profile, &ciphertext)
        .expect("decrypt of our own ciphertext must succeed");
    assert_eq!(
        recovered, plaintext,
        "FPE roundtrip must preserve the plaintext"
    );
    assert_eq!(ciphertext.chars().count(), plaintext.chars().count());
    for (input, output) in plaintext.chars().zip(ciphertext.chars()) {
        if Some(input) == separator {
            assert_eq!(input, output);
        }
    }
    if let Some(separator) = separator {
        let count = usize::from(data[1] % 6);
        let short: String = plaintext
            .chars()
            .filter(|ch| *ch != separator)
            .take(count)
            .collect();
        let formatted = format!(
            "{}{}{}",
            separator.to_string().repeat(6 - count),
            short,
            separator
        );
        let domain = (0..count).fold(1usize, |domain, _| domain.saturating_mul(alphabet.len()));
        if count == 0 || domain < 1_000_000 {
            assert!(fpe::fpe_encrypt(&profile, &formatted).is_err());
        } else {
            let encrypted = fpe::fpe_encrypt(&profile, &formatted)
                .expect("effective domain must be sufficient");
            assert_eq!(fpe::fpe_decrypt(&profile, &encrypted).unwrap(), formatted);
        }
    }
});
