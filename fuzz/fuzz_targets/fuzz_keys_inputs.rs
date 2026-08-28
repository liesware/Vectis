#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use std::sync::LazyLock;
use vectis::core::config::AppConfig;
use vectis::ops::keys;

#[allow(dead_code)]
#[path = "common.rs"]
mod common;
#[path = "input_common.rs"]
mod input_common;
use input_common::assert_public_error_is_clean;

static PROFILE_ONLY_CONFIG: LazyLock<AppConfig> = LazyLock::new(common::fuzz_config);
static ALLOW_OVERRIDES_CONFIG: LazyLock<AppConfig> = LazyLock::new(|| {
    let mut config = common::fuzz_config();
    config.crypto_policy = String::from("allow-overrides");
    config
});

fn validate_create_input(value: Value, config: &AppConfig) {
    assert_public_error_is_clean(
        keys::parse_create_keys_input(value)
            .and_then(|input| keys::validate_create_keys_input(config, input)),
    );
}

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    validate_create_input(value.clone(), &PROFILE_ONLY_CONFIG);
    validate_create_input(value.clone(), &ALLOW_OVERRIDES_CONFIG);
    assert_public_error_is_clean(keys::parse_update_lifecycle_input(value));
});
