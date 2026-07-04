use crate::core::config;
use crate::error::DynError;
use crate::ops::key_validation::{KeyValidationOutput, validate_key_material};
use crate::ops::keys;
use crate::ops::keys::KeysDbState;

pub type TestOutput = KeyValidationOutput;

pub fn handle_test_from_state(
    config: &config::AppConfig,
    keys_db_state: &KeysDbState,
    id: &str,
) -> Result<TestOutput, DynError> {
    let loaded_key = keys::get_loaded_key(keys_db_state, id)?;
    keys::require_lifecycle_for_new_use(&loaded_key)?;

    build_test_output(config, loaded_key.key_material(), loaded_key.aad())
}

fn build_test_output(
    config: &config::AppConfig,
    key_material: &keys::OpsKeysOutput,
    aad: &str,
) -> Result<TestOutput, DynError> {
    validate_key_material(config, key_material, aad, &config.plaintext_message)
}
