use crate::core::config;
use crate::error::DynError;
use crate::ops::init::ValidatedInitState;
use crate::ops::key_validation::{KeyValidationOutput, validate_key_material};
use crate::ops::keys;
use crate::ops::keys::KeysDbState;

pub type TestOutput = KeyValidationOutput;

pub async fn handle_test(
    init_state: &ValidatedInitState,
    id: &str,
) -> Result<TestOutput, DynError> {
    let loaded_key = keys::load_keys_db_entry(init_state, id).await?;
    build_test_output(loaded_key.key_material(), loaded_key.aad())
}

pub fn handle_test_from_state(
    keys_db_state: &KeysDbState,
    id: &str,
) -> Result<TestOutput, DynError> {
    let loaded_key = keys::get_loaded_key(keys_db_state, id)?;

    build_test_output(loaded_key.key_material(), loaded_key.aad())
}

fn build_test_output(
    key_material: &keys::OpsKeysOutput,
    aad: &str,
) -> Result<TestOutput, DynError> {
    let config = config::app_config()?;
    let message = config.plaintext_message;

    validate_key_material(key_material, aad, &message)
}
