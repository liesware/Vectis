use crate::core::validation;
use crate::error::DynError;
use crate::ops;
use std::fs;
use tracing::info;

const INIT_OUTPUT_PATH: &str = "init.json";

pub fn run_init() -> Result<String, DynError> {
    let output = ops::init::create_encrypted_init_output_json()?;

    fs::write(INIT_OUTPUT_PATH, output.json)?;
    info!(path = INIT_OUTPUT_PATH, "init keys written");
    println!("VECTIS_UNSEAL_KEY={}", &*output.encryption_key_hex);
    println!("VECTIS_APIKEY={}", &*output.api_key);
    println!("VECTIS_APIKEY_HASH={}", &*output.api_key_hash);
    println!("\n* VECTIS_UNSEAL_KEY should be an env var, after init it must be unset.");
    println!(
        "* VECTIS_APIKEY is the client secret. VECTIS_APIKEY_HASH is the server-side value for protected endpoints."
    );

    Ok(INIT_OUTPUT_PATH.to_string())
}

pub fn load_init_state() -> Result<ops::init::ValidatedInitState, DynError> {
    let key_hex = validation::read_unseal_key("VECTIS_UNSEAL_KEY:")?;
    let encrypted_json = fs::read_to_string(INIT_OUTPUT_PATH)?;
    let init_state = ops::init::load_validated_init_state(&encrypted_json, &key_hex)?;

    info!(path = INIT_OUTPUT_PATH, "init keys validated");

    Ok(init_state)
}
