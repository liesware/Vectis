use crate::core::{config, unseal};
use crate::error::DynError;
use crate::ops;
use std::fs;
use tracing::info;

pub fn run_init() -> Result<String, DynError> {
    let init_keys_path = config::init_keys_file_path()?;
    if init_keys_path.try_exists()? {
        return Err(crate::error::invalid_input(
            "init keys file already exists; refusing to overwrite existing init material; delete it manually before running init again",
        ));
    }

    let output = ops::init::create_encrypted_init_output_json()?;

    fs::write(&init_keys_path, output.json)?;
    info!(path = %init_keys_path.display(), "init keys written");
    println!("VECTIS_UNSEAL_KEY={}", &*output.encryption_key_hex);
    println!("VECTIS_APIKEY={}", &*output.api_key);
    println!("VECTIS_APIKEY_HASH={}", &*output.api_key_hash);
    println!("\n* VECTIS_UNSEAL_KEY should be an env var, after init it must be unset.");
    println!(
        "* VECTIS_APIKEY is the client secret. VECTIS_APIKEY_HASH is the server-side value for protected endpoints."
    );

    Ok(init_keys_path.display().to_string())
}

pub fn load_init_state() -> Result<ops::init::ValidatedInitState, DynError> {
    let init_keys_path = config::init_keys_file_path()?;
    let key_hex = unseal::read_unseal_key("VECTIS_UNSEAL_KEY:")?;
    let encrypted_json = fs::read_to_string(&init_keys_path)?;
    let init_state = ops::init::load_validated_init_state(&encrypted_json, &key_hex)?;

    info!(path = %init_keys_path.display(), "init keys validated");

    Ok(init_state)
}
