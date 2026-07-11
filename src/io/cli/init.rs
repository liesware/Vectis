use crate::core::{config, unseal};
use crate::error::DynError;
use crate::ops;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use tracing::info;

const SENSITIVE_FILE_FORBIDDEN_MODE_BITS: u32 = 0o137;
const INIT_KEYS_FILE_PERMISSION_ERROR: &str = "init keys file permissions are too open; allowed modes must not grant group write, execute, or any access to others";

pub fn run_init() -> Result<String, DynError> {
    let init_keys_path = config::init_keys_file_path()?;
    if init_keys_path.try_exists()? {
        return Err(crate::error::invalid_input(
            "init keys file already exists; refusing to overwrite existing init material; delete it manually before running init again",
        ));
    }

    let output = ops::init::create_encrypted_init_output_json()?;

    let mut init_keys_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&init_keys_path)
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                crate::error::invalid_input(
                    "init keys file already exists; refusing to overwrite existing init material; delete it manually before running init again",
                )
            } else {
                Box::new(err) as DynError
            }
        })?;
    init_keys_file.write_all(output.json.as_bytes())?;
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
    validate_init_keys_file_permissions(&init_keys_path)?;
    let encrypted_json = fs::read_to_string(&init_keys_path)?;
    let init_state = ops::init::load_validated_init_state(&encrypted_json, &key_hex)?;

    info!(path = %init_keys_path.display(), "init keys validated");

    Ok(init_state)
}

fn validate_init_keys_file_permissions(path: &Path) -> Result<(), DynError> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(crate::error::invalid_input(
            "init keys file must be a regular file",
        ));
    }

    let mode = metadata.permissions().mode() & 0o777;
    if mode & SENSITIVE_FILE_FORBIDDEN_MODE_BITS != 0 {
        return Err(crate::error::invalid_input(INIT_KEYS_FILE_PERMISSION_ERROR));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_file_modes_allow_owner_and_group_read() {
        for mode in [0o600, 0o400, 0o640, 0o440] {
            assert_eq!(mode & SENSITIVE_FILE_FORBIDDEN_MODE_BITS, 0);
        }
    }

    #[test]
    fn sensitive_file_modes_reject_group_write_others_or_execute() {
        for mode in [0o644, 0o660, 0o700, 0o750, 0o604, 0o610] {
            assert_ne!(mode & SENSITIVE_FILE_FORBIDDEN_MODE_BITS, 0);
        }
    }
}
