use crate::core::{config, files, unseal};
use crate::error::DynError;
use crate::io::cli::sensitive;
use crate::ops;
use std::path::Path;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

const INIT_KEYS_FILE_PERMISSION_ERROR: &str = "init keys file permissions are too open; allowed modes must not grant group write, execute, or any access to others";
const INIT_PUBLIC_KEYS_FILE_PERMISSION_ERROR: &str =
    "init public keys file permissions are too open; group and others must not have write access";
#[cfg(test)]
static INIT_WRITE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn run_init() -> Result<String, DynError> {
    let init_keys_path = config::init_keys_file_path()?;
    let init_public_keys_path = config::init_public_keys_file_path()?;
    if init_keys_path == init_public_keys_path {
        return Err(crate::error::invalid_input(
            "VECTIS_INIT_KEYS_FILE and VECTIS_INIT_PUBLIC_KEYS_FILE must use different paths",
        ));
    }
    if init_keys_path.try_exists()? || init_public_keys_path.try_exists()? {
        return Err(crate::error::invalid_input(
            "init keys files already exist; refusing to overwrite existing init material; delete both files manually before running init again",
        ));
    }

    let output = ops::init::create_encrypted_init_output_json()?;
    write_init_files(
        &init_keys_path,
        &output.json,
        &init_public_keys_path,
        &output.public_json,
    )?;
    info!(path = %init_keys_path.display(), "init keys written");
    info!(path = %init_public_keys_path.display(), "init public keys written");
    sensitive::warn_if_stdout_is_terminal();
    println!(
        "VECTIS_INIT_PUBLIC_KEYS_FILE={}",
        init_public_keys_path.display()
    );
    println!("VECTIS_UNSEAL_KEY={}", *output.encryption_key_hex);
    println!("VECTIS_APIKEY={}", *output.api_key);
    println!("VECTIS_APIKEY_HASH={}", *output.api_key_hash);
    println!("\n* VECTIS_UNSEAL_KEY should be an env var, after init it must be unset.");
    println!(
        "* VECTIS_APIKEY is the client secret. VECTIS_APIKEY_HASH is the server-side value for protected endpoints."
    );

    Ok(init_keys_path.display().to_string())
}

pub fn run_init_public() -> Result<String, DynError> {
    let init_keys_path = config::init_keys_file_path()?;
    let init_public_keys_path = config::init_public_keys_file_path()?;
    if init_keys_path == init_public_keys_path {
        return Err(crate::error::invalid_input(
            "VECTIS_INIT_KEYS_FILE and VECTIS_INIT_PUBLIC_KEYS_FILE must use different paths",
        ));
    }
    if init_public_keys_path.try_exists()? {
        return Err(crate::error::invalid_input(
            "init public keys file already exists; refusing to overwrite verification material; delete it manually before regenerating",
        ));
    }

    let init_state = load_init_state()?;
    let public_json = ops::init::init_public_keys_json(&init_state)?;
    write_new_file_atomically(&init_public_keys_path, &public_json, 0o644)?;
    info!(path = %init_public_keys_path.display(), "init public keys regenerated");

    Ok(init_public_keys_path.display().to_string())
}

fn write_init_files(
    init_keys_path: &Path,
    init_keys_json: &str,
    init_public_keys_path: &Path,
    init_public_keys_json: &str,
) -> Result<(), DynError> {
    write_new_file_atomically(init_keys_path, init_keys_json, 0o600)?;
    if let Err(err) = write_new_file_atomically(init_public_keys_path, init_public_keys_json, 0o644)
    {
        return Err(with_rollback_result(
            err,
            files::remove_created_file_and_sync(init_keys_path, "init key file"),
        ));
    }

    Ok(())
}

fn write_new_file_atomically(path: &Path, content: &str, mode: u32) -> Result<(), DynError> {
    files::write_new_file_atomically(path, content.as_bytes(), mode, "init key file")
}

fn with_rollback_result(operation_error: DynError, rollback: Result<(), DynError>) -> DynError {
    match rollback {
        Ok(()) => operation_error,
        Err(rollback_error) => crate::error::internal(format!(
            "{operation_error}; rollback failed: {rollback_error}"
        )),
    }
}

pub fn load_init_state() -> Result<ops::init::ValidatedInitState, DynError> {
    let init_keys_path = config::init_keys_file_path()?;
    let key_hex = unseal::read_unseal_key("VECTIS_UNSEAL_KEY:")?;
    validate_init_keys_file_permissions(&init_keys_path)?;
    let encrypted_json = read_init_keys_file(&init_keys_path)?;
    let init_state = ops::init::load_validated_init_state(&encrypted_json, &key_hex)?;

    info!(path = %init_keys_path.display(), "init keys validated");

    Ok(init_state)
}

pub fn load_init_public_state() -> Result<ops::init::ValidatedInitPublicState, DynError> {
    let init_public_keys_path = config::init_public_keys_file_path()?;
    validate_init_public_keys_file_permissions(&init_public_keys_path)?;
    let public_json = read_init_public_keys_file(&init_public_keys_path)?;
    let init_state = ops::init::load_validated_init_public_state(&public_json)?;

    info!(path = %init_public_keys_path.display(), "init public keys validated");

    Ok(init_state)
}

fn read_init_keys_file(path: &Path) -> Result<String, DynError> {
    files::read_bounded_utf8_file(
        path,
        "init keys file",
        config::INIT_KEYS_FILE_MAX_SIZE_BYTES,
        files::MissingFilePolicy::Required,
    )?
    .ok_or_else(|| crate::error::internal("required init keys file unexpectedly absent"))
}

fn read_init_public_keys_file(path: &Path) -> Result<String, DynError> {
    files::read_bounded_utf8_file(
        path,
        "init public keys file",
        config::INIT_PUBLIC_KEYS_FILE_MAX_SIZE_BYTES,
        files::MissingFilePolicy::Required,
    )?
    .ok_or_else(|| crate::error::internal("required init public keys file unexpectedly absent"))
}

fn validate_init_keys_file_permissions(path: &Path) -> Result<(), DynError> {
    files::validate_file_mode(
        path,
        files::SENSITIVE_FILE_FORBIDDEN_MODE_BITS,
        "init keys file must be a regular file",
        INIT_KEYS_FILE_PERMISSION_ERROR,
    )
}

fn validate_init_public_keys_file_permissions(path: &Path) -> Result<(), DynError> {
    files::validate_file_mode(
        path,
        files::PUBLIC_FILE_FORBIDDEN_MODE_BITS,
        "init public keys file must be a regular file",
        INIT_PUBLIC_KEYS_FILE_PERMISSION_ERROR,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_directory(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "vectis-{name}-{}-{}",
            std::process::id(),
            INIT_WRITE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).expect("test directory must be created");
        path
    }

    #[test]
    fn sensitive_file_modes_allow_owner_and_group_read() {
        for mode in [0o600, 0o400, 0o640, 0o440] {
            assert_eq!(mode & files::SENSITIVE_FILE_FORBIDDEN_MODE_BITS, 0);
        }
    }

    #[test]
    fn sensitive_file_modes_reject_group_write_others_or_execute() {
        for mode in [0o644, 0o660, 0o700, 0o750, 0o604, 0o610] {
            assert_ne!(mode & files::SENSITIVE_FILE_FORBIDDEN_MODE_BITS, 0);
        }
    }

    #[test]
    fn public_file_modes_allow_reads_but_reject_non_owner_writes() {
        for mode in [0o644, 0o640, 0o444] {
            assert_eq!(mode & files::PUBLIC_FILE_FORBIDDEN_MODE_BITS, 0);
        }
        for mode in [0o664, 0o646, 0o666] {
            assert_ne!(mode & files::PUBLIC_FILE_FORBIDDEN_MODE_BITS, 0);
        }
    }

    #[test]
    fn new_init_file_writer_never_overwrites_existing_file() {
        let directory = test_directory("init-public-write-test");
        let path = directory.join("init_pub.json");
        write_new_file_atomically(&path, "first", 0o644).expect("first write succeeds");
        assert!(write_new_file_atomically(&path, "second", 0o644).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "first");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn init_file_pair_rolls_back_private_file_without_removing_existing_public_file() {
        let directory = test_directory("init-pair-rollback");
        let init_keys_path = directory.join("init.json");
        let init_public_keys_path = directory.join("init_pub.json");
        fs::write(&init_public_keys_path, "existing public material").unwrap();

        assert!(
            write_init_files(
                &init_keys_path,
                "private material",
                &init_public_keys_path,
                "new public material",
            )
            .is_err()
        );
        assert!(
            !init_keys_path.exists(),
            "private file must be removed when public creation fails"
        );
        assert_eq!(
            fs::read_to_string(&init_public_keys_path).unwrap(),
            "existing public material",
            "pre-existing public file must not be removed or replaced"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn init_keys_file_rejects_content_over_limit() {
        let path =
            std::env::temp_dir().join(format!("vectis-init-size-test-{}", std::process::id()));
        fs::write(
            &path,
            "a".repeat((config::INIT_KEYS_FILE_MAX_SIZE_BYTES + 1) as usize),
        )
        .expect("write oversized init file");

        assert!(read_init_keys_file(&path).is_err());
        let _ = fs::remove_file(path);
    }
}
