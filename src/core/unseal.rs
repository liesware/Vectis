use crate::core::validation;
use crate::error::DynError;
use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tracing::info;
use zeroize::Zeroizing;

const DEFAULT_UNSEAL_KEY_FILE: &str = ".unseal_key";
const SENSITIVE_FILE_FORBIDDEN_MODE_BITS: u32 = 0o137;
const UNSEAL_KEY_FILE_PERMISSION_ERROR: &str = "unseal key file permissions are too open; allowed modes must not grant group write, execute, or any access to others";

pub fn read_unseal_key(prompt: &str) -> Result<Zeroizing<String>, DynError> {
    if let Some(key) = read_env_unseal_key()? {
        return Ok(key);
    }

    if let Some(key) = read_file_unseal_key()? {
        return Ok(key);
    }

    read_prompt_unseal_key(prompt)
}

fn read_env_unseal_key() -> Result<Option<Zeroizing<String>>, DynError> {
    match env::var("VECTIS_UNSEAL_KEY") {
        Ok(value) => {
            info!("reading init unseal key from VECTIS_UNSEAL_KEY");
            let key = Zeroizing::new(value.trim().to_string());
            validation::validate_symmetric_key("VECTIS_UNSEAL_KEY", &key, 32)?;

            Ok(Some(key))
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(crate::error::invalid_input(format!(
            "VECTIS_UNSEAL_KEY could not be read: {err}"
        ))),
    }
}

fn read_file_unseal_key() -> Result<Option<Zeroizing<String>>, DynError> {
    let (path, explicit_path) = unseal_key_file_path()?;
    match validate_unseal_key_file_permissions(&path) {
        Ok(()) => {}
        Err(err) if is_not_found(err.as_ref()) && !explicit_path => return Ok(None),
        Err(err) => return Err(err),
    }

    match fs::read_to_string(&path) {
        Ok(value) => {
            info!(path = %path.display(), "reading init unseal key from file");
            let key = Zeroizing::new(value.trim().to_string());
            validation::validate_symmetric_key("VECTIS_UNSEAL_KEY_FILE", &key, 32)?;

            Ok(Some(key))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound && !explicit_path => Ok(None),
        Err(err) => Err(Box::new(io::Error::new(
            err.kind(),
            format!(
                "VECTIS_UNSEAL_KEY_FILE could not be read from {}: {err}",
                path.display()
            ),
        ))),
    }
}

fn read_prompt_unseal_key(prompt: &str) -> Result<Zeroizing<String>, DynError> {
    info!("reading init unseal key from hidden prompt");
    let key = validation::read_hidden_text(prompt)?;
    validation::validate_symmetric_key("VECTIS_UNSEAL_KEY", &key, 32)?;

    Ok(key)
}

fn unseal_key_file_path() -> Result<(PathBuf, bool), DynError> {
    match env::var("VECTIS_UNSEAL_KEY_FILE") {
        Ok(value) => resolve_unseal_key_file_path(Some(value), None),
        Err(env::VarError::NotPresent) => {
            resolve_unseal_key_file_path(None, env_file_value("VECTIS_UNSEAL_KEY_FILE")?)
        }
        Err(err) => Err(crate::error::invalid_input(format!(
            "VECTIS_UNSEAL_KEY_FILE could not be read: {err}"
        ))),
    }
}

fn resolve_unseal_key_file_path(
    process_value: Option<String>,
    env_file_value: Option<String>,
) -> Result<(PathBuf, bool), DynError> {
    if let Some(value) = process_value {
        validation::validate_text_field("VECTIS_UNSEAL_KEY_FILE", &value)?;

        return Ok((PathBuf::from(value), true));
    }

    if let Some(value) = env_file_value {
        validation::validate_text_field("VECTIS_UNSEAL_KEY_FILE", &value)?;

        return Ok((PathBuf::from(value), true));
    }

    Ok((PathBuf::from(DEFAULT_UNSEAL_KEY_FILE), false))
}

fn validate_unseal_key_file_permissions(path: &Path) -> Result<(), DynError> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(crate::error::invalid_input(
            "unseal key file must be a regular file",
        ));
    }

    let mode = metadata.permissions().mode() & 0o777;
    if mode & SENSITIVE_FILE_FORBIDDEN_MODE_BITS != 0 {
        return Err(crate::error::invalid_input(
            UNSEAL_KEY_FILE_PERMISSION_ERROR,
        ));
    }

    Ok(())
}

fn is_not_found(err: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    err.downcast_ref::<io::Error>()
        .is_some_and(|err| err.kind() == io::ErrorKind::NotFound)
}

fn env_file_value(key: &str) -> Result<Option<String>, DynError> {
    let content = match fs::read_to_string(".env") {
        Ok(content) => content,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(Box::new(err)),
    };

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((env_key, value)) = line.split_once('=') else {
            continue;
        };

        if env_key.trim() == key {
            return Ok(Some(crate::core::config::clean_env_value(value.trim())));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const VALID_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const OTHER_VALID_KEY: &str =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    struct EnvGuard {
        vars: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn new(vars: &[&'static str]) -> Self {
            Self {
                vars: vars
                    .iter()
                    .map(|name| (*name, env::var(name).ok()))
                    .collect(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (name, value) in &self.vars {
                match value {
                    Some(value) => unsafe { env::set_var(name, value) },
                    None => unsafe { env::remove_var(name) },
                }
            }
        }
    }

    fn lock_env() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn with_isolated_env<T>(f: impl FnOnce() -> T) -> T {
        let _lock = lock_env();
        let _guard = EnvGuard::new(&["VECTIS_UNSEAL_KEY", "VECTIS_UNSEAL_KEY_FILE"]);
        unsafe {
            env::remove_var("VECTIS_UNSEAL_KEY");
            env::remove_var("VECTIS_UNSEAL_KEY_FILE");
        }

        f()
    }

    fn unique_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "vectis_unseal_test_{}_{}_{}",
            std::process::id(),
            tag,
            std::thread::current().name().unwrap_or("thread")
        ))
    }

    fn write_unseal_key_file(path: &Path, value: &str) {
        fs::write(path, value).expect("write unseal test file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("set unseal test file permissions");
    }

    #[test]
    fn env_key_wins_over_file() {
        with_isolated_env(|| {
            let path = unique_path("env_wins");
            fs::write(&path, OTHER_VALID_KEY).expect("write unseal test file");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
                .expect("set insecure unseal test file permissions");
            unsafe {
                env::set_var("VECTIS_UNSEAL_KEY", VALID_KEY);
                env::set_var("VECTIS_UNSEAL_KEY_FILE", &path);
            }

            let key = read_unseal_key("prompt:").expect("read env unseal key");
            assert_eq!(&*key, VALID_KEY);

            let _ = fs::remove_file(path);
        });
    }

    #[test]
    fn invalid_env_key_fails() {
        with_isolated_env(|| {
            unsafe { env::set_var("VECTIS_UNSEAL_KEY", "not-hex") };

            assert!(read_unseal_key("prompt:").is_err());
        });
    }

    #[test]
    fn explicit_file_key_works() {
        with_isolated_env(|| {
            let path = unique_path("file_works");
            write_unseal_key_file(&path, VALID_KEY);
            unsafe { env::set_var("VECTIS_UNSEAL_KEY_FILE", &path) };

            let key = read_file_unseal_key()
                .expect("read explicit file")
                .expect("explicit file key");
            assert_eq!(&*key, VALID_KEY);

            let _ = fs::remove_file(path);
        });
    }

    #[test]
    fn explicit_file_key_rejects_insecure_permissions() {
        with_isolated_env(|| {
            let path = unique_path("file_insecure_permissions");
            fs::write(&path, VALID_KEY).expect("write unseal test file");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
                .expect("set insecure unseal test file permissions");
            unsafe { env::set_var("VECTIS_UNSEAL_KEY_FILE", &path) };

            let err = read_file_unseal_key().expect_err("insecure file permissions must fail");
            assert!(
                err.to_string()
                    .contains("unseal key file permissions are too open")
            );

            let _ = fs::remove_file(path);
        });
    }

    #[test]
    fn explicit_file_key_allows_group_readable_permissions() {
        with_isolated_env(|| {
            let path = unique_path("file_group_readable");
            fs::write(&path, VALID_KEY).expect("write unseal test file");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
                .expect("set group-readable unseal test file permissions");
            unsafe { env::set_var("VECTIS_UNSEAL_KEY_FILE", &path) };

            let key = read_file_unseal_key()
                .expect("read explicit file")
                .expect("explicit file key");
            assert_eq!(&*key, VALID_KEY);

            let _ = fs::remove_file(path);
        });
    }

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

    #[test]
    fn explicit_missing_file_fails() {
        with_isolated_env(|| {
            let path = unique_path("missing");
            unsafe { env::set_var("VECTIS_UNSEAL_KEY_FILE", &path) };

            assert!(read_file_unseal_key().is_err());
        });
    }

    #[test]
    fn default_file_path_is_not_explicit() {
        with_isolated_env(|| {
            let (path, explicit) = resolve_unseal_key_file_path(None, None).expect("default path");

            assert_eq!(path, PathBuf::from(DEFAULT_UNSEAL_KEY_FILE));
            assert!(!explicit);
        });
    }

    #[test]
    fn invalid_file_key_fails() {
        with_isolated_env(|| {
            let path = unique_path("invalid_file");
            write_unseal_key_file(&path, "not-hex");
            unsafe { env::set_var("VECTIS_UNSEAL_KEY_FILE", &path) };

            assert!(read_file_unseal_key().is_err());

            let _ = fs::remove_file(path);
        });
    }

    #[test]
    fn unseal_key_is_not_read_from_env_file() {
        with_isolated_env(|| {
            let key = read_env_unseal_key().expect("env provider read");

            assert!(key.is_none());
        });
    }
}
