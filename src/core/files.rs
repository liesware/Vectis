use crate::error::DynError;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static WRITE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub const SENSITIVE_FILE_FORBIDDEN_MODE_BITS: u32 = 0o137;
pub const PUBLIC_FILE_FORBIDDEN_MODE_BITS: u32 = 0o022;

pub fn validate_file_mode(
    path: &Path,
    forbidden: u32,
    not_regular_message: &str,
    too_open_message: &str,
) -> Result<(), DynError> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(crate::error::invalid_input(not_regular_message));
    }
    if metadata.permissions().mode() & 0o777 & forbidden != 0 {
        return Err(crate::error::invalid_input(too_open_message));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissingFilePolicy {
    Required,
    Optional,
}

pub fn write_new_file_atomically(
    path: &Path,
    content: &[u8],
    mode: u32,
    label: &str,
) -> Result<(), DynError> {
    write_new_file_atomically_with_finalize(path, content, mode, label, |temporary_path, parent| {
        fs::remove_file(temporary_path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })
}

fn write_new_file_atomically_with_finalize<F>(
    path: &Path,
    content: &[u8],
    mode: u32,
    label: &str,
    finalize: F,
) -> Result<(), DynError>
where
    F: FnOnce(&Path, &Path) -> io::Result<()>,
{
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| crate::error::invalid_input(format!("{label} path must name a file")))?;
    let temporary_path = parent.join(format!(
        ".{}.{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        WRITE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut temporary_created = false;
    let mut destination_linked = false;
    let result = (|| -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary_path)?;
        temporary_created = true;
        file.write_all(content)?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(&temporary_path, path)?;
        destination_linked = true;
        finalize(&temporary_path, parent)?;
        Ok(())
    })();
    if let Err(error) = result {
        let mut rollback_errors = Vec::new();
        let mut removed = false;
        if destination_linked
            && let Err(err) = fs::remove_file(path)
            && err.kind() != io::ErrorKind::NotFound
        {
            rollback_errors.push(err.to_string());
        } else if destination_linked {
            removed = true;
        }
        if temporary_created
            && let Err(err) = fs::remove_file(&temporary_path)
            && err.kind() != io::ErrorKind::NotFound
        {
            rollback_errors.push(err.to_string());
        } else if temporary_created {
            removed = true;
        }
        if removed
            && let Err(err) = fs::File::open(parent).and_then(|directory| directory.sync_all())
        {
            rollback_errors.push(err.to_string());
        }
        if rollback_errors.is_empty() {
            return Err(Box::new(error));
        }
        return Err(crate::error::internal(format!(
            "{error}; atomic write rollback failed: {}",
            rollback_errors.join("; ")
        )));
    }
    Ok(())
}

pub fn remove_created_file_and_sync(path: &Path, label: &str) -> Result<(), DynError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::remove_file(path)
        .map_err(|err| crate::error::internal(format!("{label} could not be removed: {err}")))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| {
            crate::error::internal(format!(
                "{label} parent directory could not be synchronized: {err}"
            ))
        })
}

pub fn read_bounded_utf8_file(
    path: &Path,
    label: &str,
    max_size_bytes: u64,
    missing_policy: MissingFilePolicy,
) -> Result<Option<String>, DynError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return missing_file_result(label, missing_policy);
        }
        Err(_) => return Err(crate::error::internal(format!("{label} could not be read"))),
    };

    if !metadata.is_file() {
        return Err(crate::error::invalid_input(format!(
            "{label} must point to a file"
        )));
    }
    if metadata.len() > max_size_bytes {
        return Err(crate::error::invalid_input(format!(
            "{label} exceeds maximum allowed size"
        )));
    }

    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return missing_file_result(label, missing_policy);
        }
        Err(_) => return Err(crate::error::internal(format!("{label} could not be read"))),
    };
    let opened_metadata = file
        .metadata()
        .map_err(|_| crate::error::internal(format!("{label} could not be read")))?;
    if !opened_metadata.is_file() {
        return Err(crate::error::invalid_input(format!(
            "{label} must point to a file"
        )));
    }
    if opened_metadata.len() > max_size_bytes {
        return Err(crate::error::invalid_input(format!(
            "{label} exceeds maximum allowed size"
        )));
    }

    let max_read_bytes = max_size_bytes
        .checked_add(1)
        .ok_or_else(|| crate::error::internal("file size limit is invalid"))?;
    let mut bytes = Vec::new();
    file.take(max_read_bytes)
        .read_to_end(&mut bytes)
        .map_err(|_| crate::error::internal(format!("{label} could not be read")))?;
    if bytes.len() as u64 > max_size_bytes {
        return Err(crate::error::invalid_input(format!(
            "{label} exceeds maximum allowed size"
        )));
    }

    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| crate::error::invalid_input(format!("{label} is not valid UTF-8")))
}

fn missing_file_result(
    label: &str,
    missing_policy: MissingFilePolicy,
) -> Result<Option<String>, DynError> {
    match missing_policy {
        MissingFilePolicy::Required => {
            Err(crate::error::not_found(format!("{label} does not exist")))
        }
        MissingFilePolicy::Optional => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn unique_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("vectis-files-test-{}-{}", std::process::id(), name))
    }

    #[test]
    fn reads_regular_utf8_files_up_to_the_exact_limit() {
        let path = unique_path("exact");
        fs::write(&path, "abc").expect("write test file");

        assert_eq!(
            read_bounded_utf8_file(&path, "test file", 3, MissingFilePolicy::Required).unwrap(),
            Some(String::from("abc"))
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_files_over_limit_and_invalid_utf8() {
        let oversized = unique_path("oversized");
        fs::write(&oversized, "abcd").expect("write oversized test file");
        assert!(
            read_bounded_utf8_file(&oversized, "test file", 3, MissingFilePolicy::Required,)
                .is_err()
        );
        let _ = fs::remove_file(oversized);

        let invalid_utf8 = unique_path("utf8");
        fs::write(&invalid_utf8, [0xff]).expect("write invalid UTF-8 test file");
        assert!(
            read_bounded_utf8_file(&invalid_utf8, "test file", 1, MissingFilePolicy::Required,)
                .is_err()
        );
        let _ = fs::remove_file(invalid_utf8);
    }

    #[test]
    fn applies_required_and_optional_missing_policies() {
        let path = unique_path("missing");
        assert_eq!(
            read_bounded_utf8_file(&path, "test file", 1, MissingFilePolicy::Optional).unwrap(),
            None
        );
        assert!(
            read_bounded_utf8_file(&path, "test file", 1, MissingFilePolicy::Required).is_err()
        );
    }

    #[test]
    fn rejects_non_regular_files() {
        let path = unique_path("directory");
        fs::create_dir_all(&path).expect("create test directory");
        assert!(
            read_bounded_utf8_file(&path, "test file", 1, MissingFilePolicy::Required).is_err()
        );
        fs::remove_dir(path).expect("remove test directory");
    }

    fn unique_dir(name: &str) -> std::path::PathBuf {
        let path = unique_path(name);
        fs::create_dir(&path).expect("create test directory");
        path
    }

    #[test]
    fn atomic_writer_rolls_back_failure_before_temporary_removal() {
        let directory = unique_dir("atomic-pre-remove-failure");
        let path = directory.join("payload");
        let err = write_new_file_atomically_with_finalize(
            &path,
            b"sensitive",
            0o600,
            "test file",
            |_temporary_path, _parent| Err(io::Error::other("injected finalize failure")),
        )
        .expect_err("post-link failure must be returned");

        assert!(err.to_string().contains("injected finalize failure"));
        assert!(!path.exists(), "published destination must be rolled back");
        assert_eq!(
            fs::read_dir(&directory).unwrap().count(),
            0,
            "temporary file must be rolled back"
        );
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn atomic_writer_rolls_back_failure_after_temporary_removal() {
        let directory = unique_dir("atomic-post-remove-failure");
        let path = directory.join("payload");
        let err = write_new_file_atomically_with_finalize(
            &path,
            b"sensitive",
            0o600,
            "test file",
            |temporary_path, _parent| {
                fs::remove_file(temporary_path)?;
                Err(io::Error::other("injected directory sync failure"))
            },
        )
        .expect_err("post-link failure must be returned");

        assert!(err.to_string().contains("injected directory sync failure"));
        assert!(!path.exists(), "published destination must be rolled back");
        assert_eq!(
            fs::read_dir(&directory).unwrap().count(),
            0,
            "removed temporary file must stay absent"
        );
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn atomic_writer_tolerates_missing_destination_during_rollback() {
        let directory = unique_dir("atomic-destination-vanished");
        let path = directory.join("payload");
        let err = write_new_file_atomically_with_finalize(
            &path,
            b"sensitive",
            0o600,
            "test file",
            |_temporary_path, _parent| {
                fs::remove_file(&path)?;
                Err(io::Error::other(
                    "injected failure after destination vanished",
                ))
            },
        )
        .expect_err("post-link failure must be returned");

        assert!(
            err.to_string()
                .contains("injected failure after destination vanished")
        );
        assert!(
            !err.to_string().contains("rollback failed"),
            "a destination already gone must not be reported as a rollback failure"
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
