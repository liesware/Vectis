use crate::error::DynError;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissingFilePolicy {
    Required,
    Optional,
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
}
