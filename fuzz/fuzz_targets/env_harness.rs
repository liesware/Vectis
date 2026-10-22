use vectis::core::config::{ENV_FILE_MAX_SIZE_BYTES, validate_env_file_content};

use crate::config_checks as checks;

pub fn exercise(data: &[u8]) {
    // Fixed invalid syntax cannot be repaired by mutated bytes.
    for text in [
        format!("VECTIS_BAD-NAME={}", checks::CANARY),
        format!("VECTIS_LOG_LEVEL='{}", checks::CANARY),
    ] {
        checks::rejected(validate_env_file_content(&text));
    }
    if let Ok(content) = std::str::from_utf8(data) {
        let result = checks::checked(validate_env_file_content(content));
        if data.len() as u64 > ENV_FILE_MAX_SIZE_BYTES {
            assert!(result.is_err(), "oversized env file was accepted");
        }
    }
}
