use crate::core::validation;
use crate::error::DynError;

pub const PROTOCOL_VERSION_V1: &str = "v1";
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[PROTOCOL_VERSION_V1];

pub fn validate_protocol_version(field: &str, value: &str) -> Result<(), DynError> {
    validation::validate_allowed_value(field, value, SUPPORTED_PROTOCOL_VERSIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_v1() {
        assert!(validate_protocol_version("version", PROTOCOL_VERSION_V1).is_ok());
    }

    #[test]
    fn rejects_unknown_version() {
        assert!(validate_protocol_version("version", "v2").is_err());
        assert!(validate_protocol_version("version", "").is_err());
    }
}
