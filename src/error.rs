use std::error::Error;
use std::io;

pub type DynError = Box<dyn Error + Send + Sync>;

pub const UNTRUSTED_ERROR_DETAIL_MAX_CHARS: usize = 256;
const SANITIZED_SERDE_FALLBACK: &str = "invalid JSON";

#[derive(Debug, thiserror::Error)]
pub enum VectisError {
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    InvalidSignature(String),
    #[error("{0}")]
    ConfigSignatureStale(String),
    #[error("{0}")]
    RemoteUnreachable(String),
    #[error("{0}")]
    Storage(String),
    #[error("{0}")]
    Internal(String),
}

pub fn invalid_input(message: impl Into<String>) -> DynError {
    Box::new(VectisError::InvalidInput(message.into()))
}

pub fn not_found(message: impl Into<String>) -> DynError {
    Box::new(VectisError::NotFound(message.into()))
}

pub fn forbidden(message: impl Into<String>) -> DynError {
    Box::new(VectisError::Forbidden(message.into()))
}

pub fn invalid_signature(message: impl Into<String>) -> DynError {
    Box::new(VectisError::InvalidSignature(message.into()))
}

pub fn config_signature_stale(message: impl Into<String>) -> DynError {
    Box::new(VectisError::ConfigSignatureStale(message.into()))
}

pub fn remote_unreachable(message: impl Into<String>) -> DynError {
    Box::new(VectisError::RemoteUnreachable(message.into()))
}

pub fn storage(message: impl Into<String>) -> DynError {
    Box::new(VectisError::Storage(message.into()))
}

pub fn internal(message: impl Into<String>) -> DynError {
    Box::new(VectisError::Internal(message.into()))
}

/// Returns a bounded diagnostic for a Serde error without reflecting caller values.
///
/// Field names, expected shapes, and line/column information are useful to callers.
/// Values supplied by the caller are not: they may be sensitive or contain controls.
pub fn sanitized_serde_json_error_detail(error: &serde_json::Error) -> String {
    sanitize_untrusted_error_detail(&redact_serde_value(&error.to_string()))
}

pub fn invalid_json_input(context: &str, error: &serde_json::Error) -> DynError {
    invalid_input(format!(
        "{context}: {}",
        sanitized_serde_json_error_detail(error)
    ))
}

pub(crate) fn sanitize_untrusted_error_detail(detail: &str) -> String {
    let cleaned: String = detail
        .chars()
        .filter(|character| !character.is_control())
        .collect();
    let bounded: String = cleaned
        .chars()
        .take(UNTRUSTED_ERROR_DETAIL_MAX_CHARS)
        .collect();

    if bounded.trim().is_empty() {
        String::from(SANITIZED_SERDE_FALLBACK)
    } else {
        bounded
    }
}

fn redact_serde_value(message: &str) -> String {
    let markers = ["invalid type: ", "invalid value: "];
    let Some(value_region_start) = markers
        .iter()
        .filter_map(|marker| message.find(marker).map(|position| position + marker.len()))
        .min()
    else {
        return String::from(message);
    };

    let value_region = &message[value_region_start..];
    let Some((open_offset, delimiter)) = value_region
        .char_indices()
        .find(|&(_, character)| character == '`' || character == '"')
    else {
        return String::from(message);
    };

    let after_open = &value_region[open_offset + delimiter.len_utf8()..];
    let Some(close_offset) = after_open.find(delimiter) else {
        return String::from(message);
    };

    let value_start = value_region_start + open_offset;
    let value_end = value_start + delimiter.len_utf8() + close_offset + delimiter.len_utf8();
    let prefix = message[..value_start].trim_end();

    format!("{prefix}{}", &message[value_end..])
}

pub fn with_prefix(prefix: &str, err: DynError) -> DynError {
    match err.downcast_ref::<VectisError>() {
        Some(VectisError::InvalidInput(message)) => invalid_input(format!("{prefix}: {message}")),
        Some(VectisError::NotFound(message)) => not_found(format!("{prefix}: {message}")),
        Some(VectisError::Forbidden(message)) => forbidden(format!("{prefix}: {message}")),
        Some(VectisError::InvalidSignature(message)) => {
            invalid_signature(format!("{prefix}: {message}"))
        }
        Some(VectisError::ConfigSignatureStale(message)) => {
            config_signature_stale(format!("{prefix}: {message}"))
        }
        Some(VectisError::RemoteUnreachable(message)) => {
            remote_unreachable(format!("{prefix}: {message}"))
        }
        Some(VectisError::Storage(message)) => storage(format!("{prefix}: {message}")),
        Some(VectisError::Internal(message)) => internal(format!("{prefix}: {message}")),
        None => internal(format!("{prefix}: {err}")),
    }
}

pub fn is_config_signature_stale(err: &(dyn Error + Send + Sync + 'static)) -> bool {
    matches!(
        err.downcast_ref::<VectisError>(),
        Some(VectisError::ConfigSignatureStale(_))
    )
}

pub fn is_not_found(err: &(dyn Error + Send + Sync + 'static)) -> bool {
    if matches!(
        err.downcast_ref::<VectisError>(),
        Some(VectisError::NotFound(_))
    ) {
        return true;
    }

    err.downcast_ref::<io::Error>()
        .is_some_and(|err| err.kind() == io::ErrorKind::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitized_serde_detail_removes_control_characters_from_field_names() {
        let error = serde_json::from_str::<serde_json::Value>("{\"field\\u007f\":}")
            .expect_err("JSON must fail");
        let detail = sanitized_serde_json_error_detail(&error);

        assert!(!detail.chars().any(char::is_control));
    }

    #[test]
    fn sanitized_serde_detail_redacts_type_values() {
        let error = serde_json::from_str::<String>("4111111111111111")
            .expect_err("number must not deserialize as a string");
        let detail = sanitized_serde_json_error_detail(&error);

        assert!(!detail.contains("4111111111111111"));
    }

    #[test]
    fn untrusted_error_detail_is_bounded_and_uses_fallback() {
        assert_eq!(
            sanitize_untrusted_error_detail("\u{7f}\n\r"),
            "invalid JSON"
        );
        assert_eq!(
            sanitize_untrusted_error_detail(&"x".repeat(UNTRUSTED_ERROR_DETAIL_MAX_CHARS + 1))
                .chars()
                .count(),
            UNTRUSTED_ERROR_DETAIL_MAX_CHARS
        );
    }
}
