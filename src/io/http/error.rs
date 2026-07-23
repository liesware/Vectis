use crate::core::{audit, metrics};
use crate::error::VectisError;
use axum::Json;
use axum::http::StatusCode;
use serde::Serialize;
use std::io;
use tracing::{error, warn};

const MAX_ERROR_MESSAGE_CHARS: usize = 256;

#[derive(Serialize)]
pub struct ErrorResponse {
    error: String,
}

impl ErrorResponse {
    pub fn new(error: String) -> Self {
        Self {
            error: sanitize_error_message(&error),
        }
    }
}

fn sanitize_error_message(message: &str) -> String {
    let sanitized: String = message
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_ERROR_MESSAGE_CHARS)
        .collect();

    if sanitized.is_empty() {
        String::from("request rejected")
    } else {
        sanitized
    }
}

pub fn crypto_failed_response(
    event: &str,
    actor: Option<&audit::Actor<'_>>,
    kid: Option<&str>,
    action: Option<&str>,
    operation: &str,
    err: &(dyn std::error::Error + Send + Sync + 'static),
) -> (StatusCode, Json<ErrorResponse>) {
    audit::operation_failed(event, actor, kid, None, action, &err.to_string());
    metrics::record_crypto_operation(operation, "failed");
    error_response(err)
}

pub fn error_response(
    err: &(dyn std::error::Error + 'static),
) -> (StatusCode, Json<ErrorResponse>) {
    let status = status_for_error(err);
    log_internal_error(status, err);

    (
        status,
        Json(ErrorResponse::new(public_error_message_for_error(
            status, err,
        ))),
    )
}

fn log_internal_error(status: StatusCode, err: &(dyn std::error::Error + 'static)) {
    if status.is_server_error() {
        error!(
            status = status.as_u16(),
            error = %err,
            "http request failed"
        );
    } else {
        warn!(
            status = status.as_u16(),
            error = %err,
            "http request rejected"
        );
    }
}

pub fn status_for_error(err: &(dyn std::error::Error + 'static)) -> StatusCode {
    if let Some(vectis_err) = err.downcast_ref::<VectisError>() {
        return match vectis_err {
            VectisError::InvalidInput(_)
            | VectisError::InvalidSignature(_)
            | VectisError::ConfigSignatureStale(_) => StatusCode::BAD_REQUEST,
            VectisError::NotFound(_) => StatusCode::NOT_FOUND,
            VectisError::Forbidden(_) => StatusCode::FORBIDDEN,
            VectisError::RemoteUnreachable(_)
            | VectisError::Storage(_)
            | VectisError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
    }

    let Some(io_err) = err.downcast_ref::<io::Error>() else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    };

    match io_err.kind() {
        io::ErrorKind::InvalidInput => StatusCode::BAD_REQUEST,
        io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
        io::ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub fn public_error_message(status: StatusCode) -> String {
    match status {
        StatusCode::BAD_REQUEST => String::from("invalid request"),
        StatusCode::UNAUTHORIZED => String::from("unauthorized"),
        StatusCode::FORBIDDEN => String::from("forbidden"),
        StatusCode::NOT_FOUND => String::from("not found"),
        _ => String::from("internal server error"),
    }
}

fn public_error_message_for_error(
    status: StatusCode,
    err: &(dyn std::error::Error + 'static),
) -> String {
    if status == StatusCode::BAD_REQUEST || status == StatusCode::FORBIDDEN {
        return err.to_string();
    }

    match err.downcast_ref::<VectisError>() {
        Some(VectisError::NotFound(message)) => message.clone(),
        Some(VectisError::RemoteUnreachable(_)) => {
            String::from("internal server error final app can't be reached")
        }
        _ => public_error_message(status),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_control_chars() {
        let dirty = "unexpected field: \u{1d}#\u{8a}\u{98}value";
        let clean = sanitize_error_message(dirty);
        assert!(!clean.chars().any(|c| c.is_control()));
        assert_eq!(clean, "unexpected field: #value");
    }

    #[test]
    fn sanitize_keeps_non_control_unicode() {
        assert_eq!(sanitize_error_message("clé à 🔥"), "clé à 🔥");
    }

    #[test]
    fn sanitize_caps_length() {
        let long = "a".repeat(1000);
        assert_eq!(
            sanitize_error_message(&long).chars().count(),
            MAX_ERROR_MESSAGE_CHARS
        );
    }

    #[test]
    fn sanitize_falls_back_when_empty() {
        assert_eq!(
            sanitize_error_message("\u{0}\u{1f}\u{7f}"),
            "request rejected"
        );
        assert_eq!(sanitize_error_message(""), "request rejected");
    }

    #[test]
    fn new_error_response_is_sanitized() {
        let response = ErrorResponse::new(String::from("bad \u{1d}field"));
        assert_eq!(response.error, "bad field");
    }

    #[test]
    fn maps_vectis_variants_to_status() {
        assert_eq!(
            status_for_error(&VectisError::InvalidInput(String::from("x"))),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_for_error(&VectisError::InvalidSignature(String::from("x"))),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_for_error(&VectisError::NotFound(String::from("x"))),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status_for_error(&VectisError::Forbidden(String::from("x"))),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status_for_error(&VectisError::RemoteUnreachable(String::from("x"))),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            status_for_error(&VectisError::Storage(String::from("x"))),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn io_errors_keep_fallback_mapping() {
        let err = io::Error::new(io::ErrorKind::NotFound, "gone");
        assert_eq!(status_for_error(&err), StatusCode::NOT_FOUND);
        let err = io::Error::other("boom");
        assert_eq!(status_for_error(&err), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn remote_unreachable_hides_detail() {
        let err = VectisError::RemoteUnreachable(String::from(
            "final app can't be reached: addr=10.0.0.1:9,path=/x",
        ));
        assert_eq!(
            public_error_message_for_error(StatusCode::INTERNAL_SERVER_ERROR, &err),
            "internal server error final app can't be reached"
        );
    }

    #[test]
    fn internal_error_returns_generic_message() {
        let err = VectisError::Internal(String::from("secret detail"));
        assert_eq!(
            public_error_message_for_error(StatusCode::INTERNAL_SERVER_ERROR, &err),
            "internal server error"
        );
    }
}
