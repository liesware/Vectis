use axum::Json;
use axum::http::StatusCode;
use serde::Serialize;
use std::io;
use tracing::{error, warn};

#[derive(Serialize)]
pub struct ErrorResponse {
    error: String,
}

impl ErrorResponse {
    pub fn new(error: String) -> Self {
        Self { error }
    }
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
    let Some(io_err) = err.downcast_ref::<io::Error>() else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    };

    match io_err.kind() {
        io::ErrorKind::InvalidInput => StatusCode::BAD_REQUEST,
        io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub fn public_error_message(status: StatusCode) -> String {
    match status {
        StatusCode::BAD_REQUEST => String::from("invalid request"),
        StatusCode::UNAUTHORIZED => String::from("unauthorized"),
        StatusCode::NOT_FOUND => String::from("not found"),
        _ => String::from("internal server error"),
    }
}

fn public_error_message_for_error(
    status: StatusCode,
    err: &(dyn std::error::Error + 'static),
) -> String {
    let detail = err.to_string();

    if detail.contains("recipient_kid not found in remote /pub response") {
        return String::from("recipent kid not found");
    }

    if detail.contains("recipient can't be reached") {
        return String::from("internal server error final app can't be reached");
    }

    if detail.contains("final app can't be reached") {
        return String::from("internal server error final app can't be reached");
    }

    public_error_message(status)
}
