use super::error::{ErrorResponse, public_error_message};
use crate::core::{config, validation};
use axum::Json;
use axum::http::{HeaderMap, StatusCode, header};

pub fn authorize_api_key(headers: &HeaderMap) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let config = config::app_config().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(public_error_message(
                StatusCode::INTERNAL_SERVER_ERROR,
            ))),
        )
    })?;

    if config.api_key.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(public_error_message(
                StatusCode::UNAUTHORIZED,
            ))),
        ));
    }

    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(public_error_message(
                StatusCode::UNAUTHORIZED,
            ))),
        ));
    };

    let Ok(value) = value.to_str() else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(public_error_message(
                StatusCode::UNAUTHORIZED,
            ))),
        ));
    };

    if validation::validate_hash_hex_field("Authorization", value, config::INTERNAL_KEYS_HASH)
        .is_err()
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(public_error_message(
                StatusCode::UNAUTHORIZED,
            ))),
        ));
    }

    if value != config.api_key {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(public_error_message(
                StatusCode::UNAUTHORIZED,
            ))),
        ));
    }

    Ok(())
}
