use super::error::{ErrorResponse, public_error_message};
use crate::core::{config, crypto, validation};
use crate::ops::internal_keys::InternalDerivedKeysState;
use axum::Json;
use axum::http::{HeaderMap, HeaderName, StatusCode};

const API_KEY_HEADER: HeaderName = HeaderName::from_static("x-api-key");

pub fn authorize_api_key(
    headers: &HeaderMap,
    internal_keys: &InternalDerivedKeysState,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let config = config::app_config().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(public_error_message(
                StatusCode::INTERNAL_SERVER_ERROR,
            ))),
        )
    })?;

    if config.api_key_hash.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(public_error_message(
                StatusCode::UNAUTHORIZED,
            ))),
        ));
    }

    let Some(value) = headers.get(API_KEY_HEADER) else {
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

    if validation::validate_hash_hex_field("X-API-Key", value, config::INTERNAL_KEYS_HASH).is_err()
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(public_error_message(
                StatusCode::UNAUTHORIZED,
            ))),
        ));
    }

    let candidate_hash = internal_keys.api_key_hash(value).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(public_error_message(
                StatusCode::UNAUTHORIZED,
            ))),
        )
    })?;
    let expected_hash = hex::decode(&config.api_key_hash).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(public_error_message(
                StatusCode::UNAUTHORIZED,
            ))),
        )
    })?;
    let candidate_hash = hex::decode(candidate_hash).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(public_error_message(
                StatusCode::UNAUTHORIZED,
            ))),
        )
    })?;

    if !crypto::constant_time_eq(&candidate_hash, &expected_hash) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(public_error_message(
                StatusCode::UNAUTHORIZED,
            ))),
        ));
    }

    Ok(())
}
