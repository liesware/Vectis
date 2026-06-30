use super::HttpState;
use super::error::{ErrorResponse, error_response};
use crate::ops;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use serde_json::Value;
use tracing::{error, info};

pub async fn sign_endpoint(
    State(state): State<HttpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Result<Json<ops::sign::TimestampToken>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state.require_permission(&client, Some(&id), "sign").await?;

    ops::keys::validate_key_id(&id).map_err(|err| error_response(err.as_ref()))?;
    state
        .ensure_keys_db_entry(&id)
        .await
        .map_err(|err| error_response(err.as_ref()))?;
    let request =
        ops::sign::parse_sign_input(request).map_err(|err| error_response(err.as_ref()))?;
    info!(
        endpoint = "/sign/{id}",
        kid = %id,
        hash_alg = %request.message_hash.alg,
        hash_hex_len = request.message_hash.hex.len(),
        "sign request accepted"
    );

    let result = state
        .with_keys_db_state(|keys_db_state| {
            ops::sign::sign_timestamp_from_state(keys_db_state, &id, request)
        })
        .await;

    match result {
        Ok(response) => {
            info!(
                endpoint = "/sign/{id}",
                kid = %response.kid(),
                created_at = %response.payload.created_at,
                info = %response.payload.info,
                serial = %response.payload.serial,
                eddsa_alg = %response.signatures.eddsa.alg,
                eddsa_sig_len = response.signatures.eddsa.sig.len(),
                ml_dsa_alg = %response.signatures.ml_dsa.alg,
                ml_dsa_sig_len = response.signatures.ml_dsa.sig.len(),
                "sign response ready"
            );

            Ok(Json(response))
        }
        Err(err) => {
            error!(error = %err, id = %id, "sign endpoint failed");
            Err(error_response(err.as_ref()))
        }
    }
}

pub async fn sign_verification_endpoint(
    State(state): State<HttpState>,
    Json(request): Json<Value>,
) -> Result<Json<ops::sign::VerificationOutput>, (StatusCode, Json<ErrorResponse>)> {
    let request =
        ops::sign::parse_timestamp_token(request).map_err(|err| error_response(err.as_ref()))?;
    ops::sign::validate_timestamp_token(&request).map_err(|err| error_response(err.as_ref()))?;

    let kid = request.kid().to_string();
    state
        .ensure_keys_db_entry(&kid)
        .await
        .map_err(|err| error_response(err.as_ref()))?;
    info!(
        endpoint = "/sign/verification",
        kid = %kid,
        hash_alg = %request.payload.message_hash.alg,
        hash_hex_len = request.payload.message_hash.hex.len(),
        eddsa_alg = %request.signatures.eddsa.alg,
        eddsa_sig_len = request.signatures.eddsa.sig.len(),
        ml_dsa_alg = %request.signatures.ml_dsa.alg,
        ml_dsa_sig_len = request.signatures.ml_dsa.sig.len(),
        "sign verification request accepted"
    );
    let result = state
        .with_keys_db_state(|keys_db_state| {
            ops::sign::verify_timestamp_from_state(keys_db_state, &request)
        })
        .await;

    match result {
        Ok(response) => {
            info!(
                endpoint = "/sign/verification",
                kid = %kid,
                valid = %response.valid,
                eddsa = %response.status.eddsa,
                ml_dsa = %response.status.ml_dsa,
                "sign verification response ready"
            );

            Ok(Json(response))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "sign verification endpoint failed");
            Err(error_response(err.as_ref()))
        }
    }
}
