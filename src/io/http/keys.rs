use super::HttpState;
use super::auth::authorize_api_key;
use super::error::{ErrorResponse, error_response, public_error_message};
use crate::ops;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use serde::Serialize;
use serde_json::Value;
use tracing::{error, info};

#[derive(Serialize)]
pub struct CreateKeysResponse {
    id: String,
}

pub async fn create_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Result<Json<CreateKeysResponse>, (StatusCode, Json<ErrorResponse>)> {
    if let Err(response) = authorize_api_key(&headers) {
        return Err(response);
    }

    let request = match ops::keys::parse_create_keys_input(request) {
        Ok(request) => request,
        Err(err) => {
            return Err(error_response(err.as_ref()));
        }
    };
    info!(
        endpoint = "POST /keys",
        tag = request.tag.as_deref().unwrap_or("<default>"),
        profile = request.profile.as_deref().unwrap_or("<default>"),
        hash_algorithm = request.hash_algorithm.as_deref().unwrap_or("<default>"),
        symmetric_algorithm = request
            .symmetric_algorithm
            .as_deref()
            .unwrap_or("<default>"),
        eddsa_algorithm = request.eddsa_algorithm.as_deref().unwrap_or("<default>"),
        xecdh_algorithm = request.xecdh_algorithm.as_deref().unwrap_or("<default>"),
        ml_dsa_variant = request.ml_dsa_variant.as_deref().unwrap_or("<default>"),
        ml_kem_variant = request.ml_kem_variant.as_deref().unwrap_or("<default>"),
        "keys create request accepted"
    );

    match ops::keys::create_keys(state.storage(), state.init_state(), request).await {
        Ok(output) => {
            let loaded_key = match ops::keys::load_keys_db_entry(
                state.storage(),
                state.init_state(),
                &output.id,
            )
            .await
            {
                Ok(loaded_key) => loaded_key,
                Err(err) => {
                    error!(error = %err, id = %output.id, "failed to load created key into http state");
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse::new(public_error_message(
                            StatusCode::INTERNAL_SERVER_ERROR,
                        ))),
                    ));
                }
            };

            state.upsert_keys_db_entry(loaded_key).await;
            let loaded_key = state
                .with_keys_db_state(|keys_db_state| keys_db_state.get(&output.id).cloned())
                .await;
            if let Some(loaded_key) = loaded_key {
                info!(
                    endpoint = "POST /keys",
                    kid = %output.id,
                    info = %loaded_key.aad(),
                    hash_algorithm = %loaded_key.key_material().hash_variant(),
                    symmetric_algorithm = %loaded_key.keys().symmetric().variant(),
                    eddsa_algorithm = %loaded_key.keys().eddsa().variant(),
                    xecdh_algorithm = %loaded_key.keys().xecdh().variant(),
                    ml_dsa_variant = %loaded_key.keys().ml_dsa().variant(),
                    ml_kem_variant = %loaded_key.keys().ml_kem().variant(),
                    "keys create response ready"
                );
            }

            Ok(Json(CreateKeysResponse { id: output.id }))
        }
        Err(err) => {
            error!(error = %err, "keys endpoint failed");
            Err(error_response(err.as_ref()))
        }
    }
}

pub async fn list_endpoint(State(state): State<HttpState>) -> Json<ops::keys::ListKeysOutput> {
    info!(endpoint = "GET /keys", "keys list request accepted");
    let response = state
        .with_keys_db_state(ops::keys::list_keys_from_state)
        .await;
    let keys_count = state
        .with_keys_db_state(|keys_db_state| keys_db_state.len())
        .await;
    info!(
        endpoint = "GET /keys",
        keys_count, "keys list response ready"
    );

    Json(response)
}

pub async fn refresh_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<ops::keys::ListKeysOutput>, (StatusCode, Json<ErrorResponse>)> {
    if let Err(response) = authorize_api_key(&headers) {
        return Err(response);
    }

    info!(
        endpoint = "GET /keys/db",
        "keys db refresh request accepted"
    );
    state
        .reload_keys_db_state()
        .await
        .map_err(|err| error_response(err.as_ref()))?;
    let response = state
        .with_keys_db_state(ops::keys::list_keys_from_state)
        .await;
    let keys_count = state
        .with_keys_db_state(|keys_db_state| keys_db_state.len())
        .await;
    info!(
        endpoint = "GET /keys/db",
        keys_count, "keys db refresh response ready"
    );

    Ok(Json(response))
}
