use super::HttpState;
use super::error::{ErrorResponse, error_response};
use crate::ops;
use crate::ops::init::InitValidationOutput;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use tracing::{error, info};

pub async fn init_endpoint(
    State(state): State<HttpState>,
) -> Result<Json<InitValidationOutput>, (StatusCode, Json<ErrorResponse>)> {
    info!(endpoint = "GET /test/init", "test init request accepted");
    state
        .validation()
        .with_current_timestamp()
        .map(|response| {
            info!(endpoint = "GET /test/init", "test init response ready");
            Json(response)
        })
        .map_err(|err| {
            error!(error = %err, "test init endpoint failed");
            error_response(err.as_ref())
        })
}

pub async fn test_endpoint(
    State(state): State<HttpState>,
    Path(id): Path<String>,
) -> Result<Json<ops::test::TestOutput>, (StatusCode, Json<ErrorResponse>)> {
    ops::keys::validate_key_id(&id).map_err(|err| error_response(err.as_ref()))?;
    state
        .ensure_keys_db_entry(&id)
        .await
        .map_err(|err| error_response(err.as_ref()))?;
    info!(endpoint = "GET /test/{id}", kid = %id, "test key request accepted");
    let result = state
        .with_keys_db_state(|keys_db_state| ops::test::handle_test_from_state(keys_db_state, &id))
        .await;

    match result {
        Ok(response) => {
            info!(endpoint = "GET /test/{id}", kid = %id, "test key response ready");
            Ok(Json(response))
        }
        Err(err) => {
            error!(error = %err, "test endpoint failed");
            Err(error_response(err.as_ref()))
        }
    }
}
