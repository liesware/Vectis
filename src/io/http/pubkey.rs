use super::HttpState;
use super::error::{ErrorResponse, error_response};
use crate::ops;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use tracing::{error, info};

pub async fn pub_endpoint(
    State(state): State<HttpState>,
    Path(id): Path<String>,
) -> Result<Json<ops::pubkey::PublicKeysOutput>, (StatusCode, Json<ErrorResponse>)> {
    ops::keys::validate_key_id(&id).map_err(|err| error_response(err.as_ref()))?;
    info!(endpoint = "GET /pub/{id}", kid = %id, "pub request accepted");
    let result = state
        .with_keys_db_state(|keys_db_state| ops::pubkey::public_keys_from_state(keys_db_state, &id))
        .await;

    match result {
        Ok(response) => {
            info!(
                endpoint = "GET /pub/{id}",
                kid = %id,
                info = %response.info,
                eddsa_alg = %response.keys.eddsa.alg,
                xecdh_alg = %response.keys.xecdh.alg,
                ml_dsa_alg = %response.keys.ml_dsa.alg,
                ml_kem_alg = %response.keys.ml_kem.alg,
                "pub response ready"
            );

            Ok(Json(response))
        }
        Err(err) => {
            error!(error = %err, id = %id, "pub endpoint failed");
            Err(error_response(err.as_ref()))
        }
    }
}
