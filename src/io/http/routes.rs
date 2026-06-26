use super::HttpState;
use super::auth::authorize_api_key;
use super::error::{ErrorResponse, error_response};
use crate::core::routes::ListRoutesOutput;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use tracing::{error, info};

pub async fn list_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<ListRoutesOutput>, (StatusCode, Json<ErrorResponse>)> {
    if let Err(response) = authorize_api_key(&headers) {
        return Err(response);
    }

    info!(endpoint = "GET /routes", "routes list request accepted");
    let response = state.routes_output().await;
    info!(
        endpoint = "GET /routes",
        routes_count = response.routes_len(),
        "routes list response ready"
    );

    Ok(Json(response))
}

pub async fn reload_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<ListRoutesOutput>, (StatusCode, Json<ErrorResponse>)> {
    if let Err(response) = authorize_api_key(&headers) {
        return Err(response);
    }

    info!(
        endpoint = "POST /routes/reload",
        "routes reload request accepted"
    );
    if let Err(err) = state.reload_routes_state().await {
        error!(error = %err, "routes reload endpoint failed");
        return Err(error_response(err.as_ref()));
    }

    let response = state.routes_output().await;
    info!(
        endpoint = "POST /routes/reload",
        routes_count = response.routes_len(),
        "routes reload response ready"
    );

    Ok(Json(response))
}
