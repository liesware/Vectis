use super::HttpState;
use super::error::{ErrorResponse, error_response};
use crate::core::remote_routes::ListRemoteRoutesOutput;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use tracing::{error, info};

pub async fn list_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<ListRemoteRoutesOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state.require_permission(&client, None, "admin").await?;

    info!(
        endpoint = "GET /remote-routes",
        "remote routes list request accepted"
    );
    let response = state.remote_routes_output().await;
    info!(
        endpoint = "GET /remote-routes",
        routes_count = response.routes_len(),
        "remote routes list response ready"
    );

    Ok(Json(response))
}

pub async fn reload_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<ListRemoteRoutesOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state.require_permission(&client, None, "admin").await?;

    info!(
        endpoint = "POST /remote-routes/reload",
        "remote routes reload request accepted"
    );
    if let Err(err) = state.reload_remote_routes_state().await {
        error!(error = %err, "remote routes reload endpoint failed");
        return Err(error_response(err.as_ref()));
    }

    let response = state.remote_routes_output().await;
    info!(
        endpoint = "POST /remote-routes/reload",
        routes_count = response.routes_len(),
        "remote routes reload response ready"
    );

    Ok(Json(response))
}
