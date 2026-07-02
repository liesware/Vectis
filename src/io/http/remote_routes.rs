use super::HttpState;
use super::error::ErrorResponse;
use crate::core::remote_routes::ListRemoteRoutesOutput;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use tracing::info;

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
