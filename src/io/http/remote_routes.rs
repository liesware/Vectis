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
    let request = state.authorize_request(&headers).await?;
    request.require_permission(None, "admin")?;

    info!(
        endpoint = "GET /remote-routes",
        "remote routes list request accepted"
    );
    let response = request.config().remote_routes.list();
    info!(
        endpoint = "GET /remote-routes",
        routes_count = response.routes_len(),
        "remote routes list response ready"
    );

    Ok(Json(response))
}
