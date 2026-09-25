use super::HttpState;
use super::error::ErrorResponse;
use crate::core::routes::ListRoutesOutput;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use tracing::info;

pub async fn list_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<ListRoutesOutput>, (StatusCode, Json<ErrorResponse>)> {
    let request = state.authorize_request(&headers).await?;
    request.require_permission(None, "admin")?;

    info!(endpoint = "GET /routes", "routes list request accepted");
    let response = request.config().routes.list();
    info!(
        endpoint = "GET /routes",
        routes_count = response.routes_len(),
        "routes list response ready"
    );

    Ok(Json(response))
}
