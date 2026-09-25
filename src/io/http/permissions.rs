use super::HttpState;
use super::error::ErrorResponse;
use crate::core::permissions::ListPermissionsOutput;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use tracing::info;

pub async fn list_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<ListPermissionsOutput>, (StatusCode, Json<ErrorResponse>)> {
    let request = state.authorize_request(&headers).await?;
    request.require_permission(None, "admin")?;

    info!(
        endpoint = "GET /permissions",
        "permissions list request accepted"
    );
    let response = request.config().permissions.list();
    info!(
        endpoint = "GET /permissions",
        clients_count = response.clients_len(),
        "permissions list response ready"
    );

    Ok(Json(response))
}
