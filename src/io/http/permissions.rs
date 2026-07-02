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
    let client = state.authorize_api_key(&headers).await?;
    state.require_permission(&client, None, "admin").await?;

    info!(
        endpoint = "GET /permissions",
        "permissions list request accepted"
    );
    let response = state.permissions_output().await;
    info!(
        endpoint = "GET /permissions",
        clients_count = response.clients_len(),
        "permissions list response ready"
    );

    Ok(Json(response))
}
