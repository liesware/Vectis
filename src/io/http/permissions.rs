use super::HttpState;
use super::error::{ErrorResponse, error_response};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use serde::Serialize;
use tracing::{error, info};

#[derive(Serialize)]
pub struct ReloadPermissionsResponse {
    status: String,
    clients_loaded: usize,
}

pub async fn reload_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<ReloadPermissionsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state.require_permission(&client, None, "admin").await?;

    info!(
        endpoint = "POST /permissions/reload",
        "permissions reload request accepted"
    );
    if let Err(err) = state.reload_permissions_state().await {
        error!(error = %err, "permissions reload endpoint failed");
        return Err(error_response(err.as_ref()));
    }

    let clients_loaded = state.permissions_loaded().await;
    info!(
        endpoint = "POST /permissions/reload",
        clients_loaded, "permissions reload response ready"
    );

    Ok(Json(ReloadPermissionsResponse {
        status: String::from("reloaded"),
        clients_loaded,
    }))
}
