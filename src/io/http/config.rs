use super::HttpState;
use super::error::{ErrorResponse, error_response};
use crate::core::{audit, metrics, validation};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use serde::Serialize;
use tracing::{error, info};

#[derive(Serialize)]
pub struct ReloadConfigResponse {
    status: String,
    routes_loaded: usize,
    remote_routes_loaded: usize,
    clients_loaded: usize,
    fpe_profiles_loaded: usize,
}

pub async fn reload_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<ReloadConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(&client, None, "admin", Some("config.reload.denied"))
        .await?;
    let actor = audit::actor_from_client(&client);

    info!(
        endpoint = "POST /config/reload",
        "config reload request accepted"
    );
    if let Err(err) = state.reload_config_state().await {
        metrics::record_config_reload("failed");
        record_config_reload_timestamp("failed");
        audit::operation_failed(
            "config.reload.failed",
            Some(&actor),
            None,
            None,
            Some("admin"),
            &err.to_string(),
        );
        error!(error = %err, "config reload endpoint failed");
        return Err(error_response(err.as_ref()));
    }

    let routes_loaded = state.routes_loaded().await;
    let remote_routes_loaded = state.remote_routes_loaded().await;
    let clients_loaded = state.permissions_loaded().await;
    let fpe_profiles_loaded = state.fpe_profiles_loaded().await;
    state.refresh_loaded_gauges().await;
    metrics::record_config_reload("success");
    record_config_reload_timestamp("success");
    info!(
        endpoint = "POST /config/reload",
        routes_loaded,
        remote_routes_loaded,
        clients_loaded,
        fpe_profiles_loaded,
        "config reload response ready"
    );
    audit::operation_success(
        "config.reload.success",
        Some(&actor),
        None,
        None,
        Some("admin"),
    );

    Ok(Json(ReloadConfigResponse {
        status: String::from("reloaded"),
        routes_loaded,
        remote_routes_loaded,
        clients_loaded,
        fpe_profiles_loaded,
    }))
}

fn record_config_reload_timestamp(result: &str) {
    if let Ok(timestamp) = validation::current_timestamp()
        && let Ok(timestamp) = timestamp.parse::<f64>()
    {
        metrics::set_config_last_reload_timestamp(result, timestamp);
    }
}
