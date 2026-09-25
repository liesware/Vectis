use super::HttpState;
use super::error::{ErrorResponse, error_response};
use super::{ConfigLoadedCounts, ConfigReloadOutcome, STALE_CONFIG_SIGNATURE_WARNING};
use crate::core::{audit, metrics, validation};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use serde::Serialize;
use tracing::{error, info};

#[derive(Serialize)]
pub struct ReloadConfigResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
    routes_loaded: usize,
    remote_routes_loaded: usize,
    clients_loaded: usize,
    fpe_profiles_loaded: usize,
    tokenization_profiles_loaded: usize,
    mac_profiles_loaded: usize,
    masking_profiles_loaded: usize,
    commitment_profiles_loaded: usize,
    sharing_profiles_loaded: usize,
}

pub async fn reload_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<ReloadConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    let request = state.authorize_request(&headers).await?;
    request.require_permission_for(None, "admin", Some("config.reload.denied"))?;
    let actor = audit::actor_from_client(request.client());

    info!(
        endpoint = "POST /config/reload",
        "config reload request accepted"
    );
    let reload_outcome = match state.reload_config_state().await {
        Ok(outcome) => outcome,
        Err(err) => {
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
    };
    let (warning, reload_result, audit_event_name) = match reload_outcome {
        ConfigReloadOutcome::Applied => (None, "success", "config.reload.success"),
        ConfigReloadOutcome::StaleSignatureKeptPrevious => (
            Some(STALE_CONFIG_SIGNATURE_WARNING.to_string()),
            "stale",
            "config.reload.stale",
        ),
    };

    let config = state.config_snapshot().await;
    let counts = ConfigLoadedCounts::from_config(&config);
    state.refresh_loaded_gauges_from(&config).await;
    metrics::record_config_reload(reload_result);
    record_config_reload_timestamp(reload_result);
    info!(
        endpoint = "POST /config/reload",
        routes_loaded = counts.routes,
        remote_routes_loaded = counts.remote_routes,
        clients_loaded = counts.permission_clients,
        fpe_profiles_loaded = counts.fpe_profiles,
        tokenization_profiles_loaded = counts.tokenization_profiles,
        mac_profiles_loaded = counts.mac_profiles,
        masking_profiles_loaded = counts.masking_profiles,
        commitment_profiles_loaded = counts.commitment_profiles,
        sharing_profiles_loaded = counts.sharing_profiles,
        warning = warning.as_deref(),
        "config reload response ready"
    );
    audit::operation_success(audit_event_name, Some(&actor), None, None, Some("admin"));

    Ok(Json(ReloadConfigResponse {
        status: String::from("reloaded"),
        warning,
        routes_loaded: counts.routes,
        remote_routes_loaded: counts.remote_routes,
        clients_loaded: counts.permission_clients,
        fpe_profiles_loaded: counts.fpe_profiles,
        tokenization_profiles_loaded: counts.tokenization_profiles,
        mac_profiles_loaded: counts.mac_profiles,
        masking_profiles_loaded: counts.masking_profiles,
        commitment_profiles_loaded: counts.commitment_profiles,
        sharing_profiles_loaded: counts.sharing_profiles,
    }))
}

fn record_config_reload_timestamp(result: &str) {
    if let Ok(timestamp) = validation::current_timestamp()
        && let Ok(timestamp) = timestamp.parse::<f64>()
    {
        metrics::set_config_last_reload_timestamp(result, timestamp);
    }
}
