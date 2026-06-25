use super::HttpState;
use super::error::{ErrorResponse, error_response};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Serialize;
use tracing::error;

#[derive(Serialize)]
pub struct StartupHealthOutput {
    status: String,
    timestamp: String,
}

#[derive(Serialize)]
pub struct LiveHealthOutput {
    status: String,
}

#[derive(Serialize)]
pub struct ReadyHealthOutput {
    status: String,
    unsealed: bool,
    storage: String,
    keys_loaded: usize,
    routes_loaded: usize,
}

pub async fn startup_endpoint(State(state): State<HttpState>) -> Json<StartupHealthOutput> {
    Json(StartupHealthOutput {
        status: String::from("started"),
        timestamp: state.started_at().to_string(),
    })
}

pub async fn live_endpoint() -> Json<LiveHealthOutput> {
    Json(LiveHealthOutput {
        status: String::from("ok"),
    })
}

pub async fn ready_endpoint(
    State(state): State<HttpState>,
) -> Result<Json<ReadyHealthOutput>, (StatusCode, Json<ErrorResponse>)> {
    if let Err(err) = state.storage().health_check().await {
        error!(error = %err, "readiness storage check failed");
        return Err(error_response(err.as_ref()));
    }

    Ok(Json(ReadyHealthOutput {
        status: String::from("ready"),
        unsealed: state.key_material_loaded(),
        storage: String::from("ok"),
        keys_loaded: state.keys_loaded().await,
        routes_loaded: state.routes_loaded(),
    }))
}
