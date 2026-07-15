use super::HttpState;
use super::error::{ErrorResponse, error_response};
use crate::core::audit;
use crate::ops;
use crate::ops::init::InitValidationOutput;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use tracing::{error, info};

pub async fn init_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<InitValidationOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(&client, None, "admin", Some("self_test.denied"))
        .await?;
    let actor = audit::actor_from_client(&client);

    info!(
        endpoint = "GET /self-test/init",
        "self-test init request accepted"
    );
    audit::operation_success("self_test.started", Some(&actor), None, None, Some("admin"));
    state
        .validation()
        .with_current_timestamp()
        .map(|response| {
            info!(
                endpoint = "GET /self-test/init",
                "self-test init response ready"
            );
            audit::operation_success(
                "self_test.finished",
                Some(&actor),
                None,
                None,
                Some("admin"),
            );
            Json(response)
        })
        .map_err(|err| {
            audit::operation_failed(
                "self_test.failed",
                Some(&actor),
                None,
                None,
                Some("admin"),
                &err.to_string(),
            );
            error!(error = %err, "self-test init endpoint failed");
            error_response(err.as_ref())
        })
}

pub async fn test_endpoint(
    State(state): State<HttpState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ops::test::TestOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(&client, Some(&id), "self-test", Some("self_test.denied"))
        .await?;
    let actor = audit::actor_from_client(&client);

    ops::keys::validate_key_id(&id).map_err(|err| {
        audit::operation_failed(
            "self_test.failed",
            Some(&actor),
            Some(&id),
            None,
            Some("self-test"),
            &err.to_string(),
        );
        error_response(err.as_ref())
    })?;
    state.ensure_keys_db_entry(&id).await.map_err(|err| {
        audit::operation_failed(
            "self_test.failed",
            Some(&actor),
            Some(&id),
            None,
            Some("self-test"),
            &err.to_string(),
        );
        error_response(err.as_ref())
    })?;
    info!(
        endpoint = "GET /self-test/keys/{kid}",
        kid = %id,
        "self-test key request accepted"
    );
    audit::operation_success(
        "self_test.started",
        Some(&actor),
        Some(&id),
        None,
        Some("self-test"),
    );
    let result = state
        .with_keys_db_state(|keys_db_state| {
            ops::test::handle_test_from_state(state.config(), keys_db_state, &id)
        })
        .await;

    match result {
        Ok(response) => {
            info!(
                endpoint = "GET /self-test/keys/{kid}",
                kid = %id,
                "self-test key response ready"
            );
            audit::operation_success(
                "self_test.finished",
                Some(&actor),
                Some(&id),
                None,
                Some("self-test"),
            );
            Ok(Json(response))
        }
        Err(err) => {
            audit::operation_failed(
                "self_test.failed",
                Some(&actor),
                Some(&id),
                None,
                Some("self-test"),
                &err.to_string(),
            );
            error!(error = %err, "self-test endpoint failed");
            Err(error_response(err.as_ref()))
        }
    }
}
