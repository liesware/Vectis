use super::HttpState;
use super::error::{ErrorResponse, error_response, public_error_message};
use crate::core::{audit, metrics};
use crate::ops;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use serde::Serialize;
use serde_json::Value;
use tracing::{error, info};

#[derive(Serialize)]
pub struct CreateKeysResponse {
    id: String,
}

pub async fn create_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Result<Json<CreateKeysResponse>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(&client, None, "admin", Some("key.create.denied"))
        .await?;
    let actor = audit::actor_from_client(&client);

    let request = match ops::keys::parse_create_keys_input(request) {
        Ok(request) => request,
        Err(err) => {
            audit::operation_failed(
                "key.create.failed",
                Some(&actor),
                None,
                None,
                Some("admin"),
                &err.to_string(),
            );
            return Err(error_response(err.as_ref()));
        }
    };
    info!(
        endpoint = "POST /keys",
        tag = request.tag.as_deref().unwrap_or("<default>"),
        profile = request.profile.as_deref().unwrap_or("<default>"),
        hash_algorithm = request.hash_algorithm.as_deref().unwrap_or("<default>"),
        symmetric_algorithm = request
            .symmetric_algorithm
            .as_deref()
            .unwrap_or("<default>"),
        eddsa_algorithm = request.eddsa_algorithm.as_deref().unwrap_or("<default>"),
        xecdh_algorithm = request.xecdh_algorithm.as_deref().unwrap_or("<default>"),
        ml_dsa_variant = request.ml_dsa_variant.as_deref().unwrap_or("<default>"),
        ml_kem_variant = request.ml_kem_variant.as_deref().unwrap_or("<default>"),
        "keys create request accepted"
    );

    match ops::keys::create_keys(state.storage(), state.internal_keys(), request).await {
        Ok(output) => {
            let loaded_key = match ops::keys::load_keys_db_entry(
                state.storage(),
                state.internal_keys(),
                &output.id,
            )
            .await
            {
                Ok(loaded_key) => loaded_key,
                Err(err) => {
                    audit::operation_failed(
                        "key.create.failed",
                        Some(&actor),
                        Some(&output.id),
                        None,
                        Some("admin"),
                        &err.to_string(),
                    );
                    error!(error = %err, id = %output.id, "failed to load created key into http state");
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse::new(public_error_message(
                            StatusCode::INTERNAL_SERVER_ERROR,
                        ))),
                    ));
                }
            };

            state.upsert_keys_db_entry(loaded_key).await;
            state.refresh_loaded_gauges().await;
            let loaded_key = state
                .with_keys_db_state(|keys_db_state| keys_db_state.get(&output.id).cloned())
                .await;
            if let Some(loaded_key) = loaded_key {
                info!(
                    endpoint = "POST /keys",
                    kid = %output.id,
                    info = %loaded_key.aad(),
                    hash_algorithm = %loaded_key.key_material().hash_variant(),
                    symmetric_algorithm = %loaded_key.keys().symmetric().variant(),
                    eddsa_algorithm = %loaded_key.keys().eddsa().variant(),
                    xecdh_algorithm = %loaded_key.keys().xecdh().variant(),
                    ml_dsa_variant = %loaded_key.keys().ml_dsa().variant(),
                    ml_kem_variant = %loaded_key.keys().ml_kem().variant(),
                    "keys create response ready"
                );
            }

            audit::operation_success(
                "key.create.success",
                Some(&actor),
                Some(&output.id),
                None,
                Some("admin"),
            );

            Ok(Json(CreateKeysResponse { id: output.id }))
        }
        Err(err) => {
            audit::operation_failed(
                "key.create.failed",
                Some(&actor),
                None,
                None,
                Some("admin"),
                &err.to_string(),
            );
            error!(error = %err, "keys endpoint failed");
            Err(error_response(err.as_ref()))
        }
    }
}

pub async fn list_endpoint(State(state): State<HttpState>) -> Json<ops::keys::ListKeysOutput> {
    info!(endpoint = "GET /keys", "keys list request accepted");
    let response = state
        .with_keys_db_state(ops::keys::list_keys_from_state)
        .await;
    let keys_count = state
        .with_keys_db_state(|keys_db_state| keys_db_state.len())
        .await;
    info!(
        endpoint = "GET /keys",
        keys_count, "keys list response ready"
    );

    Json(response)
}

pub async fn list_properties_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<ops::keys::ListKeysPropertiesOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state.require_permission(&client, None, "admin").await?;

    info!(
        endpoint = "GET /keys/properties",
        "keys properties list request accepted"
    );
    let response = state
        .with_keys_db_state(ops::keys::list_keys_properties_from_state)
        .await;
    let keys_count = state
        .with_keys_db_state(|keys_db_state| keys_db_state.len())
        .await;
    info!(
        endpoint = "GET /keys/properties",
        keys_count, "keys properties list response ready"
    );

    Ok(Json(response))
}

pub async fn get_properties_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ops::keys::KeyPropertiesOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state.require_permission(&client, Some(&id), "keys").await?;
    info!(
        endpoint = "GET /keys/properties/{kid}",
        kid = %id,
        "keys properties get request accepted"
    );

    state
        .ensure_keys_db_entry(&id)
        .await
        .map_err(|err| error_response(err.as_ref()))?;
    let response = state
        .with_keys_db_state(|keys_db_state| {
            ops::keys::key_properties_from_state(keys_db_state, &id)
        })
        .await
        .map_err(|err| error_response(err.as_ref()))?;

    info!(
        endpoint = "GET /keys/properties/{kid}",
        kid = %id,
        "keys properties get response ready"
    );

    Ok(Json(response))
}

pub async fn update_lifecycle_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<Value>,
) -> Result<Json<ops::keys::UpdateLifecycleOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(
            &client,
            Some(&id),
            "lifecycle",
            Some("key.lifecycle.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);
    let request = match ops::keys::parse_update_lifecycle_input(request) {
        Ok(request) => request,
        Err(err) => {
            audit::operation_failed(
                "key.lifecycle.failed",
                Some(&actor),
                Some(&id),
                None,
                Some("lifecycle"),
                &err.to_string(),
            );
            return Err(error_response(err.as_ref()));
        }
    };

    info!(
        endpoint = "POST /lifecycle/{kid}",
        kid = %id,
        status = %request_status(&request),
        "lifecycle update request accepted"
    );

    let response =
        match ops::keys::update_key_lifecycle(state.storage(), state.internal_keys(), &id, request)
            .await
        {
            Ok(response) => response,
            Err(err) => {
                audit::operation_failed(
                    "key.lifecycle.failed",
                    Some(&actor),
                    Some(&id),
                    None,
                    Some("lifecycle"),
                    &err.to_string(),
                );
                return Err(error_response(err.as_ref()));
            }
        };
    let loaded_key =
        match ops::keys::load_keys_db_entry(state.storage(), state.internal_keys(), &id).await {
            Ok(loaded_key) => loaded_key,
            Err(err) => {
                audit::operation_failed(
                    "key.lifecycle.failed",
                    Some(&actor),
                    Some(&id),
                    None,
                    Some("lifecycle"),
                    &err.to_string(),
                );
                return Err(error_response(err.as_ref()));
            }
        };
    state.upsert_keys_db_entry(loaded_key).await;

    info!(
        endpoint = "POST /lifecycle/{kid}",
        kid = %id,
        "lifecycle update response ready"
    );
    audit::operation_success(
        "key.lifecycle.changed",
        Some(&actor),
        Some(&id),
        None,
        Some("lifecycle"),
    );

    Ok(Json(response))
}

pub async fn refresh_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Json<ops::keys::ListKeysPropertiesOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(&client, None, "admin", Some("key.reload.denied"))
        .await?;
    let actor = audit::actor_from_client(&client);

    info!(
        endpoint = "POST /keys/reload",
        "keys reload request accepted"
    );
    state.reload_keys_db_state().await.map_err(|err| {
        metrics::record_keys_reload("failed");
        audit::operation_failed(
            "key.reload.failed",
            Some(&actor),
            None,
            None,
            Some("admin"),
            &err.to_string(),
        );
        error_response(err.as_ref())
    })?;
    state.refresh_loaded_gauges().await;
    metrics::record_keys_reload("success");
    let response = state
        .with_keys_db_state(ops::keys::list_keys_properties_from_state)
        .await;
    let keys_count = state
        .with_keys_db_state(|keys_db_state| keys_db_state.len())
        .await;
    info!(
        endpoint = "POST /keys/reload",
        keys_count, "keys reload response ready"
    );
    audit::operation_success(
        "key.reload.success",
        Some(&actor),
        None,
        None,
        Some("admin"),
    );

    Ok(Json(response))
}

fn request_status(request: &ops::keys::UpdateLifecycleInput) -> &str {
    request.status()
}
