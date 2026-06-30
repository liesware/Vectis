use super::HttpState;
use super::error::{ErrorResponse, error_response};
use crate::ops;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use serde_json::Value;
use tracing::error;

pub async fn send_endpoint(
    State(state): State<HttpState>,
    Path(sender_kid): Path<String>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Result<Json<ops::message::SendMessageOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission(&client, Some(&sender_kid), "message")
        .await?;

    ops::keys::validate_key_id(&sender_kid).map_err(|err| error_response(err.as_ref()))?;
    state
        .ensure_keys_db_entry(&sender_kid)
        .await
        .map_err(|err| error_response(err.as_ref()))?;
    let request = ops::message::parse_send_message_input(request)
        .map_err(|err| error_response(err.as_ref()))?;
    let prepared = state
        .with_keys_db_state(|keys_db_state| {
            ops::message::prepare_send_message(keys_db_state, &sender_kid, request)
        })
        .await
        .map_err(|err| error_response(err.as_ref()))?;
    let remote_route = state
        .remote_route_for(prepared.recipient_kid())
        .await
        .map_err(|err| error_response(err.as_ref()))?;
    let cached_recipient = state
        .remote_public_keys(remote_route.remote_addr(), prepared.recipient_kid())
        .await;

    match ops::message::send_message(prepared, remote_route, cached_recipient).await {
        Ok(result) => {
            state
                .upsert_remote_public_keys(result.remote_public_keys)
                .await;

            Ok(Json(result.output))
        }
        Err(err) => {
            error!(error = %err, sender_kid = %sender_kid, "message send endpoint failed");
            Err(error_response(err.as_ref()))
        }
    }
}

pub async fn receive_endpoint(
    State(state): State<HttpState>,
    Json(request): Json<Value>,
) -> Result<Json<ops::message::ReceiveMessageOutput>, (StatusCode, Json<ErrorResponse>)> {
    let envelope = ops::message::parse_message_envelope(request)
        .map_err(|err| error_response(err.as_ref()))?;
    ops::keys::validate_key_id(envelope.recipient_kid())
        .map_err(|err| error_response(err.as_ref()))?;
    state
        .ensure_keys_db_entry(envelope.recipient_kid())
        .await
        .map_err(|err| error_response(err.as_ref()))?;
    let prepared = state
        .with_keys_db_state(|keys_db_state| {
            ops::message::prepare_receive_message(keys_db_state, envelope)
        })
        .await
        .map_err(|err| error_response(err.as_ref()))?;
    let sender_host = prepared.sender_host().to_string();
    let sender_kid = prepared.sender_kid().to_string();
    let recipient_kid = prepared.recipient_kid().to_string();
    let cached_sender = state.remote_public_keys(&sender_host, &sender_kid).await;
    let final_app_route = state.final_app_route_for(&recipient_kid).await;

    match ops::message::receive_message(prepared, cached_sender, final_app_route).await {
        Ok(result) => {
            state
                .upsert_remote_public_keys(result.remote_public_keys)
                .await;

            Ok(Json(result.output))
        }
        Err(err) => {
            error!(error = %err, recipient_kid = %recipient_kid, "message receive endpoint failed");
            Err(error_response(err.as_ref()))
        }
    }
}

pub async fn decrypt_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Result<Json<ops::message::DecryptMessageOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;

    let request = ops::message::parse_decrypt_message_input(request)
        .map_err(|err| error_response(err.as_ref()))?;
    let recipient_kid = ops::message::decrypt_message_recipient_kid(&request)
        .map_err(|err| error_response(err.as_ref()))?;
    state
        .require_permission(&client, Some(&recipient_kid), "message")
        .await?;
    state
        .ensure_keys_db_entry(&recipient_kid)
        .await
        .map_err(|err| error_response(err.as_ref()))?;
    let prepared = state
        .with_keys_db_state(|keys_db_state| {
            ops::message::prepare_decrypt_message(keys_db_state, request)
        })
        .await
        .map_err(|err| error_response(err.as_ref()))?;

    match ops::message::decrypt_message(prepared) {
        Ok(output) => Ok(Json(output)),
        Err(err) => {
            error!(error = %err, "message decrypt endpoint failed");
            Err(error_response(err.as_ref()))
        }
    }
}

pub async fn internal_encrypt_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Result<Json<ops::message::InternalMessageOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission(&client, Some(&kid), "message")
        .await?;

    ops::keys::validate_key_id(&kid).map_err(|err| error_response(err.as_ref()))?;
    state
        .ensure_keys_db_entry(&kid)
        .await
        .map_err(|err| error_response(err.as_ref()))?;
    let request = ops::message::parse_internal_encrypt_message_input(request)
        .map_err(|err| error_response(err.as_ref()))?;
    let prepared = state
        .with_keys_db_state(|keys_db_state| {
            ops::message::prepare_internal_encrypt_message(keys_db_state, &kid, request)
        })
        .await
        .map_err(|err| error_response(err.as_ref()))?;

    match ops::message::encrypt_internal_message(prepared) {
        Ok(output) => Ok(Json(output)),
        Err(err) => {
            error!(error = %err, kid = %kid, "internal message encrypt endpoint failed");
            Err(error_response(err.as_ref()))
        }
    }
}

pub async fn internal_decrypt_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Result<Json<ops::message::DecryptMessageOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;

    let request = ops::message::parse_internal_decrypt_message_input(request)
        .map_err(|err| error_response(err.as_ref()))?;
    state
        .require_permission(&client, Some(&request.kid), "message")
        .await?;
    ops::keys::validate_key_id(&request.kid).map_err(|err| error_response(err.as_ref()))?;
    state
        .ensure_keys_db_entry(&request.kid)
        .await
        .map_err(|err| error_response(err.as_ref()))?;
    let prepared = state
        .with_keys_db_state(|keys_db_state| {
            ops::message::prepare_internal_decrypt_message(keys_db_state, request)
        })
        .await
        .map_err(|err| error_response(err.as_ref()))?;

    match ops::message::decrypt_internal_message(prepared) {
        Ok(output) => Ok(Json(output)),
        Err(err) => {
            error!(error = %err, "internal message decrypt endpoint failed");
            Err(error_response(err.as_ref()))
        }
    }
}
