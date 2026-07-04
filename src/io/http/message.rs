use super::HttpState;
use super::error::{ErrorResponse, error_response};
use super::extract::JsonBody;
use crate::core::{audit, metrics};
use crate::ops;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use std::error::Error;
use tracing::error;

const AUDIT_MESSAGE_INTERNAL_ENCRYPT_DENIED: &str = "message.internal.encrypt.denied";
const AUDIT_MESSAGE_INTERNAL_ENCRYPT_FAILED: &str = "message.internal.encrypt.failed";
const AUDIT_MESSAGE_INTERNAL_ENCRYPT_SUCCESS: &str = "message.internal.encrypt.success";
const AUDIT_MESSAGE_INTERNAL_DECRYPT_DENIED: &str = "message.internal.decrypt.denied";
const AUDIT_MESSAGE_INTERNAL_DECRYPT_FAILED: &str = "message.internal.decrypt.failed";
const AUDIT_MESSAGE_INTERNAL_DECRYPT_SUCCESS: &str = "message.internal.decrypt.success";

pub async fn send_endpoint(
    State(state): State<HttpState>,
    Path(sender_kid): Path<String>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::message::SendMessageOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(
            &client,
            Some(&sender_kid),
            "message",
            Some("message.send.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    ops::keys::validate_key_id(&sender_kid).map_err(|err| {
        message_failed_response(
            MessageFailure::new(
                "message.send.failed",
                Some(&actor),
                Some(&sender_kid),
                None,
                Some("message"),
                "send",
            ),
            err.as_ref(),
        )
    })?;
    state
        .ensure_keys_db_entry(&sender_kid)
        .await
        .map_err(|err| {
            message_failed_response(
                MessageFailure::new(
                    "message.send.failed",
                    Some(&actor),
                    Some(&sender_kid),
                    None,
                    Some("message"),
                    "send",
                ),
                err.as_ref(),
            )
        })?;
    let request = ops::message::parse_send_message_input(request).map_err(|err| {
        message_failed_response(
            MessageFailure::new(
                "message.send.failed",
                Some(&actor),
                Some(&sender_kid),
                None,
                Some("message"),
                "send",
            ),
            err.as_ref(),
        )
    })?;
    let prepared = state
        .with_keys_db_state(|keys_db_state| {
            ops::message::prepare_send_message(keys_db_state, &sender_kid, request)
        })
        .await
        .map_err(|err| {
            message_failed_response(
                MessageFailure::new(
                    "message.send.failed",
                    Some(&actor),
                    Some(&sender_kid),
                    None,
                    Some("message"),
                    "send",
                ),
                err.as_ref(),
            )
        })?;
    let recipient_kid = prepared.recipient_kid().to_string();
    let remote_route = state
        .remote_route_for(&sender_kid, &recipient_kid)
        .await
        .map_err(|err| {
            message_failed_response(
                MessageFailure::new(
                    "message.send.failed",
                    Some(&actor),
                    Some(&sender_kid),
                    Some(&recipient_kid),
                    Some("message"),
                    "send",
                ),
                err.as_ref(),
            )
        })?;

    match ops::message::send_message(state.config(), prepared, remote_route).await {
        Ok(output) => {
            audit::operation_success(
                "message.send.success",
                Some(&actor),
                Some(&sender_kid),
                Some(&recipient_kid),
                Some("message"),
            );
            record_message_success("send");
            Ok(Json(output))
        }
        Err(err) => {
            let response = message_failed_result(
                MessageFailure::new(
                    "message.send.failed",
                    Some(&actor),
                    Some(&sender_kid),
                    Some(&recipient_kid),
                    Some("message"),
                    "send",
                ),
                err.as_ref(),
            );
            error!(error = %err, sender_kid = %sender_kid, "message send endpoint failed");
            response
        }
    }
}

pub async fn receive_endpoint(
    State(state): State<HttpState>,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::message::ReceiveMessageOutput>, (StatusCode, Json<ErrorResponse>)> {
    let envelope = ops::message::parse_message_envelope(request).map_err(|err| {
        message_failed_response(
            MessageFailure::new("message.receive.failed", None, None, None, None, "receive"),
            err.as_ref(),
        )
    })?;
    let recipient_kid = envelope.recipient_kid().to_string();
    let sender_kid = envelope.sender_kid().to_string();
    ops::keys::validate_key_id(&recipient_kid).map_err(|err| {
        message_failed_response(
            MessageFailure::new(
                "message.receive.failed",
                None,
                Some(&recipient_kid),
                Some(&sender_kid),
                None,
                "receive",
            ),
            err.as_ref(),
        )
    })?;
    state
        .ensure_keys_db_entry(&recipient_kid)
        .await
        .map_err(|err| {
            message_failed_response(
                MessageFailure::new(
                    "message.receive.failed",
                    None,
                    Some(&recipient_kid),
                    Some(&sender_kid),
                    None,
                    "receive",
                ),
                err.as_ref(),
            )
        })?;
    let prepared = state
        .with_keys_db_state(|keys_db_state| {
            ops::message::prepare_receive_message(keys_db_state, envelope)
        })
        .await
        .map_err(|err| {
            message_failed_response(
                MessageFailure::new(
                    "message.receive.failed",
                    None,
                    Some(&recipient_kid),
                    Some(&sender_kid),
                    None,
                    "receive",
                ),
                err.as_ref(),
            )
        })?;
    let sender_host = prepared.sender_host().to_string();
    let Some(peer) = state.remote_peer_public_keys(&sender_kid).await else {
        audit::operation_denied(
            "message.receive.denied",
            &audit::Actor {
                name: "",
                fingerprint: "",
                root: false,
                admin: false,
            },
            Some(&recipient_kid),
            Some(&sender_kid),
            None,
            "sender kid is not a registered peer with public keys in the signed config",
        );
        record_message_denied("receive");
        return Err(error_response(
            crate::error::forbidden(
                "sender kid is not a registered peer with public keys in the signed config",
            )
            .as_ref(),
        ));
    };
    let sender_public_keys =
        ops::message::remote_public_keys_from_peer(&sender_host, &sender_kid, &peer).map_err(
            |err| {
                message_failed_response(
                    MessageFailure::new(
                        "message.receive.failed",
                        None,
                        Some(&recipient_kid),
                        Some(&sender_kid),
                        None,
                        "receive",
                    ),
                    err.as_ref(),
                )
            },
        )?;
    let final_app_route = state.final_app_route_for(&recipient_kid).await;

    match ops::message::receive_message(prepared, sender_public_keys, final_app_route).await {
        Ok(output) => {
            audit::operation_success(
                "message.receive.success",
                None,
                Some(&recipient_kid),
                Some(&sender_kid),
                None,
            );
            record_message_success("receive");
            Ok(Json(output))
        }
        Err(err) => {
            let response = message_failed_result(
                MessageFailure::new(
                    "message.receive.failed",
                    None,
                    Some(&recipient_kid),
                    Some(&sender_kid),
                    None,
                    "receive",
                ),
                err.as_ref(),
            );
            error!(error = %err, recipient_kid = %recipient_kid, "message receive endpoint failed");
            response
        }
    }
}

pub async fn decrypt_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::message::DecryptMessageOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    let actor = audit::actor_from_client(&client);

    let request = ops::message::parse_decrypt_message_input(request).map_err(|err| {
        message_failed_response(
            MessageFailure::new(
                "message.decrypt.failed",
                Some(&actor),
                None,
                None,
                Some("message"),
                "decrypt",
            )
            .with_crypto("decrypt"),
            err.as_ref(),
        )
    })?;
    let recipient_kid = ops::message::decrypt_message_recipient_kid(&request).map_err(|err| {
        message_failed_response(
            MessageFailure::new(
                "message.decrypt.failed",
                Some(&actor),
                None,
                None,
                Some("message"),
                "decrypt",
            )
            .with_crypto("decrypt"),
            err.as_ref(),
        )
    })?;
    state
        .require_permission_for(
            &client,
            Some(&recipient_kid),
            "message",
            Some("message.decrypt.denied"),
        )
        .await?;
    state
        .ensure_keys_db_entry(&recipient_kid)
        .await
        .map_err(|err| {
            message_failed_response(
                MessageFailure::new(
                    "message.decrypt.failed",
                    Some(&actor),
                    Some(&recipient_kid),
                    None,
                    Some("message"),
                    "decrypt",
                )
                .with_crypto("decrypt"),
                err.as_ref(),
            )
        })?;
    let prepared = state
        .with_keys_db_state(|keys_db_state| {
            ops::message::prepare_decrypt_message(keys_db_state, request)
        })
        .await
        .map_err(|err| {
            message_failed_response(
                MessageFailure::new(
                    "message.decrypt.failed",
                    Some(&actor),
                    Some(&recipient_kid),
                    None,
                    Some("message"),
                    "decrypt",
                )
                .with_crypto("decrypt"),
                err.as_ref(),
            )
        })?;

    match ops::message::decrypt_message(prepared) {
        Ok(output) => {
            audit::operation_success(
                "message.decrypt.success",
                Some(&actor),
                Some(&recipient_kid),
                None,
                Some("message"),
            );
            record_message_success("decrypt");
            record_crypto_success("decrypt");
            Ok(Json(output))
        }
        Err(err) => {
            let response = message_failed_result(
                MessageFailure::new(
                    "message.decrypt.failed",
                    Some(&actor),
                    Some(&recipient_kid),
                    None,
                    Some("message"),
                    "decrypt",
                )
                .with_crypto("decrypt"),
                err.as_ref(),
            );
            error!(error = %err, "message decrypt endpoint failed");
            response
        }
    }
}

pub async fn internal_encrypt_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::message::InternalMessageOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "message",
            Some(AUDIT_MESSAGE_INTERNAL_ENCRYPT_DENIED),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    ops::keys::validate_key_id(&kid).map_err(|err| {
        message_failed_response(
            MessageFailure::new(
                AUDIT_MESSAGE_INTERNAL_ENCRYPT_FAILED,
                Some(&actor),
                Some(&kid),
                None,
                Some("message"),
                "send",
            )
            .with_crypto("encrypt"),
            err.as_ref(),
        )
    })?;
    state.ensure_keys_db_entry(&kid).await.map_err(|err| {
        message_failed_response(
            MessageFailure::new(
                AUDIT_MESSAGE_INTERNAL_ENCRYPT_FAILED,
                Some(&actor),
                Some(&kid),
                None,
                Some("message"),
                "send",
            )
            .with_crypto("encrypt"),
            err.as_ref(),
        )
    })?;
    let request = ops::message::parse_internal_encrypt_message_input(request).map_err(|err| {
        message_failed_response(
            MessageFailure::new(
                AUDIT_MESSAGE_INTERNAL_ENCRYPT_FAILED,
                Some(&actor),
                Some(&kid),
                None,
                Some("message"),
                "send",
            )
            .with_crypto("encrypt"),
            err.as_ref(),
        )
    })?;
    let prepared = state
        .with_keys_db_state(|keys_db_state| {
            ops::message::prepare_internal_encrypt_message(keys_db_state, &kid, request)
        })
        .await
        .map_err(|err| {
            message_failed_response(
                MessageFailure::new(
                    AUDIT_MESSAGE_INTERNAL_ENCRYPT_FAILED,
                    Some(&actor),
                    Some(&kid),
                    None,
                    Some("message"),
                    "send",
                )
                .with_crypto("encrypt"),
                err.as_ref(),
            )
        })?;

    match ops::message::encrypt_internal_message(prepared) {
        Ok(output) => {
            audit::operation_success(
                AUDIT_MESSAGE_INTERNAL_ENCRYPT_SUCCESS,
                Some(&actor),
                Some(&kid),
                None,
                Some("message"),
            );
            record_message_success("send");
            record_crypto_success("encrypt");
            Ok(Json(output))
        }
        Err(err) => {
            let response = message_failed_result(
                MessageFailure::new(
                    AUDIT_MESSAGE_INTERNAL_ENCRYPT_FAILED,
                    Some(&actor),
                    Some(&kid),
                    None,
                    Some("message"),
                    "send",
                )
                .with_crypto("encrypt"),
                err.as_ref(),
            );
            error!(error = %err, kid = %kid, "internal message encrypt endpoint failed");
            response
        }
    }
}

pub async fn internal_decrypt_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::message::DecryptMessageOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    let actor = audit::actor_from_client(&client);

    let request = ops::message::parse_internal_decrypt_message_input(request).map_err(|err| {
        message_failed_response(
            MessageFailure::new(
                AUDIT_MESSAGE_INTERNAL_DECRYPT_FAILED,
                Some(&actor),
                None,
                None,
                Some("message"),
                "decrypt",
            )
            .with_crypto("decrypt"),
            err.as_ref(),
        )
    })?;
    state
        .require_permission_for(
            &client,
            Some(&request.kid),
            "message",
            Some(AUDIT_MESSAGE_INTERNAL_DECRYPT_DENIED),
        )
        .await?;
    let kid = request.kid.clone();
    ops::keys::validate_key_id(&kid).map_err(|err| {
        message_failed_response(
            MessageFailure::new(
                AUDIT_MESSAGE_INTERNAL_DECRYPT_FAILED,
                Some(&actor),
                Some(&kid),
                None,
                Some("message"),
                "decrypt",
            )
            .with_crypto("decrypt"),
            err.as_ref(),
        )
    })?;
    state.ensure_keys_db_entry(&kid).await.map_err(|err| {
        message_failed_response(
            MessageFailure::new(
                AUDIT_MESSAGE_INTERNAL_DECRYPT_FAILED,
                Some(&actor),
                Some(&kid),
                None,
                Some("message"),
                "decrypt",
            )
            .with_crypto("decrypt"),
            err.as_ref(),
        )
    })?;
    let prepared = state
        .with_keys_db_state(|keys_db_state| {
            ops::message::prepare_internal_decrypt_message(keys_db_state, request)
        })
        .await
        .map_err(|err| {
            message_failed_response(
                MessageFailure::new(
                    AUDIT_MESSAGE_INTERNAL_DECRYPT_FAILED,
                    Some(&actor),
                    Some(&kid),
                    None,
                    Some("message"),
                    "decrypt",
                )
                .with_crypto("decrypt"),
                err.as_ref(),
            )
        })?;

    match ops::message::decrypt_internal_message(prepared) {
        Ok(output) => {
            audit::operation_success(
                AUDIT_MESSAGE_INTERNAL_DECRYPT_SUCCESS,
                Some(&actor),
                Some(&kid),
                None,
                Some("message"),
            );
            record_message_success("decrypt");
            record_crypto_success("decrypt");
            Ok(Json(output))
        }
        Err(err) => {
            let response = message_failed_result(
                MessageFailure::new(
                    AUDIT_MESSAGE_INTERNAL_DECRYPT_FAILED,
                    Some(&actor),
                    Some(&kid),
                    None,
                    Some("message"),
                    "decrypt",
                )
                .with_crypto("decrypt"),
                err.as_ref(),
            );
            error!(error = %err, "internal message decrypt endpoint failed");
            response
        }
    }
}

fn record_message_success(operation: &str) {
    metrics::record_message(operation, "success");
}

#[derive(Clone, Copy)]
struct MessageFailure<'a> {
    event: &'a str,
    actor: Option<&'a audit::Actor<'a>>,
    kid: Option<&'a str>,
    remote_kid: Option<&'a str>,
    action: Option<&'a str>,
    message_operation: &'a str,
    crypto_operation: Option<&'a str>,
}

impl<'a> MessageFailure<'a> {
    fn new(
        event: &'a str,
        actor: Option<&'a audit::Actor<'a>>,
        kid: Option<&'a str>,
        remote_kid: Option<&'a str>,
        action: Option<&'a str>,
        message_operation: &'a str,
    ) -> Self {
        Self {
            event,
            actor,
            kid,
            remote_kid,
            action,
            message_operation,
            crypto_operation: None,
        }
    }

    fn with_crypto(mut self, crypto_operation: &'a str) -> Self {
        self.crypto_operation = Some(crypto_operation);
        self
    }
}

fn message_failed_response(
    failure: MessageFailure<'_>,
    err: &(dyn Error + Send + Sync + 'static),
) -> (StatusCode, Json<ErrorResponse>) {
    audit::operation_failed(
        failure.event,
        failure.actor,
        failure.kid,
        failure.remote_kid,
        failure.action,
        &err.to_string(),
    );
    record_message_failed(failure.message_operation);
    if let Some(crypto_operation) = failure.crypto_operation {
        record_crypto_failed(crypto_operation);
    }

    error_response(err)
}

fn message_failed_result<T>(
    failure: MessageFailure<'_>,
    err: &(dyn Error + Send + Sync + 'static),
) -> Result<T, (StatusCode, Json<ErrorResponse>)> {
    Err(message_failed_response(failure, err))
}

fn record_message_denied(operation: &str) {
    metrics::record_message(operation, "denied");
}

fn record_message_failed(operation: &str) {
    metrics::record_message(operation, "failed");
}

fn record_crypto_success(operation: &str) {
    metrics::record_crypto_operation(operation, "success");
}

fn record_crypto_failed(operation: &str) {
    metrics::record_crypto_operation(operation, "failed");
}
