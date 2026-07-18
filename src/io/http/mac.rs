use super::HttpState;
use super::error::{ErrorResponse, error_response};
use super::extract::JsonBody;
use crate::core::{audit, blocking, metrics};
use crate::ops;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use tracing::{error, info};

pub async fn create_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::mac::MacCreateOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(&client, Some(&kid), "mac-create", Some("mac.create.denied"))
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(mac_failed_response(
            "mac.create.failed",
            Some(&actor),
            Some(&kid),
            Some("mac-create"),
            "mac_create",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(mac_failed_response(
            "mac.create.failed",
            Some(&actor),
            Some(&kid),
            Some("mac-create"),
            "mac_create",
            err.as_ref(),
        ));
    }
    let input =
        match ops::mac::parse_create_input(request).and_then(ops::mac::validate_create_input) {
            Ok(input) => input,
            Err(err) => {
                return Err(mac_failed_response(
                    "mac.create.failed",
                    Some(&actor),
                    Some(&kid),
                    Some("mac-create"),
                    "mac_create",
                    err.as_ref(),
                ));
            }
        };
    let Some(profile) = state.mac_profile(input.profile()).await else {
        let err = crate::error::invalid_input("mac profile not found");
        return Err(mac_failed_response(
            "mac.create.failed",
            Some(&actor),
            Some(&kid),
            Some("mac-create"),
            "mac_create",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::mac::prepare_create(keys_db_state, &kid, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(mac_failed_response(
                "mac.create.failed",
                Some(&actor),
                Some(&kid),
                Some("mac-create"),
                "mac_create",
                err.as_ref(),
            ));
        }
    };

    match blocking::spawn_blocking_crypto(move || ops::mac::create(prepared)).await {
        Ok(output) => {
            audit::operation_success(
                "mac.create.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("mac-create"),
            );
            metrics::record_crypto_operation("mac_create", "success");
            info!(kid = %kid, "mac create response ready");
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "mac create endpoint failed");
            Err(mac_failed_response(
                "mac.create.failed",
                Some(&actor),
                Some(&kid),
                Some("mac-create"),
                "mac_create",
                err.as_ref(),
            ))
        }
    }
}

pub async fn create_batch_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::mac::MacCreateBatchOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "mac-create",
            Some("mac.create.batch.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(mac_failed_response(
            "mac.create.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("mac-create"),
            "mac_create_batch",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(mac_failed_response(
            "mac.create.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("mac-create"),
            "mac_create_batch",
            err.as_ref(),
        ));
    }
    let input = match ops::mac::parse_create_batch_input(request)
        .and_then(ops::mac::validate_create_batch_input)
    {
        Ok(input) => input,
        Err(err) => {
            return Err(mac_failed_response(
                "mac.create.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("mac-create"),
                "mac_create_batch",
                err.as_ref(),
            ));
        }
    };
    let Some(profile) = state.mac_profile(input.profile()).await else {
        let err = crate::error::invalid_input("mac profile not found");
        return Err(mac_failed_response(
            "mac.create.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("mac-create"),
            "mac_create_batch",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::mac::prepare_create_batch(keys_db_state, &kid, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(mac_failed_response(
                "mac.create.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("mac-create"),
                "mac_create_batch",
                err.as_ref(),
            ));
        }
    };

    match blocking::spawn_blocking_crypto(move || ops::mac::create_batch(prepared)).await {
        Ok(output) => {
            audit::operation_success(
                "mac.create.batch.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("mac-create"),
            );
            metrics::record_crypto_operation("mac_create_batch", "success");
            info!(kid = %kid, items_count = output.items_len(), "mac create batch response ready");
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "mac create batch endpoint failed");
            Err(mac_failed_response(
                "mac.create.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("mac-create"),
                "mac_create_batch",
                err.as_ref(),
            ))
        }
    }
}

pub async fn verify_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::mac::MacVerifyOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(&client, Some(&kid), "mac-verify", Some("mac.verify.denied"))
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(mac_failed_response(
            "mac.verify.failed",
            Some(&actor),
            Some(&kid),
            Some("mac-verify"),
            "mac_verify",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(mac_failed_response(
            "mac.verify.failed",
            Some(&actor),
            Some(&kid),
            Some("mac-verify"),
            "mac_verify",
            err.as_ref(),
        ));
    }
    let input =
        match ops::mac::parse_verify_input(request).and_then(ops::mac::validate_verify_input) {
            Ok(input) => input,
            Err(err) => {
                return Err(mac_failed_response(
                    "mac.verify.failed",
                    Some(&actor),
                    Some(&kid),
                    Some("mac-verify"),
                    "mac_verify",
                    err.as_ref(),
                ));
            }
        };
    let Some(profile) = state.mac_profile(input.profile()).await else {
        let err = crate::error::invalid_input("mac profile not found");
        return Err(mac_failed_response(
            "mac.verify.failed",
            Some(&actor),
            Some(&kid),
            Some("mac-verify"),
            "mac_verify",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::mac::prepare_verify(keys_db_state, &kid, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(mac_failed_response(
                "mac.verify.failed",
                Some(&actor),
                Some(&kid),
                Some("mac-verify"),
                "mac_verify",
                err.as_ref(),
            ));
        }
    };

    match blocking::spawn_blocking_crypto(move || ops::mac::verify(prepared)).await {
        Ok(output) => {
            audit::operation_success(
                "mac.verify.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("mac-verify"),
            );
            metrics::record_crypto_operation("mac_verify", "success");
            info!(kid = %kid, "mac verify response ready");
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "mac verify endpoint failed");
            Err(mac_failed_response(
                "mac.verify.failed",
                Some(&actor),
                Some(&kid),
                Some("mac-verify"),
                "mac_verify",
                err.as_ref(),
            ))
        }
    }
}

pub async fn verify_batch_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::mac::MacVerifyBatchOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "mac-verify",
            Some("mac.verify.batch.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(mac_failed_response(
            "mac.verify.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("mac-verify"),
            "mac_verify_batch",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(mac_failed_response(
            "mac.verify.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("mac-verify"),
            "mac_verify_batch",
            err.as_ref(),
        ));
    }
    let input = match ops::mac::parse_verify_batch_input(request)
        .and_then(ops::mac::validate_verify_batch_input)
    {
        Ok(input) => input,
        Err(err) => {
            return Err(mac_failed_response(
                "mac.verify.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("mac-verify"),
                "mac_verify_batch",
                err.as_ref(),
            ));
        }
    };
    let Some(profile) = state.mac_profile(input.profile()).await else {
        let err = crate::error::invalid_input("mac profile not found");
        return Err(mac_failed_response(
            "mac.verify.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("mac-verify"),
            "mac_verify_batch",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::mac::prepare_verify_batch(keys_db_state, &kid, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(mac_failed_response(
                "mac.verify.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("mac-verify"),
                "mac_verify_batch",
                err.as_ref(),
            ));
        }
    };

    match blocking::spawn_blocking_crypto(move || ops::mac::verify_batch(prepared)).await {
        Ok(output) => {
            audit::operation_success(
                "mac.verify.batch.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("mac-verify"),
            );
            metrics::record_crypto_operation("mac_verify_batch", "success");
            info!(kid = %kid, items_count = output.items_len(), "mac verify batch response ready");
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "mac verify batch endpoint failed");
            Err(mac_failed_response(
                "mac.verify.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("mac-verify"),
                "mac_verify_batch",
                err.as_ref(),
            ))
        }
    }
}

fn mac_failed_response(
    event_name: &str,
    actor: Option<&audit::Actor<'_>>,
    kid: Option<&str>,
    permission: Option<&str>,
    metric_operation: &str,
    err: &(dyn std::error::Error + Send + Sync + 'static),
) -> (StatusCode, Json<ErrorResponse>) {
    audit::operation_failed(event_name, actor, kid, None, permission, &err.to_string());
    metrics::record_crypto_operation(metric_operation, "failed");
    error_response(err)
}
