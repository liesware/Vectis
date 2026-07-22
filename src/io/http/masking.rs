use super::HttpState;
use super::error::{ErrorResponse, crypto_failed_response};
use super::extract::JsonBody;
use crate::core::{audit, metrics};
use crate::ops;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use tracing::{error, info};

pub async fn mask_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::masking::MaskOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(&client, Some(&kid), "mask", Some("mask.denied"))
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(crypto_failed_response(
            "mask.failed",
            Some(&actor),
            Some(&kid),
            Some("mask"),
            "mask",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(crypto_failed_response(
            "mask.failed",
            Some(&actor),
            Some(&kid),
            Some("mask"),
            "mask",
            err.as_ref(),
        ));
    }
    let input =
        match ops::masking::parse_mask_input(request).and_then(ops::masking::validate_mask_input) {
            Ok(input) => input,
            Err(err) => {
                return Err(crypto_failed_response(
                    "mask.failed",
                    Some(&actor),
                    Some(&kid),
                    Some("mask"),
                    "mask",
                    err.as_ref(),
                ));
            }
        };
    let Some(profile) = state.masking_profile(input.profile()).await else {
        let err = crate::error::invalid_input("masking profile not found");
        return Err(crypto_failed_response(
            "mask.failed",
            Some(&actor),
            Some(&kid),
            Some("mask"),
            "mask",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::masking::prepare_mask(keys_db_state, &kid, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(crypto_failed_response(
                "mask.failed",
                Some(&actor),
                Some(&kid),
                Some("mask"),
                "mask",
                err.as_ref(),
            ));
        }
    };

    match ops::masking::mask(prepared) {
        Ok(output) => {
            audit::operation_success("mask.success", Some(&actor), Some(&kid), None, Some("mask"));
            metrics::record_crypto_operation("mask", "success");
            info!(kid = %kid, "mask response ready");
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "mask endpoint failed");
            Err(crypto_failed_response(
                "mask.failed",
                Some(&actor),
                Some(&kid),
                Some("mask"),
                "mask",
                err.as_ref(),
            ))
        }
    }
}

pub async fn mask_batch_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::masking::MaskBatchOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(&client, Some(&kid), "mask", Some("mask.batch.denied"))
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(crypto_failed_response(
            "mask.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("mask"),
            "mask_batch",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(crypto_failed_response(
            "mask.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("mask"),
            "mask_batch",
            err.as_ref(),
        ));
    }
    let input = match ops::masking::parse_mask_batch_input(request)
        .and_then(ops::masking::validate_mask_batch_input)
    {
        Ok(input) => input,
        Err(err) => {
            return Err(crypto_failed_response(
                "mask.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("mask"),
                "mask_batch",
                err.as_ref(),
            ));
        }
    };
    let Some(profile) = state.masking_profile(input.profile()).await else {
        let err = crate::error::invalid_input("masking profile not found");
        return Err(crypto_failed_response(
            "mask.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("mask"),
            "mask_batch",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::masking::prepare_mask_batch(keys_db_state, &kid, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(crypto_failed_response(
                "mask.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("mask"),
                "mask_batch",
                err.as_ref(),
            ));
        }
    };

    match ops::masking::mask_batch(prepared) {
        Ok(output) => {
            audit::operation_success(
                "mask.batch.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("mask"),
            );
            metrics::record_crypto_operation("mask_batch", "success");
            info!(
                kid = %kid,
                items_count = output.items_len(),
                "mask batch response ready"
            );
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "mask batch endpoint failed");
            Err(crypto_failed_response(
                "mask.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("mask"),
                "mask_batch",
                err.as_ref(),
            ))
        }
    }
}
