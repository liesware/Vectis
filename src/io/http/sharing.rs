use super::HttpState;
use super::error::{ErrorResponse, crypto_failed_response};
use super::extract::JsonBody;
use crate::core::{audit, blocking, metrics};
use crate::ops;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use tracing::{error, info};

pub async fn split_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::sharing::ShareSplitOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "share-split",
            Some("shares.split.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(failed(
            "shares.split.failed",
            &actor,
            Some(&kid),
            "share-split",
            "share_split",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(failed(
            "shares.split.failed",
            &actor,
            Some(&kid),
            "share-split",
            "share_split",
            err.as_ref(),
        ));
    }
    let input = match ops::sharing::parse_split_input(request)
        .and_then(ops::sharing::validate_split_input)
    {
        Ok(input) => input,
        Err(err) => {
            return Err(failed(
                "shares.split.failed",
                &actor,
                Some(&kid),
                "share-split",
                "share_split",
                err.as_ref(),
            ));
        }
    };
    let Some(profile) = state.sharing_profile(input.profile()).await else {
        let err = crate::error::invalid_input("sharing profile not found");
        return Err(failed(
            "shares.split.failed",
            &actor,
            Some(&kid),
            "share-split",
            "share_split",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys| ops::sharing::prepare_split(keys, &kid, profile, input))
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(failed(
                "shares.split.failed",
                &actor,
                Some(&kid),
                "share-split",
                "share_split",
                err.as_ref(),
            ));
        }
    };

    match blocking::spawn_blocking_crypto(move || ops::sharing::split(prepared)).await {
        Ok(output) => {
            audit::operation_success(
                "shares.split.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("share-split"),
            );
            metrics::record_crypto_operation("share_split", "success");
            info!(kid = %kid, shares = output.shares_len(), "shares split response ready");
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "shares split endpoint failed");
            Err(failed(
                "shares.split.failed",
                &actor,
                Some(&kid),
                "share-split",
                "share_split",
                err.as_ref(),
            ))
        }
    }
}

pub async fn combine_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::sharing::ShareCombineOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    let actor = audit::actor_from_client(&client);
    let input = match ops::sharing::parse_combine_input(request)
        .and_then(ops::sharing::validate_combine_input)
    {
        Ok(input) => input,
        Err(err) => {
            return Err(failed(
                "shares.combine.failed",
                &actor,
                None,
                "share-combine",
                "share_combine",
                err.as_ref(),
            ));
        }
    };
    let kid = input.kid().to_string();
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "share-combine",
            Some("shares.combine.denied"),
        )
        .await?;
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(failed(
            "shares.combine.failed",
            &actor,
            Some(&kid),
            "share-combine",
            "share_combine",
            err.as_ref(),
        ));
    }
    let Some(profile) = state.sharing_profile(input.profile()).await else {
        let err = crate::error::invalid_input("sharing profile not found");
        return Err(failed(
            "shares.combine.failed",
            &actor,
            Some(&kid),
            "share-combine",
            "share_combine",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys| ops::sharing::prepare_combine(keys, profile, input))
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(failed(
                "shares.combine.failed",
                &actor,
                Some(&kid),
                "share-combine",
                "share_combine",
                err.as_ref(),
            ));
        }
    };

    match blocking::spawn_blocking_crypto(move || ops::sharing::combine(prepared)).await {
        Ok(output) => {
            audit::operation_success(
                "shares.combine.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("share-combine"),
            );
            metrics::record_crypto_operation("share_combine", "success");
            info!(kid = %kid, "shares combine response ready");
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "shares combine endpoint failed");
            Err(failed(
                "shares.combine.failed",
                &actor,
                Some(&kid),
                "share-combine",
                "share_combine",
                err.as_ref(),
            ))
        }
    }
}

fn failed(
    event: &str,
    actor: &crate::core::audit::Actor,
    kid: Option<&str>,
    permission: &str,
    metric: &str,
    err: &(dyn std::error::Error + Send + Sync + 'static),
) -> (StatusCode, Json<ErrorResponse>) {
    crypto_failed_response(event, Some(actor), kid, Some(permission), metric, err)
}
