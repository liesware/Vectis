use super::HttpState;
use super::error::{ErrorResponse, crypto_failed_response};
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
) -> Result<Json<ops::commitments::CommitCreateOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "commit-create",
            Some("commit.create.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(crypto_failed_response(
            "commit.create.failed",
            Some(&actor),
            Some(&kid),
            Some("commit-create"),
            "commit_create",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(crypto_failed_response(
            "commit.create.failed",
            Some(&actor),
            Some(&kid),
            Some("commit-create"),
            "commit_create",
            err.as_ref(),
        ));
    }
    let input = match ops::commitments::parse_create_input(request)
        .and_then(ops::commitments::validate_create_input)
    {
        Ok(input) => input,
        Err(err) => {
            return Err(crypto_failed_response(
                "commit.create.failed",
                Some(&actor),
                Some(&kid),
                Some("commit-create"),
                "commit_create",
                err.as_ref(),
            ));
        }
    };
    let Some(profile) = state.commitment_profile(input.profile()).await else {
        let err = crate::error::invalid_input("commitment profile not found");
        return Err(crypto_failed_response(
            "commit.create.failed",
            Some(&actor),
            Some(&kid),
            Some("commit-create"),
            "commit_create",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::commitments::prepare_create(keys_db_state, &kid, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(crypto_failed_response(
                "commit.create.failed",
                Some(&actor),
                Some(&kid),
                Some("commit-create"),
                "commit_create",
                err.as_ref(),
            ));
        }
    };

    match blocking::spawn_blocking_crypto(move || ops::commitments::create(prepared)).await {
        Ok(output) => {
            audit::operation_success(
                "commit.create.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("commit-create"),
            );
            metrics::record_crypto_operation("commit_create", "success");
            info!(kid = %kid, "commit create response ready");
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "commit create endpoint failed");
            Err(crypto_failed_response(
                "commit.create.failed",
                Some(&actor),
                Some(&kid),
                Some("commit-create"),
                "commit_create",
                err.as_ref(),
            ))
        }
    }
}

pub async fn verify_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::commitments::CommitVerifyOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    let actor = audit::actor_from_client(&client);
    let input = match ops::commitments::parse_verify_input(request)
        .and_then(ops::commitments::validate_verify_input)
    {
        Ok(input) => input,
        Err(err) => {
            return Err(crypto_failed_response(
                "commit.verify.failed",
                Some(&actor),
                None,
                Some("commit-verify"),
                "commit_verify",
                err.as_ref(),
            ));
        }
    };
    let kid = input.kid().to_string();
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "commit-verify",
            Some("commit.verify.denied"),
        )
        .await?;

    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(crypto_failed_response(
            "commit.verify.failed",
            Some(&actor),
            Some(&kid),
            Some("commit-verify"),
            "commit_verify",
            err.as_ref(),
        ));
    }
    let Some(profile) = state.commitment_profile(input.profile()).await else {
        let err = crate::error::invalid_input("commitment profile not found");
        return Err(crypto_failed_response(
            "commit.verify.failed",
            Some(&actor),
            Some(&kid),
            Some("commit-verify"),
            "commit_verify",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::commitments::prepare_verify(keys_db_state, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(crypto_failed_response(
                "commit.verify.failed",
                Some(&actor),
                Some(&kid),
                Some("commit-verify"),
                "commit_verify",
                err.as_ref(),
            ));
        }
    };

    match blocking::spawn_blocking_crypto(move || ops::commitments::verify(prepared)).await {
        Ok(output) => {
            audit::operation_success(
                "commit.verify.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("commit-verify"),
            );
            metrics::record_crypto_operation("commit_verify", "success");
            info!(kid = %kid, "commit verify response ready");
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "commit verify endpoint failed");
            Err(crypto_failed_response(
                "commit.verify.failed",
                Some(&actor),
                Some(&kid),
                Some("commit-verify"),
                "commit_verify",
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
) -> Result<Json<ops::commitments::CommitCreateBatchOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "commit-create",
            Some("commit.create.batch.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(crypto_failed_response(
            "commit.create.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("commit-create"),
            "commit_create_batch",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(crypto_failed_response(
            "commit.create.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("commit-create"),
            "commit_create_batch",
            err.as_ref(),
        ));
    }
    let input = match ops::commitments::parse_create_batch_input(request)
        .and_then(ops::commitments::validate_create_batch_input)
    {
        Ok(input) => input,
        Err(err) => {
            return Err(crypto_failed_response(
                "commit.create.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("commit-create"),
                "commit_create_batch",
                err.as_ref(),
            ));
        }
    };
    let Some(profile) = state.commitment_profile(input.profile()).await else {
        let err = crate::error::invalid_input("commitment profile not found");
        return Err(crypto_failed_response(
            "commit.create.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("commit-create"),
            "commit_create_batch",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::commitments::prepare_create_batch(keys_db_state, &kid, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(crypto_failed_response(
                "commit.create.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("commit-create"),
                "commit_create_batch",
                err.as_ref(),
            ));
        }
    };

    match blocking::spawn_blocking_crypto(move || ops::commitments::create_batch(prepared)).await {
        Ok(output) => {
            audit::operation_success(
                "commit.create.batch.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("commit-create"),
            );
            metrics::record_crypto_operation("commit_create_batch", "success");
            info!(kid = %kid, items_count = output.items_len(), "commit create batch response ready");
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "commit create batch endpoint failed");
            Err(crypto_failed_response(
                "commit.create.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("commit-create"),
                "commit_create_batch",
                err.as_ref(),
            ))
        }
    }
}

pub async fn verify_batch_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::commitments::CommitVerifyBatchOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    let actor = audit::actor_from_client(&client);
    let input = match ops::commitments::parse_verify_batch_input(request)
        .and_then(ops::commitments::validate_verify_batch_input)
    {
        Ok(input) => input,
        Err(err) => {
            return Err(crypto_failed_response(
                "commit.verify.batch.failed",
                Some(&actor),
                None,
                Some("commit-verify"),
                "commit_verify_batch",
                err.as_ref(),
            ));
        }
    };
    let kid = input.kid().to_string();
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "commit-verify",
            Some("commit.verify.batch.denied"),
        )
        .await?;

    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(crypto_failed_response(
            "commit.verify.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("commit-verify"),
            "commit_verify_batch",
            err.as_ref(),
        ));
    }
    let Some(profile) = state.commitment_profile(input.profile()).await else {
        let err = crate::error::invalid_input("commitment profile not found");
        return Err(crypto_failed_response(
            "commit.verify.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("commit-verify"),
            "commit_verify_batch",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::commitments::prepare_verify_batch(keys_db_state, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(crypto_failed_response(
                "commit.verify.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("commit-verify"),
                "commit_verify_batch",
                err.as_ref(),
            ));
        }
    };

    match blocking::spawn_blocking_crypto(move || ops::commitments::verify_batch(prepared)).await {
        Ok(output) => {
            audit::operation_success(
                "commit.verify.batch.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("commit-verify"),
            );
            metrics::record_crypto_operation("commit_verify_batch", "success");
            info!(kid = %kid, items_count = output.items_len(), "commit verify batch response ready");
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "commit verify batch endpoint failed");
            Err(crypto_failed_response(
                "commit.verify.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("commit-verify"),
                "commit_verify_batch",
                err.as_ref(),
            ))
        }
    }
}
