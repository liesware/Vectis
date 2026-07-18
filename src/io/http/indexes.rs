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
) -> Result<Json<ops::indexes::IndexCreateOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "index-create",
            Some("index.create.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(crypto_failed_response(
            "index.create.failed",
            Some(&actor),
            Some(&kid),
            Some("index-create"),
            "index_create",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(crypto_failed_response(
            "index.create.failed",
            Some(&actor),
            Some(&kid),
            Some("index-create"),
            "index_create",
            err.as_ref(),
        ));
    }
    let input = match ops::indexes::parse_create_input(request)
        .and_then(ops::indexes::validate_create_input)
    {
        Ok(input) => input,
        Err(err) => {
            return Err(crypto_failed_response(
                "index.create.failed",
                Some(&actor),
                Some(&kid),
                Some("index-create"),
                "index_create",
                err.as_ref(),
            ));
        }
    };
    let Some(profile) = state.mac_profile(input.profile()).await else {
        let err = crate::error::invalid_input("mac profile not found");
        return Err(crypto_failed_response(
            "index.create.failed",
            Some(&actor),
            Some(&kid),
            Some("index-create"),
            "index_create",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::indexes::prepare_create(keys_db_state, &kid, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(crypto_failed_response(
                "index.create.failed",
                Some(&actor),
                Some(&kid),
                Some("index-create"),
                "index_create",
                err.as_ref(),
            ));
        }
    };

    let result = match blocking::spawn_blocking_crypto(move || ops::indexes::create(prepared)).await
    {
        Ok(result) => result,
        Err(err) => {
            error!(error = %err, kid = %kid, "index create endpoint failed");
            return Err(crypto_failed_response(
                "index.create.failed",
                Some(&actor),
                Some(&kid),
                Some("index-create"),
                "index_create",
                err.as_ref(),
            ));
        }
    };
    if let Err(err) = state
        .storage()
        .save_index(&result.row.kid, &result.row.digest)
        .await
    {
        return Err(crypto_failed_response(
            "index.create.failed",
            Some(&actor),
            Some(&kid),
            Some("index-create"),
            "index_create",
            err.as_ref(),
        ));
    }

    audit::operation_success(
        "index.create.success",
        Some(&actor),
        Some(&kid),
        None,
        Some("index-create"),
    );
    metrics::record_crypto_operation("index_create", "success");
    info!(kid = %kid, "index create response ready");
    Ok(Json(result.output))
}

pub async fn verify_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::indexes::IndexVerifyOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    let actor = audit::actor_from_client(&client);
    let input = match ops::indexes::parse_verify_input(request)
        .and_then(ops::indexes::validate_verify_input)
    {
        Ok(input) => input,
        Err(err) => {
            return Err(crypto_failed_response(
                "index.verify.failed",
                Some(&actor),
                None,
                Some("index-verify"),
                "index_verify",
                err.as_ref(),
            ));
        }
    };
    let kid = input.kid().to_string();
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "index-verify",
            Some("index.verify.denied"),
        )
        .await?;

    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(crypto_failed_response(
            "index.verify.failed",
            Some(&actor),
            Some(&kid),
            Some("index-verify"),
            "index_verify",
            err.as_ref(),
        ));
    }
    let Some(profile) = state.mac_profile(input.profile()).await else {
        let err = crate::error::invalid_input("mac profile not found");
        return Err(crypto_failed_response(
            "index.verify.failed",
            Some(&actor),
            Some(&kid),
            Some("index-verify"),
            "index_verify",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::indexes::prepare_verify(keys_db_state, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(crypto_failed_response(
                "index.verify.failed",
                Some(&actor),
                Some(&kid),
                Some("index-verify"),
                "index_verify",
                err.as_ref(),
            ));
        }
    };

    let (prepared, digest) = match blocking::spawn_blocking_crypto(move || {
        let digest = ops::indexes::digest(&prepared)?;
        Ok((prepared, digest))
    })
    .await
    {
        Ok(digest) => digest,
        Err(err) => {
            error!(error = %err, kid = %kid, "index verify endpoint failed");
            return Err(crypto_failed_response(
                "index.verify.failed",
                Some(&actor),
                Some(&kid),
                Some("index-verify"),
                "index_verify",
                err.as_ref(),
            ));
        }
    };
    let matched = match state.storage().index_exists(&kid, &digest).await {
        Ok(matched) => matched,
        Err(err) => {
            return Err(crypto_failed_response(
                "index.verify.failed",
                Some(&actor),
                Some(&kid),
                Some("index-verify"),
                "index_verify",
                err.as_ref(),
            ));
        }
    };
    let output = ops::indexes::verify(prepared, digest, matched);

    audit::operation_success(
        "index.verify.success",
        Some(&actor),
        Some(&kid),
        None,
        Some("index-verify"),
    );
    metrics::record_crypto_operation("index_verify", "success");
    info!(kid = %kid, matched, "index verify response ready");
    Ok(Json(output))
}

pub async fn create_batch_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::indexes::IndexCreateBatchOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "index-create",
            Some("index.create.batch.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(crypto_failed_response(
            "index.create.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("index-create"),
            "index_create_batch",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(crypto_failed_response(
            "index.create.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("index-create"),
            "index_create_batch",
            err.as_ref(),
        ));
    }
    let input = match ops::indexes::parse_batch_input(request)
        .and_then(ops::indexes::validate_batch_input)
    {
        Ok(input) => input,
        Err(err) => {
            return Err(crypto_failed_response(
                "index.create.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("index-create"),
                "index_create_batch",
                err.as_ref(),
            ));
        }
    };
    let Some(profile) = state.mac_profile(input.profile()).await else {
        let err = crate::error::invalid_input("mac profile not found");
        return Err(crypto_failed_response(
            "index.create.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("index-create"),
            "index_create_batch",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::indexes::prepare_create_batch(keys_db_state, &kid, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(crypto_failed_response(
                "index.create.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("index-create"),
                "index_create_batch",
                err.as_ref(),
            ));
        }
    };

    let result =
        match blocking::spawn_blocking_crypto(move || ops::indexes::create_batch(prepared)).await {
            Ok(result) => result,
            Err(err) => {
                error!(error = %err, kid = %kid, "index create batch endpoint failed");
                return Err(crypto_failed_response(
                    "index.create.batch.failed",
                    Some(&actor),
                    Some(&kid),
                    Some("index-create"),
                    "index_create_batch",
                    err.as_ref(),
                ));
            }
        };
    if let Err(err) = state.storage().save_indexes_batch(&result.rows).await {
        return Err(crypto_failed_response(
            "index.create.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("index-create"),
            "index_create_batch",
            err.as_ref(),
        ));
    }

    audit::operation_success(
        "index.create.batch.success",
        Some(&actor),
        Some(&kid),
        None,
        Some("index-create"),
    );
    metrics::record_crypto_operation("index_create_batch", "success");
    info!(kid = %kid, items_count = result.output.items_len(), "index create batch response ready");
    Ok(Json(result.output))
}

pub async fn verify_batch_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::indexes::IndexVerifyBatchOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    let actor = audit::actor_from_client(&client);
    let input = match ops::indexes::parse_verify_batch_input(request)
        .and_then(ops::indexes::validate_verify_batch_input)
    {
        Ok(input) => input,
        Err(err) => {
            return Err(crypto_failed_response(
                "index.verify.batch.failed",
                Some(&actor),
                None,
                Some("index-verify"),
                "index_verify_batch",
                err.as_ref(),
            ));
        }
    };
    let kid = input.kid().to_string();
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "index-verify",
            Some("index.verify.batch.denied"),
        )
        .await?;

    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(crypto_failed_response(
            "index.verify.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("index-verify"),
            "index_verify_batch",
            err.as_ref(),
        ));
    }
    let Some(profile) = state.mac_profile(input.profile()).await else {
        let err = crate::error::invalid_input("mac profile not found");
        return Err(crypto_failed_response(
            "index.verify.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("index-verify"),
            "index_verify_batch",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::indexes::prepare_verify_batch(keys_db_state, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(crypto_failed_response(
                "index.verify.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("index-verify"),
                "index_verify_batch",
                err.as_ref(),
            ));
        }
    };

    let (prepared, digests) = match blocking::spawn_blocking_crypto(move || {
        let digests = ops::indexes::batch_digests(&prepared)?;
        Ok((prepared, digests))
    })
    .await
    {
        Ok(digests) => digests,
        Err(err) => {
            error!(error = %err, kid = %kid, "index verify batch endpoint failed");
            return Err(crypto_failed_response(
                "index.verify.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("index-verify"),
                "index_verify_batch",
                err.as_ref(),
            ));
        }
    };
    let present = match state.storage().indexes_matching(&kid, &digests).await {
        Ok(present) => present,
        Err(err) => {
            return Err(crypto_failed_response(
                "index.verify.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("index-verify"),
                "index_verify_batch",
                err.as_ref(),
            ));
        }
    };
    let matches = digests
        .iter()
        .map(|digest| present.contains(digest))
        .collect::<Vec<_>>();
    let output = match ops::indexes::verify_batch(prepared, digests, matches) {
        Ok(output) => output,
        Err(err) => {
            return Err(crypto_failed_response(
                "index.verify.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("index-verify"),
                "index_verify_batch",
                err.as_ref(),
            ));
        }
    };

    audit::operation_success(
        "index.verify.batch.success",
        Some(&actor),
        Some(&kid),
        None,
        Some("index-verify"),
    );
    metrics::record_crypto_operation("index_verify_batch", "success");
    info!(kid = %kid, items_count = output.items_len(), "index verify batch response ready");
    Ok(Json(output))
}
