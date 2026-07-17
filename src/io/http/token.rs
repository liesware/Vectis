use super::HttpState;
use super::error::{ErrorResponse, error_response};
use super::extract::JsonBody;
use crate::core::{audit, blocking, metrics, storage::TokenRow};
use crate::ops;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use tracing::{error, info};

pub async fn encode_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::tokenization::TokenEncodeOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "token-encode",
            Some("token.encode.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(token_failed_response(
            "token.encode.failed",
            Some(&actor),
            Some(&kid),
            Some("token-encode"),
            "token_encode",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(token_failed_response(
            "token.encode.failed",
            Some(&actor),
            Some(&kid),
            Some("token-encode"),
            "token_encode",
            err.as_ref(),
        ));
    }
    let input = match ops::tokenization::parse_encode_input(request)
        .and_then(ops::tokenization::validate_encode_input)
    {
        Ok(input) => input,
        Err(err) => {
            return Err(token_failed_response(
                "token.encode.failed",
                Some(&actor),
                Some(&kid),
                Some("token-encode"),
                "token_encode",
                err.as_ref(),
            ));
        }
    };
    let Some(profile) = state.tokenization_profile(input.profile()).await else {
        let err = crate::error::invalid_input("tokenization profile not found");
        return Err(token_failed_response(
            "token.encode.failed",
            Some(&actor),
            Some(&kid),
            Some("token-encode"),
            "token_encode",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::tokenization::prepare_encode(keys_db_state, &kid, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(token_failed_response(
                "token.encode.failed",
                Some(&actor),
                Some(&kid),
                Some("token-encode"),
                "token_encode",
                err.as_ref(),
            ));
        }
    };

    let record =
        match blocking::spawn_blocking_crypto(move || ops::tokenization::encode(prepared)).await {
            Ok(record) => record,
            Err(err) => {
                error!(error = %err, kid = %kid, "token encode endpoint failed");
                return Err(token_failed_response(
                    "token.encode.failed",
                    Some(&actor),
                    Some(&kid),
                    Some("token-encode"),
                    "token_encode",
                    err.as_ref(),
                ));
            }
        };

    if let Err(err) = state
        .storage()
        .save_token(&record.kid, &record.hashid, &record.data)
        .await
    {
        error!(error = %err, kid = %kid, "token encode storage insert failed");
        return Err(token_failed_response(
            "token.encode.failed",
            Some(&actor),
            Some(&kid),
            Some("token-encode"),
            "token_encode",
            err.as_ref(),
        ));
    }

    audit::operation_success(
        "token.encode.success",
        Some(&actor),
        Some(&kid),
        None,
        Some("token-encode"),
    );
    metrics::record_crypto_operation("token_encode", "success");
    info!(kid = %kid, "token encode response ready");
    Ok(Json(record.output))
}

pub async fn encode_batch_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::tokenization::TokenEncodeBatchOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "token-encode",
            Some("token.encode.batch.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(token_failed_response(
            "token.encode.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("token-encode"),
            "token_encode_batch",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(token_failed_response(
            "token.encode.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("token-encode"),
            "token_encode_batch",
            err.as_ref(),
        ));
    }
    let input = match ops::tokenization::parse_encode_batch_input(request)
        .and_then(ops::tokenization::validate_encode_batch_input)
    {
        Ok(input) => input,
        Err(err) => {
            return Err(token_failed_response(
                "token.encode.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("token-encode"),
                "token_encode_batch",
                err.as_ref(),
            ));
        }
    };
    let Some(profile) = state.tokenization_profile(input.profile()).await else {
        let err = crate::error::invalid_input("tokenization profile not found");
        return Err(token_failed_response(
            "token.encode.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("token-encode"),
            "token_encode_batch",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::tokenization::prepare_encode_batch(keys_db_state, &kid, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(token_failed_response(
                "token.encode.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("token-encode"),
                "token_encode_batch",
                err.as_ref(),
            ));
        }
    };

    let batch =
        match blocking::spawn_blocking_crypto(move || ops::tokenization::encode_batch(prepared))
            .await
        {
            Ok(batch) => batch,
            Err(err) => {
                error!(error = %err, kid = %kid, "token encode batch endpoint failed");
                return Err(token_failed_response(
                    "token.encode.batch.failed",
                    Some(&actor),
                    Some(&kid),
                    Some("token-encode"),
                    "token_encode_batch",
                    err.as_ref(),
                ));
            }
        };
    let rows = batch
        .records
        .into_iter()
        .map(|record| TokenRow {
            kid: record.kid,
            hashid: record.hashid,
            data: record.data,
        })
        .collect::<Vec<_>>();

    if let Err(err) = state.storage().save_tokens_batch(&rows).await {
        error!(error = %err, kid = %kid, "token encode batch storage insert failed");
        return Err(token_failed_response(
            "token.encode.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("token-encode"),
            "token_encode_batch",
            err.as_ref(),
        ));
    }

    audit::operation_success(
        "token.encode.batch.success",
        Some(&actor),
        Some(&kid),
        None,
        Some("token-encode"),
    );
    metrics::record_crypto_operation("token_encode_batch", "success");
    info!(
        kid = %kid,
        items_count = batch.output.items_len(),
        "token encode batch response ready"
    );
    Ok(Json(batch.output))
}

pub async fn decode_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::tokenization::TokenDecodeOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    let input = ops::tokenization::parse_decode_input(request)
        .and_then(ops::tokenization::validate_decode_input)
        .map_err(|err| {
            token_failed_response(
                "token.decode.failed",
                None,
                None,
                Some("token-decode"),
                "token_decode",
                err.as_ref(),
            )
        })?;
    let kid = input.kid().to_string();
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "token-decode",
            Some("token.decode.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(token_failed_response(
            "token.decode.failed",
            Some(&actor),
            Some(&kid),
            Some("token-decode"),
            "token_decode",
            err.as_ref(),
        ));
    }
    let Some(profile) = state.tokenization_profile(input.profile()).await else {
        let err = crate::error::invalid_input("tokenization profile not found");
        return Err(token_failed_response(
            "token.decode.failed",
            Some(&actor),
            Some(&kid),
            Some("token-decode"),
            "token_decode",
            err.as_ref(),
        ));
    };
    let hashid = match crate::core::tokenization::hash_token(&profile, input.token()) {
        Ok(hashid) => hashid,
        Err(err) => {
            return Err(token_failed_response(
                "token.decode.failed",
                Some(&actor),
                Some(&kid),
                Some("token-decode"),
                "token_decode",
                err.as_ref(),
            ));
        }
    };
    let row = match state.storage().get_token(&kid, &hashid).await {
        Ok(row) => row,
        Err(err) => {
            return Err(token_failed_response(
                "token.decode.failed",
                Some(&actor),
                Some(&kid),
                Some("token-decode"),
                "token_decode",
                err.as_ref(),
            ));
        }
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::tokenization::prepare_decode(keys_db_state, profile, input, row.data)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(token_failed_response(
                "token.decode.failed",
                Some(&actor),
                Some(&kid),
                Some("token-decode"),
                "token_decode",
                err.as_ref(),
            ));
        }
    };

    match blocking::spawn_blocking_crypto(move || ops::tokenization::decode(prepared)).await {
        Ok(output) => {
            audit::operation_success(
                "token.decode.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("token-decode"),
            );
            metrics::record_crypto_operation("token_decode", "success");
            info!(kid = %kid, "token decode response ready");
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "token decode endpoint failed");
            Err(token_failed_response(
                "token.decode.failed",
                Some(&actor),
                Some(&kid),
                Some("token-decode"),
                "token_decode",
                err.as_ref(),
            ))
        }
    }
}

pub async fn decode_batch_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::tokenization::TokenDecodeBatchOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    let input = ops::tokenization::parse_decode_batch_input(request)
        .and_then(ops::tokenization::validate_decode_batch_input)
        .map_err(|err| {
            token_failed_response(
                "token.decode.batch.failed",
                None,
                None,
                Some("token-decode"),
                "token_decode_batch",
                err.as_ref(),
            )
        })?;
    let kid = input.kid().to_string();
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "token-decode",
            Some("token.decode.batch.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(token_failed_response(
            "token.decode.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("token-decode"),
            "token_decode_batch",
            err.as_ref(),
        ));
    }
    let Some(profile) = state.tokenization_profile(input.profile()).await else {
        let err = crate::error::invalid_input("tokenization profile not found");
        return Err(token_failed_response(
            "token.decode.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("token-decode"),
            "token_decode_batch",
            err.as_ref(),
        ));
    };
    if let Err(err) = state
        .with_keys_db_state(|keys_db_state| {
            ops::tokenization::authorize_decode_batch(keys_db_state, &profile, &kid)
        })
        .await
    {
        return Err(token_failed_response(
            "token.decode.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("token-decode"),
            "token_decode_batch",
            err.as_ref(),
        ));
    }
    let mut hashids = Vec::new();
    for (index, token) in input.tokens().enumerate() {
        match crate::core::tokenization::hash_token(&profile, token) {
            Ok(hashid) => hashids.push(hashid),
            Err(err) => {
                let err = crate::error::with_prefix(&format!("batch item {index} failed"), err);
                return Err(token_failed_response(
                    "token.decode.batch.failed",
                    Some(&actor),
                    Some(&kid),
                    Some("token-decode"),
                    "token_decode_batch",
                    err.as_ref(),
                ));
            }
        }
    }
    let refs = input.refs().map(str::to_string).collect::<Vec<_>>();
    let found = match state.storage().get_tokens_batch(&kid, &hashids).await {
        Ok(found) => found,
        Err(err) => {
            return Err(token_failed_response(
                "token.decode.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("token-decode"),
                "token_decode_batch",
                err.as_ref(),
            ));
        }
    };
    let mut rows = Vec::with_capacity(hashids.len());
    for (index, hashid) in hashids.iter().enumerate() {
        let Some(data) = found.get(hashid) else {
            let err = crate::error::with_prefix(
                &format!("batch item {index} failed"),
                crate::error::not_found("token not found"),
            );
            return Err(token_failed_response(
                "token.decode.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("token-decode"),
                "token_decode_batch",
                err.as_ref(),
            ));
        };
        rows.push(data.clone());
    }
    let prepared =
        match ops::tokenization::prepare_decode_batch(profile, kid.clone(), refs, hashids, rows) {
            Ok(prepared) => prepared,
            Err(err) => {
                return Err(token_failed_response(
                    "token.decode.batch.failed",
                    Some(&actor),
                    Some(&kid),
                    Some("token-decode"),
                    "token_decode_batch",
                    err.as_ref(),
                ));
            }
        };

    match blocking::spawn_blocking_crypto(move || ops::tokenization::decode_batch(prepared)).await {
        Ok(output) => {
            audit::operation_success(
                "token.decode.batch.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("token-decode"),
            );
            metrics::record_crypto_operation("token_decode_batch", "success");
            info!(
                kid = %kid,
                items_count = output.items_len(),
                "token decode batch response ready"
            );
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "token decode batch endpoint failed");
            Err(token_failed_response(
                "token.decode.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("token-decode"),
                "token_decode_batch",
                err.as_ref(),
            ))
        }
    }
}

fn token_failed_response(
    event: &str,
    actor: Option<&audit::Actor<'_>>,
    kid: Option<&str>,
    action: Option<&str>,
    operation: &str,
    err: &(dyn std::error::Error + Send + Sync + 'static),
) -> (StatusCode, Json<ErrorResponse>) {
    audit::operation_failed(event, actor, kid, None, action, &err.to_string());
    metrics::record_crypto_operation(operation, "failed");
    error_response(err)
}
