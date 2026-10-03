use super::HttpState;
use super::error::{ErrorResponse, crypto_failed_response};
use super::extract::JsonBody;
use crate::core::{
    audit, blocking, metrics,
    storage::{TokenBatchConsumeError, TokenRow},
};
use crate::ops;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use std::collections::{HashMap, HashSet};
use tracing::{error, info};

pub async fn encode_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::tokenization::TokenEncodeOutput>, (StatusCode, Json<ErrorResponse>)> {
    encode(state, kid, None, headers, request).await
}

pub async fn encode_subject_endpoint(
    State(state): State<HttpState>,
    Path((kid, subject)): Path<(String, String)>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::tokenization::TokenEncodeOutput>, (StatusCode, Json<ErrorResponse>)> {
    encode(state, kid, Some(subject), headers, request).await
}

async fn encode(
    state: HttpState,
    kid: String,
    subject: Option<String>,
    headers: HeaderMap,
    request: serde_json::Value,
) -> Result<Json<ops::tokenization::TokenEncodeOutput>, (StatusCode, Json<ErrorResponse>)> {
    let request_context = state.authorize_request(&headers).await?;
    request_context.require_permission_for(
        Some(&kid),
        "token-encode",
        Some("token.encode.denied"),
    )?;
    let actor = audit::actor_from_client(request_context.client());

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(crypto_failed_response(
            "token.encode.failed",
            Some(&actor),
            Some(&kid),
            Some("token-encode"),
            "token_encode",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(crypto_failed_response(
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
            return Err(crypto_failed_response(
                "token.encode.failed",
                Some(&actor),
                Some(&kid),
                Some("token-encode"),
                "token_encode",
                err.as_ref(),
            ));
        }
    };
    let Some(profile) = request_context
        .config()
        .tokenization_profiles
        .get(input.profile())
    else {
        let err = crate::error::invalid_input("tokenization profile not found");
        return Err(crypto_failed_response(
            "token.encode.failed",
            Some(&actor),
            Some(&kid),
            Some("token-encode"),
            "token_encode",
            err.as_ref(),
        ));
    };
    let profile = super::subject::token_context(
        &state,
        profile,
        &kid,
        subject.as_deref(),
        ops::keys::ProfileUse::NewUse,
    )
    .await
    .map_err(|err| {
        crypto_failed_response(
            "token.encode.failed",
            Some(&actor),
            Some(&kid),
            Some("token-encode"),
            "token_encode",
            err.as_ref(),
        )
    })?;
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::tokenization::prepare_encode(keys_db_state, &kid, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(crypto_failed_response(
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
                return Err(crypto_failed_response(
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
        .save_token_for_subject(
            &record.kid,
            &record.hashid,
            &record.data,
            record.subject.as_deref(),
        )
        .await
    {
        error!(error = %err, kid = %kid, "token encode storage insert failed");
        return Err(crypto_failed_response(
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
    encode_batch(state, kid, None, headers, request).await
}

pub async fn encode_subject_batch_endpoint(
    State(state): State<HttpState>,
    Path((kid, subject)): Path<(String, String)>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::tokenization::TokenEncodeBatchOutput>, (StatusCode, Json<ErrorResponse>)> {
    encode_batch(state, kid, Some(subject), headers, request).await
}

async fn encode_batch(
    state: HttpState,
    kid: String,
    subject: Option<String>,
    headers: HeaderMap,
    request: serde_json::Value,
) -> Result<Json<ops::tokenization::TokenEncodeBatchOutput>, (StatusCode, Json<ErrorResponse>)> {
    let request_context = state.authorize_request(&headers).await?;
    request_context.require_permission_for(
        Some(&kid),
        "token-encode",
        Some("token.encode.batch.denied"),
    )?;
    let actor = audit::actor_from_client(request_context.client());

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(crypto_failed_response(
            "token.encode.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("token-encode"),
            "token_encode_batch",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(crypto_failed_response(
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
            return Err(crypto_failed_response(
                "token.encode.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("token-encode"),
                "token_encode_batch",
                err.as_ref(),
            ));
        }
    };
    let Some(profile) = request_context
        .config()
        .tokenization_profiles
        .get(input.profile())
    else {
        let err = crate::error::invalid_input("tokenization profile not found");
        return Err(crypto_failed_response(
            "token.encode.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("token-encode"),
            "token_encode_batch",
            err.as_ref(),
        ));
    };
    let profile = super::subject::token_context(
        &state,
        profile,
        &kid,
        subject.as_deref(),
        ops::keys::ProfileUse::NewUse,
    )
    .await
    .map_err(|err| {
        crypto_failed_response(
            "token.encode.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("token-encode"),
            "token_encode_batch",
            err.as_ref(),
        )
    })?;
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::tokenization::prepare_encode_batch(keys_db_state, &kid, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(crypto_failed_response(
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
                return Err(crypto_failed_response(
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
            subject: record.subject,
            kid: record.kid,
            hashid: record.hashid,
            data: record.data,
        })
        .collect::<Vec<_>>();

    if let Err(err) = state.storage().save_tokens_batch(&rows).await {
        error!(error = %err, kid = %kid, "token encode batch storage insert failed");
        return Err(crypto_failed_response(
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

pub async fn delete_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::tokenization::TokenDeleteOutput>, (StatusCode, Json<ErrorResponse>)> {
    let request_context = state.authorize_request(&headers).await?;
    let actor = audit::actor_from_client(request_context.client());
    let failed = |kid: Option<&str>, err: &crate::error::DynError| {
        crypto_failed_response(
            "token.delete.failed",
            Some(&actor),
            kid,
            Some("token-delete"),
            "token_delete",
            err.as_ref(),
        )
    };
    let input = ops::tokenization::parse_delete_input(request)
        .and_then(ops::tokenization::validate_delete_input)
        .map_err(|err| failed(None, &err))?;
    let kid = input.kid().to_string();
    request_context.require_permission_for(
        Some(&kid),
        "token-delete",
        Some("token.delete.denied"),
    )?;
    state
        .ensure_keys_db_entry(&kid)
        .await
        .map_err(|err| failed(Some(&kid), &err))?;
    let profile = request_context
        .config()
        .tokenization_profiles
        .get(input.profile())
        .ok_or_else(|| {
            failed(
                Some(&kid),
                &crate::error::invalid_input("tokenization profile not found"),
            )
        })?;
    let subject = input.subject().map(str::to_owned);
    let profile = super::subject::token_context(
        &state,
        profile,
        &kid,
        subject.as_deref(),
        ops::keys::ProfileUse::TokenDelete,
    )
    .await
    .map_err(|err| failed(Some(&kid), &err))?;
    let prepared = state
        .with_keys_db_state(|keys_db_state| {
            ops::tokenization::prepare_delete(keys_db_state, profile, input)
        })
        .await
        .map_err(|err| failed(Some(&kid), &err))?;
    let (ref_id, hashid) =
        blocking::spawn_blocking_crypto(move || ops::tokenization::delete_hashid(prepared))
            .await
            .map_err(|err| failed(Some(&kid), &err))?;
    state
        .storage()
        .delete_token_for_subject(&kid, &hashid, subject.as_deref())
        .await
        .map_err(|err| failed(Some(&kid), &err))?;
    audit::operation_success(
        "token.delete.success",
        Some(&actor),
        Some(&kid),
        None,
        Some("token-delete"),
    );
    metrics::record_crypto_operation("token_delete", "success");
    Ok(Json(ops::tokenization::TokenDeleteOutput::committed(
        ref_id,
    )))
}

pub async fn decode_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::tokenization::TokenDecodeOutput>, (StatusCode, Json<ErrorResponse>)> {
    let request_context = state.authorize_request(&headers).await?;
    let input = ops::tokenization::parse_decode_input(request)
        .and_then(ops::tokenization::validate_decode_input)
        .map_err(|err| {
            crypto_failed_response(
                "token.decode.failed",
                None,
                None,
                Some("token-decode"),
                "token_decode",
                err.as_ref(),
            )
        })?;
    let kid = input.kid().to_string();
    request_context.require_permission_for(
        Some(&kid),
        "token-decode",
        Some("token.decode.denied"),
    )?;
    let actor = audit::actor_from_client(request_context.client());

    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(crypto_failed_response(
            "token.decode.failed",
            Some(&actor),
            Some(&kid),
            Some("token-decode"),
            "token_decode",
            err.as_ref(),
        ));
    }
    let Some(profile) = request_context
        .config()
        .tokenization_profiles
        .get(input.profile())
    else {
        let err = crate::error::invalid_input("tokenization profile not found");
        return Err(crypto_failed_response(
            "token.decode.failed",
            Some(&actor),
            Some(&kid),
            Some("token-decode"),
            "token_decode",
            err.as_ref(),
        ));
    };
    let one_time = profile.one_time();
    let subject = input.subject().map(str::to_owned);
    let profile = super::subject::token_context(
        &state,
        profile,
        &kid,
        subject.as_deref(),
        ops::keys::ProfileUse::Verify,
    )
    .await
    .map_err(|err| {
        crypto_failed_response(
            "token.decode.failed",
            Some(&actor),
            Some(&kid),
            Some("token-decode"),
            "token_decode",
            err.as_ref(),
        )
    })?;
    let hash_profile = profile.clone();
    let token = zeroize::Zeroizing::new(input.token().to_owned());
    let hashid = match blocking::spawn_blocking_crypto(move || hash_profile.hash(&token)).await {
        Ok(hashid) => hashid,
        Err(err) => {
            return Err(crypto_failed_response(
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
            return Err(crypto_failed_response(
                "token.decode.failed",
                Some(&actor),
                Some(&kid),
                Some("token-decode"),
                "token_decode",
                err.as_ref(),
            ));
        }
    };
    if row.subject.as_deref() != subject.as_deref() {
        let err = crate::error::internal("stored token subject does not match request");
        return Err(crypto_failed_response(
            "token.decode.failed",
            Some(&actor),
            Some(&kid),
            Some("token-decode"),
            "token_decode",
            err.as_ref(),
        ));
    }
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::tokenization::prepare_decode(keys_db_state, profile, input, row.data)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(crypto_failed_response(
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
            if one_time
                && let Err(err) = state
                    .storage()
                    .delete_token_for_subject(&kid, &hashid, subject.as_deref())
                    .await
            {
                return Err(crypto_failed_response(
                    "token.decode.failed",
                    Some(&actor),
                    Some(&kid),
                    Some("token-decode"),
                    "token_decode",
                    err.as_ref(),
                ));
            }
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
            Err(crypto_failed_response(
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
    let request_context = state.authorize_request(&headers).await?;
    let input = ops::tokenization::parse_decode_batch_input(request)
        .and_then(ops::tokenization::validate_decode_batch_input)
        .map_err(|err| {
            crypto_failed_response(
                "token.decode.batch.failed",
                None,
                None,
                Some("token-decode"),
                "token_decode_batch",
                err.as_ref(),
            )
        })?;
    let kid = input.kid().to_string();
    request_context.require_permission_for(
        Some(&kid),
        "token-decode",
        Some("token.decode.batch.denied"),
    )?;
    let actor = audit::actor_from_client(request_context.client());

    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(crypto_failed_response(
            "token.decode.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("token-decode"),
            "token_decode_batch",
            err.as_ref(),
        ));
    }
    let Some(profile) = request_context
        .config()
        .tokenization_profiles
        .get(input.profile())
    else {
        let err = crate::error::invalid_input("tokenization profile not found");
        return Err(crypto_failed_response(
            "token.decode.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("token-decode"),
            "token_decode_batch",
            err.as_ref(),
        ));
    };
    let one_time = profile.one_time();
    if let Err(err) = state
        .with_keys_db_state(|keys_db_state| {
            ops::tokenization::authorize_decode_batch(keys_db_state, &profile, &kid)
        })
        .await
    {
        return Err(crypto_failed_response(
            "token.decode.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("token-decode"),
            "token_decode_batch",
            err.as_ref(),
        ));
    }
    let subject = input.subject().map(str::to_owned);
    let profile = super::subject::token_context(
        &state,
        profile,
        &kid,
        subject.as_deref(),
        ops::keys::ProfileUse::Verify,
    )
    .await
    .map_err(|err| {
        crypto_failed_response(
            "token.decode.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("token-decode"),
            "token_decode_batch",
            err.as_ref(),
        )
    })?;
    let hash_profile = profile.clone();
    let tokens = input
        .tokens()
        .map(|token| zeroize::Zeroizing::new(token.to_owned()))
        .collect::<Vec<_>>();
    let hashids = blocking::spawn_blocking_crypto(move || {
        tokens
            .iter()
            .enumerate()
            .map(|(index, token)| {
                hash_profile.hash(token).map_err(|err| {
                    crate::error::with_prefix(&format!("batch item {index} failed"), err)
                })
            })
            .collect::<Result<Vec<_>, _>>()
    })
    .await
    .map_err(|err| {
        crypto_failed_response(
            "token.decode.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("token-decode"),
            "token_decode_batch",
            err.as_ref(),
        )
    })?;
    if one_time {
        let mut seen_hashids = HashSet::with_capacity(hashids.len());
        for (index, hashid) in hashids.iter().enumerate() {
            if !seen_hashids.insert(hashid) {
                let err = crate::error::with_prefix(
                    &format!("batch item {index} failed"),
                    crate::error::invalid_input("token batch contains duplicated token"),
                );
                return Err(crypto_failed_response(
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
    let found = match state
        .storage()
        .get_tokens_batch(
            &kid,
            &hashids,
            crate::core::config::TOKEN_DECODE_BATCH_MAX_ENVELOPE_BYTES,
        )
        .await
    {
        Ok(found) => found,
        Err(err) => {
            return Err(crypto_failed_response(
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
    for (index, data) in found.into_iter().enumerate() {
        let Some(data) = data else {
            let err = crate::error::with_prefix(
                &format!("batch item {index} failed"),
                crate::error::not_found("token not found"),
            );
            return Err(crypto_failed_response(
                "token.decode.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("token-decode"),
                "token_decode_batch",
                err.as_ref(),
            ));
        };
        if data.subject.as_deref() != subject.as_deref() {
            let err = crate::error::internal("stored token subject does not match request");
            return Err(crypto_failed_response(
                "token.decode.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("token-decode"),
                "token_decode_batch",
                err.as_ref(),
            ));
        }
        rows.push(data.data);
    }
    let hashid_indexes = one_time.then(|| {
        hashids
            .iter()
            .enumerate()
            .map(|(index, hashid)| (hashid.clone(), index))
            .collect::<HashMap<_, _>>()
    });
    let hashids_for_consume = one_time.then(|| hashids.clone());
    let prepared =
        match ops::tokenization::prepare_decode_batch(profile, kid.clone(), refs, hashids, rows) {
            Ok(prepared) => prepared,
            Err(err) => {
                return Err(crypto_failed_response(
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
            if let Some(hashids) = hashids_for_consume
                && let Err(err) = state
                    .storage()
                    .consume_tokens_batch_for_subject(&kid, &hashids, subject.as_deref())
                    .await
            {
                let err = map_token_batch_consume_error(err, hashid_indexes.as_ref());
                return Err(crypto_failed_response(
                    "token.decode.batch.failed",
                    Some(&actor),
                    Some(&kid),
                    Some("token-decode"),
                    "token_decode_batch",
                    err.as_ref(),
                ));
            }
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
            Err(crypto_failed_response(
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

fn map_token_batch_consume_error(
    err: TokenBatchConsumeError,
    hashid_indexes: Option<&HashMap<String, usize>>,
) -> crate::error::DynError {
    match err {
        TokenBatchConsumeError::MissingToken { hashid } => {
            match hashid_indexes.and_then(|indexes| indexes.get(&hashid)) {
                Some(index) => {
                    crate::error::not_found(format!("batch item {index} failed: token not found"))
                }
                None => crate::error::internal("token batch consume returned an unknown token"),
            }
        }
        TokenBatchConsumeError::Other(err) => err,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_missing_consumed_token_to_its_original_batch_item() {
        let indexes = HashMap::from([(String::from("hash-z"), 0), (String::from("hash-a"), 1)]);
        let err = map_token_batch_consume_error(
            TokenBatchConsumeError::MissingToken {
                hashid: String::from("hash-a"),
            },
            Some(&indexes),
        );

        assert!(crate::error::is_not_found(err.as_ref()));
        assert_eq!(err.to_string(), "batch item 1 failed: token not found");
    }

    #[test]
    fn does_not_expose_unknown_consumed_token_hashid() {
        let err = map_token_batch_consume_error(
            TokenBatchConsumeError::MissingToken {
                hashid: String::from("hash-secret"),
            },
            Some(&HashMap::new()),
        );

        assert_eq!(
            err.to_string(),
            "token batch consume returned an unknown token"
        );
        assert!(!err.to_string().contains("hash-secret"));
    }
}
