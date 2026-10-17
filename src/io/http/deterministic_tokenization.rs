use super::{HttpError, HttpState, error::crypto_failed_response, extract::JsonBody};
use crate::{
    core::{audit, blocking, deterministic_tokenization as core, metrics},
    error::DynError,
    ops::deterministic_tokenization as ops,
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};

pub async fn encode_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(value): JsonBody,
) -> Result<Json<ops::Output>, HttpError> {
    run(state, headers, value, Some((kid, None)), false).await
}
pub async fn encode_subject_endpoint(
    State(state): State<HttpState>,
    Path((kid, subject)): Path<(String, String)>,
    headers: HeaderMap,
    JsonBody(value): JsonBody,
) -> Result<Json<ops::Output>, HttpError> {
    run(state, headers, value, Some((kid, Some(subject))), false).await
}
pub async fn encode_batch_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(value): JsonBody,
) -> Result<Json<ops::Output>, HttpError> {
    run(state, headers, value, Some((kid, None)), true).await
}
pub async fn encode_batch_subject_endpoint(
    State(state): State<HttpState>,
    Path((kid, subject)): Path<(String, String)>,
    headers: HeaderMap,
    JsonBody(value): JsonBody,
) -> Result<Json<ops::Output>, HttpError> {
    run(state, headers, value, Some((kid, Some(subject))), true).await
}
pub async fn decode_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    JsonBody(value): JsonBody,
) -> Result<Json<ops::Output>, HttpError> {
    run(state, headers, value, None, false).await
}
pub async fn decode_batch_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    JsonBody(value): JsonBody,
) -> Result<Json<ops::Output>, HttpError> {
    run(state, headers, value, None, true).await
}

async fn run(
    state: HttpState,
    headers: HeaderMap,
    value: serde_json::Value,
    path: Option<(String, Option<String>)>,
    batch: bool,
) -> Result<Json<ops::Output>, HttpError> {
    let auth = state.authorize_request(&headers).await?;
    let actor = audit::actor_from_client(auth.client());
    let decode = path.is_none();
    let (action, metric, success, failed, denied) = match (decode, batch) {
        (false, false) => (
            "token-deterministic-encode",
            "token_deterministic_encode",
            "token.deterministic.encode.success",
            "token.deterministic.encode.failed",
            "token.deterministic.encode.denied",
        ),
        (false, true) => (
            "token-deterministic-encode",
            "token_deterministic_encode_batch",
            "token.deterministic.encode.batch.success",
            "token.deterministic.encode.batch.failed",
            "token.deterministic.encode.batch.denied",
        ),
        (true, false) => (
            "token-deterministic-decode",
            "token_deterministic_decode",
            "token.deterministic.decode.success",
            "token.deterministic.decode.failed",
            "token.deterministic.decode.denied",
        ),
        (true, true) => (
            "token-deterministic-decode",
            "token_deterministic_decode_batch",
            "token.deterministic.decode.batch.success",
            "token.deterministic.decode.batch.failed",
            "token.deterministic.decode.batch.denied",
        ),
    };
    let input = ops::parse_request(value, path, batch).map_err(|e| {
        crypto_failed_response(failed, Some(&actor), None, Some(action), metric, e.as_ref())
    })?;
    let kid = input.kid.clone();
    let fail = |e: DynError| {
        crypto_failed_response(
            failed,
            Some(&actor),
            Some(&kid),
            Some(action),
            metric,
            e.as_ref(),
        )
    };
    auth.require_permission_for(Some(&kid), action, Some(denied))?;
    let profile = auth
        .config()
        .deterministic_tokenization_profiles
        .get(&input.profile)
        .ok_or_else(|| {
            fail(crate::error::invalid_input(
                "deterministic token profile not found",
            ))
        })?;
    state.ensure_keys_db_entry(&kid).await.map_err(&fail)?;
    state
        .with_keys_db_state(|keys| {
            crate::ops::keys::prepare_profile_use(
                keys,
                &kid,
                profile.kid(),
                "deterministic token",
                if decode {
                    crate::ops::keys::ProfileUse::Verify
                } else {
                    crate::ops::keys::ProfileUse::NewUse
                },
            )
        })
        .await
        .map_err(&fail)?;
    core::validate_subject_mode(&profile, input.subject.as_deref()).map_err(&fail)?;
    let origin = if let Some(subject) = &input.subject {
        Some(
            super::subject::subject_origin(&state, auth.config(), &kid, subject)
                .await
                .map_err(&fail)?,
        )
    } else {
        None
    };
    let context = blocking::spawn_blocking_crypto(move || match origin {
        Some((row, origin)) => core::DeterministicTokenContext::from_subject_envelope(
            profile,
            &origin,
            &row.subject,
            &row.seed,
        ),
        None => core::DeterministicTokenContext::new(profile),
    })
    .await
    .map_err(&fail)?;
    let prepared = state
        .with_keys_db_state(|keys| ops::prepare(keys, input, context))
        .await
        .map_err(&fail)?;
    let output = blocking::spawn_blocking_crypto(move || ops::execute(prepared))
        .await
        .map_err(&fail)?;
    audit::operation_success(success, Some(&actor), Some(&kid), None, Some(action));
    metrics::record_crypto_operation(metric, "success");
    Ok(Json(output))
}
