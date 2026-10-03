use super::{
    HttpState,
    error::{ErrorResponse, crypto_failed_response},
    extract::JsonBody,
};
use crate::core::{
    audit, blocking, metrics, subjects,
    tokenization::{self, TokenContext, TokenizationProfile},
};
use crate::{error::DynError, ops};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use std::sync::Arc;

pub async fn token_context(
    state: &HttpState,
    profile: Arc<TokenizationProfile>,
    kid: &str,
    subject: Option<&str>,
    use_kind: ops::keys::ProfileUse,
) -> Result<TokenContext, DynError> {
    tokenization::validate_subject_mode(&profile, subject)?;
    state
        .with_keys_db_state(|keys| {
            ops::keys::prepare_profile_use(keys, kid, profile.kid(), "tokenization", use_kind)
        })
        .await?;
    let Some(subject) = subject else {
        return Ok(profile.into());
    };
    let row = state.storage().get_subject(kid, subject).await?;
    blocking::spawn_blocking_crypto(move || {
        let keys = subjects::open_seed(&profile, &row.subject, &row.seed)?;
        Ok(TokenContext::with_subject(profile, keys).with_subject_generation(row.seed))
    })
    .await
}

pub async fn create_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(value): JsonBody,
) -> Result<(StatusCode, Json<ops::subjects::CreateSubjectOutput>), (StatusCode, Json<ErrorResponse>)>
{
    let request = state.authorize_request(&headers).await?;
    let actor = audit::actor_from_client(request.client());
    let failed = |err: DynError| {
        crypto_failed_response(
            "subject.create.failed",
            Some(&actor),
            Some(&kid),
            Some("subject-create"),
            "subject_create",
            err.as_ref(),
        )
    };
    ops::keys::validate_key_id(&kid).map_err(&failed)?;
    request.require_permission_for(Some(&kid), "subject-create", Some("subject.create.denied"))?;
    let input = ops::subjects::parse_create_input(value)
        .and_then(ops::subjects::validate_create_input)
        .map_err(&failed)?;
    let profile = request
        .config()
        .tokenization_profiles
        .get(input.profile())
        .ok_or_else(|| {
            failed(crate::error::invalid_input(
                "tokenization profile not found",
            ))
        })?;
    state.ensure_keys_db_entry(&kid).await.map_err(&failed)?;
    let prepared = state
        .with_keys_db_state(|keys| ops::subjects::prepare_create(keys, &kid, profile, input))
        .await
        .map_err(&failed)?;
    let subject = ops::subjects::subject_identifier(&prepared).map_err(&failed)?;
    if state
        .storage()
        .subject_exists(&kid, &subject)
        .await
        .map_err(&failed)?
    {
        audit::operation_success(
            "subject.create.success",
            Some(&actor),
            Some(&kid),
            None,
            Some("subject-create"),
        );
        metrics::record_crypto_operation("subject_create", "success");
        return Ok((
            StatusCode::OK,
            Json(ops::subjects::existing_output(&prepared, subject)),
        ));
    }
    let (row, output) = blocking::spawn_blocking_crypto(move || ops::subjects::create(prepared))
        .await
        .map_err(&failed)?;
    let created = state.storage().save_subject(&row).await.map_err(&failed)?;
    audit::operation_success(
        "subject.create.success",
        Some(&actor),
        Some(&kid),
        None,
        Some("subject-create"),
    );
    metrics::record_crypto_operation("subject_create", "success");
    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(output),
    ))
}

pub async fn delete_endpoint(
    State(state): State<HttpState>,
    Path((kid, subject)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let request = state.authorize_request(&headers).await?;
    let actor = audit::actor_from_client(request.client());
    let failed = |err: DynError| {
        crypto_failed_response(
            "subject.delete.failed",
            Some(&actor),
            Some(&kid),
            Some("subject-delete"),
            "subject_delete",
            err.as_ref(),
        )
    };
    ops::keys::validate_key_id(&kid).map_err(&failed)?;
    subjects::validate_subject(&subject).map_err(&failed)?;
    request.require_permission_for(Some(&kid), "subject-delete", Some("subject.delete.denied"))?;
    // Administrative deletion intentionally does not load a key or open its seed.
    state
        .storage()
        .delete_subject(&kid, &subject)
        .await
        .map_err(&failed)?;
    audit::operation_success(
        "subject.delete.success",
        Some(&actor),
        Some(&kid),
        None,
        Some("subject-delete"),
    );
    metrics::record_crypto_operation("subject_delete", "success");
    Ok(StatusCode::NO_CONTENT)
}
