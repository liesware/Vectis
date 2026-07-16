use super::HttpState;
use super::error::{ErrorResponse, error_response};
use super::extract::JsonBody;
use crate::core::{audit, blocking, metrics};
use crate::ops;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use tracing::{error, info};

pub async fn encrypt_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::fpe::FpeEncryptOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "fpe-encrypt",
            Some("fpe.encrypt.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(fpe_failed_response(
            "fpe.encrypt.failed",
            Some(&actor),
            Some(&kid),
            Some("fpe-encrypt"),
            "fpe_encrypt",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(fpe_failed_response(
            "fpe.encrypt.failed",
            Some(&actor),
            Some(&kid),
            Some("fpe-encrypt"),
            "fpe_encrypt",
            err.as_ref(),
        ));
    }
    let input =
        match ops::fpe::parse_encrypt_input(request).and_then(ops::fpe::validate_encrypt_input) {
            Ok(input) => input,
            Err(err) => {
                return Err(fpe_failed_response(
                    "fpe.encrypt.failed",
                    Some(&actor),
                    Some(&kid),
                    Some("fpe-encrypt"),
                    "fpe_encrypt",
                    err.as_ref(),
                ));
            }
        };
    let Some(profile) = state.fpe_profile(input.profile()).await else {
        let err = crate::error::invalid_input("fpe profile not found");
        return Err(fpe_failed_response(
            "fpe.encrypt.failed",
            Some(&actor),
            Some(&kid),
            Some("fpe-encrypt"),
            "fpe_encrypt",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::fpe::prepare_encrypt(keys_db_state, &kid, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(fpe_failed_response(
                "fpe.encrypt.failed",
                Some(&actor),
                Some(&kid),
                Some("fpe-encrypt"),
                "fpe_encrypt",
                err.as_ref(),
            ));
        }
    };

    match blocking::spawn_blocking_crypto(move || ops::fpe::encrypt(prepared)).await {
        Ok(output) => {
            audit::operation_success(
                "fpe.encrypt.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("fpe-encrypt"),
            );
            metrics::record_crypto_operation("fpe_encrypt", "success");
            info!(kid = %kid, "fpe encrypt response ready");
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "fpe encrypt endpoint failed");
            Err(fpe_failed_response(
                "fpe.encrypt.failed",
                Some(&actor),
                Some(&kid),
                Some("fpe-encrypt"),
                "fpe_encrypt",
                err.as_ref(),
            ))
        }
    }
}

pub async fn encrypt_batch_endpoint(
    State(state): State<HttpState>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::fpe::FpeEncryptBatchOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "fpe-encrypt",
            Some("fpe.encrypt.batch.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = ops::keys::validate_key_id(&kid) {
        return Err(fpe_failed_response(
            "fpe.encrypt.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("fpe-encrypt"),
            "fpe_encrypt_batch",
            err.as_ref(),
        ));
    }
    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(fpe_failed_response(
            "fpe.encrypt.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("fpe-encrypt"),
            "fpe_encrypt_batch",
            err.as_ref(),
        ));
    }
    let input = match ops::fpe::parse_encrypt_batch_input(request)
        .and_then(ops::fpe::validate_encrypt_batch_input)
    {
        Ok(input) => input,
        Err(err) => {
            return Err(fpe_failed_response(
                "fpe.encrypt.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("fpe-encrypt"),
                "fpe_encrypt_batch",
                err.as_ref(),
            ));
        }
    };
    let Some(profile) = state.fpe_profile(input.profile()).await else {
        let err = crate::error::invalid_input("fpe profile not found");
        return Err(fpe_failed_response(
            "fpe.encrypt.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("fpe-encrypt"),
            "fpe_encrypt_batch",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::fpe::prepare_encrypt_batch(keys_db_state, &kid, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(fpe_failed_response(
                "fpe.encrypt.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("fpe-encrypt"),
                "fpe_encrypt_batch",
                err.as_ref(),
            ));
        }
    };

    match blocking::spawn_blocking_crypto(move || ops::fpe::encrypt_batch(prepared)).await {
        Ok(output) => {
            audit::operation_success(
                "fpe.encrypt.batch.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("fpe-encrypt"),
            );
            metrics::record_crypto_operation("fpe_encrypt_batch", "success");
            info!(
                kid = %kid,
                items_count = output.items_len(),
                "fpe encrypt batch response ready"
            );
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "fpe encrypt batch endpoint failed");
            Err(fpe_failed_response(
                "fpe.encrypt.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("fpe-encrypt"),
                "fpe_encrypt_batch",
                err.as_ref(),
            ))
        }
    }
}

pub async fn decrypt_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::fpe::FpeDecryptOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    let input = ops::fpe::parse_decrypt_input(request)
        .and_then(ops::fpe::validate_decrypt_input)
        .map_err(|err| {
            fpe_failed_response(
                "fpe.decrypt.failed",
                None,
                None,
                Some("fpe-decrypt"),
                "fpe_decrypt",
                err.as_ref(),
            )
        })?;
    let kid = input.kid().to_string();
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "fpe-decrypt",
            Some("fpe.decrypt.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(fpe_failed_response(
            "fpe.decrypt.failed",
            Some(&actor),
            Some(&kid),
            Some("fpe-decrypt"),
            "fpe_decrypt",
            err.as_ref(),
        ));
    }
    let Some(profile) = state.fpe_profile(input.profile()).await else {
        let err = crate::error::invalid_input("fpe profile not found");
        return Err(fpe_failed_response(
            "fpe.decrypt.failed",
            Some(&actor),
            Some(&kid),
            Some("fpe-decrypt"),
            "fpe_decrypt",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::fpe::prepare_decrypt(keys_db_state, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(fpe_failed_response(
                "fpe.decrypt.failed",
                Some(&actor),
                Some(&kid),
                Some("fpe-decrypt"),
                "fpe_decrypt",
                err.as_ref(),
            ));
        }
    };

    match blocking::spawn_blocking_crypto(move || ops::fpe::decrypt(prepared)).await {
        Ok(output) => {
            audit::operation_success(
                "fpe.decrypt.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("fpe-decrypt"),
            );
            metrics::record_crypto_operation("fpe_decrypt", "success");
            info!(kid = %kid, "fpe decrypt response ready");
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "fpe decrypt endpoint failed");
            Err(fpe_failed_response(
                "fpe.decrypt.failed",
                Some(&actor),
                Some(&kid),
                Some("fpe-decrypt"),
                "fpe_decrypt",
                err.as_ref(),
            ))
        }
    }
}

pub async fn decrypt_batch_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    JsonBody(request): JsonBody,
) -> Result<Json<ops::fpe::FpeDecryptBatchOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    let input = ops::fpe::parse_decrypt_batch_input(request)
        .and_then(ops::fpe::validate_decrypt_batch_input)
        .map_err(|err| {
            fpe_failed_response(
                "fpe.decrypt.batch.failed",
                None,
                None,
                Some("fpe-decrypt"),
                "fpe_decrypt_batch",
                err.as_ref(),
            )
        })?;
    let kid = input.kid().to_string();
    state
        .require_permission_for(
            &client,
            Some(&kid),
            "fpe-decrypt",
            Some("fpe.decrypt.batch.denied"),
        )
        .await?;
    let actor = audit::actor_from_client(&client);

    if let Err(err) = state.ensure_keys_db_entry(&kid).await {
        return Err(fpe_failed_response(
            "fpe.decrypt.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("fpe-decrypt"),
            "fpe_decrypt_batch",
            err.as_ref(),
        ));
    }
    let Some(profile) = state.fpe_profile(input.profile()).await else {
        let err = crate::error::invalid_input("fpe profile not found");
        return Err(fpe_failed_response(
            "fpe.decrypt.batch.failed",
            Some(&actor),
            Some(&kid),
            Some("fpe-decrypt"),
            "fpe_decrypt_batch",
            err.as_ref(),
        ));
    };
    let prepared = match state
        .with_keys_db_state(|keys_db_state| {
            ops::fpe::prepare_decrypt_batch(keys_db_state, profile, input)
        })
        .await
    {
        Ok(prepared) => prepared,
        Err(err) => {
            return Err(fpe_failed_response(
                "fpe.decrypt.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("fpe-decrypt"),
                "fpe_decrypt_batch",
                err.as_ref(),
            ));
        }
    };

    match blocking::spawn_blocking_crypto(move || ops::fpe::decrypt_batch(prepared)).await {
        Ok(output) => {
            audit::operation_success(
                "fpe.decrypt.batch.success",
                Some(&actor),
                Some(&kid),
                None,
                Some("fpe-decrypt"),
            );
            metrics::record_crypto_operation("fpe_decrypt_batch", "success");
            info!(
                kid = %kid,
                items_count = output.items_len(),
                "fpe decrypt batch response ready"
            );
            Ok(Json(output))
        }
        Err(err) => {
            error!(error = %err, kid = %kid, "fpe decrypt batch endpoint failed");
            Err(fpe_failed_response(
                "fpe.decrypt.batch.failed",
                Some(&actor),
                Some(&kid),
                Some("fpe-decrypt"),
                "fpe_decrypt_batch",
                err.as_ref(),
            ))
        }
    }
}

fn fpe_failed_response(
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
