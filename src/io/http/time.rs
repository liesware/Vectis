use super::HttpState;
use super::error::ErrorResponse;
use crate::core::{audit, config, metrics, time_attestation};
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use std::sync::atomic::{AtomicI64, Ordering};
use tracing::error;

static ATTEST_SLOT: AtomicI64 = AtomicI64::new(i64::MIN);

// Global admission control: succeeds at most once per min_interval_us via CAS, so a burst
// of authorized callers cannot amplify outbound load against the external time servers.
fn admit(slot: &AtomicI64, now_us: i64, min_interval_us: i64) -> bool {
    let mut last = slot.load(Ordering::Acquire);
    loop {
        if now_us.saturating_sub(last) < min_interval_us {
            return false;
        }
        match slot.compare_exchange_weak(last, now_us, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(actual) => last = actual,
        }
    }
}

pub async fn attest_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<time_attestation::TimeAttestationOutput>, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state
        .require_permission_for(&client, None, "time-attest", Some("time.attest.denied"))
        .await?;
    let actor = audit::actor_from_client(&client);
    if validate_empty_request_body(&body).is_err() {
        let err = crate::error::invalid_input("time attest request must not include a body");
        audit::operation_failed(
            "time.attest.failed",
            Some(&actor),
            None,
            None,
            Some("time-attest"),
            &err.to_string(),
        );
        metrics::record_crypto_operation("time_attest", "failed");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(err.to_string())),
        ));
    }
    let effective = state.time_attestation_config().await;
    let local_start = match time_attestation::local_unix_us() {
        Ok(value) => value,
        Err(err) => return internal_failure(&actor, err.as_ref()),
    };
    if !admit(
        &ATTEST_SLOT,
        local_start as i64,
        config::INTERNAL_TIME_ATTEST_MIN_INTERVAL_US,
    ) {
        return throttled(&actor);
    }

    let query = async {
        tokio::try_join!(
            time_attestation::query_nts(&effective),
            time_attestation::query_roughtime(&effective),
        )
    };
    let (nts, roughtime) = match tokio::time::timeout(
        std::time::Duration::from_secs(config::INTERNAL_TIME_ATTEST_TIMEOUT_SEC),
        query,
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => return unavailable(&actor, err.as_ref()),
        Err(_) => {
            return unavailable(
                &actor,
                crate::error::internal("time attestation timed out").as_ref(),
            );
        }
    };
    let local_end = match time_attestation::local_unix_us() {
        Ok(value) => value,
        Err(err) => return internal_failure(&actor, err.as_ref()),
    };
    let output = time_attestation::evaluate_time_attestation(
        local_start,
        local_end,
        &effective,
        nts,
        roughtime,
    );
    let result = if time_attestation::output_is_acceptable(&output) {
        "acceptable"
    } else {
        "unacceptable"
    };
    let event = if result == "acceptable" {
        "time.attest.success"
    } else {
        "time.attest.unacceptable"
    };
    audit::operation_success(event, Some(&actor), None, None, Some("time-attest"));
    metrics::record_crypto_operation("time_attest", result);
    Ok(Json(output))
}

fn validate_empty_request_body(body: &[u8]) -> Result<(), crate::error::DynError> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(crate::error::invalid_input(
            "time attest request must not include a body",
        ))
    }
}

fn unavailable(
    actor: &audit::Actor<'_>,
    err: &(dyn std::error::Error + Send + Sync + 'static),
) -> Result<Json<time_attestation::TimeAttestationOutput>, (StatusCode, Json<ErrorResponse>)> {
    audit::operation_failed(
        "time.attest.failed",
        Some(actor),
        None,
        None,
        Some("time-attest"),
        &err.to_string(),
    );
    metrics::record_crypto_operation("time_attest", "failed");
    error!(error = %err, "time attestation source failed");
    Err((
        StatusCode::BAD_GATEWAY,
        Json(ErrorResponse::new(String::from(
            "time attestation source unavailable",
        ))),
    ))
}

fn throttled(
    actor: &audit::Actor<'_>,
) -> Result<Json<time_attestation::TimeAttestationOutput>, (StatusCode, Json<ErrorResponse>)> {
    audit::operation_failed(
        "time.attest.throttled",
        Some(actor),
        None,
        None,
        Some("time-attest"),
        "time attestation rate limit exceeded (max 1/s)",
    );
    metrics::record_crypto_operation("time_attest", "throttled");
    Err((
        StatusCode::TOO_MANY_REQUESTS,
        Json(ErrorResponse::new(String::from(
            "time attestation rate limit exceeded",
        ))),
    ))
}

fn internal_failure(
    actor: &audit::Actor<'_>,
    err: &(dyn std::error::Error + Send + Sync + 'static),
) -> Result<Json<time_attestation::TimeAttestationOutput>, (StatusCode, Json<ErrorResponse>)> {
    audit::operation_failed(
        "time.attest.failed",
        Some(actor),
        None,
        None,
        Some("time-attest"),
        &err.to_string(),
    );
    metrics::record_crypto_operation("time_attest", "failed");
    error!(error = %err, "time attestation internal failure");
    Err((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse::new(String::from("internal server error"))),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_admits_at_most_one_per_interval() {
        let slot = AtomicI64::new(i64::MIN);
        let us = 1_000_000;
        assert!(admit(&slot, 10_000_000, us));
        assert!(!admit(&slot, 10_500_000, us));
        assert!(admit(&slot, 11_000_000, us));
        assert!(!admit(&slot, 11_999_999, us));
    }

    #[test]
    fn rejects_non_empty_attestation_requests() {
        assert!(validate_empty_request_body(b"").is_ok());
        assert_eq!(
            validate_empty_request_body(br#"{}"#)
                .unwrap_err()
                .to_string(),
            "time attest request must not include a body"
        );
    }
}
