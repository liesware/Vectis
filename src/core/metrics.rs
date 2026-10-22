use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

const HTTP_REQUESTS_TOTAL: &str = "http_requests_total";
const HTTP_REQUEST_DURATION_SECONDS: &str = "http_request_duration_seconds";
const AUTH_TOTAL: &str = "auth_total";
const VECTIS_PERMISSION_TOTAL: &str = "vectis_permission_total";
const VECTIS_CONFIG_RELOAD_TOTAL: &str = "vectis_config_reload_total";
const VECTIS_CONFIG_LAST_RELOAD_TIMESTAMP_SECONDS: &str =
    "vectis_config_last_reload_timestamp_seconds";
const VECTIS_KEYS_RELOAD_TOTAL: &str = "vectis_keys_reload_total";
const VECTIS_KEY_LOAD_FAILURES_TOTAL: &str = "vectis_key_load_failures_total";
const VECTIS_KEYS_LOAD_SKIPPED: &str = "vectis_keys_load_skipped";
const VECTIS_MESSAGE_TOTAL: &str = "vectis_message_total";
const VECTIS_CRYPTO_OPERATION_TOTAL: &str = "vectis_crypto_operation_total";
const CRYPTO_QUEUE_PENDING: &str = "vectis_crypto_queue_pending";
const CRYPTO_QUEUE_WAIT_SECONDS: &str = "vectis_crypto_queue_wait_seconds";
const CRYPTO_REJECTIONS_TOTAL: &str = "vectis_crypto_rejections_total";
const CRYPTO_WAIT_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

const DURATION_BUCKETS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];

fn builder() -> Result<PrometheusBuilder, crate::error::DynError> {
    Ok(PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full(HTTP_REQUEST_DURATION_SECONDS.to_string()),
            DURATION_BUCKETS,
        )?
        .set_buckets_for_metric(
            Matcher::Full(CRYPTO_QUEUE_WAIT_SECONDS.to_string()),
            CRYPTO_WAIT_BUCKETS,
        )?)
}

pub fn init() -> Result<PrometheusHandle, crate::error::DynError> {
    Ok(builder()?.install_recorder()?)
}

#[cfg(test)]
pub(crate) fn test_recorder() -> metrics_exporter_prometheus::PrometheusRecorder {
    builder().unwrap().build_recorder()
}

pub(crate) enum CryptoRejection {
    Full,
    Timeout,
}

pub(crate) fn record_crypto_rejection(reason: CryptoRejection) {
    let reason = match reason {
        CryptoRejection::Full => "full",
        CryptoRejection::Timeout => "timeout",
    };
    counter!(CRYPTO_REJECTIONS_TOTAL, "reason" => reason).increment(1);
}

/// Captures its metric handles so cancellation cleans up even on another thread.
pub(crate) struct CryptoQueueWait {
    pending: metrics::Gauge,
    wait: metrics::Histogram,
    started: tokio::time::Instant,
}

impl CryptoQueueWait {
    pub(crate) fn new(started: tokio::time::Instant) -> Self {
        let pending = gauge!(CRYPTO_QUEUE_PENDING);
        pending.increment(1.0);
        Self {
            pending,
            wait: histogram!(CRYPTO_QUEUE_WAIT_SECONDS),
            started,
        }
    }

    pub(crate) fn completed(&self) {
        self.wait.record(self.started.elapsed().as_secs_f64());
    }
}

impl Drop for CryptoQueueWait {
    fn drop(&mut self) {
        self.pending.decrement(1.0);
    }
}

pub fn record_http_request(method: &str, endpoint: &str, status: u16, secs: f64) {
    let method = normalized_http_method(method).to_string();
    let endpoint = endpoint.to_string();
    let status = status.to_string();

    counter!(
        HTTP_REQUESTS_TOTAL,
        "method" => method.clone(),
        "endpoint" => endpoint.clone(),
        "status" => status,
    )
    .increment(1);

    histogram!(
        HTTP_REQUEST_DURATION_SECONDS,
        "method" => method,
        "endpoint" => endpoint,
    )
    .record(secs);
}

fn normalized_http_method(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "PATCH" => "PATCH",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        "CONNECT" => "CONNECT",
        "TRACE" => "TRACE",
        _ => "other",
    }
}

pub fn record_auth(outcome: &str) {
    counter!(AUTH_TOTAL, "outcome" => outcome.to_string()).increment(1);
}

pub fn set_unsealed_state(unsealed: bool) {
    gauge!("vectis_unsealed").set(if unsealed { 1.0 } else { 0.0 });
}

pub struct LoadedGaugeCounts {
    pub keys: usize,
    pub routes: usize,
    pub remote_routes: usize,
    pub permission_clients: usize,
    pub fpe_profiles: usize,
    pub tokenization_profiles: usize,
    pub deterministic_tokenization_profiles: usize,
    pub mac_profiles: usize,
    pub masking_profiles: usize,
    pub commitment_profiles: usize,
    pub sharing_profiles: usize,
}

pub fn set_loaded_gauges(counts: LoadedGaugeCounts) {
    gauge!("vectis_keys_loaded").set(counts.keys as f64);
    gauge!("vectis_routes_loaded").set(counts.routes as f64);
    gauge!("vectis_remote_routes_loaded").set(counts.remote_routes as f64);
    gauge!("vectis_permission_clients").set(counts.permission_clients as f64);
    gauge!("vectis_fpe_profiles_loaded").set(counts.fpe_profiles as f64);
    gauge!("vectis_tokenization_profiles_loaded").set(counts.tokenization_profiles as f64);
    gauge!("vectis_deterministic_tokenization_profiles_loaded")
        .set(counts.deterministic_tokenization_profiles as f64);
    gauge!("vectis_mac_profiles_loaded").set(counts.mac_profiles as f64);
    gauge!("vectis_masking_profiles_loaded").set(counts.masking_profiles as f64);
    gauge!("vectis_commitment_profiles_loaded").set(counts.commitment_profiles as f64);
    gauge!("vectis_sharing_profiles_loaded").set(counts.sharing_profiles as f64);
}

pub fn record_permission(result: &str) {
    counter!(VECTIS_PERMISSION_TOTAL, "result" => result.to_string()).increment(1);
}

pub fn record_config_reload(result: &str) {
    counter!(VECTIS_CONFIG_RELOAD_TOTAL, "result" => result.to_string()).increment(1);
}

pub fn set_config_last_reload_timestamp(result: &str, timestamp_seconds: f64) {
    gauge!(
        VECTIS_CONFIG_LAST_RELOAD_TIMESTAMP_SECONDS,
        "result" => result.to_string()
    )
    .set(timestamp_seconds);
}

pub fn record_keys_reload(result: &str) {
    counter!(VECTIS_KEYS_RELOAD_TOTAL, "result" => result.to_string()).increment(1);
}

pub fn record_key_load_failures(reason: &str, count: usize) {
    if count == 0 {
        return;
    }

    counter!(VECTIS_KEY_LOAD_FAILURES_TOTAL, "reason" => reason.to_string())
        .increment(count as u64);
}

pub fn set_keys_load_skipped(count: usize) {
    gauge!(VECTIS_KEYS_LOAD_SKIPPED).set(count as f64);
}

pub fn record_message(operation: &str, result: &str) {
    counter!(
        VECTIS_MESSAGE_TOTAL,
        "operation" => operation.to_string(),
        "result" => result.to_string()
    )
    .increment(1);
}

pub fn record_crypto_operation(operation: &str, result: &str) {
    counter!(
        VECTIS_CRYPTO_OPERATION_TOTAL,
        "operation" => operation.to_string(),
        "result" => result.to_string()
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_http_method_accepts_standard_methods() {
        for method in [
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE",
        ] {
            assert_eq!(normalized_http_method(method), method);
        }
    }

    #[test]
    fn normalized_http_method_maps_extensions_to_other() {
        for method in ["FOO", "FOO123", "get", "", "BREW"] {
            assert_eq!(normalized_http_method(method), "other");
        }
    }
}
