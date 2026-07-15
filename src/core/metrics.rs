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
const VECTIS_MESSAGE_TOTAL: &str = "vectis_message_total";
const VECTIS_CRYPTO_OPERATION_TOTAL: &str = "vectis_crypto_operation_total";

const DURATION_BUCKETS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];

pub fn init() -> Result<PrometheusHandle, crate::error::DynError> {
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full(HTTP_REQUEST_DURATION_SECONDS.to_string()),
            DURATION_BUCKETS,
        )?
        .install_recorder()?;

    Ok(handle)
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

pub fn set_loaded_gauges(
    keys: usize,
    routes: usize,
    remote_routes: usize,
    permission_clients: usize,
    fpe_profiles: usize,
) {
    gauge!("vectis_keys_loaded").set(keys as f64);
    gauge!("vectis_routes_loaded").set(routes as f64);
    gauge!("vectis_remote_routes_loaded").set(remote_routes as f64);
    gauge!("vectis_permission_clients").set(permission_clients as f64);
    gauge!("vectis_fpe_profiles_loaded").set(fpe_profiles as f64);
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
