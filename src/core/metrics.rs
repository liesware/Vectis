use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

const HTTP_REQUESTS_TOTAL: &str = "http_requests_total";
const HTTP_REQUEST_DURATION_SECONDS: &str = "http_request_duration_seconds";
const AUTH_TOTAL: &str = "auth_total";

const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

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
    let method = method.to_string();
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

pub fn record_auth(outcome: &str) {
    counter!(AUTH_TOTAL, "outcome" => outcome.to_string()).increment(1);
}

pub fn set_loaded_gauges(keys: usize, routes: usize, remote_routes: usize, permission_clients: usize) {
    gauge!("vectis_keys_loaded").set(keys as f64);
    gauge!("vectis_routes_loaded").set(routes as f64);
    gauge!("vectis_remote_routes_loaded").set(remote_routes as f64);
    gauge!("vectis_permission_clients").set(permission_clients as f64);
}
