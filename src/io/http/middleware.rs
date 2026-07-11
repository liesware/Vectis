use axum::extract::{MatchedPath, Request};
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{Instrument, info_span};

use crate::core::{crypto, metrics};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);
static REQUEST_NONCE: OnceLock<[u8; 8]> = OnceLock::new();

pub async fn request_context(request: Request, next: Next) -> Response {
    let request_id = next_request_id();
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let endpoint = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| String::from("unknown"));

    let span = info_span!(
        "request",
        request_id = %request_id,
        method = %method,
        path = %path,
    );

    let start = std::time::Instant::now();
    let mut response = next.run(request).instrument(span).await;
    if !request_id.is_empty()
        && let Ok(value) = HeaderValue::from_str(&request_id)
    {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-request-id"), value);
    }

    metrics::record_http_request(
        method.as_str(),
        &endpoint,
        response.status().as_u16(),
        start.elapsed().as_secs_f64(),
    );

    response
}

fn next_request_id() -> String {
    let nonce = REQUEST_NONCE.get_or_init(process_request_nonce);
    let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);

    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(nonce);
    bytes[8..].copy_from_slice(&counter.to_be_bytes());

    hex::encode(bytes)
}

fn process_request_nonce() -> [u8; 8] {
    if let Ok(bytes) = crypto::random_bytes(8)
        && let Ok(nonce) = <[u8; 8]>::try_from(bytes.as_slice())
    {
        return nonce;
    }

    fallback_request_nonce()
}

fn fallback_request_nonce() -> [u8; 8] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or_default();
    let pid = u64::from(std::process::id());
    let local = 0u8;
    let addr = (&local as *const u8 as usize) as u64;

    (now.rotate_left(17) ^ pid.rotate_left(32) ^ addr).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_is_32_hex_chars() {
        let request_id = next_request_id();

        assert_eq!(request_id.len(), 32);
        assert!(request_id.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn request_ids_are_distinct() {
        let first = next_request_id();
        let second = next_request_id();

        assert_ne!(first, second);
    }

    #[test]
    fn request_id_decodes_to_16_bytes() {
        let request_id = next_request_id();
        let bytes = hex::decode(request_id).expect("request id must be hex");

        assert_eq!(bytes.len(), 16);
    }
}
