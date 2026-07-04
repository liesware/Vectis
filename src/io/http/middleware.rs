use axum::extract::{MatchedPath, Request};
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use tracing::{Instrument, info_span};

use crate::core::{crypto, metrics};

pub async fn request_context(request: Request, next: Next) -> Response {
    let request_id = crypto::random_bytes(16)
        .map(hex::encode)
        .unwrap_or_default();
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
