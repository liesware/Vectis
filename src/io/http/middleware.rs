use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use tracing::{Instrument, info_span};

use crate::core::crypto;

pub async fn request_context(request: Request, next: Next) -> Response {
    let request_id = crypto::random_bytes(16)
        .map(hex::encode)
        .unwrap_or_default();
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    let span = info_span!(
        "request",
        request_id = %request_id,
        method = %method,
        path = %path,
    );

    next.run(request).instrument(span).await
}
