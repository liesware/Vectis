use super::HttpState;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

pub async fn metrics_endpoint(State(state): State<HttpState>) -> Response {
    match state.metrics_handle() {
        Some(handle) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            handle.render(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
