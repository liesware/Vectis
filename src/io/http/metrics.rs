use super::HttpState;
use super::error::ErrorResponse;
use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

pub async fn metrics_endpoint(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let client = state.authorize_api_key(&headers).await?;
    state.require_permission(&client, None, "metrics").await?;

    match state.metrics_handle() {
        Some(handle) => Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            handle.render(),
        )
            .into_response()),
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}
