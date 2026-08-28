use axum::Json;
use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::{StatusCode, header::CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use super::error::{ErrorResponse, error_response};

const REQUEST_BODY_TOO_LARGE_ERROR: &str = "request body exceeds maximum allowed size";
const REQUEST_CONTENT_TYPE_ERROR: &str = "request content type must be application/json";

#[derive(Debug)]
pub struct JsonBody(pub Value);

impl<S> FromRequest<S> for JsonBody
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        if !has_json_content_type(&req) {
            return Err(content_type_error_response());
        }
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|rejection| body_read_error_response(rejection.into_response().status()))?;
        let value = serde_json::from_slice(&bytes).map_err(|error| {
            error_response(
                crate::error::invalid_json_input("request body must be valid JSON", &error)
                    .as_ref(),
            )
            .into_response()
        })?;

        Ok(JsonBody(value))
    }
}

fn has_json_content_type(request: &Request) -> bool {
    request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

fn content_type_error_response() -> Response {
    (
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        Json(ErrorResponse::new(String::from(REQUEST_CONTENT_TYPE_ERROR))),
    )
        .into_response()
}

fn body_read_error_response(status: StatusCode) -> Response {
    if status == StatusCode::PAYLOAD_TOO_LARGE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse::new(String::from(
                REQUEST_BODY_TOO_LARGE_ERROR,
            ))),
        )
            .into_response();
    }

    error_response(crate::error::invalid_input("request body could not be read").as_ref())
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config;
    use axum::body::{Body, to_bytes};
    use axum::extract::DefaultBodyLimit;
    use axum::http::header::CONTENT_TYPE;
    use serde_json::json;

    async fn extract_json_body(body: Vec<u8>) -> Result<JsonBody, Box<Response>> {
        extract_json_body_with_content_type(body, Some("application/json")).await
    }

    async fn extract_json_body_with_content_type(
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<JsonBody, Box<Response>> {
        let mut builder = Request::builder();
        if let Some(content_type) = content_type {
            builder = builder.header(CONTENT_TYPE, content_type);
        }
        let mut request = builder.body(Body::from(body)).expect("request must build");
        DefaultBodyLimit::max(config::INTERNAL_HTTP_MAX_SIZE).apply(&mut request);

        JsonBody::from_request(request, &()).await.map_err(Box::new)
    }

    fn valid_json_with_size(size: usize) -> Vec<u8> {
        const PREFIX: &[u8] = br#"{"value":""#;
        const SUFFIX: &[u8] = br#""}"#;

        assert!(size >= PREFIX.len() + SUFFIX.len());
        let mut body = Vec::with_capacity(size);
        body.extend_from_slice(PREFIX);
        body.resize(size - SUFFIX.len(), b'a');
        body.extend_from_slice(SUFFIX);
        assert_eq!(body.len(), size);
        body
    }

    async fn response_json(response: Response) -> Value {
        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("response body must be readable");
        serde_json::from_slice(&body).expect("response body must be JSON")
    }

    #[tokio::test]
    async fn json_body_accepts_valid_body_below_limit() {
        let JsonBody(value) = extract_json_body(br#"{"ok":true}"#.to_vec())
            .await
            .expect("valid body must be accepted");

        assert_eq!(value, json!({"ok": true}));
    }

    #[tokio::test]
    async fn json_body_accepts_json_content_type_with_charset() {
        let JsonBody(value) = extract_json_body_with_content_type(
            br#"{"ok":true}"#.to_vec(),
            Some("application/json; charset=utf-8"),
        )
        .await
        .expect("JSON content type with charset must be accepted");

        assert_eq!(value, json!({"ok": true}));
    }

    #[tokio::test]
    async fn json_body_rejects_missing_or_non_json_content_type() {
        for content_type in [None, Some("text/plain"), Some("application/octet-stream")] {
            let response =
                extract_json_body_with_content_type(br#"{"ok":true}"#.to_vec(), content_type)
                    .await
                    .expect_err("non-JSON content type must be rejected");

            assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
            assert_eq!(
                response_json(*response).await,
                json!({"error": REQUEST_CONTENT_TYPE_ERROR})
            );
        }
    }

    #[tokio::test]
    async fn json_body_accepts_body_at_exact_limit() {
        let JsonBody(value) =
            extract_json_body(valid_json_with_size(config::INTERNAL_HTTP_MAX_SIZE))
                .await
                .expect("body at exact limit must be accepted");

        assert_eq!(
            value["value"].as_str().map(str::len),
            Some(config::INTERNAL_HTTP_MAX_SIZE - br#"{"value":""#.len() - br#""}"#.len())
        );
    }

    #[tokio::test]
    async fn json_body_rejects_body_over_limit_with_json_413() {
        let response = extract_json_body(valid_json_with_size(config::INTERNAL_HTTP_MAX_SIZE + 1))
            .await
            .expect_err("body over limit must be rejected");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            response_json(*response).await,
            json!({"error": REQUEST_BODY_TOO_LARGE_ERROR})
        );
    }

    #[tokio::test]
    async fn json_body_keeps_invalid_json_as_bad_request() {
        let response = extract_json_body(b"{".to_vec())
            .await
            .expect_err("malformed JSON must be rejected");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_json(*response).await;
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|message| message.starts_with("request body must be valid JSON:"))
        );
    }

    #[tokio::test]
    async fn non_size_body_read_failure_keeps_generic_bad_request() {
        let response = body_read_error_response(StatusCode::BAD_REQUEST);

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(response).await,
            json!({"error": "request body could not be read"})
        );
    }
}
