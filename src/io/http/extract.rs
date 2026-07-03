use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use super::error::error_response;

pub struct JsonBody(pub Value);

impl<S> FromRequest<S> for JsonBody
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state).await.map_err(|_| {
            error_response(crate::error::invalid_input("request body could not be read").as_ref())
                .into_response()
        })?;
        let value = serde_json::from_slice(&bytes).map_err(|err| {
            error_response(
                crate::error::invalid_input(format!("request body must be valid JSON: {err}"))
                    .as_ref(),
            )
            .into_response()
        })?;

        Ok(JsonBody(value))
    }
}
