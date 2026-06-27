use crate::core::{config, validation};
use crate::error::DynError;
use reqwest::StatusCode;
use serde::{Serialize, de::DeserializeOwned};
use std::io;
use std::sync::OnceLock;
use std::time::Duration;
use tracing::warn;

const DEFAULT_TIMEOUT_SECONDS: u64 = 30;

static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

pub async fn get_json<T>(host: &str, path: &str) -> Result<T, DynError>
where
    T: DeserializeOwned,
{
    let url = http_url(host, path)?;
    let response = client()?.get(url).send().await?;
    let response = ensure_success(host, response).await?;

    Ok(response.json::<T>().await?)
}

pub async fn post_json<TRequest, TResponse>(
    host: &str,
    path: &str,
    body: &TRequest,
) -> Result<TResponse, DynError>
where
    TRequest: Serialize,
    TResponse: DeserializeOwned,
{
    let url = http_url(host, path)?;
    let response = client()?.post(url).json(body).send().await?;
    let response = ensure_success(host, response).await?;

    Ok(response.json::<TResponse>().await?)
}

fn client() -> Result<&'static reqwest::Client, DynError> {
    if let Some(client) = HTTP_CLIENT.get() {
        return Ok(client);
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECONDS))
        .build()?;
    let _ = HTTP_CLIENT.set(client);

    HTTP_CLIENT.get().ok_or_else(|| {
        Box::new(io::Error::other("HTTP client could not be initialized")) as DynError
    })
}

fn http_url(host: &str, path: &str) -> Result<String, DynError> {
    validation::validate_host_port("http_host", host)?;
    config::validate_http_path_field("http_path", path)?;

    Ok(format!("http://{host}{path}"))
}

async fn ensure_success(
    host: &str,
    response: reqwest::Response,
) -> Result<reqwest::Response, DynError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }

    warn!(
        host = %host,
        status_code = status.as_u16(),
        "remote HTTP request returned non-success status"
    );

    Err(Box::new(io::Error::new(
        error_kind_for_status(status),
        format!("remote HTTP request failed with status {}", status.as_u16()),
    )))
}

fn error_kind_for_status(status: StatusCode) -> io::ErrorKind {
    match status.as_u16() {
        400 => io::ErrorKind::InvalidInput,
        401 | 403 => io::ErrorKind::PermissionDenied,
        404 => io::ErrorKind::NotFound,
        _ => io::ErrorKind::InvalidData,
    }
}
