use crate::core::{config, validation};
use crate::error::DynError;
use reqwest::StatusCode;
use serde::{Serialize, de::DeserializeOwned};
use std::io;
use std::sync::OnceLock;
use std::time::Duration;
use tracing::warn;

const DEFAULT_TIMEOUT_SECONDS: u64 = 30;

struct HttpClientState {
    client: reqwest::Client,
    config: config::HttpClientConfig,
}

static HTTP_CLIENT: OnceLock<HttpClientState> = OnceLock::new();

pub async fn get_remote_json<T>(host: &str, path: &str) -> Result<T, DynError>
where
    T: DeserializeOwned,
{
    let state = client_state()?;
    let url = http_url(&state.config.remote_scheme, host, path)?;
    let response = state.client.get(url).send().await?;
    let response = ensure_success(host, response).await?;

    Ok(response.json::<T>().await?)
}

pub async fn post_remote_json<TRequest, TResponse>(
    host: &str,
    path: &str,
    body: &TRequest,
) -> Result<TResponse, DynError>
where
    TRequest: Serialize,
    TResponse: DeserializeOwned,
{
    let state = client_state()?;
    let url = http_url(&state.config.remote_scheme, host, path)?;
    let response = state.client.post(url).json(body).send().await?;
    let response = ensure_success(host, response).await?;

    Ok(response.json::<TResponse>().await?)
}

pub async fn post_final_app_json<TRequest, TResponse>(
    host: &str,
    path: &str,
    body: &TRequest,
) -> Result<TResponse, DynError>
where
    TRequest: Serialize,
    TResponse: DeserializeOwned,
{
    let state = client_state()?;
    let url = http_url(&state.config.final_app_scheme, host, path)?;
    let response = state.client.post(url).json(body).send().await?;
    let response = ensure_success(host, response).await?;

    Ok(response.json::<TResponse>().await?)
}

fn client_state() -> Result<&'static HttpClientState, DynError> {
    if let Some(state) = HTTP_CLIENT.get() {
        return Ok(state);
    }

    let config = config::http_client_config()?;
    if config.tls_skip_verify {
        warn!("VECTIS_TLS_SKIP_VERIFY=true; TLS certificate verification is disabled");
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECONDS))
        .danger_accept_invalid_certs(config.tls_skip_verify)
        .build()?;
    let _ = HTTP_CLIENT.set(HttpClientState { client, config });

    HTTP_CLIENT.get().ok_or_else(|| {
        Box::new(io::Error::other("HTTP client could not be initialized")) as DynError
    })
}

fn http_url(scheme: &str, host: &str, path: &str) -> Result<String, DynError> {
    config::validate_http_scheme(scheme)?;
    validation::validate_host_port("http_host", host)?;
    config::validate_http_path_field("http_path", path)?;

    Ok(format!("{scheme}://{host}{path}"))
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
