use crate::core::{config, validation};
use crate::error::DynError;
use reqwest::StatusCode;
use serde::{Serialize, de::DeserializeOwned};
use std::sync::OnceLock;
use std::time::Duration;
use tracing::warn;

const DEFAULT_TIMEOUT_SECONDS: u64 = 30;

struct HttpClientState {
    client: reqwest::Client,
    config: config::HttpClientConfig,
}

static HTTP_CLIENT: OnceLock<HttpClientState> = OnceLock::new();

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
    if config.mode == "prod" && config.tls_skip_verify {
        warn!("VECTIS_TLS_SKIP_VERIFY=true; outbound TLS certificate verification is disabled");
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECONDS))
        .danger_accept_invalid_certs(config.tls_skip_verify)
        .build()?;
    let _ = HTTP_CLIENT.set(HttpClientState { client, config });

    HTTP_CLIENT
        .get()
        .ok_or_else(|| crate::error::internal("HTTP client could not be initialized"))
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

    Err(error_for_status(status))
}

fn error_for_status(status: StatusCode) -> DynError {
    let message = format!("remote HTTP request failed with status {}", status.as_u16());
    match status.as_u16() {
        400 => crate::error::invalid_input(message),
        401 | 403 => crate::error::forbidden(message),
        404 => crate::error::not_found(message),
        _ => crate::error::internal(message),
    }
}
