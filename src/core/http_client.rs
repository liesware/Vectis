use crate::core::{config, validation};
use crate::error::DynError;
use reqwest::StatusCode;
use serde::{Serialize, de::DeserializeOwned};
use std::sync::OnceLock;
use std::time::Duration;
use tracing::warn;

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

    let client = build_runtime_http_client(runtime_http_timeout(), config.tls_skip_verify)?;
    let _ = HTTP_CLIENT.set(HttpClientState { client, config });

    HTTP_CLIENT
        .get()
        .ok_or_else(|| crate::error::internal("HTTP client could not be initialized"))
}

fn runtime_http_timeout() -> Duration {
    Duration::from_secs(config::INTERNAL_HTTP_TIMEOUT_SEC)
}

fn build_runtime_http_client(
    timeout: Duration,
    tls_skip_verify: bool,
) -> Result<reqwest::Client, DynError> {
    Ok(reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(tls_skip_verify)
        .build()?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use std::net::SocketAddr;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    async fn start_test_server() -> (
        axum_server::Handle,
        JoinHandle<std::io::Result<()>>,
        SocketAddr,
    ) {
        let app = Router::new().route("/fast", get(|| async { "ok" })).route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                "late"
            }),
        );
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        let server_task = tokio::spawn(async move {
            axum_server::bind("127.0.0.1:0".parse().expect("test address must parse"))
                .handle(server_handle)
                .serve(app.into_make_service())
                .await
        });
        let addr = timeout(Duration::from_secs(1), handle.listening())
            .await
            .expect("test server must start within one second")
            .expect("test server must report its listening address");

        (handle, server_task, addr)
    }

    async fn stop_test_server(
        handle: axum_server::Handle,
        server_task: JoinHandle<std::io::Result<()>>,
    ) {
        handle.shutdown();
        timeout(Duration::from_secs(1), server_task)
            .await
            .expect("test server must stop within one second")
            .expect("test server task must not panic")
            .expect("test server must stop cleanly");
    }

    #[test]
    fn runtime_timeout_uses_internal_constant() {
        assert_eq!(
            runtime_http_timeout(),
            Duration::from_secs(config::INTERNAL_HTTP_TIMEOUT_SEC)
        );
        assert_eq!(runtime_http_timeout(), Duration::from_secs(10));
    }

    #[tokio::test]
    async fn runtime_client_completes_response_within_timeout() {
        let (handle, server_task, addr) = start_test_server().await;
        let client = build_runtime_http_client(Duration::from_millis(500), false)
            .expect("test client must build");

        let response = client
            .get(format!("http://{addr}/fast"))
            .send()
            .await
            .expect("fast response must complete");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.text().await.expect("response body must read"),
            "ok"
        );

        stop_test_server(handle, server_task).await;
    }

    #[tokio::test]
    async fn runtime_client_times_out_slow_response() {
        let (handle, server_task, addr) = start_test_server().await;
        let client = build_runtime_http_client(Duration::from_millis(25), false)
            .expect("test client must build");

        let err = client
            .get(format!("http://{addr}/slow"))
            .send()
            .await
            .expect_err("slow response must exceed the client timeout");
        assert!(err.is_timeout());

        stop_test_server(handle, server_task).await;
    }
}
