// Copyright 2026 Eduardo Lopez
// SPDX-License-Identifier: Apache-2.0

use artbox::{
    Alignment, Artbox, Color, ColorStop, Fill, LinearGradient, RenderTarget, Renderer, fonts,
};

use crate::core::validation;
use crate::core::{config, project, protocol, storage::StorageState};
use crate::error::DynError;
use crate::ops::init::ValidatedInitState;
use crate::ops::keys;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use zeroize::Zeroizing;

pub async fn run(init_state: ValidatedInitState) -> Result<(), DynError> {
    let config = Arc::new(config::app_config()?);
    let metrics_handle = if config.metrics_enabled {
        Some(Arc::new(crate::core::metrics::init()?))
    } else {
        None
    };
    let auth_state = super::auth::HttpAuthState::from_config(&config)?;
    let logging = crate::core::logging::logging_config();
    crate::core::audit_chain::initialize(&logging, &init_state)?;
    let storage = StorageState::new(&config).await?;
    let internal_keys = Zeroizing::new(
        crate::ops::internal_keys::InternalDerivedKeysState::from_init_state(&init_state)?,
    );
    let keys_db_state = keys::load_keys_db_state(&storage, &internal_keys).await?;
    let config_state = crate::core::config_file::load_config_state(
        &config,
        |config_path, config_content| {
            let config_sign_path = crate::core::config_file::config_signature_path(
                config_path,
                &config.config_sign_path,
            );
            let signature_content =
                crate::core::config_file::read_config_signature_file(&config_sign_path)?;
            crate::ops::sign::verify_config_file_signature(
                &init_state,
                config_path,
                config_content,
                &signature_content,
            )
        },
        |kid| keys_db_state.contains_id(kid),
        |request| {
            let loaded_key = keys_db_state.get(request.kid).ok_or_else(|| {
                crate::error::invalid_input(format!(
                    "fpe profile references kid not loaded in memory: {}",
                    request.kid
                ))
            })?;
            crate::core::fpe::derive_fpe_key_for_profile(
                loaded_key.keys().symmetric().key_hex(),
                request,
            )
        },
        |request| {
            let loaded_key = keys_db_state.get(request.kid).ok_or_else(|| {
                crate::error::invalid_input(format!(
                    "tokenization profile references kid not loaded in memory: {}",
                    request.kid
                ))
            })?;
            crate::core::tokenization::derive_tokenization_keys(
                loaded_key.keys().symmetric().key_hex(),
                loaded_key.keys().symmetric().variant(),
                request,
            )
        },
        |kid| {
            let loaded_key = keys_db_state.get(kid).ok_or_else(|| {
                crate::error::invalid_input(format!(
                    "mac profile references kid not loaded in memory: {kid}"
                ))
            })?;
            Ok(loaded_key.key_material().hash_variant().to_string())
        },
        |request| {
            let loaded_key = keys_db_state.get(request.kid).ok_or_else(|| {
                crate::error::invalid_input(format!(
                    "mac profile references kid not loaded in memory: {}",
                    request.kid
                ))
            })?;
            crate::core::mac::derive_mac_key_for_profile(
                loaded_key.keys().symmetric().key_hex(),
                request,
            )
        },
        |request| {
            let loaded_key = keys_db_state.get(request.kid).ok_or_else(|| {
                crate::error::invalid_input(format!(
                    "commitment profile references kid not loaded in memory: {}",
                    request.kid
                ))
            })?;
            crate::core::commitments::derive_commitment_key_for_profile(
                loaded_key.keys().symmetric().key_hex(),
                request,
            )
        },
        |request| {
            let loaded_key = keys_db_state.get(request.kid).ok_or_else(|| {
                crate::error::invalid_input(format!(
                    "sharing profile references kid not loaded in memory: {}",
                    request.kid
                ))
            })?;
            crate::core::sharing::derive_sharing_key_for_profile(
                loaded_key.keys().symmetric().key_hex(),
                request,
            )
        },
    )?;
    let started_at = validation::current_timestamp()?;
    info!(
        http_bind_addr = %config.http_bind_addr,
        mode = %config.mode,
        server_scheme = %config.server_scheme,
        remote_scheme = %config.remote_scheme,
        final_app_scheme = %config.final_app_scheme,
        public_addr = %config.public_addr,
        final_app_addr = %config.final_app_addr,
        final_app_path = %config.final_app_path,
        config_path = %config.config_path.display(),
        config_sign_path = %config.config_sign_path.display(),
        storage_type = %config.storage_type,
        sqlite_path = %config.sqlite_path.display(),
        protocol_version = %config.protocol_version,
        log_level = %logging.level,
        log_dir = %logging.dir,
        log_file = %logging.file,
        tls_skip_verify = config.tls_skip_verify,
        http_grace_seconds = config::INTERNAL_HTTP_GRACE_SEC,
        http_timeout_seconds = config::INTERNAL_HTTP_TIMEOUT_SEC,
        postgres_configured = !config.postgres_dsn.is_empty(),
        "http service configuration loaded"
    );
    info!(
        loaded_keys = keys_db_state.len(),
        "decrypted ops keys loaded into http state"
    );
    info!(
        loaded_routes = config_state.routes.len(),
        loaded_remote_routes = config_state.remote_routes.len(),
        loaded_permission_clients = config_state.permissions.len(),
        loaded_fpe_profiles = config_state.fpe_profiles.len(),
        loaded_tokenization_profiles = config_state.tokenization_profiles.len(),
        loaded_mac_profiles = config_state.mac_profiles.len(),
        loaded_masking_profiles = config_state.masking_profiles.len(),
        loaded_commitment_profiles = config_state.commitment_profiles.len(),
        loaded_sharing_profiles = config_state.sharing_profiles.len(),
        "signed config loaded into http state"
    );
    if metrics_handle.is_some() {
        crate::core::metrics::set_unsealed_state(true);
        crate::core::metrics::set_loaded_gauges(crate::core::metrics::LoadedGaugeCounts {
            keys: keys_db_state.len(),
            routes: config_state.routes.len(),
            remote_routes: config_state.remote_routes.len(),
            permission_clients: config_state.permissions.len(),
            fpe_profiles: config_state.fpe_profiles.len(),
            tokenization_profiles: config_state.tokenization_profiles.len(),
            mac_profiles: config_state.mac_profiles.len(),
            masking_profiles: config_state.masking_profiles.len(),
            commitment_profiles: config_state.commitment_profiles.len(),
            sharing_profiles: config_state.sharing_profiles.len(),
        });
    }
    let app = super::router(super::HttpState::new(super::HttpStateInput {
        config: config.clone(),
        auth_state,
        init_state,
        internal_keys,
        storage,
        keys_db_state,
        config_state,
        started_at,
        metrics_handle,
    }));
    let renderer = Renderer::new(fonts::family("slant").unwrap())
        .with_alignment(Alignment::Center)
        .with_plain_fallback()
        .with_fill(Fill::Linear(LinearGradient::new(
            90.0,
            vec![
                ColorStop::new(0.00, Color::rgb(0, 200, 255)),
                ColorStop::new(1.00, Color::rgb(255, 90, 120)),
            ],
        )));

    let art = Artbox::from_renderer(renderer);
    let target = RenderTarget::new(30, 6);
    let rendered = art.render_text("Vectis", target)?;
    println!("--------------------------------------------------------------");
    println!("\nLicense: {}", project::LICENSE);
    print!("{}", rendered.to_ansi_string());
    println!("\nOpen Source Advanced Data Protection Service");
    println!("\n{}", project::COPYRIGHT);
    println!("Developed by {}", project::DEVELOPER);
    println!(
        "Version {} | Protocol {} | {}",
        project::VERSION,
        protocol::PROTOCOL_VERSION_V1,
        project::BUILD_STATUS
    );
    println!("\n--------------------------------------------------------------");
    println!("\n[OK] Loaded cryptographic runtime");
    println!("[OK] Verified signed configuration");
    println!("[OK] Initialized protected storage");
    println!("[OK] Loaded operational key material");
    println!("[OK] Started audit and metrics subsystems");
    println!("\nDo one thing and do it well.");
    println!("Protect sensitive data.");
    println!("\nComplexity is inevitable,");
    println!("Simplicity is intentional.");
    println!("\n--------------------------------------------------------------");
    println!("\nvectis> running...");

    let handle = axum_server::Handle::new();
    tokio::spawn(graceful_shutdown_on(
        handle.clone(),
        shutdown_signal(),
        http_grace_period(),
    ));

    let server_result = if config.server_scheme == "https" {
        let cert_path = config.tls_cert_path.as_ref().ok_or_else(|| {
            crate::error::invalid_input("VECTIS_TLS_CERT_PATH is required when VECTIS_MODE=prod")
        })?;
        let key_path = config.tls_key_path.as_ref().ok_or_else(|| {
            crate::error::invalid_input("VECTIS_TLS_KEY_PATH is required when VECTIS_MODE=prod")
        })?;
        crate::core::tls::ensure_crypto_provider();
        let tls_config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await?;

        info!(addr = %config.http_bind_addr, scheme = %config.server_scheme, "server listening");
        axum_server::bind_rustls(config.http_bind_addr, tls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await
    } else {
        warn!("server running without TLS because VECTIS_MODE=dev");

        info!(addr = %config.http_bind_addr, scheme = %config.server_scheme, "server listening");
        axum_server::bind(config.http_bind_addr)
            .handle(handle)
            .serve(app.into_make_service())
            .await
    };

    let audit_result = crate::core::audit_chain::shutdown().await;
    server_result?;
    audit_result?;
    Ok(())
}

fn http_grace_period() -> Duration {
    Duration::from_secs(config::INTERNAL_HTTP_GRACE_SEC)
}

async fn graceful_shutdown_on<F>(handle: axum_server::Handle, shutdown: F, grace_period: Duration)
where
    F: Future<Output = ()>,
{
    shutdown.await;
    info!(
        grace_seconds = grace_period.as_secs(),
        "graceful shutdown started"
    );
    handle.graceful_shutdown(Some(grace_period));
}

async fn shutdown_signal() {
    let sigint = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "failed to listen for ctrl+c shutdown signal");
        }
    };

    let sigterm = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::error!(error = %err, "failed to listen for SIGTERM shutdown signal");
            }
        }
    };

    tokio::select! {
        _ = sigint => tracing::info!("shutdown signal received: SIGINT"),
        _ = sigterm => tracing::info!("shutdown signal received: SIGTERM"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use std::net::SocketAddr;
    use tokio::sync::Notify;
    use tokio::task::JoinHandle;
    use tokio::time::{Instant, timeout};

    async fn start_test_server(
        app: Router,
    ) -> (
        axum_server::Handle,
        JoinHandle<std::io::Result<()>>,
        SocketAddr,
    ) {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("test server listener must bind");
        let addr = listener
            .local_addr()
            .expect("test server listener must report its address");
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        let server_task = tokio::spawn(async move {
            axum_server::from_tcp(listener)
                .handle(server_handle)
                .serve(app.into_make_service())
                .await
        });

        (handle, server_task, addr)
    }

    async fn wait_for_server(server_task: JoinHandle<std::io::Result<()>>) -> std::io::Result<()> {
        timeout(Duration::from_secs(1), server_task)
            .await
            .expect("test server must stop within one second")
            .expect("test server task must not panic")
    }

    #[test]
    fn http_grace_period_uses_internal_limit() {
        assert_eq!(
            http_grace_period(),
            Duration::from_secs(config::INTERNAL_HTTP_GRACE_SEC)
        );
        assert_eq!(http_grace_period(), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn request_finishing_within_grace_period_completes() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let app = Router::new().route(
            "/slow",
            get({
                let entered = entered.clone();
                let release = release.clone();
                move || {
                    let entered = entered.clone();
                    let release = release.clone();
                    async move {
                        entered.notify_one();
                        release.notified().await;
                        "complete"
                    }
                }
            }),
        );
        let (handle, server_task, addr) = start_test_server(app).await;
        let request_task = tokio::spawn(async move {
            let response = reqwest::get(format!("http://{addr}/slow")).await?;
            let status = response.status();
            let body = response.text().await?;
            Ok::<_, reqwest::Error>((status, body))
        });

        timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("slow handler must start");
        graceful_shutdown_on(handle, std::future::ready(()), Duration::from_millis(500)).await;
        release.notify_one();

        let (status, body) = timeout(Duration::from_secs(1), request_task)
            .await
            .expect("request must finish within the grace period")
            .expect("request task must not panic")
            .expect("request must complete successfully");
        assert_eq!(status, reqwest::StatusCode::OK);
        assert_eq!(body, "complete");
        wait_for_server(server_task)
            .await
            .expect("server must stop cleanly after draining");
    }

    #[tokio::test]
    async fn request_exceeding_grace_period_is_terminated() {
        let entered = Arc::new(Notify::new());
        let never_release = Arc::new(Notify::new());
        let app = Router::new().route(
            "/blocked",
            get({
                let entered = entered.clone();
                let never_release = never_release.clone();
                move || {
                    let entered = entered.clone();
                    let never_release = never_release.clone();
                    async move {
                        entered.notify_one();
                        never_release.notified().await;
                        "unreachable"
                    }
                }
            }),
        );
        let (handle, server_task, addr) = start_test_server(app).await;
        let request_task =
            tokio::spawn(async move { reqwest::get(format!("http://{addr}/blocked")).await });

        timeout(Duration::from_secs(1), entered.notified())
            .await
            .expect("blocked handler must start");
        let grace_period = Duration::from_millis(50);
        let started = Instant::now();
        graceful_shutdown_on(handle, std::future::ready(()), grace_period).await;

        wait_for_server(server_task)
            .await
            .expect("server must stop after the grace period");
        assert!(started.elapsed() >= grace_period);
        let request_result = timeout(Duration::from_secs(1), request_task)
            .await
            .expect("terminated request must return")
            .expect("request task must not panic");
        assert!(request_result.is_err());

        let new_request = reqwest::get(format!("http://{addr}/blocked")).await;
        assert!(new_request.is_err());
    }
}
