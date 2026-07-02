use artbox::{
    Alignment, Artbox, Color, ColorStop, Fill, LinearGradient, RenderTarget, Renderer, fonts,
};

use crate::core::validation;
use crate::core::{config, storage::StorageState};
use crate::error::DynError;
use crate::ops::init::ValidatedInitState;
use crate::ops::keys;
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
    );
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
        "signed config loaded into http state"
    );
    if metrics_handle.is_some() {
        crate::core::metrics::set_loaded_gauges(
            keys_db_state.len(),
            config_state.routes.len(),
            config_state.remote_routes.len(),
            config_state.permissions.len(),
        );
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
    println!("\nLicense Apache 2.0, 18 June 2026");
    print!("{}", rendered.to_ansi_string());
    println!("\nData Lifecycle Protection");
    println!("\n-------------------------");
    println!("\nby Liesware Corp.");
    println!("\nComplexity is inevitable, simplicity is intentional.");

    if config.server_scheme == "https" {
        let cert_path = config.tls_cert_path.as_ref().ok_or_else(|| {
            crate::error::invalid_input("VECTIS_TLS_CERT_PATH is required when VECTIS_MODE=prod")
        })?;
        let key_path = config.tls_key_path.as_ref().ok_or_else(|| {
            crate::error::invalid_input("VECTIS_TLS_KEY_PATH is required when VECTIS_MODE=prod")
        })?;
        let tls_config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await?;
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
        });

        info!(addr = %config.http_bind_addr, scheme = %config.server_scheme, "server listening");
        axum_server::bind_rustls(config.http_bind_addr, tls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    } else {
        warn!("server running without TLS because VECTIS_MODE=dev");
        let listener = tokio::net::TcpListener::bind(config.http_bind_addr).await?;

        info!(addr = %config.http_bind_addr, scheme = %config.server_scheme, "server listening");
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    }

    Ok(())
}

async fn shutdown_signal() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        tracing::error!(error = %err, "failed to listen for ctrl+c shutdown signal");
    }
}
