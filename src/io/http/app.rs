use artbox::{
    Alignment, Artbox, Color, ColorStop, Fill, LinearGradient, RenderTarget, Renderer, fonts,
};

use crate::core::validation;
use crate::core::{config, permissions, remote_routes, routes, storage::StorageState};
use crate::error::DynError;
use crate::ops::init::ValidatedInitState;
use crate::ops::keys;
use std::io;
use std::time::Duration;
use tracing::{info, warn};
use zeroize::Zeroizing;

pub async fn run(init_state: ValidatedInitState) -> Result<(), DynError> {
    let config = config::app_config()?;
    let logging = crate::core::logging::logging_config();
    let storage = StorageState::new(&config).await?;
    let internal_keys = Zeroizing::new(
        crate::ops::internal_keys::InternalDerivedKeysState::from_init_state(&init_state)?,
    );
    let keys_db_state = keys::load_keys_db_state(&storage, &internal_keys).await?;
    let permissions_state = Zeroizing::new(permissions::load_permissions_state(
        &config.permissions_path,
        |permissions_path, permissions_content| {
            let permissions_sign_path = permissions::permissions_signature_path(
                permissions_path,
                &config.permissions_sign_path,
            );
            let signature_content = std::fs::read_to_string(&permissions_sign_path)?;
            crate::ops::sign::verify_permissions_file_signature(
                &init_state,
                permissions_path,
                permissions_content,
                &signature_content,
            )
        },
        |kid| keys_db_state.contains_id(kid),
    )?);
    let routes_state = routes::load_routes_state(
        &config,
        |routes_path, routes_content| {
            let routes_sign_path =
                routes::routes_signature_path(routes_path, &config.routes_sign_path);
            let signature_content = std::fs::read_to_string(&routes_sign_path)?;
            crate::ops::sign::verify_routes_file_signature(
                &init_state,
                routes_path,
                routes_content,
                &signature_content,
            )
        },
        |kid| keys_db_state.contains_id(kid),
    );
    let remote_routes_state = remote_routes::load_remote_routes_state(
        &config.remote_routes_path,
        |remote_routes_path, remote_routes_content| {
            let remote_routes_sign_path = remote_routes::remote_routes_signature_path(
                remote_routes_path,
                &config.remote_routes_sign_path,
            );
            let signature_content = std::fs::read_to_string(&remote_routes_sign_path)?;
            crate::ops::sign::verify_remote_routes_file_signature(
                &init_state,
                remote_routes_path,
                remote_routes_content,
                &signature_content,
            )
        },
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
        routes_path = %config.routes_path.display(),
        routes_sign_path = %config.routes_sign_path.display(),
        remote_routes_path = %config.remote_routes_path.display(),
        remote_routes_sign_path = %config.remote_routes_sign_path.display(),
        permissions_path = %config.permissions_path.display(),
        permissions_sign_path = %config.permissions_sign_path.display(),
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
        loaded_routes = routes_state.len(),
        "final app routes loaded into http state"
    );
    info!(
        loaded_remote_routes = remote_routes_state.len(),
        "remote routes loaded into http state"
    );
    info!(
        loaded_permission_clients = permissions_state.len(),
        "permissions loaded into http state"
    );
    let app = super::router(super::HttpState::new(super::HttpStateInput {
        init_state,
        internal_keys,
        storage,
        keys_db_state,
        permissions_state,
        routes_state,
        remote_routes_state,
        permissions_path: config.permissions_path.clone(),
        permissions_sign_path: config.permissions_sign_path.clone(),
        routes_path: config.routes_path.clone(),
        routes_sign_path: config.routes_sign_path.clone(),
        remote_routes_path: config.remote_routes_path.clone(),
        remote_routes_sign_path: config.remote_routes_sign_path.clone(),
        started_at,
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
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VECTIS_TLS_CERT_PATH is required when VECTIS_MODE=prod",
            )) as DynError
        })?;
        let key_path = config.tls_key_path.as_ref().ok_or_else(|| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VECTIS_TLS_KEY_PATH is required when VECTIS_MODE=prod",
            )) as DynError
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
