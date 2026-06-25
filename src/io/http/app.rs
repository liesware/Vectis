use artbox::{
    Alignment, Artbox, Color, ColorStop, Fill, LinearGradient, RenderTarget, Renderer, fonts,
};

use crate::core::validation;
use crate::core::{config, routes, storage::StorageState};
use crate::error::DynError;
use crate::ops::init::ValidatedInitState;
use crate::ops::keys;
use tracing::info;

pub async fn run(init_state: ValidatedInitState) -> Result<(), DynError> {
    let config = config::app_config()?;
    let logging = crate::core::logging::logging_config();
    let storage = StorageState::new(&config).await?;
    let keys_db_state = keys::load_keys_db_state(&storage, &init_state).await?;
    let routes_state = routes::load_routes_state(&config);
    let started_at = validation::current_timestamp()?;
    info!(
        http_bind_addr = %config.http_bind_addr,
        public_addr = %config.public_addr,
        final_app_addr = %config.final_app_addr,
        final_app_path = %config.final_app_path,
        routes_path = %config.routes_path.display(),
        storage_type = %config.storage_type,
        sqlite_path = %config.sqlite_path.display(),
        protocol_version = %config.protocol_version,
        log_level = %logging.level,
        log_dir = %logging.dir,
        log_file = %logging.file,
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
    let app = super::router(super::HttpState::new(
        init_state,
        storage,
        keys_db_state,
        routes_state,
        started_at,
    ));
    let listener = tokio::net::TcpListener::bind(config.http_bind_addr).await?;

    info!(addr = %config.http_bind_addr, "server listening");

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

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        tracing::error!(error = %err, "failed to listen for ctrl+c shutdown signal");
    }
}
