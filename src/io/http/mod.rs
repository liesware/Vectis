use axum::Json;
use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

mod app;
mod auth;
mod config;
mod error;
mod extract;
mod health;
mod keys;
mod message;
mod metrics;
mod middleware;
mod permissions;
mod pubkey;
mod remote_routes;
mod routes;
mod sign;
mod test;

use crate::core::config::AppConfig;
use crate::core::config_file::ConfigState;
use crate::core::permissions::AuthenticatedClient;
use crate::core::remote_routes::{PeerPublicKeys, RemoteRoute};
use crate::core::routes::FinalAppRoute;
use crate::core::storage::StorageState;
use crate::core::{audit, blocking, metrics as core_metrics};
use crate::error::DynError;
use crate::ops::init::{InitValidationOutput, ValidatedInitState};
use crate::ops::internal_keys::InternalDerivedKeysState;
use crate::ops::keys::{KeysDbState, LoadedOpsKey};
use metrics_exporter_prometheus::PrometheusHandle;

pub use app::run;

#[derive(Clone)]
pub struct HttpState {
    config: Arc<AppConfig>,
    auth_state: Arc<auth::HttpAuthState>,
    init_state: Arc<ValidatedInitState>,
    internal_keys: Arc<Zeroizing<InternalDerivedKeysState>>,
    storage: Arc<StorageState>,
    started_at: Arc<String>,
    keys_db_state: Arc<RwLock<Zeroizing<KeysDbState>>>,
    config_state: Arc<RwLock<Zeroizing<ConfigState>>>,
    metrics_handle: Option<Arc<PrometheusHandle>>,
}

struct HttpStateInput {
    config: Arc<AppConfig>,
    auth_state: auth::HttpAuthState,
    init_state: ValidatedInitState,
    internal_keys: Zeroizing<InternalDerivedKeysState>,
    storage: StorageState,
    keys_db_state: Zeroizing<KeysDbState>,
    config_state: ConfigState,
    started_at: String,
    metrics_handle: Option<Arc<PrometheusHandle>>,
}

impl HttpState {
    fn new(input: HttpStateInput) -> Self {
        Self {
            config: input.config,
            auth_state: Arc::new(input.auth_state),
            init_state: Arc::new(input.init_state),
            internal_keys: Arc::new(input.internal_keys),
            storage: Arc::new(input.storage),
            started_at: Arc::new(input.started_at),
            keys_db_state: Arc::new(RwLock::new(input.keys_db_state)),
            config_state: Arc::new(RwLock::new(Zeroizing::new(input.config_state))),
            metrics_handle: input.metrics_handle,
        }
    }

    fn metrics_handle(&self) -> Option<&PrometheusHandle> {
        self.metrics_handle.as_deref()
    }

    fn key_material_loaded(&self) -> bool {
        let _ = &self.keys_db_state;

        self.init_state.key_material_loaded()
    }

    fn validation(&self) -> &InitValidationOutput {
        self.init_state.validation()
    }

    fn internal_keys(&self) -> &InternalDerivedKeysState {
        &self.internal_keys
    }

    fn config(&self) -> &AppConfig {
        &self.config
    }

    async fn authorize_api_key(
        &self,
        headers: &HeaderMap,
    ) -> Result<Zeroizing<AuthenticatedClient>, (StatusCode, Json<error::ErrorResponse>)> {
        let config_state = self.config_state.read().await;

        auth::authorize_api_key(
            headers,
            self.config(),
            &self.auth_state,
            self.internal_keys(),
            &config_state.permissions,
        )
    }

    async fn require_permission(
        &self,
        client: &AuthenticatedClient,
        kid: Option<&str>,
        action: &str,
    ) -> Result<(), (StatusCode, Json<error::ErrorResponse>)> {
        self.require_permission_for(client, kid, action, None).await
    }

    async fn require_permission_for(
        &self,
        client: &AuthenticatedClient,
        kid: Option<&str>,
        action: &str,
        denied_event: Option<&str>,
    ) -> Result<(), (StatusCode, Json<error::ErrorResponse>)> {
        let config_state = self.config_state.read().await;
        let actor = audit::actor_from_client(client);

        match config_state
            .permissions
            .require_permission(client, kid, action)
        {
            Ok(()) => {
                audit::permission_allowed(&actor, kid, action);
                core_metrics::record_permission("allow");
                Ok(())
            }
            Err(err) => {
                let reason = err.to_string();
                audit::permission_denied(&actor, kid, action, &reason);
                core_metrics::record_permission("deny");
                if let Some(event_name) = denied_event {
                    audit::operation_denied(event_name, &actor, kid, None, Some(action), &reason);
                    record_operation_denied_metric(event_name);
                }

                Err(error::error_response(err.as_ref()))
            }
        }
    }

    fn storage(&self) -> &StorageState {
        &self.storage
    }

    fn started_at(&self) -> &str {
        &self.started_at
    }

    async fn keys_loaded(&self) -> usize {
        let keys_db_state = self.keys_db_state.read().await;

        keys_db_state.len()
    }

    async fn routes_loaded(&self) -> usize {
        let config_state = self.config_state.read().await;

        config_state.routes.len()
    }

    async fn remote_routes_loaded(&self) -> usize {
        let config_state = self.config_state.read().await;

        config_state.remote_routes.len()
    }

    async fn permissions_loaded(&self) -> usize {
        let config_state = self.config_state.read().await;

        config_state.permissions.len()
    }

    async fn routes_output(&self) -> crate::core::routes::ListRoutesOutput {
        let config_state = self.config_state.read().await;

        config_state.routes.list()
    }

    async fn remote_routes_output(&self) -> crate::core::remote_routes::ListRemoteRoutesOutput {
        let config_state = self.config_state.read().await;

        config_state.remote_routes.list()
    }

    async fn permissions_output(&self) -> crate::core::permissions::ListPermissionsOutput {
        let config_state = self.config_state.read().await;

        config_state.permissions.list()
    }

    async fn reload_config_state(&self) -> Result<(), DynError> {
        let loaded_key_ids = {
            let keys_db_state = self.keys_db_state.read().await;
            keys_db_state.ids()
        };
        let config = Arc::clone(&self.config);
        let init_state = (*self.init_state).clone();
        let reloaded = blocking::spawn_blocking_crypto(move || {
            crate::core::config_file::reload_config_state(
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
                |kid| loaded_key_ids.iter().any(|id| id == kid),
            )
        })
        .await?;
        let mut config_state = self.config_state.write().await;
        *config_state = Zeroizing::new(reloaded);

        Ok(())
    }

    async fn refresh_loaded_gauges(&self) {
        core_metrics::set_loaded_gauges(
            self.keys_loaded().await,
            self.routes_loaded().await,
            self.remote_routes_loaded().await,
            self.permissions_loaded().await,
        );
    }

    async fn with_keys_db_state<T>(&self, f: impl FnOnce(&KeysDbState) -> T) -> T {
        let keys_db_state = self.keys_db_state.read().await;

        f(&keys_db_state)
    }

    async fn upsert_keys_db_entry(&self, loaded_key: LoadedOpsKey) {
        let mut keys_db_state = self.keys_db_state.write().await;
        keys_db_state.upsert(loaded_key);
    }

    async fn ensure_keys_db_entry(&self, id: &str) -> Result<(), DynError> {
        crate::ops::keys::validate_key_id(id)?;
        {
            let keys_db_state = self.keys_db_state.read().await;
            if keys_db_state.get(id).is_some() {
                return Ok(());
            }
        }

        let loaded_key =
            crate::ops::keys::load_keys_db_entry(self.storage(), self.internal_keys(), id).await?;
        self.upsert_keys_db_entry(loaded_key).await;

        Ok(())
    }

    async fn reload_keys_db_state(&self) -> Result<(), DynError> {
        let reloaded =
            crate::ops::keys::load_keys_db_state(self.storage(), self.internal_keys()).await?;
        let mut keys_db_state = self.keys_db_state.write().await;
        *keys_db_state = reloaded;

        Ok(())
    }

    async fn final_app_route_for(&self, kid: &str) -> FinalAppRoute {
        let config_state = self.config_state.read().await;

        config_state.routes.route_for(kid)
    }

    async fn remote_route_for(
        &self,
        sender_kid: &str,
        recipient_kid: &str,
    ) -> Result<RemoteRoute, DynError> {
        let config_state = self.config_state.read().await;

        config_state
            .remote_routes
            .route_for(sender_kid, recipient_kid)
    }

    async fn remote_peer_public_keys(&self, kid: &str) -> Option<PeerPublicKeys> {
        let config_state = self.config_state.read().await;

        config_state.remote_routes.public_keys_for(kid).cloned()
    }
}

fn record_operation_denied_metric(event_name: &str) {
    match event_name {
        "config.reload.denied" => core_metrics::record_config_reload("failed"),
        "key.reload.denied" => core_metrics::record_keys_reload("failed"),
        "message.send.denied" => core_metrics::record_message("send", "denied"),
        "message.receive.denied" => core_metrics::record_message("receive", "denied"),
        "message.decrypt.denied" => core_metrics::record_message("decrypt", "denied"),
        "message.internal.encrypt.denied" => core_metrics::record_message("send", "denied"),
        "message.internal.decrypt.denied" => core_metrics::record_message("decrypt", "denied"),
        "sign.denied" => core_metrics::record_crypto_operation("sign", "failed"),
        "self_test.denied" => {}
        _ => {}
    }
}

pub fn router(state: HttpState) -> Router {
    debug_assert!(state.key_material_loaded());

    Router::new()
        .route("/healthz/startup", get(health::startup_endpoint))
        .route("/healthz/live", get(health::live_endpoint))
        .route("/healthz/ready", get(health::ready_endpoint))
        .route("/metrics", get(metrics::metrics_endpoint))
        .route("/self-test/keys/{kid}", get(test::test_endpoint))
        .route("/self-test/init", get(test::init_endpoint))
        .route("/keys/reload", post(keys::refresh_endpoint))
        .route("/keys/properties/{kid}", get(keys::get_properties_endpoint))
        .route("/keys/properties", get(keys::list_properties_endpoint))
        .route("/lifecycle/{kid}", post(keys::update_lifecycle_endpoint))
        .route("/config/reload", post(config::reload_endpoint))
        .route("/routes", get(routes::list_endpoint))
        .route("/remote-routes", get(remote_routes::list_endpoint))
        .route("/permissions", get(permissions::list_endpoint))
        .route(
            "/keys",
            get(keys::list_endpoint).post(keys::create_endpoint),
        )
        .route("/sign/verification", post(sign::sign_verification_endpoint))
        .route("/sign/{kid}", post(sign::sign_endpoint))
        .route("/pub/{kid}", get(pubkey::pub_endpoint))
        .route(
            "/message/internal/encrypt/{kid}",
            post(message::internal_encrypt_endpoint),
        )
        .route(
            "/message/internal/decrypt",
            post(message::internal_decrypt_endpoint),
        )
        .route("/message/decrypt", post(message::decrypt_endpoint))
        .route("/message", post(message::receive_endpoint))
        .route("/message/{sender_kid}", post(message::send_endpoint))
        .layer(axum::middleware::from_fn(middleware::request_context))
        .with_state(state)
}
