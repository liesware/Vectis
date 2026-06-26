use axum::Router;
use axum::routing::{get, post};
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

mod app;
mod auth;
mod error;
mod health;
mod keys;
mod message;
mod pubkey;
mod sign;
mod test;

use crate::core::routes::{FinalAppRoute, RoutesState};
use crate::core::storage::StorageState;
use crate::error::DynError;
use crate::ops::init::{InitValidationOutput, ValidatedInitState};
use crate::ops::keys::{KeysDbState, LoadedOpsKey};
use crate::ops::message::{RemotePublicKeys, RemotePublicKeysState};

pub use app::run;

#[derive(Clone)]
pub struct HttpState {
    init_state: Arc<ValidatedInitState>,
    storage: Arc<StorageState>,
    started_at: Arc<String>,
    keys_db_state: Arc<RwLock<Zeroizing<KeysDbState>>>,
    remote_public_keys_state: Arc<RwLock<Zeroizing<RemotePublicKeysState>>>,
    routes_state: Arc<RoutesState>,
}

impl HttpState {
    fn new(
        init_state: ValidatedInitState,
        storage: StorageState,
        keys_db_state: Zeroizing<KeysDbState>,
        routes_state: RoutesState,
        started_at: String,
    ) -> Self {
        Self {
            init_state: Arc::new(init_state),
            storage: Arc::new(storage),
            started_at: Arc::new(started_at),
            keys_db_state: Arc::new(RwLock::new(keys_db_state)),
            remote_public_keys_state: Arc::new(RwLock::new(Zeroizing::new(
                RemotePublicKeysState::default(),
            ))),
            routes_state: Arc::new(routes_state),
        }
    }

    fn key_material_loaded(&self) -> bool {
        let _ = &self.keys_db_state;

        self.init_state.key_material_loaded()
    }

    fn validation(&self) -> &InitValidationOutput {
        self.init_state.validation()
    }

    fn init_state(&self) -> &ValidatedInitState {
        &self.init_state
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

    fn routes_loaded(&self) -> usize {
        self.routes_state.len()
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
            crate::ops::keys::load_keys_db_entry(self.storage(), self.init_state(), id).await?;
        self.upsert_keys_db_entry(loaded_key).await;

        Ok(())
    }

    async fn reload_keys_db_state(&self) -> Result<(), DynError> {
        let reloaded =
            crate::ops::keys::load_keys_db_state(self.storage(), self.init_state()).await?;
        let mut keys_db_state = self.keys_db_state.write().await;
        *keys_db_state = reloaded;

        Ok(())
    }

    async fn remote_public_keys(&self, host: &str, kid: &str) -> Option<RemotePublicKeys> {
        let remote_public_keys_state = self.remote_public_keys_state.read().await;

        remote_public_keys_state.get(host, kid).cloned()
    }

    async fn upsert_remote_public_keys(&self, remote_key: RemotePublicKeys) {
        let mut remote_public_keys_state = self.remote_public_keys_state.write().await;
        remote_public_keys_state.upsert(remote_key);
    }

    fn final_app_route_for(&self, kid: &str) -> FinalAppRoute {
        self.routes_state.route_for(kid)
    }
}

pub fn router(state: HttpState) -> Router {
    debug_assert!(state.key_material_loaded());

    Router::new()
        .route("/healthz/startup", get(health::startup_endpoint))
        .route("/healthz/live", get(health::live_endpoint))
        .route("/healthz/ready", get(health::ready_endpoint))
        .route("/self-test/keys/{id}", get(test::test_endpoint))
        .route("/self-test/init", get(test::init_endpoint))
        .route("/keys/reload", post(keys::refresh_endpoint))
        .route(
            "/keys",
            get(keys::list_endpoint).post(keys::create_endpoint),
        )
        .route("/sign/verification", post(sign::sign_verification_endpoint))
        .route("/sign/{id}", post(sign::sign_endpoint))
        .route("/pub/{id}", get(pubkey::pub_endpoint))
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
        .with_state(state)
}
