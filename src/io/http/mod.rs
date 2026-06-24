use axum::Router;
use axum::routing::{get, post};
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

mod app;
mod auth;
mod error;
mod keys;
mod message;
mod pubkey;
mod sign;
mod test;

use crate::core::routes::{FinalAppRoute, RoutesState};
use crate::ops::init::{InitValidationOutput, ValidatedInitState};
use crate::ops::keys::{KeysDbState, LoadedOpsKey};
use crate::ops::message::{RemotePublicKeys, RemotePublicKeysState};

pub use app::run;

#[derive(Clone)]
pub struct HttpState {
    init_state: Arc<ValidatedInitState>,
    keys_db_state: Arc<RwLock<Zeroizing<KeysDbState>>>,
    remote_public_keys_state: Arc<RwLock<Zeroizing<RemotePublicKeysState>>>,
    routes_state: Arc<RoutesState>,
}

impl HttpState {
    fn new(
        init_state: ValidatedInitState,
        keys_db_state: Zeroizing<KeysDbState>,
        routes_state: RoutesState,
    ) -> Self {
        Self {
            init_state: Arc::new(init_state),
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

    async fn with_keys_db_state<T>(&self, f: impl FnOnce(&KeysDbState) -> T) -> T {
        let keys_db_state = self.keys_db_state.read().await;

        f(&keys_db_state)
    }

    async fn upsert_keys_db_entry(&self, loaded_key: LoadedOpsKey) {
        let mut keys_db_state = self.keys_db_state.write().await;
        keys_db_state.upsert(loaded_key);
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
        .route("/test/{id}", get(test::test_endpoint))
        .route("/test/init", get(test::init_endpoint))
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
