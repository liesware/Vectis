use axum::Json;
use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

mod app;
mod auth;
mod commitments;
mod config;
mod error;
mod extract;
mod fpe;
mod health;
mod indexes;
mod keys;
mod mac;
mod masking;
mod message;
mod metrics;
mod middleware;
mod permissions;
mod pubkey;
mod remote_routes;
mod routes;
mod sign;
mod test;
mod token;

use crate::core::commitments::CommitmentProfile;
use crate::core::config::AppConfig;
use crate::core::config_file::ConfigState;
use crate::core::fpe::FpeProfile;
use crate::core::mac::MacProfile;
use crate::core::masking::MaskingProfile;
use crate::core::permissions::AuthenticatedClient;
use crate::core::remote_routes::{PeerPublicKeys, RemoteRoute};
use crate::core::routes::FinalAppRoute;
use crate::core::storage::StorageState;
use crate::core::tokenization::TokenizationProfile;
use crate::core::{audit, blocking, metrics as core_metrics};
use crate::error::DynError;
use crate::ops::init::{InitValidationOutput, ValidatedInitState};
use crate::ops::internal_keys::InternalDerivedKeysState;
use crate::ops::keys::{KeysDbState, LoadedOpsKey};
use commitments::{
    create_batch_endpoint as commit_create_batch_endpoint,
    verify_batch_endpoint as commit_verify_batch_endpoint,
};
use metrics_exporter_prometheus::PrometheusHandle;
use zeroize::Zeroize;

pub use app::run;

#[derive(Clone)]
struct ConfigKeySource {
    kid: String,
    symmetric_key_hex: String,
    symmetric_algorithm: String,
    hash_algorithm: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigReloadOutcome {
    Applied,
    StaleSignatureKeptPrevious,
}

const STALE_CONFIG_SIGNATURE_WARNING: &str =
    "config.json has changes not covered by config_sign.json — run 'vectis config sign' first";

impl Zeroize for ConfigKeySource {
    fn zeroize(&mut self) {
        self.kid.zeroize();
        self.symmetric_key_hex.zeroize();
        self.symmetric_algorithm.zeroize();
        self.hash_algorithm.zeroize();
    }
}

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

    async fn fpe_profiles_loaded(&self) -> usize {
        let config_state = self.config_state.read().await;

        config_state.fpe_profiles.len()
    }

    async fn tokenization_profiles_loaded(&self) -> usize {
        let config_state = self.config_state.read().await;

        config_state.tokenization_profiles.len()
    }

    async fn mac_profiles_loaded(&self) -> usize {
        let config_state = self.config_state.read().await;

        config_state.mac_profiles.len()
    }

    async fn masking_profiles_loaded(&self) -> usize {
        let config_state = self.config_state.read().await;

        config_state.masking_profiles.len()
    }

    async fn commitment_profiles_loaded(&self) -> usize {
        let config_state = self.config_state.read().await;

        config_state.commitment_profiles.len()
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

    async fn fpe_profile(&self, name: &str) -> Option<FpeProfile> {
        let config_state = self.config_state.read().await;

        config_state.fpe_profiles.get(name).cloned()
    }

    async fn tokenization_profile(&self, name: &str) -> Option<TokenizationProfile> {
        let config_state = self.config_state.read().await;

        config_state.tokenization_profiles.get(name).cloned()
    }

    async fn mac_profile(&self, name: &str) -> Option<MacProfile> {
        let config_state = self.config_state.read().await;

        config_state.mac_profiles.get(name).cloned()
    }

    async fn masking_profile(&self, name: &str) -> Option<MaskingProfile> {
        let config_state = self.config_state.read().await;

        config_state.masking_profiles.get(name).cloned()
    }

    async fn commitment_profile(&self, name: &str) -> Option<CommitmentProfile> {
        let config_state = self.config_state.read().await;

        config_state.commitment_profiles.get(name).cloned()
    }

    async fn reload_config_state(&self) -> Result<ConfigReloadOutcome, DynError> {
        let config_key_sources = {
            let keys_db_state = self.keys_db_state.read().await;
            keys_db_state
                .ids()
                .into_iter()
                .filter_map(|kid| {
                    keys_db_state.get(&kid).map(|loaded_key| ConfigKeySource {
                        kid,
                        symmetric_key_hex: loaded_key.keys().symmetric().key_hex().to_string(),
                        symmetric_algorithm: loaded_key.keys().symmetric().variant().to_string(),
                        hash_algorithm: loaded_key.key_material().hash_variant().to_string(),
                    })
                })
                .collect::<Vec<_>>()
        };
        let config = Arc::clone(&self.config);
        let init_state = (*self.init_state).clone();
        let reload_result = blocking::spawn_blocking_crypto(move || {
            let config_key_sources = Zeroizing::new(config_key_sources);
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
                |kid| config_key_sources.iter().any(|source| source.kid == kid),
                |request| {
                    let source = config_key_sources
                        .iter()
                        .find(|source| source.kid == request.kid)
                        .ok_or_else(|| {
                            crate::error::invalid_input(format!(
                                "fpe profile references kid not loaded in memory: {}",
                                request.kid
                            ))
                        })?;
                    crate::core::fpe::derive_fpe_key_for_profile(&source.symmetric_key_hex, request)
                },
                |request| {
                    let source = config_key_sources
                        .iter()
                        .find(|source| source.kid == request.kid)
                        .ok_or_else(|| {
                            crate::error::invalid_input(format!(
                                "tokenization profile references kid not loaded in memory: {}",
                                request.kid
                            ))
                        })?;
                    crate::core::tokenization::derive_tokenization_keys(
                        &source.symmetric_key_hex,
                        &source.symmetric_algorithm,
                        request,
                    )
                },
                |kid| {
                    let source = config_key_sources
                        .iter()
                        .find(|source| source.kid == kid)
                        .ok_or_else(|| {
                            crate::error::invalid_input(format!(
                                "mac profile references kid not loaded in memory: {kid}"
                            ))
                        })?;
                    Ok(source.hash_algorithm.clone())
                },
                |request| {
                    let source = config_key_sources
                        .iter()
                        .find(|source| source.kid == request.kid)
                        .ok_or_else(|| {
                            crate::error::invalid_input(format!(
                                "mac profile references kid not loaded in memory: {}",
                                request.kid
                            ))
                        })?;
                    crate::core::mac::derive_mac_key_for_profile(&source.symmetric_key_hex, request)
                },
                |request| {
                    let source = config_key_sources
                        .iter()
                        .find(|source| source.kid == request.kid)
                        .ok_or_else(|| {
                            crate::error::invalid_input(format!(
                                "commitment profile references kid not loaded in memory: {}",
                                request.kid
                            ))
                        })?;
                    crate::core::commitments::derive_commitment_key_for_profile(
                        &source.symmetric_key_hex,
                        request,
                    )
                },
            )
        })
        .await;
        let reloaded = match reload_result {
            Ok(reloaded) => reloaded,
            Err(err) if config_signature_is_stale_for_content(err.as_ref()) => {
                return Ok(ConfigReloadOutcome::StaleSignatureKeptPrevious);
            }
            Err(err) => return Err(err),
        };
        let mut config_state = self.config_state.write().await;
        *config_state = Zeroizing::new(reloaded);

        Ok(ConfigReloadOutcome::Applied)
    }

    async fn refresh_loaded_gauges(&self) {
        core_metrics::set_loaded_gauges(core_metrics::LoadedGaugeCounts {
            keys: self.keys_loaded().await,
            routes: self.routes_loaded().await,
            remote_routes: self.remote_routes_loaded().await,
            permission_clients: self.permissions_loaded().await,
            fpe_profiles: self.fpe_profiles_loaded().await,
            tokenization_profiles: self.tokenization_profiles_loaded().await,
            mac_profiles: self.mac_profiles_loaded().await,
            masking_profiles: self.masking_profiles_loaded().await,
            commitment_profiles: self.commitment_profiles_loaded().await,
        });
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

fn config_signature_is_stale_for_content(
    err: &(dyn std::error::Error + Send + Sync + 'static),
) -> bool {
    crate::error::is_config_signature_stale(err)
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
        "fpe.encrypt.denied" => core_metrics::record_crypto_operation("fpe_encrypt", "failed"),
        "fpe.decrypt.denied" => core_metrics::record_crypto_operation("fpe_decrypt", "failed"),
        "fpe.encrypt.batch.denied" => record_crypto_failed("fpe_encrypt_batch"),
        "fpe.decrypt.batch.denied" => record_crypto_failed("fpe_decrypt_batch"),
        "token.encode.denied" => core_metrics::record_crypto_operation("token_encode", "failed"),
        "token.decode.denied" => core_metrics::record_crypto_operation("token_decode", "failed"),
        "token.encode.batch.denied" => record_crypto_failed("token_encode_batch"),
        "token.decode.batch.denied" => record_crypto_failed("token_decode_batch"),
        "mac.create.denied" => record_crypto_failed("mac_create"),
        "mac.verify.denied" => record_crypto_failed("mac_verify"),
        "mac.create.batch.denied" => record_crypto_failed("mac_create_batch"),
        "mac.verify.batch.denied" => record_crypto_failed("mac_verify_batch"),
        "index.create.denied" => record_crypto_failed("index_create"),
        "index.verify.denied" => record_crypto_failed("index_verify"),
        "index.create.batch.denied" => record_crypto_failed("index_create_batch"),
        "index.verify.batch.denied" => record_crypto_failed("index_verify_batch"),
        "mask.denied" => record_crypto_failed("mask"),
        "mask.batch.denied" => record_crypto_failed("mask_batch"),
        "commit.create.denied" => record_crypto_failed("commit_create"),
        "commit.verify.denied" => record_crypto_failed("commit_verify"),
        "commit.create.batch.denied" => record_crypto_failed("commit_create_batch"),
        "commit.verify.batch.denied" => record_crypto_failed("commit_verify_batch"),
        "sign.denied" => core_metrics::record_crypto_operation("sign", "failed"),
        "self_test.denied" => {}
        _ => {}
    }
}

fn record_crypto_failed(operation: &str) {
    core_metrics::record_crypto_operation(operation, "failed");
}

pub fn router(state: HttpState) -> Router {
    use fpe::encrypt_batch_endpoint as fpe_encrypt_batch;
    use indexes::verify_batch_endpoint as index_verify_batch;
    use token::encode_batch_endpoint as token_encode_batch;

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
        .route("/fpe/encrypt/batch/{kid}", post(fpe_encrypt_batch))
        .route("/fpe/decrypt/batch", post(fpe::decrypt_batch_endpoint))
        .route("/fpe/encrypt/{kid}", post(fpe::encrypt_endpoint))
        .route("/fpe/decrypt", post(fpe::decrypt_endpoint))
        .route("/token/encode/batch/{kid}", post(token_encode_batch))
        .route("/token/decode/batch", post(token::decode_batch_endpoint))
        .route("/token/encode/{kid}", post(token::encode_endpoint))
        .route("/token/decode", post(token::decode_endpoint))
        .route("/mac/batch/{kid}", post(mac::create_batch_endpoint))
        .route("/mac/verify/batch", post(mac::verify_batch_endpoint))
        .route("/mac/verify", post(mac::verify_endpoint))
        .route("/mac/{kid}", post(mac::create_endpoint))
        .route("/index/batch/{kid}", post(indexes::create_batch_endpoint))
        .route("/index/verify/batch", post(index_verify_batch))
        .route("/index/verify", post(indexes::verify_endpoint))
        .route("/index/{kid}", post(indexes::create_endpoint))
        .route("/mask/batch/{kid}", post(masking::mask_batch_endpoint))
        .route("/mask/{kid}", post(masking::mask_endpoint))
        .route("/commit/batch/{kid}", post(commit_create_batch_endpoint))
        .route("/commit/verify/batch", post(commit_verify_batch_endpoint))
        .route("/commit/verify", post(commitments::verify_endpoint))
        .route("/commit/{kid}", post(commitments::create_endpoint))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_config_signature_classifier_matches_only_typed_stale_error() {
        let stale = crate::error::config_signature_stale(
            "config signature message_hash does not match config content",
        );
        let corrupt = crate::error::invalid_signature("config signature verification failed");
        let same_text_wrong_type = crate::error::invalid_input(
            "config signature message_hash does not match config content",
        );

        assert!(config_signature_is_stale_for_content(stale.as_ref()));
        assert!(!config_signature_is_stale_for_content(corrupt.as_ref()));
        assert!(!config_signature_is_stale_for_content(
            same_text_wrong_type.as_ref()
        ));
    }
}
