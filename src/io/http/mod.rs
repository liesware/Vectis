use axum::Json;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use std::collections::HashMap;
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
mod key_load;
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
mod sharing;
mod sign;
mod test;
mod time;
mod token;

use crate::core::config::{AppConfig, INTERNAL_HTTP_MAX_SIZE};
use crate::core::config_file::ConfigState;
use crate::core::permissions::AuthenticatedClient;
use crate::core::storage::StorageState;
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

struct ConfigKeySource {
    symmetric_key_hex: String,
    symmetric_algorithm: String,
    hash_algorithm: String,
}

#[derive(Default)]
struct ConfigKeySources {
    by_kid: HashMap<String, ConfigKeySource>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigReloadOutcome {
    Applied,
    StaleSignatureKeptPrevious,
}

const STALE_CONFIG_SIGNATURE_WARNING: &str =
    "config.json has changes not covered by config_sign.json — run 'vectis config sign' first";

type HttpError = (StatusCode, Json<error::ErrorResponse>);
type ConfigSnapshot = Arc<Zeroizing<ConfigState>>;

struct AuthenticatedRequest {
    client: Zeroizing<AuthenticatedClient>,
    config: ConfigSnapshot,
}

impl AuthenticatedRequest {
    fn client(&self) -> &AuthenticatedClient {
        &self.client
    }

    fn config(&self) -> &ConfigState {
        &self.config
    }

    fn require_permission(&self, kid: Option<&str>, action: &str) -> Result<(), HttpError> {
        self.require_permission_for(kid, action, None)
    }

    fn require_permission_for(
        &self,
        kid: Option<&str>,
        action: &str,
        denied_event: Option<&str>,
    ) -> Result<(), HttpError> {
        let actor = audit::actor_from_client(self.client());

        match self
            .config()
            .permissions
            .require_permission(self.client(), kid, action)
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
}

#[derive(Clone, Copy)]
struct ConfigLoadedCounts {
    routes: usize,
    remote_routes: usize,
    permission_clients: usize,
    fpe_profiles: usize,
    tokenization_profiles: usize,
    mac_profiles: usize,
    masking_profiles: usize,
    commitment_profiles: usize,
    sharing_profiles: usize,
}

impl ConfigLoadedCounts {
    fn from_config(config: &ConfigState) -> Self {
        Self {
            routes: config.routes.len(),
            remote_routes: config.remote_routes.len(),
            permission_clients: config.permissions.len(),
            fpe_profiles: config.fpe_profiles.len(),
            tokenization_profiles: config.tokenization_profiles.len(),
            mac_profiles: config.mac_profiles.len(),
            masking_profiles: config.masking_profiles.len(),
            commitment_profiles: config.commitment_profiles.len(),
            sharing_profiles: config.sharing_profiles.len(),
        }
    }
}

impl Zeroize for ConfigKeySource {
    fn zeroize(&mut self) {
        self.symmetric_key_hex.zeroize();
        self.symmetric_algorithm.zeroize();
        self.hash_algorithm.zeroize();
    }
}

impl Zeroize for ConfigKeySources {
    fn zeroize(&mut self) {
        for (mut kid, mut source) in self.by_kid.drain() {
            kid.zeroize();
            source.zeroize();
        }
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
    key_loads: Arc<key_load::KeyLoadSingleflight>,
    config_state: Arc<RwLock<ConfigSnapshot>>,
    metrics_handle: Option<Arc<PrometheusHandle>>,
}

struct HttpStateInput {
    config: Arc<AppConfig>,
    auth_state: auth::HttpAuthState,
    init_state: ValidatedInitState,
    internal_keys: Arc<Zeroizing<InternalDerivedKeysState>>,
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
            internal_keys: input.internal_keys,
            storage: Arc::new(input.storage),
            started_at: Arc::new(input.started_at),
            keys_db_state: Arc::new(RwLock::new(input.keys_db_state)),
            key_loads: Arc::new(key_load::KeyLoadSingleflight::new()),
            config_state: Arc::new(RwLock::new(Arc::new(Zeroizing::new(input.config_state)))),
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

    async fn config_snapshot(&self) -> ConfigSnapshot {
        let config = self.config_state.read().await;
        Arc::clone(&config)
    }

    async fn authorize_request(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedRequest, HttpError> {
        let config = self.config_snapshot().await;
        let client = auth::authorize_api_key(
            headers,
            self.config(),
            &self.auth_state,
            self.internal_keys(),
            &config.permissions,
        )?;

        Ok(AuthenticatedRequest { client, config })
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

    async fn reload_config_state(&self) -> Result<ConfigReloadOutcome, DynError> {
        let config_key_sources = {
            let keys_db_state = self.keys_db_state.read().await;
            let by_kid = keys_db_state
                .ids()
                .into_iter()
                .filter_map(|kid| {
                    keys_db_state.get(&kid).map(|loaded_key| {
                        (
                            kid,
                            ConfigKeySource {
                                symmetric_key_hex: loaded_key
                                    .keys()
                                    .symmetric()
                                    .key_hex()
                                    .to_string(),
                                symmetric_algorithm: loaded_key
                                    .keys()
                                    .symmetric()
                                    .variant()
                                    .to_string(),
                                hash_algorithm: loaded_key
                                    .key_material()
                                    .hash_variant()
                                    .to_string(),
                            },
                        )
                    })
                })
                .collect();
            ConfigKeySources { by_kid }
        };
        let config = Arc::clone(&self.config);
        let init_state = (*self.init_state).clone();
        let reload_result = blocking::spawn_blocking_unbounded(move || {
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
                |kid| config_key_sources.by_kid.contains_key(kid),
                |request| {
                    let source = config_key_sources.by_kid.get(request.kid).ok_or_else(|| {
                        crate::error::invalid_input(format!(
                            "fpe profile references kid not loaded in memory: {}",
                            request.kid
                        ))
                    })?;
                    crate::core::fpe::derive_fpe_key_for_profile(&source.symmetric_key_hex, request)
                },
                |request| {
                    let source = config_key_sources.by_kid.get(request.kid).ok_or_else(|| {
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
                    let source = config_key_sources.by_kid.get(kid).ok_or_else(|| {
                        crate::error::invalid_input(format!(
                            "mac profile references kid not loaded in memory: {kid}"
                        ))
                    })?;
                    Ok(source.hash_algorithm.clone())
                },
                |request| {
                    let source = config_key_sources.by_kid.get(request.kid).ok_or_else(|| {
                        crate::error::invalid_input(format!(
                            "mac profile references kid not loaded in memory: {}",
                            request.kid
                        ))
                    })?;
                    crate::core::mac::derive_mac_key_for_profile(&source.symmetric_key_hex, request)
                },
                |request| {
                    let source = config_key_sources.by_kid.get(request.kid).ok_or_else(|| {
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
                |request| {
                    let source = config_key_sources.by_kid.get(request.kid).ok_or_else(|| {
                        crate::error::invalid_input(format!(
                            "sharing profile references kid not loaded in memory: {}",
                            request.kid
                        ))
                    })?;
                    crate::core::sharing::derive_sharing_key_for_profile(
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
        *config_state = Arc::new(Zeroizing::new(reloaded));

        Ok(ConfigReloadOutcome::Applied)
    }

    async fn refresh_loaded_gauges(&self) {
        let config = self.config_snapshot().await;
        self.refresh_loaded_gauges_from(&config).await;
    }

    async fn refresh_loaded_gauges_from(&self, config: &ConfigState) {
        let keys_count = self.keys_loaded().await;
        Self::set_loaded_gauges(config, keys_count);
    }

    fn set_loaded_gauges(config: &ConfigState, keys_count: usize) {
        let counts = ConfigLoadedCounts::from_config(config);
        core_metrics::set_loaded_gauges(core_metrics::LoadedGaugeCounts {
            keys: keys_count,
            routes: counts.routes,
            remote_routes: counts.remote_routes,
            permission_clients: counts.permission_clients,
            fpe_profiles: counts.fpe_profiles,
            tokenization_profiles: counts.tokenization_profiles,
            mac_profiles: counts.mac_profiles,
            masking_profiles: counts.masking_profiles,
            commitment_profiles: counts.commitment_profiles,
            sharing_profiles: counts.sharing_profiles,
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

        self.key_loads
            .run(id, || async {
                {
                    let keys_db_state = self.keys_db_state.read().await;
                    if keys_db_state.contains_id(id) {
                        return Ok(());
                    }
                }

                let loaded_key =
                    crate::ops::keys::load_keys_db_entry(self.storage(), self.internal_keys(), id)
                        .await?;
                let mut keys_db_state = self.keys_db_state.write().await;
                keys_db_state.insert_if_absent(loaded_key);

                Ok(())
            })
            .await
    }

    async fn reload_keys_db_state(&self) -> Result<(), DynError> {
        let reloaded =
            crate::ops::keys::load_keys_db_state(self.storage(), &self.internal_keys).await?;
        let mut keys_db_state = self.keys_db_state.write().await;
        *keys_db_state = reloaded;

        Ok(())
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
        "shares.split.denied" => record_crypto_failed("share_split"),
        "shares.combine.denied" => record_crypto_failed("share_combine"),
        "time.attest.denied" => record_crypto_failed("time_attest"),
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
        .route("/time/attest", post(time::attest_endpoint))
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
        .route("/shares/split/{kid}", post(sharing::split_endpoint))
        .route("/shares/combine", post(sharing::combine_endpoint))
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
        .layer(DefaultBodyLimit::max(INTERNAL_HTTP_MAX_SIZE))
        .layer(axum::middleware::from_fn(middleware::request_context))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_config_state(final_app_addr: &str) -> ConfigState {
        test_config_state_with_permissions(
            final_app_addr,
            crate::core::permissions::PermissionsState::default(),
        )
    }

    fn test_config_state_with_permissions(
        final_app_addr: &str,
        permissions: crate::core::permissions::PermissionsState,
    ) -> ConfigState {
        ConfigState {
            routes: crate::core::routes::RoutesState::from_parts(
                final_app_addr.to_string(),
                String::from("/message"),
                Vec::new(),
            ),
            remote_routes: crate::core::remote_routes::RemoteRoutesState::default(),
            permissions,
            fpe_profiles: crate::core::fpe::FpeProfilesState::default(),
            tokenization_profiles: crate::core::tokenization::TokenizationProfilesState::default(),
            mac_profiles: crate::core::mac::MacProfilesState::default(),
            masking_profiles: crate::core::masking::MaskingProfilesState::default(),
            commitment_profiles: crate::core::commitments::CommitmentProfilesState::default(),
            sharing_profiles: crate::core::sharing::SharingProfilesState::default(),
            time_attestation:
                crate::core::time_attestation::EffectiveTimeAttestationConfig::defaults(),
        }
    }

    #[tokio::test]
    async fn config_snapshot_remains_stable_after_swap() {
        let state = RwLock::new(Arc::new(Zeroizing::new(test_config_state(
            "old.example:443",
        ))));
        let old = {
            let config = state.read().await;
            Arc::clone(&config)
        };
        let same = {
            let config = state.read().await;
            Arc::clone(&config)
        };
        assert!(Arc::ptr_eq(&old, &same));

        *state.write().await = Arc::new(Zeroizing::new(test_config_state("new.example:443")));
        let current = {
            let config = state.read().await;
            Arc::clone(&config)
        };

        assert!(!Arc::ptr_eq(&old, &current));
        assert_eq!(
            old.routes.route_for("kid").final_app_addr(),
            "old.example:443"
        );
        assert_eq!(
            current.routes.route_for("kid").final_app_addr(),
            "new.example:443"
        );
    }

    #[tokio::test]
    async fn authenticated_request_keeps_permissions_and_routes_from_one_snapshot() {
        let kid = "a".repeat(64);
        let apikey_hash = "b".repeat(64);
        let inputs: Vec<crate::core::permissions::PermissionClientInput> =
            serde_json::from_value(json!([{
                "client": "snapshot-client",
                "apikey_hash": apikey_hash,
                "status": "active",
                "permissions": [{
                    "kid": kid,
                    "actions": ["sign"]
                }]
            }]))
            .unwrap();
        let permissions = crate::core::permissions::validate_permission_clients(inputs, |_| true)
            .expect("old permissions must be valid");
        let old = Arc::new(Zeroizing::new(test_config_state_with_permissions(
            "old.example:443",
            permissions,
        )));
        let client = old
            .permissions
            .authenticate_hash(&apikey_hash)
            .expect("configured client must authenticate");
        let request = AuthenticatedRequest {
            client: Zeroizing::new(client),
            config: Arc::clone(&old),
        };
        let state = RwLock::new(old);

        *state.write().await = Arc::new(Zeroizing::new(test_config_state("new.example:443")));
        let current = {
            let config = state.read().await;
            Arc::clone(&config)
        };

        assert!(request.require_permission(Some(&kid), "sign").is_ok());
        assert!(
            current
                .permissions
                .require_permission(request.client(), Some(&kid), "sign")
                .is_err()
        );
        assert_eq!(
            request.config().routes.route_for(&kid).final_app_addr(),
            "old.example:443"
        );
        assert_eq!(
            current.routes.route_for(&kid).final_app_addr(),
            "new.example:443"
        );
    }

    #[test]
    fn loaded_counts_are_derived_from_one_config() {
        let config = test_config_state("localhost:3999");
        let counts = ConfigLoadedCounts::from_config(&config);

        assert_eq!(counts.routes, config.routes.len());
        assert_eq!(counts.remote_routes, config.remote_routes.len());
        assert_eq!(counts.permission_clients, config.permissions.len());
        assert_eq!(counts.fpe_profiles, config.fpe_profiles.len());
        assert_eq!(
            counts.tokenization_profiles,
            config.tokenization_profiles.len()
        );
        assert_eq!(counts.mac_profiles, config.mac_profiles.len());
        assert_eq!(counts.masking_profiles, config.masking_profiles.len());
        assert_eq!(counts.commitment_profiles, config.commitment_profiles.len());
        assert_eq!(counts.sharing_profiles, config.sharing_profiles.len());
    }

    #[test]
    fn config_key_sources_are_indexed_by_kid_and_zeroized() {
        let kid = "a".repeat(64);
        let mut sources = ConfigKeySources::default();
        sources.by_kid.insert(
            kid.clone(),
            ConfigKeySource {
                symmetric_key_hex: "b".repeat(64),
                symmetric_algorithm: String::from("ChaCha20Poly1305"),
                hash_algorithm: String::from("BLAKE2b(256)"),
            },
        );

        let source = sources
            .by_kid
            .get(&kid)
            .expect("configured KID must resolve through the index");
        assert_eq!(source.symmetric_algorithm, "ChaCha20Poly1305");
        assert!(!sources.by_kid.contains_key(&"c".repeat(64)));

        sources.zeroize();
        assert!(sources.by_kid.is_empty());
    }

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
