use super::error::{ErrorResponse, public_error_message};
use crate::core::permissions::{AuthenticatedClient, PermissionsState};
use crate::core::{audit, config, crypto, validation};
use crate::error::DynError;
use crate::ops::internal_keys::InternalDerivedKeysState;
use axum::Json;
use axum::http::{HeaderMap, HeaderName, StatusCode};
use std::io;
use zeroize::Zeroizing;

const API_KEY_HEADER: HeaderName = HeaderName::from_static("x-api-key");

#[derive(Clone)]
pub struct HttpAuthState {
    root_api_key_hash_hex: Option<String>,
    root_api_key_hash_bytes: Option<Zeroizing<Vec<u8>>>,
}

impl HttpAuthState {
    pub fn from_config(config: &config::AppConfig) -> Result<Self, DynError> {
        if config.api_key_hash.is_empty() {
            return Ok(Self {
                root_api_key_hash_hex: None,
                root_api_key_hash_bytes: None,
            });
        }

        let root_api_key_hash_bytes = hex::decode(&config.api_key_hash).map_err(|err| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("VECTIS_APIKEY_HASH could not be decoded: {err}"),
            )) as DynError
        })?;

        Ok(Self {
            root_api_key_hash_hex: Some(config.api_key_hash.clone()),
            root_api_key_hash_bytes: Some(Zeroizing::new(root_api_key_hash_bytes)),
        })
    }

    fn root_api_key_hash_hex(&self) -> Option<&str> {
        self.root_api_key_hash_hex.as_deref()
    }

    fn root_api_key_hash_bytes(&self) -> Option<&[u8]> {
        self.root_api_key_hash_bytes.as_deref().map(Vec::as_slice)
    }
}

pub fn authorize_api_key(
    headers: &HeaderMap,
    config: &config::AppConfig,
    auth_state: &HttpAuthState,
    internal_keys: &InternalDerivedKeysState,
    permissions_state: &PermissionsState,
) -> Result<Zeroizing<AuthenticatedClient>, (StatusCode, Json<ErrorResponse>)> {
    let deny = |reason: &str| -> (StatusCode, Json<ErrorResponse>) {
        audit::auth_denied(reason);
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(public_error_message(
                StatusCode::UNAUTHORIZED,
            ))),
        )
    };

    let Some(value) = headers.get(API_KEY_HEADER) else {
        return Err(deny("missing api key"));
    };

    let Ok(value) = value.to_str() else {
        return Err(deny("malformed api key"));
    };

    if validation::validate_hash_hex_field("X-API-Key", value, config::INTERNAL_KEYS_HASH).is_err()
    {
        return Err(deny("malformed api key"));
    }

    let candidate_hash = internal_keys
        .api_key_hash(value)
        .map_err(|_| deny("authentication error"))?;
    let candidate_hash = hex::decode(candidate_hash).map_err(|_| deny("authentication error"))?;

    if let (Some(expected_hash), Some(root_hash_hex)) = (
        auth_state.root_api_key_hash_bytes(),
        auth_state.root_api_key_hash_hex(),
    ) {
        debug_assert_eq!(config.api_key_hash.as_str(), root_hash_hex);
        if crypto::constant_time_eq(&candidate_hash, expected_hash) {
            let client = AuthenticatedClient::root(root_hash_hex.to_string());
            audit::auth_success(&audit::Actor {
                name: client.client_name(),
                fingerprint: client.fingerprint(),
                root: client.is_root(),
                admin: client.is_admin(),
            });
            return Ok(Zeroizing::new(client));
        }
    }

    let candidate_hash_hex = hex::encode(candidate_hash);
    if let Some(client) = permissions_state.authenticate_hash(&candidate_hash_hex) {
        audit::auth_success(&audit::Actor {
            name: client.client_name(),
            fingerprint: client.fingerprint(),
            root: client.is_root(),
            admin: client.is_admin(),
        });
        return Ok(Zeroizing::new(client));
    }

    Err(deny("unknown api key"))
}
