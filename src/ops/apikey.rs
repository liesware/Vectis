use crate::core::{config, crypto, validation};
use crate::error::DynError;
use crate::ops::init::ValidatedInitState;
use zeroize::{Zeroize, Zeroizing};

pub struct ApiKeyCreateOutput {
    pub api_key: Zeroizing<String>,
    pub api_key_hash: Zeroizing<String>,
}

impl Zeroize for ApiKeyCreateOutput {
    fn zeroize(&mut self) {
        self.api_key.zeroize();
        self.api_key_hash.zeroize();
    }
}

pub fn create_api_key(init_state: &ValidatedInitState) -> Result<ApiKeyCreateOutput, DynError> {
    let api_key = Zeroizing::new(hex::encode(crypto::random_bytes(
        config::INTERNAL_KEYS_KEY_SIZE_BYTES,
    )?));
    validation::validate_hash_hex_field("VECTIS_APIKEY", &api_key, config::INTERNAL_KEYS_HASH)?;

    let api_key_hash = Zeroizing::new(crate::ops::internal_keys::api_key_hash_from_root_key_hex(
        init_state.symmetric_key_hex(),
        &api_key,
    )?);
    validation::validate_symmetric_key("VECTIS_APIKEY_HASH", &api_key_hash, 32)?;

    Ok(ApiKeyCreateOutput {
        api_key,
        api_key_hash,
    })
}
