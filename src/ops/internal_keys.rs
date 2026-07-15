use crate::core::{config, crypto, validation};
use crate::error::DynError;
use crate::ops::init::ValidatedInitState;
use zeroize::{Zeroize, Zeroizing};

const INTERNAL_HKDF_SALT: &[u8] = b"vectis/internal-keys/v1";
const DB_KEY_INFO: &[u8] = b"vectis/db-key/v1";
const PROPERTIES_KEY_INFO: &[u8] = b"vectis/properties-key/v1";
const API_AUTH_KEY_INFO: &[u8] = b"vectis/api-key-auth/v1";

pub struct InternalDerivedKeysState {
    db_key: Zeroizing<Vec<u8>>,
    properties_key: Zeroizing<Vec<u8>>,
    api_auth_key: Zeroizing<Vec<u8>>,
}

impl InternalDerivedKeysState {
    pub fn from_init_state(init_state: &ValidatedInitState) -> Result<Self, DynError> {
        validation::validate_symmetric_key(
            "init symmetric key",
            init_state.symmetric_key_hex(),
            config::INTERNAL_KEYS_KEY_SIZE_BYTES,
        )?;
        let root_key = Zeroizing::new(hex::decode(init_state.symmetric_key_hex())?);

        Ok(Self {
            db_key: derive_internal_key(&root_key, DB_KEY_INFO)?,
            properties_key: derive_internal_key(&root_key, PROPERTIES_KEY_INFO)?,
            api_auth_key: derive_internal_key(&root_key, API_AUTH_KEY_INFO)?,
        })
    }

    pub fn db_key(&self) -> &[u8] {
        &self.db_key
    }

    pub fn properties_key(&self) -> &[u8] {
        &self.properties_key
    }

    pub fn api_key_hash(&self, api_key: &str) -> Result<String, DynError> {
        api_key_hash_with_key(&self.api_auth_key, api_key)
    }
}

impl Zeroize for InternalDerivedKeysState {
    fn zeroize(&mut self) {
        self.db_key.zeroize();
        self.properties_key.zeroize();
        self.api_auth_key.zeroize();
    }
}

fn derive_internal_key(root_key: &[u8], info: &[u8]) -> Result<Zeroizing<Vec<u8>>, DynError> {
    Ok(Zeroizing::new(crypto::create_hkdf(
        root_key,
        INTERNAL_HKDF_SALT,
        info,
        config::INTERNAL_KEYS_KEY_SIZE_BYTES,
    )?))
}

pub fn api_key_hash_from_root_key_hex(
    root_key_hex: &str,
    api_key: &str,
) -> Result<String, DynError> {
    validation::validate_symmetric_key(
        "init symmetric key",
        root_key_hex,
        config::INTERNAL_KEYS_KEY_SIZE_BYTES,
    )?;
    let root_key = Zeroizing::new(hex::decode(root_key_hex)?);
    let api_auth_key = derive_internal_key(&root_key, API_AUTH_KEY_INFO)?;

    api_key_hash_with_key(&api_auth_key, api_key)
}

fn api_key_hash_with_key(api_auth_key: &[u8], api_key: &str) -> Result<String, DynError> {
    validation::validate_hash_hex_field("VECTIS_APIKEY", api_key, config::INTERNAL_KEYS_HASH)?;

    Ok(hex::encode(crypto::create_hmac(
        api_auth_key,
        api_key.as_bytes(),
    )?))
}
