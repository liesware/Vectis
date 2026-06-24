use crate::core::{config, crypto, storage, validation};
use crate::error::DynError;
use crate::ops::init::ValidatedInitState;
use crate::ops::key_material::{
    KeyMaterialKeys, KeyMaterialOutput, KeyMaterialSpec, create_key_material,
};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io;
use tracing::{error, info};
use zeroize::{Zeroize, Zeroizing};

pub(crate) type OpsKeysOutput = KeyMaterialOutput;
pub(crate) type OpsKeys = KeyMaterialKeys;

#[derive(Serialize)]
pub struct KeysDbState {
    keys_db: Vec<LoadedOpsKey>,
}

#[derive(Clone, Serialize)]
pub(crate) struct LoadedOpsKey {
    id: String,
    aad: String,
    key_material: OpsKeysOutput,
}

impl KeysDbState {
    pub fn len(&self) -> usize {
        self.keys_db.len()
    }

    pub(crate) fn get(&self, id: &str) -> Option<&LoadedOpsKey> {
        self.keys_db.iter().find(|loaded_key| loaded_key.id == id)
    }

    pub(crate) fn upsert(&mut self, loaded_key: LoadedOpsKey) {
        if let Some(index) = self
            .keys_db
            .iter()
            .position(|existing_key| existing_key.id == loaded_key.id)
        {
            let mut existing_key = self.keys_db.remove(index);
            existing_key.zeroize();
        }

        self.keys_db.push(loaded_key);
    }
}

impl LoadedOpsKey {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn aad(&self) -> &str {
        &self.aad
    }

    pub(crate) fn keys(&self) -> &OpsKeys {
        self.key_material.keys()
    }

    pub(crate) fn key_material(&self) -> &OpsKeysOutput {
        &self.key_material
    }
}

pub(crate) struct KeyId(String);

impl KeyId {
    pub(crate) fn parse(value: &str) -> Result<Self, DynError> {
        validation::validate_hash_hex_field("id", value, config::INTERNAL_KEYS_HASH)?;

        Ok(Self(value.to_string()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn get_loaded_key<'a>(
    keys_db_state: &'a KeysDbState,
    id: &str,
) -> Result<&'a LoadedOpsKey, DynError> {
    let id = KeyId::parse(id)?;

    keys_db_state.get(id.as_str()).ok_or_else(|| {
        Box::new(io::Error::new(
            io::ErrorKind::NotFound,
            format!("ops key not loaded in state: {}", id.as_str()),
        )) as DynError
    })
}

pub fn list_keys_from_state(keys_db_state: &KeysDbState) -> ListKeysOutput {
    let keys = keys_db_state
        .keys_db
        .iter()
        .map(|loaded_key| ListKeysItem {
            kid: loaded_key.id().to_string(),
            info: loaded_key.aad().to_string(),
        })
        .collect();

    ListKeysOutput { keys }
}

impl Zeroize for KeysDbState {
    fn zeroize(&mut self) {
        self.keys_db.zeroize();
    }
}

impl Zeroize for LoadedOpsKey {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.aad.zeroize();
        self.key_material.zeroize();
    }
}

#[derive(Serialize)]
pub struct CreateKeysOutput {
    pub id: String,
}

#[derive(Serialize)]
pub struct ListKeysOutput {
    keys: Vec<ListKeysItem>,
}

#[derive(Serialize)]
struct ListKeysItem {
    kid: String,
    info: String,
}

#[derive(Deserialize)]
pub struct CreateKeysInput {
    pub tag: Option<String>,
    pub hash_algorithm: Option<String>,
    pub symmetric_algorithm: Option<String>,
    pub eddsa_algorithm: Option<String>,
    pub xecdh_algorithm: Option<String>,
    pub ml_dsa_variant: Option<String>,
    pub ml_kem_variant: Option<String>,
}

struct ResolvedKeysInput {
    tag: String,
    timestamp: String,
    hash_algorithm: String,
    symmetric_algorithm: String,
    eddsa_algorithm: String,
    xecdh_algorithm: String,
    ml_dsa_variant: String,
    ml_kem_variant: String,
}

pub async fn create_keys(
    init_state: &ValidatedInitState,
    input: CreateKeysInput,
) -> Result<CreateKeysOutput, DynError> {
    let config = config::app_config()?;
    let input = resolve_keys_input(input, &config)?;
    let keys = Zeroizing::new(create_stored_key_material(&input)?);
    let plaintext = Zeroizing::new(serde_json::to_string_pretty(&*keys)?);
    let key = Zeroizing::new(hex::decode(init_state.symmetric_key_hex())?);
    validation::validate_symmetric_key(
        "init symmetric key",
        init_state.symmetric_key_hex(),
        config::INTERNAL_KEYS_KEY_SIZE_BYTES,
    )?;

    let nonce = Zeroizing::new(crypto::random_bytes(
        config::INTERNAL_KEYS_NONCE_SIZE_BYTES,
    )?);
    let aad = validation::build_aad(&[
        ("version", &config.protocol_version),
        ("hostname", &config.sender_hostname),
        ("type", "ops-keys"),
        ("cipher", config::INTERNAL_KEYS_CIPHER),
        ("tag", &input.tag),
        ("timestamp", &input.timestamp),
    ]);
    let ciphertext = crypto::encrypt_symmetric(
        config::INTERNAL_KEYS_CIPHER,
        &plaintext,
        &key,
        &nonce,
        aad.as_bytes(),
    )?;
    let keys_b64 = general_purpose::STANDARD.encode(ciphertext);
    let nonce_b64 = general_purpose::STANDARD.encode(&*nonce);
    let aad_b64 = general_purpose::STANDARD.encode(aad.as_bytes());
    let id = create_key_id(&keys_b64)?;
    let enc_keys = format!("{keys_b64}.{nonce_b64}.{aad_b64}");

    storage::save_ops_keys(&id, &enc_keys).await?;

    Ok(CreateKeysOutput { id })
}

fn create_key_id(keys_b64: &str) -> Result<String, DynError> {
    validation::validate_allowed_value(
        "INTERNAL_KEYS_HASH",
        config::INTERNAL_KEYS_HASH,
        crypto::HASH_ALGORITHMS,
    )?;

    Ok(hex::encode(crypto::hash_text(
        config::INTERNAL_KEYS_HASH,
        keys_b64,
    )?))
}

pub fn parse_create_keys_input(request: Value) -> Result<CreateKeysInput, DynError> {
    let Some(object) = request.as_object() else {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "request body must be a JSON object",
        )));
    };

    if let Some(tag) = object.get("tag")
        && !tag.is_string()
    {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tag must be a string",
        )));
    }

    serde_json::from_value(request).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid keys request: {err}"),
        )) as DynError
    })
}

pub async fn load_keys_db_state(
    init_state: &ValidatedInitState,
) -> Result<Zeroizing<KeysDbState>, DynError> {
    let rows = storage::list_ops_keys().await?;
    let mut keys_db = Vec::new();

    for row in rows {
        match decrypt_ops_keys_payload(init_state, &row.enc_keys) {
            Ok(decrypted) => {
                info!(id = %row.id, "decrypted ops key loaded from db");
                keys_db.push(LoadedOpsKey {
                    id: row.id,
                    aad: decrypted.aad,
                    key_material: decrypted.output,
                });
            }
            Err(err) => {
                error!(id = %row.id, error = %err, "failed to decrypt ops key from db");
            }
        }
    }

    Ok(Zeroizing::new(KeysDbState { keys_db }))
}

pub async fn load_keys_db_entry(
    init_state: &ValidatedInitState,
    id: &str,
) -> Result<LoadedOpsKey, DynError> {
    let id = KeyId::parse(id)?;

    let row = storage::get_ops_keys(id.as_str()).await?;
    let decrypted = decrypt_ops_keys_payload(init_state, &row.enc_keys)?;
    info!(id = %row.id, "decrypted ops key loaded from db");

    Ok(LoadedOpsKey {
        id: row.id,
        aad: decrypted.aad,
        key_material: decrypted.output,
    })
}

struct DecryptedOpsKeys {
    aad: String,
    output: OpsKeysOutput,
}

fn decrypt_ops_keys_payload(
    init_state: &ValidatedInitState,
    enc_keys: &str,
) -> Result<DecryptedOpsKeys, DynError> {
    let parts = enc_keys.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "enc_keys must have keys.nonce.aad base64 sections",
        )));
    }

    let ciphertext = general_purpose::STANDARD.decode(parts[0])?;
    let nonce = Zeroizing::new(general_purpose::STANDARD.decode(parts[1])?);
    let aad = general_purpose::STANDARD.decode(parts[2])?;
    let aad_text = String::from_utf8(aad.clone())?;
    validation::validate_encrypted_payload(
        "enc_keys ciphertext",
        &hex::encode(&ciphertext),
        "enc_keys nonce",
        &hex::encode(&*nonce),
        "enc_keys aad",
        &aad_text,
        config::INTERNAL_KEYS_NONCE_SIZE_BYTES,
    )?;
    validation::validate_symmetric_key(
        "init symmetric key",
        init_state.symmetric_key_hex(),
        config::INTERNAL_KEYS_KEY_SIZE_BYTES,
    )?;

    let key = Zeroizing::new(hex::decode(init_state.symmetric_key_hex())?);
    let plaintext_bytes = Zeroizing::new(crypto::decrypt_symmetric(
        config::INTERNAL_KEYS_CIPHER,
        &ciphertext,
        &key,
        &nonce,
        &aad,
    )?);
    let plaintext = Zeroizing::new(String::from_utf8((*plaintext_bytes).clone())?);
    let output = serde_json::from_str(&plaintext)?;

    Ok(DecryptedOpsKeys {
        aad: aad_text,
        output,
    })
}

fn resolve_keys_input(
    input: CreateKeysInput,
    config: &config::AppConfig,
) -> Result<ResolvedKeysInput, DynError> {
    let timestamp = validation::current_timestamp()?;
    let tag = input.tag.unwrap_or_else(|| timestamp.clone());
    validation::validate_text_field("tag", &tag)?;

    let hash_algorithm = input
        .hash_algorithm
        .unwrap_or_else(|| config.hash_algorithm.clone());
    validation::validate_allowed_value("hash_algorithm", &hash_algorithm, crypto::HASH_ALGORITHMS)?;

    let symmetric_algorithm = input
        .symmetric_algorithm
        .unwrap_or_else(|| config.symmetric_algorithm.clone());
    validation::validate_allowed_value(
        "symmetric_algorithm",
        &symmetric_algorithm,
        crypto::SYMMETRIC_ALGORITHMS,
    )?;

    let eddsa_algorithm = input
        .eddsa_algorithm
        .unwrap_or_else(|| config.eddsa_algorithm.clone());
    validation::validate_allowed_value("eddsa_algorithm", &eddsa_algorithm, &["Ed25519", "Ed448"])?;

    let xecdh_algorithm = input
        .xecdh_algorithm
        .unwrap_or_else(|| config.xecdh_algorithm.clone());
    validation::validate_allowed_value("xecdh_algorithm", &xecdh_algorithm, &["X25519", "X448"])?;

    let ml_dsa_variant = input
        .ml_dsa_variant
        .unwrap_or_else(|| config.ml_dsa_variant.clone());
    validation::validate_allowed_value(
        "ml_dsa_variant",
        &ml_dsa_variant,
        &["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
    )?;

    let ml_kem_variant = input
        .ml_kem_variant
        .unwrap_or_else(|| config.ml_kem_variant.clone());
    validation::validate_allowed_value(
        "ml_kem_variant",
        &ml_kem_variant,
        &["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
    )?;

    Ok(ResolvedKeysInput {
        tag,
        timestamp,
        hash_algorithm,
        symmetric_algorithm,
        eddsa_algorithm,
        xecdh_algorithm,
        ml_dsa_variant,
        ml_kem_variant,
    })
}

fn create_stored_key_material(input: &ResolvedKeysInput) -> Result<OpsKeysOutput, DynError> {
    let spec = KeyMaterialSpec {
        hash_algorithm: input.hash_algorithm.clone(),
        symmetric_algorithm: input.symmetric_algorithm.clone(),
        eddsa_algorithm: input.eddsa_algorithm.clone(),
        xecdh_algorithm: input.xecdh_algorithm.clone(),
        ml_dsa_variant: input.ml_dsa_variant.clone(),
        ml_kem_variant: input.ml_kem_variant.clone(),
    };

    create_key_material(&spec)
}
