use crate::core::{config, crypto, storage::StorageState, validation};
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
const PROPERTY_PROFILES: &[&str] = &[
    "hybrid-performance-v1",
    "hybrid-high-assurance-v1",
    "hybrid-long-term-v1",
    "custom",
];
const LIFECYCLE_STATUSES: &[&str] = &["active", "disabled", "retired", "compromised", "destroyed"];

#[derive(Serialize)]
pub struct KeysDbState {
    keys_db: Vec<LoadedOpsKey>,
}

#[derive(Clone, Serialize)]
pub(crate) struct LoadedOpsKey {
    id: String,
    aad: String,
    properties_aad: String,
    key_material: OpsKeysOutput,
    properties: OpsKeyProperties,
}

impl KeysDbState {
    pub fn len(&self) -> usize {
        self.keys_db.len()
    }

    pub(crate) fn get(&self, id: &str) -> Option<&LoadedOpsKey> {
        self.keys_db.iter().find(|loaded_key| loaded_key.id == id)
    }

    pub fn contains_id(&self, id: &str) -> bool {
        self.keys_db.iter().any(|loaded_key| loaded_key.id == id)
    }

    pub fn ids(&self) -> Vec<String> {
        self.keys_db
            .iter()
            .map(|loaded_key| loaded_key.id.clone())
            .collect()
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

    pub(crate) fn properties(&self) -> &OpsKeyProperties {
        &self.properties
    }

    pub(crate) fn lifecycle_status(&self) -> &str {
        self.properties.lifecycle.status()
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

pub fn validate_key_id(id: &str) -> Result<(), DynError> {
    KeyId::parse(id)?;

    Ok(())
}

pub(crate) fn require_lifecycle_for_new_use(loaded_key: &LoadedOpsKey) -> Result<(), DynError> {
    match loaded_key.lifecycle_status() {
        "active" => Ok(()),
        "retired" => {
            lifecycle_error("key is retired and can only be used for decrypt or verification")
        }
        status => blocked_lifecycle_error(status),
    }
}

pub(crate) fn require_lifecycle_for_decrypt_or_verify(
    loaded_key: &LoadedOpsKey,
) -> Result<(), DynError> {
    match loaded_key.lifecycle_status() {
        "active" | "retired" => Ok(()),
        status => blocked_lifecycle_error(status),
    }
}

pub(crate) fn require_lifecycle_for_public_keys(loaded_key: &LoadedOpsKey) -> Result<(), DynError> {
    match loaded_key.lifecycle_status() {
        "active" => Ok(()),
        "retired" => {
            lifecycle_error("key is retired and can only be used for decrypt or verification")
        }
        status => blocked_lifecycle_error(status),
    }
}

fn blocked_lifecycle_error(status: &str) -> Result<(), DynError> {
    match status {
        "disabled" => lifecycle_error("key is currently disabled"),
        "compromised" => {
            lifecycle_error("key is compromised and cannot be used for security reasons")
        }
        "destroyed" => lifecycle_error("key is logically destroyed and cannot be used"),
        _ => lifecycle_error("key lifecycle status does not allow this operation"),
    }
}

fn lifecycle_error(message: &str) -> Result<(), DynError> {
    Err(Box::new(io::Error::new(
        io::ErrorKind::PermissionDenied,
        message,
    )))
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

pub fn list_keys_properties_from_state(keys_db_state: &KeysDbState) -> ListKeysPropertiesOutput {
    let keys = keys_db_state
        .keys_db
        .iter()
        .map(|loaded_key| ListKeysPropertiesItem {
            kid: loaded_key.id().to_string(),
            info: loaded_key.aad().to_string(),
            properties_info: loaded_key.properties_aad.clone(),
            properties: loaded_key.properties().clone(),
        })
        .collect();

    ListKeysPropertiesOutput { keys }
}

fn key_properties_output(loaded_key: &LoadedOpsKey) -> KeyPropertiesOutput {
    KeyPropertiesOutput {
        kid: loaded_key.id().to_string(),
        info: loaded_key.aad().to_string(),
        properties_info: loaded_key.properties_aad.clone(),
        properties: loaded_key.properties().clone(),
    }
}

pub fn key_properties_from_state(
    keys_db_state: &KeysDbState,
    id: &str,
) -> Result<KeyPropertiesOutput, DynError> {
    let id = KeyId::parse(id)?;
    let loaded_key = get_loaded_key(keys_db_state, id.as_str())?;

    Ok(key_properties_output(loaded_key))
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
        self.properties_aad.zeroize();
        self.key_material.zeroize();
        self.properties.zeroize();
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

#[derive(Serialize)]
pub struct ListKeysPropertiesOutput {
    keys: Vec<ListKeysPropertiesItem>,
}

#[derive(Serialize)]
struct ListKeysPropertiesItem {
    kid: String,
    info: String,
    properties_info: String,
    properties: OpsKeyProperties,
}

#[derive(Serialize)]
pub struct KeyPropertiesOutput {
    kid: String,
    info: String,
    properties_info: String,
    properties: OpsKeyProperties,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct OpsKeyProperties {
    version: u8,
    profile: String,
    tag: String,
    created_at: String,
    lifecycle: OpsKeyLifecycle,
    access: Option<Value>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct OpsKeyLifecycle {
    status: String,
    reason: String,
    changed_at: String,
}

impl OpsKeyLifecycle {
    pub fn status(&self) -> &str {
        &self.status
    }
}

#[derive(Deserialize)]
pub struct UpdateLifecycleInput {
    status: String,
    reason: String,
}

impl UpdateLifecycleInput {
    pub fn status(&self) -> &str {
        &self.status
    }
}

#[derive(Serialize)]
pub struct UpdateLifecycleOutput {
    kid: String,
    lifecycle: OpsKeyLifecycle,
}

impl Zeroize for OpsKeyProperties {
    fn zeroize(&mut self) {
        self.version.zeroize();
        self.profile.zeroize();
        self.tag.zeroize();
        self.created_at.zeroize();
        self.lifecycle.zeroize();
        self.access = None;
    }
}

impl Zeroize for OpsKeyLifecycle {
    fn zeroize(&mut self) {
        self.status.zeroize();
        self.reason.zeroize();
        self.changed_at.zeroize();
    }
}

#[derive(Deserialize)]
pub struct CreateKeysInput {
    pub tag: Option<String>,
    pub profile: Option<String>,
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
    profile: String,
    properties_profile: String,
    hash_algorithm: String,
    symmetric_algorithm: String,
    eddsa_algorithm: String,
    xecdh_algorithm: String,
    ml_dsa_variant: String,
    ml_kem_variant: String,
}

struct CryptoProfile {
    name: &'static str,
    hash_algorithm: &'static str,
    symmetric_algorithm: &'static str,
    eddsa_algorithm: &'static str,
    xecdh_algorithm: &'static str,
    ml_dsa_variant: &'static str,
    ml_kem_variant: &'static str,
}

pub async fn create_keys(
    storage: &StorageState,
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
        ("profile", &input.profile),
        ("timestamp", &input.timestamp),
    ]);
    let keys_b64 = encrypt_internal_payload(&plaintext, &key, &nonce, &aad)?;
    let nonce_b64 = general_purpose::STANDARD.encode(&*nonce);
    let aad_b64 = general_purpose::STANDARD.encode(aad.as_bytes());
    let id = create_key_id(&keys_b64)?;
    let enc_keys = format!("{keys_b64}.{nonce_b64}.{aad_b64}");

    let properties = Zeroizing::new(create_ops_key_properties(&input));
    let properties_plaintext = Zeroizing::new(serde_json::to_string_pretty(&*properties)?);
    let properties_nonce = Zeroizing::new(crypto::random_bytes(
        config::INTERNAL_KEYS_NONCE_SIZE_BYTES,
    )?);
    let properties_aad = validation::build_aad(&[
        ("version", &config.protocol_version),
        ("hostname", &config.sender_hostname),
        ("type", "ops-key-properties"),
        ("cipher", config::INTERNAL_KEYS_CIPHER),
        ("kid", &id),
        ("tag", &input.tag),
        ("profile", &input.properties_profile),
        ("timestamp", &input.timestamp),
    ]);
    let properties_b64 = encrypt_internal_payload(
        &properties_plaintext,
        &key,
        &properties_nonce,
        &properties_aad,
    )?;
    let properties_nonce_b64 = general_purpose::STANDARD.encode(&*properties_nonce);
    let properties_aad_b64 = general_purpose::STANDARD.encode(properties_aad.as_bytes());
    let properties = format!("{properties_b64}.{properties_nonce_b64}.{properties_aad_b64}");

    storage.save_ops_keys(&id, &enc_keys, &properties).await?;

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

fn validate_key_id_matches_enc_keys(id: &str, enc_keys: &str) -> Result<(), DynError> {
    KeyId::parse(id)?;
    let parts = split_internal_payload("enc_keys", enc_keys)?;
    let expected_id = create_key_id(parts[0])?;

    if id != expected_id {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "id does not match INTERNAL_KEYS_HASH(enc_keys payload)",
        )));
    }

    Ok(())
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
    if let Some(profile) = object.get("profile")
        && !profile.is_string()
    {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "profile must be a string",
        )));
    }

    serde_json::from_value(request).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid keys request: {err}"),
        )) as DynError
    })
}

pub fn parse_update_lifecycle_input(request: Value) -> Result<UpdateLifecycleInput, DynError> {
    let Some(object) = request.as_object() else {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "request body must be a JSON object",
        )));
    };

    validate_json_string_field(object, "status")?;
    validate_json_string_field(object, "reason")?;

    let input: UpdateLifecycleInput = serde_json::from_value(request).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid lifecycle request: {err}"),
        )) as DynError
    })?;
    validate_lifecycle_status("status", &input.status)?;
    validation::validate_text_field("reason", &input.reason)?;

    Ok(input)
}

pub async fn load_keys_db_state(
    storage: &StorageState,
    init_state: &ValidatedInitState,
) -> Result<Zeroizing<KeysDbState>, DynError> {
    let rows = storage.list_ops_keys().await?;
    let mut keys_db = Vec::new();

    for row in rows {
        let id = row.id.clone();
        match load_ops_key_from_row(init_state, row) {
            Ok(loaded_key) => {
                info!(id = %loaded_key.id, "decrypted ops key loaded from db");
                keys_db.push(loaded_key);
            }
            Err(err) => {
                error!(id = %id, error = %err, "failed to decrypt ops key from db");
            }
        }
    }

    Ok(Zeroizing::new(KeysDbState { keys_db }))
}

pub async fn load_keys_db_entry(
    storage: &StorageState,
    init_state: &ValidatedInitState,
    id: &str,
) -> Result<LoadedOpsKey, DynError> {
    let id = KeyId::parse(id)?;

    let row = storage.get_ops_keys(id.as_str()).await?;
    let loaded_key = load_ops_key_from_row(init_state, row)?;
    info!(id = %loaded_key.id, "decrypted ops key loaded from db");

    Ok(loaded_key)
}

pub async fn update_key_lifecycle(
    storage: &StorageState,
    init_state: &ValidatedInitState,
    id: &str,
    input: UpdateLifecycleInput,
) -> Result<UpdateLifecycleOutput, DynError> {
    let id = KeyId::parse(id)?;
    let row = storage.get_ops_keys(id.as_str()).await?;
    validate_key_id_matches_enc_keys(&row.id, &row.enc_keys)?;

    let decrypted = decrypt_ops_keys_payload(init_state, &row.enc_keys)?;
    let mut properties = decrypt_ops_key_properties_payload(init_state, &row.properties)?;
    validate_ops_key_properties(&properties.output)?;
    validate_loaded_ops_key_binding(&row.id, &decrypted, &properties)?;

    validate_lifecycle_transition(&properties.output.lifecycle.status, &input.status)?;
    let changed_at = validation::current_timestamp()?;
    properties.output.lifecycle = OpsKeyLifecycle {
        status: input.status,
        reason: input.reason,
        changed_at,
    };
    validate_ops_key_properties(&properties.output)?;

    let encrypted_properties =
        encrypt_ops_key_properties_payload(init_state, &properties.output, &properties.aad)?;
    storage
        .update_ops_key_properties(id.as_str(), &encrypted_properties)
        .await?;

    Ok(UpdateLifecycleOutput {
        kid: id.as_str().to_string(),
        lifecycle: properties.output.lifecycle,
    })
}

fn load_ops_key_from_row(
    init_state: &ValidatedInitState,
    row: crate::core::storage::OpsKeyRow,
) -> Result<LoadedOpsKey, DynError> {
    validate_key_id_matches_enc_keys(&row.id, &row.enc_keys)?;
    let decrypted = decrypt_ops_keys_payload(init_state, &row.enc_keys)?;
    let properties = decrypt_ops_key_properties_payload(init_state, &row.properties)?;
    validate_ops_key_properties(&properties.output)?;
    validate_loaded_ops_key_binding(&row.id, &decrypted, &properties)?;

    Ok(LoadedOpsKey {
        id: row.id,
        aad: decrypted.aad,
        properties_aad: properties.aad,
        key_material: decrypted.output,
        properties: properties.output,
    })
}

struct DecryptedOpsKeys {
    aad: String,
    output: OpsKeysOutput,
}

struct DecryptedOpsKeyProperties {
    aad: String,
    output: OpsKeyProperties,
}

fn encrypt_internal_payload(
    plaintext: &str,
    key: &[u8],
    nonce: &[u8],
    aad: &str,
) -> Result<String, DynError> {
    let ciphertext = crypto::encrypt_symmetric(
        config::INTERNAL_KEYS_CIPHER,
        plaintext,
        key,
        nonce,
        aad.as_bytes(),
    )?;

    Ok(general_purpose::STANDARD.encode(ciphertext))
}

fn encrypt_ops_key_properties_payload(
    init_state: &ValidatedInitState,
    properties: &OpsKeyProperties,
    aad: &str,
) -> Result<String, DynError> {
    validation::validate_symmetric_key(
        "init symmetric key",
        init_state.symmetric_key_hex(),
        config::INTERNAL_KEYS_KEY_SIZE_BYTES,
    )?;
    let key = Zeroizing::new(hex::decode(init_state.symmetric_key_hex())?);
    let plaintext = Zeroizing::new(serde_json::to_string_pretty(properties)?);
    let nonce = Zeroizing::new(crypto::random_bytes(
        config::INTERNAL_KEYS_NONCE_SIZE_BYTES,
    )?);
    let properties_b64 = encrypt_internal_payload(&plaintext, &key, &nonce, aad)?;
    let nonce_b64 = general_purpose::STANDARD.encode(&*nonce);
    let aad_b64 = general_purpose::STANDARD.encode(aad.as_bytes());

    Ok(format!("{properties_b64}.{nonce_b64}.{aad_b64}"))
}

fn decrypt_ops_keys_payload(
    init_state: &ValidatedInitState,
    enc_keys: &str,
) -> Result<DecryptedOpsKeys, DynError> {
    let parts = split_internal_payload("enc_keys", enc_keys)?;

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

fn decrypt_ops_key_properties_payload(
    init_state: &ValidatedInitState,
    properties: &str,
) -> Result<DecryptedOpsKeyProperties, DynError> {
    let parts = split_internal_payload("properties", properties)?;

    let ciphertext = general_purpose::STANDARD.decode(parts[0])?;
    let nonce = Zeroizing::new(general_purpose::STANDARD.decode(parts[1])?);
    let aad = general_purpose::STANDARD.decode(parts[2])?;
    let aad_text = String::from_utf8(aad.clone())?;
    validation::validate_encrypted_payload(
        "properties ciphertext",
        &hex::encode(&ciphertext),
        "properties nonce",
        &hex::encode(&*nonce),
        "properties aad",
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

    Ok(DecryptedOpsKeyProperties {
        aad: aad_text,
        output,
    })
}

fn split_internal_payload<'a>(field: &str, value: &'a str) -> Result<Vec<&'a str>, DynError> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} must have ciphertext.nonce.aad base64 sections"),
        )));
    }

    Ok(parts)
}

fn validate_loaded_ops_key_binding(
    id: &str,
    keys: &DecryptedOpsKeys,
    properties: &DecryptedOpsKeyProperties,
) -> Result<(), DynError> {
    let keys_aad = parse_aad_fields(&keys.aad)?;
    let properties_aad = parse_aad_fields(&properties.aad)?;

    validate_aad_field(
        "enc_keys.aad.type",
        aad_field(&keys_aad, "type")?,
        "ops-keys",
    )?;
    validate_aad_field(
        "enc_keys.aad.cipher",
        aad_field(&keys_aad, "cipher")?,
        config::INTERNAL_KEYS_CIPHER,
    )?;
    validate_aad_field(
        "properties.aad.type",
        aad_field(&properties_aad, "type")?,
        "ops-key-properties",
    )?;
    validate_aad_field(
        "properties.aad.cipher",
        aad_field(&properties_aad, "cipher")?,
        config::INTERNAL_KEYS_CIPHER,
    )?;
    validate_aad_field("properties.aad.kid", aad_field(&properties_aad, "kid")?, id)?;

    validate_aad_field(
        "properties.aad.tag",
        aad_field(&properties_aad, "tag")?,
        &properties.output.tag,
    )?;
    validate_aad_field(
        "properties.aad.profile",
        aad_field(&properties_aad, "profile")?,
        &properties.output.profile,
    )?;
    validate_aad_field(
        "properties.aad.timestamp",
        aad_field(&properties_aad, "timestamp")?,
        &properties.output.created_at,
    )?;

    validate_aad_field(
        "enc_keys.aad.tag",
        aad_field(&keys_aad, "tag")?,
        aad_field(&properties_aad, "tag")?,
    )?;
    validate_aad_field(
        "enc_keys.aad.timestamp",
        aad_field(&keys_aad, "timestamp")?,
        aad_field(&properties_aad, "timestamp")?,
    )?;
    validate_aad_field(
        "enc_keys.aad.version",
        aad_field(&keys_aad, "version")?,
        aad_field(&properties_aad, "version")?,
    )?;
    validate_aad_field(
        "enc_keys.aad.hostname",
        aad_field(&keys_aad, "hostname")?,
        aad_field(&properties_aad, "hostname")?,
    )?;

    Ok(())
}

fn parse_aad_fields(aad: &str) -> Result<Vec<(String, String)>, DynError> {
    validation::validate_text_field("aad", aad)?;
    let mut fields = Vec::new();

    for part in aad.split(';') {
        let Some((key, value)) = part.split_once('=') else {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "aad must contain key=value fields",
            )));
        };

        validation::validate_text_field("aad key", key)?;
        validation::validate_text_field("aad value", value)?;
        fields.push((key.to_string(), value.to_string()));
    }

    Ok(fields)
}

fn aad_field<'a>(fields: &'a [(String, String)], key: &str) -> Result<&'a str, DynError> {
    fields
        .iter()
        .find(|(field_key, _)| field_key == key)
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("aad missing {key}"),
            )) as DynError
        })
}

fn validate_aad_field(field: &str, actual: &str, expected: &str) -> Result<(), DynError> {
    if actual != expected {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} does not match expected value"),
        )));
    }

    Ok(())
}

fn create_ops_key_properties(input: &ResolvedKeysInput) -> OpsKeyProperties {
    OpsKeyProperties {
        version: 1,
        profile: input.properties_profile.clone(),
        tag: input.tag.clone(),
        created_at: input.timestamp.clone(),
        lifecycle: OpsKeyLifecycle {
            status: String::from("active"),
            reason: String::from("initial creation"),
            changed_at: input.timestamp.clone(),
        },
        access: None,
    }
}

fn validate_ops_key_properties(properties: &OpsKeyProperties) -> Result<(), DynError> {
    validation::validate_allowed_value(
        "properties.profile",
        &properties.profile,
        PROPERTY_PROFILES,
    )?;
    validation::validate_text_field("properties.tag", &properties.tag)?;
    validation::validate_text_field("properties.created_at", &properties.created_at)?;
    validate_lifecycle_status("properties.lifecycle.status", &properties.lifecycle.status)?;
    validation::validate_text_field("properties.lifecycle.reason", &properties.lifecycle.reason)?;
    validation::validate_text_field(
        "properties.lifecycle.changed_at",
        &properties.lifecycle.changed_at,
    )?;

    Ok(())
}

fn validate_lifecycle_status(field: &str, status: &str) -> Result<(), DynError> {
    validation::validate_allowed_value(field, status, LIFECYCLE_STATUSES)
}

fn validate_lifecycle_transition(current: &str, next: &str) -> Result<(), DynError> {
    let allowed = match current {
        "active" => matches!(next, "disabled" | "retired" | "compromised" | "destroyed"),
        "disabled" => next == "active",
        "retired" | "compromised" | "destroyed" => false,
        _ => false,
    };

    if allowed {
        return Ok(());
    }

    Err(Box::new(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid lifecycle transition: {current} -> {next}"),
    )))
}

fn validate_json_string_field(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), DynError> {
    match object.get(field) {
        Some(value) if value.is_string() => Ok(()),
        Some(_) => Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} must be a string"),
        ))),
        None => Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} is required"),
        ))),
    }
}

fn resolve_keys_input(
    input: CreateKeysInput,
    config: &config::AppConfig,
) -> Result<ResolvedKeysInput, DynError> {
    let timestamp = validation::current_timestamp()?;
    let tag = input.tag.clone().unwrap_or_else(|| timestamp.clone());
    validation::validate_text_field("tag", &tag)?;

    let profile_name = input
        .profile
        .clone()
        .unwrap_or_else(|| config.default_crypto_profile.clone());
    validation::validate_allowed_value("profile", &profile_name, config::CRYPTO_PROFILES)?;
    let profile = crypto_profile(&profile_name)?;
    validate_crypto_policy(config, &input)?;
    let has_overrides = input.hash_algorithm.is_some()
        || input.symmetric_algorithm.is_some()
        || input.eddsa_algorithm.is_some()
        || input.xecdh_algorithm.is_some()
        || input.ml_dsa_variant.is_some()
        || input.ml_kem_variant.is_some();

    let hash_algorithm = if config.crypto_policy == "allow-overrides" {
        input
            .hash_algorithm
            .unwrap_or_else(|| profile.hash_algorithm.to_string())
    } else {
        profile.hash_algorithm.to_string()
    };
    validation::validate_allowed_value("hash_algorithm", &hash_algorithm, crypto::HASH_ALGORITHMS)?;

    let symmetric_algorithm = if config.crypto_policy == "allow-overrides" {
        input
            .symmetric_algorithm
            .unwrap_or_else(|| profile.symmetric_algorithm.to_string())
    } else {
        profile.symmetric_algorithm.to_string()
    };
    validation::validate_allowed_value(
        "symmetric_algorithm",
        &symmetric_algorithm,
        crypto::SYMMETRIC_ALGORITHMS,
    )?;

    let eddsa_algorithm = if config.crypto_policy == "allow-overrides" {
        input
            .eddsa_algorithm
            .unwrap_or_else(|| profile.eddsa_algorithm.to_string())
    } else {
        profile.eddsa_algorithm.to_string()
    };
    validation::validate_allowed_value("eddsa_algorithm", &eddsa_algorithm, &["Ed25519", "Ed448"])?;

    let xecdh_algorithm = if config.crypto_policy == "allow-overrides" {
        input
            .xecdh_algorithm
            .unwrap_or_else(|| profile.xecdh_algorithm.to_string())
    } else {
        profile.xecdh_algorithm.to_string()
    };
    validation::validate_allowed_value("xecdh_algorithm", &xecdh_algorithm, &["X25519", "X448"])?;

    let ml_dsa_variant = if config.crypto_policy == "allow-overrides" {
        input
            .ml_dsa_variant
            .unwrap_or_else(|| profile.ml_dsa_variant.to_string())
    } else {
        profile.ml_dsa_variant.to_string()
    };
    validation::validate_allowed_value(
        "ml_dsa_variant",
        &ml_dsa_variant,
        &["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
    )?;

    let ml_kem_variant = if config.crypto_policy == "allow-overrides" {
        input
            .ml_kem_variant
            .unwrap_or_else(|| profile.ml_kem_variant.to_string())
    } else {
        profile.ml_kem_variant.to_string()
    };
    validation::validate_allowed_value(
        "ml_kem_variant",
        &ml_kem_variant,
        &["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
    )?;

    let properties_profile = if config.crypto_policy == "allow-overrides" && has_overrides {
        String::from("custom")
    } else {
        profile.name.to_string()
    };
    validation::validate_allowed_value(
        "properties.profile",
        &properties_profile,
        PROPERTY_PROFILES,
    )?;

    Ok(ResolvedKeysInput {
        tag,
        timestamp,
        profile: profile.name.to_string(),
        properties_profile,
        hash_algorithm,
        symmetric_algorithm,
        eddsa_algorithm,
        xecdh_algorithm,
        ml_dsa_variant,
        ml_kem_variant,
    })
}

fn validate_crypto_policy(
    config: &config::AppConfig,
    input: &CreateKeysInput,
) -> Result<(), DynError> {
    validation::validate_allowed_value(
        "VECTIS_CRYPTO_POLICY",
        &config.crypto_policy,
        config::CRYPTO_POLICIES,
    )?;
    if config.crypto_policy != "profile-only" {
        return Ok(());
    }

    if input.hash_algorithm.is_some()
        || input.symmetric_algorithm.is_some()
        || input.eddsa_algorithm.is_some()
        || input.xecdh_algorithm.is_some()
        || input.ml_dsa_variant.is_some()
        || input.ml_kem_variant.is_some()
    {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "individual algorithm overrides are rejected when VECTIS_CRYPTO_POLICY=profile-only",
        )));
    }

    Ok(())
}

fn crypto_profile(name: &str) -> Result<CryptoProfile, DynError> {
    match name {
        "hybrid-performance-v1" => Ok(CryptoProfile {
            name: "hybrid-performance-v1",
            hash_algorithm: "BLAKE2b(256)",
            symmetric_algorithm: "ChaCha20Poly1305",
            eddsa_algorithm: "Ed25519",
            xecdh_algorithm: "X25519",
            ml_dsa_variant: "ML-DSA-44",
            ml_kem_variant: "ML-KEM-512",
        }),
        "hybrid-high-assurance-v1" => Ok(CryptoProfile {
            name: "hybrid-high-assurance-v1",
            hash_algorithm: "SHA-3(384)",
            symmetric_algorithm: "AES-256/GCM",
            eddsa_algorithm: "Ed25519",
            xecdh_algorithm: "X25519",
            ml_dsa_variant: "ML-DSA-65",
            ml_kem_variant: "ML-KEM-768",
        }),
        "hybrid-long-term-v1" => Ok(CryptoProfile {
            name: "hybrid-long-term-v1",
            hash_algorithm: "SHA-3(512)",
            symmetric_algorithm: "AES-256/GCM",
            eddsa_algorithm: "Ed448",
            xecdh_algorithm: "X448",
            ml_dsa_variant: "ML-DSA-87",
            ml_kem_variant: "ML-KEM-1024",
        }),
        _ => Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported crypto profile: {name}"),
        ))),
    }
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
