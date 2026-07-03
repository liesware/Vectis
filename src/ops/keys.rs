use crate::core::{config, crypto, storage::StorageState, validation};
use crate::error::DynError;
use crate::ops::internal_keys::InternalDerivedKeysState;
use crate::ops::key_material::{
    KeyMaterialKeys, KeyMaterialOutput, KeyMaterialSpec, create_key_material,
};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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

    pub fn is_empty(&self) -> bool {
        self.keys_db.is_empty()
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
    Err(crate::error::forbidden(message))
}

pub(crate) fn get_loaded_key<'a>(
    keys_db_state: &'a KeysDbState,
    id: &str,
) -> Result<&'a LoadedOpsKey, DynError> {
    let id = KeyId::parse(id)?;

    keys_db_state.get(id.as_str()).ok_or_else(|| {
        crate::error::not_found(format!("ops key not loaded in state: {}", id.as_str()))
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
#[serde(deny_unknown_fields)]
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
    internal_keys: &InternalDerivedKeysState,
    input: CreateKeysInput,
) -> Result<CreateKeysOutput, DynError> {
    let config = config::app_config()?;
    let input = resolve_keys_input(input, &config)?;
    let keys = Zeroizing::new(create_stored_key_material(&input)?);
    let plaintext = Zeroizing::new(serde_json::to_string_pretty(&*keys)?);

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
    let keys_b64 = encrypt_internal_payload(&plaintext, internal_keys.db_key(), &nonce, &aad)?;
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
        internal_keys.properties_key(),
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
        return Err(crate::error::invalid_input(
            "id does not match INTERNAL_KEYS_HASH(enc_keys payload)",
        ));
    }

    Ok(())
}

pub fn parse_create_keys_input(request: Value) -> Result<CreateKeysInput, DynError> {
    const ALLOWED_FIELDS: &[&str] = &[
        "tag",
        "profile",
        "hash_algorithm",
        "symmetric_algorithm",
        "eddsa_algorithm",
        "xecdh_algorithm",
        "ml_dsa_variant",
        "ml_kem_variant",
    ];

    let Some(object) = request.as_object() else {
        return Err(crate::error::invalid_input(
            "request body must be a JSON object",
        ));
    };

    for field in object.keys() {
        if !ALLOWED_FIELDS.contains(&field.as_str()) {
            return Err(crate::error::invalid_input(
                "request contains an unexpected field",
            ));
        }
    }

    for field in ALLOWED_FIELDS {
        if let Some(value) = object.get(*field)
            && !value.is_string()
        {
            return Err(crate::error::invalid_input(format!(
                "{field} must be a string"
            )));
        }
    }

    serde_json::from_value(request)
        .map_err(|err| crate::error::invalid_input(format!("invalid keys request: {err}")))
}

pub fn parse_update_lifecycle_input(request: Value) -> Result<UpdateLifecycleInput, DynError> {
    let Some(object) = request.as_object() else {
        return Err(crate::error::invalid_input(
            "request body must be a JSON object",
        ));
    };

    validate_json_string_field(object, "status")?;
    validate_json_string_field(object, "reason")?;

    let input: UpdateLifecycleInput = serde_json::from_value(request)
        .map_err(|err| crate::error::invalid_input(format!("invalid lifecycle request: {err}")))?;
    validate_lifecycle_status("status", &input.status)?;
    validation::validate_text_field("reason", &input.reason)?;

    Ok(input)
}

pub async fn load_keys_db_state(
    storage: &StorageState,
    internal_keys: &InternalDerivedKeysState,
) -> Result<Zeroizing<KeysDbState>, DynError> {
    let rows = storage.list_ops_keys().await?;
    let mut keys_db = Vec::new();

    for row in rows {
        let id = row.id.clone();
        match load_ops_key_from_row(internal_keys, row) {
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

pub(crate) async fn load_keys_db_entry(
    storage: &StorageState,
    internal_keys: &InternalDerivedKeysState,
    id: &str,
) -> Result<LoadedOpsKey, DynError> {
    let id = KeyId::parse(id)?;

    let row = storage.get_ops_keys(id.as_str()).await?;
    let loaded_key = load_ops_key_from_row(internal_keys, row)?;
    info!(id = %loaded_key.id, "decrypted ops key loaded from db");

    Ok(loaded_key)
}

pub async fn update_key_lifecycle(
    storage: &StorageState,
    internal_keys: &InternalDerivedKeysState,
    id: &str,
    input: UpdateLifecycleInput,
) -> Result<UpdateLifecycleOutput, DynError> {
    let id = KeyId::parse(id)?;
    let row = storage.get_ops_keys(id.as_str()).await?;
    validate_key_id_matches_enc_keys(&row.id, &row.enc_keys)?;

    let decrypted = decrypt_ops_keys_payload(internal_keys, &row.enc_keys)?;
    let mut properties = decrypt_ops_key_properties_payload(internal_keys, &row.properties)?;
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
        encrypt_ops_key_properties_payload(internal_keys, &properties.output, &properties.aad)?;
    storage
        .update_ops_key_properties(id.as_str(), &encrypted_properties)
        .await?;

    Ok(UpdateLifecycleOutput {
        kid: id.as_str().to_string(),
        lifecycle: properties.output.lifecycle,
    })
}

fn load_ops_key_from_row(
    internal_keys: &InternalDerivedKeysState,
    row: crate::core::storage::OpsKeyRow,
) -> Result<LoadedOpsKey, DynError> {
    validate_key_id_matches_enc_keys(&row.id, &row.enc_keys)?;
    let decrypted = decrypt_ops_keys_payload(internal_keys, &row.enc_keys)?;
    let properties = decrypt_ops_key_properties_payload(internal_keys, &row.properties)?;
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
    internal_keys: &InternalDerivedKeysState,
    properties: &OpsKeyProperties,
    aad: &str,
) -> Result<String, DynError> {
    let plaintext = Zeroizing::new(serde_json::to_string_pretty(properties)?);
    let nonce = Zeroizing::new(crypto::random_bytes(
        config::INTERNAL_KEYS_NONCE_SIZE_BYTES,
    )?);
    let properties_b64 =
        encrypt_internal_payload(&plaintext, internal_keys.properties_key(), &nonce, aad)?;
    let nonce_b64 = general_purpose::STANDARD.encode(&*nonce);
    let aad_b64 = general_purpose::STANDARD.encode(aad.as_bytes());

    Ok(format!("{properties_b64}.{nonce_b64}.{aad_b64}"))
}

fn decrypt_ops_keys_payload(
    internal_keys: &InternalDerivedKeysState,
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
    let plaintext_bytes = Zeroizing::new(crypto::decrypt_symmetric(
        config::INTERNAL_KEYS_CIPHER,
        &ciphertext,
        internal_keys.db_key(),
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
    internal_keys: &InternalDerivedKeysState,
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
    let plaintext_bytes = Zeroizing::new(crypto::decrypt_symmetric(
        config::INTERNAL_KEYS_CIPHER,
        &ciphertext,
        internal_keys.properties_key(),
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
        return Err(crate::error::invalid_input(format!(
            "{field} must have ciphertext.nonce.aad base64 sections"
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
            return Err(crate::error::invalid_input(
                "aad must contain key=value fields",
            ));
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
        .ok_or_else(|| crate::error::invalid_input(format!("aad missing {key}")))
}

fn validate_aad_field(field: &str, actual: &str, expected: &str) -> Result<(), DynError> {
    if actual != expected {
        return Err(crate::error::invalid_input(format!(
            "{field} does not match expected value"
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

    Err(crate::error::invalid_input(format!(
        "invalid lifecycle transition: {current} -> {next}"
    )))
}

fn validate_json_string_field(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), DynError> {
    match object.get(field) {
        Some(value) if value.is_string() => Ok(()),
        Some(_) => Err(crate::error::invalid_input(format!(
            "{field} must be a string"
        ))),
        None => Err(crate::error::invalid_input(format!("{field} is required"))),
    }
}

fn resolve_keys_input(
    input: CreateKeysInput,
    config: &config::AppConfig,
) -> Result<ResolvedKeysInput, DynError> {
    let timestamp = validation::current_timestamp()?;
    let tag = input.tag.clone().unwrap_or_else(|| timestamp.clone());
    validation::validate_aad_value("tag", &tag)?;

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
        return Err(crate::error::invalid_input(
            "individual algorithm overrides are rejected when VECTIS_CRYPTO_POLICY=profile-only",
        ));
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
        _ => Err(crate::error::invalid_input(format!(
            "unsupported crypto profile: {name}"
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::key_material::{
        VariantDerKeyPair, VariantHash, VariantKeyAgreementKeyPair, VariantSymmetricKey,
    };
    use proptest::prelude::*;
    use serde_json::json;

    const LIFECYCLE: &[&str] = &["active", "disabled", "retired", "compromised", "destroyed"];
    const CREATE_KEYS_FIELDS: &[&str] = &[
        "tag",
        "profile",
        "hash_algorithm",
        "symmetric_algorithm",
        "eddsa_algorithm",
        "xecdh_algorithm",
        "ml_dsa_variant",
        "ml_kem_variant",
    ];

    fn lifecycle_transition_allowed(current: &str, next: &str) -> bool {
        matches!(
            (current, next),
            ("active", "disabled")
                | ("active", "retired")
                | ("active", "compromised")
                | ("active", "destroyed")
                | ("disabled", "active")
        )
    }

    fn loaded_key_with_lifecycle(status: &str) -> LoadedOpsKey {
        LoadedOpsKey {
            id: "a".repeat(64),
            aad: String::from("type=ops-keys"),
            properties_aad: String::from("type=ops-key-properties"),
            key_material: KeyMaterialOutput {
                hash: VariantHash {
                    variant: String::from("SHA-256"),
                },
                keys: KeyMaterialKeys {
                    symmetric: VariantSymmetricKey {
                        variant: String::from("AES-256/GCM"),
                        key_hex: "a".repeat(64),
                    },
                    eddsa: VariantDerKeyPair {
                        variant: String::from("Ed25519"),
                        private_key_der_hex: String::from("aa"),
                        public_key_der_hex: String::from("aa"),
                    },
                    xecdh: VariantKeyAgreementKeyPair {
                        variant: String::from("X25519"),
                        private_key_der_hex: String::from("aa"),
                        public_key_hex: "a".repeat(64),
                    },
                    ml_dsa: VariantDerKeyPair {
                        variant: String::from("ML-DSA-44"),
                        private_key_der_hex: String::from("aa"),
                        public_key_der_hex: String::from("aa"),
                    },
                    ml_kem: VariantDerKeyPair {
                        variant: String::from("ML-KEM-512"),
                        private_key_der_hex: String::from("aa"),
                        public_key_der_hex: String::from("aa"),
                    },
                },
            },
            properties: OpsKeyProperties {
                version: 1,
                profile: String::from("custom"),
                tag: String::from("test"),
                created_at: String::from("1"),
                lifecycle: OpsKeyLifecycle {
                    status: status.to_string(),
                    reason: String::from("test"),
                    changed_at: String::from("1"),
                },
                access: None,
            },
        }
    }

    proptest! {
        #[test]
        fn lifecycle_transition_matches_policy(
            current in prop::sample::select(LIFECYCLE),
            next in prop::sample::select(LIFECYCLE)
        ) {
            let result = validate_lifecycle_transition(current, next);
            prop_assert_eq!(result.is_ok(), lifecycle_transition_allowed(current, next));
        }

        #[test]
        fn lifecycle_rejects_unknown_statuses(status in "[A-Za-z0-9_-]{1,32}") {
            prop_assume!(!LIFECYCLE.contains(&status.as_str()));
            prop_assert!(validate_lifecycle_status("status", &status).is_err());
            prop_assert!(validate_lifecycle_transition(&status, "active").is_err());
            prop_assert!(validate_lifecycle_transition("active", &status).is_err());
        }

        #[test]
        fn lifecycle_requirement_helpers_match_policy(status in "[A-Za-z0-9_-]{1,32}") {
            let loaded_key = loaded_key_with_lifecycle(&status);
            let known_status = LIFECYCLE.contains(&status.as_str());

            prop_assert_eq!(require_lifecycle_for_new_use(&loaded_key).is_ok(), status == "active");
            prop_assert_eq!(
                require_lifecycle_for_decrypt_or_verify(&loaded_key).is_ok(),
                status == "active" || status == "retired"
            );
            prop_assert_eq!(require_lifecycle_for_public_keys(&loaded_key).is_ok(), status == "active");

            if !known_status {
                prop_assert!(require_lifecycle_for_new_use(&loaded_key).is_err());
                prop_assert!(require_lifecycle_for_decrypt_or_verify(&loaded_key).is_err());
                prop_assert!(require_lifecycle_for_public_keys(&loaded_key).is_err());
            }
        }

        #[test]
        fn parse_create_keys_input_accepts_known_string_fields(
            tag in "[A-Za-z0-9_.-]{1,32}",
            profile in prop::sample::select(config::CRYPTO_PROFILES)
        ) {
            let value = json!({
                "tag": tag,
                "profile": profile,
                "hash_algorithm": "SHA-256",
                "symmetric_algorithm": "AES-256/GCM",
                "eddsa_algorithm": "Ed25519",
                "xecdh_algorithm": "X25519",
                "ml_dsa_variant": "ML-DSA-44",
                "ml_kem_variant": "ML-KEM-512"
            });

            prop_assert!(parse_create_keys_input(value).is_ok());
        }

        #[test]
        fn parse_create_keys_input_rejects_unknown_fields(field in "[A-Za-z0-9_]{1,32}") {
            prop_assume!(!CREATE_KEYS_FIELDS.contains(&field.as_str()));
            let value = json!({ "tag": "ok", field: "unexpected" });

            prop_assert!(parse_create_keys_input(value).is_err());
        }

        #[test]
        fn parse_create_keys_input_rejects_non_string_known_fields(field in prop::sample::select(CREATE_KEYS_FIELDS)) {
            for value in [Value::Null, json!(1), json!(true), json!([]), json!({})] {
                let request = json!({ field: value });
                prop_assert!(parse_create_keys_input(request).is_err());
            }
        }

        #[test]
        fn parse_update_lifecycle_input_accepts_valid_shape(
            status in prop::sample::select(LIFECYCLE),
            reason in "[A-Za-z0-9._:-][A-Za-z0-9 ._:-]{0,63}"
        ) {
            let input = parse_update_lifecycle_input(json!({
                "status": status,
                "reason": reason,
            }))
            .expect("generated lifecycle update input must parse");

            prop_assert_eq!(input.status(), status);
            prop_assert!(validate_lifecycle_status("status", input.status()).is_ok());
            prop_assert!(validation::validate_text_field("reason", &reason).is_ok());
        }

        #[test]
        fn parse_update_lifecycle_input_rejects_unknown_fields(
            status in prop::sample::select(LIFECYCLE),
            reason in "[A-Za-z0-9._:-][A-Za-z0-9 ._:-]{0,63}",
            field in "[A-Za-z_][A-Za-z0-9_]{0,24}"
        ) {
            prop_assume!(!["status", "reason"].contains(&field.as_str()));
            let request = json!({
                "status": status,
                "reason": reason,
                field: "unexpected",
            });

            prop_assert!(parse_update_lifecycle_input(request).is_err());
        }

        #[test]
        fn parse_update_lifecycle_input_rejects_non_string_fields(field in prop::sample::select(&["status", "reason"])) {
            for value in [Value::Null, json!(1), json!(true), json!([]), json!({})] {
                let request = if field == "status" {
                    json!({"status": value, "reason": "ok"})
                } else {
                    json!({"status": "active", "reason": value})
                };
                prop_assert!(parse_update_lifecycle_input(request).is_err());
            }
        }

        #[test]
        fn parsed_lifecycle_update_validates_status_and_reason(
            status in "[A-Za-z0-9_-]{1,32}",
            reason in "[A-Za-z0-9 ._:-]{0,64}"
        ) {
            let result = parse_update_lifecycle_input(json!({
                "status": status,
                "reason": reason,
            }));
            let valid = LIFECYCLE.contains(&status.as_str()) && !reason.trim().is_empty();

            prop_assert_eq!(result.is_ok(), valid);
        }

        #[test]
        fn aad_fields_parse_and_lookup_round_trip(
            first_key in "[a-z]{1,8}",
            first_value in "[A-Za-z0-9_.-]{1,16}",
            second_key in "[a-z]{1,8}",
            second_value in "[A-Za-z0-9_.-]{1,16}"
        ) {
            prop_assume!(first_key != second_key);
            let aad = validation::build_aad(&[
                (&first_key, &first_value),
                (&second_key, &second_value),
            ]);
            let fields = parse_aad_fields(&aad).expect("generated aad must parse");

            prop_assert_eq!(aad_field(&fields, &first_key).unwrap(), first_value);
            prop_assert_eq!(aad_field(&fields, &second_key).unwrap(), second_value);
            prop_assert!(aad_field(&fields, "missing").is_err());
        }

        #[test]
        fn aad_fields_reject_invalid_parts(
            key in "[A-Za-z0-9_.-]{0,16}",
            value in "[A-Za-z0-9_.-]{0,16}"
        ) {
            let empty_key = format!("={value}");
            let empty_value = format!("{key}=");
            let missing_separator = format!("{key}=ok;badpart");
            let control_char = format!("{key}=ok\n");

            prop_assert!(parse_aad_fields("missing_separator").is_err());
            prop_assert!(parse_aad_fields(&empty_key).is_err());
            prop_assert!(parse_aad_fields(&empty_value).is_err());
            prop_assert!(parse_aad_fields(&missing_separator).is_err());
            prop_assert!(parse_aad_fields(&control_char).is_err());
        }

        #[test]
        fn aad_field_validation_requires_exact_match(
            actual in "[A-Za-z0-9_.-]{1,16}",
            expected in "[A-Za-z0-9_.-]{1,16}"
        ) {
            prop_assert_eq!(
                validate_aad_field("field", &actual, &expected).is_ok(),
                actual == expected
            );
        }

        #[test]
        fn split_internal_payload_requires_exactly_three_sections(
            first in "[A-Za-z0-9+/=]{1,16}",
            second in "[A-Za-z0-9+/=]{1,16}",
            third in "[A-Za-z0-9+/=]{1,16}",
            extra in "[A-Za-z0-9+/=]{1,16}"
        ) {
            let valid = format!("{first}.{second}.{third}");
            let two_sections = format!("{first}.{second}");
            let four_sections = format!("{first}.{second}.{third}.{extra}");

            prop_assert_eq!(split_internal_payload("payload", &valid).unwrap().len(), 3);

            prop_assert!(split_internal_payload("payload", &first).is_err());
            prop_assert!(split_internal_payload("payload", &two_sections).is_err());
            prop_assert!(split_internal_payload("payload", &four_sections).is_err());
        }

        #[test]
        fn key_id_must_match_enc_keys_payload(payload in "[A-Za-z0-9_-]{1,64}") {
            let payload_b64 = general_purpose::STANDARD.encode(payload.as_bytes());
            let nonce_b64 = general_purpose::STANDARD.encode(b"nonce");
            let aad_b64 = general_purpose::STANDARD.encode(b"aad");
            let enc_keys = format!("{payload_b64}.{nonce_b64}.{aad_b64}");
            let id = create_key_id(&payload_b64).expect("generated key id must hash");
            let wrong_id = "f".repeat(64);

            prop_assert!(validate_key_id_matches_enc_keys(&id, &enc_keys).is_ok());
            if wrong_id != id {
                prop_assert!(validate_key_id_matches_enc_keys(&wrong_id, &enc_keys).is_err());
            }
        }
    }
}
