use crate::core::{config, crypto, validation};
use crate::error::DynError;
use crate::ops::key_material::{KeyMaterialOutput, KeyMaterialSpec, create_key_material};
use crate::ops::key_validation::{KeyValidationOutput, validate_key_material};
use serde::{Deserialize, Serialize};
use std::io;
use zeroize::Zeroizing;

pub type InitOutput = KeyMaterialOutput;
pub type InitValidationOutput = KeyValidationOutput;

#[derive(Serialize)]
struct EncryptedInitOutput {
    keys_enc: String,
    nonce: String,
    aad: String,
}

#[derive(Deserialize)]
struct EncryptedInitInput {
    keys_enc: String,
    nonce: String,
    aad: String,
}

pub struct EncryptedInitJsonOutput {
    pub json: String,
    pub encryption_key_hex: Zeroizing<String>,
    pub api_key: Zeroizing<String>,
}

pub struct ValidatedInitState {
    pub init_keys: Zeroizing<InitOutput>,
    pub validation: InitValidationOutput,
}

impl ValidatedInitState {
    pub fn key_material_loaded(&self) -> bool {
        let _ = &self.init_keys;

        true
    }

    pub fn validation(&self) -> &InitValidationOutput {
        &self.validation
    }

    pub fn symmetric_key_hex(&self) -> &str {
        &self.init_keys.keys.symmetric.key_hex
    }
}

pub fn create_init_output() -> Result<InitOutput, DynError> {
    let spec = KeyMaterialSpec::internal_keys();

    create_key_material(&spec)
}

pub fn create_encrypted_init_output_json() -> Result<EncryptedInitJsonOutput, DynError> {
    let config = config::app_config()?;
    let timestamp = validation::current_timestamp()?;
    let aad = validation::build_aad(&[
        ("version", &config.protocol_version),
        ("hostname", &config.sender_hostname),
        ("type", "init-keys"),
        ("cipher", config::INTERNAL_KEYS_CIPHER),
    ]);
    validation::validate_allowed_value(
        "INTERNAL_KEYS_HASH",
        config::INTERNAL_KEYS_HASH,
        crypto::HASH_ALGORITHMS,
    )?;
    let api_key_material = format!("{aad}{timestamp}");
    let api_key = Zeroizing::new(hex::encode(crypto::hash_text(
        config::INTERNAL_KEYS_HASH,
        &api_key_material,
    )?));
    validation::validate_hash_hex_field("APIKEY", &api_key, config::INTERNAL_KEYS_HASH)?;
    let output = Zeroizing::new(create_init_output()?);
    let plaintext = Zeroizing::new(serde_json::to_string_pretty(&*output)?);
    let encryption_key =
        Zeroizing::new(crypto::random_bytes(config::INTERNAL_KEYS_KEY_SIZE_BYTES)?);
    let nonce = Zeroizing::new(crypto::random_bytes(
        config::INTERNAL_KEYS_NONCE_SIZE_BYTES,
    )?);
    let ciphertext = crypto::encrypt_symmetric(
        config::INTERNAL_KEYS_CIPHER,
        &plaintext,
        &encryption_key,
        &nonce,
        aad.as_bytes(),
    )?;
    let encryption_key_hex = Zeroizing::new(hex::encode(&*encryption_key));
    let encrypted_output = EncryptedInitOutput {
        keys_enc: hex::encode(ciphertext),
        nonce: hex::encode(&*nonce),
        aad,
    };
    let json = serde_json::to_string_pretty(&encrypted_output)?;

    Ok(EncryptedInitJsonOutput {
        json,
        encryption_key_hex,
        api_key,
    })
}

fn validate_init_output(output: &InitOutput, aad: &str) -> Result<InitValidationOutput, DynError> {
    let config = config::app_config()?;
    let message = config.plaintext_message;
    validate_key_material(output, aad, &message)
}

pub fn load_validated_init_state(
    encrypted_json: &str,
    key_hex: &str,
) -> Result<ValidatedInitState, DynError> {
    let decrypted_init = decrypt_encrypted_init_output(encrypted_json, key_hex)?;
    let validation = validate_init_output(&decrypted_init.output, &decrypted_init.aad)?;

    Ok(ValidatedInitState {
        init_keys: decrypted_init.output,
        validation,
    })
}

struct DecryptedInitOutput {
    aad: String,
    output: Zeroizing<InitOutput>,
}

fn decrypt_encrypted_init_output(
    encrypted_json: &str,
    key_hex: &str,
) -> Result<DecryptedInitOutput, DynError> {
    validation::validate_symmetric_key(
        "init AES-256 key",
        key_hex,
        config::INTERNAL_KEYS_KEY_SIZE_BYTES,
    )?;

    let encrypted_input: EncryptedInitInput = serde_json::from_str(encrypted_json)?;
    validation::validate_encrypted_payload(
        "keys_enc",
        &encrypted_input.keys_enc,
        "nonce",
        &encrypted_input.nonce,
        "aad",
        &encrypted_input.aad,
        config::INTERNAL_KEYS_NONCE_SIZE_BYTES,
    )?;
    let key = Zeroizing::new(hex::decode(key_hex)?);
    let ciphertext = hex::decode(encrypted_input.keys_enc)?;
    let nonce = hex::decode(encrypted_input.nonce)?;
    let decrypted = crypto::decrypt_symmetric(
        config::INTERNAL_KEYS_CIPHER,
        &ciphertext,
        &key,
        &nonce,
        encrypted_input.aad.as_bytes(),
    )
    .map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "init.json could not be decrypted: wrong init AES-256 key, stale UNSEAL_KEY, or init.json was regenerated ({err})"
            ),
        )) as DynError
    })?;
    let mut plaintext_bytes = Zeroizing::new(decrypted);
    let plaintext = Zeroizing::new(String::from_utf8(std::mem::take(&mut *plaintext_bytes))?);
    let output = serde_json::from_str::<InitOutput>(&plaintext)?;

    Ok(DecryptedInitOutput {
        aad: encrypted_input.aad,
        output: Zeroizing::new(output),
    })
}
