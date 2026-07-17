use crate::core::{config, crypto, validation};
use crate::error::DynError;
use crate::ops::key_material::{KeyMaterialOutput, KeyMaterialSpec, create_key_material};
use crate::ops::key_validation::{KeyValidationOutput, validate_key_material};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub(crate) type InitOutput = KeyMaterialOutput;
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
    pub api_key_hash: Zeroizing<String>,
}

#[derive(Clone)]
pub struct ValidatedInitState {
    pub(crate) init_keys: Zeroizing<InitOutput>,
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

pub(crate) fn create_init_output() -> Result<InitOutput, DynError> {
    let spec = KeyMaterialSpec::internal_keys();

    create_key_material(&spec)
}

pub fn create_encrypted_init_output_json() -> Result<EncryptedInitJsonOutput, DynError> {
    let config = config::app_config()?;
    let aad = init_keys_aad(&config)?;
    validation::validate_allowed_value(
        "INTERNAL_KEYS_HASH",
        config::INTERNAL_KEYS_HASH,
        crypto::HASH_ALGORITHMS,
    )?;
    let api_key = Zeroizing::new(hex::encode(crypto::random_bytes(
        config::INTERNAL_KEYS_KEY_SIZE_BYTES,
    )?));
    validation::validate_hash_hex_field("VECTIS_APIKEY", &api_key, config::INTERNAL_KEYS_HASH)?;
    let output = Zeroizing::new(create_init_output()?);
    let api_key_hash = Zeroizing::new(crate::ops::internal_keys::api_key_hash_from_root_key_hex(
        output.keys.symmetric.key_hex.as_str(),
        &api_key,
    )?);
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
        api_key_hash,
    })
}

fn init_keys_aad(config: &config::AppConfig) -> Result<String, DynError> {
    validation::build_validated_aad(&[
        ("version", &config.protocol_version),
        ("hostname", &config.sender_hostname),
        ("type", "init-keys"),
        ("cipher", config::INTERNAL_KEYS_CIPHER),
    ])
}

fn validate_init_output(output: &InitOutput, aad: &str) -> Result<InitValidationOutput, DynError> {
    let config = config::app_config()?;
    validate_key_material(&config, output, aad, &config.plaintext_message)
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
        crate::error::forbidden(format!(
                "init keys file could not be decrypted: wrong init AES-256 key, stale VECTIS_UNSEAL_KEY, or init key material was regenerated ({err})"
            ))
    })?;
    let mut plaintext_bytes = Zeroizing::new(decrypted);
    let plaintext = Zeroizing::new(String::from_utf8(std::mem::take(&mut *plaintext_bytes))?);
    let output = serde_json::from_str::<InitOutput>(&plaintext)?;

    Ok(DecryptedInitOutput {
        aad: encrypted_input.aad,
        output: Zeroizing::new(output),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_keys_aad_keeps_legacy_format_for_valid_fields() {
        let config = config::test_app_config();
        let actual = init_keys_aad(&config).expect("valid init AAD must build");
        let expected = validation::build_aad(&[
            ("version", &config.protocol_version),
            ("hostname", &config.sender_hostname),
            ("type", "init-keys"),
            ("cipher", config::INTERNAL_KEYS_CIPHER),
        ]);

        assert_eq!(actual, expected);
    }

    #[test]
    fn init_keys_aad_rejects_delimiters_in_dynamic_fields() {
        let mut config = config::test_app_config();
        config.protocol_version = String::from("v1;type=evil");
        let err = init_keys_aad(&config).expect_err("protocol version delimiter must fail");
        assert!(err.to_string().contains("must not contain ';' or '='"));

        let mut config = config::test_app_config();
        config.sender_hostname = String::from("node=a");
        let err = init_keys_aad(&config).expect_err("sender hostname delimiter must fail");
        assert!(err.to_string().contains("must not contain ';' or '='"));
    }
}
