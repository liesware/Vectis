use crate::core::{config, crypto, remote_routes, validation};
use crate::error::DynError;
use crate::ops::contracts::{PublicDerKey, PublicKeys, PublicKeysOutput, PublicRawKey};
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
    pub public_json: String,
    pub encryption_key_hex: Zeroizing<String>,
    pub api_key: Zeroizing<String>,
    pub api_key_hash: Zeroizing<String>,
}

#[derive(Clone)]
pub struct ValidatedInitState {
    pub(crate) init_keys: Zeroizing<InitOutput>,
    init_aad: String,
    pub validation: InitValidationOutput,
}

#[derive(Clone)]
pub struct ValidatedInitPublicState {
    eddsa_public_key_der_hex: String,
    ml_dsa_public_key_der_hex: String,
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

impl ValidatedInitPublicState {
    pub fn eddsa_public_key_der_hex(&self) -> &str {
        &self.eddsa_public_key_der_hex
    }

    pub fn ml_dsa_public_key_der_hex(&self) -> &str {
        &self.ml_dsa_public_key_der_hex
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
        aad: aad.clone(),
    };
    let json = serde_json::to_string_pretty(&encrypted_output)?;
    let public_json = serialize_init_public_keys_json(&output, &aad)?;

    Ok(EncryptedInitJsonOutput {
        json,
        public_json,
        encryption_key_hex,
        api_key,
        api_key_hash,
    })
}

pub fn init_public_keys_json(init_state: &ValidatedInitState) -> Result<String, DynError> {
    serialize_init_public_keys_json(&init_state.init_keys, &init_state.init_aad)
}

fn serialize_init_public_keys_json(output: &InitOutput, info: &str) -> Result<String, DynError> {
    let keys = output.keys();

    Ok(serde_json::to_string_pretty(&PublicKeysOutput {
        info: info.to_string(),
        keys: PublicKeys {
            eddsa: PublicDerKey {
                alg: keys.eddsa().variant().to_string(),
                public_key_der_hex: keys.eddsa().public_key_der_hex().to_string(),
            },
            xecdh: PublicRawKey {
                alg: keys.xecdh().variant().to_string(),
                public_key_hex: keys.xecdh().public_key_hex().to_string(),
            },
            ml_dsa: PublicDerKey {
                alg: keys.ml_dsa().variant().to_string(),
                public_key_der_hex: keys.ml_dsa().public_key_der_hex().to_string(),
            },
            ml_kem: PublicDerKey {
                alg: keys.ml_kem().variant().to_string(),
                public_key_der_hex: keys.ml_kem().public_key_der_hex().to_string(),
            },
        },
    })?)
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
        init_aad: decrypted_init.aad,
        validation,
    })
}

pub fn load_validated_init_public_state(
    public_json: &str,
) -> Result<ValidatedInitPublicState, DynError> {
    let output: PublicKeysOutput = serde_json::from_str(public_json)?;
    validation::validate_text_field("init public keys info", &output.info)?;
    let peer_keys = remote_routes::PeerPublicKeys {
        eddsa: remote_routes::PeerDerKey {
            alg: output.keys.eddsa.alg,
            public_key_der_hex: output.keys.eddsa.public_key_der_hex,
        },
        xecdh: remote_routes::PeerRawKey {
            alg: output.keys.xecdh.alg,
            public_key_hex: output.keys.xecdh.public_key_hex,
        },
        ml_dsa: remote_routes::PeerDerKey {
            alg: output.keys.ml_dsa.alg,
            public_key_der_hex: output.keys.ml_dsa.public_key_der_hex,
        },
        ml_kem: remote_routes::PeerDerKey {
            alg: output.keys.ml_kem.alg,
            public_key_der_hex: output.keys.ml_kem.public_key_der_hex,
        },
    };
    remote_routes::validate_peer_public_keys(&peer_keys)?;

    Ok(ValidatedInitPublicState {
        eddsa_public_key_der_hex: peer_keys.eddsa.public_key_der_hex,
        ml_dsa_public_key_der_hex: peer_keys.ml_dsa.public_key_der_hex,
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
    use serde_json::Value;

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

    #[test]
    fn init_public_output_contains_only_validated_public_material() {
        let output = create_encrypted_init_output_json().expect("init output must be created");
        let value: Value = serde_json::from_str(&output.public_json).unwrap();
        let rendered = output.public_json.as_str();

        assert!(value.get("info").is_some());
        assert!(value.get("keys").is_some());
        assert!(!rendered.contains("private_key"));
        assert!(!rendered.contains("\"key_hex\""));
        assert!(load_validated_init_public_state(&output.public_json).is_ok());

        let mut invalid = value;
        invalid["unexpected"] = Value::Bool(true);
        assert!(load_validated_init_public_state(&invalid.to_string()).is_err());
    }

    #[test]
    fn reconstructs_identical_public_output_from_validated_init_state() {
        let output = create_encrypted_init_output_json().expect("init output must be created");
        let init_state =
            load_validated_init_state(&output.json, &output.encryption_key_hex).unwrap();

        assert_eq!(
            init_public_keys_json(&init_state).unwrap(),
            output.public_json
        );
    }
}
