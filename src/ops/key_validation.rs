use crate::core::{config, crypto, validation};
use crate::error::DynError;
use crate::ops::key_material::{
    KeyMaterialOutput, VariantDerKeyPair, VariantKeyAgreementKeyPair, VariantSymmetricKey,
};
use serde::Serialize;
use tracing::info;
use zeroize::Zeroizing;

#[derive(Clone, Serialize)]
pub struct KeyValidationOutput {
    timestamp: String,
    aad: String,
    hash: HashValidation,
    symmetric: VariantKeyValidation,
    eddsa: VariantKeyValidation,
    xecdh: VariantKeyValidation,
    #[serde(rename = "ml-dsa")]
    ml_dsa: VariantKeyValidation,
    #[serde(rename = "ml-kem")]
    ml_kem: VariantKeyValidation,
}

impl KeyValidationOutput {
    pub fn with_current_timestamp(&self) -> Result<Self, DynError> {
        let mut output = self.clone();
        output.timestamp = validation::current_timestamp()?;

        Ok(output)
    }
}

#[derive(Clone, Serialize)]
struct HashValidation {
    variant: String,
    value_hex: String,
}

#[derive(Clone, Serialize)]
struct VariantKeyValidation {
    variant: String,
    valid: bool,
}

pub fn validate_key_material(
    config: &config::AppConfig,
    output: &KeyMaterialOutput,
    aad: &str,
    message: &str,
) -> Result<KeyValidationOutput, DynError> {
    validation::validate_allowed_value(
        "hash.variant",
        output.hash_variant(),
        crypto::HASH_ALGORITHMS,
    )?;
    let plaintext_message_hash_hex =
        hex::encode(crypto::hash_text(output.hash_variant(), message)?);

    info!(
        message_len = message.len(),
        "message ready for key validation"
    );

    let symmetric_valid =
        validate_symmetric_encryption(config, output.keys().symmetric(), message)?;
    let eddsa_valid = validate_eddsa(output.keys().eddsa(), message)?;
    let xecdh_valid = validate_xecdh(output.keys().xecdh())?;
    let ml_dsa_valid = validate_ml_dsa(output.keys().ml_dsa(), message)?;
    let ml_kem_valid = validate_ml_kem(output.keys().ml_kem())?;

    ensure_valid("symmetric", symmetric_valid)?;
    ensure_valid("eddsa", eddsa_valid)?;
    ensure_valid("xecdh", xecdh_valid)?;
    ensure_valid("ml-dsa", ml_dsa_valid)?;
    ensure_valid("ml-kem", ml_kem_valid)?;

    Ok(KeyValidationOutput {
        timestamp: validation::current_timestamp()?,
        aad: aad.to_string(),
        hash: HashValidation {
            variant: output.hash_variant().to_string(),
            value_hex: plaintext_message_hash_hex,
        },
        symmetric: VariantKeyValidation {
            variant: output.keys().symmetric().variant().to_string(),
            valid: symmetric_valid,
        },
        eddsa: VariantKeyValidation {
            variant: output.keys().eddsa().variant().to_string(),
            valid: eddsa_valid,
        },
        xecdh: VariantKeyValidation {
            variant: output.keys().xecdh().variant().to_string(),
            valid: xecdh_valid,
        },
        ml_dsa: VariantKeyValidation {
            variant: output.keys().ml_dsa().variant().to_string(),
            valid: ml_dsa_valid,
        },
        ml_kem: VariantKeyValidation {
            variant: output.keys().ml_kem().variant().to_string(),
            valid: ml_kem_valid,
        },
    })
}

fn validate_symmetric_encryption(
    config: &config::AppConfig,
    keys: &VariantSymmetricKey,
    message: &str,
) -> Result<bool, DynError> {
    let cipher = symmetric_cipher(keys.variant())?;
    validation::validate_symmetric_key("symmetric", keys.key_hex(), cipher.key_size_bytes)?;

    let key = Zeroizing::new(hex::decode(keys.key_hex())?);
    let nonce = Zeroizing::new(crypto::random_bytes(cipher.nonce_size_bytes)?);
    let aad = validation::build_aad(&[
        ("type", "key-material-symmetric-validation"),
        ("sender_hostname", &config.sender_hostname),
        ("receiver_hostname", &config.receiver_hostname),
        ("cipher", cipher.algorithm),
    ]);
    let ciphertext =
        crypto::encrypt_symmetric(cipher.algorithm, message, &key, &nonce, aad.as_bytes())?;
    let plaintext = Zeroizing::new(crypto::decrypt_symmetric(
        cipher.algorithm,
        &ciphertext,
        &key,
        &nonce,
        aad.as_bytes(),
    )?);

    Ok(plaintext.as_slice() == message.as_bytes())
}

fn symmetric_cipher(algorithm: &str) -> Result<crypto::SymmetricCipherSpec, DynError> {
    validation::validate_allowed_value(
        "symmetric_algorithm",
        algorithm,
        crypto::SYMMETRIC_ALGORITHMS,
    )?;

    crypto::symmetric_cipher(algorithm).ok_or_else(|| {
        crate::error::invalid_input(format!("invalid symmetric algorithm: {algorithm}"))
    })
}

fn validate_eddsa(keys: &VariantDerKeyPair, message: &str) -> Result<bool, DynError> {
    validation::validate_allowed_value("eddsa.variant", keys.variant(), &["Ed25519", "Ed448"])?;

    let private_key = crypto::load_private_key_der_hex(keys.private_key_der_hex())?;
    let public_key = crypto::load_public_key_der_hex(keys.public_key_der_hex())?;
    let signature = crypto::sign_message(&private_key, message)?;

    Ok(crypto::verify_message(&public_key, message, &signature)?)
}

fn validate_xecdh(keys: &VariantKeyAgreementKeyPair) -> Result<bool, DynError> {
    validation::validate_allowed_value("xecdh.variant", keys.variant(), &["X25519", "X448"])?;
    let private_key = crypto::load_private_key_der_hex(keys.private_key_der_hex())?;
    let public_key = hex::decode(keys.public_key_hex())?;
    let derived_public_key = crypto::key_agreement_public_key(&private_key)?;
    if derived_public_key != public_key {
        return Ok(false);
    }

    let peer_private_key = crypto::create_x_key_agreement_private_key(keys.variant())?;
    let peer_public_key = crypto::key_agreement_public_key(&peer_private_key)?;
    let shared_key = Zeroizing::new(crypto::agree_key(&private_key, &peer_public_key)?);
    let peer_shared_key = Zeroizing::new(crypto::agree_key(&peer_private_key, &public_key)?);

    Ok(shared_key.as_slice() == peer_shared_key.as_slice())
}

fn validate_ml_dsa(keys: &VariantDerKeyPair, message: &str) -> Result<bool, DynError> {
    if crypto::MlDsaVariant::from_name(keys.variant()).is_none() {
        return Err(crate::error::invalid_input(format!(
            "invalid stored ml-dsa variant: {}",
            keys.variant()
        )));
    }

    let private_key = crypto::load_private_key_der_hex(keys.private_key_der_hex())?;
    let public_key = crypto::load_public_key_der_hex(keys.public_key_der_hex())?;
    let signature = crypto::sign_ml_dsa_message(&private_key, message)?;

    Ok(crypto::verify_ml_dsa_message(
        &public_key,
        message,
        &signature,
    )?)
}

fn validate_ml_kem(keys: &VariantDerKeyPair) -> Result<bool, DynError> {
    let variant = crypto::MlKemVariant::from_name(keys.variant()).ok_or_else(|| {
        crate::error::invalid_input(format!(
            "invalid ML-KEM variant in key material: {}",
            keys.variant()
        ))
    })?;
    let private_key = crypto::load_private_key_der_hex(keys.private_key_der_hex())?;
    let public_key = crypto::load_public_key_der_hex(keys.public_key_der_hex())?;
    let peer_private_key = crypto::create_ml_kem_private_key(&variant)?;
    let salt = Zeroizing::new(crypto::random_bytes(12)?);
    let shared_key_len = 32;
    let encapsulation =
        crypto::encapsulate_ml_kem_shared_key(&public_key, salt.as_slice(), shared_key_len)?;
    let encapsulated_key = encapsulation.encapsulated_key;
    let encapsulated_shared_key = Zeroizing::new(encapsulation.shared_key);
    let decapsulated_shared_key = Zeroizing::new(crypto::decapsulate_ml_kem_shared_key(
        &private_key,
        &encapsulated_key,
        salt.as_slice(),
        shared_key_len,
    )?);
    let peer_decapsulated_shared_key = Zeroizing::new(crypto::decapsulate_ml_kem_shared_key(
        &peer_private_key,
        &encapsulated_key,
        salt.as_slice(),
        shared_key_len,
    )?);
    let hkdf_salt = Zeroizing::new(crypto::random_bytes(32)?);
    let hkdf_info = format!("key-material-validation:ml-kem:{}", keys.variant());
    let sender_key = Zeroizing::new(crypto::hkdf_sha256(
        encapsulated_shared_key.as_slice(),
        hkdf_salt.as_slice(),
        hkdf_info.as_bytes(),
        32,
    )?);
    let receiver_key = Zeroizing::new(crypto::hkdf_sha256(
        decapsulated_shared_key.as_slice(),
        hkdf_salt.as_slice(),
        hkdf_info.as_bytes(),
        32,
    )?);

    Ok(
        encapsulated_shared_key.as_slice() == decapsulated_shared_key.as_slice()
            && encapsulated_shared_key.as_slice() != peer_decapsulated_shared_key.as_slice()
            && sender_key.as_slice() == receiver_key.as_slice(),
    )
}

fn ensure_valid(name: &str, valid: bool) -> Result<(), DynError> {
    if valid {
        Ok(())
    } else {
        Err(crate::error::internal(format!(
            "{name} key validation failed"
        )))
    }
}
