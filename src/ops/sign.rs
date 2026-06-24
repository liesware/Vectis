use crate::core::{crypto, validation};
use crate::error::DynError;
use crate::ops::contracts::{
    MessageHash, SignatureBlock, TimestampPayload, TimestampSignatures, VerificationStatus,
};
use crate::ops::keys::{self, KeysDbState, LoadedOpsKey};
use serde_json::Value;
use std::io;
use tracing::{debug, info};

pub use crate::ops::contracts::{SignInput, TimestampToken, VerificationOutput};

pub struct ValidatedSignInput {
    input: SignInput,
}

pub fn sign_timestamp(
    loaded_key: &LoadedOpsKey,
    input: ValidatedSignInput,
) -> Result<TimestampToken, DynError> {
    debug!(
        kid = %loaded_key.id(),
        hash_alg = %input.input.message_hash.alg,
        hash_hex_len = input.input.message_hash.hex.len(),
        "timestamp signing started"
    );
    let created_at = validation::current_timestamp()?;
    let payload = TimestampPayload {
        token_type: String::from("tsp"),
        created_at,
        info: loaded_key.aad().to_string(),
        kid: loaded_key.id().to_string(),
        serial: hex::encode(crypto::random_bytes(16)?),
        message_hash: input.input.message_hash,
    };
    debug!(
        kid = %loaded_key.id(),
        created_at = %payload.created_at,
        serial = %payload.serial,
        "timestamp payload built"
    );
    let payload_bytes = serde_json::to_vec(&payload)?;
    let eddsa = loaded_key.keys().eddsa();
    let ml_dsa = loaded_key.keys().ml_dsa();
    debug!(
        kid = %loaded_key.id(),
        eddsa_alg = %eddsa.variant(),
        ml_dsa_alg = %ml_dsa.variant(),
        payload_len = payload_bytes.len(),
        "timestamp signing keys selected"
    );
    let eddsa_private_key = crypto::load_private_key_der_hex(eddsa.private_key_der_hex())?;
    let ml_dsa_private_key = crypto::load_private_key_der_hex(ml_dsa.private_key_der_hex())?;
    debug!(kid = %loaded_key.id(), "timestamp private keys loaded");
    let eddsa_signature =
        crypto::sign_message(&eddsa_private_key, std::str::from_utf8(&payload_bytes)?)?;
    debug!(
        kid = %loaded_key.id(),
        eddsa_alg = %eddsa.variant(),
        sig_len = eddsa_signature.len(),
        "timestamp eddsa signature created"
    );
    let ml_dsa_signature =
        crypto::sign_ml_dsa_message(&ml_dsa_private_key, std::str::from_utf8(&payload_bytes)?)?;
    debug!(
        kid = %loaded_key.id(),
        ml_dsa_alg = %ml_dsa.variant(),
        sig_len = ml_dsa_signature.len(),
        "timestamp ml-dsa signature created"
    );
    info!(
        kid = %loaded_key.id(),
        hash_alg = %payload.message_hash.alg,
        created_at = %payload.created_at,
        serial = %payload.serial,
        eddsa_alg = %eddsa.variant(),
        ml_dsa_alg = %ml_dsa.variant(),
        "timestamp token signed"
    );

    Ok(TimestampToken {
        version: String::from("v1"),
        payload,
        signatures: TimestampSignatures {
            eddsa: SignatureBlock {
                alg: eddsa.variant().to_string(),
                sig: hex::encode(eddsa_signature),
            },
            ml_dsa: SignatureBlock {
                alg: ml_dsa.variant().to_string(),
                sig: hex::encode(ml_dsa_signature),
            },
        },
    })
}

pub fn parse_sign_input(request: Value) -> Result<SignInput, DynError> {
    debug!("parsing sign request");

    serde_json::from_value(request).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid sign request: {err}"),
        )) as DynError
    })
}

pub fn sign_timestamp_from_state(
    keys_db_state: &KeysDbState,
    id: &str,
    input: SignInput,
) -> Result<TimestampToken, DynError> {
    debug!(kid = %id, "validating sign input");
    let input = validate_sign_input(input)?;
    debug!(kid = %id, "loading key for timestamp signing");
    let loaded_key = keys::get_loaded_key(keys_db_state, id)?;

    sign_timestamp(loaded_key, input)
}

pub fn validate_sign_input(input: SignInput) -> Result<ValidatedSignInput, DynError> {
    debug!(
        hash_alg = %input.message_hash.alg,
        hash_hex_len = input.message_hash.hex.len(),
        "validating message hash"
    );
    validation::validate_allowed_value("HASH", &input.message_hash.alg, crypto::HASH_ALGORITHMS)?;
    validation::validate_hash_hex_field(
        "message_hash.hex",
        &input.message_hash.hex,
        &input.message_hash.alg,
    )?;

    Ok(ValidatedSignInput { input })
}

pub fn parse_timestamp_token(request: Value) -> Result<TimestampToken, DynError> {
    debug!("parsing timestamp verification token");

    serde_json::from_value(request).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid timestamp token: {err}"),
        )) as DynError
    })
}

pub fn verify_timestamp(
    loaded_key: &LoadedOpsKey,
    token: &TimestampToken,
) -> Result<VerificationOutput, DynError> {
    debug!(
        kid = %loaded_key.id(),
        token_kid = %token.kid(),
        eddsa_alg = %token.signatures.eddsa.alg,
        ml_dsa_alg = %token.signatures.ml_dsa.alg,
        "timestamp verification started"
    );
    validate_timestamp_token_for_key(loaded_key, token)?;

    let payload_bytes = serde_json::to_vec(&token.payload)?;
    let payload_text = std::str::from_utf8(&payload_bytes)?;
    let eddsa = loaded_key.keys().eddsa();
    let ml_dsa = loaded_key.keys().ml_dsa();
    let eddsa_public_key = crypto::load_public_key_der_hex(eddsa.public_key_der_hex())?;
    let ml_dsa_public_key = crypto::load_public_key_der_hex(ml_dsa.public_key_der_hex())?;
    let eddsa_signature = hex::decode(&token.signatures.eddsa.sig)?;
    let ml_dsa_signature = hex::decode(&token.signatures.ml_dsa.sig)?;
    debug!(
        kid = %loaded_key.id(),
        payload_len = payload_bytes.len(),
        eddsa_sig_len = eddsa_signature.len(),
        ml_dsa_sig_len = ml_dsa_signature.len(),
        "timestamp verification material loaded"
    );
    let eddsa_valid = crypto::verify_message(&eddsa_public_key, payload_text, &eddsa_signature)?;
    let ml_dsa_valid =
        crypto::verify_ml_dsa_message(&ml_dsa_public_key, payload_text, &ml_dsa_signature)?;
    info!(
        kid = %loaded_key.id(),
        eddsa = status_text(eddsa_valid),
        ml_dsa = status_text(ml_dsa_valid),
        valid = eddsa_valid && ml_dsa_valid,
        "timestamp token verified"
    );

    if !eddsa_valid || !ml_dsa_valid {
        return Ok(VerificationOutput {
            status: VerificationStatus {
                eddsa: status_text(eddsa_valid),
                ml_dsa: status_text(ml_dsa_valid),
            },
            valid: String::from("fail"),
        });
    }

    Ok(VerificationOutput {
        status: VerificationStatus {
            eddsa: String::from("ok"),
            ml_dsa: String::from("ok"),
        },
        valid: String::from("ok"),
    })
}

pub fn verify_timestamp_from_state(
    keys_db_state: &KeysDbState,
    token: &TimestampToken,
) -> Result<VerificationOutput, DynError> {
    debug!(kid = %token.kid(), "validating timestamp token");
    validate_timestamp_token(token)?;

    let kid = token.kid();
    debug!(kid = %kid, "loading key for timestamp verification");
    let loaded_key = keys::get_loaded_key(keys_db_state, kid)?;

    verify_timestamp(loaded_key, token)
}

pub fn validate_timestamp_token(token: &TimestampToken) -> Result<(), DynError> {
    debug!(
        version = %token.version,
        token_type = %token.payload.token_type,
        kid = %token.payload.kid,
        hash_alg = %token.payload.message_hash.alg,
        hash_hex_len = token.payload.message_hash.hex.len(),
        eddsa_alg = %token.signatures.eddsa.alg,
        ml_dsa_alg = %token.signatures.ml_dsa.alg,
        "validating timestamp token fields"
    );
    validation::validate_allowed_value("version", &token.version, &["v1"])?;
    validation::validate_allowed_value("payload.type", &token.payload.token_type, &["tsp"])?;
    validation::validate_text_field("payload.created_at", &token.payload.created_at)?;
    validation::validate_text_field("payload.info", &token.payload.info)?;
    validation::validate_hash_hex_field(
        "payload.kid",
        &token.payload.kid,
        crate::core::config::INTERNAL_KEYS_HASH,
    )?;
    validation::validate_hex_field("payload.serial", &token.payload.serial)?;
    if token.payload.serial.len() != 32 {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "payload.serial must be 32 hex characters, got {}",
                token.payload.serial.len()
            ),
        )));
    }
    validate_message_hash(&token.payload.message_hash)?;
    validation::validate_allowed_value(
        "signatures.eddsa.alg",
        &token.signatures.eddsa.alg,
        &["Ed25519", "Ed448"],
    )?;
    validation::validate_hex_field("signatures.eddsa.sig", &token.signatures.eddsa.sig)?;
    validation::validate_allowed_value(
        "signatures.ml-dsa.alg",
        &token.signatures.ml_dsa.alg,
        &["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
    )?;
    validation::validate_hex_field("signatures.ml-dsa.sig", &token.signatures.ml_dsa.sig)?;

    Ok(())
}

fn validate_timestamp_token_for_key(
    loaded_key: &LoadedOpsKey,
    token: &TimestampToken,
) -> Result<(), DynError> {
    validate_timestamp_token(token)?;
    if token.payload.kid != loaded_key.id() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "payload.kid does not match loaded key",
        )));
    }
    if token.payload.info != loaded_key.aad() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "payload.info does not match loaded key aad",
        )));
    }
    if token.signatures.eddsa.alg != loaded_key.keys().eddsa().variant() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "signatures.eddsa.alg does not match loaded key",
        )));
    }
    if token.signatures.ml_dsa.alg != loaded_key.keys().ml_dsa().variant() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "signatures.ml-dsa.alg does not match loaded key",
        )));
    }

    Ok(())
}

fn validate_message_hash(message_hash: &MessageHash) -> Result<(), DynError> {
    validation::validate_allowed_value(
        "message_hash.alg",
        &message_hash.alg,
        crypto::HASH_ALGORITHMS,
    )?;
    validation::validate_hash_hex_field("message_hash.hex", &message_hash.hex, &message_hash.alg)?;

    Ok(())
}

fn status_text(valid: bool) -> String {
    if valid {
        String::from("ok")
    } else {
        String::from("fail")
    }
}
