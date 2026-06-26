use crate::core::{config, crypto, routes, validation};
use crate::error::DynError;
use crate::ops::contracts::{
    MessageHash, SignatureBlock, TimestampPayload, TimestampSignatures, VerificationStatus,
};
use crate::ops::init::ValidatedInitState;
use crate::ops::key_material::VariantDerKeyPair;
use crate::ops::keys::{self, KeysDbState, LoadedOpsKey};
use serde_json::Value;
use std::io;
use std::path::Path;
use tracing::{debug, info};

pub use crate::ops::contracts::{SignInput, TimestampToken, VerificationOutput};

const TIMESTAMP_TOKEN_TYPE: &str = "vectis-sign";
const ROUTES_TOKEN_TYPE: &str = "vectis-routes";
const INIT_KEYS_KID: &str = "init-keys";
const PAYLOAD_SERIAL_RANDOM_BYTES: usize = 32;

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
        token_type: String::from(TIMESTAMP_TOKEN_TYPE),
        serial: create_payload_serial(&created_at)?,
        created_at,
        info: loaded_key.aad().to_string(),
        kid: loaded_key.id().to_string(),
        message_hash: input.input.message_hash,
    };
    debug!(
        kid = %loaded_key.id(),
        created_at = %payload.created_at,
        serial = %payload.serial,
        "timestamp payload built"
    );
    let eddsa = loaded_key.keys().eddsa();
    let ml_dsa = loaded_key.keys().ml_dsa();
    debug!(
        kid = %loaded_key.id(),
        eddsa_alg = %eddsa.variant(),
        ml_dsa_alg = %ml_dsa.variant(),
        "timestamp signing keys selected"
    );
    let signatures = sign_hybrid_payload(&payload, eddsa, ml_dsa)?;
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
        signatures,
    })
}

pub fn sign_routes_file(
    init_state: &ValidatedInitState,
    routes_path: &Path,
    routes_content: &str,
) -> Result<TimestampToken, DynError> {
    let canonical_routes = routes::canonical_routes_json(routes_content)?;
    let message_hash = MessageHash {
        alg: config::INTERNAL_KEYS_HASH.to_string(),
        hex: hex::encode(crypto::hash_text(
            config::INTERNAL_KEYS_HASH,
            &canonical_routes,
        )?),
    };
    let created_at = validation::current_timestamp()?;
    let info = validation::build_aad(&[
        ("version", "v1"),
        ("type", ROUTES_TOKEN_TYPE),
        ("path", &routes_path.display().to_string()),
    ]);
    let payload = TimestampPayload {
        token_type: String::from(ROUTES_TOKEN_TYPE),
        serial: create_payload_serial(&created_at)?,
        created_at,
        info,
        kid: String::from(INIT_KEYS_KID),
        message_hash,
    };
    let signatures = sign_hybrid_payload(
        &payload,
        init_state.init_keys.keys().eddsa(),
        init_state.init_keys.keys().ml_dsa(),
    )?;

    Ok(TimestampToken {
        version: String::from("v1"),
        payload,
        signatures,
    })
}

pub fn verify_routes_file_signature(
    init_state: &ValidatedInitState,
    routes_path: &Path,
    routes_content: &str,
    signature_content: &str,
) -> Result<(), DynError> {
    let token = parse_timestamp_token(serde_json::from_str(signature_content).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("routes signature must be valid JSON: {err}"),
        )) as DynError
    })?)?;
    validate_signed_payload_token(&token, ROUTES_TOKEN_TYPE, INIT_KEYS_KID)?;
    let expected_info = validation::build_aad(&[
        ("version", "v1"),
        ("type", ROUTES_TOKEN_TYPE),
        ("path", &routes_path.display().to_string()),
    ]);
    if token.payload.info != expected_info {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "routes signature payload.info does not match routes path",
        )));
    }

    let canonical_routes = routes::canonical_routes_json(routes_content)?;
    let expected_hash = hex::encode(crypto::hash_text(
        config::INTERNAL_KEYS_HASH,
        &canonical_routes,
    )?);
    if token.payload.message_hash.alg != config::INTERNAL_KEYS_HASH
        || token.payload.message_hash.hex != expected_hash
    {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "routes signature message_hash does not match routes content",
        )));
    }

    let status = verify_hybrid_payload(
        &token.payload,
        &token.signatures,
        init_state.init_keys.keys().eddsa(),
        init_state.init_keys.keys().ml_dsa(),
    )?;
    if status.eddsa != "ok" || status.ml_dsa != "ok" {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "routes signature verification failed",
        )));
    }

    Ok(())
}

fn create_payload_serial(created_at: &str) -> Result<String, DynError> {
    let random = crypto::random_bytes(PAYLOAD_SERIAL_RANDOM_BYTES)?;
    let material = [created_at.as_bytes(), random.as_slice()].concat();

    Ok(hex::encode(crypto::hash_bytes(
        config::INTERNAL_KEYS_HASH,
        &material,
    )?))
}

fn sign_hybrid_payload(
    payload: &TimestampPayload,
    eddsa: &VariantDerKeyPair,
    ml_dsa: &VariantDerKeyPair,
) -> Result<TimestampSignatures, DynError> {
    let payload_bytes = serde_json::to_vec(payload)?;
    let payload_text = std::str::from_utf8(&payload_bytes)?;
    let eddsa_private_key = crypto::load_private_key_der_hex(eddsa.private_key_der_hex())?;
    let ml_dsa_private_key = crypto::load_private_key_der_hex(ml_dsa.private_key_der_hex())?;
    let eddsa_signature = crypto::sign_message(&eddsa_private_key, payload_text)?;
    let ml_dsa_signature = crypto::sign_ml_dsa_message(&ml_dsa_private_key, payload_text)?;

    Ok(TimestampSignatures {
        eddsa: SignatureBlock {
            alg: eddsa.variant().to_string(),
            sig: hex::encode(eddsa_signature),
        },
        ml_dsa: SignatureBlock {
            alg: ml_dsa.variant().to_string(),
            sig: hex::encode(ml_dsa_signature),
        },
    })
}

fn verify_hybrid_payload(
    payload: &TimestampPayload,
    signatures: &TimestampSignatures,
    eddsa: &VariantDerKeyPair,
    ml_dsa: &VariantDerKeyPair,
) -> Result<VerificationStatus, DynError> {
    let payload_bytes = serde_json::to_vec(payload)?;
    let payload_text = std::str::from_utf8(&payload_bytes)?;
    let eddsa_public_key = crypto::load_public_key_der_hex(eddsa.public_key_der_hex())?;
    let ml_dsa_public_key = crypto::load_public_key_der_hex(ml_dsa.public_key_der_hex())?;
    let eddsa_signature = hex::decode(&signatures.eddsa.sig)?;
    let ml_dsa_signature = hex::decode(&signatures.ml_dsa.sig)?;
    let eddsa_valid = crypto::verify_message(&eddsa_public_key, payload_text, &eddsa_signature)?;
    let ml_dsa_valid =
        crypto::verify_ml_dsa_message(&ml_dsa_public_key, payload_text, &ml_dsa_signature)?;

    Ok(VerificationStatus {
        eddsa: status_text(eddsa_valid),
        ml_dsa: status_text(ml_dsa_valid),
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
    validation::validate_allowed_value(
        "message_hash.alg",
        &input.message_hash.alg,
        crypto::HASH_ALGORITHMS,
    )?;
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

    let eddsa = loaded_key.keys().eddsa();
    let ml_dsa = loaded_key.keys().ml_dsa();
    debug!(
        kid = %loaded_key.id(),
        "timestamp verification material loaded"
    );
    let status = verify_hybrid_payload(&token.payload, &token.signatures, eddsa, ml_dsa)?;
    let eddsa_valid = status.eddsa == "ok";
    let ml_dsa_valid = status.ml_dsa == "ok";
    info!(
        kid = %loaded_key.id(),
        eddsa = status_text(eddsa_valid),
        ml_dsa = status_text(ml_dsa_valid),
        valid = eddsa_valid && ml_dsa_valid,
        "timestamp token verified"
    );

    if !eddsa_valid || !ml_dsa_valid {
        return Ok(VerificationOutput {
            status,
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
    validate_signed_payload_token(token, TIMESTAMP_TOKEN_TYPE, &token.payload.kid)?;
    validation::validate_hash_hex_field(
        "payload.kid",
        &token.payload.kid,
        crate::core::config::INTERNAL_KEYS_HASH,
    )?;

    Ok(())
}

fn validate_signed_payload_token(
    token: &TimestampToken,
    expected_type: &str,
    expected_kid: &str,
) -> Result<(), DynError> {
    validation::validate_allowed_value("version", &token.version, &["v1"])?;
    validation::validate_allowed_value(
        "payload.type",
        &token.payload.token_type,
        &[expected_type],
    )?;
    validation::validate_text_field("payload.created_at", &token.payload.created_at)?;
    validation::validate_text_field("payload.info", &token.payload.info)?;
    if token.payload.kid != expected_kid {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload.kid does not match expected signer",
        )));
    }
    validation::validate_hex_field("payload.serial", &token.payload.serial)?;
    let expected_serial_len = crypto::hash_bytes(config::INTERNAL_KEYS_HASH, &[])?.len() * 2;
    if token.payload.serial.len() != expected_serial_len {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "payload.serial must be {expected_serial_len} hex characters, got {}",
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
