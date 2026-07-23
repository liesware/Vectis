use crate::core::remote_routes::PeerPublicKeys;
use crate::core::{canonical, config, config_file, crypto, protocol, validation};
use crate::error::DynError;
use crate::ops::contracts::{
    MessageHash, SignatureBlock, TimestampPayload, TimestampSignatures, VerificationStatus,
};
use crate::ops::init::ValidatedInitState;
use crate::ops::key_material::VariantDerKeyPair;
use crate::ops::keys::{self, KeysDbState, LoadedOpsKey};
use serde_json::Value;
use std::path::Path;
use tracing::{debug, info};

pub use crate::ops::contracts::{SignInput, TimestampToken, VerificationOutput};

const TIMESTAMP_TOKEN_TYPE: &str = "vectis-sign";
const CONFIG_TOKEN_TYPE: &str = "vectis-config";
const INIT_KEYS_KID: &str = "init-keys";
const PAYLOAD_SERIAL_RANDOM_BYTES: usize = 32;

pub struct ValidatedSignInput {
    input: SignInput,
}

fn sign_timestamp(
    loaded_key: &LoadedOpsKey,
    input: ValidatedSignInput,
) -> Result<TimestampToken, DynError> {
    keys::require_lifecycle_for_new_use(loaded_key)?;
    debug!(
        kid = %loaded_key.id(),
        hash_alg = %input.input.message_hash.alg,
        hash_hex_len = input.input.message_hash.hex.len(),
        "timestamp signing started"
    );
    let created_at = validation::current_timestamp()?;
    let mut rng = crypto::new_rng()?;
    let payload = TimestampPayload {
        version: protocol::PROTOCOL_VERSION_V1.to_string(),
        token_type: String::from(TIMESTAMP_TOKEN_TYPE),
        serial: create_payload_serial(&mut rng, &created_at)?,
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
    let signatures = sign_hybrid_payload(&mut rng, &payload, eddsa, ml_dsa)?;
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
        version: protocol::PROTOCOL_VERSION_V1.to_string(),
        payload,
        signatures,
    })
}

pub fn sign_config_file(
    init_state: &ValidatedInitState,
    _config_path: &Path,
    config_content: &str,
) -> Result<TimestampToken, DynError> {
    let canonical_config = config_file::canonical_config_json(config_content)?;
    let message_hash = MessageHash {
        alg: config::INTERNAL_KEYS_HASH.to_string(),
        hex: hex::encode(crypto::hash_text(
            config::INTERNAL_KEYS_HASH,
            &canonical_config,
        )?),
    };
    let created_at = validation::current_timestamp()?;
    let mut rng = crypto::new_rng()?;
    let info = config_token_info()?;
    let payload = TimestampPayload {
        version: protocol::PROTOCOL_VERSION_V1.to_string(),
        token_type: String::from(CONFIG_TOKEN_TYPE),
        serial: create_payload_serial(&mut rng, &created_at)?,
        created_at,
        info,
        kid: String::from(INIT_KEYS_KID),
        message_hash,
    };
    let signatures = sign_hybrid_payload(
        &mut rng,
        &payload,
        init_state.init_keys.keys().eddsa(),
        init_state.init_keys.keys().ml_dsa(),
    )?;

    Ok(TimestampToken {
        version: protocol::PROTOCOL_VERSION_V1.to_string(),
        payload,
        signatures,
    })
}

pub fn verify_config_file_signature(
    init_state: &ValidatedInitState,
    _config_path: &Path,
    config_content: &str,
    signature_content: &str,
) -> Result<(), DynError> {
    let token = parse_timestamp_token(serde_json::from_str(signature_content).map_err(|err| {
        crate::error::invalid_input(format!("config signature must be valid JSON: {err}"))
    })?)?;
    validate_signed_payload_token(&token, CONFIG_TOKEN_TYPE, INIT_KEYS_KID)?;
    let expected_info = config_token_info()?;
    if token.payload.info != expected_info {
        return Err(crate::error::invalid_input(
            "config signature payload.info does not match config token",
        ));
    }

    let status = verify_hybrid_payload(
        &token.payload,
        &token.signatures,
        init_state.init_keys.keys().eddsa(),
        init_state.init_keys.keys().ml_dsa(),
    )?;
    if status.eddsa != "ok" || status.ml_dsa != "ok" {
        return Err(crate::error::invalid_signature(
            "config signature verification failed",
        ));
    }

    let canonical_config = config_file::canonical_config_json(config_content)?;
    let expected_hash = hex::encode(crypto::hash_text(
        config::INTERNAL_KEYS_HASH,
        &canonical_config,
    )?);
    if token.payload.message_hash.alg != config::INTERNAL_KEYS_HASH
        || token.payload.message_hash.hex != expected_hash
    {
        return Err(crate::error::config_signature_stale(
            "config signature message_hash does not match config content",
        ));
    }

    Ok(())
}

fn config_token_info() -> Result<String, DynError> {
    validation::build_validated_aad(&[
        ("version", protocol::PROTOCOL_VERSION_V1),
        ("type", CONFIG_TOKEN_TYPE),
    ])
}

fn create_payload_serial(
    rng: &mut crypto::CryptoRng,
    created_at: &str,
) -> Result<String, DynError> {
    let random = crypto::random_bytes_with_rng(rng, PAYLOAD_SERIAL_RANDOM_BYTES)?;
    let material = [created_at.as_bytes(), random.as_slice()].concat();

    Ok(hex::encode(crypto::hash_bytes(
        config::INTERNAL_KEYS_HASH,
        &material,
    )?))
}

fn sign_hybrid_payload(
    rng: &mut crypto::CryptoRng,
    payload: &TimestampPayload,
    eddsa: &VariantDerKeyPair,
    ml_dsa: &VariantDerKeyPair,
) -> Result<TimestampSignatures, DynError> {
    let payload_bytes = canonical::canonical_json_v1(payload)?;
    let payload_text = std::str::from_utf8(&payload_bytes)?;
    let eddsa_private_key = crypto::load_private_key_der_hex(eddsa.private_key_der_hex())?;
    let ml_dsa_private_key = crypto::load_private_key_der_hex(ml_dsa.private_key_der_hex())?;
    let eddsa_signature = crypto::sign_message_with_rng(rng, &eddsa_private_key, payload_text)?;
    let ml_dsa_signature =
        crypto::sign_ml_dsa_message_with_rng(rng, &ml_dsa_private_key, payload_text)?;

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
    verify_payload_with_public_keys(
        payload,
        signatures,
        eddsa.public_key_der_hex(),
        ml_dsa.public_key_der_hex(),
    )
}

fn verify_payload_with_public_keys(
    payload: &TimestampPayload,
    signatures: &TimestampSignatures,
    eddsa_public_key_der_hex: &str,
    ml_dsa_public_key_der_hex: &str,
) -> Result<VerificationStatus, DynError> {
    let payload_bytes = canonical::canonical_json_v1(payload)?;
    let payload_text = std::str::from_utf8(&payload_bytes)?;
    let eddsa_public_key = crypto::load_public_key_der_hex(eddsa_public_key_der_hex)?;
    let ml_dsa_public_key = crypto::load_public_key_der_hex(ml_dsa_public_key_der_hex)?;
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

    crate::ops::json::parse_json_request(request, "sign request")
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

    sign_timestamp(&loaded_key, input)
}

pub(crate) fn sign_timestamp_with_loaded_key(
    loaded_key: &LoadedOpsKey,
    input: SignInput,
) -> Result<TimestampToken, DynError> {
    let input = validate_sign_input(input)?;

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

    serde_json::from_value(request)
        .map_err(|err| crate::error::invalid_input(format!("invalid timestamp token: {err}")))
}

fn verify_timestamp(
    loaded_key: &LoadedOpsKey,
    token: &TimestampToken,
) -> Result<VerificationOutput, DynError> {
    keys::require_lifecycle_for_decrypt_or_verify(loaded_key)?;
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

pub fn verify_timestamp_with_peer_keys(
    token: &TimestampToken,
    peer: &PeerPublicKeys,
) -> Result<VerificationOutput, DynError> {
    validate_timestamp_token(token)?;
    if token.signatures.eddsa.alg != peer.eddsa.alg {
        return Err(crate::error::invalid_input(
            "signatures.eddsa.alg does not match peer public key",
        ));
    }
    if token.signatures.ml_dsa.alg != peer.ml_dsa.alg {
        return Err(crate::error::invalid_input(
            "signatures.ml-dsa.alg does not match peer public key",
        ));
    }

    let status = verify_payload_with_public_keys(
        &token.payload,
        &token.signatures,
        &peer.eddsa.public_key_der_hex,
        &peer.ml_dsa.public_key_der_hex,
    )?;
    let eddsa_valid = status.eddsa == "ok";
    let ml_dsa_valid = status.ml_dsa == "ok";
    info!(
        token_kid = %token.kid(),
        valid = eddsa_valid && ml_dsa_valid,
        "timestamp token verified against peer public keys"
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

    verify_timestamp(&loaded_key, token)
}

pub(crate) fn verify_timestamp_with_loaded_key(
    loaded_key: &LoadedOpsKey,
    token: &TimestampToken,
) -> Result<VerificationOutput, DynError> {
    validate_timestamp_token(token)?;

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
    protocol::validate_protocol_version("version", &token.version)?;
    protocol::validate_protocol_version("payload.version", &token.payload.version)?;
    if token.version != token.payload.version {
        return Err(crate::error::invalid_input(
            "token version does not match signed payload version",
        ));
    }
    validation::validate_allowed_value(
        "payload.type",
        &token.payload.token_type,
        &[expected_type],
    )?;
    validation::validate_text_field("payload.created_at", &token.payload.created_at)?;
    validation::validate_text_field("payload.info", &token.payload.info)?;
    if token.payload.kid != expected_kid {
        return Err(crate::error::invalid_input(
            "payload.kid does not match expected signer",
        ));
    }
    validation::validate_hex_field("payload.serial", &token.payload.serial)?;
    let expected_serial_len = crypto::hash_bytes(config::INTERNAL_KEYS_HASH, &[])?.len() * 2;
    if token.payload.serial.len() != expected_serial_len {
        return Err(crate::error::invalid_input(format!(
            "payload.serial must be {expected_serial_len} hex characters, got {}",
            token.payload.serial.len()
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
        return Err(crate::error::invalid_input(
            "payload.kid does not match loaded key",
        ));
    }
    if token.payload.info != loaded_key.aad() {
        return Err(crate::error::invalid_input(
            "payload.info does not match loaded key aad",
        ));
    }
    if token.signatures.eddsa.alg != loaded_key.keys().eddsa().variant() {
        return Err(crate::error::invalid_input(
            "signatures.eddsa.alg does not match loaded key",
        ));
    }
    if token.signatures.ml_dsa.alg != loaded_key.keys().ml_dsa().variant() {
        return Err(crate::error::invalid_input(
            "signatures.ml-dsa.alg does not match loaded key",
        ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;
    use std::path::PathBuf;

    fn hex64(seed: char) -> String {
        String::from(seed).repeat(64)
    }

    fn init_state() -> ValidatedInitState {
        let encrypted =
            crate::ops::init::create_encrypted_init_output_json().expect("init must be created");
        crate::ops::init::load_validated_init_state(&encrypted.json, &encrypted.encryption_key_hex)
            .expect("init must validate")
    }

    fn empty_config() -> &'static str {
        r#"{"version":"v1","routes":[],"remote_routes":[],"permissions":[]}"#
    }

    fn token(eddsa_alg: &str, ml_dsa_alg: &str, payload_version: &str) -> TimestampToken {
        serde_json::from_value(json!({
            "version": "v1",
            "payload": {
                "version": payload_version,
                "type": "vectis-sign",
                "created_at": "2024-01-01T00:00:00Z",
                "info": "peer-info",
                "kid": hex64('a'),
                "serial": hex64('b'),
                "message_hash": {"alg": "BLAKE2b(256)", "hex": hex64('c')}
            },
            "signatures": {
                "eddsa": {"alg": eddsa_alg, "sig": "aa"},
                "ml-dsa": {"alg": ml_dsa_alg, "sig": "aa"}
            }
        }))
        .unwrap()
    }

    fn token_value() -> serde_json::Value {
        serde_json::to_value(token("Ed25519", "ML-DSA-44", "v1")).unwrap()
    }

    fn peer(eddsa_alg: &str, ml_dsa_alg: &str) -> PeerPublicKeys {
        serde_json::from_value(json!({
            "eddsa": {"alg": eddsa_alg, "public_key_der_hex": "aa"},
            "xecdh": {"alg": "X25519", "public_key_hex": "aa"},
            "ml-dsa": {"alg": ml_dsa_alg, "public_key_der_hex": "aa"},
            "ml-kem": {"alg": "ML-KEM-512", "public_key_der_hex": "aa"}
        }))
        .unwrap()
    }

    #[test]
    fn validate_timestamp_token_accepts_well_formed_token() {
        assert!(validate_timestamp_token(&token("Ed25519", "ML-DSA-44", "v1")).is_ok());
    }

    #[test]
    fn validate_timestamp_token_rejects_wrong_token_type() {
        let mut value = serde_json::to_value(token("Ed25519", "ML-DSA-44", "v1")).unwrap();
        value["payload"]["type"] = json!("vectis-config");
        let token: TimestampToken = serde_json::from_value(value).unwrap();
        assert!(validate_timestamp_token(&token).is_err());
    }

    #[test]
    fn validate_timestamp_token_rejects_unsupported_payload_version() {
        assert!(validate_timestamp_token(&token("Ed25519", "ML-DSA-44", "v2")).is_err());
    }

    #[test]
    fn verify_timestamp_with_peer_keys_rejects_eddsa_alg_mismatch() {
        let token = token("Ed25519", "ML-DSA-44", "v1");
        assert!(verify_timestamp_with_peer_keys(&token, &peer("Ed448", "ML-DSA-44")).is_err());
    }

    #[test]
    fn verify_timestamp_with_peer_keys_rejects_ml_dsa_alg_mismatch() {
        let token = token("Ed25519", "ML-DSA-44", "v1");
        assert!(verify_timestamp_with_peer_keys(&token, &peer("Ed25519", "ML-DSA-65")).is_err());
    }

    #[test]
    fn config_token_info_keeps_legacy_format() {
        let actual = config_token_info().expect("config token info must build");
        let expected = validation::build_aad(&[
            ("version", protocol::PROTOCOL_VERSION_V1),
            ("type", CONFIG_TOKEN_TYPE),
        ]);

        assert_eq!(actual, expected);
    }

    #[test]
    fn config_signature_is_portable_across_paths() {
        let init_state = init_state();
        let token = sign_config_file(
            &init_state,
            &PathBuf::from("/host/path/config.json"),
            empty_config(),
        )
        .expect("config must sign");
        assert_eq!(token.payload.info, "version=v1;type=vectis-config");
        let signature_content = serde_json::to_string(&token).expect("token must serialize");

        verify_config_file_signature(
            &init_state,
            &PathBuf::from("/opt/vectis/conf/config.json"),
            empty_config(),
            &signature_content,
        )
        .expect("config signature must verify from a different path");
    }

    #[test]
    fn config_signature_rejects_wrong_info_token() {
        let init_state = init_state();
        let mut token =
            sign_config_file(&init_state, &PathBuf::from("config.json"), empty_config())
                .expect("config must sign");
        token.payload.info = String::from("version=v1;type=vectis-config;path=config.json");
        let signature_content = serde_json::to_string(&token).expect("token must serialize");

        let err = verify_config_file_signature(
            &init_state,
            &PathBuf::from("/opt/vectis/conf/config.json"),
            empty_config(),
            &signature_content,
        )
        .expect_err("path-bound info must be rejected");

        assert_eq!(
            err.to_string(),
            "config signature payload.info does not match config token"
        );
    }

    #[test]
    fn config_signature_rejects_tampered_config_content() {
        let init_state = init_state();
        let token = sign_config_file(&init_state, &PathBuf::from("config.json"), empty_config())
            .expect("config must sign");
        let signature_content = serde_json::to_string(&token).expect("token must serialize");
        let tampered_config = r#"{"version":"v1","routes":[{"kid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"app","final_app_addr":"127.0.0.1:3999","final_app_path":"/message"}],"remote_routes":[],"permissions":[]}"#;

        let err = verify_config_file_signature(
            &init_state,
            &PathBuf::from("config.json"),
            tampered_config,
            &signature_content,
        )
        .expect_err("tampered config content must fail");

        assert_eq!(
            err.to_string(),
            "config signature message_hash does not match config content"
        );
    }

    #[test]
    fn config_signature_rejects_tampered_signature() {
        let init_state = init_state();
        let mut token =
            sign_config_file(&init_state, &PathBuf::from("config.json"), empty_config())
                .expect("config must sign");
        token.signatures.eddsa.sig.replace_range(0..2, "00");
        let signature_content = serde_json::to_string(&token).expect("token must serialize");

        let err = verify_config_file_signature(
            &init_state,
            &PathBuf::from("config.json"),
            empty_config(),
            &signature_content,
        )
        .expect_err("tampered signature must fail");

        assert_eq!(err.to_string(), "config signature verification failed");
    }

    #[test]
    fn config_signature_checks_signature_before_content_staleness() {
        let init_state = init_state();
        let mut token =
            sign_config_file(&init_state, &PathBuf::from("config.json"), empty_config())
                .expect("config must sign");
        token.signatures.eddsa.sig.replace_range(0..2, "00");
        let signature_content = serde_json::to_string(&token).expect("token must serialize");
        let tampered_config = r#"{"version":"v1","routes":[{"kid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"app","final_app_addr":"127.0.0.1:3999","final_app_path":"/message"}],"remote_routes":[],"permissions":[]}"#;

        let err = verify_config_file_signature(
            &init_state,
            &PathBuf::from("config.json"),
            tampered_config,
            &signature_content,
        )
        .expect_err("invalid signature must fail before content staleness");

        assert_eq!(err.to_string(), "config signature verification failed");
        assert!(!crate::error::is_config_signature_stale(err.as_ref()));
    }

    proptest! {
        #[test]
        fn parse_sign_input_rejects_extra_fields_with_actionable_shape_error(extra_field in ".{1,32}") {
            prop_assume!(extra_field != "message_hash");
            let value = json!({
                "message_hash": {"alg": "SHA-256", "hex": hex64('a')},
                extra_field.clone(): "unexpected"
            });

            let err = match parse_sign_input(value) {
                Ok(_) => panic!("sign input with extra fields must be rejected"),
                Err(err) => err,
            };
            let public_error = err.to_string();

            prop_assert!(public_error.starts_with("invalid sign request:"));
            prop_assert!(public_error.contains("unknown field"));
            let sanitized_field: String = extra_field
                .chars()
                .filter(|c| !c.is_control())
                .collect();
            if !sanitized_field.is_empty() {
                prop_assert!(public_error.contains(&sanitized_field));
            }
            prop_assert!(!public_error.chars().any(char::is_control));
            prop_assert!(!public_error.contains("unexpected"));
        }

        #[test]
        fn validate_message_hash_requires_exact_hash_length(hex in "[0-9a-fA-F]{0,130}") {
            let message_hash = MessageHash {
                alg: String::from("SHA-256"),
                hex,
            };
            let result = validate_message_hash(&message_hash);

            prop_assert_eq!(result.is_ok(), message_hash.hex.len() == 64);
        }

        #[test]
        fn parse_timestamp_token_rejects_extra_fields(suffix in "[A-Za-z0-9_]{1,24}") {
            let extra_field = format!("extra_{suffix}");

            let mut top_level = token_value();
            top_level
                .as_object_mut()
                .unwrap()
                .insert(extra_field.clone(), json!("unexpected"));
            prop_assert!(parse_timestamp_token(top_level).is_err());

            let mut payload = token_value();
            payload["payload"]
                .as_object_mut()
                .unwrap()
                .insert(extra_field.clone(), json!("unexpected"));
            prop_assert!(parse_timestamp_token(payload).is_err());

            let mut signatures = token_value();
            signatures["signatures"]
                .as_object_mut()
                .unwrap()
                .insert(extra_field.clone(), json!("unexpected"));
            prop_assert!(parse_timestamp_token(signatures).is_err());

            let mut eddsa = token_value();
            eddsa["signatures"]["eddsa"]
                .as_object_mut()
                .unwrap()
                .insert(extra_field.clone(), json!("unexpected"));
            prop_assert!(parse_timestamp_token(eddsa).is_err());

            let mut ml_dsa = token_value();
            ml_dsa["signatures"]["ml-dsa"]
                .as_object_mut()
                .unwrap()
                .insert(extra_field, json!("unexpected"));
            prop_assert!(parse_timestamp_token(ml_dsa).is_err());
        }

        #[test]
        fn validate_timestamp_token_rejects_invalid_kid(kid in "[A-Za-z0-9]{0,80}") {
            prop_assume!(kid.len() != 64 || !kid.chars().all(|item| item.is_ascii_hexdigit()));
            let mut token = token("Ed25519", "ML-DSA-44", "v1");
            token.payload.kid = kid;

            prop_assert!(validate_timestamp_token(&token).is_err());
        }

        #[test]
        fn validate_timestamp_token_rejects_invalid_serial(serial in "[A-Za-z0-9]{0,80}") {
            prop_assume!(serial.len() != 64 || !serial.chars().all(|item| item.is_ascii_hexdigit()));
            let mut token = token("Ed25519", "ML-DSA-44", "v1");
            token.payload.serial = serial;

            prop_assert!(validate_timestamp_token(&token).is_err());
        }

        #[test]
        fn validate_timestamp_token_rejects_invalid_signature_fields(
            eddsa_alg in "[A-Za-z0-9_-]{1,24}",
            ml_dsa_alg in "[A-Za-z0-9_-]{1,24}",
            sig in "[A-Za-z0-9_-]{1,32}"
        ) {
            prop_assume!(!["Ed25519", "Ed448"].contains(&eddsa_alg.as_str()));
            prop_assume!(!["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"].contains(&ml_dsa_alg.as_str()));
            prop_assume!(!sig.chars().all(|item| item.is_ascii_hexdigit()) || sig.len() % 2 != 0);

            let invalid_eddsa = token(&eddsa_alg, "ML-DSA-44", "v1");
            prop_assert!(validate_timestamp_token(&invalid_eddsa).is_err());

            let invalid_ml_dsa = token("Ed25519", &ml_dsa_alg, "v1");
            prop_assert!(validate_timestamp_token(&invalid_ml_dsa).is_err());

            let mut invalid_sig = token("Ed25519", "ML-DSA-44", "v1");
            invalid_sig.signatures.eddsa.sig = sig.clone();
            prop_assert!(validate_timestamp_token(&invalid_sig).is_err());

            let mut invalid_ml_sig = token("Ed25519", "ML-DSA-44", "v1");
            invalid_ml_sig.signatures.ml_dsa.sig = sig;
            prop_assert!(validate_timestamp_token(&invalid_ml_sig).is_err());
        }
    }
}
