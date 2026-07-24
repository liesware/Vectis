use crate::core::remote_routes::PeerPublicKeys;
use crate::core::{canonical, config, config_file, crypto, protocol, validation};
use crate::error::DynError;
use crate::ops::contracts::{MessageHash, TimestampPayload, VerificationStatus};
use crate::ops::init::ValidatedInitState;
use crate::ops::key_material::VariantDerKeyPair;
use crate::ops::keys::{self, LoadedOpsKey};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use tracing::{debug, info};

pub use crate::ops::contracts::{SignInput, TimestampToken, VerificationOutput};

const TIMESTAMP_TOKEN_TYPE: &str = "vectis-sign";
const CONFIG_TOKEN_TYPE: &str = "vectis-config";
const INIT_KEYS_KID: &str = "init-keys";
const PAYLOAD_SERIAL_RANDOM_BYTES: usize = 32;
const COMPACT_SIGNATURE_VERSION: &str = "vectis-signature-v1";
const COMPACT_SIGNATURE_SEGMENTS: usize = 4;
const COMPACT_SIGNATURE_MAX_CHARS: usize = 64 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompactSignatureFile {
    pub signature: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompactSignatureToken {
    pub kid: String,
    pub signature: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompactSignatureHeader {
    version: String,
}

#[derive(Debug)]
struct CompactSignatureParts<'a> {
    header: &'a str,
    payload: &'a str,
    header_bytes: Vec<u8>,
    payload_bytes: Vec<u8>,
    eddsa_signature_bytes: Vec<u8>,
    ml_dsa_signature_bytes: Vec<u8>,
}

enum CompactSignatureFailure {
    MlDsaFailed,
    EdDsaFailed,
}

enum CompactSignatureVerification<T> {
    Valid(T),
    Invalid(CompactSignatureFailure),
}

pub struct ValidatedSignInput {
    input: SignInput,
}

fn sign_timestamp(
    loaded_key: &LoadedOpsKey,
    input: ValidatedSignInput,
) -> Result<CompactSignatureToken, DynError> {
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
    let signature = sign_compact_hybrid_payload(&mut rng, &payload, eddsa, ml_dsa)?;
    info!(
        kid = %loaded_key.id(),
        hash_alg = %payload.message_hash.alg,
        created_at = %payload.created_at,
        serial = %payload.serial,
        eddsa_alg = %eddsa.variant(),
        ml_dsa_alg = %ml_dsa.variant(),
        "timestamp token signed"
    );

    Ok(CompactSignatureToken {
        kid: loaded_key.id().to_string(),
        signature,
    })
}

pub fn sign_config_file(
    init_state: &ValidatedInitState,
    _config_path: &Path,
    config_content: &str,
) -> Result<CompactSignatureFile, DynError> {
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
    let signature = sign_compact_hybrid_payload(
        &mut rng,
        &payload,
        init_state.init_keys.keys().eddsa(),
        init_state.init_keys.keys().ml_dsa(),
    )?;

    Ok(CompactSignatureFile { signature })
}

pub fn verify_config_file_signature(
    init_state: &ValidatedInitState,
    _config_path: &Path,
    config_content: &str,
    signature_content: &str,
) -> Result<(), DynError> {
    let signature_file: CompactSignatureFile =
        serde_json::from_str(signature_content).map_err(|_| {
            crate::error::invalid_input(
                "unsupported config signature format; run 'vectis config sign'",
            )
        })?;
    let payload: TimestampPayload = verify_compact_hybrid_signature(
        &signature_file.signature,
        init_state.init_keys.keys().eddsa(),
        init_state.init_keys.keys().ml_dsa(),
    )
    .map_err(|_| crate::error::invalid_signature("config signature verification failed"))?;
    validate_config_signature_payload(&payload)?;
    let expected_info = config_token_info()?;
    if payload.info != expected_info {
        return Err(crate::error::invalid_input(
            "config signature payload.info does not match config token",
        ));
    }

    let canonical_config = config_file::canonical_config_json(config_content)?;
    let expected_hash = hex::encode(crypto::hash_text(
        config::INTERNAL_KEYS_HASH,
        &canonical_config,
    )?);
    if payload.message_hash.alg != config::INTERNAL_KEYS_HASH
        || payload.message_hash.hex != expected_hash
    {
        return Err(crate::error::config_signature_stale(
            "config signature message_hash does not match config content",
        ));
    }

    Ok(())
}

fn validate_signed_payload_fields(
    payload: &TimestampPayload,
    expected_type: &str,
    check_kid: impl Fn(&str) -> Result<(), DynError>,
) -> Result<(), DynError> {
    protocol::validate_protocol_version("payload.version", &payload.version)?;
    validation::validate_allowed_value("payload.type", &payload.token_type, &[expected_type])?;
    validation::validate_text_field("payload.created_at", &payload.created_at)?;
    validation::validate_text_field("payload.info", &payload.info)?;
    check_kid(&payload.kid)?;
    validation::validate_hex_field("payload.serial", &payload.serial)?;
    let expected_serial_len = crypto::hash_bytes(config::INTERNAL_KEYS_HASH, &[])?.len() * 2;
    if payload.serial.len() != expected_serial_len {
        return Err(crate::error::invalid_input(format!(
            "payload.serial must be {expected_serial_len} hex characters, got {}",
            payload.serial.len()
        )));
    }
    validate_message_hash(&payload.message_hash)
}

fn validate_config_signature_payload(payload: &TimestampPayload) -> Result<(), DynError> {
    validate_signed_payload_fields(payload, CONFIG_TOKEN_TYPE, |kid| {
        if kid != INIT_KEYS_KID {
            return Err(crate::error::invalid_input(
                "payload.kid does not match expected signer",
            ));
        }
        Ok(())
    })
}

pub(crate) fn sign_compact_hybrid_payload<T: Serialize>(
    rng: &mut crypto::CryptoRng,
    payload: &T,
    eddsa: &VariantDerKeyPair,
    ml_dsa: &VariantDerKeyPair,
) -> Result<String, DynError> {
    let header = CompactSignatureHeader {
        version: COMPACT_SIGNATURE_VERSION.to_string(),
    };
    let header = URL_SAFE_NO_PAD.encode(canonical::canonical_json_v1(&header)?);
    let payload = URL_SAFE_NO_PAD.encode(canonical::canonical_json_v1(payload)?);
    let signing_input = format!("{header}.{payload}");
    let eddsa_private_key = crypto::load_private_key_der_hex(eddsa.private_key_der_hex())?;
    let ml_dsa_private_key = crypto::load_private_key_der_hex(ml_dsa.private_key_der_hex())?;
    let eddsa_signature = crypto::sign_message_with_rng(rng, &eddsa_private_key, &signing_input)?;
    let ml_dsa_signature =
        crypto::sign_ml_dsa_message_with_rng(rng, &ml_dsa_private_key, &signing_input)?;

    let signature = format!(
        "{signing_input}.{}.{}",
        URL_SAFE_NO_PAD.encode(eddsa_signature),
        URL_SAFE_NO_PAD.encode(ml_dsa_signature),
    );
    if signature.len() > COMPACT_SIGNATURE_MAX_CHARS {
        return Err(crate::error::internal(
            "compact signature exceeds the maximum supported size",
        ));
    }

    Ok(signature)
}

pub(crate) fn verify_compact_hybrid_signature<T>(
    signature: &str,
    eddsa: &VariantDerKeyPair,
    ml_dsa: &VariantDerKeyPair,
) -> Result<T, DynError>
where
    T: DeserializeOwned + Serialize,
{
    match verify_compact_hybrid_signature_with_public_keys(
        signature,
        eddsa.public_key_der_hex(),
        ml_dsa.public_key_der_hex(),
    )? {
        CompactSignatureVerification::Valid(payload) => Ok(payload),
        CompactSignatureVerification::Invalid(CompactSignatureFailure::MlDsaFailed) => Err(
            crate::error::invalid_signature("compact signature ML-DSA verification failed"),
        ),
        CompactSignatureVerification::Invalid(CompactSignatureFailure::EdDsaFailed) => Err(
            crate::error::invalid_signature("compact signature EdDSA verification failed"),
        ),
    }
}

fn verify_compact_hybrid_signature_with_public_keys<T>(
    signature: &str,
    eddsa_public_key_der_hex: &str,
    ml_dsa_public_key_der_hex: &str,
) -> Result<CompactSignatureVerification<T>, DynError>
where
    T: DeserializeOwned + Serialize,
{
    let parts = split_compact_signature(signature)?;
    let signing_input = format!("{}.{}", parts.header, parts.payload);

    let ml_dsa_public_key = crypto::load_public_key_der_hex(ml_dsa_public_key_der_hex)?;
    if !crypto::verify_ml_dsa_message(
        &ml_dsa_public_key,
        &signing_input,
        &parts.ml_dsa_signature_bytes,
    )? {
        return Ok(CompactSignatureVerification::Invalid(
            CompactSignatureFailure::MlDsaFailed,
        ));
    }

    let eddsa_public_key = crypto::load_public_key_der_hex(eddsa_public_key_der_hex)?;
    if !crypto::verify_message(
        &eddsa_public_key,
        &signing_input,
        &parts.eddsa_signature_bytes,
    )? {
        return Ok(CompactSignatureVerification::Invalid(
            CompactSignatureFailure::EdDsaFailed,
        ));
    }

    let header: CompactSignatureHeader = parse_canonical_compact_segment(&parts.header_bytes)?;
    if header.version != COMPACT_SIGNATURE_VERSION {
        return Err(crate::error::invalid_signature(
            "compact signature version is not supported",
        ));
    }

    Ok(CompactSignatureVerification::Valid(
        parse_canonical_compact_segment(&parts.payload_bytes)?,
    ))
}

fn split_compact_signature(signature: &str) -> Result<CompactSignatureParts<'_>, DynError> {
    if signature.is_empty()
        || signature.len() > COMPACT_SIGNATURE_MAX_CHARS
        || !signature.is_ascii()
        || signature.chars().any(char::is_whitespace)
        || signature.chars().any(char::is_control)
    {
        return Err(crate::error::invalid_signature(
            "compact signature is malformed",
        ));
    }
    let segments: Vec<_> = signature.split('.').collect();
    if segments.len() != COMPACT_SIGNATURE_SEGMENTS
        || segments.iter().any(|segment| segment.is_empty())
    {
        return Err(crate::error::invalid_signature(
            "compact signature is malformed",
        ));
    }

    Ok(CompactSignatureParts {
        header: segments[0],
        payload: segments[1],
        header_bytes: decode_compact_segment(segments[0])?,
        payload_bytes: decode_compact_segment(segments[1])?,
        eddsa_signature_bytes: decode_compact_segment(segments[2])?,
        ml_dsa_signature_bytes: decode_compact_segment(segments[3])?,
    })
}

fn decode_compact_segment(segment: &str) -> Result<Vec<u8>, DynError> {
    URL_SAFE_NO_PAD.decode(segment).map_err(|_| {
        crate::error::invalid_signature("compact signature contains invalid base64url")
    })
}

fn parse_canonical_compact_segment<T>(bytes: &[u8]) -> Result<T, DynError>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(bytes)
        .map_err(|_| crate::error::invalid_signature("compact signature contains invalid JSON"))?;
    if canonical::canonical_json_v1(&value)? != bytes {
        return Err(crate::error::invalid_signature(
            "compact signature JSON is not canonical",
        ));
    }

    Ok(value)
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

pub fn parse_sign_input(request: Value) -> Result<SignInput, DynError> {
    debug!("parsing sign request");

    crate::ops::json::parse_json_request(request, "sign request")
}

pub(crate) fn sign_timestamp_with_loaded_key(
    loaded_key: &LoadedOpsKey,
    input: SignInput,
) -> Result<CompactSignatureToken, DynError> {
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

pub fn parse_compact_signature_token(request: Value) -> Result<CompactSignatureToken, DynError> {
    let token: CompactSignatureToken =
        crate::ops::json::parse_json_request(request, "compact signature token")?;
    keys::validate_key_id(&token.kid)
        .map_err(|err| crate::error::invalid_input(format!("kid is invalid: {err}")))?;
    Ok(token)
}

pub(crate) fn verify_compact_timestamp_with_loaded_key(
    loaded_key: &LoadedOpsKey,
    token: &CompactSignatureToken,
) -> Result<VerificationOutput, DynError> {
    keys::require_lifecycle_for_decrypt_or_verify(loaded_key)?;
    let result = verify_compact_timestamp_with_public_keys(
        token,
        loaded_key.keys().eddsa().public_key_der_hex(),
        loaded_key.keys().ml_dsa().public_key_der_hex(),
    )?;

    match result {
        CompactSignatureVerification::Valid(payload) => {
            validate_compact_timestamp_payload(&payload, &token.kid)?;
            if payload.info != loaded_key.aad() {
                return Err(crate::error::invalid_input(
                    "payload.info does not match loaded key aad",
                ));
            }
            Ok(verification_ok())
        }
        CompactSignatureVerification::Invalid(failure) => Ok(verification_failure(failure)),
    }
}

pub fn verify_compact_timestamp_with_peer_keys(
    token: &CompactSignatureToken,
    peer: &PeerPublicKeys,
) -> Result<VerificationOutput, DynError> {
    let result = verify_compact_timestamp_with_public_keys(
        token,
        &peer.eddsa.public_key_der_hex,
        &peer.ml_dsa.public_key_der_hex,
    )?;

    match result {
        CompactSignatureVerification::Valid(payload) => {
            validate_compact_timestamp_payload(&payload, &token.kid)?;
            Ok(verification_ok())
        }
        CompactSignatureVerification::Invalid(failure) => Ok(verification_failure(failure)),
    }
}

fn verify_compact_timestamp_with_public_keys(
    token: &CompactSignatureToken,
    eddsa_public_key_der_hex: &str,
    ml_dsa_public_key_der_hex: &str,
) -> Result<CompactSignatureVerification<TimestampPayload>, DynError> {
    verify_compact_hybrid_signature_with_public_keys(
        &token.signature,
        eddsa_public_key_der_hex,
        ml_dsa_public_key_der_hex,
    )
}

fn validate_compact_timestamp_payload(
    payload: &TimestampPayload,
    expected_kid: &str,
) -> Result<(), DynError> {
    validate_signed_payload_fields(payload, TIMESTAMP_TOKEN_TYPE, |kid| {
        if kid != expected_kid {
            return Err(crate::error::invalid_input(
                "payload.kid does not match request kid",
            ));
        }
        keys::validate_key_id(kid)
            .map_err(|err| crate::error::invalid_input(format!("payload.kid is invalid: {err}")))
    })
}

fn verification_ok() -> VerificationOutput {
    VerificationOutput {
        status: VerificationStatus {
            eddsa: String::from("ok"),
            ml_dsa: String::from("ok"),
        },
        valid: String::from("ok"),
    }
}

fn verification_failure(failure: CompactSignatureFailure) -> VerificationOutput {
    match failure {
        CompactSignatureFailure::MlDsaFailed => VerificationOutput {
            status: VerificationStatus {
                eddsa: String::from("not_checked"),
                ml_dsa: String::from("fail"),
            },
            valid: String::from("fail"),
        },
        CompactSignatureFailure::EdDsaFailed => VerificationOutput {
            status: VerificationStatus {
                eddsa: String::from("fail"),
                ml_dsa: String::from("ok"),
            },
            valid: String::from("fail"),
        },
    }
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

    #[test]
    fn config_token_info_keeps_legacy_format() {
        let actual = config_token_info().expect("config token info must build");
        let expected = validation::build_aad(&[
            ("version", protocol::PROTOCOL_VERSION_V1),
            ("type", CONFIG_TOKEN_TYPE),
        ]);

        assert_eq!(actual, expected);
    }

    fn compact_timestamp_payload(kid: &str) -> TimestampPayload {
        TimestampPayload {
            version: String::from("v1"),
            token_type: String::from(TIMESTAMP_TOKEN_TYPE),
            created_at: String::from("2024-01-01T00:00:00Z"),
            info: String::from("type=ops-keys"),
            kid: kid.to_string(),
            serial: hex64('b'),
            message_hash: MessageHash {
                alg: String::from("BLAKE2b(256)"),
                hex: hex64('c'),
            },
        }
    }

    #[test]
    fn compact_runtime_signature_round_trips_and_reports_ordered_failures() {
        let init_state = init_state();
        let kid = hex64('a');
        let payload = compact_timestamp_payload(&kid);
        let mut rng = crypto::new_rng().expect("rng must initialize");
        let signature = sign_compact_hybrid_payload(
            &mut rng,
            &payload,
            init_state.init_keys.keys().eddsa(),
            init_state.init_keys.keys().ml_dsa(),
        )
        .expect("timestamp payload must sign");
        let token = CompactSignatureToken {
            kid: kid.clone(),
            signature,
        };

        let verified = verify_compact_hybrid_signature_with_public_keys::<TimestampPayload>(
            &token.signature,
            init_state.init_keys.keys().eddsa().public_key_der_hex(),
            init_state.init_keys.keys().ml_dsa().public_key_der_hex(),
        )
        .expect("compact signature must verify");
        assert!(matches!(verified, CompactSignatureVerification::Valid(_)));

        let mut segments: Vec<String> = token.signature.split('.').map(str::to_string).collect();
        let replacement = if segments[3].starts_with('A') {
            "B"
        } else {
            "A"
        };
        segments[3].replace_range(0..1, replacement);
        let invalid_ml_dsa = verify_compact_hybrid_signature_with_public_keys::<TimestampPayload>(
            &segments.join("."),
            init_state.init_keys.keys().eddsa().public_key_der_hex(),
            init_state.init_keys.keys().ml_dsa().public_key_der_hex(),
        )
        .expect("well-formed tampered signature must be checked");
        let failure = match invalid_ml_dsa {
            CompactSignatureVerification::Invalid(failure) => failure,
            CompactSignatureVerification::Valid(_) => {
                panic!("tampered signature must not verify")
            }
        };
        let output = verification_failure(failure);
        assert_eq!(output.valid, "fail");
        assert_eq!(output.status.ml_dsa, "fail");
        assert_eq!(output.status.eddsa, "not_checked");
    }

    fn config_signature_content(signature: &CompactSignatureFile) -> String {
        serde_json::to_string(signature).expect("compact signature must serialize")
    }

    fn config_payload(signature: &CompactSignatureFile) -> TimestampPayload {
        let payload = signature
            .signature
            .split('.')
            .nth(1)
            .expect("compact signature must contain a payload");
        serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(payload)
                .expect("payload must use base64url"),
        )
        .expect("payload must be valid JSON")
    }

    fn sign_config_payload(
        init_state: &ValidatedInitState,
        payload: &TimestampPayload,
    ) -> CompactSignatureFile {
        let mut rng = crypto::new_rng().expect("rng must initialize");
        CompactSignatureFile {
            signature: sign_compact_hybrid_payload(
                &mut rng,
                payload,
                init_state.init_keys.keys().eddsa(),
                init_state.init_keys.keys().ml_dsa(),
            )
            .expect("payload must sign"),
        }
    }

    fn tamper_compact_segment(
        signature: &CompactSignatureFile,
        index: usize,
    ) -> CompactSignatureFile {
        let mut segments: Vec<String> =
            signature.signature.split('.').map(str::to_string).collect();
        let first = segments[index]
            .chars()
            .next()
            .expect("compact segments must be non-empty");
        segments[index].replace_range(0..first.len_utf8(), if first == 'A' { "B" } else { "A" });

        CompactSignatureFile {
            signature: segments.join("."),
        }
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
        let wrapper: Value = serde_json::from_str(&config_signature_content(&token)).unwrap();
        let signature = wrapper["signature"]
            .as_str()
            .expect("signature wrapper must contain a string");
        let segments: Vec<_> = signature.split('.').collect();
        assert_eq!(segments.len(), COMPACT_SIGNATURE_SEGMENTS);
        let header: CompactSignatureHeader = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(segments[0])
                .expect("header must decode"),
        )
        .expect("header must parse");
        assert_eq!(header.version, COMPACT_SIGNATURE_VERSION);
        let payload = config_payload(&token);
        assert_eq!(payload.info, "version=v1;type=vectis-config");
        assert_eq!(
            canonical::canonical_json_v1(&payload).unwrap(),
            URL_SAFE_NO_PAD.decode(segments[1]).unwrap()
        );
        let signature_content = config_signature_content(&token);

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
        let token = sign_config_file(&init_state, &PathBuf::from("config.json"), empty_config())
            .expect("config must sign");
        let mut payload = config_payload(&token);
        payload.info = String::from("version=v1;type=vectis-config;path=config.json");
        let signature_content =
            config_signature_content(&sign_config_payload(&init_state, &payload));

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
        let signature_content = config_signature_content(&token);
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
        let token = sign_config_file(&init_state, &PathBuf::from("config.json"), empty_config())
            .expect("config must sign");
        for index in 0..COMPACT_SIGNATURE_SEGMENTS {
            let signature_content =
                config_signature_content(&tamper_compact_segment(&token, index));
            let err = verify_config_file_signature(
                &init_state,
                &PathBuf::from("config.json"),
                empty_config(),
                &signature_content,
            )
            .expect_err("tampered signature must fail");

            assert_eq!(err.to_string(), "config signature verification failed");
        }
    }

    #[test]
    fn config_signature_checks_signature_before_content_staleness() {
        let init_state = init_state();
        let token = sign_config_file(&init_state, &PathBuf::from("config.json"), empty_config())
            .expect("config must sign");
        let signature_content = config_signature_content(&tamper_compact_segment(&token, 3));
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

    #[test]
    fn config_signature_rejects_legacy_timestamp_envelope() {
        let legacy = serde_json::to_string(&token("Ed25519", "ML-DSA-44", "v1"))
            .expect("legacy token must serialize");
        let err = verify_config_file_signature(
            &init_state(),
            &PathBuf::from("config.json"),
            empty_config(),
            &legacy,
        )
        .expect_err("legacy config signature format must be rejected");

        assert_eq!(
            err.to_string(),
            "unsupported config signature format; run 'vectis config sign'"
        );
    }

    #[test]
    fn compact_signature_rejects_padding_and_extra_segments() {
        let init_state = init_state();
        let token = sign_config_file(&init_state, &PathBuf::from("config.json"), empty_config())
            .expect("config must sign");
        for malformed in [
            format!("{}=", token.signature),
            format!("{}.extra", token.signature),
        ] {
            let content = config_signature_content(&CompactSignatureFile {
                signature: malformed,
            });
            let err = verify_config_file_signature(
                &init_state,
                &PathBuf::from("config.json"),
                empty_config(),
                &content,
            )
            .expect_err("malformed compact signature must fail");
            assert_eq!(err.to_string(), "config signature verification failed");
        }
    }

    #[test]
    fn compact_signature_validates_every_segment_as_base64url_before_verification() {
        let token = sign_config_file(&init_state(), &PathBuf::from("config.json"), empty_config())
            .expect("config must sign");

        for index in 0..COMPACT_SIGNATURE_SEGMENTS {
            let mut segments: Vec<String> =
                token.signature.split('.').map(str::to_string).collect();
            segments[index] = String::from("!");

            let err = split_compact_signature(&segments.join("."))
                .expect_err("invalid base64url must fail during structural validation");
            assert_eq!(
                err.to_string(),
                "compact signature contains invalid base64url"
            );
        }
    }

    #[test]
    fn config_signature_rejects_authenticated_payload_with_invalid_fields() {
        let init_state = init_state();
        let token = sign_config_file(&init_state, &PathBuf::from("config.json"), empty_config())
            .expect("config must sign");

        let mut wrong_kid = config_payload(&token);
        wrong_kid.kid = String::from("not-init-keys");
        let content = config_signature_content(&sign_config_payload(&init_state, &wrong_kid));
        let err = verify_config_file_signature(
            &init_state,
            &PathBuf::from("config.json"),
            empty_config(),
            &content,
        )
        .expect_err("payload with wrong kid must be rejected");
        assert_eq!(
            err.to_string(),
            "payload.kid does not match expected signer"
        );

        let mut short_serial = config_payload(&token);
        short_serial.serial = String::from("abcd");
        let content = config_signature_content(&sign_config_payload(&init_state, &short_serial));
        let err = verify_config_file_signature(
            &init_state,
            &PathBuf::from("config.json"),
            empty_config(),
            &content,
        )
        .expect_err("payload with short serial must be rejected");
        assert!(err.to_string().contains("payload.serial must be"));
    }

    proptest! {
        #[test]
        fn compact_signature_structure_handles_arbitrary_text(signature in ".{0,256}") {
            let _ = split_compact_signature(&signature);
        }

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
    }
}
