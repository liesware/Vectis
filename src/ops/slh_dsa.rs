use crate::core::{canonical, config, crypto, validation};
use crate::error::DynError;
use crate::ops::init::ValidatedInitState;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

const PRIVATE_FILE_VERSION: &str = "vectis-slh-private-key-v1";
const PUBLIC_FILE_VERSION: &str = "vectis-slh-public-key-v1";
const SIGNATURE_VERSION: &str = "vectis-slh-dsa-signature-v1";
const PAYLOAD_VERSION: &str = "v1";
const ARTIFACT_TYPE: &str = "vectis-artifact";
const PUBLIC_KEY_TYPE: &str = "slh-dsa-public-key";
const PRIVATE_KEY_TYPE: &str = "slh-dsa-private-key";
const SIGNATURE_INFO: &str = "version=v1;type=vectis-artifact";

#[derive(Serialize)]
pub struct CreateOutput {
    pub kid: String,
    pub algorithm: String,
}

#[derive(Serialize)]
pub struct SignOutput {
    pub kid: String,
    pub algorithm: String,
    pub message_hash_alg: String,
    pub message_hash: String,
}

#[derive(Serialize)]
pub struct VerifyOutput {
    pub valid: bool,
    pub kid: String,
    pub algorithm: String,
    pub message_hash_alg: String,
    pub message_hash: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateFile {
    version: String,
    kid: String,
    algorithm: String,
    created_at: String,
    key_enc: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivatePayload {
    version: String,
    kid: String,
    algorithm: String,
    private_key_der_hex: String,
    public_key_der_hex: String,
    created_at: String,
}

impl Zeroize for PrivatePayload {
    fn zeroize(&mut self) {
        self.version.zeroize();
        self.kid.zeroize();
        self.algorithm.zeroize();
        self.private_key_der_hex.zeroize();
        self.public_key_der_hex.zeroize();
        self.created_at.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicFile {
    version: String,
    kid: String,
    algorithm: String,
    public_key_der_hex: String,
    created_at: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureHeader {
    algorithm: String,
    version: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactPayload {
    version: String,
    r#type: String,
    kid: String,
    created_at: String,
    info: String,
    message_hash: MessageHash,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageHash {
    alg: String,
    hex: String,
}

struct LoadedPrivateKey {
    kid: String,
    private_key: botan::Privkey,
}

struct LoadedPublicKey {
    kid: String,
    public_key: botan::Pubkey,
}

struct CompactSignatureParts<'a> {
    header: &'a str,
    payload: &'a str,
    header_bytes: Vec<u8>,
    payload_bytes: Vec<u8>,
    signature_bytes: Vec<u8>,
}

pub fn create(init_state: &ValidatedInitState) -> Result<(CreateOutput, String, String), DynError> {
    let mut rng = crypto::new_rng()?;
    let private_key =
        crypto::create_slh_dsa_private_key_with_rng(&mut rng, config::INTERNAL_SLH_DSA_VARIANT)?;
    let public_key = crypto::public_key(&private_key)?;
    let private_der = Zeroizing::new(crypto::private_key_der(&private_key)?);
    let public_der = crypto::public_key_der(&public_key)?;
    let public_key_der_hex = hex::encode(&public_der);
    let kid = key_id(&public_key_der_hex)?;
    let created_at = validation::current_timestamp()?;
    let payload = Zeroizing::new(PrivatePayload {
        version: PAYLOAD_VERSION.to_string(),
        kid: kid.clone(),
        algorithm: config::INTERNAL_SLH_DSA_VARIANT.to_string(),
        private_key_der_hex: hex::encode(&*private_der),
        public_key_der_hex: public_key_der_hex.clone(),
        created_at: created_at.clone(),
    });
    let key = derive_file_key(init_state)?;
    let aad = private_key_aad(&kid, &created_at)?;
    let key_enc = encrypt_payload(&payload, &key, &aad)?;
    let private_file = PrivateFile {
        version: PRIVATE_FILE_VERSION.to_string(),
        kid: kid.clone(),
        algorithm: config::INTERNAL_SLH_DSA_VARIANT.to_string(),
        created_at: created_at.clone(),
        key_enc,
    };
    let public_file = PublicFile {
        version: PUBLIC_FILE_VERSION.to_string(),
        kid: kid.clone(),
        algorithm: config::INTERNAL_SLH_DSA_VARIANT.to_string(),
        public_key_der_hex,
        created_at,
    };
    Ok((
        CreateOutput {
            kid,
            algorithm: config::INTERNAL_SLH_DSA_VARIANT.to_string(),
        },
        serde_json::to_string_pretty(&private_file)?,
        serde_json::to_string_pretty(&public_file)?,
    ))
}

pub fn sign(
    init_state: &ValidatedInitState,
    private_file_content: &str,
    artifact: &Path,
) -> Result<(SignOutput, String), DynError> {
    let loaded = load_private(init_state, private_file_content)?;
    let hash = artifact_hash(artifact)?;
    let created_at = validation::current_timestamp()?;
    let payload = ArtifactPayload {
        version: PAYLOAD_VERSION.to_string(),
        r#type: ARTIFACT_TYPE.to_string(),
        kid: loaded.kid.clone(),
        created_at,
        info: SIGNATURE_INFO.to_string(),
        message_hash: MessageHash {
            alg: config::INTERNAL_SLH_DSA_ARTIFACT_HASH.to_string(),
            hex: hash.clone(),
        },
    };
    let header = SignatureHeader {
        algorithm: config::INTERNAL_SLH_DSA_VARIANT.to_string(),
        version: SIGNATURE_VERSION.to_string(),
    };
    let header_b64 = URL_SAFE_NO_PAD.encode(canonical::canonical_json_v1(&header)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(canonical::canonical_json_v1(&payload)?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let mut rng = crypto::new_rng()?;
    let signature =
        crypto::sign_slh_dsa_with_rng(&mut rng, &loaded.private_key, signing_input.as_bytes())?;
    drop(loaded); // botan::Privkey::drop borra la clave privada de forma segura
    let compact = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));
    validate_compact_signature_encoding(&compact)?;
    Ok((
        SignOutput {
            kid: payload.kid,
            algorithm: config::INTERNAL_SLH_DSA_VARIANT.to_string(),
            message_hash_alg: config::INTERNAL_SLH_DSA_ARTIFACT_HASH.to_string(),
            message_hash: hash,
        },
        compact,
    ))
}

pub fn verify(
    public_file_content: &str,
    artifact: &Path,
    signature: &str,
) -> Result<VerifyOutput, DynError> {
    let public = load_public(public_file_content)?;
    let parts = split_compact_signature(signature)?;
    let signing_input = format!("{}.{}", parts.header, parts.payload);
    if !crypto::verify_slh_dsa(
        &public.public_key,
        signing_input.as_bytes(),
        &parts.signature_bytes,
    )? {
        return Err(crate::error::invalid_signature(
            "SLH-DSA signature verification failed",
        ));
    }
    let header: SignatureHeader = parse_canonical_segment(&parts.header_bytes)?;
    if header.version != SIGNATURE_VERSION || header.algorithm != config::INTERNAL_SLH_DSA_VARIANT {
        return Err(crate::error::invalid_signature(
            "SLH-DSA signature header is not supported",
        ));
    }
    let payload: ArtifactPayload = parse_canonical_segment(&parts.payload_bytes)?;
    validate_artifact_payload(&payload, &public.kid)?;
    let hash = artifact_hash(artifact)?;
    if !crypto::constant_time_eq(hash.as_bytes(), payload.message_hash.hex.as_bytes()) {
        return Err(crate::error::invalid_signature(
            "artifact hash does not match SLH-DSA signature",
        ));
    }
    Ok(VerifyOutput {
        valid: true,
        kid: public.kid,
        algorithm: config::INTERNAL_SLH_DSA_VARIANT.to_string(),
        message_hash_alg: config::INTERNAL_SLH_DSA_ARTIFACT_HASH.to_string(),
        message_hash: hash,
    })
}

pub fn validate_compact_signature_encoding(signature: &str) -> Result<(), DynError> {
    split_compact_signature(signature).map(|_| ())
}

/// Validates only the encrypted private-file wrapper and envelope encoding.
/// It deliberately does not derive keys, decrypt, or load DER material.
pub fn validate_private_key_file_encoding(content: &str) -> Result<(), DynError> {
    if content.len() > config::SLH_DSA_PRIVATE_FILE_MAX_SIZE_BYTES as usize {
        return Err(crate::error::invalid_input(
            "SLH-DSA private key file exceeds maximum size",
        ));
    }
    let file: PrivateFile = serde_json::from_str(content).map_err(|_| {
        crate::error::invalid_input("SLH-DSA private key file contains invalid JSON")
    })?;
    validate_private_file_structure(&file)?;
    validation::decode_base64_standard_envelope(
        "SLH-DSA private key key_enc",
        &file.key_enc,
        config::SLH_DSA_PRIVATE_FILE_MAX_SIZE_BYTES as usize,
        config::INTERNAL_KEYS_NONCE_SIZE_BYTES,
    )?;
    Ok(())
}

/// Validates only the public-file schema and textual encodings.
/// KID binding and DER loading remain part of `load_public` and therefore do
/// not run in native fuzz loops.
pub fn validate_public_key_file_encoding(content: &str) -> Result<(), DynError> {
    if content.len() > config::SLH_DSA_PUBLIC_FILE_MAX_SIZE_BYTES as usize {
        return Err(crate::error::invalid_input(
            "SLH-DSA public key file exceeds maximum size",
        ));
    }
    let file: PublicFile = serde_json::from_str(content).map_err(|_| {
        crate::error::invalid_input("SLH-DSA public key file contains invalid JSON")
    })?;
    validate_public_file(&file)
}

fn validate_public_file(file: &PublicFile) -> Result<(), DynError> {
    if file.version != PUBLIC_FILE_VERSION || file.algorithm != config::INTERNAL_SLH_DSA_VARIANT {
        return Err(crate::error::invalid_input(
            "SLH-DSA public key file version or algorithm is not supported",
        ));
    }
    validation::validate_hex_field("SLH-DSA public key kid", &file.kid)?;
    validation::validate_hex_field(
        "SLH-DSA public key public_key_der_hex",
        &file.public_key_der_hex,
    )?;
    validation::validate_text_field("SLH-DSA public key created_at", &file.created_at)
}

fn load_private(
    init_state: &ValidatedInitState,
    content: &str,
) -> Result<LoadedPrivateKey, DynError> {
    let file: PrivateFile = serde_json::from_str(content).map_err(|_| {
        crate::error::invalid_input("SLH-DSA private key file contains invalid JSON")
    })?;
    validate_private_file(&file)?;
    let key = derive_file_key(init_state)?;
    let aad = private_key_aad(&file.kid, &file.created_at)?;
    let envelope = validation::decode_base64_standard_envelope(
        "SLH-DSA private key key_enc",
        &file.key_enc,
        config::SLH_DSA_PRIVATE_FILE_MAX_SIZE_BYTES as usize,
        config::INTERNAL_KEYS_NONCE_SIZE_BYTES,
    )?;
    if !crypto::constant_time_eq(&envelope.aad, aad.as_bytes()) {
        return Err(crate::error::invalid_input(
            "SLH-DSA private key AAD does not match metadata",
        ));
    }
    let bytes = Zeroizing::new(crypto::decrypt_symmetric(
        config::INTERNAL_KEYS_CIPHER,
        &envelope.ciphertext,
        &key,
        &envelope.nonce,
        &envelope.aad,
    )?);
    let plaintext = Zeroizing::new(String::from_utf8(bytes.to_vec()).map_err(|_| {
        crate::error::invalid_input("SLH-DSA private key payload is not valid UTF-8")
    })?);
    let payload = Zeroizing::new(serde_json::from_str::<PrivatePayload>(&plaintext).map_err(
        |_| crate::error::invalid_input("SLH-DSA private key payload contains invalid JSON"),
    )?);
    if payload.version != PAYLOAD_VERSION
        || payload.kid != file.kid
        || payload.algorithm != file.algorithm
        || payload.created_at != file.created_at
    {
        return Err(crate::error::invalid_input(
            "SLH-DSA private key metadata does not match payload",
        ));
    }
    validation::validate_hex_field(
        "SLH-DSA private key private_key_der_hex",
        &payload.private_key_der_hex,
    )?;
    validation::validate_hex_field(
        "SLH-DSA private key public_key_der_hex",
        &payload.public_key_der_hex,
    )?;
    let private_key = crypto::load_private_key_der_hex(&payload.private_key_der_hex)
        .map_err(|_| crate::error::invalid_input("SLH-DSA private key DER is invalid"))?;
    let derived_public = crypto::public_key(&private_key)?;
    let derived_hex = hex::encode(crypto::public_key_der(&derived_public)?);
    if !crypto::constant_time_eq(
        derived_hex.as_bytes(),
        payload.public_key_der_hex.as_bytes(),
    ) || key_id(&derived_hex)? != file.kid
    {
        return Err(crate::error::invalid_input(
            "SLH-DSA private key public key binding is invalid",
        ));
    }
    Ok(LoadedPrivateKey {
        kid: file.kid,
        private_key,
    })
}

fn load_public(content: &str) -> Result<LoadedPublicKey, DynError> {
    if content.len() > config::SLH_DSA_PUBLIC_FILE_MAX_SIZE_BYTES as usize {
        return Err(crate::error::invalid_input(
            "SLH-DSA public key file exceeds maximum size",
        ));
    }
    let file: PublicFile = serde_json::from_str(content).map_err(|_| {
        crate::error::invalid_input("SLH-DSA public key file contains invalid JSON")
    })?;
    validate_public_file(&file)?;
    if key_id(&file.public_key_der_hex)? != file.kid {
        return Err(crate::error::invalid_input(
            "SLH-DSA public key kid does not match public key",
        ));
    }
    let public_key = crypto::load_public_key_der_hex(&file.public_key_der_hex)
        .map_err(|_| crate::error::invalid_input("SLH-DSA public key DER is invalid"))?;
    Ok(LoadedPublicKey {
        kid: file.kid,
        public_key,
    })
}

fn validate_private_file(file: &PrivateFile) -> Result<(), DynError> {
    validate_private_file_structure(file)?;
    validation::validate_hash_hex_field(
        "SLH-DSA private key kid",
        &file.kid,
        config::INTERNAL_KEYS_HASH,
    )
}

fn validate_private_file_structure(file: &PrivateFile) -> Result<(), DynError> {
    if file.version != PRIVATE_FILE_VERSION || file.algorithm != config::INTERNAL_SLH_DSA_VARIANT {
        return Err(crate::error::invalid_input(
            "SLH-DSA private key file version or algorithm is not supported",
        ));
    }
    validation::validate_hex_field("SLH-DSA private key kid", &file.kid)?;
    validation::validate_text_field("SLH-DSA private key created_at", &file.created_at)?;
    Ok(())
}

fn derive_file_key(init_state: &ValidatedInitState) -> Result<Zeroizing<Vec<u8>>, DynError> {
    validation::validate_symmetric_key(
        "init symmetric key",
        init_state.symmetric_key_hex(),
        config::INTERNAL_KEYS_KEY_SIZE_BYTES,
    )?;
    let root = Zeroizing::new(hex::decode(init_state.symmetric_key_hex())?);
    Ok(Zeroizing::new(crypto::create_hkdf(
        &root,
        config::INTERNAL_ROOT_KEY_HKDF_SALT,
        config::SLH_DSA_FILE_KEY_INFO,
        config::INTERNAL_KEYS_KEY_SIZE_BYTES,
    )?))
}

fn private_key_aad(kid: &str, created_at: &str) -> Result<String, DynError> {
    validation::build_validated_aad(&[
        ("version", PAYLOAD_VERSION),
        ("type", PRIVATE_KEY_TYPE),
        ("kid", kid),
        ("algorithm", config::INTERNAL_SLH_DSA_VARIANT),
        ("cipher", config::INTERNAL_KEYS_CIPHER),
        ("created_at", created_at),
    ])
}

fn encrypt_payload(payload: &PrivatePayload, key: &[u8], aad: &str) -> Result<String, DynError> {
    let mut value = serde_json::to_value(payload)?;
    let plaintext = Zeroizing::new(String::from_utf8(serde_json::to_vec(&value)?)?);
    zeroize_json_value(&mut value);
    let nonce = Zeroizing::new(crypto::random_bytes(
        config::INTERNAL_KEYS_NONCE_SIZE_BYTES,
    )?);
    let ciphertext = crypto::encrypt_symmetric(
        config::INTERNAL_KEYS_CIPHER,
        &plaintext,
        key,
        &nonce,
        aad.as_bytes(),
    )?;
    Ok(format!(
        "{}.{}.{}",
        STANDARD.encode(ciphertext),
        STANDARD.encode(&*nonce),
        STANDARD.encode(aad.as_bytes())
    ))
}

fn zeroize_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(items) => items.iter_mut().for_each(zeroize_json_value),
        serde_json::Value::Object(entries) => entries.values_mut().for_each(zeroize_json_value),
        _ => {}
    }
}

fn key_id(public_key_der_hex: &str) -> Result<String, DynError> {
    let material = serde_json::json!({"version": PAYLOAD_VERSION, "type": PUBLIC_KEY_TYPE, "algorithm": config::INTERNAL_SLH_DSA_VARIANT, "public_key_der_hex": public_key_der_hex});
    Ok(hex::encode(crypto::hash_bytes(
        config::INTERNAL_KEYS_HASH,
        &canonical::canonical_json_v1(&material)?,
    )?))
}

fn artifact_hash(path: &Path) -> Result<String, DynError> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(crate::error::invalid_input(
            "SLH-DSA artifact input must be a regular file",
        ));
    }
    Ok(hex::encode(crypto::hash_reader(
        config::INTERNAL_SLH_DSA_ARTIFACT_HASH,
        File::open(path)?,
    )?))
}

fn split_compact_signature(signature: &str) -> Result<CompactSignatureParts<'_>, DynError> {
    if signature.is_empty()
        || signature.len() > config::SLH_DSA_SIGNATURE_FILE_MAX_SIZE_BYTES as usize
        || !signature.is_ascii()
        || signature.chars().any(char::is_whitespace)
        || signature.chars().any(char::is_control)
    {
        return Err(crate::error::invalid_signature(
            "SLH-DSA signature is malformed",
        ));
    }
    let segments: Vec<_> = signature.split('.').collect();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        return Err(crate::error::invalid_signature(
            "SLH-DSA signature is malformed",
        ));
    }
    let decode = |segment| {
        URL_SAFE_NO_PAD.decode(segment).map_err(|_| {
            crate::error::invalid_signature("SLH-DSA signature contains invalid base64url")
        })
    };
    Ok(CompactSignatureParts {
        header: segments[0],
        payload: segments[1],
        header_bytes: decode(segments[0])?,
        payload_bytes: decode(segments[1])?,
        signature_bytes: decode(segments[2])?,
    })
}

fn parse_canonical_segment<T>(bytes: &[u8]) -> Result<T, DynError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T = serde_json::from_slice(bytes)
        .map_err(|_| crate::error::invalid_signature("SLH-DSA signature contains invalid JSON"))?;
    if canonical::canonical_json_v1(&value)? != bytes {
        return Err(crate::error::invalid_signature(
            "SLH-DSA signature JSON is not canonical",
        ));
    }
    Ok(value)
}

fn validate_artifact_payload(payload: &ArtifactPayload, kid: &str) -> Result<(), DynError> {
    if payload.version != PAYLOAD_VERSION
        || payload.r#type != ARTIFACT_TYPE
        || payload.kid != kid
        || payload.info != SIGNATURE_INFO
        || payload.message_hash.alg != config::INTERNAL_SLH_DSA_ARTIFACT_HASH
    {
        return Err(crate::error::invalid_signature(
            "SLH-DSA signature payload is not supported",
        ));
    }
    validation::validate_text_field("SLH-DSA signature created_at", &payload.created_at)?;
    validation::validate_hash_hex_field(
        "SLH-DSA signature message_hash.hex",
        &payload.message_hash.hex,
        config::INTERNAL_SLH_DSA_ARTIFACT_HASH,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "vectis-slh-dsa-{name}-{}-{}",
            std::process::id(),
            validation::current_timestamp().expect("timestamp must be available")
        ))
    }

    #[test]
    fn botan_supports_the_configured_slh_dsa_variant_and_randomized_mode() {
        let mut rng = crypto::new_rng().expect("Botan RNG must be available");
        let private =
            crypto::create_slh_dsa_private_key_with_rng(&mut rng, config::INTERNAL_SLH_DSA_VARIANT)
                .expect("configured Botan SLH-DSA variant must be available");
        let public = crypto::public_key(&private).expect("SLH-DSA public key must derive");
        let first = crypto::sign_slh_dsa_with_rng(&mut rng, &private, b"vectis slh dsa test")
            .expect("SLH-DSA signature must succeed");
        let second = crypto::sign_slh_dsa_with_rng(&mut rng, &private, b"vectis slh dsa test")
            .expect("randomized SLH-DSA signature must succeed");
        assert_ne!(first, second);
        assert!(
            crypto::verify_slh_dsa(&public, b"vectis slh dsa test", &first)
                .expect("SLH-DSA verification must succeed")
        );
    }

    #[test]
    fn compact_signature_requires_three_strict_base64url_segments() {
        assert!(validate_compact_signature_encoding("e30.e30.AA").is_ok());
        for signature in [
            "e30.e30",
            "e30..AA",
            "e30.e30.AA=",
            "e30.e30.++",
            "e30.e30.AA.extra",
        ] {
            assert!(
                validate_compact_signature_encoding(signature).is_err(),
                "{signature}"
            );
        }
    }

    #[test]
    fn key_file_encoding_validators_stop_before_decryption_or_der_loading() {
        let private = r#"{"version":"vectis-slh-private-key-v1","kid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","algorithm":"SLH-DSA-SHAKE-256s","created_at":"1","key_enc":"AAAAAAAAAAAAAAAAAAAAAA==.AAAAAAAAAAAAAAAA.dHlwZT10ZXN0"}"#;
        assert!(validate_private_key_file_encoding(private).is_ok());

        let public = r#"{"version":"vectis-slh-public-key-v1","kid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","algorithm":"SLH-DSA-SHAKE-256s","public_key_der_hex":"aa","created_at":"1"}"#;
        assert!(validate_public_key_file_encoding(public).is_ok());
        assert!(validate_public_key_file_encoding(
            r#"{"version":"vectis-slh-public-key-v1","kid":"aa","algorithm":"SLH-DSA-SHAKE-256s","public_key_der_hex":"aa","created_at":"1","extra":true}"#
        )
        .is_err());
    }

    #[test]
    fn key_id_is_bound_to_the_public_key_material() {
        let first = key_id("aabb").expect("kid must derive");
        let second = key_id("ccdd").expect("kid must derive");
        assert_ne!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn encrypted_key_signs_and_public_key_verifies_tampering() {
        let encrypted = crate::ops::init::create_encrypted_init_output_json()
            .expect("init material must be created");
        let init_state = crate::ops::init::load_validated_init_state(
            &encrypted.json,
            &encrypted.encryption_key_hex,
        )
        .expect("init material must load");
        let (created, private_file, public_file) =
            create(&init_state).expect("SLH key files build");
        let artifact = temp_path("artifact");
        fs::write(&artifact, "settlement-v1").expect("artifact must write");
        let (signed, compact) =
            sign(&init_state, &private_file, &artifact).expect("artifact signs");
        let verified = verify(&public_file, &artifact, &compact).expect("artifact verifies");
        assert_eq!(created.kid, signed.kid);
        assert_eq!(signed.kid, verified.kid);
        assert!(verified.valid);

        fs::write(&artifact, "settlement-v2").expect("tampered artifact must write");
        assert!(verify(&public_file, &artifact, &compact).is_err());

        let mut private_value: serde_json::Value =
            serde_json::from_str(&private_file).expect("private JSON parses");
        private_value["created_at"] = serde_json::Value::String(String::from("1"));
        let tampered_private =
            serde_json::to_string(&private_value).expect("private JSON serializes");
        assert!(sign(&init_state, &tampered_private, &artifact).is_err());
        let _ = fs::remove_file(artifact);
    }

    #[test]
    fn verify_rejects_signature_from_a_different_key_pair() {
        let encrypted = crate::ops::init::create_encrypted_init_output_json()
            .expect("init material must be created");
        let init_state = crate::ops::init::load_validated_init_state(
            &encrypted.json,
            &encrypted.encryption_key_hex,
        )
        .expect("init material must load");
        let (_a, private_a, _public_a) = create(&init_state).expect("key pair A builds");
        let (_b, _private_b, public_b) = create(&init_state).expect("key pair B builds");
        let artifact = temp_path("cross-key-artifact");
        fs::write(&artifact, "settlement-v1").expect("artifact must write");
        let (_signed, compact) =
            sign(&init_state, &private_a, &artifact).expect("artifact signs with A");
        assert!(
            verify(&public_b, &artifact, &compact).is_err(),
            "signature from key pair A must not verify under B's public key"
        );
        let _ = fs::remove_file(artifact);
    }

    #[test]
    fn verify_rejects_mutated_payload_segment() {
        let encrypted = crate::ops::init::create_encrypted_init_output_json()
            .expect("init material must be created");
        let init_state = crate::ops::init::load_validated_init_state(
            &encrypted.json,
            &encrypted.encryption_key_hex,
        )
        .expect("init material must load");
        let (_created, private_file, public_file) =
            create(&init_state).expect("SLH key files build");
        let artifact = temp_path("mutated-payload-artifact");
        fs::write(&artifact, "settlement-v1").expect("artifact must write");
        let (_signed, compact) =
            sign(&init_state, &private_file, &artifact).expect("artifact signs");

        let segments: Vec<&str> = compact.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(segments[1])
            .expect("payload segment decodes");

        for mutate in [
            |payload: &mut ArtifactPayload| {
                payload.message_hash.hex = "0".repeat(payload.message_hash.hex.len());
            },
            |payload: &mut ArtifactPayload| {
                payload.kid = "0".repeat(payload.kid.len());
            },
        ] {
            let mut payload: ArtifactPayload =
                serde_json::from_slice(&payload_bytes).expect("payload parses");
            mutate(&mut payload);
            let mutated_payload = URL_SAFE_NO_PAD
                .encode(canonical::canonical_json_v1(&payload).expect("payload re-encodes"));
            let mutated_compact = format!("{}.{}.{}", segments[0], mutated_payload, segments[2]);
            assert!(
                verify(&public_file, &artifact, &mutated_compact).is_err(),
                "mutated payload segment must fail verification"
            );
        }
        let _ = fs::remove_file(artifact);
    }
}
