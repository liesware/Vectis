use crate::core::{crypto, validation};
use crate::error::DynError;
use crate::ops::keys;
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub const TOKENIZATION_VERSION_RANDOM_V1: &str = "token-random-v1";
pub const TOKENIZATION_HKDF_SALT: &[u8] = b"vectis/tokenization/v1";
pub const TOKEN_HASH_KEY_PURPOSE: &str = "token-hash";
pub const TOKEN_DATA_KEY_PURPOSE: &str = "token-data";
pub const TOKEN_KEY_SIZE_BYTES: usize = 32;
pub const TOKEN_LEN_MIN_BYTES: usize = 32;
pub const TOKEN_PLAINTEXT_MAX_LEN: usize = 1024;
pub const TOKEN_METADATA_MAX_CHARS: usize = 128;
pub const TOKEN_PREFIX_MAX_CHARS: usize = 16;
pub const TOKEN_DATA_TYPE: &str = "token-data";

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct TokenizationProfileInput {
    name: String,
    tokenization_version: String,
    kid: String,
    token_prefix: String,
    token_len: usize,
    max_plaintext_len: usize,
}

#[derive(Clone)]
pub struct TokenizationProfile {
    name: String,
    tokenization_version: String,
    kid: String,
    token_prefix: String,
    token_len: usize,
    max_plaintext_len: usize,
    cipher_algorithm: String,
    hash_key: Zeroizing<Vec<u8>>,
    data_key: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Default)]
pub struct TokenizationProfilesState {
    profiles: Vec<TokenizationProfile>,
    by_name: HashMap<String, usize>,
}

pub struct DerivedTokenizationKeys {
    pub hash_key: Zeroizing<Vec<u8>>,
    pub data_key: Zeroizing<Vec<u8>>,
    pub cipher_algorithm: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenDataPayload {
    pub profile: String,
    pub plaintext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    pub created_at: String,
}

impl fmt::Debug for TokenizationProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenizationProfile")
            .field("name", &self.name)
            .field("tokenization_version", &self.tokenization_version)
            .field("kid", &self.kid)
            .field("token_prefix", &self.token_prefix)
            .field("token_len", &self.token_len)
            .field("max_plaintext_len", &self.max_plaintext_len)
            .field("cipher_algorithm", &self.cipher_algorithm)
            .field("hash_key", &"<redacted>")
            .field("data_key", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for TokenizationProfilesState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenizationProfilesState")
            .field("profiles", &self.profiles)
            .finish_non_exhaustive()
    }
}

impl TokenizationProfile {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn tokenization_version(&self) -> &str {
        &self.tokenization_version
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn token_prefix(&self) -> &str {
        &self.token_prefix
    }

    pub fn token_len(&self) -> usize {
        self.token_len
    }

    pub fn max_plaintext_len(&self) -> usize {
        self.max_plaintext_len
    }

    pub fn cipher_algorithm(&self) -> &str {
        &self.cipher_algorithm
    }

    pub fn hash_key(&self) -> &[u8] {
        &self.hash_key
    }

    pub fn data_key(&self) -> &[u8] {
        &self.data_key
    }
}

impl TokenizationProfilesState {
    fn from_profiles(profiles: Vec<TokenizationProfile>) -> Self {
        let by_name = profiles
            .iter()
            .enumerate()
            .map(|(index, profile)| (profile.name.clone(), index))
            .collect();

        Self { profiles, by_name }
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    pub fn get(&self, name: &str) -> Option<&TokenizationProfile> {
        self.by_name
            .get(name)
            .and_then(|index| self.profiles.get(*index))
    }
}

impl Zeroize for TokenizationProfilesState {
    fn zeroize(&mut self) {
        self.profiles.zeroize();
        self.by_name.clear();
    }
}

impl Zeroize for TokenizationProfile {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.tokenization_version.zeroize();
        self.kid.zeroize();
        self.token_prefix.zeroize();
        self.token_len = 0;
        self.max_plaintext_len = 0;
        self.cipher_algorithm.zeroize();
        self.hash_key.zeroize();
        self.data_key.zeroize();
    }
}

pub(crate) fn validate_tokenization_profiles(
    profile_inputs: Vec<TokenizationProfileInput>,
    is_loaded_kid: impl Fn(&str) -> bool,
    derive_keys: impl Fn(
        TokenizationKeyDerivationRequest<'_>,
    ) -> Result<DerivedTokenizationKeys, DynError>,
) -> Result<TokenizationProfilesState, DynError> {
    let mut seen_names = HashSet::new();
    let mut profiles = Vec::new();

    for profile in profile_inputs {
        validate_tokenization_profile_fields(
            &profile.name,
            &profile.tokenization_version,
            &profile.token_prefix,
            profile.token_len,
            profile.max_plaintext_len,
        )?;
        keys::validate_key_id(&profile.kid).map_err(|err| {
            crate::error::invalid_input(format!("tokenization_profiles.kid is invalid: {err}"))
        })?;
        if !is_loaded_kid(&profile.kid) {
            return Err(crate::error::invalid_input(format!(
                "tokenization profile references kid not loaded in memory: {}",
                profile.kid
            )));
        }
        if !seen_names.insert(profile.name.clone()) {
            return Err(crate::error::invalid_input(format!(
                "tokenization profile has duplicated name: {}",
                profile.name
            )));
        }

        let derived = derive_keys(TokenizationKeyDerivationRequest {
            profile_name: &profile.name,
            kid: &profile.kid,
            tokenization_version: &profile.tokenization_version,
        })?;
        let cipher = crypto::symmetric_cipher(&derived.cipher_algorithm).ok_or_else(|| {
            crate::error::invalid_input(format!(
                "tokenization profile symmetric algorithm is not supported: {}",
                derived.cipher_algorithm
            ))
        })?;
        if derived.hash_key.len() != TOKEN_KEY_SIZE_BYTES
            || derived.data_key.len() != cipher.key_size_bytes
        {
            return Err(crate::error::internal(
                "derived tokenization key has invalid length",
            ));
        }

        profiles.push(TokenizationProfile {
            name: profile.name,
            tokenization_version: profile.tokenization_version,
            kid: profile.kid,
            token_prefix: profile.token_prefix,
            token_len: profile.token_len,
            max_plaintext_len: profile.max_plaintext_len,
            cipher_algorithm: derived.cipher_algorithm,
            hash_key: derived.hash_key,
            data_key: derived.data_key,
        });
    }

    Ok(TokenizationProfilesState::from_profiles(profiles))
}

pub struct TokenizationKeyDerivationRequest<'a> {
    pub profile_name: &'a str,
    pub kid: &'a str,
    pub tokenization_version: &'a str,
}

pub fn validate_tokenization_version(value: &str) -> Result<(), DynError> {
    validation::validate_allowed_value(
        "tokenization_profiles.tokenization_version",
        value,
        &[TOKENIZATION_VERSION_RANDOM_V1],
    )
}

pub fn validate_tokenization_profile_fields(
    name: &str,
    tokenization_version: &str,
    token_prefix: &str,
    token_len: usize,
    max_plaintext_len: usize,
) -> Result<(), DynError> {
    validation::validate_aad_config_name("tokenization_profiles.name", name)?;
    validate_tokenization_version(tokenization_version)?;
    validate_token_prefix(token_prefix)?;
    validate_token_lengths(token_len, max_plaintext_len)?;

    Ok(())
}

pub fn validate_token_prefix(value: &str) -> Result<(), DynError> {
    validation::validate_text_field("tokenization_profiles.token_prefix", value)?;
    if value.chars().count() > TOKEN_PREFIX_MAX_CHARS {
        return Err(crate::error::invalid_input(format!(
            "tokenization_profiles.token_prefix exceeds maximum allowed length: {TOKEN_PREFIX_MAX_CHARS}"
        )));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(crate::error::invalid_input(
            "tokenization_profiles.token_prefix must not contain whitespace",
        ));
    }
    if value.contains(';') || value.contains('=') {
        return Err(crate::error::invalid_input(
            "tokenization_profiles.token_prefix must not contain ';' or '='",
        ));
    }

    Ok(())
}

pub fn validate_token_lengths(token_len: usize, max_plaintext_len: usize) -> Result<(), DynError> {
    if token_len < TOKEN_LEN_MIN_BYTES {
        return Err(crate::error::invalid_input(format!(
            "tokenization_profiles.token_len must be at least {TOKEN_LEN_MIN_BYTES}"
        )));
    }
    if max_plaintext_len == 0 || max_plaintext_len > TOKEN_PLAINTEXT_MAX_LEN {
        return Err(crate::error::invalid_input(format!(
            "tokenization_profiles.max_plaintext_len must be between 1 and {TOKEN_PLAINTEXT_MAX_LEN}"
        )));
    }

    Ok(())
}

pub(crate) fn derive_tokenization_keys(
    ops_symmetric_key_hex: &str,
    cipher_algorithm: &str,
    request: TokenizationKeyDerivationRequest<'_>,
) -> Result<DerivedTokenizationKeys, DynError> {
    let cipher = crypto::symmetric_cipher(cipher_algorithm).ok_or_else(|| {
        crate::error::invalid_input(format!(
            "tokenization profile symmetric algorithm is not supported: {cipher_algorithm}"
        ))
    })?;
    let ops_symmetric_key = Zeroizing::new(hex::decode(ops_symmetric_key_hex)?);
    let hash_info = tokenization_key_info(
        TOKEN_HASH_KEY_PURPOSE,
        request.profile_name,
        request.kid,
        request.tokenization_version,
    )?;
    let data_info = tokenization_key_info(
        TOKEN_DATA_KEY_PURPOSE,
        request.profile_name,
        request.kid,
        request.tokenization_version,
    )?;
    let hash_key = crypto::create_hkdf(
        &ops_symmetric_key,
        TOKENIZATION_HKDF_SALT,
        hash_info.as_bytes(),
        TOKEN_KEY_SIZE_BYTES,
    )?;
    let data_key = crypto::create_hkdf(
        &ops_symmetric_key,
        TOKENIZATION_HKDF_SALT,
        data_info.as_bytes(),
        cipher.key_size_bytes,
    )?;

    Ok(DerivedTokenizationKeys {
        hash_key: Zeroizing::new(hash_key),
        data_key: Zeroizing::new(data_key),
        cipher_algorithm: cipher_algorithm.to_string(),
    })
}

fn tokenization_key_info(
    purpose: &str,
    profile_name: &str,
    kid: &str,
    tokenization_version: &str,
) -> Result<String, DynError> {
    validation::build_validated_aad(&[
        ("purpose", purpose),
        ("profile", profile_name),
        ("kid", kid),
        ("tokenization_version", tokenization_version),
    ])
}

pub fn generate_token(profile: &TokenizationProfile) -> Result<String, DynError> {
    let random = Zeroizing::new(crypto::random_bytes(profile.token_len())?);
    Ok(format!(
        "{}_{}",
        profile.token_prefix(),
        general_purpose::URL_SAFE_NO_PAD.encode(&*random)
    ))
}

pub fn validate_token_value(profile: &TokenizationProfile, token: &str) -> Result<(), DynError> {
    validation::validate_text_field("token", token)?;
    let expected_prefix = format!("{}_", profile.token_prefix());
    if !token.starts_with(&expected_prefix) {
        return Err(crate::error::invalid_input(
            "token prefix does not match tokenization profile",
        ));
    }

    let encoded = &token[expected_prefix.len()..];
    let random = Zeroizing::new(general_purpose::URL_SAFE_NO_PAD.decode(encoded).map_err(
        |_| crate::error::invalid_input("token contains invalid tokenization encoding"),
    )?);
    if random.len() != profile.token_len() {
        return Err(crate::error::invalid_input(
            "token length does not match tokenization profile",
        ));
    }

    Ok(())
}

pub fn hash_token(profile: &TokenizationProfile, token: &str) -> Result<String, DynError> {
    validate_token_value(profile, token)?;
    let message =
        validation::build_validated_aad(&[("profile", profile.name()), ("token", token)])?;
    Ok(hex::encode(crypto::create_hmac(
        profile.hash_key(),
        message.as_bytes(),
    )?))
}

pub fn encrypt_token_data(
    profile: &TokenizationProfile,
    hashid: &str,
    payload: &TokenDataPayload,
) -> Result<String, DynError> {
    let cipher = crypto::symmetric_cipher(profile.cipher_algorithm()).ok_or_else(|| {
        crate::error::invalid_input("tokenization symmetric algorithm is not supported")
    })?;
    let nonce = Zeroizing::new(crypto::random_bytes(cipher.nonce_size_bytes)?);
    let aad = token_data_aad(profile, hashid)?;
    let plaintext = Zeroizing::new(serde_json::to_string(payload)?);
    let ciphertext = crypto::encrypt_symmetric(
        cipher.algorithm,
        &plaintext,
        profile.data_key(),
        &nonce,
        aad.as_bytes(),
    )?;

    Ok(format!(
        "{}.{}.{}",
        general_purpose::STANDARD.encode(ciphertext),
        general_purpose::STANDARD.encode(&*nonce),
        general_purpose::STANDARD.encode(aad.as_bytes())
    ))
}

pub fn decrypt_token_data(
    profile: &TokenizationProfile,
    hashid: &str,
    data: &str,
) -> Result<TokenDataPayload, DynError> {
    let cipher = crypto::symmetric_cipher(profile.cipher_algorithm()).ok_or_else(|| {
        crate::error::invalid_input("tokenization symmetric algorithm is not supported")
    })?;
    let (ciphertext_b64, nonce_b64, aad_b64) = parse_token_data(data)?;
    let ciphertext = Zeroizing::new(general_purpose::STANDARD.decode(ciphertext_b64)?);
    let nonce = Zeroizing::new(general_purpose::STANDARD.decode(nonce_b64)?);
    let aad_bytes = Zeroizing::new(general_purpose::STANDARD.decode(aad_b64)?);
    let aad = std::str::from_utf8(&aad_bytes)
        .map_err(|_| crate::error::invalid_input("token data aad is not valid UTF-8"))?;
    let expected_aad = token_data_aad(profile, hashid)?;
    if aad != expected_aad {
        return Err(crate::error::invalid_input(
            "token data aad does not match request",
        ));
    }
    validation::validate_encrypted_payload(
        "token.data.ciphertext",
        &hex::encode(&*ciphertext),
        "token.data.nonce",
        &hex::encode(&*nonce),
        "token.data.aad",
        aad,
        cipher.nonce_size_bytes,
    )?;
    let mut plaintext_bytes = Zeroizing::new(crypto::decrypt_symmetric(
        cipher.algorithm,
        &ciphertext,
        profile.data_key(),
        &nonce,
        aad.as_bytes(),
    )?);
    let plaintext = String::from_utf8(std::mem::take(&mut *plaintext_bytes)).map_err(|err| {
        let mut bytes = err.into_bytes();
        bytes.zeroize();
        crate::error::invalid_input("token data plaintext is not valid UTF-8")
    })?;
    let payload: TokenDataPayload = serde_json::from_str(&plaintext)
        .map_err(|_| crate::error::invalid_input("token data payload is not valid JSON"))?;
    if payload.profile != profile.name() {
        return Err(crate::error::invalid_input(
            "token data payload profile does not match request",
        ));
    }

    Ok(payload)
}

fn token_data_aad(profile: &TokenizationProfile, hashid: &str) -> Result<String, DynError> {
    validation::build_validated_aad(&[
        ("version", "v1"),
        ("type", TOKEN_DATA_TYPE),
        ("kid", profile.kid()),
        ("profile", profile.name()),
        ("tokenization_version", profile.tokenization_version()),
        ("hashid", hashid),
        ("cipher", profile.cipher_algorithm()),
    ])
}

fn parse_token_data(data: &str) -> Result<(&str, &str, &str), DynError> {
    let mut parts = data.split('.');
    let ciphertext = parts.next().ok_or_else(|| {
        crate::error::invalid_input("token data must have ciphertext.nonce.aad base64 sections")
    })?;
    let nonce = parts.next().ok_or_else(|| {
        crate::error::invalid_input("token data must have ciphertext.nonce.aad base64 sections")
    })?;
    let aad = parts.next().ok_or_else(|| {
        crate::error::invalid_input("token data must have ciphertext.nonce.aad base64 sections")
    })?;
    if parts.next().is_some() {
        return Err(crate::error::invalid_input(
            "token data must have ciphertext.nonce.aad base64 sections",
        ));
    }

    Ok((ciphertext, nonce, aad))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kid() -> &'static str {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }

    fn input(name: &str) -> TokenizationProfileInput {
        TokenizationProfileInput {
            name: name.to_string(),
            tokenization_version: TOKENIZATION_VERSION_RANDOM_V1.to_string(),
            kid: kid().to_string(),
            token_prefix: "tok_patient".to_string(),
            token_len: TOKEN_LEN_MIN_BYTES,
            max_plaintext_len: TOKEN_PLAINTEXT_MAX_LEN,
        }
    }

    fn derived() -> DerivedTokenizationKeys {
        DerivedTokenizationKeys {
            hash_key: Zeroizing::new(vec![7u8; TOKEN_KEY_SIZE_BYTES]),
            data_key: Zeroizing::new(vec![9u8; TOKEN_KEY_SIZE_BYTES]),
            cipher_algorithm: String::from("AES-256/GCM"),
        }
    }

    fn profile() -> TokenizationProfile {
        validate_tokenization_profiles(
            vec![input("patient-id-token-v1")],
            |item| item == kid(),
            |_| Ok(derived()),
        )
        .unwrap()
        .get("patient-id-token-v1")
        .unwrap()
        .clone()
    }

    #[test]
    fn validates_tokenization_profile() {
        let state = validate_tokenization_profiles(
            vec![input("patient-id-token-v1")],
            |item| item == kid(),
            |_| Ok(derived()),
        )
        .expect("profile must validate");
        assert_eq!(state.len(), 1);
        let profile = state.get("patient-id-token-v1").expect("profile exists");
        assert_eq!(profile.hash_key().len(), TOKEN_KEY_SIZE_BYTES);
        assert_eq!(profile.data_key().len(), TOKEN_KEY_SIZE_BYTES);
        assert!(!format!("{profile:?}").contains("777777"));
    }

    #[test]
    fn derives_data_key_with_cipher_key_size() {
        let ops_key = "11".repeat(32);
        let aes128 = derive_tokenization_keys(
            &ops_key,
            "AES-128/GCM",
            TokenizationKeyDerivationRequest {
                profile_name: "patient-id-token-v1",
                kid: kid(),
                tokenization_version: TOKENIZATION_VERSION_RANDOM_V1,
            },
        )
        .expect("AES-128 tokenization keys must derive");
        let aes192 = derive_tokenization_keys(
            &ops_key,
            "AES-192/GCM",
            TokenizationKeyDerivationRequest {
                profile_name: "patient-id-token-v1",
                kid: kid(),
                tokenization_version: TOKENIZATION_VERSION_RANDOM_V1,
            },
        )
        .expect("AES-192 tokenization keys must derive");
        let aes256 = derive_tokenization_keys(
            &ops_key,
            "AES-256/GCM",
            TokenizationKeyDerivationRequest {
                profile_name: "patient-id-token-v1",
                kid: kid(),
                tokenization_version: TOKENIZATION_VERSION_RANDOM_V1,
            },
        )
        .expect("AES-256 tokenization keys must derive");

        assert_eq!(aes128.hash_key.len(), TOKEN_KEY_SIZE_BYTES);
        assert_eq!(aes128.data_key.len(), 16);
        assert_eq!(aes192.data_key.len(), 24);
        assert_eq!(aes256.data_key.len(), 32);
    }

    #[test]
    fn derived_keys_are_bound_to_profile_and_version() {
        let ops_key = "11".repeat(32);
        let first = derive_tokenization_keys(
            &ops_key,
            "AES-256/GCM",
            TokenizationKeyDerivationRequest {
                profile_name: "patient-id-token-v1",
                kid: kid(),
                tokenization_version: TOKENIZATION_VERSION_RANDOM_V1,
            },
        )
        .expect("first profile keys must derive");
        let same = derive_tokenization_keys(
            &ops_key,
            "AES-256/GCM",
            TokenizationKeyDerivationRequest {
                profile_name: "patient-id-token-v1",
                kid: kid(),
                tokenization_version: TOKENIZATION_VERSION_RANDOM_V1,
            },
        )
        .expect("same profile keys must derive");
        let other_profile = derive_tokenization_keys(
            &ops_key,
            "AES-256/GCM",
            TokenizationKeyDerivationRequest {
                profile_name: "account-id-token-v1",
                kid: kid(),
                tokenization_version: TOKENIZATION_VERSION_RANDOM_V1,
            },
        )
        .expect("other profile keys must derive");
        let other_version = derive_tokenization_keys(
            &ops_key,
            "AES-256/GCM",
            TokenizationKeyDerivationRequest {
                profile_name: "patient-id-token-v1",
                kid: kid(),
                tokenization_version: "token-random-v2",
            },
        )
        .expect("other version keys must derive");

        assert_eq!(&*first.hash_key, &*same.hash_key);
        assert_eq!(&*first.data_key, &*same.data_key);
        assert_ne!(&*first.hash_key, &*other_profile.hash_key);
        assert_ne!(&*first.data_key, &*other_profile.data_key);
        assert_ne!(&*first.hash_key, &*other_version.hash_key);
        assert_ne!(&*first.data_key, &*other_version.data_key);
    }

    #[test]
    fn tokenization_key_derivation_keeps_legacy_aad_format_for_valid_fields() {
        let ops_key = "11".repeat(32);
        let actual = derive_tokenization_keys(
            &ops_key,
            "AES-256/GCM",
            TokenizationKeyDerivationRequest {
                profile_name: "patient-id-token-v1",
                kid: kid(),
                tokenization_version: TOKENIZATION_VERSION_RANDOM_V1,
            },
        )
        .expect("valid tokenization keys must derive");
        let ops_symmetric_key = Zeroizing::new(hex::decode(ops_key).unwrap());
        let legacy_hash_info = validation::build_aad(&[
            ("purpose", TOKEN_HASH_KEY_PURPOSE),
            ("profile", "patient-id-token-v1"),
            ("kid", kid()),
            ("tokenization_version", TOKENIZATION_VERSION_RANDOM_V1),
        ]);
        let legacy_data_info = validation::build_aad(&[
            ("purpose", TOKEN_DATA_KEY_PURPOSE),
            ("profile", "patient-id-token-v1"),
            ("kid", kid()),
            ("tokenization_version", TOKENIZATION_VERSION_RANDOM_V1),
        ]);
        let expected_hash_key = crypto::create_hkdf(
            &ops_symmetric_key,
            TOKENIZATION_HKDF_SALT,
            legacy_hash_info.as_bytes(),
            TOKEN_KEY_SIZE_BYTES,
        )
        .expect("legacy hash key must derive");
        let expected_data_key = crypto::create_hkdf(
            &ops_symmetric_key,
            TOKENIZATION_HKDF_SALT,
            legacy_data_info.as_bytes(),
            crypto::symmetric_cipher("AES-256/GCM")
                .expect("AES-256/GCM must be supported")
                .key_size_bytes,
        )
        .expect("legacy data key must derive");

        assert_eq!(actual.hash_key.as_slice(), expected_hash_key.as_slice());
        assert_eq!(actual.data_key.as_slice(), expected_data_key.as_slice());
    }

    #[test]
    fn tokenization_key_derivation_rejects_aad_delimiters_in_dynamic_fields() {
        for request in [
            TokenizationKeyDerivationRequest {
                profile_name: "bad;profile",
                kid: kid(),
                tokenization_version: TOKENIZATION_VERSION_RANDOM_V1,
            },
            TokenizationKeyDerivationRequest {
                profile_name: "bad=profile",
                kid: kid(),
                tokenization_version: TOKENIZATION_VERSION_RANDOM_V1,
            },
            TokenizationKeyDerivationRequest {
                profile_name: "patient-id-token-v1",
                kid: "bad;kid",
                tokenization_version: TOKENIZATION_VERSION_RANDOM_V1,
            },
            TokenizationKeyDerivationRequest {
                profile_name: "patient-id-token-v1",
                kid: "bad=kid",
                tokenization_version: TOKENIZATION_VERSION_RANDOM_V1,
            },
            TokenizationKeyDerivationRequest {
                profile_name: "patient-id-token-v1",
                kid: kid(),
                tokenization_version: "bad;version",
            },
            TokenizationKeyDerivationRequest {
                profile_name: "patient-id-token-v1",
                kid: kid(),
                tokenization_version: "bad=version",
            },
        ] {
            let err = match derive_tokenization_keys(&"11".repeat(32), "AES-256/GCM", request) {
                Ok(_) => panic!("AAD delimiters in tokenization HKDF fields must fail"),
                Err(err) => err,
            };
            assert!(err.to_string().contains("must not contain ';' or '='"));
        }
    }

    #[test]
    fn rejects_invalid_tokenization_profiles() {
        let mut duplicate = input("patient-id-token-v1");
        let err = validate_tokenization_profiles(
            vec![input("patient-id-token-v1"), duplicate.clone()],
            |item| item == kid(),
            |_| Ok(derived()),
        )
        .expect_err("duplicate names must fail");
        assert!(err.to_string().contains("duplicated name"));

        for invalid_name in ["bad=name", "bad;name"] {
            let err = validate_tokenization_profiles(
                vec![input(invalid_name)],
                |item| item == kid(),
                |_| Ok(derived()),
            )
            .expect_err("name with AAD delimiter must fail");
            assert_eq!(
                err.to_string(),
                "tokenization_profiles.name must not contain ';' or '='"
            );
        }

        let max = crate::core::config::CONFIG_NAME_MAX_CHARS;
        assert!(
            validate_tokenization_profiles(
                vec![input(&"a".repeat(max))],
                |item| item == kid(),
                |_| Ok(derived()),
            )
            .is_ok()
        );
        let err = validate_tokenization_profiles(
            vec![input(&"a".repeat(max + 1))],
            |item| item == kid(),
            |_| Ok(derived()),
        )
        .expect_err("overlong tokenization profile name must fail");
        assert_eq!(
            err.to_string(),
            "tokenization_profiles.name exceeds maximum allowed length: 128"
        );

        duplicate.tokenization_version = String::from("token-v0");
        assert!(
            validate_tokenization_profiles(
                vec![duplicate],
                |item| item == kid(),
                |_| { Ok(derived()) }
            )
            .is_err()
        );

        let mut bad_prefix = input("bad-prefix");
        bad_prefix.token_prefix = String::from("tok patient");
        assert!(
            validate_tokenization_profiles(
                vec![bad_prefix],
                |item| item == kid(),
                |_| { Ok(derived()) }
            )
            .is_err()
        );
        assert!(validate_token_prefix("tok_patient").is_ok());
        assert!(validate_token_prefix(&"a".repeat(TOKEN_PREFIX_MAX_CHARS)).is_ok());
        let err = validate_token_prefix(&"a".repeat(TOKEN_PREFIX_MAX_CHARS + 1))
            .expect_err("overlong token prefix must fail");
        assert_eq!(
            err.to_string(),
            "tokenization_profiles.token_prefix exceeds maximum allowed length: 16"
        );
        assert_eq!(
            validate_token_prefix("tok patient")
                .unwrap_err()
                .to_string(),
            "tokenization_profiles.token_prefix must not contain whitespace"
        );
        assert_eq!(
            validate_token_prefix("tok=patient")
                .unwrap_err()
                .to_string(),
            "tokenization_profiles.token_prefix must not contain ';' or '='"
        );

        let mut short_token = input("short-token");
        short_token.token_len = TOKEN_LEN_MIN_BYTES - 1;
        assert!(
            validate_tokenization_profiles(
                vec![short_token],
                |item| item == kid(),
                |_| { Ok(derived()) }
            )
            .is_err()
        );

        assert!(
            validate_tokenization_profiles(vec![input("unloaded")], |_| false, |_| Ok(derived()))
                .is_err()
        );
    }

    #[test]
    fn token_data_encrypt_decrypt_round_trips_metadata() {
        let profile = profile();
        let token = generate_token(&profile).expect("token must generate");
        let hashid = hash_token(&profile, &token).expect("token must hash");
        let payload = TokenDataPayload {
            profile: profile.name().to_string(),
            plaintext: String::from("123456"),
            metadata: Some(serde_json::json!({"tenant":"acme"})),
            created_at: String::from("1782058090"),
        };

        let data = encrypt_token_data(&profile, &hashid, &payload).expect("payload must encrypt");
        let decrypted = decrypt_token_data(&profile, &hashid, &data).expect("payload must decrypt");

        assert_eq!(decrypted.profile, profile.name());
        assert_eq!(decrypted.plaintext, "123456");
        assert_eq!(decrypted.metadata, payload.metadata);
    }

    #[test]
    fn token_hash_keeps_legacy_message_format_for_valid_fields() {
        let profile = profile();
        let token = generate_token(&profile).expect("token must generate");
        let actual = hash_token(&profile, &token).expect("token must hash");
        let legacy_message =
            validation::build_aad(&[("profile", profile.name()), ("token", &token)]);
        let expected = hex::encode(
            crypto::create_hmac(profile.hash_key(), legacy_message.as_bytes())
                .expect("legacy token hash must work"),
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn token_data_aad_keeps_legacy_format_for_valid_fields() {
        let profile = profile();
        let hashid = "b".repeat(64);
        let actual = token_data_aad(&profile, &hashid).expect("valid token data AAD must build");
        let expected = validation::build_aad(&[
            ("version", "v1"),
            ("type", TOKEN_DATA_TYPE),
            ("kid", profile.kid()),
            ("profile", profile.name()),
            ("tokenization_version", profile.tokenization_version()),
            ("hashid", &hashid),
            ("cipher", profile.cipher_algorithm()),
        ]);

        assert_eq!(actual, expected);
    }

    #[test]
    fn token_data_aad_rejects_aad_delimiters_in_dynamic_fields() {
        let profile = profile();
        for hashid in ["bad;hashid", "bad=hashid"] {
            let err = token_data_aad(&profile, hashid)
                .expect_err("AAD delimiters in token data hashid must fail");
            assert!(err.to_string().contains("must not contain ';' or '='"));
        }

        let mut bad_profile = profile.clone();
        bad_profile.name = String::from("bad;profile");
        let err = token_data_aad(&bad_profile, &"b".repeat(64))
            .expect_err("AAD delimiters in token data profile must fail");
        assert!(err.to_string().contains("must not contain ';' or '='"));

        let mut bad_profile = profile.clone();
        bad_profile.tokenization_version = String::from("bad=version");
        let err = token_data_aad(&bad_profile, &"b".repeat(64))
            .expect_err("AAD delimiters in tokenization version must fail");
        assert!(err.to_string().contains("must not contain ';' or '='"));
    }

    #[test]
    fn generated_tokens_are_random_and_prefix_checked() {
        let profile = profile();
        let first = generate_token(&profile).unwrap();
        let second = generate_token(&profile).unwrap();
        assert_ne!(first, second);
        assert!(first.starts_with("tok_patient_"));
        validate_token_value(&profile, &first).expect("generated token must validate");
        assert!(hash_token(&profile, "wrong_prefix_abc").is_err());
    }

    #[test]
    fn token_value_rejects_malformed_encoding_and_wrong_length() {
        let profile = profile();

        let err = validate_token_value(&profile, "tok_patient_abc;def")
            .expect_err("AAD delimiters must not be accepted in token encoding");
        assert_eq!(
            err.to_string(),
            "token contains invalid tokenization encoding"
        );

        let err = validate_token_value(&profile, "tok_patient_abc=def")
            .expect_err("padding or '=' must not be accepted in token encoding");
        assert_eq!(
            err.to_string(),
            "token contains invalid tokenization encoding"
        );

        let err = validate_token_value(&profile, "tok_patient_AA")
            .expect_err("decoded random token length must match the profile");
        assert_eq!(
            err.to_string(),
            "token length does not match tokenization profile"
        );
    }

    #[test]
    fn token_data_rejects_wrong_profile() {
        let profile = profile();
        let mut other = input("other-token-v1");
        other.token_prefix = String::from("tok_other");
        let other_profile =
            validate_tokenization_profiles(vec![other], |item| item == kid(), |_| Ok(derived()))
                .unwrap()
                .get("other-token-v1")
                .unwrap()
                .clone();
        let token = generate_token(&profile).unwrap();
        let hashid = hash_token(&profile, &token).unwrap();
        let payload = TokenDataPayload {
            profile: profile.name().to_string(),
            plaintext: String::from("123456"),
            metadata: None,
            created_at: String::from("1782058090"),
        };
        let data = encrypt_token_data(&profile, &hashid, &payload).unwrap();

        assert!(decrypt_token_data(&other_profile, &hashid, &data).is_err());
    }

    #[test]
    fn token_data_aad_rejects_wrong_tokenization_version() {
        let profile = profile();
        let mut other_profile = profile.clone();
        other_profile.tokenization_version = String::from("token-random-v2");
        let token = generate_token(&profile).unwrap();
        let hashid = hash_token(&profile, &token).unwrap();
        let payload = TokenDataPayload {
            profile: profile.name().to_string(),
            plaintext: String::from("123456"),
            metadata: None,
            created_at: String::from("1782058090"),
        };
        let data = encrypt_token_data(&profile, &hashid, &payload).unwrap();

        assert!(decrypt_token_data(&other_profile, &hashid, &data).is_err());
    }
}
