use crate::core::validation;
use crate::error::DynError;
use crate::ops::keys;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

pub const FPE_VERSION_FF1_2025: &str = "fpe-ff1-2025";
pub const FPE_KEY_SALT: &[u8] = b"vectis:fpe:ff1:v1";
pub const FPE_KEY_SIZE_BYTES: usize = 32;
pub const FPE_VALUE_MIN_LEN: usize = 6;
pub const FPE_VALUE_MAX_LEN: usize = 1024;

type PreparedFpeCipher = Arc<vectis_fpe::ff1::FF1<aes::Aes256>>;
type PreparedFpeAlphabet = Arc<Vec<char>>;
type PreparedFpeAlphabetIndex = Arc<HashMap<char, u16>>;

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct FpeProfileInput {
    name: String,
    fpe_version: String,
    alphabet: String,
    min_len: usize,
    max_len: usize,
    tweak_aad: String,
    kid: String,
}

#[derive(Clone)]
pub struct FpeProfile {
    name: String,
    fpe_version: String,
    alphabet: String,
    min_len: usize,
    max_len: usize,
    tweak_aad: String,
    kid: String,
    alphabet_chars: PreparedFpeAlphabet,
    alphabet_index: PreparedFpeAlphabetIndex,
    cipher: PreparedFpeCipher,
}

#[derive(Clone, Default)]
pub struct FpeProfilesState {
    profiles: Vec<FpeProfile>,
    by_name: HashMap<String, usize>,
}

impl fmt::Debug for FpeProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FpeProfile")
            .field("name", &self.name)
            .field("fpe_version", &self.fpe_version)
            .field("alphabet", &self.alphabet)
            .field("min_len", &self.min_len)
            .field("max_len", &self.max_len)
            .field("tweak_aad", &self.tweak_aad)
            .field("kid", &self.kid)
            .field("cipher", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for FpeProfilesState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FpeProfilesState")
            .field("profiles", &self.profiles)
            .finish_non_exhaustive()
    }
}

impl FpeProfile {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn fpe_version(&self) -> &str {
        &self.fpe_version
    }

    pub fn alphabet(&self) -> &str {
        &self.alphabet
    }

    pub fn min_len(&self) -> usize {
        self.min_len
    }

    pub fn max_len(&self) -> usize {
        self.max_len
    }

    pub fn tweak_aad(&self) -> &str {
        &self.tweak_aad
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    fn cipher(&self) -> &vectis_fpe::ff1::FF1<aes::Aes256> {
        &self.cipher
    }

    fn alphabet_chars(&self) -> &[char] {
        &self.alphabet_chars
    }

    fn alphabet_index(&self) -> &HashMap<char, u16> {
        &self.alphabet_index
    }
}

impl FpeProfilesState {
    fn from_profiles(profiles: Vec<FpeProfile>) -> Self {
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

    pub fn get(&self, name: &str) -> Option<&FpeProfile> {
        self.by_name
            .get(name)
            .and_then(|index| self.profiles.get(*index))
    }
}

impl Zeroize for FpeProfilesState {
    fn zeroize(&mut self) {
        self.profiles.zeroize();
        self.by_name.clear();
    }
}

impl Zeroize for FpeProfile {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.fpe_version.zeroize();
        self.alphabet.zeroize();
        self.min_len = 0;
        self.max_len = 0;
        self.tweak_aad.zeroize();
        self.kid.zeroize();
    }
}

pub(crate) fn validate_fpe_profiles(
    profile_inputs: Vec<FpeProfileInput>,
    is_loaded_kid: impl Fn(&str) -> bool,
    derive_fpe_key: impl Fn(FpeKeyDerivationRequest<'_>) -> Result<Zeroizing<Vec<u8>>, DynError>,
) -> Result<FpeProfilesState, DynError> {
    let mut seen_names = HashSet::new();
    let mut profiles = Vec::new();

    for profile in profile_inputs {
        validate_fpe_profile_fields(
            &profile.name,
            &profile.fpe_version,
            &profile.alphabet,
            profile.min_len,
            profile.max_len,
            &profile.tweak_aad,
        )?;
        keys::validate_key_id(&profile.kid).map_err(|err| {
            crate::error::invalid_input(format!("fpe_profiles.kid is invalid: {err}"))
        })?;
        if !is_loaded_kid(&profile.kid) {
            return Err(crate::error::invalid_input(format!(
                "fpe profile references kid not loaded in memory: {}",
                profile.kid
            )));
        }

        if !seen_names.insert(profile.name.clone()) {
            return Err(crate::error::invalid_input(format!(
                "fpe profile has duplicated name: {}",
                profile.name
            )));
        }
        let fpe_key = derive_fpe_key(FpeKeyDerivationRequest {
            kid: &profile.kid,
            profile_name: &profile.name,
            fpe_version: &profile.fpe_version,
        })?;
        if fpe_key.len() != FPE_KEY_SIZE_BYTES {
            return Err(crate::error::internal("derived fpe key has invalid length"));
        }
        let (alphabet_chars, alphabet_index) = prepare_fpe_alphabet(&profile.alphabet)?;
        let cipher = build_fpe_cipher(&fpe_key, alphabet_chars.len())?;

        profiles.push(FpeProfile {
            name: profile.name,
            fpe_version: profile.fpe_version,
            alphabet: profile.alphabet,
            min_len: profile.min_len,
            max_len: profile.max_len,
            tweak_aad: profile.tweak_aad,
            kid: profile.kid,
            alphabet_chars,
            alphabet_index,
            cipher,
        });
    }

    Ok(FpeProfilesState::from_profiles(profiles))
}

pub struct FpeKeyDerivationRequest<'a> {
    pub kid: &'a str,
    pub profile_name: &'a str,
    pub fpe_version: &'a str,
}

fn parse_fpe_value_digits(
    field: &str,
    value: &str,
    profile: &FpeProfile,
) -> Result<Zeroizing<Vec<u16>>, DynError> {
    validation::validate_text_field(field, value)?;
    let digits = Zeroizing::new(
        value
            .chars()
            .map(|item| {
                profile.alphabet_index().get(&item).copied().ok_or_else(|| {
                    crate::error::invalid_input(format!(
                        "{field} contains character outside fpe profile alphabet"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    );
    if digits.len() < profile.min_len() || digits.len() > profile.max_len() {
        return Err(crate::error::invalid_input(format!(
            "{field} length is outside fpe profile bounds"
        )));
    }

    Ok(digits)
}

pub fn validate_fpe_version(value: &str) -> Result<(), DynError> {
    validation::validate_allowed_value("fpe_profiles.fpe_version", value, &[FPE_VERSION_FF1_2025])
}

pub fn validate_fpe_profile_fields(
    name: &str,
    fpe_version: &str,
    alphabet: &str,
    min_len: usize,
    max_len: usize,
    tweak_aad: &str,
) -> Result<usize, DynError> {
    validation::validate_aad_config_name("fpe_profiles.name", name)?;
    validate_fpe_version(fpe_version)?;
    let radix = validate_fpe_alphabet(alphabet)?;
    validate_fpe_lengths(min_len, max_len, radix)?;
    validation::validate_labels(
        "fpe_profiles.tweak_aad",
        tweak_aad,
        crate::core::config::FPE_TWEAK_AAD_MAX_CHARS,
    )?;
    Ok(radix)
}

pub fn validate_fpe_alphabet(alphabet: &str) -> Result<usize, DynError> {
    validation::validate_text_field("fpe_profiles.alphabet", alphabet)?;
    let mut seen = HashSet::new();
    for item in alphabet.chars() {
        if !seen.insert(item) {
            return Err(crate::error::invalid_input(
                "fpe_profiles.alphabet must not contain duplicate characters",
            ));
        }
    }
    let radix = seen.len();
    if !(2..=(1 << 16)).contains(&radix) {
        return Err(crate::error::invalid_input(
            "fpe_profiles.alphabet length must be between 2 and 65536",
        ));
    }

    Ok(radix)
}

fn prepare_fpe_alphabet(
    alphabet: &str,
) -> Result<(PreparedFpeAlphabet, PreparedFpeAlphabetIndex), DynError> {
    let alphabet_chars = Arc::new(alphabet.chars().collect::<Vec<_>>());
    let mut alphabet_index = HashMap::with_capacity(alphabet_chars.len());
    for (index, item) in alphabet_chars.iter().enumerate() {
        let index = u16::try_from(index)
            .map_err(|_| crate::error::internal("fpe alphabet index is invalid"))?;
        alphabet_index.insert(*item, index);
    }

    Ok((alphabet_chars, Arc::new(alphabet_index)))
}

pub fn validate_fpe_lengths(min_len: usize, max_len: usize, radix: usize) -> Result<(), DynError> {
    validate_fpe_length_bounds(min_len, max_len)?;
    if !fpe_domain_is_large_enough(radix, min_len) {
        return Err(crate::error::invalid_input(
            "fpe profile domain is too small for FF1",
        ));
    }

    Ok(())
}

pub fn validate_fpe_min_len(min_len: usize) -> Result<(), DynError> {
    if min_len < FPE_VALUE_MIN_LEN {
        return Err(crate::error::invalid_input(format!(
            "fpe_profiles.min_len must be at least {FPE_VALUE_MIN_LEN}"
        )));
    }

    Ok(())
}

pub fn validate_fpe_max_len(max_len: usize) -> Result<(), DynError> {
    if max_len > FPE_VALUE_MAX_LEN {
        return Err(crate::error::invalid_input(
            "fpe_profiles.max_len exceeds maximum allowed value",
        ));
    }

    Ok(())
}

pub fn validate_fpe_length_bounds(min_len: usize, max_len: usize) -> Result<(), DynError> {
    validate_fpe_min_len(min_len)?;
    validate_fpe_max_len(max_len)?;
    if max_len < min_len {
        return Err(crate::error::invalid_input(
            "fpe_profiles.max_len must be greater than or equal to min_len",
        ));
    }

    Ok(())
}

fn fpe_domain_is_large_enough(radix: usize, min_len: usize) -> bool {
    let mut domain = 1usize;
    for _ in 0..min_len {
        domain = domain.saturating_mul(radix);
        if domain >= 1_000_000 {
            return true;
        }
    }

    false
}

pub fn derive_fpe_key(
    ops_symmetric_key_hex: &str,
    profile: &FpeProfile,
) -> Result<Zeroizing<Vec<u8>>, DynError> {
    derive_fpe_key_for_profile(
        ops_symmetric_key_hex,
        FpeKeyDerivationRequest {
            kid: profile.kid(),
            profile_name: profile.name(),
            fpe_version: profile.fpe_version(),
        },
    )
}

pub(crate) fn derive_fpe_key_for_profile(
    ops_symmetric_key_hex: &str,
    request: FpeKeyDerivationRequest<'_>,
) -> Result<Zeroizing<Vec<u8>>, DynError> {
    let ops_symmetric_key = Zeroizing::new(hex::decode(ops_symmetric_key_hex)?);
    let info = validation::build_validated_aad(&[
        ("profile", request.profile_name),
        ("kid", request.kid),
        ("fpe_version", request.fpe_version),
    ])?;
    let fpe_key = crate::core::crypto::create_hkdf(
        &ops_symmetric_key,
        FPE_KEY_SALT,
        info.as_bytes(),
        FPE_KEY_SIZE_BYTES,
    )?;

    Ok(Zeroizing::new(fpe_key))
}

fn build_fpe_cipher(fpe_key: &[u8], radix: usize) -> Result<PreparedFpeCipher, DynError> {
    let radix = u32::try_from(radix)
        .map_err(|_| crate::error::invalid_input("fpe profile radix is invalid"))?;
    vectis_fpe::ff1::FF1::<aes::Aes256>::new(fpe_key, radix)
        .map(Arc::new)
        .map_err(|err| crate::error::invalid_input(format!("fpe profile is invalid: {err}")))
}

pub fn fpe_encrypt(profile: &FpeProfile, plaintext: &str) -> Result<String, DynError> {
    let digits = parse_fpe_value_digits("plaintext", plaintext, profile)?;
    fpe_transform(profile, digits, true)
}

pub fn fpe_decrypt(profile: &FpeProfile, ciphertext: &str) -> Result<String, DynError> {
    let digits = parse_fpe_value_digits("ciphertext", ciphertext, profile)?;
    fpe_transform(profile, digits, false)
}

fn fpe_transform(
    profile: &FpeProfile,
    mut digits: Zeroizing<Vec<u16>>,
    encrypt: bool,
) -> Result<String, DynError> {
    let input = vectis_fpe::ff1::FlexibleNumeralString::from(std::mem::take(&mut *digits));
    let output_result = if encrypt {
        profile
            .cipher()
            .encrypt(profile.tweak_aad().as_bytes(), &input)
    } else {
        profile
            .cipher()
            .decrypt(profile.tweak_aad().as_bytes(), &input)
    };
    let mut input_digits = Vec::<u16>::from(input);
    input_digits.zeroize();
    let output = match output_result {
        Ok(output) => output,
        Err(err) => {
            return Err(crate::error::invalid_input(format!(
                "fpe operation failed: {err}"
            )));
        }
    };
    let output_digits = Zeroizing::new(Vec::<u16>::from(output));

    output_digits
        .iter()
        .map(|digit| {
            profile
                .alphabet_chars()
                .get(*digit as usize)
                .copied()
                .ok_or_else(|| {
                    crate::error::internal("fpe operation returned invalid alphabet index")
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(name: &str, kid: &str) -> FpeProfileInput {
        FpeProfileInput {
            name: name.to_string(),
            fpe_version: FPE_VERSION_FF1_2025.to_string(),
            alphabet: "0123456789".to_string(),
            min_len: 6,
            max_len: 32,
            tweak_aad: "tenant=acme;field=patient_id;version=1".to_string(),
            kid: kid.to_string(),
        }
    }

    fn kid() -> &'static str {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }

    fn fpe_key() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(vec![7u8; FPE_KEY_SIZE_BYTES])
    }

    fn real_fpe_key(kid: &str, profile_name: &str, fpe_version: &str) -> Zeroizing<Vec<u8>> {
        derive_fpe_key_for_profile(
            &"11".repeat(32),
            FpeKeyDerivationRequest {
                kid,
                profile_name,
                fpe_version,
            },
        )
        .unwrap()
    }

    fn real_fpe_key_for_request(
        request: FpeKeyDerivationRequest<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, DynError> {
        Ok(real_fpe_key(
            request.kid,
            request.profile_name,
            request.fpe_version,
        ))
    }

    #[test]
    fn validates_fpe_profile() {
        let state = validate_fpe_profiles(
            vec![input("patient-id", kid())],
            |item| item == kid(),
            |_| Ok(fpe_key()),
        )
        .expect("profile must validate");
        assert_eq!(state.len(), 1);
        let profile = state.get("patient-id").expect("profile must exist");
        assert_eq!(profile.alphabet_chars().len(), 10);
        assert_eq!(profile.alphabet_index().len(), 10);
        assert_eq!(profile.alphabet_index().get(&'7'), Some(&7));
        let debug = format!("{profile:?}");
        assert!(debug.contains("alphabet"));
        assert!(!debug.contains("alphabet_chars"));
        assert!(!debug.contains("alphabet_index"));
        assert!(debug.contains("cipher"));
        assert!(!debug.contains("070707"));
    }

    #[test]
    fn rejects_duplicate_name() {
        let err = validate_fpe_profiles(
            vec![input("patient-id", kid()), input("patient-id", kid())],
            |item| item == kid(),
            |_| Ok(fpe_key()),
        )
        .expect_err("duplicate name must fail");
        assert!(err.to_string().contains("duplicated name"));
    }

    #[test]
    fn rejects_invalid_alphabet() {
        let mut profile = input("patient-id", kid());
        profile.alphabet = "001234".to_string();
        assert!(
            validate_fpe_profiles(vec![profile], |item| item == kid(), |_| Ok(fpe_key())).is_err()
        );

        let mut profile = input("patient-id", kid());
        profile.max_len = FPE_VALUE_MAX_LEN;
        validate_fpe_profiles(vec![profile], |item| item == kid(), |_| Ok(fpe_key()))
            .expect("maximum allowed fpe length must validate");

        let mut profile = input("patient-id", kid());
        profile.max_len = FPE_VALUE_MAX_LEN + 1;
        let err = validate_fpe_profiles(vec![profile], |item| item == kid(), |_| Ok(fpe_key()))
            .expect_err("oversized fpe max length must fail");
        assert_eq!(
            err.to_string(),
            "fpe_profiles.max_len exceeds maximum allowed value"
        );
    }

    #[test]
    fn rejects_invalid_lengths() {
        let min_len_err =
            validate_fpe_min_len(5).expect_err("short minimum length must fail validation");
        assert_eq!(
            min_len_err.to_string(),
            "fpe_profiles.min_len must be at least 6"
        );

        let max_len_err = validate_fpe_max_len(FPE_VALUE_MAX_LEN + 1)
            .expect_err("oversized maximum length must fail validation");
        assert_eq!(
            max_len_err.to_string(),
            "fpe_profiles.max_len exceeds maximum allowed value"
        );

        let bounds_err = validate_fpe_length_bounds(10, 9)
            .expect_err("max length below min length must fail validation");
        assert_eq!(
            bounds_err.to_string(),
            "fpe_profiles.max_len must be greater than or equal to min_len"
        );

        let mut profile = input("patient-id", kid());
        profile.min_len = FPE_VALUE_MIN_LEN - 1;
        assert!(
            validate_fpe_profiles(vec![profile], |item| item == kid(), |_| Ok(fpe_key())).is_err()
        );

        let mut profile = input("patient-id", kid());
        profile.min_len = 4;
        profile.max_len = 3;
        assert!(
            validate_fpe_profiles(vec![profile], |item| item == kid(), |_| Ok(fpe_key())).is_err()
        );

        let err =
            validate_fpe_lengths(6, 32, 6).expect_err("small FF1 domain must fail validation");
        assert_eq!(err.to_string(), "fpe profile domain is too small for FF1");
    }

    #[test]
    fn public_fpe_field_validators_match_profile_policy() {
        assert!(validate_fpe_version(FPE_VERSION_FF1_2025).is_ok());
        assert!(validate_fpe_version("fpe-ff1-legacy").is_err());
        assert_eq!(validate_fpe_alphabet("0123456789").unwrap(), 10);
        assert!(validate_fpe_alphabet("001234").is_err());
        assert!(validate_fpe_lengths(6, 32, 10).is_ok());
        assert!(validate_fpe_lengths(5, 32, 10).is_err());
        assert!(validate_fpe_lengths(6, 32, 6).is_err());
        assert!(
            validate_fpe_profile_fields(
                "patient-id",
                FPE_VERSION_FF1_2025,
                "0123456789",
                6,
                32,
                "tenant=acme"
            )
            .is_ok()
        );
        for name in ["bad=name", "bad;name"] {
            let err = validate_fpe_profile_fields(
                name,
                FPE_VERSION_FF1_2025,
                "0123456789",
                6,
                32,
                "tenant=acme",
            )
            .expect_err("AAD delimiters in FPE profile names must fail");
            assert_eq!(
                err.to_string(),
                "fpe_profiles.name must not contain ';' or '='"
            );
        }
        let max = crate::core::config::CONFIG_NAME_MAX_CHARS;
        assert!(
            validate_fpe_profile_fields(
                &"a".repeat(max),
                FPE_VERSION_FF1_2025,
                "0123456789",
                6,
                32,
                "tenant=acme",
            )
            .is_ok()
        );
        let err = validate_fpe_profile_fields(
            &"a".repeat(max + 1),
            FPE_VERSION_FF1_2025,
            "0123456789",
            6,
            32,
            "tenant=acme",
        )
        .expect_err("overlong FPE profile name must fail validation");
        assert_eq!(
            err.to_string(),
            "fpe_profiles.name exceeds maximum allowed length: 128"
        );

        let err = validate_fpe_profile_fields(
            "patient-id",
            FPE_VERSION_FF1_2025,
            "0123456789",
            6,
            32,
            "tenant",
        )
        .expect_err("malformed FPE tweak AAD must fail validation");
        assert_eq!(
            err.to_string(),
            "fpe_profiles.tweak_aad labels must use key=value format"
        );
    }

    #[test]
    fn rejects_unloaded_kid() {
        assert!(
            validate_fpe_profiles(
                vec![input("patient-id", kid())],
                |_| false,
                |_| { Ok(fpe_key()) }
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_invalid_cipher_radix_during_profile_preparation() {
        let err = match build_fpe_cipher(&fpe_key(), 1) {
            Ok(_) => panic!("invalid radix must fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("fpe profile is invalid"));
    }

    #[test]
    fn fpe_key_derivation_keeps_legacy_aad_format_for_valid_fields() {
        let ops_symmetric_key_hex = "11".repeat(32);
        let actual = derive_fpe_key_for_profile(
            &ops_symmetric_key_hex,
            FpeKeyDerivationRequest {
                kid: kid(),
                profile_name: "patient-id",
                fpe_version: FPE_VERSION_FF1_2025,
            },
        )
        .expect("valid FPE key derivation must work");

        let ops_symmetric_key = Zeroizing::new(hex::decode(ops_symmetric_key_hex).unwrap());
        let legacy_info = validation::build_aad(&[
            ("profile", "patient-id"),
            ("kid", kid()),
            ("fpe_version", FPE_VERSION_FF1_2025),
        ]);
        let expected = crate::core::crypto::create_hkdf(
            &ops_symmetric_key,
            FPE_KEY_SALT,
            legacy_info.as_bytes(),
            FPE_KEY_SIZE_BYTES,
        )
        .expect("legacy FPE key derivation must work");

        assert_eq!(actual.as_slice(), expected.as_slice());
    }

    #[test]
    fn fpe_key_derivation_rejects_aad_delimiters_in_dynamic_fields() {
        for request in [
            FpeKeyDerivationRequest {
                kid: kid(),
                profile_name: "bad;profile",
                fpe_version: FPE_VERSION_FF1_2025,
            },
            FpeKeyDerivationRequest {
                kid: kid(),
                profile_name: "bad=profile",
                fpe_version: FPE_VERSION_FF1_2025,
            },
            FpeKeyDerivationRequest {
                kid: "bad;kid",
                profile_name: "patient-id",
                fpe_version: FPE_VERSION_FF1_2025,
            },
            FpeKeyDerivationRequest {
                kid: "bad=kid",
                profile_name: "patient-id",
                fpe_version: FPE_VERSION_FF1_2025,
            },
            FpeKeyDerivationRequest {
                kid: kid(),
                profile_name: "patient-id",
                fpe_version: "bad;version",
            },
            FpeKeyDerivationRequest {
                kid: kid(),
                profile_name: "patient-id",
                fpe_version: "bad=version",
            },
        ] {
            let err = derive_fpe_key_for_profile(&"11".repeat(32), request)
                .expect_err("AAD delimiters in FPE HKDF fields must fail");
            assert!(err.to_string().contains("must not contain ';' or '='"));
        }
    }

    #[test]
    fn fpe_encrypt_decrypt_round_trips() {
        let state = validate_fpe_profiles(
            vec![input("patient-id", kid())],
            |item| item == kid(),
            |_| Ok(fpe_key()),
        )
        .expect("profile must validate");
        let profile = state.get("patient-id").expect("profile must exist");
        let ciphertext = fpe_encrypt(profile, "123456").expect("encrypt must work");
        let plaintext = fpe_decrypt(profile, &ciphertext).expect("decrypt must work");

        assert_ne!(ciphertext, "123456");
        assert_eq!(plaintext, "123456");
    }

    #[test]
    fn fpe_is_deterministic_for_same_profile() {
        let state = validate_fpe_profiles(
            vec![input("patient-id", kid())],
            |item| item == kid(),
            real_fpe_key_for_request,
        )
        .expect("profile must validate");
        let profile = state.get("patient-id").expect("profile must exist");

        assert_eq!(
            fpe_encrypt(profile, "123456").unwrap(),
            fpe_encrypt(profile, "123456").unwrap()
        );
    }

    #[test]
    fn different_tweak_or_profile_changes_ciphertext() {
        let state = validate_fpe_profiles(
            vec![input("patient-id", kid())],
            |item| item == kid(),
            real_fpe_key_for_request,
        )
        .expect("profile must validate");
        let profile = state.get("patient-id").expect("profile must exist");
        let baseline = fpe_encrypt(profile, "123456").unwrap();

        let mut other_tweak = input("patient-id", kid());
        other_tweak.tweak_aad = "tenant=acme;field=other;version=1".to_string();
        let other_tweak_state = validate_fpe_profiles(
            vec![other_tweak],
            |item| item == kid(),
            real_fpe_key_for_request,
        )
        .expect("profile must validate");
        let other_tweak_profile = other_tweak_state
            .get("patient-id")
            .expect("profile must exist");

        let other_profile_state = validate_fpe_profiles(
            vec![input("other-profile", kid())],
            |item| item == kid(),
            real_fpe_key_for_request,
        )
        .expect("profile must validate");
        let other_profile = other_profile_state
            .get("other-profile")
            .expect("profile must exist");

        assert_ne!(
            baseline,
            fpe_encrypt(other_tweak_profile, "123456").unwrap()
        );
        assert_ne!(baseline, fpe_encrypt(other_profile, "123456").unwrap());
        assert_ne!(
            real_fpe_key(kid(), "patient-id", FPE_VERSION_FF1_2025).as_slice(),
            real_fpe_key(kid(), "patient-id", "future-version").as_slice()
        );
    }

    #[test]
    fn fpe_rejects_value_outside_profile() {
        let state = validate_fpe_profiles(
            vec![input("patient-id", kid())],
            |item| item == kid(),
            |_| Ok(fpe_key()),
        )
        .expect("profile must validate");
        let profile = state.get("patient-id").expect("profile must exist");

        let err = fpe_encrypt(profile, "abc123").expect_err("invalid plaintext must fail");
        assert_eq!(
            err.to_string(),
            "plaintext contains character outside fpe profile alphabet"
        );
        let err = fpe_decrypt(profile, "abc123").expect_err("invalid ciphertext must fail");
        assert_eq!(
            err.to_string(),
            "ciphertext contains character outside fpe profile alphabet"
        );
        assert!(fpe_encrypt(profile, "123").is_err());
    }

    #[test]
    fn fpe_profile_zeroize_clears_metadata() {
        let state = validate_fpe_profiles(
            vec![input("patient-id", kid())],
            |item| item == kid(),
            |_| Ok(fpe_key()),
        )
        .expect("profile must validate");
        let mut profile = state.get("patient-id").expect("profile must exist").clone();

        profile.zeroize();

        assert!(profile.name().is_empty());
        assert!(profile.kid().is_empty());
    }

    #[test]
    fn fpe_cipher_uses_zeroizing_aes_key_schedule() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<aes::Aes256>();
    }
}
