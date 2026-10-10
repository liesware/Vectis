use crate::core::{tokenization::SubjectMode, validation};
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
pub const FPE_PRESERVE_MAX_CHARS: usize = 32;
pub const FPE_AUTH_KEY_SALT: &[u8] = b"vectis:fpe:mac:v1";
pub const FPE_AUTH_KEY_SIZE_BYTES: usize = 32;
pub const FPE_AUTH_VERSION: &str = "v1";
pub const FPE_AUTH_MAC: &str = "HMAC(BLAKE2b(256))";

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlphabetPreset {
    Num,
    Alpha,
    Alphanum,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LetterCase {
    Uppercase,
    Lowercase,
    Mixed,
}

pub(crate) fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

type PreparedFpeCipher = Arc<vectis_fpe::ff1::FF1<aes::Aes256>>;
type PreparedFpeAlphabet = Arc<Vec<char>>;
type PreparedFpeAlphabetIndex = Arc<HashMap<char, u16>>;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FpeProfileInput {
    name: String,
    fpe_version: String,
    #[serde(
        default,
        deserialize_with = "deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    alphabet: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    alphabet_preset: Option<AlphabetPreset>,
    #[serde(
        default,
        deserialize_with = "deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    letter_case: Option<LetterCase>,
    #[serde(
        default,
        deserialize_with = "deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    preserve_characters: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    authenticated: bool,
    #[serde(default, skip_serializing_if = "SubjectMode::is_none")]
    subject_mode: SubjectMode,
    min_len: usize,
    max_len: usize,
    tweak_aad: String,
    kid: String,
}

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
    cipher: Option<PreparedFpeCipher>,
    parent_key: Option<Zeroizing<Vec<u8>>>,
    subject_mode: SubjectMode,
    preserve_characters: String,
    preserved: HashSet<char>,
    authenticated: bool,
    auth_key: Option<Zeroizing<Vec<u8>>>,
}

pub struct FpeContext {
    profile: Arc<FpeProfile>,
    keys: FpeContextKeys,
}

enum FpeContextKeys {
    Legacy,
    Subject {
        subject: String,
        cipher: PreparedFpeCipher,
        auth_key: Option<Zeroizing<Vec<u8>>>,
    },
}

impl From<Arc<FpeProfile>> for FpeContext {
    fn from(profile: Arc<FpeProfile>) -> Self {
        Self {
            profile,
            keys: FpeContextKeys::Legacy,
        }
    }
}

impl std::ops::Deref for FpeContext {
    type Target = FpeProfile;
    fn deref(&self) -> &FpeProfile {
        &self.profile
    }
}

impl FpeContext {
    pub fn from_subject_envelope(
        profile: Arc<FpeProfile>,
        origin: &crate::core::tokenization::TokenizationProfile,
        subject: &str,
        envelope: &str,
    ) -> Result<Self, DynError> {
        validate_subject_mode(&profile, Some(subject))?;
        if origin.kid() != profile.kid() || origin.subject_mode() != SubjectMode::Stored {
            return Err(crate::error::internal("stored subject seed is invalid"));
        }
        let seed = crate::core::subjects::open_authenticated_seed(origin, subject, envelope)?;
        Self::with_subject(profile, subject, &seed)
    }
    pub fn subject(&self) -> Option<&str> {
        match &self.keys {
            FpeContextKeys::Legacy => None,
            FpeContextKeys::Subject { subject, .. } => Some(subject),
        }
    }

    pub fn validate_mode(&self, expected: Option<&str>) -> Result<(), DynError> {
        validate_subject_mode(&self.profile, expected)?;
        if self.subject() != expected {
            return Err(crate::error::invalid_input(
                "subject does not match FPE context",
            ));
        }
        Ok(())
    }

    pub(crate) fn with_subject(
        profile: Arc<FpeProfile>,
        subject: &str,
        seed: &crate::core::subjects::OpenedSeed,
    ) -> Result<Self, DynError> {
        validate_subject_mode(&profile, Some(subject))?;
        let parent = profile
            .parent_key
            .as_ref()
            .ok_or_else(|| crate::error::internal("FPE parent key unavailable"))?;
        let info = |purpose: &str, auth: bool| {
            let mut fields = vec![
                ("purpose", purpose),
                ("kid", profile.kid()),
                ("profile", profile.name()),
                ("fpe_version", profile.fpe_version()),
            ];
            if auth {
                fields.push(("auth_version", FPE_AUTH_VERSION));
            }
            fields.push(("version", "v1"));
            validation::build_validated_aad(&fields)
        };
        let key = Zeroizing::new(crate::core::crypto::create_hkdf(
            parent,
            seed.as_bytes(),
            info("subject-fpe-encryption", false)?.as_bytes(),
            32,
        )?);
        let cipher = build_fpe_cipher(&key, profile.alphabet_chars.len())?;
        let auth_key = if profile.authenticated() {
            let parent = profile
                .auth_key
                .as_ref()
                .ok_or_else(|| crate::error::internal("FPE parent MAC key unavailable"))?;
            Some(Zeroizing::new(crate::core::crypto::create_hkdf(
                parent,
                seed.as_bytes(),
                info("subject-fpe-authentication", true)?.as_bytes(),
                32,
            )?))
        } else {
            None
        };
        Ok(Self {
            profile,
            keys: FpeContextKeys::Subject {
                subject: subject.to_owned(),
                cipher,
                auth_key,
            },
        })
    }

    fn cipher(&self) -> Result<&vectis_fpe::ff1::FF1<aes::Aes256>, DynError> {
        self.validate_mode(self.subject())?;
        match &self.keys {
            FpeContextKeys::Legacy => self.profile.cipher(),
            FpeContextKeys::Subject { cipher, .. } => Ok(cipher),
        }
    }

    fn auth_key(&self) -> Option<&[u8]> {
        match &self.keys {
            FpeContextKeys::Legacy => self.profile.auth_key.as_ref().map(|key| key.as_slice()),
            FpeContextKeys::Subject { auth_key, .. } => auth_key.as_ref().map(|key| key.as_slice()),
        }
    }

    pub fn encrypt(&self, value: &str) -> Result<String, DynError> {
        let cipher = self.cipher()?;
        fpe_transform(
            &self.profile,
            parse_fpe_value_digits("plaintext", value, &self.profile)?,
            true,
            cipher,
        )
    }

    pub fn decrypt(&self, value: &str) -> Result<String, DynError> {
        let cipher = self.cipher()?;
        #[cfg(test)]
        DECRYPT_CALLS.set(DECRYPT_CALLS.get() + 1);
        fpe_transform(
            &self.profile,
            parse_fpe_value_digits("ciphertext", value, &self.profile)?,
            false,
            cipher,
        )
    }

    pub fn generate_tag(&self, ciphertext: &str) -> Result<Option<String>, DynError> {
        self.validate_mode(self.subject())?;
        generate_tag_with_key(&self.profile, ciphertext, self.auth_key())
    }

    pub fn verify_tag(&self, ciphertext: &str, tag: Option<&str>) -> Result<(), DynError> {
        self.validate_mode(self.subject())?;
        verify_tag_with_key(&self.profile, ciphertext, tag, self.auth_key())
    }
}

pub fn validate_subject_mode(profile: &FpeProfile, subject: Option<&str>) -> Result<(), DynError> {
    if let Some(subject) = subject {
        crate::core::subjects::validate_subject(subject)?;
    }
    match (profile.subject_mode(), subject) {
        (SubjectMode::Stored, None) => Err(crate::error::invalid_input(
            "subject is required for stored FPE profiles",
        )),
        (SubjectMode::None, Some(_)) => Err(crate::error::invalid_input(
            "subject is prohibited for legacy FPE profiles",
        )),
        _ => Ok(()),
    }
}

#[derive(Clone, Default)]
pub struct FpeProfilesState {
    profiles: Vec<Arc<FpeProfile>>,
    by_name: HashMap<String, usize>,
}

impl fmt::Debug for FpeProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FpeProfile")
            .field("name", &self.name)
            .field("fpe_version", &self.fpe_version)
            .field("alphabet", &self.alphabet)
            .field("preserve_characters", &self.preserve_characters)
            .field("authenticated", &self.authenticated)
            .field("subject_mode", &self.subject_mode)
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
    pub fn subject_mode(&self) -> SubjectMode {
        self.subject_mode
    }
    pub fn authenticated(&self) -> bool {
        self.authenticated
    }
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn fpe_version(&self) -> &str {
        &self.fpe_version
    }

    pub fn alphabet(&self) -> &str {
        &self.alphabet
    }

    pub fn preserve_characters(&self) -> &str {
        &self.preserve_characters
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

    fn cipher(&self) -> Result<&vectis_fpe::ff1::FF1<aes::Aes256>, DynError> {
        self.cipher.as_deref().ok_or_else(|| {
            crate::error::invalid_input("stored FPE profile requires a subject context")
        })
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
        let profiles = profiles.into_iter().map(Arc::new).collect::<Vec<_>>();
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

    pub fn get(&self, name: &str) -> Option<Arc<FpeProfile>> {
        self.by_name
            .get(name)
            .and_then(|index| self.profiles.get(*index))
            .map(Arc::clone)
    }
}

impl Zeroize for FpeProfilesState {
    fn zeroize(&mut self) {
        while let Some(profile) = self.profiles.pop() {
            drop(profile);
        }
        self.by_name.clear();
    }
}

impl Zeroize for FpeProfile {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.fpe_version.zeroize();
        self.alphabet.zeroize();
        self.preserve_characters.zeroize();
        self.preserved.clear();
        self.min_len = 0;
        self.max_len = 0;
        self.tweak_aad.zeroize();
        self.kid.zeroize();
        self.auth_key = None;
        self.parent_key = None;
    }
}

impl Drop for FpeProfile {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub(crate) fn validate_fpe_profiles(
    profile_inputs: Vec<FpeProfileInput>,
    is_loaded_kid: impl Fn(&str) -> bool,
    derive_fpe_key: impl Fn(FpeKeyDerivationRequest<'_>) -> Result<Zeroizing<Vec<u8>>, DynError>,
    derive_fpe_auth_key: impl Fn(FpeKeyDerivationRequest<'_>) -> Result<Zeroizing<Vec<u8>>, DynError>,
) -> Result<FpeProfilesState, DynError> {
    let mut seen_names = HashSet::new();
    let mut profiles = Vec::new();

    for profile in profile_inputs {
        let alphabet = resolve_fpe_alphabet(
            profile.alphabet.as_deref(),
            profile.alphabet_preset,
            profile.letter_case,
        )?;
        let preserve_characters = profile.preserve_characters.unwrap_or_default();
        let preserved = validate_preserved_characters(&alphabet, &preserve_characters)?;
        validate_fpe_profile_fields(
            &profile.name,
            &profile.fpe_version,
            &alphabet,
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
        let (alphabet_chars, alphabet_index) = prepare_fpe_alphabet(&alphabet)?;
        let (cipher, parent_key) = match profile.subject_mode {
            SubjectMode::None => (
                Some(build_fpe_cipher(&fpe_key, alphabet_chars.len())?),
                None,
            ),
            SubjectMode::Stored => (None, Some(fpe_key)),
        };
        let auth_key = if profile.authenticated {
            let key = derive_fpe_auth_key(FpeKeyDerivationRequest {
                kid: &profile.kid,
                profile_name: &profile.name,
                fpe_version: &profile.fpe_version,
            })?;
            if key.len() != FPE_AUTH_KEY_SIZE_BYTES {
                return Err(crate::error::internal(
                    "derived fpe authentication key has invalid length",
                ));
            }
            Some(key)
        } else {
            None
        };

        profiles.push(FpeProfile {
            name: profile.name,
            fpe_version: profile.fpe_version,
            alphabet,
            min_len: profile.min_len,
            max_len: profile.max_len,
            tweak_aad: profile.tweak_aad,
            kid: profile.kid,
            alphabet_chars,
            alphabet_index,
            cipher,
            parent_key,
            subject_mode: profile.subject_mode,
            preserve_characters,
            preserved,
            authenticated: profile.authenticated,
            auth_key,
        });
    }

    Ok(FpeProfilesState::from_profiles(profiles))
}

pub struct FpeKeyDerivationRequest<'a> {
    pub kid: &'a str,
    pub profile_name: &'a str,
    pub fpe_version: &'a str,
}

pub(crate) fn derive_fpe_auth_key_for_profile(
    source: &str,
    request: FpeKeyDerivationRequest<'_>,
) -> Result<Zeroizing<Vec<u8>>, DynError> {
    let source = Zeroizing::new(hex::decode(source)?);
    let info = validation::build_validated_aad(&[
        ("purpose", "fpe-auth"),
        ("profile", request.profile_name),
        ("kid", request.kid),
        ("fpe_version", request.fpe_version),
        ("auth_version", FPE_AUTH_VERSION),
    ])?;
    Ok(Zeroizing::new(crate::core::crypto::create_hkdf(
        &source,
        FPE_AUTH_KEY_SALT,
        info.as_bytes(),
        FPE_AUTH_KEY_SIZE_BYTES,
    )?))
}

#[derive(Serialize)]
struct FpeAuthMaterial<'a> {
    purpose: &'static str,
    auth_version: &'static str,
    kid: &'a str,
    profile: &'a str,
    fpe_version: &'a str,
    alphabet: &'a str,
    preserve_characters: &'a str,
    tweak_aad: &'a str,
    ciphertext: &'a str,
}

fn auth_bytes(
    profile: &FpeProfile,
    ciphertext: &str,
    key: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, DynError> {
    let key = key.ok_or_else(|| crate::error::internal("fpe authentication key unavailable"))?;
    let material = crate::core::canonical::canonical_json_v1(&FpeAuthMaterial {
        purpose: "fpe-auth",
        auth_version: FPE_AUTH_VERSION,
        kid: profile.kid(),
        profile: profile.name(),
        fpe_version: profile.fpe_version(),
        alphabet: profile.alphabet(),
        preserve_characters: profile.preserve_characters(),
        tweak_aad: profile.tweak_aad(),
        ciphertext,
    })?;
    let tag = crate::core::crypto::create_hmac_with_algorithm(FPE_AUTH_MAC, key, &material)
        .map_err(|_| crate::error::internal("fpe authentication operation failed"))?;
    if tag.len() != FPE_AUTH_KEY_SIZE_BYTES {
        return Err(crate::error::internal(
            "fpe authentication tag has invalid length",
        ));
    }
    Ok(Zeroizing::new(tag))
}

pub fn validate_auth_tag(tag: &str) -> Result<(), DynError> {
    if tag.len() != 64
        || !tag
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(crate::error::invalid_input(
            "fpe tag must be 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

pub fn validate_tag_policy(profile: &FpeProfile, tag: Option<&str>) -> Result<(), DynError> {
    match (profile.authenticated(), tag) {
        (true, None) => Err(crate::error::invalid_input(
            "fpe tag is required for authenticated profiles",
        )),
        (false, Some(_)) => Err(crate::error::invalid_input(
            "fpe tag is prohibited for legacy profiles",
        )),
        (_, Some(tag)) => validate_auth_tag(tag),
        _ => Ok(()),
    }
}

pub fn generate_auth_tag(
    profile: &FpeProfile,
    ciphertext: &str,
) -> Result<Option<String>, DynError> {
    validate_subject_mode(profile, None)?;
    generate_tag_with_key(
        profile,
        ciphertext,
        profile.auth_key.as_ref().map(|key| key.as_slice()),
    )
}

fn generate_tag_with_key(
    profile: &FpeProfile,
    ciphertext: &str,
    key: Option<&[u8]>,
) -> Result<Option<String>, DynError> {
    if !profile.authenticated() {
        return Ok(None);
    }
    Ok(Some(hex::encode(auth_bytes(profile, ciphertext, key)?)))
}

pub fn verify_auth_tag(
    profile: &FpeProfile,
    ciphertext: &str,
    tag: Option<&str>,
) -> Result<(), DynError> {
    validate_subject_mode(profile, None)?;
    verify_tag_with_key(
        profile,
        ciphertext,
        tag,
        profile.auth_key.as_ref().map(|key| key.as_slice()),
    )
}

fn verify_tag_with_key(
    profile: &FpeProfile,
    ciphertext: &str,
    tag: Option<&str>,
    key: Option<&[u8]>,
) -> Result<(), DynError> {
    validate_tag_policy(profile, tag)?;
    if let Some(tag) = tag {
        let received = Zeroizing::new(hex::decode(tag)?);
        let expected = auth_bytes(profile, ciphertext, key)?;
        if !crate::core::crypto::constant_time_eq(&received, &expected) {
            return Err(crate::error::invalid_input("fpe authentication failed"));
        }
    }
    Ok(())
}

#[cfg(test)]
thread_local! { static DECRYPT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(crate) fn reset_decrypt_calls() {
    DECRYPT_CALLS.set(0);
}
#[cfg(test)]
pub(crate) fn decrypt_calls() -> usize {
    DECRYPT_CALLS.get()
}

struct PreparedFpeValue {
    digits: Zeroizing<Vec<u16>>,
    preserved: Zeroizing<Vec<(usize, char)>>,
    total_len: usize,
}

fn parse_fpe_value_digits(
    field: &str,
    value: &str,
    profile: &FpeProfile,
) -> Result<PreparedFpeValue, DynError> {
    let total_len = value.chars().count();
    if total_len < profile.min_len() || total_len > profile.max_len() {
        return Err(crate::error::invalid_input(format!(
            "{field} length is outside fpe profile bounds"
        )));
    }
    validation::validate_text_field(field, value)?;
    let mut digits = Zeroizing::new(Vec::with_capacity(total_len));
    let mut preserved = Zeroizing::new(Vec::with_capacity(total_len));
    for (position, item) in value.chars().enumerate() {
        if profile.preserved.contains(&item) {
            preserved.push((position, item));
        } else {
            let digit = profile
                .alphabet_index()
                .get(&item)
                .copied()
                .ok_or_else(|| {
                    crate::error::invalid_input(format!(
                        "{field} contains character outside fpe profile alphabet"
                    ))
                })?;
            digits.push(digit);
        }
    }
    if digits.is_empty() || !fpe_domain_is_large_enough(profile.alphabet_chars.len(), digits.len())
    {
        return Err(crate::error::invalid_input(format!(
            "{field} effective domain is too small for FF1 after excluding preserved characters"
        )));
    }
    Ok(PreparedFpeValue {
        digits,
        preserved,
        total_len,
    })
}

pub fn resolve_fpe_alphabet(
    alphabet: Option<&str>,
    preset: Option<AlphabetPreset>,
    case: Option<LetterCase>,
) -> Result<String, DynError> {
    const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
    let resolved = match (alphabet, preset, case) {
        (Some(alphabet), None, None) => alphabet.to_owned(),
        (None, Some(AlphabetPreset::Num), None) => "0123456789".to_owned(),
        (None, Some(preset @ (AlphabetPreset::Alpha | AlphabetPreset::Alphanum)), Some(case)) => {
            let letters = match case {
                LetterCase::Uppercase => UPPER.to_owned(),
                LetterCase::Lowercase => LOWER.to_owned(),
                LetterCase::Mixed => format!("{UPPER}{LOWER}"),
            };
            match preset {
                AlphabetPreset::Alphanum => format!("0123456789{letters}"),
                _ => letters,
            }
        }
        (Some(_), Some(_), _) | (None, None, _) => {
            return Err(crate::error::invalid_input(
                "fpe_profiles requires exactly one of alphabet or alphabet_preset",
            ));
        }
        _ => {
            return Err(crate::error::invalid_input(
                "fpe_profiles.letter_case is required for alpha/alphanum and prohibited for num/custom",
            ));
        }
    };
    validate_fpe_alphabet(&resolved)?;
    Ok(resolved)
}

pub fn validate_preserve_characters(value: &str) -> Result<(), DynError> {
    let mut seen = HashSet::new();
    for ch in value.chars() {
        if ch.is_control() || !seen.insert(ch) {
            return Err(crate::error::invalid_input(
                "fpe_profiles.preserve_characters must contain distinct characters without controls",
            ));
        }
        if seen.len() > FPE_PRESERVE_MAX_CHARS {
            return Err(crate::error::invalid_input(format!(
                "fpe_profiles.preserve_characters exceeds maximum allowed length: {FPE_PRESERVE_MAX_CHARS}"
            )));
        }
    }
    Ok(())
}

fn validate_preserved_characters(alphabet: &str, value: &str) -> Result<HashSet<char>, DynError> {
    validate_preserve_characters(value)?;
    let preserved: HashSet<_> = value.chars().collect();
    if alphabet.chars().any(|ch| preserved.contains(&ch)) {
        return Err(crate::error::invalid_input(
            "fpe_profiles.preserve_characters overlaps the alphabet",
        ));
    }
    Ok(preserved)
}

pub(crate) fn validate_profile_definition(value: &serde_json::Value) -> Result<(), DynError> {
    let input: FpeProfileInput = serde_json::from_value(value.clone())
        .map_err(|_| crate::error::invalid_input("invalid fpe profile definition"))?;
    let alphabet = resolve_fpe_alphabet(
        input.alphabet.as_deref(),
        input.alphabet_preset,
        input.letter_case,
    )?;
    validate_preserved_characters(
        &alphabet,
        input.preserve_characters.as_deref().unwrap_or_default(),
    )?;
    validate_fpe_profile_fields(
        &input.name,
        &input.fpe_version,
        &alphabet,
        input.min_len,
        input.max_len,
        &input.tweak_aad,
    )
    .map(drop)
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
    validate_profile_lengths(min_len, max_len, radix, Some(alphabet))?;
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
            return Err(alphabet_validation_error(
                "fpe_profiles.alphabet must not contain duplicate characters",
                Some(alphabet),
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
    validate_profile_lengths(min_len, max_len, radix, None)
}

fn alphabet_validation_error(message: &str, alphabet: Option<&str>) -> DynError {
    let hint = match alphabet {
        Some("num") => {
            Some("alphabet \"num\" is literal; for the preset use alphabet_preset: \"num\"")
        }
        Some("alpha") => Some(
            "alphabet \"alpha\" is literal; for the preset use alphabet_preset: \"alpha\" with letter_case",
        ),
        Some("alphanum") => Some(
            "alphabet \"alphanum\" is literal; for the preset use alphabet_preset: \"alphanum\" with letter_case",
        ),
        _ => None,
    };
    crate::error::invalid_input(match hint {
        Some(hint) => format!("{message}; {hint}"),
        None => message.to_owned(),
    })
}

fn validate_profile_lengths(
    min_len: usize,
    max_len: usize,
    radix: usize,
    alphabet: Option<&str>,
) -> Result<(), DynError> {
    validate_fpe_length_bounds(min_len, max_len)?;
    if !fpe_domain_is_large_enough(radix, min_len) {
        return Err(alphabet_validation_error(
            "fpe profile domain is too small for FF1",
            alphabet,
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
    fpe_transform(profile, digits, true, profile.cipher()?)
}

pub fn fpe_decrypt(profile: &FpeProfile, ciphertext: &str) -> Result<String, DynError> {
    #[cfg(test)]
    DECRYPT_CALLS.set(DECRYPT_CALLS.get() + 1);
    let digits = parse_fpe_value_digits("ciphertext", ciphertext, profile)?;
    fpe_transform(profile, digits, false, profile.cipher()?)
}

fn fpe_transform(
    profile: &FpeProfile,
    value: PreparedFpeValue,
    encrypt: bool,
    cipher: &vectis_fpe::ff1::FF1<aes::Aes256>,
) -> Result<String, DynError> {
    let PreparedFpeValue {
        mut digits,
        preserved,
        total_len,
    } = value;
    let input = vectis_fpe::ff1::FlexibleNumeralString::from(std::mem::take(&mut *digits));
    let output_result = if encrypt {
        cipher.encrypt(profile.tweak_aad().as_bytes(), &input)
    } else {
        cipher.decrypt(profile.tweak_aad().as_bytes(), &input)
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

    // Four bytes per Unicode scalar avoids reallocating a partially decrypted value.
    let mut result = Zeroizing::new(String::with_capacity(total_len * 4));
    let mut positions = preserved.iter().peekable();
    let mut digits = output_digits.iter();
    for position in 0..total_len {
        if positions.peek().is_some_and(|item| item.0 == position) {
            result.push(positions.next().expect("preserved position exists").1);
        } else {
            let ch = digits
                .next()
                .and_then(|digit| profile.alphabet_chars().get(*digit as usize))
                .copied()
                .ok_or_else(|| {
                    crate::error::internal("fpe operation returned invalid alphabet index")
                })?;
            result.push(ch);
        }
    }
    Ok(std::mem::take(&mut *result))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(name: &str, kid: &str) -> FpeProfileInput {
        FpeProfileInput {
            name: name.to_string(),
            fpe_version: FPE_VERSION_FF1_2025.to_string(),
            alphabet: Some("0123456789".to_string()),
            alphabet_preset: None,
            letter_case: None,
            preserve_characters: None,
            authenticated: false,
            subject_mode: SubjectMode::None,
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
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
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
    fn legacy_ciphertext_vector() {
        let state = validate_fpe_profiles(
            vec![input("patient-id", kid())],
            |_| true,
            |_| Ok(fpe_key()),
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
        )
        .unwrap();
        let profile = state.get("patient-id").unwrap();
        assert_eq!(fpe_encrypt(&profile, "001234567").unwrap(), "392168046");
        assert_eq!(fpe_decrypt(&profile, "392168046").unwrap(), "001234567");
    }

    #[test]
    fn subject_context_uses_original_seed_and_separate_versioned_keys() {
        let token_input = serde_json::json!([{"name":"creator-token","kid":kid(),"token_prefix":"tok_subject","token_len":32,"max_plaintext_len":128,"one_time":false,"subject_mode":"stored"}]);
        let tokens = crate::core::tokenization::validate_tokenization_profiles(
            serde_json::from_value(token_input).unwrap(),
            |_| true,
            |request| {
                crate::core::tokenization::derive_tokenization_keys(
                    &"11".repeat(32),
                    "AES-256/GCM",
                    request,
                )
            },
        )
        .unwrap();
        let creator = tokens.get("creator-token").unwrap();
        let subject = crate::core::subjects::subject_id(&creator, "user").unwrap();
        let envelope = crate::core::subjects::create_seed(&creator, &subject).unwrap();
        assert_eq!(
            crate::core::subjects::seed_profile_hint(&envelope).unwrap(),
            "creator-token"
        );
        let seed =
            crate::core::subjects::open_authenticated_seed(&creator, &subject, &envelope).unwrap();
        let token_keys = crate::core::subjects::open_seed(&creator, &subject, &envelope).unwrap();
        for authenticated in [false, true] {
            let mut def = input("stored-fpe", kid());
            def.authenticated = authenticated;
            def.subject_mode = SubjectMode::Stored;
            def.preserve_characters = Some("-".to_owned());
            let profiles = validate_fpe_profiles(
                vec![def],
                |_| true,
                |_| Ok(fpe_key()),
                |_| Ok(Zeroizing::new(vec![9; 32])),
            )
            .unwrap();
            let profile = profiles.get("stored-fpe").unwrap();
            assert!(profile.cipher.is_none());
            assert!(fpe_encrypt(&profile, "001-234").is_err());
            assert!(
                FpeContext::from(profile.clone())
                    .encrypt("001-234")
                    .is_err()
            );
            let ctx = FpeContext::with_subject(profile.clone(), &subject, &seed).unwrap();
            let ciphertext = ctx.encrypt("001-234").unwrap();
            let tag = ctx.generate_tag(&ciphertext).unwrap();
            ctx.verify_tag(&ciphertext, tag.as_deref()).unwrap();
            assert_eq!(ctx.decrypt(&ciphertext).unwrap(), "001-234");
            let info = format!(
                "purpose=subject-fpe-encryption;kid={};profile=stored-fpe;fpe_version=fpe-ff1-2025;version=v1",
                kid()
            );
            let expected = Zeroizing::new(
                crate::core::crypto::create_hkdf(&[7; 32], seed.as_bytes(), info.as_bytes(), 32)
                    .unwrap(),
            );
            assert_ne!(expected.as_slice(), token_keys.hash_key.as_slice());
            assert_ne!(expected.as_slice(), token_keys.data_key.as_slice());
            let cipher = build_fpe_cipher(&expected, 10).unwrap();
            assert_eq!(
                ciphertext,
                fpe_transform(
                    &profile,
                    parse_fpe_value_digits("plaintext", "001-234", &profile).unwrap(),
                    true,
                    &cipher
                )
                .unwrap()
            );
            if let FpeContextKeys::Subject {
                auth_key: Some(key),
                ..
            } = &ctx.keys
            {
                let info = format!(
                    "purpose=subject-fpe-authentication;kid={};profile=stored-fpe;fpe_version=fpe-ff1-2025;auth_version=v1;version=v1",
                    kid()
                );
                let expected_mac = crate::core::crypto::create_hkdf(
                    &[9; 32],
                    seed.as_bytes(),
                    info.as_bytes(),
                    32,
                )
                .unwrap();
                assert_eq!(key.as_slice(), expected_mac.as_slice());
                assert_ne!(key.as_slice(), expected.as_slice());
            }
            let replacement = crate::core::subjects::create_seed(&creator, &subject).unwrap();
            let new_seed =
                crate::core::subjects::open_authenticated_seed(&creator, &subject, &replacement)
                    .unwrap();
            let recreated = FpeContext::with_subject(profile, &subject, &new_seed).unwrap();
            if authenticated {
                assert!(recreated.verify_tag(&ciphertext, tag.as_deref()).is_err());
            }
        }
        let mut definition = serde_json::to_value(input("mode", kid())).unwrap();
        assert!(definition.get("subject_mode").is_none());
        definition["subject_mode"] = serde_json::json!("none");
        assert!(
            serde_json::to_value(
                serde_json::from_value::<FpeProfileInput>(definition.clone()).unwrap()
            )
            .unwrap()
            .get("subject_mode")
            .is_none()
        );
        for bad in [
            serde_json::Value::Null,
            serde_json::json!("other"),
            serde_json::json!(true),
        ] {
            definition["subject_mode"] = bad;
            assert!(serde_json::from_value::<FpeProfileInput>(definition.clone()).is_err());
        }
    }

    #[test]
    fn authentication_default_and_false_preserve_legacy_serialization() {
        let original = serde_json::to_value(input("legacy", kid())).unwrap();
        assert!(original.get("authenticated").is_none());
        let mut explicit = original.clone();
        explicit["authenticated"] = serde_json::json!(false);
        let decoded: FpeProfileInput = serde_json::from_value(explicit).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), original);
        for invalid in [
            serde_json::Value::Null,
            serde_json::json!("true"),
            serde_json::json!(1),
        ] {
            let mut value = original.clone();
            value["authenticated"] = invalid;
            assert!(serde_json::from_value::<FpeProfileInput>(value).is_err());
        }
        let state = validate_fpe_profiles(
            vec![input("legacy", kid())],
            |_| true,
            |_| Ok(fpe_key()),
            |_| panic!("legacy must not derive a MAC key"),
        )
        .unwrap();
        assert!(!state.get("legacy").unwrap().authenticated());
        let mut enabled = input("enabled", kid());
        enabled.authenticated = true;
        assert!(
            validate_fpe_profiles(
                vec![enabled],
                |_| true,
                |_| Ok(fpe_key()),
                |_| Ok(Zeroizing::new(vec![9; 31]))
            )
            .is_err()
        );
    }

    #[test]
    fn authentication_key_derivation_is_separate_and_binds_context() {
        let derive = |name: &str| {
            derive_fpe_auth_key_for_profile(
                &"11".repeat(32),
                FpeKeyDerivationRequest {
                    kid: kid(),
                    profile_name: name,
                    fpe_version: FPE_VERSION_FF1_2025,
                },
            )
            .unwrap()
        };
        let key = derive("auth");
        assert_eq!(key.len(), FPE_AUTH_KEY_SIZE_BYTES);
        assert_eq!(key, derive("auth"));
        assert_ne!(key, real_fpe_key(kid(), "auth", FPE_VERSION_FF1_2025));
        assert_ne!(key, derive("other"));
        let info = "purpose=fpe-auth;profile=auth;kid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;fpe_version=fpe-ff1-2025;auth_version=v1";
        let expected =
            crate::core::crypto::create_hkdf(&[0x11; 32], FPE_AUTH_KEY_SALT, info.as_bytes(), 32)
                .unwrap();
        assert_eq!(key.as_slice(), expected.as_slice());
    }

    #[test]
    fn authentication_binds_exact_material_and_zeroizes_key() {
        let mut definition = input("auth", kid());
        definition.authenticated = true;
        definition.preserve_characters = Some("- ".to_owned());
        let mut state = validate_fpe_profiles(
            vec![definition],
            |_| true,
            |_| Ok(fpe_key()),
            |_| Ok(Zeroizing::new(vec![9; 32])),
        )
        .unwrap();
        let mut profile = state.profiles.pop().unwrap();
        let profile = Arc::get_mut(&mut profile).unwrap();
        let ciphertext = fpe_encrypt(profile, "001-234").unwrap();
        let tag = generate_auth_tag(profile, &ciphertext).unwrap().unwrap();
        assert!(validate_auth_tag(&tag).is_ok());
        verify_auth_tag(profile, &ciphertext, Some(&tag)).unwrap();
        assert_eq!(
            verify_auth_tag(profile, &ciphertext.replace('-', " "), Some(&tag))
                .unwrap_err()
                .to_string(),
            "fpe authentication failed"
        );
        assert!(format!("{profile:?}").find("090909").is_none());
        macro_rules! mutated {
            ($field:ident, $value:expr) => {{
                let original = std::mem::replace(&mut profile.$field, $value.to_owned());
                assert_eq!(
                    verify_auth_tag(profile, &ciphertext, Some(&tag))
                        .unwrap_err()
                        .to_string(),
                    "fpe authentication failed"
                );
                profile.$field = original;
            }};
        }
        mutated!(kid, &"b".repeat(64));
        mutated!(name, "other");
        mutated!(fpe_version, "different");
        mutated!(alphabet, "9876543210");
        mutated!(preserve_characters, " -");
        mutated!(tweak_aad, "tenant=other");
        profile.zeroize();
        assert!(profile.auth_key.is_none());
        assert!(profile.authenticated());
        assert!(verify_auth_tag(profile, &ciphertext, Some(&tag)).is_err());
    }

    #[test]
    fn presets_have_exact_order_and_strict_selectors() {
        let upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let lower = "abcdefghijklmnopqrstuvwxyz";
        assert_eq!(
            resolve_fpe_alphabet(None, Some(AlphabetPreset::Num), None).unwrap(),
            "0123456789"
        );
        for (case, expected) in [
            (LetterCase::Uppercase, upper.to_owned()),
            (LetterCase::Lowercase, lower.to_owned()),
            (LetterCase::Mixed, format!("{upper}{lower}")),
        ] {
            assert_eq!(
                resolve_fpe_alphabet(None, Some(AlphabetPreset::Alpha), Some(case)).unwrap(),
                expected
            );
            assert_eq!(
                resolve_fpe_alphabet(None, Some(AlphabetPreset::Alphanum), Some(case)).unwrap(),
                format!("0123456789{expected}")
            );
        }
        assert_eq!(
            resolve_fpe_alphabet(Some("num"), None, None).unwrap(),
            "num"
        );
        assert!(resolve_fpe_alphabet(None, None, None).is_err());
        assert!(resolve_fpe_alphabet(Some("0123456789"), Some(AlphabetPreset::Num), None).is_err());
        assert!(resolve_fpe_alphabet(None, Some(AlphabetPreset::Alpha), None).is_err());
        assert!(
            resolve_fpe_alphabet(None, Some(AlphabetPreset::Num), Some(LetterCase::Mixed)).is_err()
        );
        assert!(resolve_fpe_alphabet(Some("0123456789"), None, Some(LetterCase::Mixed)).is_err());
    }

    #[test]
    fn literal_preset_hints_only_annotate_existing_failures() {
        let error = validate_fpe_profile_fields(
            "literal-num",
            FPE_VERSION_FF1_2025,
            "num",
            6,
            32,
            "tenant=test",
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "fpe profile domain is too small for FF1; alphabet \"num\" is literal; for the preset use alphabet_preset: \"num\""
        );
        assert!(matches!(
            error.downcast_ref::<crate::error::VectisError>(),
            Some(crate::error::VectisError::InvalidInput(_))
        ));
        for name in ["alpha", "alphanum"] {
            let error = resolve_fpe_alphabet(Some(name), None, None)
                .unwrap_err()
                .to_string();
            assert!(
                error.starts_with("fpe_profiles.alphabet must not contain duplicate characters;")
            );
            assert!(error.contains(&format!("alphabet_preset: \"{name}\" with letter_case")));
            assert!(!error.chars().any(char::is_control));
            assert!(error.chars().count() <= 256);
        }
        assert_eq!(
            validate_fpe_alphabet("001234").unwrap_err().to_string(),
            "fpe_profiles.alphabet must not contain duplicate characters"
        );
        assert_eq!(
            validate_fpe_lengths(6, 32, 3).unwrap_err().to_string(),
            "fpe profile domain is too small for FF1"
        );
        let mut definition = input("literal-num", kid());
        definition.alphabet = Some("num".to_owned());
        definition.min_len = 13;
        let state = validate_fpe_profiles(
            vec![definition],
            |_| true,
            |_| Ok(fpe_key()),
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
        )
        .unwrap();
        let profile = state.get("literal-num").unwrap();
        assert_eq!(profile.alphabet(), "num");
        let plaintext = format!("{}n", "num".repeat(4));
        let ciphertext = fpe_encrypt(&profile, &plaintext).unwrap();
        assert!(ciphertext.chars().all(|ch| "num".contains(ch)));
        assert_eq!(fpe_decrypt(&profile, &ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn effective_domain_errors_explain_excluded_characters_without_reflection() {
        let profile = formatted_profile(None, Some(AlphabetPreset::Num), None, "-");
        for (field, error) in [
            ("plaintext", fpe_encrypt(&profile, "001-23").unwrap_err()),
            ("ciphertext", fpe_decrypt(&profile, "001-23").unwrap_err()),
        ] {
            assert_eq!(
                error.to_string(),
                format!(
                    "{field} effective domain is too small for FF1 after excluding preserved characters"
                )
            );
            assert!(!error.to_string().contains("001-23"));
            assert!(matches!(
                error.downcast_ref::<crate::error::VectisError>(),
                Some(crate::error::VectisError::InvalidInput(_))
            ));
        }
        assert!(fpe_encrypt(&profile, "001-234").is_ok());
    }

    #[test]
    fn optional_fields_reject_null_and_preserve_serialized_presence() {
        let original = serde_json::json!({"name":"patient-id","fpe_version":FPE_VERSION_FF1_2025,"alphabet":"0123456789","min_len":6,"max_len":32,"tweak_aad":"tenant=acme;field=patient_id;version=1","kid":kid()});
        let input: FpeProfileInput = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(serde_json::to_value(input).unwrap(), original);
        for field in [
            "name",
            "fpe_version",
            "alphabet",
            "alphabet_preset",
            "letter_case",
            "preserve_characters",
            "min_len",
            "max_len",
            "tweak_aad",
            "kid",
        ] {
            let mut value = original.clone();
            value[field] = serde_json::Value::Null;
            assert!(
                serde_json::from_value::<FpeProfileInput>(value).is_err(),
                "{field}"
            );
        }
        let mut explicit = original.clone();
        explicit["preserve_characters"] = serde_json::json!("");
        let input: FpeProfileInput = serde_json::from_value(explicit.clone()).unwrap();
        assert_eq!(serde_json::to_value(input).unwrap(), explicit);
        for (field, value) in [("alphabet_preset", "NUM"), ("letter_case", "upper")] {
            let mut bad = original.clone();
            bad[field] = serde_json::json!(value);
            assert!(serde_json::from_value::<FpeProfileInput>(bad).is_err());
        }
    }

    fn formatted_profile(
        alphabet: Option<&str>,
        preset: Option<AlphabetPreset>,
        case: Option<LetterCase>,
        preserve: &str,
    ) -> Arc<FpeProfile> {
        let mut profile = input("patient-id", kid());
        profile.alphabet = alphabet.map(str::to_owned);
        profile.alphabet_preset = preset;
        profile.letter_case = case;
        profile.preserve_characters = Some(preserve.to_owned());
        validate_fpe_profiles(
            vec![profile],
            |_| true,
            |_| Ok(fpe_key()),
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
        )
        .unwrap()
        .get("patient-id")
        .unwrap()
    }

    #[test]
    fn separators_preserve_positions_and_encrypt_one_effective_domain() {
        let profile = formatted_profile(None, Some(AlphabetPreset::Num), None, "- ");
        let value = "001-234-567";
        let ciphertext = fpe_encrypt(&profile, value).unwrap();
        assert_eq!(ciphertext.replace('-', ""), "392168046");
        for plaintext in [value, "-001234-", "--001--234--", " 001234 "] {
            let encrypted = fpe_encrypt(&profile, plaintext).unwrap();
            assert_eq!(encrypted.chars().count(), plaintext.chars().count());
            for (position, ch) in plaintext.chars().enumerate() {
                if profile.preserved.contains(&ch) {
                    assert_eq!(encrypted.chars().nth(position), Some(ch));
                }
            }
            assert_eq!(fpe_decrypt(&profile, &encrypted).unwrap(), plaintext);
        }
        assert!(fpe_encrypt(&profile, "--001-23--").is_err());
        assert!(fpe_encrypt(&profile, "------").is_err());
        assert!(fpe_encrypt(&profile, "001234!").is_err());
        assert!(fpe_decrypt(&profile, "--001-23--").is_err());
        assert!(fpe_encrypt(&profile, &format!("{}001234", "-".repeat(26))).is_ok());
        assert!(fpe_encrypt(&profile, &format!("{}001234", "-".repeat(27))).is_err());
        let alpha = formatted_profile(
            None,
            Some(AlphabetPreset::Alpha),
            Some(LetterCase::Mixed),
            "-",
        );
        let ciphertext = fpe_encrypt(&alpha, "-ABCD-").unwrap();
        assert_eq!(fpe_decrypt(&alpha, &ciphertext).unwrap(), "-ABCD-");
    }

    #[test]
    fn unicode_format_and_preserved_character_bounds() {
        let profile = formatted_profile(Some("零一二三四五六七八九"), None, None, "🩺");
        let input = "零零一🩺二三四";
        let encrypted = fpe_encrypt(&profile, input).unwrap();
        assert_eq!(encrypted.chars().count(), 7);
        assert_eq!(encrypted.chars().nth(3), Some('🩺'));
        assert_eq!(fpe_decrypt(&profile, &encrypted).unwrap(), input);
        let exact: String = (0x1f600..0x1f600 + FPE_PRESERVE_MAX_CHARS as u32)
            .map(|v| char::from_u32(v).unwrap())
            .collect();
        assert!(validate_preserved_characters("0123456789", &exact).is_ok());
        let error = validate_preserve_characters(&(exact + "🩺")).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "fpe_profiles.preserve_characters exceeds maximum allowed length: {FPE_PRESERVE_MAX_CHARS}"
            )
        );
        for bad in ["--", "\n", "\u{7f}", "\u{85}"] {
            assert!(validate_preserve_characters(bad).is_err());
        }
        assert!(validate_preserved_characters("0123456789", "-0").is_err());
        assert!(validate_preserve_characters(" ").is_ok());
    }

    #[test]
    fn profile_lookups_share_ownership_across_state_zeroize() {
        let mut state = validate_fpe_profiles(
            vec![input("patient-id", kid())],
            |item| item == kid(),
            |_| Ok(fpe_key()),
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
        )
        .expect("profile must validate");
        let first = state.get("patient-id").expect("profile must exist");
        let second = state.get("patient-id").expect("profile must exist");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(Arc::strong_count(&first), 3);
        state.zeroize();
        assert!(state.is_empty());
        assert_eq!(first.name(), "patient-id");
        assert_eq!(Arc::strong_count(&first), 2);
        drop(second);
        assert_eq!(Arc::strong_count(&first), 1);
    }

    #[test]
    fn in_flight_profile_keeps_old_snapshot_after_state_replacement() {
        let mut old_input = input("patient-id", kid());
        old_input.tweak_aad = "tenant=old;field=patient_id;version=1".to_string();
        let mut old_state = validate_fpe_profiles(
            vec![old_input],
            |item| item == kid(),
            |_| Ok(fpe_key()),
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
        )
        .expect("old profile must validate");
        let in_flight = old_state.get("patient-id").expect("profile must exist");

        old_state.zeroize();
        let mut new_input = input("patient-id", kid());
        new_input.tweak_aad = "tenant=new;field=patient_id;version=1".to_string();
        let new_state = validate_fpe_profiles(
            vec![new_input],
            |item| item == kid(),
            |_| Ok(fpe_key()),
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
        )
        .expect("new profile must validate");
        let current = new_state.get("patient-id").expect("profile must exist");

        assert_eq!(
            in_flight.tweak_aad(),
            "tenant=old;field=patient_id;version=1"
        );
        assert_eq!(current.tweak_aad(), "tenant=new;field=patient_id;version=1");
        assert!(!Arc::ptr_eq(&in_flight, &current));
    }

    #[test]
    fn rejects_duplicate_name() {
        let err = validate_fpe_profiles(
            vec![input("patient-id", kid()), input("patient-id", kid())],
            |item| item == kid(),
            |_| Ok(fpe_key()),
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
        )
        .expect_err("duplicate name must fail");
        assert!(err.to_string().contains("duplicated name"));
    }

    #[test]
    fn rejects_invalid_alphabet() {
        let mut profile = input("patient-id", kid());
        profile.alphabet = Some("001234".to_string());
        assert!(
            validate_fpe_profiles(
                vec![profile],
                |item| item == kid(),
                |_| Ok(fpe_key()),
                |_| Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES]
                )),
            )
            .is_err()
        );

        let mut profile = input("patient-id", kid());
        profile.max_len = FPE_VALUE_MAX_LEN;
        validate_fpe_profiles(
            vec![profile],
            |item| item == kid(),
            |_| Ok(fpe_key()),
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
        )
        .expect("maximum allowed fpe length must validate");

        let mut profile = input("patient-id", kid());
        profile.max_len = FPE_VALUE_MAX_LEN + 1;
        let err = validate_fpe_profiles(
            vec![profile],
            |item| item == kid(),
            |_| Ok(fpe_key()),
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
        )
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
            validate_fpe_profiles(
                vec![profile],
                |item| item == kid(),
                |_| Ok(fpe_key()),
                |_| Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES]
                )),
            )
            .is_err()
        );

        let mut profile = input("patient-id", kid());
        profile.min_len = 4;
        profile.max_len = 3;
        assert!(
            validate_fpe_profiles(
                vec![profile],
                |item| item == kid(),
                |_| Ok(fpe_key()),
                |_| Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES]
                )),
            )
            .is_err()
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
                |_| { Ok(fpe_key()) },
                |_| Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES]
                )),
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
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
        )
        .expect("profile must validate");
        let profile = state.get("patient-id").expect("profile must exist");
        let ciphertext = fpe_encrypt(&profile, "123456").expect("encrypt must work");
        let plaintext = fpe_decrypt(&profile, &ciphertext).expect("decrypt must work");

        assert_ne!(ciphertext, "123456");
        assert_eq!(plaintext, "123456");
    }

    #[test]
    fn fpe_is_deterministic_for_same_profile() {
        let state = validate_fpe_profiles(
            vec![input("patient-id", kid())],
            |item| item == kid(),
            real_fpe_key_for_request,
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
        )
        .expect("profile must validate");
        let profile = state.get("patient-id").expect("profile must exist");

        assert_eq!(
            fpe_encrypt(&profile, "123456").unwrap(),
            fpe_encrypt(&profile, "123456").unwrap()
        );
    }

    #[test]
    fn different_tweak_or_profile_changes_ciphertext() {
        let state = validate_fpe_profiles(
            vec![input("patient-id", kid())],
            |item| item == kid(),
            real_fpe_key_for_request,
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
        )
        .expect("profile must validate");
        let profile = state.get("patient-id").expect("profile must exist");
        let baseline = fpe_encrypt(&profile, "123456").unwrap();

        let mut other_tweak = input("patient-id", kid());
        other_tweak.tweak_aad = "tenant=acme;field=other;version=1".to_string();
        let other_tweak_state = validate_fpe_profiles(
            vec![other_tweak],
            |item| item == kid(),
            real_fpe_key_for_request,
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
        )
        .expect("profile must validate");
        let other_tweak_profile = other_tweak_state
            .get("patient-id")
            .expect("profile must exist");

        let other_profile_state = validate_fpe_profiles(
            vec![input("other-profile", kid())],
            |item| item == kid(),
            real_fpe_key_for_request,
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
        )
        .expect("profile must validate");
        let other_profile = other_profile_state
            .get("other-profile")
            .expect("profile must exist");

        assert_ne!(
            baseline,
            fpe_encrypt(&other_tweak_profile, "123456").unwrap()
        );
        assert_ne!(baseline, fpe_encrypt(&other_profile, "123456").unwrap());
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
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
        )
        .expect("profile must validate");
        let profile = state.get("patient-id").expect("profile must exist");

        let err = fpe_encrypt(&profile, "abc123").expect_err("invalid plaintext must fail");
        assert_eq!(
            err.to_string(),
            "plaintext contains character outside fpe profile alphabet"
        );
        let err = fpe_decrypt(&profile, "abc123").expect_err("invalid ciphertext must fail");
        assert_eq!(
            err.to_string(),
            "ciphertext contains character outside fpe profile alphabet"
        );
        assert!(fpe_encrypt(&profile, "123").is_err());
    }

    #[test]
    fn fpe_profile_zeroize_clears_metadata() {
        let mut state = validate_fpe_profiles(
            vec![input("patient-id", kid())],
            |item| item == kid(),
            |_| Ok(fpe_key()),
            |_| {
                Ok(zeroize::Zeroizing::new(
                    vec![9; crate::core::fpe::FPE_AUTH_KEY_SIZE_BYTES],
                ))
            },
        )
        .expect("profile must validate");
        let profile = state.get("patient-id").expect("profile must exist");
        state.zeroize();
        let mut profile = Arc::try_unwrap(profile).expect("profile must have one owner");

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
