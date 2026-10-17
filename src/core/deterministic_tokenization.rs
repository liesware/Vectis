use crate::core::tokenization::SubjectMode;
use crate::core::{canonical, crypto, mac, subjects, validation};
use crate::error::DynError;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use zeroize::{Zeroize, Zeroizing};

pub const PLAINTEXT_MAX_CHARS: usize = 16_384;
pub const TOKEN_MAX_CHARS: usize = 131_072;
pub const KEY_BYTES: usize = 64;
pub const HKDF_SALT: &[u8] = b"vectis/tokenization/deterministic/v1";
pub const VERSION: &str = "token-deterministic-v1";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeterministicTokenProfileInput {
    pub name: String,
    pub kid: String,
    pub context: String,
    pub min_plaintext_len: usize,
    pub max_plaintext_len: usize,
    #[serde(default, skip_serializing_if = "SubjectMode::is_none")]
    pub subject_mode: SubjectMode,
}

pub struct DeterministicTokenProfile {
    input: DeterministicTokenProfileInput,
    key: Zeroizing<Vec<u8>>,
}

impl DeterministicTokenProfile {
    pub fn kid(&self) -> &str {
        &self.input.kid
    }
    pub fn name(&self) -> &str {
        &self.input.name
    }
    pub fn subject_mode(&self) -> SubjectMode {
        self.input.subject_mode
    }
    pub fn validate_plaintext(&self, text: &str) -> Result<(), DynError> {
        let count = text.chars().count();
        if count < self.input.min_plaintext_len || count > self.input.max_plaintext_len {
            return Err(crate::error::invalid_input(
                "plaintext length is outside deterministic token profile bounds",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct DeterministicTokenProfilesState {
    profiles: HashMap<String, Arc<DeterministicTokenProfile>>,
}
impl DeterministicTokenProfilesState {
    pub fn get(&self, name: &str) -> Option<Arc<DeterministicTokenProfile>> {
        self.profiles.get(name).cloned()
    }
    pub fn len(&self) -> usize {
        self.profiles.len()
    }
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}
impl Zeroize for DeterministicTokenProfilesState {
    fn zeroize(&mut self) {
        self.profiles.clear();
    }
}

pub struct DeterministicTokenKeyDerivationRequest<'a> {
    pub profile_name: &'a str,
    pub kid: &'a str,
    pub context: &'a str,
}

pub(crate) fn validate_profiles(
    inputs: Vec<DeterministicTokenProfileInput>,
    loaded: impl Fn(&str) -> bool,
    derive: impl Fn(DeterministicTokenKeyDerivationRequest<'_>) -> Result<Zeroizing<Vec<u8>>, DynError>,
) -> Result<DeterministicTokenProfilesState, DynError> {
    let mut profiles = HashMap::new();
    for input in inputs {
        validation::validate_aad_config_name(
            "deterministic_tokenization_profiles.name",
            &input.name,
        )?;
        crate::ops::keys::validate_key_id(&input.kid)?;
        mac::validate_mac_profile_fields(&input.name, &input.context)?;
        if input.min_plaintext_len == 0
            || input.min_plaintext_len > input.max_plaintext_len
            || input.max_plaintext_len > PLAINTEXT_MAX_CHARS
        {
            return Err(crate::error::invalid_input(
                "deterministic token profile lengths must satisfy 1 <= min_plaintext_len <= max_plaintext_len <= 16384",
            ));
        }
        if profiles.contains_key(&input.name) {
            return Err(crate::error::invalid_input(
                "duplicate deterministic token profile name",
            ));
        }
        if !loaded(&input.kid) {
            return Err(crate::error::invalid_input(
                "deterministic token profile kid is not loaded",
            ));
        }
        let key = derive(DeterministicTokenKeyDerivationRequest {
            profile_name: &input.name,
            kid: &input.kid,
            context: &input.context,
        })?;
        if key.len() != KEY_BYTES {
            return Err(crate::error::internal(
                "invalid deterministic token key length",
            ));
        }
        profiles.insert(
            input.name.clone(),
            Arc::new(DeterministicTokenProfile { input, key }),
        );
    }
    Ok(DeterministicTokenProfilesState { profiles })
}

pub(crate) fn derive_profile_key(
    parent_hex: &str,
    request: DeterministicTokenKeyDerivationRequest<'_>,
) -> Result<Zeroizing<Vec<u8>>, DynError> {
    validation::validate_aad_config_name(
        "deterministic_tokenization_profiles.name",
        request.profile_name,
    )?;
    crate::ops::keys::validate_key_id(request.kid)?;
    let info = mac::build_mac_domain_aad(
        &[
            ("purpose", "token-deterministic-data"),
            ("profile", request.profile_name),
            ("kid", request.kid),
            ("tokenization_version", VERSION),
        ],
        request.context,
    )?;
    let parent = Zeroizing::new(hex::decode(parent_hex)?);
    Ok(Zeroizing::new(crypto::create_hkdf(
        &parent,
        HKDF_SALT,
        info.as_bytes(),
        KEY_BYTES,
    )?))
}

#[derive(Serialize)]
struct TokenContext<'a> {
    purpose: &'static str,
    version: &'static str,
    kid: &'a str,
    profile: &'a str,
    context: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<&'a str>,
}

pub struct DeterministicTokenContext {
    profile: Arc<DeterministicTokenProfile>,
    subject: Option<String>,
    child_key: Option<Zeroizing<Vec<u8>>>,
    aad: Vec<u8>,
}
impl DeterministicTokenContext {
    pub fn new(profile: Arc<DeterministicTokenProfile>) -> Result<Self, DynError> {
        validate_subject_mode(&profile, None)?;
        Self::build(profile, None, None)
    }
    pub fn from_subject_envelope(
        profile: Arc<DeterministicTokenProfile>,
        origin: &crate::core::tokenization::TokenizationProfile,
        subject: &str,
        envelope: &str,
    ) -> Result<Self, DynError> {
        validate_subject_mode(&profile, Some(subject))?;
        if origin.kid() != profile.kid()
            || origin.subject_mode() != crate::core::tokenization::SubjectMode::Stored
        {
            return Err(crate::error::internal("stored subject seed is invalid"));
        }
        let seed = subjects::open_authenticated_seed(origin, subject, envelope)?;
        let info = validation::build_validated_aad(&[
            ("purpose", "subject-token-deterministic-data"),
            ("kid", profile.kid()),
            ("profile", profile.name()),
            ("version", "v1"),
        ])?;
        let key = Zeroizing::new(crypto::create_hkdf(
            &profile.key,
            seed.as_bytes(),
            info.as_bytes(),
            KEY_BYTES,
        )?);
        Self::build(profile, Some(subject.to_owned()), Some(key))
    }
    fn build(
        profile: Arc<DeterministicTokenProfile>,
        subject: Option<String>,
        child_key: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<Self, DynError> {
        let aad = canonical::canonical_json_v1(&TokenContext {
            purpose: "token-deterministic",
            version: "v1",
            kid: profile.kid(),
            profile: profile.name(),
            context: &profile.input.context,
            subject: subject.as_deref(),
        })?;
        Ok(Self {
            profile,
            subject,
            child_key,
            aad,
        })
    }
    pub fn kid(&self) -> &str {
        self.profile.kid()
    }
    pub fn profile_name(&self) -> &str {
        self.profile.name()
    }
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }
    fn key(&self) -> &[u8] {
        self.child_key
            .as_deref()
            .map(Vec::as_slice)
            .unwrap_or(&self.profile.key)
    }
    pub fn encode(&self, plaintext: &str) -> Result<String, DynError> {
        self.profile.validate_plaintext(plaintext)?;
        let encrypted = crypto::encrypt_aes256_siv(self.key(), &self.aad, plaintext.as_bytes())?;
        let token = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&self.aad),
            URL_SAFE_NO_PAD.encode(encrypted)
        );
        validate_token(&token)?;
        Ok(token)
    }
    pub fn decode(&self, token: &str) -> Result<Zeroizing<String>, DynError> {
        validate_token(token)?;
        let (context, ciphertext) = token.split_once('.').expect("validated segments");
        let context = decode_segment(context)?;
        let ciphertext = decode_segment(ciphertext)?;
        if context != self.aad {
            return Err(authentication_failed());
        }
        let plaintext = crypto::decrypt_aes256_siv(self.key(), &self.aad, &ciphertext)?;
        let text = std::str::from_utf8(&plaintext).map_err(|_| authentication_failed())?;
        Ok(Zeroizing::new(text.to_owned()))
    }
}

pub fn validate_subject_mode(
    profile: &DeterministicTokenProfile,
    subject: Option<&str>,
) -> Result<(), DynError> {
    if let Some(subject) = subject {
        subjects::validate_subject(subject)?;
    }
    match (profile.subject_mode(), subject) {
        (SubjectMode::Stored, None) => Err(crate::error::invalid_input(
            "subject is required for stored deterministic token profiles",
        )),
        (SubjectMode::None, Some(_)) => Err(crate::error::invalid_input(
            "subject is prohibited for none deterministic token profiles",
        )),
        _ => Ok(()),
    }
}

pub fn authentication_failed() -> DynError {
    crate::error::invalid_input("deterministic token authentication failed")
}
fn decode_segment(value: &str) -> Result<Vec<u8>, DynError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| crate::error::invalid_input("invalid deterministic token encoding"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(crate::error::invalid_input(
            "invalid deterministic token encoding",
        ));
    }
    Ok(bytes)
}
pub fn validate_token(token: &str) -> Result<(), DynError> {
    if token.len() > TOKEN_MAX_CHARS || !token.is_ascii() {
        return Err(crate::error::invalid_input(
            "deterministic token exceeds maximum allowed size or is not ASCII",
        ));
    }
    let Some((context, ciphertext)) = token.split_once('.') else {
        return Err(crate::error::invalid_input(
            "deterministic token requires two segments",
        ));
    };
    if context.is_empty() || ciphertext.is_empty() || ciphertext.contains('.') {
        return Err(crate::error::invalid_input(
            "deterministic token requires two segments",
        ));
    }
    decode_segment(context)?;
    if decode_segment(ciphertext)?.len() <= 16 {
        return Err(crate::error::invalid_input(
            "deterministic token ciphertext is too short",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn input() -> DeterministicTokenProfileInput {
        serde_json::from_value(json!({"name":"email-v1","kid":"a".repeat(64),"context":"tenant=acme;field=email;version=1","min_plaintext_len":1,"max_plaintext_len":16384})).unwrap()
    }
    fn profile(input: DeterministicTokenProfileInput) -> Arc<DeterministicTokenProfile> {
        let name = input.name.clone();
        validate_profiles(
            vec![input],
            |_| true,
            |r| derive_profile_key(&"ab".repeat(32), r),
        )
        .unwrap()
        .get(&name)
        .unwrap()
    }
    #[test]
    fn aes256_siv_wycheproof_302() {
        // Google Wycheproof aes_siv_cmac_test.json, tcId 302 (512-bit combined key).
        let key = hex::decode("c25cafc6018b98dfbb79a40ec89c575a4f88c4116489bba27707479800c0130235334a45dbe8d8dae3da8dcb45bbe5dce031b0f68ded544fda7eca30d6749442").unwrap();
        let aad = hex::decode("deeb0ccf3aef47a296ed1ca8f4ae5907").unwrap();
        let msg = hex::decode("beec61030fa3d670337196beade6aeaa").unwrap();
        let expected =
            hex::decode("5865208eab9163db85cab9f96d846234a2626aae22f5c17c9aad4b501f4416e4")
                .unwrap();
        assert_eq!(
            crypto::encrypt_aes256_siv(&key, &aad, &msg).unwrap(),
            expected
        );
        assert_eq!(
            &*crypto::decrypt_aes256_siv(&key, &aad, &expected).unwrap(),
            &msg
        );
        assert!(crypto::encrypt_aes256_siv(&key[..32], &aad, &msg).is_err());
        assert!(crypto::decrypt_aes256_siv(&key, b"other", &expected).is_err());
    }
    #[test]
    fn deterministic_unicode_roundtrip_and_tampering() {
        let context = DeterministicTokenContext::new(profile(input())).unwrap();
        let text = "\u{1f600}".repeat(PLAINTEXT_MAX_CHARS);
        let token = context.encode(&text).unwrap();
        assert!(token.len() < TOKEN_MAX_CHARS);
        assert_eq!(token, context.encode(&text).unwrap());
        assert_eq!(*context.decode(&token).unwrap(), text);
        assert!(context.encode(&(text + "a")).is_err());
        assert!(context.encode("").is_err());
        let (aad, ct) = token.split_once('.').unwrap();
        let mut raw = decode_segment(ct).unwrap();
        raw[0] ^= 1;
        let bad = format!("{aad}.{}", URL_SAFE_NO_PAD.encode(raw));
        assert_eq!(
            context.decode(&bad).unwrap_err().to_string(),
            "deterministic token authentication failed"
        );
        let mut changed = input();
        changed.context = "tenant=other".to_owned();
        let other = DeterministicTokenContext::new(profile(changed)).unwrap();
        assert_ne!(
            other.encode("same").unwrap(),
            context.encode("same").unwrap()
        );
        assert!(other.decode(&token).is_err());
    }
    #[test]
    fn exact_derivation_and_subject_separation() {
        let unscoped = profile(input());
        let mut stored = input();
        stored.subject_mode = SubjectMode::Stored;
        let p = profile(stored);
        assert_eq!(p.key, unscoped.key);
        let info = format!(
            "purpose=token-deterministic-data;profile=email-v1;kid={};tokenization_version=token-deterministic-v1;context.tenant=acme;context.field=email;context.version=1",
            p.kid()
        );
        assert_eq!(
            *p.key,
            crypto::create_hkdf(&[0xab; 32], HKDF_SALT, info.as_bytes(), 64).unwrap()
        );
        let origins = crate::core::tokenization::validate_tokenization_profiles(
            serde_json::from_value(json!([{"name":"origin","kid":p.kid(),"token_prefix":"subject","token_len":32,"max_plaintext_len":128,"one_time":false,"subject_mode":"stored"}])).unwrap(),
            |_| true, |r| crate::core::tokenization::derive_tokenization_keys(&"ab".repeat(32), "AES-256/GCM", r),
        ).unwrap();
        let origin = origins.get("origin").unwrap();
        let subject = subjects::subject_id(&origin, "user").unwrap();
        let envelope = subjects::create_seed(&origin, &subject).unwrap();
        let context = DeterministicTokenContext::from_subject_envelope(
            p.clone(),
            &origin,
            &subject,
            &envelope,
        )
        .unwrap();
        let seed = subjects::open_authenticated_seed(&origin, &subject, &envelope).unwrap();
        let info = format!(
            "purpose=subject-token-deterministic-data;kid={};profile=email-v1;version=v1",
            p.kid()
        );
        assert_eq!(
            context.key(),
            crypto::create_hkdf(&p.key, seed.as_bytes(), info.as_bytes(), 64).unwrap()
        );
        let token = context.encode("same").unwrap();
        assert_eq!(&*context.decode(&token).unwrap(), "same");
        assert!(
            DeterministicTokenContext::new(unscoped)
                .unwrap()
                .decode(&token)
                .is_err()
        );
        let fresh = subjects::create_seed(&origin, &subject).unwrap();
        let recreated =
            DeterministicTokenContext::from_subject_envelope(p.clone(), &origin, &subject, &fresh)
                .unwrap();
        assert!(recreated.decode(&token).is_err());
        assert!(
            DeterministicTokenContext::from_subject_envelope(p, &origin, &subject, "corrupt")
                .is_err()
        );
    }
    #[test]
    fn strict_config_and_encoding() {
        for field in [
            "name",
            "kid",
            "context",
            "min_plaintext_len",
            "max_plaintext_len",
        ] {
            let mut value = serde_json::to_value(input()).unwrap();
            value[field] = serde_json::Value::Null;
            assert!(serde_json::from_value::<DeterministicTokenProfileInput>(value).is_err());
        }
        for (min, max) in [(0, 1), (2, 1), (1, 16385)] {
            let mut i = input();
            i.min_plaintext_len = min;
            i.max_plaintext_len = max;
            assert!(
                validate_profiles(vec![i], |_| true, |_| Ok(Zeroizing::new(vec![0; 64]))).is_err()
            );
        }
        assert!(
            validate_profiles(
                vec![input(), input()],
                |_| true,
                |_| Ok(Zeroizing::new(vec![0; 64]))
            )
            .is_err()
        );
        assert!(
            validate_profiles(vec![input()], |_| false, |_| panic!("must not derive")).is_err()
        );
        let token = DeterministicTokenContext::new(profile(input()))
            .unwrap()
            .encode("hello")
            .unwrap();
        for bad in [
            "".to_owned(),
            "a.b.c".to_owned(),
            token.clone() + "=",
            "a".repeat(TOKEN_MAX_CHARS + 1),
        ] {
            assert!(validate_token(&bad).is_err());
        }
        let (aad, ct) = token.split_once('.').unwrap();
        let mut context = decode_segment(aad).unwrap();
        context.push(b' ');
        let noncanonical = format!("{}.{ct}", URL_SAFE_NO_PAD.encode(context));
        assert!(
            DeterministicTokenContext::new(profile(input()))
                .unwrap()
                .decode(&noncanonical)
                .is_err()
        );
    }

    #[test]
    fn subject_mode_is_strict_and_preserves_canonical_config() {
        let absent = serde_json::to_value(input()).unwrap();
        assert!(absent.get("subject_mode").is_none());
        let mut explicit = absent.clone();
        explicit["subject_mode"] = json!("none");
        let parsed: DeterministicTokenProfileInput = serde_json::from_value(explicit).unwrap();
        assert_eq!(
            canonical::canonical_json_v1(&parsed).unwrap(),
            canonical::canonical_json_v1(&input()).unwrap()
        );
        let mut stored = absent.clone();
        stored["subject_mode"] = json!("stored");
        let parsed: DeterministicTokenProfileInput =
            serde_json::from_value(stored.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), stored);
        for invalid in [
            json!(null),
            json!(false),
            json!(1),
            json!("optional"),
            json!("STORED"),
        ] {
            let mut value = absent.clone();
            value["subject_mode"] = invalid;
            assert!(serde_json::from_value::<DeterministicTokenProfileInput>(value).is_err());
        }
    }

    #[test]
    fn subject_policy_rejects_before_seed_open_and_does_not_change_crypto() {
        let none = profile(input());
        let mut input = input();
        input.subject_mode = SubjectMode::Stored;
        let stored = profile(input);
        let subject = "b".repeat(64);
        assert!(validate_subject_mode(&none, None).is_ok());
        assert!(validate_subject_mode(&stored, Some(&subject)).is_ok());
        assert_eq!(
            DeterministicTokenContext::new(stored.clone())
                .err()
                .unwrap()
                .to_string(),
            "subject is required for stored deterministic token profiles"
        );
        // Both profiles have exactly the same parent; mode is policy, not KDF input.
        assert_eq!(none.key, stored.key);
        let origins = crate::core::tokenization::validate_tokenization_profiles(
            serde_json::from_value(json!([{"name":"origin","kid":none.kid(),"token_prefix":"subject","token_len":32,"max_plaintext_len":128,"one_time":false,"subject_mode":"stored"}])).unwrap(),
            |_| true, |r| crate::core::tokenization::derive_tokenization_keys(&"ab".repeat(32), "AES-256/GCM", r),
        ).unwrap();
        let origin = origins.get("origin").unwrap();
        assert_eq!(
            DeterministicTokenContext::from_subject_envelope(
                none.clone(),
                &origin,
                &subject,
                "corrupt"
            )
            .err()
            .unwrap()
            .to_string(),
            "subject is prohibited for none deterministic token profiles"
        );
        let envelope = subjects::create_seed(&origin, &subject).unwrap();
        let context =
            DeterministicTokenContext::from_subject_envelope(stored, &origin, &subject, &envelope)
                .unwrap();
        let previous = DeterministicTokenContext::build(
            none,
            Some(subject),
            Some(Zeroizing::new(context.key().to_vec())),
        )
        .unwrap();
        let token = previous.encode("previous subject token").unwrap();
        assert_eq!(token, context.encode("previous subject token").unwrap());
        assert_eq!(&*context.decode(&token).unwrap(), "previous subject token");
    }

    #[test]
    fn shared_snapshot_retains_parent_until_last_owner_drops() {
        let mut state = validate_profiles(
            vec![input()],
            |_| true,
            |r| derive_profile_key(&"ab".repeat(32), r),
        )
        .unwrap();
        let profile = state.get("email-v1").unwrap();
        let weak = Arc::downgrade(&profile);
        let context = DeterministicTokenContext::new(profile).unwrap();
        state.zeroize();
        assert!(weak.upgrade().is_some());
        assert!(context.encode("in-flight").is_ok());
        drop(context);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn decode_ignores_tightened_bounds_and_rejects_empty_ciphertext() {
        let token = DeterministicTokenContext::new(profile(input()))
            .unwrap()
            .encode(&"x".repeat(100))
            .unwrap();
        let mut narrow = input();
        narrow.max_plaintext_len = 10;
        assert_eq!(
            *DeterministicTokenContext::new(profile(narrow))
                .unwrap()
                .decode(&token)
                .unwrap(),
            "x".repeat(100)
        );
        let (aad, _) = token.split_once('.').unwrap();
        let empty = format!("{aad}.{}", URL_SAFE_NO_PAD.encode([0u8; 16]));
        assert!(validate_token(&empty).is_err());
    }
}
