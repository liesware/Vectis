//! Per-subject seed envelopes and request-scoped token keys. No storage or IO.
use crate::core::{crypto, tokenization::TokenizationProfile, validation};
use crate::error::DynError;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const SUBJECT_NAME_MAX_CHARS: usize = 128;
pub const SUBJECT_ID_HEX_CHARS: usize = 64;
pub const SUBJECT_SEED_BYTES: usize = 32;
pub const SUBJECT_SEED_ENVELOPE_MAX_CHARS: usize = 2048;
const WRAP_SALT: &[u8] = b"vectis/subjects/v1";

pub struct SubjectTokenKeys {
    pub(crate) subject: String,
    pub(crate) hash_key: Zeroizing<Vec<u8>>,
    pub(crate) data_key: Zeroizing<Vec<u8>>,
}

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct SeedPayload {
    seed: String,
}

pub fn validate_subject_name(value: &str) -> Result<(), DynError> {
    validation::validate_bounded_text_field("subject_name", value, SUBJECT_NAME_MAX_CHARS)?;
    if value.contains([';', '=']) {
        return Err(crate::error::invalid_input(
            "subject_name must not contain ';' or '='",
        ));
    }
    Ok(())
}

pub fn validate_subject(value: &str) -> Result<(), DynError> {
    if value.len() != SUBJECT_ID_HEX_CHARS
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(crate::error::invalid_input(
            "subject must be exactly 64 lowercase hex characters",
        ));
    }
    Ok(())
}

pub fn validate_seed_envelope(seed: &str) -> Result<(), DynError> {
    if !seed.is_ascii() {
        return Err(crate::error::invalid_input("subjects.seed must be ASCII"));
    }
    let (ciphertext, nonce, _) = validation::validate_base64_standard_envelope_segments(
        "subjects.seed",
        seed,
        SUBJECT_SEED_ENVELOPE_MAX_CHARS,
    )?;
    if STANDARD.decode(ciphertext)?.len() < 16 || !matches!(STANDARD.decode(nonce)?.len(), 12 | 24)
    {
        return Err(crate::error::invalid_input(
            "subjects.seed has invalid tag or nonce length",
        ));
    }
    Ok(())
}

fn key_info(profile: &TokenizationProfile, purpose: &str) -> Result<String, DynError> {
    validation::build_validated_aad(&[
        ("purpose", purpose),
        ("kid", profile.kid()),
        ("profile", profile.name()),
        ("version", "v1"),
    ])
}

fn seed_aad(profile: &TokenizationProfile, subject: &str) -> Result<String, DynError> {
    validate_subject(subject)?;
    validation::build_validated_aad(&[
        ("version", "v1"),
        ("type", "subject-seed"),
        ("kid", profile.kid()),
        ("profile", profile.name()),
        ("subject", subject),
        ("cipher", profile.cipher_algorithm()),
    ])
}

pub fn subject_id(profile: &TokenizationProfile, name: &str) -> Result<String, DynError> {
    validate_subject_name(name)?;
    let message = Zeroizing::new(validation::build_validated_aad(&[
        ("purpose", "subject-lookup"),
        ("kid", profile.kid()),
        ("profile", profile.name()),
        ("subject_name", name),
        ("version", "v1"),
    ])?);
    Ok(hex::encode(crypto::create_hmac(
        profile.hash_key(),
        message.as_bytes(),
    )?))
}

fn wrapping_key(profile: &TokenizationProfile) -> Result<Zeroizing<Vec<u8>>, DynError> {
    let cipher = crypto::symmetric_cipher(profile.cipher_algorithm())
        .ok_or_else(|| crate::error::internal("unsupported subject cipher"))?;
    Ok(Zeroizing::new(crypto::create_hkdf(
        profile.data_key(),
        WRAP_SALT,
        key_info(profile, "subject-wrap")?.as_bytes(),
        cipher.key_size_bytes,
    )?))
}

pub fn create_seed(profile: &TokenizationProfile, subject: &str) -> Result<String, DynError> {
    let aad = seed_aad(profile, subject)?;
    let cipher = crypto::symmetric_cipher(profile.cipher_algorithm())
        .ok_or_else(|| crate::error::internal("unsupported subject cipher"))?;
    let seed = Zeroizing::new(crypto::random_bytes(SUBJECT_SEED_BYTES)?);
    let payload = SeedPayload {
        seed: hex::encode(&*seed),
    };
    let plaintext = Zeroizing::new(serde_json::to_string(&payload)?);
    let nonce = Zeroizing::new(crypto::random_bytes(cipher.nonce_size_bytes)?);
    let key = wrapping_key(profile)?;
    let ciphertext =
        crypto::encrypt_symmetric(cipher.algorithm, &plaintext, &key, &nonce, aad.as_bytes())?;
    let envelope = format!(
        "{}.{}.{}",
        STANDARD.encode(ciphertext),
        STANDARD.encode(&*nonce),
        STANDARD.encode(aad)
    );
    validate_seed_envelope(&envelope)?;
    Ok(envelope)
}

pub fn open_seed(
    profile: &TokenizationProfile,
    subject: &str,
    envelope: &str,
) -> Result<SubjectTokenKeys, DynError> {
    // Stored corruption is an internal failure, never reflected to callers.
    open_seed_inner(profile, subject, envelope)
        .map_err(|_| crate::error::internal("stored subject seed is invalid"))
}

fn open_seed_inner(
    profile: &TokenizationProfile,
    subject: &str,
    envelope: &str,
) -> Result<SubjectTokenKeys, DynError> {
    validate_seed_envelope(envelope)?;
    let cipher = crypto::symmetric_cipher(profile.cipher_algorithm())
        .ok_or_else(|| crate::error::internal("unsupported subject cipher"))?;
    let decoded = validation::decode_base64_standard_envelope(
        "subjects.seed",
        envelope,
        SUBJECT_SEED_ENVELOPE_MAX_CHARS,
        cipher.nonce_size_bytes,
    )?;
    let aad = seed_aad(profile, subject)?;
    if decoded.aad.as_slice() != aad.as_bytes() {
        return Err(crate::error::internal("subject seed context mismatch"));
    }
    let key = wrapping_key(profile)?;
    let plaintext = Zeroizing::new(crypto::decrypt_symmetric(
        cipher.algorithm,
        &decoded.ciphertext,
        &key,
        &decoded.nonce,
        &decoded.aad,
    )?);
    let payload: SeedPayload = serde_json::from_slice(&plaintext)?;
    validation::validate_symmetric_key("seed", &payload.seed, SUBJECT_SEED_BYTES)?;
    let seed = Zeroizing::new(hex::decode(&payload.seed)?);
    Ok(SubjectTokenKeys {
        subject: subject.to_owned(),
        hash_key: Zeroizing::new(crypto::create_hkdf(
            profile.hash_key(),
            &seed,
            key_info(profile, "subject-token-hash")?.as_bytes(),
            32,
        )?),
        data_key: Zeroizing::new(crypto::create_hkdf(
            profile.data_key(),
            &seed,
            key_info(profile, "subject-token-data")?.as_bytes(),
            cipher.key_size_bytes,
        )?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str, kid: &str, cipher: &str) -> std::sync::Arc<TokenizationProfile> {
        let state = crate::core::tokenization::validate_tokenization_profiles(
            serde_json::from_value(serde_json::json!([{
                "name":name,"kid":kid,"token_prefix":"tok_subject","token_len":32,
                "max_plaintext_len":128,"one_time":false,"subject_mode":"stored"
            }]))
            .unwrap(),
            |_| true,
            |request| {
                crate::core::tokenization::derive_tokenization_keys(
                    &"aa".repeat(32),
                    cipher,
                    request,
                )
            },
        )
        .unwrap();
        state.get(name).unwrap()
    }

    #[test]
    fn seed_keys_are_separated_authenticated_and_not_recoverable_after_recreation() {
        for cipher in [
            "AES-128/GCM",
            "AES-192/GCM",
            "AES-256/GCM",
            "ChaCha20Poly1305",
        ] {
            let profile = profile("subjects-v1", &"a".repeat(64), cipher);
            let subject = subject_id(&profile, "user-1").unwrap();
            let other = subject_id(&profile, "user-2").unwrap();
            assert_ne!(subject, other);
            assert_ne!(subject_id(&profile, " user-1").unwrap(), subject);
            assert_ne!(
                subject_id(&profile, "\u{e9}").unwrap(),
                subject_id(&profile, "e\u{301}").unwrap()
            );
            let envelope = create_seed(&profile, &subject).unwrap();
            let keys = open_seed(&profile, &subject, &envelope).unwrap();
            let same = open_seed(&profile, &subject, &envelope).unwrap();
            assert_eq!(&*keys.hash_key, &*same.hash_key);
            assert_eq!(&*keys.data_key, &*same.data_key);
            assert_ne!(keys.hash_key.as_slice(), profile.hash_key());
            assert_ne!(keys.hash_key.as_slice(), keys.data_key.as_slice());
            assert!(open_seed(&profile, &other, &envelope).is_err());
            let token = crate::core::tokenization::generate_token(&profile).unwrap();
            let context =
                crate::core::tokenization::TokenContext::with_subject(profile.clone(), keys);
            let hashid = context.hash(&token).unwrap();
            let payload = crate::core::tokenization::TokenDataPayload {
                profile: profile.name().to_owned(),
                plaintext: "synthetic".to_owned(),
                metadata: None,
                created_at: validation::current_timestamp().unwrap(),
            };
            let data = context.encrypt(&hashid, &payload).unwrap();
            assert_eq!(
                context.decrypt(&hashid, &data).unwrap().plaintext,
                "synthetic"
            );
            let new_keys = open_seed(
                &profile,
                &subject,
                &create_seed(&profile, &subject).unwrap(),
            )
            .unwrap();
            let recreated =
                crate::core::tokenization::TokenContext::with_subject(profile.clone(), new_keys);
            assert_ne!(recreated.hash(&token).unwrap(), hashid);
            assert!(recreated.decrypt(&hashid, &data).is_err());
            let legacy = crate::core::tokenization::TokenContext::from(profile.clone());
            assert!(legacy.hash(&token).is_err());
            for index in 0..3 {
                let mut segments = envelope.split('.').map(str::to_owned).collect::<Vec<_>>();
                let mut bytes = STANDARD.decode(&segments[index]).unwrap();
                bytes[0] ^= 1;
                segments[index] = STANDARD.encode(bytes);
                let error = open_seed(&profile, &subject, &segments.join("."))
                    .err()
                    .unwrap();
                assert_eq!(error.to_string(), "stored subject seed is invalid");
            }
        }
    }

    #[test]
    fn domains_and_decoded_seed_shape_are_strict() {
        let kid = "a".repeat(64);
        let p = profile("subjects-v1", &kid, "AES-256/GCM");
        let id = subject_id(&p, "user").unwrap();
        assert_ne!(
            id,
            subject_id(&profile("subjects-v2", &kid, "AES-256/GCM"), "user").unwrap()
        );
        assert_ne!(
            id,
            subject_id(
                &profile("subjects-v1", &"b".repeat(64), "AES-256/GCM"),
                "user"
            )
            .unwrap()
        );
        let envelope = create_seed(&p, &id).unwrap();
        assert!(open_seed(&profile("subjects-v2", &kid, "AES-256/GCM"), &id, &envelope).is_err());
        let nonce = vec![0; 12];
        let aad = seed_aad(&p, &id).unwrap();
        for plaintext in [
            serde_json::json!({"seed":"aa".repeat(31)}),
            serde_json::json!({"seed":"aa".repeat(32),"extra":true}),
        ] {
            let ciphertext = crypto::encrypt_symmetric(
                "AES-256/GCM",
                &plaintext.to_string(),
                &wrapping_key(&p).unwrap(),
                &nonce,
                aad.as_bytes(),
            )
            .unwrap();
            let envelope = format!(
                "{}.{}.{}",
                STANDARD.encode(ciphertext),
                STANDARD.encode(&nonce),
                STANDARD.encode(&aad)
            );
            assert!(open_seed(&p, &id, &envelope).is_err());
        }
    }
    #[test]
    fn subject_fields_are_bounded_and_not_normalized() {
        for valid in ["a".repeat(128), "界".repeat(128), " user ".to_owned()] {
            validate_subject_name(&valid).unwrap();
        }
        for invalid in [
            "a".repeat(129),
            "界".repeat(129),
            " ".to_owned(),
            "a;b".to_owned(),
            "a=b".to_owned(),
            "a\n".to_owned(),
        ] {
            assert!(validate_subject_name(&invalid).is_err());
        }
        validate_subject(&"a".repeat(64)).unwrap();
        for invalid in [
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            "界".repeat(64),
        ] {
            assert!(validate_subject(&invalid).is_err());
        }
        assert!(validate_seed_envelope(&"a".repeat(2049)).is_err());
        // Base64 segment lengths are multiples of four; two separators remain.
        let max = format!("{}.AAAAAAAAAAAAAAAA.dmFsaWQtYWFk", "A".repeat(2016));
        assert_eq!(max.len(), SUBJECT_SEED_ENVELOPE_MAX_CHARS - 2);
        validate_seed_envelope(&max).unwrap();
        assert!(validate_seed_envelope(&(max + "AAA")).is_err());
    }
}
