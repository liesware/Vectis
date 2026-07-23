use crate::core::{canonical, config, crypto, mac, validation};
use crate::error::DynError;
use crate::ops::keys;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub const SHARING_KEY_SALT: &[u8] = b"vectis/sharing/v1";
pub const SHARING_HMAC_SUBKEY_SALT: &[u8] = b"vectis/sharing/hmac/v1";
pub const SHARING_KEY_SIZE_BYTES: usize = 32;
pub const SHARING_CONTEXT_MAX_CHARS: usize = 128;
pub const SHARING_MIN_THRESHOLD: usize = 2;
pub const SHARING_SECRET_MAX_BYTES: usize = 4096;
pub const SHARING_SET_ID_BYTES: usize = 16;
pub const SHARE_PREFIX: &str = "vectis-sss-v1.";
const SHARE_ENVELOPE_MAX_CHARS: usize = 16 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SharingProfileInput {
    name: String,
    kid: String,
    threshold: usize,
    shares: usize,
    max_secret_len: usize,
    context: String,
}

#[derive(Clone)]
pub struct SharingProfile {
    name: String,
    kid: String,
    threshold: usize,
    shares: usize,
    max_secret_len: usize,
    context: String,
    public_algorithm: String,
    botan_algorithm: String,
    customization: String,
    share_auth_key: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Default)]
pub struct SharingProfilesState {
    profiles: Vec<SharingProfile>,
    by_name: HashMap<String, usize>,
}

pub struct SharingKeyDerivationRequest<'a> {
    pub profile_name: &'a str,
    pub kid: &'a str,
    pub context: &'a str,
    pub hash_algorithm: &'a str,
}

pub struct DerivedSharingKey {
    pub public_algorithm: String,
    pub botan_algorithm: String,
    pub share_auth_key: Zeroizing<Vec<u8>>,
}

pub(crate) struct RawShare {
    pub index: u8,
    pub value: Zeroizing<Vec<u8>>,
}

#[derive(Serialize)]
struct UnsignedShareEnvelope<'a> {
    version: &'static str,
    set_id: &'a str,
    profile: &'a str,
    kid: &'a str,
    threshold: usize,
    shares: usize,
    index: u8,
    share: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShareEnvelope {
    version: String,
    set_id: String,
    profile: String,
    kid: String,
    threshold: usize,
    shares: usize,
    index: u8,
    share: String,
    tag: String,
}

impl fmt::Debug for SharingProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharingProfile")
            .field("name", &self.name)
            .field("kid", &self.kid)
            .field("threshold", &self.threshold)
            .field("shares", &self.shares)
            .field("max_secret_len", &self.max_secret_len)
            .field("context", &self.context)
            .field("public_algorithm", &self.public_algorithm)
            .field("botan_algorithm", &self.botan_algorithm)
            .field("share_auth_key", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for SharingProfilesState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharingProfilesState")
            .field("profiles", &self.profiles)
            .finish_non_exhaustive()
    }
}

impl SharingProfile {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn shares(&self) -> usize {
        self.shares
    }

    pub fn max_secret_len(&self) -> usize {
        self.max_secret_len
    }

    pub fn customization(&self) -> &str {
        &self.customization
    }

    pub fn botan_algorithm(&self) -> &str {
        &self.botan_algorithm
    }

    pub fn share_auth_key(&self) -> &[u8] {
        &self.share_auth_key
    }

    pub fn uses_kmac(&self) -> bool {
        mac::is_kmac_algorithm(&self.public_algorithm)
    }
}

impl SharingProfilesState {
    fn from_profiles(profiles: Vec<SharingProfile>) -> Self {
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

    pub fn get(&self, name: &str) -> Option<&SharingProfile> {
        self.by_name
            .get(name)
            .and_then(|index| self.profiles.get(*index))
    }
}

impl Zeroize for SharingProfilesState {
    fn zeroize(&mut self) {
        self.profiles.zeroize();
        self.by_name.clear();
    }
}

impl Zeroize for SharingProfile {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.kid.zeroize();
        self.context.zeroize();
        self.public_algorithm.zeroize();
        self.botan_algorithm.zeroize();
        self.customization.zeroize();
        self.share_auth_key.zeroize();
        self.threshold = 0;
        self.shares = 0;
        self.max_secret_len = 0;
    }
}

pub(crate) fn validate_sharing_profiles(
    inputs: Vec<SharingProfileInput>,
    is_loaded_kid: impl Fn(&str) -> bool,
    hash_algorithm_for_kid: impl Fn(&str) -> Result<String, DynError>,
    derive_sharing_key: impl Fn(SharingKeyDerivationRequest<'_>) -> Result<DerivedSharingKey, DynError>,
) -> Result<SharingProfilesState, DynError> {
    let mut seen_names = HashSet::new();
    let mut profiles = Vec::new();

    for input in inputs {
        validate_sharing_profile_fields(
            &input.name,
            &input.context,
            input.threshold,
            input.shares,
            input.max_secret_len,
        )?;
        keys::validate_key_id(&input.kid).map_err(|err| {
            crate::error::invalid_input(format!("sharing_profiles.kid is invalid: {err}"))
        })?;
        if !is_loaded_kid(&input.kid) {
            return Err(crate::error::invalid_input(format!(
                "sharing profile references kid not loaded in memory: {}",
                input.kid
            )));
        }
        if !seen_names.insert(input.name.clone()) {
            return Err(crate::error::invalid_input(format!(
                "sharing profile has duplicated name: {}",
                input.name
            )));
        }

        let hash_algorithm = hash_algorithm_for_kid(&input.kid)?;
        let derived = derive_sharing_key(SharingKeyDerivationRequest {
            profile_name: &input.name,
            kid: &input.kid,
            context: &input.context,
            hash_algorithm: &hash_algorithm,
        })?;
        if derived.share_auth_key.len() != SHARING_KEY_SIZE_BYTES {
            return Err(crate::error::internal(
                "derived sharing key has invalid length",
            ));
        }

        let customization = mac::build_mac_domain_aad(
            &[("profile", &input.name), ("kid", &input.kid)],
            &input.context,
        )?;
        let share_auth_key = mac::derive_keyed_tag_subkey(
            &derived.public_algorithm,
            derived.share_auth_key,
            SHARING_HMAC_SUBKEY_SALT,
            &customization,
            SHARING_KEY_SIZE_BYTES,
        )?;

        profiles.push(SharingProfile {
            name: input.name,
            kid: input.kid,
            threshold: input.threshold,
            shares: input.shares,
            max_secret_len: input.max_secret_len,
            context: input.context,
            public_algorithm: derived.public_algorithm,
            botan_algorithm: derived.botan_algorithm,
            customization,
            share_auth_key,
        });
    }

    Ok(SharingProfilesState::from_profiles(profiles))
}

pub fn validate_sharing_profile_fields(
    name: &str,
    context: &str,
    threshold: usize,
    shares: usize,
    max_secret_len: usize,
) -> Result<(), DynError> {
    validation::validate_aad_config_name("sharing_profiles.name", name)?;
    validation::validate_labels(
        "sharing_profiles.context",
        context,
        SHARING_CONTEXT_MAX_CHARS,
    )?;
    validate_threshold(threshold, shares)?;
    validate_max_secret_len(max_secret_len)?;
    Ok(())
}

pub fn validate_threshold(threshold: usize, shares: usize) -> Result<(), DynError> {
    if threshold < SHARING_MIN_THRESHOLD {
        return Err(crate::error::invalid_input(format!(
            "sharing_profiles.threshold must be at least {SHARING_MIN_THRESHOLD}"
        )));
    }
    if shares > config::INTERNAL_SHARE_MAX {
        return Err(crate::error::invalid_input(format!(
            "sharing_profiles.shares exceeds maximum allowed value: {}",
            config::INTERNAL_SHARE_MAX
        )));
    }
    if threshold > shares {
        return Err(crate::error::invalid_input(
            "sharing_profiles.threshold must be less than or equal to shares",
        ));
    }
    Ok(())
}

pub fn validate_max_secret_len(max_secret_len: usize) -> Result<(), DynError> {
    if max_secret_len == 0 {
        return Err(crate::error::invalid_input(
            "sharing_profiles.max_secret_len must be at least 1",
        ));
    }
    if max_secret_len > SHARING_SECRET_MAX_BYTES {
        return Err(crate::error::invalid_input(format!(
            "sharing_profiles.max_secret_len exceeds maximum allowed value: {SHARING_SECRET_MAX_BYTES}"
        )));
    }
    Ok(())
}

pub(crate) fn derive_sharing_key_for_profile(
    ops_symmetric_key_hex: &str,
    request: SharingKeyDerivationRequest<'_>,
) -> Result<DerivedSharingKey, DynError> {
    let resolved = mac::resolve_mac_algorithm(request.hash_algorithm)?;
    let ops_symmetric_key = Zeroizing::new(hex::decode(ops_symmetric_key_hex)?);
    let info = mac::build_mac_domain_aad(
        &[
            ("purpose", "sharing-key"),
            ("profile", request.profile_name),
            ("kid", request.kid),
            ("algorithm", &resolved.public_algorithm),
        ],
        request.context,
    )?;
    let share_auth_key = Zeroizing::new(crypto::create_hkdf(
        &ops_symmetric_key,
        SHARING_KEY_SALT,
        info.as_bytes(),
        SHARING_KEY_SIZE_BYTES,
    )?);

    Ok(DerivedSharingKey {
        public_algorithm: resolved.public_algorithm,
        botan_algorithm: resolved.botan_algorithm,
        share_auth_key,
    })
}

pub fn new_set_id() -> Result<String, DynError> {
    let bytes = Zeroizing::new(crypto::random_bytes(SHARING_SET_ID_BYTES)?);
    Ok(URL_SAFE_NO_PAD.encode(&*bytes))
}

pub(crate) fn split(profile: &SharingProfile, secret: &[u8]) -> Result<Vec<RawShare>, DynError> {
    validate_secret(profile, secret)?;
    let mut output = (1..=profile.shares())
        .map(|index| RawShare {
            index: index as u8,
            value: Zeroizing::new(vec![0; secret.len()]),
        })
        .collect::<Vec<_>>();

    let mut rng = crypto::new_rng()?;
    for (offset, secret_byte) in secret.iter().copied().enumerate() {
        let mut coefficients = Zeroizing::new(vec![0; profile.threshold()]);
        coefficients[0] = secret_byte;
        let random = Zeroizing::new(crypto::random_bytes_with_rng(
            &mut rng,
            profile.threshold() - 1,
        )?);
        coefficients[1..].copy_from_slice(&random);

        for share in &mut output {
            share.value[offset] = evaluate_polynomial(&coefficients, share.index);
        }
    }

    Ok(output)
}

pub(crate) fn combine(
    shares: &[RawShare],
    threshold: usize,
) -> Result<Zeroizing<Vec<u8>>, DynError> {
    if shares.len() < threshold {
        return Err(crate::error::invalid_input(
            "not enough shares to meet sharing profile threshold",
        ));
    }
    let length = validate_raw_shares(shares)?;
    let basis = &shares[..threshold];
    let mut secret = Zeroizing::new(vec![0; length]);

    for (offset, value) in secret.iter_mut().enumerate() {
        *value = interpolate_at(basis, offset, 0)?;
    }

    for share in shares.iter().skip(threshold) {
        for offset in 0..length {
            if interpolate_at(basis, offset, share.index)? != share.value[offset] {
                return Err(crate::error::invalid_input(
                    "shares are inconsistent with the sharing set",
                ));
            }
        }
    }

    Ok(secret)
}

pub(crate) fn encode_share(
    profile: &SharingProfile,
    set_id: &str,
    raw_share: &RawShare,
) -> Result<String, DynError> {
    validate_set_id(set_id)?;
    validate_raw_share(profile, raw_share)?;
    let share = URL_SAFE_NO_PAD.encode(&*raw_share.value);
    let unsigned = UnsignedShareEnvelope {
        version: "sss-v1",
        set_id,
        profile: profile.name(),
        kid: profile.kid(),
        threshold: profile.threshold(),
        shares: profile.shares(),
        index: raw_share.index,
        share: &share,
    };
    let tag = compute_tag(profile, &unsigned)?;
    let mut envelope = serde_json::to_value(&unsigned)?;
    let fields = envelope
        .as_object_mut()
        .ok_or_else(|| crate::error::internal("share envelope must serialize as an object"))?;
    fields.insert(
        String::from("tag"),
        serde_json::Value::String(hex::encode(tag)),
    );
    let encoded = canonical::canonical_json_v1(&envelope)?;
    Ok(format!("{SHARE_PREFIX}{}", URL_SAFE_NO_PAD.encode(encoded)))
}

pub(crate) fn decode_share(
    profile: &SharingProfile,
    encoded: &str,
) -> Result<(String, RawShare), DynError> {
    if encoded.len() > SHARE_ENVELOPE_MAX_CHARS {
        return Err(crate::error::invalid_input(
            "share exceeds maximum allowed length",
        ));
    }
    let encoded = encoded
        .strip_prefix(SHARE_PREFIX)
        .ok_or_else(|| crate::error::invalid_input("share must use vectis-sss-v1 encoding"))?;
    let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
        crate::error::invalid_input("share contains invalid vectis-sss-v1 encoding")
    })?);
    let envelope: ShareEnvelope = serde_json::from_slice(&bytes).map_err(|err| {
        crate::error::invalid_input(format!(
            "share contains invalid vectis-sss-v1 envelope: {err}"
        ))
    })?;
    validate_envelope(profile, &envelope)?;
    let unsigned = UnsignedShareEnvelope {
        version: "sss-v1",
        set_id: &envelope.set_id,
        profile: &envelope.profile,
        kid: &envelope.kid,
        threshold: envelope.threshold,
        shares: envelope.shares,
        index: envelope.index,
        share: &envelope.share,
    };
    let expected = compute_tag(profile, &unsigned)?;
    let actual = Zeroizing::new(
        hex::decode(&envelope.tag)
            .map_err(|_| crate::error::invalid_input("share tag contains invalid encoding"))?,
    );
    if !crypto::constant_time_eq(&expected, &actual) {
        return Err(crate::error::invalid_input("share authentication failed"));
    }
    let value = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(&envelope.share)
            .map_err(|_| crate::error::invalid_input("share payload contains invalid encoding"))?,
    );
    let raw_share = RawShare {
        index: envelope.index,
        value,
    };
    validate_raw_share(profile, &raw_share)?;
    Ok((envelope.set_id, raw_share))
}

fn validate_secret(profile: &SharingProfile, secret: &[u8]) -> Result<(), DynError> {
    if secret.is_empty() {
        return Err(crate::error::invalid_input("plaintext must not be empty"));
    }
    if secret.len() > profile.max_secret_len() {
        return Err(crate::error::invalid_input(
            "plaintext exceeds sharing profile maximum length",
        ));
    }
    Ok(())
}

fn validate_set_id(set_id: &str) -> Result<(), DynError> {
    let decoded =
        Zeroizing::new(URL_SAFE_NO_PAD.decode(set_id).map_err(|_| {
            crate::error::invalid_input("set_id contains invalid sharing encoding")
        })?);
    if decoded.len() != SHARING_SET_ID_BYTES {
        return Err(crate::error::invalid_input(
            "set_id length does not match sharing format",
        ));
    }
    Ok(())
}

fn validate_envelope(profile: &SharingProfile, envelope: &ShareEnvelope) -> Result<(), DynError> {
    if envelope.version != "sss-v1" {
        return Err(crate::error::invalid_input(
            "share version is not supported",
        ));
    }
    validate_set_id(&envelope.set_id)?;
    if envelope.profile != profile.name() {
        return Err(crate::error::invalid_input(
            "share profile does not match sharing profile",
        ));
    }
    if envelope.kid != profile.kid() {
        return Err(crate::error::invalid_input(
            "share kid does not match sharing profile",
        ));
    }
    if envelope.threshold != profile.threshold() || envelope.shares != profile.shares() {
        return Err(crate::error::invalid_input(
            "share threshold does not match sharing profile",
        ));
    }
    if envelope.index == 0 || usize::from(envelope.index) > profile.shares() {
        return Err(crate::error::invalid_input(
            "share index is outside sharing profile range",
        ));
    }
    Ok(())
}

fn validate_raw_share(profile: &SharingProfile, raw_share: &RawShare) -> Result<(), DynError> {
    if raw_share.index == 0 || usize::from(raw_share.index) > profile.shares() {
        return Err(crate::error::invalid_input(
            "share index is outside sharing profile range",
        ));
    }
    if raw_share.value.is_empty() || raw_share.value.len() > profile.max_secret_len() {
        return Err(crate::error::invalid_input(
            "share payload length does not match sharing profile",
        ));
    }
    Ok(())
}

fn validate_raw_shares(shares: &[RawShare]) -> Result<usize, DynError> {
    let Some(first) = shares.first() else {
        return Err(crate::error::invalid_input("shares must not be empty"));
    };
    let length = first.value.len();
    let mut indexes = HashSet::new();
    for share in shares {
        if share.index == 0 || !indexes.insert(share.index) {
            return Err(crate::error::invalid_input("share indexes must be unique"));
        }
        if share.value.len() != length {
            return Err(crate::error::invalid_input(
                "share payload lengths must match",
            ));
        }
    }
    Ok(length)
}

fn compute_tag(
    profile: &SharingProfile,
    unsigned: &UnsignedShareEnvelope<'_>,
) -> Result<Vec<u8>, DynError> {
    let payload = Zeroizing::new(canonical::canonical_json_v1(unsigned)?);

    mac::compute_keyed_tag(
        profile.uses_kmac(),
        profile.botan_algorithm(),
        profile.share_auth_key(),
        profile.customization(),
        &payload,
    )
}

fn evaluate_polynomial(coefficients: &[u8], x: u8) -> u8 {
    coefficients
        .iter()
        .rev()
        .fold(0, |value, coefficient| gf_mul(value, x) ^ coefficient)
}

fn interpolate_at(shares: &[RawShare], offset: usize, x: u8) -> Result<u8, DynError> {
    let mut value = 0;
    for (index, share) in shares.iter().enumerate() {
        let mut coefficient = 1;
        for (other_index, other) in shares.iter().enumerate() {
            if index == other_index {
                continue;
            }
            let denominator = share.index ^ other.index;
            coefficient = gf_mul(coefficient, gf_div(x ^ other.index, denominator)?);
        }
        value ^= gf_mul(share.value[offset], coefficient);
    }
    Ok(value)
}

fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0;
    for _ in 0..8 {
        product ^= left & bit_mask(right & 1);
        let carry = left >> 7;
        left <<= 1;
        left ^= 0x1b & bit_mask(carry);
        right >>= 1;
    }
    product
}

fn gf_div(left: u8, right: u8) -> Result<u8, DynError> {
    if right == 0 {
        return Err(crate::error::invalid_input(
            "shares contain duplicate indexes",
        ));
    }
    Ok(gf_mul(left, gf_inverse(right)))
}

fn gf_inverse(value: u8) -> u8 {
    let mut result = 1;
    let mut base = value;
    let exponent = 254u8;
    for bit in 0..8 {
        let multiplied = gf_mul(result, base);
        let mask = bit_mask((exponent >> bit) & 1);
        result = (result & !mask) | (multiplied & mask);
        base = gf_mul(base, base);
    }
    result
}

fn bit_mask(bit: u8) -> u8 {
    0u8.wrapping_sub(bit & 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn profile() -> SharingProfile {
        let input = serde_json::from_value(serde_json::json!({
            "name": "customer-secret-3of5-v1",
            "kid": KID,
            "threshold": 3,
            "shares": 5,
            "max_secret_len": 128,
            "context": "tenant=acme;purpose=customer-secret-sharing;version=1"
        }))
        .unwrap();
        validate_sharing_profiles(
            vec![input],
            |_| true,
            |_| Ok("BLAKE2b(256)".to_string()),
            |_| {
                Ok(DerivedSharingKey {
                    public_algorithm: "HMAC(BLAKE2b(256))".to_string(),
                    botan_algorithm: "HMAC(BLAKE2b(256))".to_string(),
                    share_auth_key: Zeroizing::new(vec![7; SHARING_KEY_SIZE_BYTES]),
                })
            },
        )
        .unwrap()
        .get("customer-secret-3of5-v1")
        .unwrap()
        .clone()
    }

    #[test]
    fn gf256_has_expected_product_and_inverse() {
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
        assert_eq!(gf_mul(0x53, gf_inverse(0x53)), 1);
    }

    #[test]
    fn any_threshold_subset_recovers_secret() {
        let profile = profile();
        let shares = split(&profile, b"secret-value").unwrap();
        for subset in [[0, 1, 2], [0, 2, 4], [1, 3, 4]] {
            let selected = subset
                .iter()
                .map(|index| RawShare {
                    index: shares[*index].index,
                    value: Zeroizing::new(shares[*index].value.to_vec()),
                })
                .collect::<Vec<_>>();
            assert_eq!(
                &*combine(&selected, profile.threshold()).unwrap(),
                b"secret-value"
            );
        }
    }

    #[test]
    fn authenticated_envelope_round_trips() {
        let profile = profile();
        let set_id = new_set_id().unwrap();
        let shares = split(&profile, b"secret-value").unwrap();
        let encoded = encode_share(&profile, &set_id, &shares[0]).unwrap();
        let (actual_set_id, decoded) = decode_share(&profile, &encoded).unwrap();
        assert_eq!(actual_set_id, set_id);
        assert_eq!(decoded.index, shares[0].index);
        assert_eq!(&*decoded.value, &*shares[0].value);
    }

    #[test]
    fn rejects_invalid_profile_bounds_and_tampered_share() {
        assert!(validate_sharing_profile_fields("profile", "tenant=demo", 1, 5, 64).is_err());
        assert!(validate_sharing_profile_fields("profile", "tenant=demo", 3, 33, 64).is_err());
        assert!(validate_sharing_profile_fields("profile", "tenant", 3, 5, 64).is_err());

        let profile = profile();
        let set_id = new_set_id().unwrap();
        let shares = split(&profile, b"secret-value").unwrap();
        let mut encoded = encode_share(&profile, &set_id, &shares[0]).unwrap();
        encoded.push('x');
        assert!(decode_share(&profile, &encoded).is_err());
    }

    #[test]
    fn rejects_duplicate_indexes_and_inconsistent_extra_share() {
        let profile = profile();
        let shares = split(&profile, b"secret-value").unwrap();
        let duplicate = vec![
            RawShare {
                index: shares[0].index,
                value: Zeroizing::new(shares[0].value.to_vec()),
            },
            RawShare {
                index: shares[0].index,
                value: Zeroizing::new(shares[0].value.to_vec()),
            },
            RawShare {
                index: shares[2].index,
                value: Zeroizing::new(shares[2].value.to_vec()),
            },
        ];
        assert!(combine(&duplicate, profile.threshold()).is_err());

        let mut inconsistent = shares
            .iter()
            .map(|share| RawShare {
                index: share.index,
                value: Zeroizing::new(share.value.to_vec()),
            })
            .collect::<Vec<_>>();
        inconsistent[4].value[0] ^= 1;
        assert!(combine(&inconsistent, profile.threshold()).is_err());
    }
}
