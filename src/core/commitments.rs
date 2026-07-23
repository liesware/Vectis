use crate::core::{canonical, crypto, mac, validation};
use crate::error::DynError;
use crate::ops::keys;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub const COMMITMENT_KEY_SALT: &[u8] = b"vectis/commitment/v1";
pub const COMMITMENT_HMAC_SUBKEY_SALT: &[u8] = b"vectis/commitment/hmac/v1";
pub const COMMITMENT_KEY_SIZE_BYTES: usize = 32;
pub const COMMITMENT_CONTEXT_MAX_CHARS: usize = 128;
pub const COMMITMENT_PLAINTEXT_MAX_CHARS: usize = 1024;
pub const COMMITMENT_OPENING_MIN_BYTES: usize = 32;
pub const COMMITMENT_OPENING_MAX_BYTES: usize = 64;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommitmentProfileInput {
    name: String,
    kid: String,
    context: String,
    max_plaintext_len: usize,
    opening_len: usize,
}

#[derive(Clone)]
pub struct CommitmentProfile {
    name: String,
    kid: String,
    context: String,
    max_plaintext_len: usize,
    opening_len: usize,
    public_algorithm: String,
    botan_algorithm: String,
    customization: String,
    commit_key: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Default)]
pub struct CommitmentProfilesState {
    profiles: Vec<CommitmentProfile>,
    by_name: HashMap<String, usize>,
}

pub struct CommitmentKeyDerivationRequest<'a> {
    pub profile_name: &'a str,
    pub kid: &'a str,
    pub context: &'a str,
    pub hash_algorithm: &'a str,
}

pub struct DerivedCommitmentKey {
    pub public_algorithm: String,
    pub botan_algorithm: String,
    pub commit_key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for CommitmentProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitmentProfile")
            .field("name", &self.name)
            .field("kid", &self.kid)
            .field("context", &self.context)
            .field("max_plaintext_len", &self.max_plaintext_len)
            .field("opening_len", &self.opening_len)
            .field("public_algorithm", &self.public_algorithm)
            .field("botan_algorithm", &self.botan_algorithm)
            .field("commit_key", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for CommitmentProfilesState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitmentProfilesState")
            .field("profiles", &self.profiles)
            .finish_non_exhaustive()
    }
}

impl CommitmentProfile {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn max_plaintext_len(&self) -> usize {
        self.max_plaintext_len
    }

    pub fn opening_len(&self) -> usize {
        self.opening_len
    }

    pub fn algorithm(&self) -> &str {
        &self.public_algorithm
    }

    pub fn botan_algorithm(&self) -> &str {
        &self.botan_algorithm
    }

    pub fn customization(&self) -> &str {
        &self.customization
    }

    pub fn commit_key(&self) -> &[u8] {
        &self.commit_key
    }

    pub fn uses_kmac(&self) -> bool {
        mac::is_kmac_algorithm(&self.public_algorithm)
    }
}

impl CommitmentProfilesState {
    fn from_profiles(profiles: Vec<CommitmentProfile>) -> Self {
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

    pub fn get(&self, name: &str) -> Option<&CommitmentProfile> {
        self.by_name
            .get(name)
            .and_then(|index| self.profiles.get(*index))
    }
}

impl Zeroize for CommitmentProfilesState {
    fn zeroize(&mut self) {
        self.profiles.zeroize();
        self.by_name.clear();
    }
}

impl Zeroize for CommitmentProfile {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.kid.zeroize();
        self.context.zeroize();
        self.public_algorithm.zeroize();
        self.botan_algorithm.zeroize();
        self.customization.zeroize();
        self.commit_key.zeroize();
        self.max_plaintext_len = 0;
        self.opening_len = 0;
    }
}

pub(crate) fn validate_commitment_profiles(
    profile_inputs: Vec<CommitmentProfileInput>,
    is_loaded_kid: impl Fn(&str) -> bool,
    hash_algorithm_for_kid: impl Fn(&str) -> Result<String, DynError>,
    derive_commitment_key: impl Fn(
        CommitmentKeyDerivationRequest<'_>,
    ) -> Result<DerivedCommitmentKey, DynError>,
) -> Result<CommitmentProfilesState, DynError> {
    let mut seen_names = HashSet::new();
    let mut profiles = Vec::new();

    for profile in profile_inputs {
        validate_commitment_profile_fields(
            &profile.name,
            &profile.context,
            profile.max_plaintext_len,
            profile.opening_len,
        )?;
        keys::validate_key_id(&profile.kid).map_err(|err| {
            crate::error::invalid_input(format!("commitment_profiles.kid is invalid: {err}"))
        })?;
        if !is_loaded_kid(&profile.kid) {
            return Err(crate::error::invalid_input(format!(
                "commitment profile references kid not loaded in memory: {}",
                profile.kid
            )));
        }
        if !seen_names.insert(profile.name.clone()) {
            return Err(crate::error::invalid_input(format!(
                "commitment profile has duplicated name: {}",
                profile.name
            )));
        }

        let hash_algorithm = hash_algorithm_for_kid(&profile.kid)?;
        let derived = derive_commitment_key(CommitmentKeyDerivationRequest {
            profile_name: &profile.name,
            kid: &profile.kid,
            context: &profile.context,
            hash_algorithm: &hash_algorithm,
        })?;
        if derived.commit_key.len() != COMMITMENT_KEY_SIZE_BYTES {
            return Err(crate::error::internal(
                "derived commitment key has invalid length",
            ));
        }

        let customization = mac::build_mac_domain_aad(
            &[("profile", &profile.name), ("kid", &profile.kid)],
            &profile.context,
        )?;
        let commit_key = mac::derive_keyed_tag_subkey(
            &derived.public_algorithm,
            derived.commit_key,
            COMMITMENT_HMAC_SUBKEY_SALT,
            &customization,
            COMMITMENT_KEY_SIZE_BYTES,
        )?;

        profiles.push(CommitmentProfile {
            name: profile.name,
            kid: profile.kid,
            context: profile.context,
            max_plaintext_len: profile.max_plaintext_len,
            opening_len: profile.opening_len,
            public_algorithm: derived.public_algorithm,
            botan_algorithm: derived.botan_algorithm,
            customization,
            commit_key,
        });
    }

    Ok(CommitmentProfilesState::from_profiles(profiles))
}

pub fn validate_commitment_profile_fields(
    name: &str,
    context: &str,
    max_plaintext_len: usize,
    opening_len: usize,
) -> Result<(), DynError> {
    validation::validate_aad_config_name("commitment_profiles.name", name)?;
    validation::validate_labels(
        "commitment_profiles.context",
        context,
        COMMITMENT_CONTEXT_MAX_CHARS,
    )?;
    validate_commitment_plaintext_len(max_plaintext_len)?;
    validate_commitment_opening_len(opening_len)?;

    Ok(())
}

pub fn validate_commitment_plaintext_len(max_plaintext_len: usize) -> Result<(), DynError> {
    if max_plaintext_len == 0 {
        return Err(crate::error::invalid_input(
            "commitment_profiles.max_plaintext_len must be at least 1",
        ));
    }
    if max_plaintext_len > COMMITMENT_PLAINTEXT_MAX_CHARS {
        return Err(crate::error::invalid_input(format!(
            "commitment_profiles.max_plaintext_len exceeds maximum allowed value: {COMMITMENT_PLAINTEXT_MAX_CHARS}"
        )));
    }
    Ok(())
}

pub fn validate_commitment_opening_len(opening_len: usize) -> Result<(), DynError> {
    if opening_len < COMMITMENT_OPENING_MIN_BYTES {
        return Err(crate::error::invalid_input(format!(
            "commitment_profiles.opening_len must be at least {COMMITMENT_OPENING_MIN_BYTES}"
        )));
    }
    if opening_len > COMMITMENT_OPENING_MAX_BYTES {
        return Err(crate::error::invalid_input(format!(
            "commitment_profiles.opening_len exceeds maximum allowed value: {COMMITMENT_OPENING_MAX_BYTES}"
        )));
    }
    Ok(())
}

pub(crate) fn derive_commitment_key_for_profile(
    ops_symmetric_key_hex: &str,
    request: CommitmentKeyDerivationRequest<'_>,
) -> Result<DerivedCommitmentKey, DynError> {
    let resolved = mac::resolve_mac_algorithm(request.hash_algorithm)?;
    let ops_symmetric_key = Zeroizing::new(hex::decode(ops_symmetric_key_hex)?);
    let info = mac::build_mac_domain_aad(
        &[
            ("purpose", "commitment-key"),
            ("profile", request.profile_name),
            ("kid", request.kid),
            ("algorithm", &resolved.public_algorithm),
        ],
        request.context,
    )?;
    let commit_key = Zeroizing::new(crypto::create_hkdf(
        &ops_symmetric_key,
        COMMITMENT_KEY_SALT,
        info.as_bytes(),
        COMMITMENT_KEY_SIZE_BYTES,
    )?);

    Ok(DerivedCommitmentKey {
        public_algorithm: resolved.public_algorithm,
        botan_algorithm: resolved.botan_algorithm,
        commit_key,
    })
}

pub fn encode_opening(opening: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(opening)
}

pub fn validate_opening(profile: &CommitmentProfile, opening: &str) -> Result<(), DynError> {
    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(opening).map_err(|_| {
        crate::error::invalid_input("opening contains invalid commitment encoding")
    })?);
    if decoded.len() != profile.opening_len() {
        return Err(crate::error::invalid_input(
            "opening length does not match commitment profile",
        ));
    }
    Ok(())
}

pub fn commitment_payload(
    profile: &CommitmentProfile,
    opening_b64: &str,
    plaintext: &str,
) -> Result<Zeroizing<Vec<u8>>, DynError> {
    let payload = serde_json::json!({
        "version": "v1",
        "profile": profile.name(),
        "kid": profile.kid(),
        "opening": opening_b64,
        "plaintext": plaintext,
    });
    Ok(Zeroizing::new(canonical::canonical_json_v1(&payload)?))
}

pub fn compute_commitment(
    profile: &CommitmentProfile,
    opening_b64: &str,
    plaintext: &str,
) -> Result<Vec<u8>, DynError> {
    let payload = commitment_payload(profile, opening_b64, plaintext)?;

    mac::compute_keyed_tag(
        profile.uses_kmac(),
        profile.botan_algorithm(),
        profile.commit_key(),
        profile.customization(),
        &payload,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const KID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn request<'a>(
        profile_name: &'a str,
        context: &'a str,
        hash_algorithm: &'a str,
    ) -> CommitmentKeyDerivationRequest<'a> {
        CommitmentKeyDerivationRequest {
            profile_name,
            kid: KID,
            context,
            hash_algorithm,
        }
    }

    #[test]
    fn validates_commitment_profile_fields() {
        assert!(
            validate_commitment_profile_fields(
                "pan-commitment-v1",
                "tenant=mx;field=pan;purpose=commitment;version=1",
                128,
                32,
            )
            .is_ok()
        );
        let err = validate_commitment_profile_fields("bad=name", "tenant=mx", 128, 32)
            .expect_err("commitment profile name must be AAD-safe");
        assert_eq!(
            err.to_string(),
            "commitment_profiles.name must not contain ';' or '='"
        );
        let err = validate_commitment_profile_fields("pan", "tenant", 128, 32)
            .expect_err("commitment context must be labels");
        assert_eq!(
            err.to_string(),
            "commitment_profiles.context labels must use key=value format"
        );
    }

    #[test]
    fn validates_commitment_lengths() {
        assert_eq!(
            validate_commitment_profile_fields("pan", "tenant=mx", 0, 32)
                .unwrap_err()
                .to_string(),
            "commitment_profiles.max_plaintext_len must be at least 1"
        );
        assert_eq!(
            validate_commitment_profile_fields("pan", "tenant=mx", 128, 31)
                .unwrap_err()
                .to_string(),
            "commitment_profiles.opening_len must be at least 32"
        );
    }

    #[test]
    fn derived_commitment_keys_are_bound_to_profile_context_and_algorithm() {
        let key = "11".repeat(32);
        let first = derive_commitment_key_for_profile(
            &key,
            request("pan-v1", "tenant=mx;field=pan", "BLAKE2b(256)"),
        )
        .unwrap();
        let repeat = derive_commitment_key_for_profile(
            &key,
            request("pan-v1", "tenant=mx;field=pan", "BLAKE2b(256)"),
        )
        .unwrap();
        let other_profile = derive_commitment_key_for_profile(
            &key,
            request("ssn-v1", "tenant=mx;field=pan", "BLAKE2b(256)"),
        )
        .unwrap();
        let kmac = derive_commitment_key_for_profile(
            &key,
            request("pan-v1", "tenant=mx;field=pan", "SHA-3(384)"),
        )
        .unwrap();

        assert_eq!(&*first.commit_key, &*repeat.commit_key);
        assert_ne!(&*first.commit_key, &*other_profile.commit_key);
        assert_ne!(&*first.commit_key, &*kmac.commit_key);
        assert_eq!(kmac.public_algorithm, mac::MAC_ALGORITHM_KMAC_384);
    }
}
