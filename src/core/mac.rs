use crate::core::{crypto, validation};
use crate::error::DynError;
use crate::ops::keys;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub const MAC_KEY_SALT: &[u8] = b"vectis/mac/v1";
pub const MAC_HMAC_SUBKEY_SALT: &[u8] = b"vectis/mac/hmac/v1";
pub const MAC_KEY_SIZE_BYTES: usize = 32;
pub const MAC_CONTEXT_MAX_CHARS: usize = 128;
pub const MAC_ALGORITHM_KMAC_224: &str = "KMAC-224";
pub const MAC_ALGORITHM_KMAC_256: &str = "KMAC-256";
pub const MAC_ALGORITHM_KMAC_384: &str = "KMAC-384";
pub const MAC_ALGORITHM_KMAC_512: &str = "KMAC-512";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacProfileInput {
    name: String,
    kid: String,
    context: String,
}

#[derive(Clone)]
pub struct MacProfile {
    name: String,
    kid: String,
    context: String,
    public_algorithm: String,
    botan_algorithm: String,
    customization: String,
    mac_key: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Default)]
pub struct MacProfilesState {
    profiles: Vec<MacProfile>,
    by_name: HashMap<String, usize>,
}

pub struct MacKeyDerivationRequest<'a> {
    pub profile_name: &'a str,
    pub kid: &'a str,
    pub context: &'a str,
    pub hash_algorithm: &'a str,
}

pub struct DerivedMacKey {
    pub public_algorithm: String,
    pub botan_algorithm: String,
    pub mac_key: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMacAlgorithm {
    pub public_algorithm: String,
    pub botan_algorithm: String,
}

impl fmt::Debug for MacProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacProfile")
            .field("name", &self.name)
            .field("kid", &self.kid)
            .field("context", &self.context)
            .field("public_algorithm", &self.public_algorithm)
            .field("botan_algorithm", &self.botan_algorithm)
            .field("mac_key", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for MacProfilesState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MacProfilesState")
            .field("profiles", &self.profiles)
            .finish_non_exhaustive()
    }
}

impl MacProfile {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn context(&self) -> &str {
        &self.context
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

    pub fn mac_key(&self) -> &[u8] {
        &self.mac_key
    }

    pub fn uses_kmac(&self) -> bool {
        is_kmac_algorithm(&self.public_algorithm)
    }
}

impl MacProfilesState {
    fn from_profiles(profiles: Vec<MacProfile>) -> Self {
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

    pub fn get(&self, name: &str) -> Option<&MacProfile> {
        self.by_name
            .get(name)
            .and_then(|index| self.profiles.get(*index))
    }
}

impl Zeroize for MacProfilesState {
    fn zeroize(&mut self) {
        self.profiles.zeroize();
        self.by_name.clear();
    }
}

impl Zeroize for MacProfile {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.kid.zeroize();
        self.context.zeroize();
        self.public_algorithm.zeroize();
        self.botan_algorithm.zeroize();
        self.customization.zeroize();
        self.mac_key.zeroize();
    }
}

pub(crate) fn validate_mac_profiles(
    profile_inputs: Vec<MacProfileInput>,
    is_loaded_kid: impl Fn(&str) -> bool,
    hash_algorithm_for_kid: impl Fn(&str) -> Result<String, DynError>,
    derive_mac_key: impl Fn(MacKeyDerivationRequest<'_>) -> Result<DerivedMacKey, DynError>,
) -> Result<MacProfilesState, DynError> {
    let mut seen_names = HashSet::new();
    let mut profiles = Vec::new();

    for profile in profile_inputs {
        validate_mac_profile_fields(&profile.name, &profile.context)?;
        keys::validate_key_id(&profile.kid).map_err(|err| {
            crate::error::invalid_input(format!("mac_profiles.kid is invalid: {err}"))
        })?;
        if !is_loaded_kid(&profile.kid) {
            return Err(crate::error::invalid_input(format!(
                "mac profile references kid not loaded in memory: {}",
                profile.kid
            )));
        }
        if !seen_names.insert(profile.name.clone()) {
            return Err(crate::error::invalid_input(format!(
                "mac profile has duplicated name: {}",
                profile.name
            )));
        }

        let hash_algorithm = hash_algorithm_for_kid(&profile.kid)?;
        let derived = derive_mac_key(MacKeyDerivationRequest {
            profile_name: &profile.name,
            kid: &profile.kid,
            context: &profile.context,
            hash_algorithm: &hash_algorithm,
        })?;
        if derived.mac_key.len() != MAC_KEY_SIZE_BYTES {
            return Err(crate::error::internal("derived mac key has invalid length"));
        }

        let customization = build_mac_domain_aad(
            &[("profile", &profile.name), ("kid", &profile.kid)],
            &profile.context,
        )?;

        let mac_key = derive_keyed_tag_subkey(
            &derived.public_algorithm,
            derived.mac_key,
            MAC_HMAC_SUBKEY_SALT,
            &customization,
            MAC_KEY_SIZE_BYTES,
        )?;

        profiles.push(MacProfile {
            name: profile.name,
            kid: profile.kid,
            context: profile.context,
            public_algorithm: derived.public_algorithm,
            botan_algorithm: derived.botan_algorithm,
            customization,
            mac_key,
        });
    }

    Ok(MacProfilesState::from_profiles(profiles))
}

pub fn validate_mac_profile_fields(name: &str, context: &str) -> Result<(), DynError> {
    validation::validate_aad_config_name("mac_profiles.name", name)?;
    validation::validate_labels("mac_profiles.context", context, MAC_CONTEXT_MAX_CHARS)?;

    Ok(())
}

pub fn resolve_mac_algorithm(hash_algorithm: &str) -> Result<ResolvedMacAlgorithm, DynError> {
    validation::validate_allowed_value("hash_algorithm", hash_algorithm, crypto::HASH_ALGORITHMS)?;
    let resolved = match hash_algorithm {
        "SHA-3(224)" => ResolvedMacAlgorithm {
            public_algorithm: MAC_ALGORITHM_KMAC_224.to_string(),
            botan_algorithm: format!("{}(224)", crate::core::config::INTERNAL_KEYS_KMAC),
        },
        "SHA-3(256)" => ResolvedMacAlgorithm {
            public_algorithm: MAC_ALGORITHM_KMAC_256.to_string(),
            botan_algorithm: format!("{}(256)", crate::core::config::INTERNAL_KEYS_KMAC),
        },
        "SHA-3(384)" => ResolvedMacAlgorithm {
            public_algorithm: MAC_ALGORITHM_KMAC_384.to_string(),
            botan_algorithm: format!("{}(384)", crate::core::config::INTERNAL_KEYS_KMAC),
        },
        "SHA-3(512)" => ResolvedMacAlgorithm {
            public_algorithm: MAC_ALGORITHM_KMAC_512.to_string(),
            botan_algorithm: format!("{}(512)", crate::core::config::INTERNAL_KEYS_KMAC),
        },
        _ => ResolvedMacAlgorithm {
            public_algorithm: format!("HMAC({hash_algorithm})"),
            botan_algorithm: format!("HMAC({hash_algorithm})"),
        },
    };

    Ok(resolved)
}

pub(crate) fn derive_mac_key_for_profile(
    ops_symmetric_key_hex: &str,
    request: MacKeyDerivationRequest<'_>,
) -> Result<DerivedMacKey, DynError> {
    let resolved = resolve_mac_algorithm(request.hash_algorithm)?;
    let ops_symmetric_key = Zeroizing::new(hex::decode(ops_symmetric_key_hex)?);
    let info = build_mac_domain_aad(
        &[
            ("purpose", "mac-key"),
            ("profile", request.profile_name),
            ("kid", request.kid),
            ("algorithm", &resolved.public_algorithm),
        ],
        request.context,
    )?;
    let mac_key = Zeroizing::new(crypto::create_hkdf(
        &ops_symmetric_key,
        MAC_KEY_SALT,
        info.as_bytes(),
        MAC_KEY_SIZE_BYTES,
    )?);

    Ok(DerivedMacKey {
        public_algorithm: resolved.public_algorithm,
        botan_algorithm: resolved.botan_algorithm,
        mac_key,
    })
}

pub(crate) fn is_kmac_algorithm(public_algorithm: &str) -> bool {
    public_algorithm.starts_with("KMAC-")
}

pub(crate) fn derive_keyed_tag_subkey(
    public_algorithm: &str,
    derived_key: Zeroizing<Vec<u8>>,
    hmac_subkey_salt: &[u8],
    customization: &str,
    key_size_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, DynError> {
    if is_kmac_algorithm(public_algorithm) {
        return Ok(derived_key);
    }

    Ok(Zeroizing::new(crypto::create_hkdf(
        &derived_key,
        hmac_subkey_salt,
        customization.as_bytes(),
        key_size_bytes,
    )?))
}

pub(crate) fn compute_keyed_tag(
    uses_kmac: bool,
    botan_algorithm: &str,
    key: &[u8],
    customization: &str,
    payload: &[u8],
) -> Result<Vec<u8>, DynError> {
    if uses_kmac {
        return Ok(crypto::create_kmac_with_algorithm(
            botan_algorithm,
            key,
            customization.as_bytes(),
            payload,
        )?);
    }

    Ok(crypto::create_hmac_with_algorithm(
        botan_algorithm,
        key,
        payload,
    )?)
}

pub(crate) fn build_mac_domain_aad(
    base_fields: &[(&str, &str)],
    context: &str,
) -> Result<String, DynError> {
    validation::validate_labels("mac_profiles.context", context, MAC_CONTEXT_MAX_CHARS)?;

    let mut fields: Vec<(String, String)> = base_fields
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect();
    for label in context.split(';') {
        let Some((key, value)) = label.split_once('=') else {
            return Err(crate::error::invalid_input(
                "mac_profiles.context labels must use key=value format",
            ));
        };
        fields.push((format!("context.{key}"), value.to_string()));
    }

    let borrowed = fields
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    validation::build_validated_aad(&borrowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn request<'a>(
        profile_name: &'a str,
        context: &'a str,
        hash_algorithm: &'a str,
    ) -> MacKeyDerivationRequest<'a> {
        MacKeyDerivationRequest {
            profile_name,
            kid: KID,
            context,
            hash_algorithm,
        }
    }

    #[test]
    fn validates_mac_profile_fields() {
        assert!(
            validate_mac_profile_fields(
                "pan-blind-index-v1",
                "tenant=mx;field=pan;purpose=blind-index;version=1",
            )
            .is_ok()
        );
        let err = validate_mac_profile_fields("bad=name", "tenant=mx")
            .expect_err("MAC profile names must be AAD-safe");
        assert_eq!(
            err.to_string(),
            "mac_profiles.name must not contain ';' or '='"
        );

        let err = validate_mac_profile_fields("pan", "tenant")
            .expect_err("MAC context labels must be structured");
        assert_eq!(
            err.to_string(),
            "mac_profiles.context labels must use key=value format"
        );

        let overlong = format!("tenant={}", "a".repeat(MAC_CONTEXT_MAX_CHARS));
        let err = validate_mac_profile_fields("pan", &overlong)
            .expect_err("overlong MAC context must fail");
        assert_eq!(
            err.to_string(),
            "mac_profiles.context exceeds maximum allowed length: 128"
        );
    }

    #[test]
    fn resolves_mac_algorithm_from_hash_algorithm() {
        assert_eq!(
            resolve_mac_algorithm("SHA-3(224)").unwrap(),
            ResolvedMacAlgorithm {
                public_algorithm: MAC_ALGORITHM_KMAC_224.to_string(),
                botan_algorithm: "KMAC-256(224)".to_string(),
            }
        );
        assert_eq!(
            resolve_mac_algorithm("SHA-3(256)").unwrap(),
            ResolvedMacAlgorithm {
                public_algorithm: MAC_ALGORITHM_KMAC_256.to_string(),
                botan_algorithm: "KMAC-256(256)".to_string(),
            }
        );
        assert_eq!(
            resolve_mac_algorithm("SHA-3(384)").unwrap(),
            ResolvedMacAlgorithm {
                public_algorithm: MAC_ALGORITHM_KMAC_384.to_string(),
                botan_algorithm: "KMAC-256(384)".to_string(),
            }
        );
        assert_eq!(
            resolve_mac_algorithm("SHA-3(512)").unwrap(),
            ResolvedMacAlgorithm {
                public_algorithm: MAC_ALGORITHM_KMAC_512.to_string(),
                botan_algorithm: "KMAC-256(512)".to_string(),
            }
        );
        assert_eq!(
            resolve_mac_algorithm("BLAKE2b(256)").unwrap(),
            ResolvedMacAlgorithm {
                public_algorithm: "HMAC(BLAKE2b(256))".to_string(),
                botan_algorithm: "HMAC(BLAKE2b(256))".to_string(),
            }
        );
    }

    #[test]
    fn derived_mac_keys_are_bound_to_profile_context_and_algorithm() {
        let key = "11".repeat(32);
        let first = derive_mac_key_for_profile(
            &key,
            request("pan-v1", "tenant=mx;field=pan", "BLAKE2b(256)"),
        )
        .unwrap();
        let repeat = derive_mac_key_for_profile(
            &key,
            request("pan-v1", "tenant=mx;field=pan", "BLAKE2b(256)"),
        )
        .unwrap();
        let other_profile = derive_mac_key_for_profile(
            &key,
            request("ssn-v1", "tenant=mx;field=pan", "BLAKE2b(256)"),
        )
        .unwrap();
        let other_context = derive_mac_key_for_profile(
            &key,
            request("pan-v1", "tenant=mx;field=ssn", "BLAKE2b(256)"),
        )
        .unwrap();
        let kmac_256 = derive_mac_key_for_profile(
            &key,
            request("pan-v1", "tenant=mx;field=pan", "SHA-3(256)"),
        )
        .unwrap();
        let kmac_384 = derive_mac_key_for_profile(
            &key,
            request("pan-v1", "tenant=mx;field=pan", "SHA-3(384)"),
        )
        .unwrap();
        let kmac_512 = derive_mac_key_for_profile(
            &key,
            request("pan-v1", "tenant=mx;field=pan", "SHA-3(512)"),
        )
        .unwrap();

        assert_eq!(&*first.mac_key, &*repeat.mac_key);
        assert_ne!(&*first.mac_key, &*other_profile.mac_key);
        assert_ne!(&*first.mac_key, &*other_context.mac_key);
        assert_ne!(&*first.mac_key, &*kmac_256.mac_key);
        assert_ne!(&*kmac_256.mac_key, &*kmac_384.mac_key);
        assert_ne!(&*kmac_384.mac_key, &*kmac_512.mac_key);
        assert_eq!(kmac_256.public_algorithm, MAC_ALGORITHM_KMAC_256);
        assert_eq!(kmac_384.public_algorithm, MAC_ALGORITHM_KMAC_384);
        assert_eq!(kmac_512.public_algorithm, MAC_ALGORITHM_KMAC_512);
        assert_eq!(kmac_256.botan_algorithm, "KMAC-256(256)");
        assert_eq!(kmac_384.botan_algorithm, "KMAC-256(384)");
        assert_eq!(kmac_512.botan_algorithm, "KMAC-256(512)");
    }
}
