use crate::error::DynError;
use crate::ops::keys;
use std::collections::{HashMap, HashSet};
use zeroize::Zeroize;

pub const MASKING_PLAINTEXT_MAX_LEN: usize = 1024;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MaskingProfileInput {
    name: String,
    kid: String,
    visible_first: usize,
    visible_last: usize,
    mask_char: String,
    min_len: usize,
    max_len: usize,
}

#[derive(Clone, Debug)]
pub struct MaskingProfile {
    name: String,
    kid: String,
    visible_first: usize,
    visible_last: usize,
    mask_char: String,
    min_len: usize,
    max_len: usize,
}

#[derive(Clone, Debug, Default)]
pub struct MaskingProfilesState {
    profiles: Vec<MaskingProfile>,
    by_name: HashMap<String, usize>,
}

impl MaskingProfile {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn min_len(&self) -> usize {
        self.min_len
    }

    pub fn max_len(&self) -> usize {
        self.max_len
    }
}

impl MaskingProfilesState {
    fn from_profiles(profiles: Vec<MaskingProfile>) -> Self {
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

    pub fn get(&self, name: &str) -> Option<&MaskingProfile> {
        self.by_name
            .get(name)
            .and_then(|index| self.profiles.get(*index))
    }
}

impl Zeroize for MaskingProfilesState {
    fn zeroize(&mut self) {
        self.profiles.zeroize();
        self.by_name.clear();
    }
}

impl Zeroize for MaskingProfile {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.kid.zeroize();
        self.visible_first = 0;
        self.visible_last = 0;
        self.mask_char.zeroize();
        self.min_len = 0;
        self.max_len = 0;
    }
}

pub(crate) fn validate_masking_profiles(
    profile_inputs: Vec<MaskingProfileInput>,
    is_loaded_kid: impl Fn(&str) -> bool,
) -> Result<MaskingProfilesState, DynError> {
    let mut seen_names = HashSet::new();
    let mut profiles = Vec::new();

    for profile in profile_inputs {
        validate_masking_profile_fields(
            &profile.name,
            &profile.kid,
            profile.visible_first,
            profile.visible_last,
            &profile.mask_char,
            profile.min_len,
            profile.max_len,
        )?;
        if !is_loaded_kid(&profile.kid) {
            return Err(crate::error::invalid_input(format!(
                "masking profile references kid not loaded in memory: {}",
                profile.kid
            )));
        }
        if !seen_names.insert(profile.name.clone()) {
            return Err(crate::error::invalid_input(format!(
                "masking profile has duplicated name: {}",
                profile.name
            )));
        }

        profiles.push(MaskingProfile {
            name: profile.name,
            kid: profile.kid,
            visible_first: profile.visible_first,
            visible_last: profile.visible_last,
            mask_char: profile.mask_char,
            min_len: profile.min_len,
            max_len: profile.max_len,
        });
    }

    Ok(MaskingProfilesState::from_profiles(profiles))
}

pub fn validate_masking_profile_fields(
    name: &str,
    kid: &str,
    visible_first: usize,
    visible_last: usize,
    mask_char: &str,
    min_len: usize,
    max_len: usize,
) -> Result<(), DynError> {
    crate::core::validation::validate_aad_config_name("masking_profiles.name", name)?;
    keys::validate_key_id(kid).map_err(|err| {
        crate::error::invalid_input(format!("masking_profiles.kid is invalid: {err}"))
    })?;
    validate_mask_char(mask_char)?;
    validate_masking_lengths(visible_first, visible_last, min_len, max_len)
}

pub fn validate_mask_char(value: &str) -> Result<(), DynError> {
    crate::core::validation::validate_text_field("masking_profiles.mask_char", value)?;
    if value.chars().count() != 1 {
        return Err(crate::error::invalid_input(
            "masking_profiles.mask_char must be exactly one character",
        ));
    }

    Ok(())
}

pub fn validate_masking_lengths(
    visible_first: usize,
    visible_last: usize,
    min_len: usize,
    max_len: usize,
) -> Result<(), DynError> {
    if min_len < 1 {
        return Err(crate::error::invalid_input(
            "masking_profiles.min_len must be at least 1",
        ));
    }
    if max_len > MASKING_PLAINTEXT_MAX_LEN {
        return Err(crate::error::invalid_input(
            "masking_profiles.max_len exceeds maximum allowed value",
        ));
    }
    if max_len < min_len {
        return Err(crate::error::invalid_input(
            "masking_profiles.max_len must be greater than or equal to min_len",
        ));
    }
    if visible_first > max_len || visible_last > max_len {
        return Err(crate::error::invalid_input(
            "masking_profiles.visible_first and visible_last must not exceed max_len",
        ));
    }
    if visible_first + visible_last >= min_len {
        return Err(crate::error::invalid_input(
            "masking_profiles.visible_first plus visible_last must be less than min_len",
        ));
    }

    Ok(())
}

pub fn validate_plaintext_for_profile(
    profile: &MaskingProfile,
    plaintext: &str,
) -> Result<(), DynError> {
    crate::core::validation::validate_text_field("plaintext", plaintext)?;
    let len = plaintext.chars().count();
    if len < profile.min_len() || len > profile.max_len() {
        return Err(crate::error::invalid_input(
            "plaintext length is outside masking profile bounds",
        ));
    }

    Ok(())
}

pub fn mask(profile: &MaskingProfile, plaintext: &str) -> Result<String, DynError> {
    validate_plaintext_for_profile(profile, plaintext)?;
    let chars = plaintext.chars().collect::<Vec<_>>();
    let prefix = chars.iter().take(profile.visible_first).collect::<String>();
    let suffix = chars
        .iter()
        .skip(chars.len() - profile.visible_last)
        .collect::<String>();
    let hidden_len = chars.len() - profile.visible_first - profile.visible_last;
    let masked = profile.mask_char.repeat(hidden_len);

    Ok(format!("{prefix}{masked}{suffix}"))
}

#[cfg(test)]
fn input_for_tests(
    name: &str,
    kid: &str,
    visible_first: usize,
    visible_last: usize,
    mask_char: &str,
    min_len: usize,
    max_len: usize,
) -> MaskingProfileInput {
    MaskingProfileInput {
        name: name.to_string(),
        kid: kid.to_string(),
        visible_first,
        visible_last,
        mask_char: mask_char.to_string(),
        min_len,
        max_len,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn validates_and_loads_profiles() {
        let state = validate_masking_profiles(
            vec![input_for_tests("pan-display-v1", KID, 6, 4, "*", 12, 19)],
            |kid| kid == KID,
        )
        .expect("valid profile must load");

        assert_eq!(state.len(), 1);
        assert_eq!(
            mask(state.get("pan-display-v1").unwrap(), "4111111111111111").unwrap(),
            "411111******1111"
        );
    }

    #[test]
    fn rejects_invalid_profiles() {
        assert!(validate_mask_char("").is_err());
        assert!(validate_mask_char("**").is_err());
        assert!(validate_mask_char("\n").is_err());
        assert!(validate_masking_lengths(0, 4, 0, 19).is_err());
        assert!(validate_masking_lengths(0, 4, 12, MASKING_PLAINTEXT_MAX_LEN + 1).is_err());
        assert!(validate_masking_lengths(0, 4, 12, 11).is_err());
        assert!(validate_masking_lengths(6, 6, 12, 19).is_err());
        assert!(validate_masking_lengths(usize::MAX, 1, 12, 19).is_err());
        assert!(validate_masking_lengths(1, usize::MAX, 12, 19).is_err());
    }

    #[test]
    fn rejects_duplicates_and_unloaded_kids() {
        assert!(
            validate_masking_profiles(vec![input_for_tests("pan", KID, 0, 4, "*", 12, 19)], |_| {
                false
            })
            .is_err()
        );
        assert!(
            validate_masking_profiles(
                vec![
                    input_for_tests("pan", KID, 0, 4, "*", 12, 19),
                    input_for_tests("pan", KID, 0, 4, "*", 12, 19),
                ],
                |_| true,
            )
            .is_err()
        );
    }
}
