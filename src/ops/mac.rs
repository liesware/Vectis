use crate::core::{mac, validation};
use crate::error::DynError;
use crate::ops::keys::{self, KeysDbState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacCreateInput {
    profile: String,
    plaintext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacVerifyInput {
    profile: String,
    plaintext: String,
    digest: String,
}

#[derive(Serialize)]
pub struct MacCreateOutput {
    kid: String,
    profile: String,
    algorithm: String,
    digest: String,
}

#[derive(Serialize)]
pub struct MacVerifyOutput {
    valid: bool,
}

pub struct ValidatedMacCreateInput {
    profile: String,
    plaintext: Zeroizing<String>,
}

pub struct ValidatedMacVerifyInput {
    profile: String,
    plaintext: Zeroizing<String>,
    digest: Zeroizing<String>,
}

pub struct PreparedMacCreate {
    kid: String,
    profile: mac::MacProfile,
    input: ValidatedMacCreateInput,
}

pub struct PreparedMacVerify {
    profile: mac::MacProfile,
    input: ValidatedMacVerifyInput,
}

impl ValidatedMacCreateInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedMacVerifyInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

pub fn parse_create_input(request: Value) -> Result<MacCreateInput, DynError> {
    serde_json::from_value(request).map_err(|_| crate::error::invalid_input("invalid mac request"))
}

pub fn parse_verify_input(request: Value) -> Result<MacVerifyInput, DynError> {
    serde_json::from_value(request).map_err(|_| crate::error::invalid_input("invalid mac request"))
}

pub fn validate_create_input(input: MacCreateInput) -> Result<ValidatedMacCreateInput, DynError> {
    validation::validate_aad_config_name("profile", &input.profile)?;
    validation::validate_text_field("plaintext", &input.plaintext)?;

    Ok(ValidatedMacCreateInput {
        profile: input.profile,
        plaintext: Zeroizing::new(input.plaintext),
    })
}

pub fn validate_verify_input(input: MacVerifyInput) -> Result<ValidatedMacVerifyInput, DynError> {
    validation::validate_aad_config_name("profile", &input.profile)?;
    validation::validate_text_field("plaintext", &input.plaintext)?;
    validation::validate_hex_field("digest", &input.digest)?;

    Ok(ValidatedMacVerifyInput {
        profile: input.profile,
        plaintext: Zeroizing::new(input.plaintext),
        digest: Zeroizing::new(input.digest),
    })
}

pub fn prepare_create(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: mac::MacProfile,
    input: ValidatedMacCreateInput,
) -> Result<PreparedMacCreate, DynError> {
    if profile.kid() != kid {
        return Err(crate::error::invalid_input(
            "mac profile kid does not match request kid",
        ));
    }
    let loaded_key = keys::get_loaded_key(keys_db_state, kid)?;
    keys::require_lifecycle_for_new_use(&loaded_key)?;

    Ok(PreparedMacCreate {
        kid: kid.to_string(),
        profile,
        input,
    })
}

pub fn prepare_verify(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: mac::MacProfile,
    input: ValidatedMacVerifyInput,
) -> Result<PreparedMacVerify, DynError> {
    if profile.kid() != kid {
        return Err(crate::error::invalid_input(
            "mac profile kid does not match request kid",
        ));
    }
    let loaded_key = keys::get_loaded_key(keys_db_state, kid)?;
    keys::require_lifecycle_for_decrypt_or_verify(&loaded_key)?;

    Ok(PreparedMacVerify { profile, input })
}

pub fn create(prepared: PreparedMacCreate) -> Result<MacCreateOutput, DynError> {
    let digest = compute_digest(&prepared.profile, &prepared.input.plaintext)?;

    Ok(MacCreateOutput {
        kid: prepared.kid,
        profile: prepared.input.profile,
        algorithm: prepared.profile.algorithm().to_string(),
        digest: hex::encode(digest),
    })
}

pub fn verify(prepared: PreparedMacVerify) -> Result<MacVerifyOutput, DynError> {
    let expected = compute_digest(&prepared.profile, &prepared.input.plaintext)?;
    let actual = hex::decode(&*prepared.input.digest)?;

    Ok(MacVerifyOutput {
        valid: crate::core::crypto::constant_time_eq(&expected, &actual),
    })
}

fn compute_digest(profile: &mac::MacProfile, plaintext: &str) -> Result<Vec<u8>, DynError> {
    if profile.uses_kmac() {
        return Ok(crate::core::crypto::create_kmac_with_algorithm(
            profile.botan_algorithm(),
            profile.mac_key(),
            profile.customization().as_bytes(),
            plaintext.as_bytes(),
        )?);
    }

    let message = mac::mac_message(profile, plaintext);
    Ok(crate::core::crypto::create_hmac_with_algorithm(
        profile.botan_algorithm(),
        profile.mac_key(),
        &message,
    )?)
}
