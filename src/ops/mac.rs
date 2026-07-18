use crate::core::{mac, validation};
use crate::error::DynError;
use crate::ops::keys::{self, KeysDbState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacCreateInput {
    #[serde(rename = "ref")]
    ref_id: String,
    profile: String,
    plaintext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacVerifyInput {
    #[serde(rename = "ref")]
    ref_id: String,
    profile: String,
    plaintext: String,
    digest: String,
}

#[derive(Serialize)]
pub struct MacCreateOutput {
    #[serde(rename = "ref")]
    ref_id: String,
    kid: String,
    profile: String,
    algorithm: String,
    digest: String,
}

#[derive(Serialize)]
pub struct MacVerifyOutput {
    #[serde(rename = "ref")]
    ref_id: String,
    valid: bool,
}

pub struct ValidatedMacCreateInput {
    ref_id: String,
    profile: String,
    plaintext: Zeroizing<String>,
}

pub struct ValidatedMacVerifyInput {
    ref_id: String,
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
    let ref_id = validation::validate_ref(&input.ref_id)?;
    validation::validate_aad_config_name("profile", &input.profile)?;
    validation::validate_text_field("plaintext", &input.plaintext)?;

    Ok(ValidatedMacCreateInput {
        ref_id,
        profile: input.profile,
        plaintext: Zeroizing::new(input.plaintext),
    })
}

pub fn validate_verify_input(input: MacVerifyInput) -> Result<ValidatedMacVerifyInput, DynError> {
    let ref_id = validation::validate_ref(&input.ref_id)?;
    validation::validate_aad_config_name("profile", &input.profile)?;
    validation::validate_text_field("plaintext", &input.plaintext)?;
    validation::validate_hex_field("digest", &input.digest)?;

    Ok(ValidatedMacVerifyInput {
        ref_id,
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
        ref_id: prepared.input.ref_id,
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
        ref_id: prepared.input.ref_id,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mac_create_requires_valid_ref() {
        let err = match parse_create_input(json!({
            "profile": "pan-blind-index-v1",
            "plaintext": "4111111111111111"
        })) {
            Ok(_) => panic!("missing ref must fail"),
            Err(err) => err,
        };
        assert_eq!(err.to_string(), "invalid mac request");

        let err = match validate_create_input(MacCreateInput {
            ref_id: String::new(),
            profile: "pan-blind-index-v1".to_string(),
            plaintext: "4111111111111111".to_string(),
        }) {
            Ok(_) => panic!("empty ref must fail"),
            Err(err) => err,
        };
        assert_eq!(err.to_string(), "ref must not be empty");

        let err = match validate_create_input(MacCreateInput {
            ref_id: "r".repeat(crate::core::config::INTERNAL_REF_MAX_CHARS + 1),
            profile: "pan-blind-index-v1".to_string(),
            plaintext: "4111111111111111".to_string(),
        }) {
            Ok(_) => panic!("long ref must fail"),
            Err(err) => err,
        };
        assert_eq!(err.to_string(), "ref exceeds maximum allowed length: 128");
    }

    #[test]
    fn mac_verify_requires_valid_ref() {
        let err = match parse_verify_input(json!({
            "profile": "pan-blind-index-v1",
            "plaintext": "4111111111111111",
            "digest": "00"
        })) {
            Ok(_) => panic!("missing ref must fail"),
            Err(err) => err,
        };
        assert_eq!(err.to_string(), "invalid mac request");

        let err = match validate_verify_input(MacVerifyInput {
            ref_id: "bad\u{0001}".to_string(),
            profile: "pan-blind-index-v1".to_string(),
            plaintext: "4111111111111111".to_string(),
            digest: "00".to_string(),
        }) {
            Ok(_) => panic!("control char ref must fail"),
            Err(err) => err,
        };
        assert_eq!(err.to_string(), "ref must not contain control characters");
    }

    #[test]
    fn mac_outputs_serialize_ref() {
        let created = serde_json::to_value(MacCreateOutput {
            ref_id: "reg1".to_string(),
            kid: "a".repeat(64),
            profile: "pan-blind-index-v1".to_string(),
            algorithm: "KMAC-256".to_string(),
            digest: "00".repeat(32),
        })
        .unwrap();
        assert_eq!(created["ref"], "reg1");

        let verified = serde_json::to_value(MacVerifyOutput {
            ref_id: "reg1".to_string(),
            valid: true,
        })
        .unwrap();
        assert_eq!(verified, json!({"ref": "reg1", "valid": true}));
    }
}
