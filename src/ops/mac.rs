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
    kid: String,
    profile: String,
    plaintext: String,
    digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacCreateBatchItemInput {
    #[serde(rename = "ref")]
    ref_id: String,
    plaintext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacCreateBatchInput {
    profile: String,
    items: Vec<MacCreateBatchItemInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacVerifyBatchItemInput {
    #[serde(rename = "ref")]
    ref_id: String,
    plaintext: String,
    digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacVerifyBatchInput {
    kid: String,
    profile: String,
    items: Vec<MacVerifyBatchItemInput>,
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

#[derive(Serialize)]
pub struct MacCreateBatchOutputItem {
    #[serde(rename = "ref")]
    ref_id: String,
    digest: String,
}

#[derive(Serialize)]
pub struct MacCreateBatchOutput {
    kid: String,
    profile: String,
    algorithm: String,
    items: Vec<MacCreateBatchOutputItem>,
}

#[derive(Serialize)]
pub struct MacVerifyBatchOutputItem {
    #[serde(rename = "ref")]
    ref_id: String,
    valid: bool,
}

#[derive(Serialize)]
pub struct MacVerifyBatchOutput {
    kid: String,
    profile: String,
    items: Vec<MacVerifyBatchOutputItem>,
}

impl MacCreateBatchOutput {
    pub fn items_len(&self) -> usize {
        self.items.len()
    }
}

impl MacVerifyBatchOutput {
    pub fn items_len(&self) -> usize {
        self.items.len()
    }
}

pub struct ValidatedMacCreateInput {
    ref_id: String,
    profile: String,
    plaintext: Zeroizing<String>,
}

pub struct ValidatedMacVerifyInput {
    ref_id: String,
    kid: String,
    profile: String,
    plaintext: Zeroizing<String>,
    digest: Zeroizing<String>,
}

pub struct ValidatedMacCreateBatchItem {
    ref_id: String,
    plaintext: Zeroizing<String>,
}

pub struct ValidatedMacCreateBatchInput {
    profile: String,
    items: Vec<ValidatedMacCreateBatchItem>,
}

pub struct ValidatedMacVerifyBatchItem {
    ref_id: String,
    plaintext: Zeroizing<String>,
    digest: Zeroizing<String>,
}

pub struct ValidatedMacVerifyBatchInput {
    kid: String,
    profile: String,
    items: Vec<ValidatedMacVerifyBatchItem>,
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

pub struct PreparedMacCreateBatch {
    kid: String,
    profile: mac::MacProfile,
    input: ValidatedMacCreateBatchInput,
}

pub struct PreparedMacVerifyBatch {
    kid: String,
    profile: mac::MacProfile,
    input: ValidatedMacVerifyBatchInput,
}

impl ValidatedMacCreateInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedMacVerifyInput {
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedMacCreateBatchInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedMacVerifyBatchInput {
    pub fn kid(&self) -> &str {
        &self.kid
    }

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

pub fn parse_create_batch_input(request: Value) -> Result<MacCreateBatchInput, DynError> {
    crate::ops::batch::reject_oversized_value(
        &request,
        crate::core::config::INTERNAL_MAC_BATCH,
        "mac",
    )?;
    serde_json::from_value(request).map_err(|_| crate::error::invalid_input("invalid mac request"))
}

pub fn parse_verify_batch_input(request: Value) -> Result<MacVerifyBatchInput, DynError> {
    crate::ops::batch::reject_oversized_value(
        &request,
        crate::core::config::INTERNAL_MAC_BATCH,
        "mac",
    )?;
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
    keys::validate_key_id(&input.kid)
        .map_err(|err| crate::error::invalid_input(format!("kid is invalid: {err}")))?;
    validation::validate_aad_config_name("profile", &input.profile)?;
    validation::validate_text_field("plaintext", &input.plaintext)?;
    validation::validate_hex_field("digest", &input.digest)?;

    Ok(ValidatedMacVerifyInput {
        ref_id,
        kid: input.kid,
        profile: input.profile,
        plaintext: Zeroizing::new(input.plaintext),
        digest: Zeroizing::new(input.digest),
    })
}

pub fn validate_create_batch_input(
    input: MacCreateBatchInput,
) -> Result<ValidatedMacCreateBatchInput, DynError> {
    validation::validate_aad_config_name("profile", &input.profile)?;
    crate::ops::batch::validate_len(
        input.items.len(),
        crate::core::config::INTERNAL_MAC_BATCH,
        "mac",
    )?;
    let mut items = Vec::with_capacity(input.items.len());
    for (index, item) in input.items.into_iter().enumerate() {
        let ref_id = validation::validate_ref(&item.ref_id)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        validation::validate_text_field("plaintext", &item.plaintext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        items.push(ValidatedMacCreateBatchItem {
            ref_id,
            plaintext: Zeroizing::new(item.plaintext),
        });
    }
    crate::ops::batch::validate_unique_refs(items.iter().map(|item| item.ref_id.as_str()), "mac")?;

    Ok(ValidatedMacCreateBatchInput {
        profile: input.profile,
        items,
    })
}

pub fn validate_verify_batch_input(
    input: MacVerifyBatchInput,
) -> Result<ValidatedMacVerifyBatchInput, DynError> {
    keys::validate_key_id(&input.kid)
        .map_err(|err| crate::error::invalid_input(format!("kid is invalid: {err}")))?;
    validation::validate_aad_config_name("profile", &input.profile)?;
    crate::ops::batch::validate_len(
        input.items.len(),
        crate::core::config::INTERNAL_MAC_BATCH,
        "mac",
    )?;
    let mut items = Vec::with_capacity(input.items.len());
    for (index, item) in input.items.into_iter().enumerate() {
        let ref_id = validation::validate_ref(&item.ref_id)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        validation::validate_text_field("plaintext", &item.plaintext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        validation::validate_hex_field("digest", &item.digest)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        items.push(ValidatedMacVerifyBatchItem {
            ref_id,
            plaintext: Zeroizing::new(item.plaintext),
            digest: Zeroizing::new(item.digest),
        });
    }
    crate::ops::batch::validate_unique_refs(items.iter().map(|item| item.ref_id.as_str()), "mac")?;

    Ok(ValidatedMacVerifyBatchInput {
        kid: input.kid,
        profile: input.profile,
        items,
    })
}

pub fn prepare_create(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: mac::MacProfile,
    input: ValidatedMacCreateInput,
) -> Result<PreparedMacCreate, DynError> {
    keys::prepare_profile_use(keys_db_state, kid, profile.kid(), keys::ProfileUse::NewUse)?;

    Ok(PreparedMacCreate {
        kid: kid.to_string(),
        profile,
        input,
    })
}

pub fn prepare_verify(
    keys_db_state: &KeysDbState,
    profile: mac::MacProfile,
    input: ValidatedMacVerifyInput,
) -> Result<PreparedMacVerify, DynError> {
    keys::prepare_profile_use(
        keys_db_state,
        input.kid(),
        profile.kid(),
        keys::ProfileUse::Verify,
    )?;

    Ok(PreparedMacVerify { profile, input })
}

pub fn prepare_create_batch(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: mac::MacProfile,
    input: ValidatedMacCreateBatchInput,
) -> Result<PreparedMacCreateBatch, DynError> {
    keys::prepare_profile_use(keys_db_state, kid, profile.kid(), keys::ProfileUse::NewUse)?;

    Ok(PreparedMacCreateBatch {
        kid: kid.to_string(),
        profile,
        input,
    })
}

pub fn prepare_verify_batch(
    keys_db_state: &KeysDbState,
    profile: mac::MacProfile,
    input: ValidatedMacVerifyBatchInput,
) -> Result<PreparedMacVerifyBatch, DynError> {
    keys::prepare_profile_use(
        keys_db_state,
        input.kid(),
        profile.kid(),
        keys::ProfileUse::Verify,
    )?;

    Ok(PreparedMacVerifyBatch {
        kid: input.kid.clone(),
        profile,
        input,
    })
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

pub fn create_batch(prepared: PreparedMacCreateBatch) -> Result<MacCreateBatchOutput, DynError> {
    let mut items = Vec::with_capacity(prepared.input.items.len());
    for (index, item) in prepared.input.items.iter().enumerate() {
        let digest = compute_digest(&prepared.profile, &item.plaintext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        items.push(MacCreateBatchOutputItem {
            ref_id: item.ref_id.clone(),
            digest: hex::encode(digest),
        });
    }

    Ok(MacCreateBatchOutput {
        kid: prepared.kid,
        profile: prepared.input.profile,
        algorithm: prepared.profile.algorithm().to_string(),
        items,
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

pub fn verify_batch(prepared: PreparedMacVerifyBatch) -> Result<MacVerifyBatchOutput, DynError> {
    let mut items = Vec::with_capacity(prepared.input.items.len());
    for (index, item) in prepared.input.items.iter().enumerate() {
        let expected = compute_digest(&prepared.profile, &item.plaintext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        let actual = hex::decode(&*item.digest)?;
        items.push(MacVerifyBatchOutputItem {
            ref_id: item.ref_id.clone(),
            valid: crate::core::crypto::constant_time_eq(&expected, &actual),
        });
    }

    Ok(MacVerifyBatchOutput {
        kid: prepared.kid,
        profile: prepared.input.profile,
        items,
    })
}

pub(crate) fn compute_digest(
    profile: &mac::MacProfile,
    plaintext: &str,
) -> Result<Vec<u8>, DynError> {
    if profile.uses_kmac() {
        return Ok(crate::core::crypto::create_kmac_with_algorithm(
            profile.botan_algorithm(),
            profile.mac_key(),
            profile.customization().as_bytes(),
            plaintext.as_bytes(),
        )?);
    }

    Ok(crate::core::crypto::create_hmac_with_algorithm(
        profile.botan_algorithm(),
        profile.mac_key(),
        plaintext.as_bytes(),
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
            "kid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
            kid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
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

    #[test]
    fn validates_create_batch_input() {
        let input = parse_create_batch_input(json!({
            "profile": "pan-blind-index-v1",
            "items": [
                {"ref": "reg1", "plaintext": "4111111111111111"},
                {"ref": "reg2", "plaintext": "5555555555554444"}
            ]
        }))
        .and_then(validate_create_batch_input)
        .expect("valid MAC create batch input must pass");

        assert_eq!(input.profile(), "pan-blind-index-v1");
    }

    #[test]
    fn validates_verify_batch_input() {
        let input = parse_verify_batch_input(json!({
            "kid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "profile": "pan-blind-index-v1",
            "items": [
                {"ref": "reg1", "plaintext": "4111111111111111", "digest": "00"},
                {"ref": "reg2", "plaintext": "5555555555554444", "digest": "11"}
            ]
        }))
        .and_then(validate_verify_batch_input)
        .expect("valid MAC verify batch input must pass");

        assert_eq!(input.profile(), "pan-blind-index-v1");
    }

    #[test]
    fn rejects_invalid_create_batch_bounds_and_refs() {
        let empty = parse_create_batch_input(json!({
            "profile": "pan-blind-index-v1",
            "items": []
        }))
        .and_then(validate_create_batch_input);
        let err = match empty {
            Ok(_) => panic!("empty MAC batch must fail"),
            Err(err) => err,
        };
        assert_eq!(err.to_string(), "mac batch items must not be empty");

        let duplicate = parse_create_batch_input(json!({
            "profile": "pan-blind-index-v1",
            "items": [
                {"ref": "dup", "plaintext": "4111111111111111"},
                {"ref": "dup", "plaintext": "5555555555554444"}
            ]
        }))
        .and_then(validate_create_batch_input);
        let err = match duplicate {
            Ok(_) => panic!("duplicate refs must fail"),
            Err(err) => err,
        };
        assert_eq!(
            err.to_string(),
            "batch item 1 failed: mac batch ref must be unique"
        );
    }

    #[test]
    fn rejects_oversized_create_batch_early() {
        let items = (0..=crate::core::config::INTERNAL_MAC_BATCH)
            .map(|index| json!({"ref": format!("reg{index}"), "plaintext": "4111111111111111"}))
            .collect::<Vec<_>>();
        let result = parse_create_batch_input(json!({
            "profile": "pan-blind-index-v1",
            "items": items
        }))
        .and_then(validate_create_batch_input);
        let err = match result {
            Ok(_) => panic!("oversized MAC batch must fail"),
            Err(err) => err,
        };
        assert_eq!(
            err.to_string(),
            "mac batch items exceeds maximum allowed value: 128"
        );
    }

    #[test]
    fn rejects_invalid_verify_batch_digest() {
        let invalid = parse_verify_batch_input(json!({
            "kid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "profile": "pan-blind-index-v1",
            "items": [
                {"ref": "reg1", "plaintext": "4111111111111111", "digest": "not-hex"}
            ]
        }))
        .and_then(validate_verify_batch_input);
        let err = match invalid {
            Ok(_) => panic!("invalid digest must fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("batch item 0 failed: digest"));
    }

    #[test]
    fn mac_batch_outputs_serialize_items() {
        let created = serde_json::to_value(MacCreateBatchOutput {
            kid: "a".repeat(64),
            profile: "pan-blind-index-v1".to_string(),
            algorithm: "KMAC-256".to_string(),
            items: vec![MacCreateBatchOutputItem {
                ref_id: "reg1".to_string(),
                digest: "00".repeat(32),
            }],
        })
        .unwrap();
        assert_eq!(created["items"][0]["ref"], "reg1");
        assert_eq!(created["items"][0]["digest"], "00".repeat(32));

        let verified = serde_json::to_value(MacVerifyBatchOutput {
            kid: "a".repeat(64),
            profile: "pan-blind-index-v1".to_string(),
            items: vec![MacVerifyBatchOutputItem {
                ref_id: "reg1".to_string(),
                valid: false,
            }],
        })
        .unwrap();
        assert_eq!(verified["items"][0], json!({"ref": "reg1", "valid": false}));
    }

    const TEST_KID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TEST_OPS_KEY_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    fn build_profile(name: &str, context: &str, hash: &'static str) -> mac::MacProfile {
        let inputs: Vec<mac::MacProfileInput> = serde_json::from_value(json!([
            {"name": name, "kid": TEST_KID, "context": context}
        ]))
        .expect("mac profile input must deserialize");
        let state = mac::validate_mac_profiles(
            inputs,
            |_| true,
            move |_| Ok(hash.to_string()),
            |req| mac::derive_mac_key_for_profile(TEST_OPS_KEY_HEX, req),
        )
        .expect("mac profile must validate");

        state.get(name).expect("profile must be present").clone()
    }

    #[test]
    fn kmac_digest_uses_native_customization() {
        let profile = build_profile("kmac-prof", "tenant=mx;field=pan", "SHA-3(256)");
        assert!(profile.uses_kmac());
        let plaintext = "4111111111111111";

        let actual = compute_digest(&profile, plaintext).expect("kmac digest must compute");
        let expected = crate::core::crypto::create_kmac_with_algorithm(
            profile.botan_algorithm(),
            profile.mac_key(),
            profile.customization().as_bytes(),
            plaintext.as_bytes(),
        )
        .expect("expected kmac must compute");

        assert_eq!(actual, expected);
    }

    #[test]
    fn hmac_digest_macs_plaintext_with_baked_subkey() {
        let profile = build_profile("hmac-prof", "tenant=mx;field=pan", "BLAKE2b(256)");
        assert!(!profile.uses_kmac());
        let plaintext = "4111111111111111";

        let actual = compute_digest(&profile, plaintext).expect("hmac digest must compute");
        let expected = crate::core::crypto::create_hmac_with_algorithm(
            profile.botan_algorithm(),
            profile.mac_key(),
            plaintext.as_bytes(),
        )
        .expect("expected hmac must compute");

        assert_eq!(actual, expected);
    }

    #[test]
    fn hmac_profile_bakes_customization_into_key() {
        let profile = build_profile("hmac-prof", "tenant=mx;field=pan", "BLAKE2b(256)");
        let raw = mac::derive_mac_key_for_profile(
            TEST_OPS_KEY_HEX,
            mac::MacKeyDerivationRequest {
                profile_name: "hmac-prof",
                kid: TEST_KID,
                context: "tenant=mx;field=pan",
                hash_algorithm: "BLAKE2b(256)",
            },
        )
        .expect("raw mac key must derive");
        let expected = crate::core::crypto::create_hkdf(
            &raw.mac_key,
            mac::MAC_HMAC_SUBKEY_SALT,
            profile.customization().as_bytes(),
            mac::MAC_KEY_SIZE_BYTES,
        )
        .expect("expected hmac subkey must derive");

        assert_eq!(profile.mac_key(), expected.as_slice());
        assert_ne!(profile.mac_key(), raw.mac_key.as_slice());
    }

    #[test]
    fn compute_digest_is_deterministic_and_context_separated() {
        for hash in ["SHA-3(256)", "BLAKE2b(256)"] {
            let a = build_profile("prof", "tenant=mx;field=pan", hash);
            let a_again = build_profile("prof", "tenant=mx;field=pan", hash);
            let other_context = build_profile("prof", "tenant=mx;field=ssn", hash);
            let plaintext = "4111111111111111";

            let digest = compute_digest(&a, plaintext).expect("digest must compute");
            assert_eq!(
                digest,
                compute_digest(&a_again, plaintext).expect("digest must compute")
            );
            assert_ne!(
                digest,
                compute_digest(&other_context, plaintext).expect("digest must compute")
            );
        }
    }
}
