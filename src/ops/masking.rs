use crate::core::{masking, validation};
use crate::error::DynError;
use crate::ops::keys::{self, KeysDbState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaskInput {
    #[serde(rename = "ref")]
    ref_id: String,
    profile: String,
    plaintext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaskBatchItemInput {
    #[serde(rename = "ref")]
    ref_id: String,
    plaintext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaskBatchInput {
    profile: String,
    items: Vec<MaskBatchItemInput>,
}

#[derive(Serialize)]
pub struct MaskOutput {
    #[serde(rename = "ref")]
    ref_id: String,
    kid: String,
    profile: String,
    masked: String,
}

#[derive(Serialize)]
pub struct MaskBatchOutputItem {
    #[serde(rename = "ref")]
    ref_id: String,
    masked: String,
}

#[derive(Serialize)]
pub struct MaskBatchOutput {
    kid: String,
    profile: String,
    items: Vec<MaskBatchOutputItem>,
}

impl MaskBatchOutput {
    pub fn items_len(&self) -> usize {
        self.items.len()
    }
}

pub struct ValidatedMaskInput {
    ref_id: String,
    profile: String,
    plaintext: Zeroizing<String>,
}

pub struct ValidatedMaskBatchItem {
    ref_id: String,
    plaintext: Zeroizing<String>,
}

pub struct ValidatedMaskBatchInput {
    profile: String,
    items: Vec<ValidatedMaskBatchItem>,
}

pub struct PreparedMask {
    kid: String,
    profile: masking::MaskingProfile,
    input: ValidatedMaskInput,
}

pub struct PreparedMaskBatch {
    kid: String,
    profile: masking::MaskingProfile,
    input: ValidatedMaskBatchInput,
}

impl ValidatedMaskInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedMaskBatchInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

pub fn parse_mask_input(request: Value) -> Result<MaskInput, DynError> {
    crate::ops::json::parse_json_request(request, "mask request")
}

pub fn parse_mask_batch_input(request: Value) -> Result<MaskBatchInput, DynError> {
    crate::ops::batch::reject_oversized_value(
        &request,
        crate::core::config::INTERNAL_MASK_BATCH,
        "mask",
    )?;
    crate::ops::json::parse_json_request(request, "mask request")
}

pub fn validate_mask_input(input: MaskInput) -> Result<ValidatedMaskInput, DynError> {
    let ref_id = validation::validate_ref(&input.ref_id)?;
    validation::validate_aad_config_name("profile", &input.profile)?;
    validation::validate_text_field("plaintext", &input.plaintext)?;

    Ok(ValidatedMaskInput {
        ref_id,
        profile: input.profile,
        plaintext: Zeroizing::new(input.plaintext),
    })
}

pub fn validate_mask_batch_input(
    input: MaskBatchInput,
) -> Result<ValidatedMaskBatchInput, DynError> {
    validation::validate_aad_config_name("profile", &input.profile)?;
    crate::ops::batch::validate_len(
        input.items.len(),
        crate::core::config::INTERNAL_MASK_BATCH,
        "mask",
    )?;
    let mut items = Vec::with_capacity(input.items.len());
    for (index, item) in input.items.into_iter().enumerate() {
        let ref_id = validation::validate_ref(&item.ref_id)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        validation::validate_text_field("plaintext", &item.plaintext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        items.push(ValidatedMaskBatchItem {
            ref_id,
            plaintext: Zeroizing::new(item.plaintext),
        });
    }
    crate::ops::batch::validate_unique_refs(items.iter().map(|item| item.ref_id.as_str()), "mask")?;

    Ok(ValidatedMaskBatchInput {
        profile: input.profile,
        items,
    })
}

pub fn prepare_mask(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: masking::MaskingProfile,
    input: ValidatedMaskInput,
) -> Result<PreparedMask, DynError> {
    keys::prepare_profile_use(
        keys_db_state,
        kid,
        profile.kid(),
        "masking",
        keys::ProfileUse::Verify,
    )?;

    Ok(PreparedMask {
        kid: kid.to_string(),
        profile,
        input,
    })
}

pub fn prepare_mask_batch(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: masking::MaskingProfile,
    input: ValidatedMaskBatchInput,
) -> Result<PreparedMaskBatch, DynError> {
    keys::prepare_profile_use(
        keys_db_state,
        kid,
        profile.kid(),
        "masking",
        keys::ProfileUse::Verify,
    )?;

    Ok(PreparedMaskBatch {
        kid: kid.to_string(),
        profile,
        input,
    })
}

pub fn mask(prepared: PreparedMask) -> Result<MaskOutput, DynError> {
    let masked = masking::mask(&prepared.profile, &prepared.input.plaintext)?;
    info!(
        kid = %prepared.kid,
        profile = %prepared.profile.name(),
        plaintext_len = prepared.input.plaintext.chars().count(),
        "mask completed"
    );

    Ok(MaskOutput {
        ref_id: prepared.input.ref_id,
        kid: prepared.kid,
        profile: prepared.profile.name().to_string(),
        masked,
    })
}

pub fn mask_batch(prepared: PreparedMaskBatch) -> Result<MaskBatchOutput, DynError> {
    let mut items = Vec::with_capacity(prepared.input.items.len());
    for (index, item) in prepared.input.items.iter().enumerate() {
        let masked = masking::mask(&prepared.profile, &item.plaintext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        items.push(MaskBatchOutputItem {
            ref_id: item.ref_id.clone(),
            masked,
        });
    }
    info!(
        kid = %prepared.kid,
        profile = %prepared.profile.name(),
        items_count = items.len(),
        "mask batch completed"
    );

    Ok(MaskBatchOutput {
        kid: prepared.kid,
        profile: prepared.profile.name().to_string(),
        items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_KID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn masking_profile(kid: &str) -> masking::MaskingProfile {
        let input = serde_json::from_value(json!({
            "name": "pan-display-v1",
            "kid": kid,
            "visible_first": 0,
            "visible_last": 4,
            "mask_char": "*",
            "min_len": 12,
            "max_len": 19
        }))
        .expect("masking profile input must deserialize");
        masking::validate_masking_profiles(vec![input], |_| true)
            .expect("masking profile must validate")
            .get("pan-display-v1")
            .expect("profile must exist")
            .clone()
    }

    fn keys_state(status: &str) -> KeysDbState {
        keys::test_keys_state_with_lifecycle(KID, status)
    }

    fn mask_input() -> MaskInput {
        parse_mask_input(json!({
            "ref": "row1",
            "profile": "pan-display-v1",
            "plaintext": "4111111111111111"
        }))
        .expect("mask input must parse")
    }

    fn err_string<T>(result: Result<T, DynError>) -> String {
        result.err().expect("operation must fail").to_string()
    }

    #[test]
    fn validates_single_mask_input_and_rejects_bad_shapes() {
        let input = validate_mask_input(mask_input()).expect("valid mask input must pass");
        assert_eq!(input.profile(), "pan-display-v1");

        assert!(
            parse_mask_input(json!({
                "ref": "row1",
                "profile": "pan-display-v1",
                "plaintext": "4111111111111111",
                "extra": true
            }))
            .is_err()
        );
        assert_eq!(
            err_string(validate_mask_input(
                parse_mask_input(json!({
                    "ref": "bad\nref",
                    "profile": "pan-display-v1",
                    "plaintext": "4111111111111111"
                }))
                .unwrap()
            )),
            "ref must not contain control characters"
        );
        assert_eq!(
            err_string(validate_mask_input(
                parse_mask_input(json!({
                    "ref": "row1",
                    "profile": "bad;profile",
                    "plaintext": "4111111111111111"
                }))
                .unwrap()
            )),
            "profile must not contain ';' or '='"
        );
        assert_eq!(
            err_string(validate_mask_input(
                parse_mask_input(json!({
                    "ref": "row1",
                    "profile": "pan-display-v1",
                    "plaintext": ""
                }))
                .unwrap()
            )),
            "plaintext must not be empty"
        );
    }

    #[test]
    fn validates_mask_batch_input() {
        let input = parse_mask_batch_input(json!({
            "profile": "pan-display-v1",
            "items": [
                {"ref": "row1", "plaintext": "4111111111111111"},
                {"ref": "row2", "plaintext": "5555555555554444"}
            ]
        }))
        .and_then(validate_mask_batch_input)
        .expect("valid mask batch input must pass");

        assert_eq!(input.items.len(), 2);
    }

    #[test]
    fn rejects_empty_and_duplicate_refs() {
        assert!(
            parse_mask_batch_input(json!({"profile": "pan-display-v1", "items": []}))
                .and_then(validate_mask_batch_input)
                .is_err()
        );
        assert!(
            parse_mask_batch_input(json!({
                "profile": "pan-display-v1",
                "items": [
                    {"ref": "row1", "plaintext": "4111111111111111"},
                    {"ref": "row1", "plaintext": "5555555555554444"}
                ]
            }))
            .and_then(validate_mask_batch_input)
            .is_err()
        );
    }

    #[test]
    fn prepare_mask_enforces_profile_kid_and_lifecycle() {
        let profile = masking_profile(KID);
        let input = validate_mask_input(mask_input()).unwrap();
        assert!(prepare_mask(&keys_state("active"), KID, profile.clone(), input).is_ok());

        let input = validate_mask_input(mask_input()).unwrap();
        let err = prepare_mask(&keys_state("active"), OTHER_KID, profile.clone(), input)
            .err()
            .expect("profile kid mismatch must fail");
        assert_eq!(
            err.to_string(),
            "masking profile is not authorized for this kid"
        );

        let input = validate_mask_input(mask_input()).unwrap();
        assert!(
            prepare_mask(&keys_state("retired"), KID, profile.clone(), input).is_ok(),
            "retired keys may support verify-like masking"
        );

        let input = validate_mask_input(mask_input()).unwrap();
        let err = prepare_mask(&keys_state("compromised"), KID, profile, input)
            .err()
            .expect("compromised key must block masking");
        assert_eq!(
            err.to_string(),
            "key is compromised and cannot be used for security reasons"
        );
    }

    #[test]
    fn mask_outputs_expected_value() {
        let profile = masking_profile(KID);
        let input = validate_mask_input(mask_input()).unwrap();
        let prepared =
            prepare_mask(&keys_state("active"), KID, profile, input).expect("mask must prepare");
        let output = mask(prepared).expect("mask must succeed");

        assert_eq!(output.ref_id, "row1");
        assert_eq!(output.kid, KID);
        assert_eq!(output.profile, "pan-display-v1");
        assert_eq!(output.masked, "************1111");
    }

    #[test]
    fn mask_batch_preserves_order_and_reports_item_errors() {
        let profile = masking_profile(KID);
        let input = parse_mask_batch_input(json!({
            "profile": "pan-display-v1",
            "items": [
                {"ref": "row1", "plaintext": "4111111111111111"},
                {"ref": "row2", "plaintext": "5555555555554444"}
            ]
        }))
        .and_then(validate_mask_batch_input)
        .unwrap();
        let prepared = prepare_mask_batch(&keys_state("active"), KID, profile.clone(), input)
            .expect("batch must prepare");
        let output = mask_batch(prepared).expect("batch must mask");

        assert_eq!(output.kid, KID);
        assert_eq!(output.profile, "pan-display-v1");
        assert_eq!(output.items[0].ref_id, "row1");
        assert_eq!(output.items[0].masked, "************1111");
        assert_eq!(output.items[1].ref_id, "row2");
        assert_eq!(output.items[1].masked, "************4444");

        let input = parse_mask_batch_input(json!({
            "profile": "pan-display-v1",
            "items": [
                {"ref": "row1", "plaintext": "4111111111111111"},
                {"ref": "row2", "plaintext": "123"}
            ]
        }))
        .and_then(validate_mask_batch_input)
        .unwrap();
        let prepared = prepare_mask_batch(&keys_state("active"), KID, profile, input)
            .expect("batch with short plaintext still prepares");
        let err = mask_batch(prepared)
            .err()
            .expect("short plaintext must fail during masking");
        assert_eq!(
            err.to_string(),
            "batch item 1 failed: plaintext length is outside masking profile bounds"
        );
    }

    #[test]
    fn parse_mask_input_preserves_unknown_field_detail() {
        let err = match parse_mask_input(json!({
            "ref": "row1",
            "profile": "pan-display-v1",
            "plaintext": "4111111111111111",
            "sorpresa": true
        })) {
            Ok(_) => panic!("unknown fields must fail"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("invalid mask request: unknown field")
        );
        assert!(err.to_string().contains("sorpresa"));
    }
}
