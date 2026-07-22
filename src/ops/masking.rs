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
    serde_json::from_value(request).map_err(|_| crate::error::invalid_input("invalid mask request"))
}

pub fn parse_mask_batch_input(request: Value) -> Result<MaskBatchInput, DynError> {
    crate::ops::batch::reject_oversized_value(
        &request,
        crate::core::config::INTERNAL_MASK_BATCH,
        "mask",
    )?;
    serde_json::from_value(request).map_err(|_| crate::error::invalid_input("invalid mask request"))
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
}
