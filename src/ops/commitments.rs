use crate::core::{commitments, crypto, validation};
use crate::error::DynError;
use crate::ops::keys::{self, KeysDbState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitCreateInput {
    #[serde(rename = "ref")]
    ref_id: String,
    profile: String,
    plaintext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitVerifyInput {
    #[serde(rename = "ref")]
    ref_id: String,
    kid: String,
    profile: String,
    plaintext: String,
    opening: String,
    commitment: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitCreateBatchItemInput {
    #[serde(rename = "ref")]
    ref_id: String,
    plaintext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitCreateBatchInput {
    profile: String,
    items: Vec<CommitCreateBatchItemInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitVerifyBatchItemInput {
    #[serde(rename = "ref")]
    ref_id: String,
    plaintext: String,
    opening: String,
    commitment: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitVerifyBatchInput {
    kid: String,
    profile: String,
    items: Vec<CommitVerifyBatchItemInput>,
}

#[derive(Serialize)]
pub struct CommitCreateOutput {
    #[serde(rename = "ref")]
    ref_id: String,
    kid: String,
    profile: String,
    algorithm: String,
    commitment: String,
    opening: String,
}

#[derive(Serialize)]
pub struct CommitVerifyOutput {
    #[serde(rename = "ref")]
    ref_id: String,
    kid: String,
    profile: String,
    valid: bool,
}

#[derive(Serialize)]
pub struct CommitCreateBatchOutputItem {
    #[serde(rename = "ref")]
    ref_id: String,
    commitment: String,
    opening: String,
}

#[derive(Serialize)]
pub struct CommitCreateBatchOutput {
    kid: String,
    profile: String,
    algorithm: String,
    items: Vec<CommitCreateBatchOutputItem>,
}

#[derive(Serialize)]
pub struct CommitVerifyBatchOutputItem {
    #[serde(rename = "ref")]
    ref_id: String,
    valid: bool,
}

#[derive(Serialize)]
pub struct CommitVerifyBatchOutput {
    kid: String,
    profile: String,
    items: Vec<CommitVerifyBatchOutputItem>,
}

pub struct ValidatedCommitCreateInput {
    ref_id: String,
    profile: String,
    plaintext: Zeroizing<String>,
}

pub struct ValidatedCommitVerifyInput {
    ref_id: String,
    kid: String,
    profile: String,
    plaintext: Zeroizing<String>,
    opening: Zeroizing<String>,
    commitment: Zeroizing<String>,
}

pub struct ValidatedCommitCreateBatchItem {
    ref_id: String,
    plaintext: Zeroizing<String>,
}

pub struct ValidatedCommitCreateBatchInput {
    profile: String,
    items: Vec<ValidatedCommitCreateBatchItem>,
}

pub struct ValidatedCommitVerifyBatchItem {
    ref_id: String,
    plaintext: Zeroizing<String>,
    opening: Zeroizing<String>,
    commitment: Zeroizing<String>,
}

pub struct ValidatedCommitVerifyBatchInput {
    kid: String,
    profile: String,
    items: Vec<ValidatedCommitVerifyBatchItem>,
}

pub struct PreparedCommitCreate {
    kid: String,
    profile: commitments::CommitmentProfile,
    input: ValidatedCommitCreateInput,
}

pub struct PreparedCommitVerify {
    kid: String,
    profile: commitments::CommitmentProfile,
    input: ValidatedCommitVerifyInput,
}

pub struct PreparedCommitCreateBatch {
    kid: String,
    profile: commitments::CommitmentProfile,
    input: ValidatedCommitCreateBatchInput,
}

pub struct PreparedCommitVerifyBatch {
    kid: String,
    profile: commitments::CommitmentProfile,
    input: ValidatedCommitVerifyBatchInput,
}

impl ValidatedCommitCreateInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedCommitVerifyInput {
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedCommitCreateBatchInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedCommitVerifyBatchInput {
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl CommitCreateBatchOutput {
    pub fn items_len(&self) -> usize {
        self.items.len()
    }
}

impl CommitVerifyBatchOutput {
    pub fn items_len(&self) -> usize {
        self.items.len()
    }
}

pub fn parse_create_input(request: Value) -> Result<CommitCreateInput, DynError> {
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid commit request"))
}

pub fn parse_verify_input(request: Value) -> Result<CommitVerifyInput, DynError> {
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid commit request"))
}

pub fn parse_create_batch_input(request: Value) -> Result<CommitCreateBatchInput, DynError> {
    crate::ops::batch::reject_oversized_value(
        &request,
        crate::core::config::INTERNAL_COMMIT_BATCH,
        "commit",
    )?;
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid commit request"))
}

pub fn parse_verify_batch_input(request: Value) -> Result<CommitVerifyBatchInput, DynError> {
    crate::ops::batch::reject_oversized_value(
        &request,
        crate::core::config::INTERNAL_COMMIT_BATCH,
        "commit",
    )?;
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid commit request"))
}

pub fn validate_create_input(
    input: CommitCreateInput,
) -> Result<ValidatedCommitCreateInput, DynError> {
    let ref_id = validation::validate_ref(&input.ref_id)?;
    validation::validate_aad_config_name("profile", &input.profile)?;
    validation::validate_text_field("plaintext", &input.plaintext)?;

    Ok(ValidatedCommitCreateInput {
        ref_id,
        profile: input.profile,
        plaintext: Zeroizing::new(input.plaintext),
    })
}

pub fn validate_verify_input(
    input: CommitVerifyInput,
) -> Result<ValidatedCommitVerifyInput, DynError> {
    let ref_id = validation::validate_ref(&input.ref_id)?;
    keys::validate_key_id(&input.kid)
        .map_err(|err| crate::error::invalid_input(format!("kid is invalid: {err}")))?;
    validation::validate_aad_config_name("profile", &input.profile)?;
    validation::validate_text_field("plaintext", &input.plaintext)?;
    validation::validate_text_field("opening", &input.opening)?;
    validation::validate_hex_field("commitment", &input.commitment)?;

    Ok(ValidatedCommitVerifyInput {
        ref_id,
        kid: input.kid,
        profile: input.profile,
        plaintext: Zeroizing::new(input.plaintext),
        opening: Zeroizing::new(input.opening),
        commitment: Zeroizing::new(input.commitment),
    })
}

pub fn validate_create_batch_input(
    input: CommitCreateBatchInput,
) -> Result<ValidatedCommitCreateBatchInput, DynError> {
    validation::validate_aad_config_name("profile", &input.profile)?;
    crate::ops::batch::validate_len(
        input.items.len(),
        crate::core::config::INTERNAL_COMMIT_BATCH,
        "commit",
    )?;
    let mut items = Vec::with_capacity(input.items.len());
    for (index, item) in input.items.into_iter().enumerate() {
        let ref_id = validation::validate_ref(&item.ref_id)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        validation::validate_text_field("plaintext", &item.plaintext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        items.push(ValidatedCommitCreateBatchItem {
            ref_id,
            plaintext: Zeroizing::new(item.plaintext),
        });
    }
    crate::ops::batch::validate_unique_refs(
        items.iter().map(|item| item.ref_id.as_str()),
        "commit",
    )?;

    Ok(ValidatedCommitCreateBatchInput {
        profile: input.profile,
        items,
    })
}

pub fn validate_verify_batch_input(
    input: CommitVerifyBatchInput,
) -> Result<ValidatedCommitVerifyBatchInput, DynError> {
    keys::validate_key_id(&input.kid)
        .map_err(|err| crate::error::invalid_input(format!("kid is invalid: {err}")))?;
    validation::validate_aad_config_name("profile", &input.profile)?;
    crate::ops::batch::validate_len(
        input.items.len(),
        crate::core::config::INTERNAL_COMMIT_BATCH,
        "commit",
    )?;
    let mut items = Vec::with_capacity(input.items.len());
    for (index, item) in input.items.into_iter().enumerate() {
        let ref_id = validation::validate_ref(&item.ref_id)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        validation::validate_text_field("plaintext", &item.plaintext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        validation::validate_text_field("opening", &item.opening)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        validation::validate_hex_field("commitment", &item.commitment)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        items.push(ValidatedCommitVerifyBatchItem {
            ref_id,
            plaintext: Zeroizing::new(item.plaintext),
            opening: Zeroizing::new(item.opening),
            commitment: Zeroizing::new(item.commitment),
        });
    }
    crate::ops::batch::validate_unique_refs(
        items.iter().map(|item| item.ref_id.as_str()),
        "commit",
    )?;

    Ok(ValidatedCommitVerifyBatchInput {
        kid: input.kid,
        profile: input.profile,
        items,
    })
}

pub fn prepare_create(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: commitments::CommitmentProfile,
    input: ValidatedCommitCreateInput,
) -> Result<PreparedCommitCreate, DynError> {
    keys::prepare_profile_use(
        keys_db_state,
        kid,
        profile.kid(),
        "commit",
        keys::ProfileUse::NewUse,
    )?;
    validate_plaintext_len(&profile, &input.plaintext)?;

    Ok(PreparedCommitCreate {
        kid: kid.to_string(),
        profile,
        input,
    })
}

pub fn prepare_verify(
    keys_db_state: &KeysDbState,
    profile: commitments::CommitmentProfile,
    input: ValidatedCommitVerifyInput,
) -> Result<PreparedCommitVerify, DynError> {
    keys::prepare_profile_use(
        keys_db_state,
        input.kid(),
        profile.kid(),
        "commit",
        keys::ProfileUse::Verify,
    )?;
    validate_plaintext_len(&profile, &input.plaintext)?;
    commitments::validate_opening(&profile, &input.opening)?;

    Ok(PreparedCommitVerify {
        kid: input.kid.clone(),
        profile,
        input,
    })
}

pub fn prepare_create_batch(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: commitments::CommitmentProfile,
    input: ValidatedCommitCreateBatchInput,
) -> Result<PreparedCommitCreateBatch, DynError> {
    keys::prepare_profile_use(
        keys_db_state,
        kid,
        profile.kid(),
        "commit",
        keys::ProfileUse::NewUse,
    )?;
    for (index, item) in input.items.iter().enumerate() {
        validate_plaintext_len(&profile, &item.plaintext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
    }

    Ok(PreparedCommitCreateBatch {
        kid: kid.to_string(),
        profile,
        input,
    })
}

pub fn prepare_verify_batch(
    keys_db_state: &KeysDbState,
    profile: commitments::CommitmentProfile,
    input: ValidatedCommitVerifyBatchInput,
) -> Result<PreparedCommitVerifyBatch, DynError> {
    keys::prepare_profile_use(
        keys_db_state,
        input.kid(),
        profile.kid(),
        "commit",
        keys::ProfileUse::Verify,
    )?;
    for (index, item) in input.items.iter().enumerate() {
        validate_plaintext_len(&profile, &item.plaintext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        commitments::validate_opening(&profile, &item.opening)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
    }

    Ok(PreparedCommitVerifyBatch {
        kid: input.kid.clone(),
        profile,
        input,
    })
}

pub fn create(prepared: PreparedCommitCreate) -> Result<CommitCreateOutput, DynError> {
    let opening = generate_opening(&prepared.profile)?;
    let commitment =
        commitments::compute_commitment(&prepared.profile, &opening, &prepared.input.plaintext)?;

    Ok(CommitCreateOutput {
        ref_id: prepared.input.ref_id,
        kid: prepared.kid,
        profile: prepared.input.profile,
        algorithm: prepared.profile.algorithm().to_string(),
        commitment: hex::encode(commitment),
        opening,
    })
}

pub fn create_batch(
    prepared: PreparedCommitCreateBatch,
) -> Result<CommitCreateBatchOutput, DynError> {
    let mut items = Vec::with_capacity(prepared.input.items.len());
    for (index, item) in prepared.input.items.iter().enumerate() {
        let opening = generate_opening(&prepared.profile)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        let commitment =
            commitments::compute_commitment(&prepared.profile, &opening, &item.plaintext).map_err(
                |err| crate::error::with_prefix(&format!("batch item {index} failed"), err),
            )?;
        items.push(CommitCreateBatchOutputItem {
            ref_id: item.ref_id.clone(),
            commitment: hex::encode(commitment),
            opening,
        });
    }

    Ok(CommitCreateBatchOutput {
        kid: prepared.kid,
        profile: prepared.input.profile,
        algorithm: prepared.profile.algorithm().to_string(),
        items,
    })
}

pub fn verify(prepared: PreparedCommitVerify) -> Result<CommitVerifyOutput, DynError> {
    let expected = commitments::compute_commitment(
        &prepared.profile,
        &prepared.input.opening,
        &prepared.input.plaintext,
    )?;
    let actual = hex::decode(&*prepared.input.commitment)?;

    Ok(CommitVerifyOutput {
        ref_id: prepared.input.ref_id,
        kid: prepared.kid,
        profile: prepared.input.profile,
        valid: crypto::constant_time_eq(&expected, &actual),
    })
}

pub fn verify_batch(
    prepared: PreparedCommitVerifyBatch,
) -> Result<CommitVerifyBatchOutput, DynError> {
    let mut items = Vec::with_capacity(prepared.input.items.len());
    for (index, item) in prepared.input.items.iter().enumerate() {
        let expected =
            commitments::compute_commitment(&prepared.profile, &item.opening, &item.plaintext)
                .map_err(|err| {
                    crate::error::with_prefix(&format!("batch item {index} failed"), err)
                })?;
        let actual = hex::decode(&*item.commitment)?;
        items.push(CommitVerifyBatchOutputItem {
            ref_id: item.ref_id.clone(),
            valid: crypto::constant_time_eq(&expected, &actual),
        });
    }

    Ok(CommitVerifyBatchOutput {
        kid: prepared.kid,
        profile: prepared.input.profile,
        items,
    })
}

fn validate_plaintext_len(
    profile: &commitments::CommitmentProfile,
    plaintext: &str,
) -> Result<(), DynError> {
    if plaintext.chars().count() > profile.max_plaintext_len() {
        return Err(crate::error::invalid_input(
            "plaintext exceeds commitment profile maximum length",
        ));
    }
    Ok(())
}

fn generate_opening(profile: &commitments::CommitmentProfile) -> Result<String, DynError> {
    let random = Zeroizing::new(crate::core::crypto::random_bytes(profile.opening_len())?);
    Ok(commitments::encode_opening(&random))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validates_commit_batch_input() {
        let input = parse_create_batch_input(json!({
            "profile": "pan-commitment-v1",
            "items": [
                {"ref": "row1", "plaintext": "4111111111111111"},
                {"ref": "row2", "plaintext": "5555555555554444"}
            ]
        }))
        .and_then(validate_create_batch_input)
        .expect("valid commit batch must pass");

        assert_eq!(input.profile(), "pan-commitment-v1");
        assert_eq!(input.items.len(), 2);
    }

    #[test]
    fn rejects_empty_and_duplicate_refs() {
        let empty = match parse_create_batch_input(json!({
            "profile": "pan-commitment-v1",
            "items": []
        }))
        .and_then(validate_create_batch_input)
        {
            Ok(_) => panic!("empty batch must fail"),
            Err(err) => err,
        };
        assert_eq!(empty.to_string(), "commit batch items must not be empty");

        let duplicate = match parse_create_batch_input(json!({
            "profile": "pan-commitment-v1",
            "items": [
                {"ref": "row1", "plaintext": "4111111111111111"},
                {"ref": "row1", "plaintext": "5555555555554444"}
            ]
        }))
        .and_then(validate_create_batch_input)
        {
            Ok(_) => panic!("duplicate refs must fail"),
            Err(err) => err,
        };
        assert_eq!(
            duplicate.to_string(),
            "batch item 1 failed: commit batch ref must be unique"
        );
    }

    #[test]
    fn commitment_outputs_serialize_ref() {
        let created = serde_json::to_value(CommitCreateOutput {
            ref_id: "reg1".to_string(),
            kid: "a".repeat(64),
            profile: "pan-commitment-v1".to_string(),
            algorithm: "KMAC-256".to_string(),
            commitment: "00".repeat(32),
            opening: "abcd".to_string(),
        })
        .unwrap();
        assert_eq!(created["ref"], "reg1");
        assert_eq!(created["commitment"], "00".repeat(32));

        let verified = serde_json::to_value(CommitVerifyOutput {
            ref_id: "reg1".to_string(),
            kid: "a".repeat(64),
            profile: "pan-commitment-v1".to_string(),
            valid: true,
        })
        .unwrap();
        assert_eq!(verified["ref"], "reg1");
        assert_eq!(verified["valid"], true);
    }
}
