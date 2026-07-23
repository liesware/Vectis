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
    crate::ops::json::parse_json_request(request, "commit request")
}

pub fn parse_verify_input(request: Value) -> Result<CommitVerifyInput, DynError> {
    crate::ops::json::parse_json_request(request, "commit request")
}

pub fn parse_create_batch_input(request: Value) -> Result<CommitCreateBatchInput, DynError> {
    crate::ops::batch::reject_oversized_value(
        &request,
        crate::core::config::INTERNAL_COMMIT_BATCH,
        "commit",
    )?;
    crate::ops::json::parse_json_request(request, "commit request")
}

pub fn parse_verify_batch_input(request: Value) -> Result<CommitVerifyBatchInput, DynError> {
    crate::ops::batch::reject_oversized_value(
        &request,
        crate::core::config::INTERNAL_COMMIT_BATCH,
        "commit",
    )?;
    crate::ops::json::parse_json_request(request, "commit request")
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

    const KID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_KID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn commitment_profile(kid: &str) -> commitments::CommitmentProfile {
        let input = serde_json::from_value(json!({
            "name": "pan-commitment-v1",
            "kid": kid,
            "context": "tenant=mx;field=pan;purpose=commitment;version=1",
            "max_plaintext_len": 20,
            "opening_len": 32
        }))
        .expect("commitment profile input must deserialize");
        commitments::validate_commitment_profiles(
            vec![input],
            |_| true,
            |_| Ok(String::from("SHA-3(256)")),
            |request| commitments::derive_commitment_key_for_profile(&"11".repeat(32), request),
        )
        .expect("commitment profile must validate")
        .get("pan-commitment-v1")
        .expect("profile must exist")
        .clone()
    }

    fn keys_state(status: &str) -> KeysDbState {
        keys::test_keys_state_with_lifecycle(KID, status)
    }

    fn create_input_with_plaintext(plaintext: &str) -> CommitCreateInput {
        parse_create_input(json!({
            "ref": "row1",
            "profile": "pan-commitment-v1",
            "plaintext": plaintext
        }))
        .expect("commit create input must parse")
    }

    fn create_input() -> CommitCreateInput {
        create_input_with_plaintext("4111111111111111")
    }

    fn verify_input(plaintext: &str, opening: &str, commitment: &str) -> CommitVerifyInput {
        parse_verify_input(json!({
            "ref": "row1",
            "kid": KID,
            "profile": "pan-commitment-v1",
            "plaintext": plaintext,
            "opening": opening,
            "commitment": commitment
        }))
        .expect("commit verify input must parse")
    }

    fn created_commitment(profile: commitments::CommitmentProfile) -> CommitCreateOutput {
        let input = validate_create_input(create_input()).unwrap();
        let prepared = prepare_create(&keys_state("active"), KID, profile, input)
            .expect("commit create must prepare");
        create(prepared).expect("commitment must create")
    }

    fn err_string<T>(result: Result<T, DynError>) -> String {
        result.err().expect("operation must fail").to_string()
    }

    #[test]
    fn validates_single_commit_inputs_and_rejects_bad_shapes() {
        let create = validate_create_input(create_input()).expect("valid create input must pass");
        assert_eq!(create.profile(), "pan-commitment-v1");

        assert!(
            parse_create_input(json!({
                "ref": "row1",
                "profile": "pan-commitment-v1",
                "plaintext": "4111111111111111",
                "extra": true
            }))
            .is_err()
        );
        assert_eq!(
            err_string(validate_create_input(
                parse_create_input(json!({
                    "ref": "bad\nref",
                    "profile": "pan-commitment-v1",
                    "plaintext": "4111111111111111"
                }))
                .unwrap()
            )),
            "ref must not contain control characters"
        );
        assert_eq!(
            err_string(validate_create_input(
                parse_create_input(json!({
                    "ref": "row1",
                    "profile": "bad=profile",
                    "plaintext": "4111111111111111"
                }))
                .unwrap()
            )),
            "profile must not contain ';' or '='"
        );
        assert_eq!(
            err_string(validate_create_input(
                parse_create_input(json!({
                    "ref": "row1",
                    "profile": "pan-commitment-v1",
                    "plaintext": ""
                }))
                .unwrap()
            )),
            "plaintext must not be empty"
        );

        assert_eq!(
            err_string(validate_verify_input(
                parse_verify_input(json!({
                    "ref": "row1",
                "kid": "aa",
                    "profile": "pan-commitment-v1",
                    "plaintext": "4111111111111111",
                    "opening": "abcd",
                    "commitment": "00"
                }))
                .unwrap()
            )),
            "kid is invalid: id must be 64 hex characters for BLAKE2b(256), got 2"
        );
        assert_eq!(
            err_string(validate_verify_input(
                parse_verify_input(json!({
                    "ref": "row1",
                    "kid": KID,
                    "profile": "pan-commitment-v1",
                    "plaintext": "4111111111111111",
                    "opening": "abcd",
                "commitment": "zz"
                }))
                .unwrap()
            )),
            "commitment must contain only hexadecimal characters"
        );
    }

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
    fn validates_commit_verify_batch_input() {
        let opening = commitments::encode_opening(&[7u8; 32]);
        let input = parse_verify_batch_input(json!({
            "kid": KID,
            "profile": "pan-commitment-v1",
            "items": [
                {"ref": "row1", "plaintext": "4111111111111111", "opening": opening, "commitment": "00".repeat(32)}
            ]
        }))
        .and_then(validate_verify_batch_input)
        .expect("valid verify batch input must pass");

        assert_eq!(input.kid(), KID);
        assert_eq!(input.profile(), "pan-commitment-v1");
        assert_eq!(input.items.len(), 1);
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
    fn prepare_commit_operations_enforce_profile_lifecycle_and_bounds() {
        let profile = commitment_profile(KID);
        let input = validate_create_input(create_input()).unwrap();
        assert!(prepare_create(&keys_state("active"), KID, profile.clone(), input).is_ok());

        let input = validate_create_input(create_input()).unwrap();
        let err = prepare_create(&keys_state("active"), OTHER_KID, profile.clone(), input)
            .err()
            .expect("profile kid mismatch must fail");
        assert_eq!(
            err.to_string(),
            "commit profile is not authorized for this kid"
        );

        let input = validate_create_input(create_input()).unwrap();
        let err = prepare_create(&keys_state("retired"), KID, profile.clone(), input)
            .err()
            .expect("retired key cannot create commitments");
        assert_eq!(
            err.to_string(),
            "key is retired and can only be used for decrypt or verification"
        );

        let overlong_plaintext = "1".repeat(21);
        let input = validate_create_input(create_input_with_plaintext(&overlong_plaintext))
            .expect("overlong plaintext is still syntactically valid");
        let err = prepare_create(&keys_state("active"), KID, profile.clone(), input)
            .err()
            .expect("profile plaintext bound must be enforced");
        assert_eq!(
            err.to_string(),
            "plaintext exceeds commitment profile maximum length"
        );

        let bad_opening = commitments::encode_opening(&[7u8; 31]);
        let input = validate_verify_input(verify_input(
            "4111111111111111",
            &bad_opening,
            &"00".repeat(32),
        ))
        .unwrap();
        let err = prepare_verify(&keys_state("active"), profile, input)
            .err()
            .expect("wrong opening length must fail");
        assert_eq!(
            err.to_string(),
            "opening length does not match commitment profile"
        );
    }

    #[test]
    fn commit_create_and_verify_round_trip_and_detect_tampering() {
        let profile = commitment_profile(KID);
        let created = created_commitment(profile.clone());

        assert_eq!(created.kid, KID);
        assert_eq!(created.profile, "pan-commitment-v1");
        assert_eq!(created.algorithm, "KMAC-256");
        assert_eq!(created.commitment.len(), 64);
        assert!(commitments::validate_opening(&profile, &created.opening).is_ok());

        let input = validate_verify_input(verify_input(
            "4111111111111111",
            &created.opening,
            &created.commitment,
        ))
        .unwrap();
        let prepared = prepare_verify(&keys_state("retired"), profile.clone(), input)
            .expect("verify prepares");
        let verified = verify(prepared).expect("verify must run");
        assert!(verified.valid);

        let input = validate_verify_input(verify_input(
            "5555555555554444",
            &created.opening,
            &created.commitment,
        ))
        .unwrap();
        let prepared =
            prepare_verify(&keys_state("active"), profile.clone(), input).expect("verify prepares");
        assert!(!verify(prepared).unwrap().valid);

        let other_opening = commitments::encode_opening(&[9u8; 32]);
        let input = validate_verify_input(verify_input(
            "4111111111111111",
            &other_opening,
            &created.commitment,
        ))
        .unwrap();
        let prepared =
            prepare_verify(&keys_state("active"), profile.clone(), input).expect("verify prepares");
        assert!(!verify(prepared).unwrap().valid);

        let mut tampered_commitment = created.commitment.clone();
        let replacement = if tampered_commitment.starts_with("ff") {
            "00"
        } else {
            "ff"
        };
        tampered_commitment.replace_range(0..2, replacement);
        let input = validate_verify_input(verify_input(
            "4111111111111111",
            &created.opening,
            &tampered_commitment,
        ))
        .unwrap();
        let prepared =
            prepare_verify(&keys_state("active"), profile, input).expect("verify prepares");
        assert!(!verify(prepared).unwrap().valid);
    }

    #[test]
    fn commit_create_uses_fresh_openings_for_same_plaintext() {
        let profile = commitment_profile(KID);
        let first = created_commitment(profile.clone());
        let second = created_commitment(profile);

        assert_ne!(first.opening, second.opening);
        assert_ne!(first.commitment, second.commitment);
    }

    #[test]
    fn commit_batch_create_and_verify_preserve_order() {
        let profile = commitment_profile(KID);
        let input = parse_create_batch_input(json!({
            "profile": "pan-commitment-v1",
            "items": [
                {"ref": "row1", "plaintext": "4111111111111111"},
                {"ref": "row2", "plaintext": "5555555555554444"}
            ]
        }))
        .and_then(validate_create_batch_input)
        .unwrap();
        let prepared = prepare_create_batch(&keys_state("active"), KID, profile.clone(), input)
            .expect("create batch prepares");
        let created = create_batch(prepared).expect("batch must create");

        assert_eq!(created.items[0].ref_id, "row1");
        assert_eq!(created.items[1].ref_id, "row2");
        assert_ne!(created.items[0].commitment, created.items[1].commitment);

        let input = parse_verify_batch_input(json!({
            "kid": KID,
            "profile": "pan-commitment-v1",
            "items": [
                {
                    "ref": "row1",
                    "plaintext": "4111111111111111",
                    "opening": created.items[0].opening,
                    "commitment": created.items[0].commitment
                },
                {
                    "ref": "row2",
                    "plaintext": "0000000000000000",
                    "opening": created.items[1].opening,
                    "commitment": created.items[1].commitment
                }
            ]
        }))
        .and_then(validate_verify_batch_input)
        .unwrap();
        let prepared = prepare_verify_batch(&keys_state("active"), profile, input)
            .expect("verify batch prepares");
        let verified = verify_batch(prepared).expect("batch must verify");

        assert_eq!(verified.items[0].ref_id, "row1");
        assert!(verified.items[0].valid);
        assert_eq!(verified.items[1].ref_id, "row2");
        assert!(!verified.items[1].valid);
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

    #[test]
    fn parse_commit_input_preserves_unknown_field_detail() {
        let err = match parse_create_input(json!({
            "ref": "reg1",
            "profile": "pan-commitment-v1",
            "plaintext": "4111111111111111",
            "sorpresa": true
        })) {
            Ok(_) => panic!("unknown fields must fail"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("invalid commit request: unknown field")
        );
        assert!(err.to_string().contains("sorpresa"));
    }
}
