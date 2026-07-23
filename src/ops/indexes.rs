use crate::core::{mac, storage::IndexRow, validation};
use crate::error::DynError;
use crate::ops::keys::{self, KeysDbState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexCreateInput {
    #[serde(rename = "ref")]
    ref_id: String,
    profile: String,
    plaintext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexVerifyInput {
    #[serde(rename = "ref")]
    ref_id: String,
    kid: String,
    profile: String,
    plaintext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexBatchItemInput {
    #[serde(rename = "ref")]
    ref_id: String,
    plaintext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexBatchInput {
    profile: String,
    items: Vec<IndexBatchItemInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexVerifyBatchInput {
    kid: String,
    profile: String,
    items: Vec<IndexBatchItemInput>,
}

#[derive(Serialize)]
pub struct IndexCreateOutput {
    #[serde(rename = "ref")]
    ref_id: String,
    kid: String,
    profile: String,
    #[serde(rename = "index")]
    digest: String,
}

#[derive(Serialize)]
pub struct IndexVerifyOutput {
    #[serde(rename = "ref")]
    ref_id: String,
    kid: String,
    profile: String,
    matched: bool,
    #[serde(rename = "index")]
    digest: String,
}

#[derive(Serialize)]
pub struct IndexCreateBatchOutputItem {
    #[serde(rename = "ref")]
    ref_id: String,
    #[serde(rename = "index")]
    digest: String,
}

#[derive(Serialize)]
pub struct IndexCreateBatchOutput {
    kid: String,
    profile: String,
    items: Vec<IndexCreateBatchOutputItem>,
}

#[derive(Serialize)]
pub struct IndexVerifyBatchOutputItem {
    #[serde(rename = "ref")]
    ref_id: String,
    matched: bool,
    #[serde(rename = "index")]
    digest: String,
}

#[derive(Serialize)]
pub struct IndexVerifyBatchOutput {
    kid: String,
    profile: String,
    items: Vec<IndexVerifyBatchOutputItem>,
}

pub struct IndexCreateResult {
    pub row: IndexRow,
    pub output: IndexCreateOutput,
}

pub struct IndexCreateBatchResult {
    pub rows: Vec<IndexRow>,
    pub output: IndexCreateBatchOutput,
}

pub struct ValidatedIndexCreateInput {
    ref_id: String,
    profile: String,
    plaintext: Zeroizing<String>,
}

pub struct ValidatedIndexVerifyInput {
    ref_id: String,
    kid: String,
    profile: String,
    plaintext: Zeroizing<String>,
}

pub struct ValidatedIndexBatchItem {
    ref_id: String,
    plaintext: Zeroizing<String>,
}

pub struct ValidatedIndexBatchInput {
    profile: String,
    items: Vec<ValidatedIndexBatchItem>,
}

pub struct ValidatedIndexVerifyBatchInput {
    kid: String,
    profile: String,
    items: Vec<ValidatedIndexBatchItem>,
}

pub struct PreparedIndexCreate {
    kid: String,
    profile: mac::MacProfile,
    input: ValidatedIndexCreateInput,
}

pub struct PreparedIndexVerify {
    kid: String,
    profile: mac::MacProfile,
    input: ValidatedIndexVerifyInput,
}

pub struct PreparedIndexCreateBatch {
    kid: String,
    profile: mac::MacProfile,
    input: ValidatedIndexBatchInput,
}

pub struct PreparedIndexVerifyBatch {
    kid: String,
    profile: mac::MacProfile,
    input: ValidatedIndexVerifyBatchInput,
}

impl ValidatedIndexCreateInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedIndexVerifyInput {
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedIndexBatchInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedIndexVerifyBatchInput {
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl IndexCreateBatchOutput {
    pub fn items_len(&self) -> usize {
        self.items.len()
    }
}

impl IndexVerifyBatchOutput {
    pub fn items_len(&self) -> usize {
        self.items.len()
    }
}

pub fn parse_create_input(request: Value) -> Result<IndexCreateInput, DynError> {
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid index request"))
}

pub fn parse_verify_input(request: Value) -> Result<IndexVerifyInput, DynError> {
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid index request"))
}

pub fn parse_batch_input(request: Value) -> Result<IndexBatchInput, DynError> {
    crate::ops::batch::reject_oversized_value(
        &request,
        crate::core::config::INTERNAL_INDEX_BATCH,
        "index",
    )?;
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid index request"))
}

pub fn parse_verify_batch_input(request: Value) -> Result<IndexVerifyBatchInput, DynError> {
    crate::ops::batch::reject_oversized_value(
        &request,
        crate::core::config::INTERNAL_INDEX_BATCH,
        "index",
    )?;
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid index request"))
}

pub fn validate_create_input(
    input: IndexCreateInput,
) -> Result<ValidatedIndexCreateInput, DynError> {
    let ref_id = validation::validate_ref(&input.ref_id)?;
    validation::validate_aad_config_name("profile", &input.profile)?;
    validation::validate_text_field("plaintext", &input.plaintext)?;

    Ok(ValidatedIndexCreateInput {
        ref_id,
        profile: input.profile,
        plaintext: Zeroizing::new(input.plaintext),
    })
}

pub fn validate_verify_input(
    input: IndexVerifyInput,
) -> Result<ValidatedIndexVerifyInput, DynError> {
    let ref_id = validation::validate_ref(&input.ref_id)?;
    keys::validate_key_id(&input.kid)
        .map_err(|err| crate::error::invalid_input(format!("kid is invalid: {err}")))?;
    validation::validate_aad_config_name("profile", &input.profile)?;
    validation::validate_text_field("plaintext", &input.plaintext)?;

    Ok(ValidatedIndexVerifyInput {
        ref_id,
        kid: input.kid,
        profile: input.profile,
        plaintext: Zeroizing::new(input.plaintext),
    })
}

pub fn validate_batch_input(input: IndexBatchInput) -> Result<ValidatedIndexBatchInput, DynError> {
    validation::validate_aad_config_name("profile", &input.profile)?;
    crate::ops::batch::validate_len(
        input.items.len(),
        crate::core::config::INTERNAL_INDEX_BATCH,
        "index",
    )?;
    let mut items = Vec::with_capacity(input.items.len());
    for (index, item) in input.items.into_iter().enumerate() {
        let ref_id = validation::validate_ref(&item.ref_id)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        validation::validate_text_field("plaintext", &item.plaintext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        items.push(ValidatedIndexBatchItem {
            ref_id,
            plaintext: Zeroizing::new(item.plaintext),
        });
    }
    crate::ops::batch::validate_unique_refs(
        items.iter().map(|item| item.ref_id.as_str()),
        "index",
    )?;

    Ok(ValidatedIndexBatchInput {
        profile: input.profile,
        items,
    })
}

pub fn validate_verify_batch_input(
    input: IndexVerifyBatchInput,
) -> Result<ValidatedIndexVerifyBatchInput, DynError> {
    keys::validate_key_id(&input.kid)
        .map_err(|err| crate::error::invalid_input(format!("kid is invalid: {err}")))?;
    validation::validate_aad_config_name("profile", &input.profile)?;
    crate::ops::batch::validate_len(
        input.items.len(),
        crate::core::config::INTERNAL_INDEX_BATCH,
        "index",
    )?;
    let mut items = Vec::with_capacity(input.items.len());
    for (index, item) in input.items.into_iter().enumerate() {
        let ref_id = validation::validate_ref(&item.ref_id)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        validation::validate_text_field("plaintext", &item.plaintext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        items.push(ValidatedIndexBatchItem {
            ref_id,
            plaintext: Zeroizing::new(item.plaintext),
        });
    }
    crate::ops::batch::validate_unique_refs(
        items.iter().map(|item| item.ref_id.as_str()),
        "index",
    )?;

    Ok(ValidatedIndexVerifyBatchInput {
        kid: input.kid,
        profile: input.profile,
        items,
    })
}

pub fn prepare_create(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: mac::MacProfile,
    input: ValidatedIndexCreateInput,
) -> Result<PreparedIndexCreate, DynError> {
    keys::prepare_profile_use(
        keys_db_state,
        kid,
        profile.kid(),
        "index",
        keys::ProfileUse::NewUse,
    )?;

    Ok(PreparedIndexCreate {
        kid: kid.to_string(),
        profile,
        input,
    })
}

pub fn prepare_verify(
    keys_db_state: &KeysDbState,
    profile: mac::MacProfile,
    input: ValidatedIndexVerifyInput,
) -> Result<PreparedIndexVerify, DynError> {
    keys::prepare_profile_use(
        keys_db_state,
        input.kid(),
        profile.kid(),
        "index",
        keys::ProfileUse::Verify,
    )?;

    Ok(PreparedIndexVerify {
        kid: input.kid.clone(),
        profile,
        input,
    })
}

pub fn prepare_create_batch(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: mac::MacProfile,
    input: ValidatedIndexBatchInput,
) -> Result<PreparedIndexCreateBatch, DynError> {
    keys::prepare_profile_use(
        keys_db_state,
        kid,
        profile.kid(),
        "index",
        keys::ProfileUse::NewUse,
    )?;

    Ok(PreparedIndexCreateBatch {
        kid: kid.to_string(),
        profile,
        input,
    })
}

pub fn prepare_verify_batch(
    keys_db_state: &KeysDbState,
    profile: mac::MacProfile,
    input: ValidatedIndexVerifyBatchInput,
) -> Result<PreparedIndexVerifyBatch, DynError> {
    keys::prepare_profile_use(
        keys_db_state,
        input.kid(),
        profile.kid(),
        "index",
        keys::ProfileUse::Verify,
    )?;

    Ok(PreparedIndexVerifyBatch {
        kid: input.kid.clone(),
        profile,
        input,
    })
}

pub fn create(prepared: PreparedIndexCreate) -> Result<IndexCreateResult, DynError> {
    let digest = hex::encode(crate::ops::mac::compute_digest(
        &prepared.profile,
        &prepared.input.plaintext,
    )?);
    let row = IndexRow {
        kid: prepared.kid.clone(),
        digest: digest.clone(),
    };
    let output = IndexCreateOutput {
        ref_id: prepared.input.ref_id,
        kid: prepared.kid,
        profile: prepared.input.profile,
        digest,
    };

    Ok(IndexCreateResult { row, output })
}

pub fn create_batch(
    prepared: PreparedIndexCreateBatch,
) -> Result<IndexCreateBatchResult, DynError> {
    let mut rows = Vec::with_capacity(prepared.input.items.len());
    let mut items = Vec::with_capacity(prepared.input.items.len());
    for (index, item) in prepared.input.items.iter().enumerate() {
        let digest = hex::encode(
            crate::ops::mac::compute_digest(&prepared.profile, &item.plaintext).map_err(|err| {
                crate::error::with_prefix(&format!("batch item {index} failed"), err)
            })?,
        );
        rows.push(IndexRow {
            kid: prepared.kid.clone(),
            digest: digest.clone(),
        });
        items.push(IndexCreateBatchOutputItem {
            ref_id: item.ref_id.clone(),
            digest,
        });
    }

    Ok(IndexCreateBatchResult {
        rows,
        output: IndexCreateBatchOutput {
            kid: prepared.kid,
            profile: prepared.input.profile,
            items,
        },
    })
}

pub fn verify(prepared: PreparedIndexVerify, digest: String, matched: bool) -> IndexVerifyOutput {
    IndexVerifyOutput {
        ref_id: prepared.input.ref_id,
        kid: prepared.kid,
        profile: prepared.input.profile,
        matched,
        digest,
    }
}

pub fn verify_batch(
    prepared: PreparedIndexVerifyBatch,
    digests: Vec<String>,
    matches: Vec<bool>,
) -> Result<IndexVerifyBatchOutput, DynError> {
    if digests.len() != prepared.input.items.len() || matches.len() != prepared.input.items.len() {
        return Err(crate::error::internal("index batch match count is invalid"));
    }
    let mut items = Vec::with_capacity(prepared.input.items.len());
    for (index, item) in prepared.input.items.iter().enumerate() {
        items.push(IndexVerifyBatchOutputItem {
            ref_id: item.ref_id.clone(),
            matched: matches[index],
            digest: digests[index].clone(),
        });
    }

    Ok(IndexVerifyBatchOutput {
        kid: prepared.kid,
        profile: prepared.input.profile,
        items,
    })
}

pub fn digest(prepared: &PreparedIndexVerify) -> Result<String, DynError> {
    Ok(hex::encode(crate::ops::mac::compute_digest(
        &prepared.profile,
        &prepared.input.plaintext,
    )?))
}

pub fn batch_digests(prepared: &PreparedIndexVerifyBatch) -> Result<Vec<String>, DynError> {
    prepared
        .input
        .items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            crate::ops::mac::compute_digest(&prepared.profile, &item.plaintext)
                .map(hex::encode)
                .map_err(|err| {
                    crate::error::with_prefix(&format!("batch item {index} failed"), err)
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_KID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn mac_profile(kid: &str) -> mac::MacProfile {
        let input = serde_json::from_value(json!({
            "name": "pan-index-v1",
            "kid": kid,
            "context": "tenant=mx;field=pan;purpose=index;version=1"
        }))
        .expect("mac profile input must deserialize");
        mac::validate_mac_profiles(
            vec![input],
            |_| true,
            |_| Ok(String::from("SHA-3(256)")),
            |request| mac::derive_mac_key_for_profile(&"11".repeat(32), request),
        )
        .expect("mac profile must validate")
        .get("pan-index-v1")
        .expect("profile must exist")
        .clone()
    }

    fn create_input() -> IndexCreateInput {
        parse_create_input(json!({
            "ref": "row1",
            "profile": "pan-index-v1",
            "plaintext": "4111111111111111"
        }))
        .expect("index create input must parse")
    }

    fn verify_input() -> IndexVerifyInput {
        parse_verify_input(json!({
            "ref": "row1",
            "kid": KID,
            "profile": "pan-index-v1",
            "plaintext": "4111111111111111"
        }))
        .expect("index verify input must parse")
    }

    fn keys_state(status: &str) -> KeysDbState {
        keys::test_keys_state_with_lifecycle(KID, status)
    }

    fn err_string<T>(result: Result<T, DynError>) -> String {
        result.err().expect("operation must fail").to_string()
    }

    #[test]
    fn validates_single_index_inputs_and_rejects_bad_shapes() {
        let create = validate_create_input(create_input()).expect("valid create input must pass");
        assert_eq!(create.profile(), "pan-index-v1");

        let verify = validate_verify_input(verify_input()).expect("valid verify input must pass");
        assert_eq!(verify.profile(), "pan-index-v1");
        assert_eq!(verify.kid(), KID);

        assert!(
            parse_create_input(json!({
                "ref": "row1",
                "profile": "pan-index-v1",
                "plaintext": "4111111111111111",
                "extra": true
            }))
            .is_err()
        );
        assert_eq!(
            err_string(validate_create_input(
                parse_create_input(json!({
                    "ref": "bad\nref",
                    "profile": "pan-index-v1",
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
            err_string(validate_verify_input(
                parse_verify_input(json!({
                    "ref": "row1",
                "kid": "aa",
                    "profile": "pan-index-v1",
                    "plaintext": "4111111111111111"
                }))
                .unwrap()
            )),
            "kid is invalid: id must be 64 hex characters for BLAKE2b(256), got 2"
        );
        assert_eq!(
            err_string(validate_create_input(
                parse_create_input(json!({
                    "ref": "row1",
                    "profile": "pan-index-v1",
                    "plaintext": ""
                }))
                .unwrap()
            )),
            "plaintext must not be empty"
        );
    }

    #[test]
    fn validates_index_batch_input() {
        let input = parse_batch_input(json!({
            "profile": "pan-index-v1",
            "items": [
                {"ref": "row1", "plaintext": "4111111111111111"},
                {"ref": "row2", "plaintext": "5555555555554444"}
            ]
        }))
        .and_then(validate_batch_input)
        .expect("valid index batch input must pass");

        assert_eq!(input.profile(), "pan-index-v1");
        assert_eq!(input.items.len(), 2);
    }

    #[test]
    fn validates_index_verify_batch_input() {
        let input = parse_verify_batch_input(json!({
            "kid": KID,
            "profile": "pan-index-v1",
            "items": [
                {"ref": "row1", "plaintext": "4111111111111111"},
                {"ref": "row2", "plaintext": "5555555555554444"}
            ]
        }))
        .and_then(validate_verify_batch_input)
        .expect("valid verify batch input must pass");

        assert_eq!(input.kid(), KID);
        assert_eq!(input.profile(), "pan-index-v1");
        assert_eq!(input.items.len(), 2);
    }

    #[test]
    fn rejects_empty_and_duplicate_refs() {
        let empty = match parse_batch_input(json!({
            "profile": "pan-index-v1",
            "items": []
        }))
        .and_then(validate_batch_input)
        {
            Ok(_) => panic!("empty batch must fail"),
            Err(err) => err,
        };
        assert_eq!(empty.to_string(), "index batch items must not be empty");

        let duplicate = match parse_batch_input(json!({
            "profile": "pan-index-v1",
            "items": [
                {"ref": "row1", "plaintext": "4111111111111111"},
                {"ref": "row1", "plaintext": "5555555555554444"}
            ]
        }))
        .and_then(validate_batch_input)
        {
            Ok(_) => panic!("duplicate refs must fail"),
            Err(err) => err,
        };
        assert_eq!(
            duplicate.to_string(),
            "batch item 1 failed: index batch ref must be unique"
        );
    }

    #[test]
    fn prepare_index_operations_enforce_lifecycle_and_profile_kid() {
        let profile = mac_profile(KID);
        let create = validate_create_input(create_input()).unwrap();
        assert!(prepare_create(&keys_state("active"), KID, profile.clone(), create).is_ok());

        let create = validate_create_input(create_input()).unwrap();
        let err = prepare_create(&keys_state("active"), OTHER_KID, profile.clone(), create)
            .err()
            .expect("profile kid mismatch must fail");
        assert_eq!(
            err.to_string(),
            "index profile is not authorized for this kid"
        );

        let create = validate_create_input(create_input()).unwrap();
        let err = prepare_create(&keys_state("retired"), KID, profile.clone(), create)
            .err()
            .expect("retired key cannot create indexes");
        assert_eq!(
            err.to_string(),
            "key is retired and can only be used for decrypt or verification"
        );

        let verify = validate_verify_input(verify_input()).unwrap();
        assert!(prepare_verify(&keys_state("retired"), profile.clone(), verify).is_ok());

        let verify = validate_verify_input(verify_input()).unwrap();
        let err = prepare_verify(&keys_state("destroyed"), profile, verify)
            .err()
            .expect("destroyed key cannot verify indexes");
        assert_eq!(
            err.to_string(),
            "key is logically destroyed and cannot be used"
        );
    }

    #[test]
    fn index_create_digest_and_verify_outputs_are_stable() {
        let profile = mac_profile(KID);
        let create_input = validate_create_input(create_input()).unwrap();
        let prepared = prepare_create(&keys_state("active"), KID, profile.clone(), create_input)
            .expect("create must prepare");
        let result = create(prepared).expect("index must create");

        assert_eq!(result.row.kid, KID);
        assert_eq!(result.row.digest.len(), 64);
        assert_eq!(result.output.digest, result.row.digest);

        let verify_input = validate_verify_input(verify_input()).unwrap();
        let prepared = prepare_verify(&keys_state("active"), profile, verify_input)
            .expect("verify must prepare");
        let digest = digest(&prepared).expect("digest must compute");
        assert_eq!(digest, result.row.digest);

        let output = verify(prepared, digest.clone(), true);
        assert_eq!(output.kid, KID);
        assert_eq!(output.profile, "pan-index-v1");
        assert!(output.matched);
        assert_eq!(output.digest, digest);
    }

    #[test]
    fn index_batch_create_and_verify_preserve_order() {
        let profile = mac_profile(KID);
        let input = parse_batch_input(json!({
            "profile": "pan-index-v1",
            "items": [
                {"ref": "row1", "plaintext": "4111111111111111"},
                {"ref": "row2", "plaintext": "5555555555554444"}
            ]
        }))
        .and_then(validate_batch_input)
        .unwrap();
        let prepared = prepare_create_batch(&keys_state("active"), KID, profile.clone(), input)
            .expect("create batch must prepare");
        let result = create_batch(prepared).expect("batch must create");

        assert_eq!(result.rows.len(), 2);
        assert_eq!(result.output.items[0].ref_id, "row1");
        assert_eq!(result.output.items[1].ref_id, "row2");
        assert_ne!(result.output.items[0].digest, result.output.items[1].digest);

        let input = parse_verify_batch_input(json!({
            "kid": KID,
            "profile": "pan-index-v1",
            "items": [
                {"ref": "row1", "plaintext": "4111111111111111"},
                {"ref": "row2", "plaintext": "5555555555554444"}
            ]
        }))
        .and_then(validate_verify_batch_input)
        .unwrap();
        let prepared = prepare_verify_batch(&keys_state("retired"), profile, input)
            .expect("verify batch must prepare");
        let digests = batch_digests(&prepared).expect("batch digests must compute");
        assert_eq!(
            digests,
            result
                .rows
                .iter()
                .map(|row| row.digest.clone())
                .collect::<Vec<_>>()
        );

        let output = verify_batch(prepared, digests, vec![true, false]).unwrap();
        assert_eq!(output.items[0].ref_id, "row1");
        assert!(output.items[0].matched);
        assert_eq!(output.items[1].ref_id, "row2");
        assert!(!output.items[1].matched);
    }

    #[test]
    fn index_verify_batch_rejects_mismatched_result_lengths() {
        let profile = mac_profile(KID);
        let input = parse_verify_batch_input(json!({
            "kid": KID,
            "profile": "pan-index-v1",
            "items": [{"ref": "row1", "plaintext": "4111111111111111"}]
        }))
        .and_then(validate_verify_batch_input)
        .unwrap();
        let prepared =
            prepare_verify_batch(&keys_state("active"), profile, input).expect("must prepare");

        let err = verify_batch(prepared, Vec::new(), vec![true])
            .err()
            .expect("mismatched digest count must fail");
        assert_eq!(err.to_string(), "index batch match count is invalid");
    }

    #[test]
    fn index_outputs_serialize_public_index_field() {
        let output = IndexCreateOutput {
            ref_id: String::from("reg1"),
            kid: String::from("kid"),
            profile: String::from("pan-index-v1"),
            digest: String::from("abcd"),
        };
        let value = serde_json::to_value(output).expect("output must serialize");
        assert_eq!(
            value,
            json!({"ref": "reg1", "kid": "kid", "profile": "pan-index-v1", "index": "abcd"})
        );
    }
}
