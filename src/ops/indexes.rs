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
