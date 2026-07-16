use crate::core::{fpe, sensitive::SensitiveString, validation};
use crate::error::DynError;
use crate::ops::keys::{self, KeysDbState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FpeEncryptInput {
    profile: String,
    plaintext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FpeDecryptInput {
    kid: String,
    profile: String,
    ciphertext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FpeEncryptBatchItemInput {
    plaintext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FpeEncryptBatchInput {
    profile: String,
    items: Vec<FpeEncryptBatchItemInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FpeDecryptBatchItemInput {
    ciphertext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FpeDecryptBatchInput {
    kid: String,
    profile: String,
    items: Vec<FpeDecryptBatchItemInput>,
}

#[derive(Serialize)]
pub struct FpeEncryptOutput {
    kid: String,
    profile: String,
    ciphertext: String,
}

#[derive(Serialize)]
pub struct FpeDecryptOutput {
    plaintext: SensitiveString,
}

#[derive(Serialize)]
pub struct FpeEncryptBatchOutputItem {
    ciphertext: String,
}

#[derive(Serialize)]
pub struct FpeEncryptBatchOutput {
    kid: String,
    profile: String,
    items: Vec<FpeEncryptBatchOutputItem>,
}

#[derive(Serialize)]
pub struct FpeDecryptBatchOutputItem {
    plaintext: SensitiveString,
}

#[derive(Serialize)]
pub struct FpeDecryptBatchOutput {
    kid: String,
    profile: String,
    items: Vec<FpeDecryptBatchOutputItem>,
}

impl FpeEncryptBatchOutput {
    pub fn items_len(&self) -> usize {
        self.items.len()
    }
}

impl FpeDecryptBatchOutput {
    pub fn items_len(&self) -> usize {
        self.items.len()
    }
}

pub struct ValidatedFpeEncryptInput {
    profile: String,
    plaintext: Zeroizing<String>,
}

pub struct ValidatedFpeDecryptInput {
    kid: String,
    profile: String,
    ciphertext: Zeroizing<String>,
}

pub struct ValidatedFpeEncryptBatchItem {
    plaintext: Zeroizing<String>,
}

pub struct ValidatedFpeEncryptBatchInput {
    profile: String,
    items: Vec<ValidatedFpeEncryptBatchItem>,
}

pub struct ValidatedFpeDecryptBatchItem {
    ciphertext: Zeroizing<String>,
}

pub struct ValidatedFpeDecryptBatchInput {
    kid: String,
    profile: String,
    items: Vec<ValidatedFpeDecryptBatchItem>,
}

pub struct PreparedFpeEncrypt {
    kid: String,
    profile: fpe::FpeProfile,
    input: ValidatedFpeEncryptInput,
}

pub struct PreparedFpeDecrypt {
    kid: String,
    profile: fpe::FpeProfile,
    input: ValidatedFpeDecryptInput,
}

pub struct PreparedFpeEncryptBatch {
    kid: String,
    profile: fpe::FpeProfile,
    input: ValidatedFpeEncryptBatchInput,
}

pub struct PreparedFpeDecryptBatch {
    kid: String,
    profile: fpe::FpeProfile,
    input: ValidatedFpeDecryptBatchInput,
}

impl ValidatedFpeEncryptInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedFpeDecryptInput {
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedFpeEncryptBatchInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedFpeDecryptBatchInput {
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }
}

pub fn parse_encrypt_input(request: Value) -> Result<FpeEncryptInput, DynError> {
    serde_json::from_value(request).map_err(|_| crate::error::invalid_input("invalid fpe request"))
}

pub fn parse_decrypt_input(request: Value) -> Result<FpeDecryptInput, DynError> {
    serde_json::from_value(request).map_err(|_| crate::error::invalid_input("invalid fpe request"))
}

pub fn parse_encrypt_batch_input(request: Value) -> Result<FpeEncryptBatchInput, DynError> {
    reject_oversized_batch_value(&request)?;
    serde_json::from_value(request).map_err(|_| crate::error::invalid_input("invalid fpe request"))
}

pub fn parse_decrypt_batch_input(request: Value) -> Result<FpeDecryptBatchInput, DynError> {
    reject_oversized_batch_value(&request)?;
    serde_json::from_value(request).map_err(|_| crate::error::invalid_input("invalid fpe request"))
}

pub fn validate_encrypt_input(
    input: FpeEncryptInput,
) -> Result<ValidatedFpeEncryptInput, DynError> {
    validation::validate_text_field("profile", &input.profile)?;
    validation::validate_text_field("plaintext", &input.plaintext)?;

    Ok(ValidatedFpeEncryptInput {
        profile: input.profile,
        plaintext: Zeroizing::new(input.plaintext),
    })
}

pub fn validate_decrypt_input(
    input: FpeDecryptInput,
) -> Result<ValidatedFpeDecryptInput, DynError> {
    keys::validate_key_id(&input.kid)?;
    validation::validate_text_field("profile", &input.profile)?;
    validation::validate_text_field("ciphertext", &input.ciphertext)?;

    Ok(ValidatedFpeDecryptInput {
        kid: input.kid,
        profile: input.profile,
        ciphertext: Zeroizing::new(input.ciphertext),
    })
}

pub fn validate_encrypt_batch_input(
    input: FpeEncryptBatchInput,
) -> Result<ValidatedFpeEncryptBatchInput, DynError> {
    validation::validate_text_field("profile", &input.profile)?;
    validate_batch_len(input.items.len())?;
    let mut items = Vec::with_capacity(input.items.len());
    for item in input.items {
        validation::validate_text_field("plaintext", &item.plaintext)?;
        items.push(ValidatedFpeEncryptBatchItem {
            plaintext: Zeroizing::new(item.plaintext),
        });
    }

    Ok(ValidatedFpeEncryptBatchInput {
        profile: input.profile,
        items,
    })
}

pub fn validate_decrypt_batch_input(
    input: FpeDecryptBatchInput,
) -> Result<ValidatedFpeDecryptBatchInput, DynError> {
    keys::validate_key_id(&input.kid)?;
    validation::validate_text_field("profile", &input.profile)?;
    validate_batch_len(input.items.len())?;
    let mut items = Vec::with_capacity(input.items.len());
    for item in input.items {
        validation::validate_text_field("ciphertext", &item.ciphertext)?;
        items.push(ValidatedFpeDecryptBatchItem {
            ciphertext: Zeroizing::new(item.ciphertext),
        });
    }

    Ok(ValidatedFpeDecryptBatchInput {
        kid: input.kid,
        profile: input.profile,
        items,
    })
}

fn reject_oversized_batch_value(request: &Value) -> Result<(), DynError> {
    if let Some(items) = request.get("items").and_then(Value::as_array)
        && items.len() > crate::core::config::INTERNAL_FPE_BATCH
    {
        return Err(oversized_batch_error());
    }

    Ok(())
}

fn validate_batch_len(len: usize) -> Result<(), DynError> {
    if len == 0 {
        return Err(crate::error::invalid_input(
            "fpe batch items must not be empty",
        ));
    }
    if len > crate::core::config::INTERNAL_FPE_BATCH {
        return Err(oversized_batch_error());
    }

    Ok(())
}

fn oversized_batch_error() -> DynError {
    crate::error::invalid_input(format!(
        "fpe batch items exceeds maximum allowed value: {}",
        crate::core::config::INTERNAL_FPE_BATCH
    ))
}

pub fn prepare_encrypt(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: fpe::FpeProfile,
    input: ValidatedFpeEncryptInput,
) -> Result<PreparedFpeEncrypt, DynError> {
    if profile.kid() != kid {
        return Err(crate::error::forbidden(
            "fpe profile is not authorized for this kid",
        ));
    }
    let key = keys::get_loaded_key(keys_db_state, kid)?;
    keys::require_lifecycle_for_new_use(&key)?;

    Ok(PreparedFpeEncrypt {
        kid: kid.to_string(),
        profile,
        input,
    })
}

pub fn prepare_decrypt(
    keys_db_state: &KeysDbState,
    profile: fpe::FpeProfile,
    input: ValidatedFpeDecryptInput,
) -> Result<PreparedFpeDecrypt, DynError> {
    if profile.kid() != input.kid {
        return Err(crate::error::forbidden(
            "fpe profile is not authorized for this kid",
        ));
    }
    let key = keys::get_loaded_key(keys_db_state, &input.kid)?;
    keys::require_lifecycle_for_decrypt_or_verify(&key)?;

    Ok(PreparedFpeDecrypt {
        kid: input.kid.clone(),
        profile,
        input,
    })
}

pub fn prepare_encrypt_batch(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: fpe::FpeProfile,
    input: ValidatedFpeEncryptBatchInput,
) -> Result<PreparedFpeEncryptBatch, DynError> {
    if profile.kid() != kid {
        return Err(crate::error::forbidden(
            "fpe profile is not authorized for this kid",
        ));
    }
    let key = keys::get_loaded_key(keys_db_state, kid)?;
    keys::require_lifecycle_for_new_use(&key)?;

    Ok(PreparedFpeEncryptBatch {
        kid: kid.to_string(),
        profile,
        input,
    })
}

pub fn prepare_decrypt_batch(
    keys_db_state: &KeysDbState,
    profile: fpe::FpeProfile,
    input: ValidatedFpeDecryptBatchInput,
) -> Result<PreparedFpeDecryptBatch, DynError> {
    if profile.kid() != input.kid {
        return Err(crate::error::forbidden(
            "fpe profile is not authorized for this kid",
        ));
    }
    let key = keys::get_loaded_key(keys_db_state, &input.kid)?;
    keys::require_lifecycle_for_decrypt_or_verify(&key)?;

    Ok(PreparedFpeDecryptBatch {
        kid: input.kid.clone(),
        profile,
        input,
    })
}

pub fn encrypt(prepared: PreparedFpeEncrypt) -> Result<FpeEncryptOutput, DynError> {
    let ciphertext = fpe::fpe_encrypt(&prepared.profile, &prepared.input.plaintext)?;
    info!(
        kid = %prepared.kid,
        profile = %prepared.profile.name(),
        plaintext_len = prepared.input.plaintext.chars().count(),
        "fpe encrypt completed"
    );

    Ok(FpeEncryptOutput {
        kid: prepared.kid,
        profile: prepared.profile.name().to_string(),
        ciphertext,
    })
}

pub fn decrypt(prepared: PreparedFpeDecrypt) -> Result<FpeDecryptOutput, DynError> {
    let plaintext = fpe::fpe_decrypt(&prepared.profile, &prepared.input.ciphertext)?;
    info!(
        kid = %prepared.kid,
        profile = %prepared.profile.name(),
        ciphertext_len = prepared.input.ciphertext.chars().count(),
        "fpe decrypt completed"
    );

    Ok(FpeDecryptOutput {
        plaintext: SensitiveString::from(plaintext),
    })
}

pub fn encrypt_batch(prepared: PreparedFpeEncryptBatch) -> Result<FpeEncryptBatchOutput, DynError> {
    let mut items = Vec::with_capacity(prepared.input.items.len());
    for (index, item) in prepared.input.items.iter().enumerate() {
        let ciphertext = fpe::fpe_encrypt(&prepared.profile, &item.plaintext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        items.push(FpeEncryptBatchOutputItem { ciphertext });
    }
    info!(
        kid = %prepared.kid,
        profile = %prepared.profile.name(),
        items_count = items.len(),
        "fpe encrypt batch completed"
    );

    Ok(FpeEncryptBatchOutput {
        kid: prepared.kid,
        profile: prepared.profile.name().to_string(),
        items,
    })
}

pub fn decrypt_batch(prepared: PreparedFpeDecryptBatch) -> Result<FpeDecryptBatchOutput, DynError> {
    let mut items = Vec::with_capacity(prepared.input.items.len());
    for (index, item) in prepared.input.items.iter().enumerate() {
        let plaintext = fpe::fpe_decrypt(&prepared.profile, &item.ciphertext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        items.push(FpeDecryptBatchOutputItem {
            plaintext: SensitiveString::from(plaintext),
        });
    }
    info!(
        kid = %prepared.kid,
        profile = %prepared.profile.name(),
        items_count = items.len(),
        "fpe decrypt batch completed"
    );

    Ok(FpeDecryptBatchOutput {
        kid: prepared.kid,
        profile: prepared.profile.name().to_string(),
        items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hex64(seed: char) -> String {
        String::from(seed).repeat(64)
    }

    #[test]
    fn validates_encrypt_batch_input() {
        let input = parse_encrypt_batch_input(json!({
            "profile": "patient-id-decimal-v1",
            "items": [{"plaintext": "123456"}, {"plaintext": "654321"}]
        }))
        .and_then(validate_encrypt_batch_input)
        .expect("valid batch input must pass");

        assert_eq!(input.profile(), "patient-id-decimal-v1");
        assert_eq!(input.items.len(), 2);
    }

    #[test]
    fn rejects_empty_batch() {
        let result = parse_encrypt_batch_input(json!({
            "profile": "patient-id-decimal-v1",
            "items": []
        }))
        .and_then(validate_encrypt_batch_input);
        let err = match result {
            Ok(_) => panic!("empty batch must fail"),
            Err(err) => err,
        };

        assert_eq!(err.to_string(), "fpe batch items must not be empty");
    }

    #[test]
    fn rejects_oversized_batch() {
        let items = (0..=crate::core::config::INTERNAL_FPE_BATCH)
            .map(|_| json!({"plaintext": "123456"}))
            .collect::<Vec<_>>();
        let result = parse_encrypt_batch_input(json!({
            "profile": "patient-id-decimal-v1",
            "items": items
        }))
        .and_then(validate_encrypt_batch_input);
        let err = match result {
            Ok(_) => panic!("oversized batch must fail"),
            Err(err) => err,
        };

        assert_eq!(
            err.to_string(),
            "fpe batch items exceeds maximum allowed value: 128"
        );
    }

    #[test]
    fn validates_decrypt_batch_input() {
        let kid = hex64('a');
        let input = parse_decrypt_batch_input(json!({
            "kid": kid,
            "profile": "patient-id-decimal-v1",
            "items": [{"ciphertext": "123456"}, {"ciphertext": "654321"}]
        }))
        .and_then(validate_decrypt_batch_input)
        .expect("valid decrypt batch input must pass");

        assert_eq!(input.kid(), hex64('a'));
        assert_eq!(input.profile(), "patient-id-decimal-v1");
        assert_eq!(input.items.len(), 2);
    }

    #[test]
    fn decrypt_output_serializes_plaintext() {
        let output = FpeDecryptOutput {
            plaintext: SensitiveString::from(String::from("123456")),
        };
        let serialized = serde_json::to_value(output).expect("decrypt output must serialize");

        assert_eq!(serialized, json!({"plaintext": "123456"}));
    }

    #[test]
    fn decrypt_batch_output_serializes_plaintext_items() {
        let output = FpeDecryptBatchOutput {
            kid: hex64('a'),
            profile: String::from("patient-id-decimal-v1"),
            items: vec![
                FpeDecryptBatchOutputItem {
                    plaintext: SensitiveString::from(String::from("123456")),
                },
                FpeDecryptBatchOutputItem {
                    plaintext: SensitiveString::from(String::from("654321")),
                },
            ],
        };
        let serialized = serde_json::to_value(output).expect("batch output must serialize");

        assert_eq!(
            serialized,
            json!({
                "kid": hex64('a'),
                "profile": "patient-id-decimal-v1",
                "items": [
                    {"plaintext": "123456"},
                    {"plaintext": "654321"}
                ]
            })
        );
    }
}
