use crate::core::{sensitive::SensitiveString, tokenization, validation};
use crate::error::DynError;
use crate::ops::keys::{self, KeysDbState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenEncodeInput {
    profile: String,
    plaintext: String,
    #[serde(default)]
    metadata: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenDecodeInput {
    kid: String,
    profile: String,
    token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenEncodeBatchItemInput {
    plaintext: String,
    #[serde(default)]
    metadata: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenEncodeBatchInput {
    profile: String,
    items: Vec<TokenEncodeBatchItemInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenDecodeBatchItemInput {
    token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenDecodeBatchInput {
    kid: String,
    profile: String,
    items: Vec<TokenDecodeBatchItemInput>,
}

#[derive(Serialize)]
pub struct TokenEncodeOutput {
    kid: String,
    profile: String,
    token: String,
}

#[derive(Serialize)]
pub struct TokenDecodeOutput {
    plaintext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
}

#[derive(Serialize)]
pub struct TokenEncodeBatchOutputItem {
    token: String,
}

#[derive(Serialize)]
pub struct TokenEncodeBatchOutput {
    kid: String,
    profile: String,
    items: Vec<TokenEncodeBatchOutputItem>,
}

#[derive(Serialize)]
pub struct TokenDecodeBatchOutputItem {
    plaintext: SensitiveString,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
}

#[derive(Serialize)]
pub struct TokenDecodeBatchOutput {
    kid: String,
    profile: String,
    items: Vec<TokenDecodeBatchOutputItem>,
}

pub struct ValidatedTokenEncodeInput {
    profile: String,
    plaintext: Zeroizing<String>,
    metadata: Option<Value>,
}

pub struct ValidatedTokenDecodeInput {
    kid: String,
    profile: String,
    token: Zeroizing<String>,
}

pub struct ValidatedTokenEncodeBatchItem {
    plaintext: Zeroizing<String>,
    metadata: Option<Value>,
}

pub struct ValidatedTokenEncodeBatchInput {
    profile: String,
    items: Vec<ValidatedTokenEncodeBatchItem>,
}

pub struct ValidatedTokenDecodeBatchItem {
    token: Zeroizing<String>,
}

pub struct ValidatedTokenDecodeBatchInput {
    kid: String,
    profile: String,
    items: Vec<ValidatedTokenDecodeBatchItem>,
}

pub struct PreparedTokenEncode {
    kid: String,
    profile: tokenization::TokenizationProfile,
    input: ValidatedTokenEncodeInput,
}

pub struct PreparedTokenDecode {
    kid: String,
    profile: tokenization::TokenizationProfile,
    input: ValidatedTokenDecodeInput,
    data: String,
}

pub struct PreparedTokenEncodeBatch {
    kid: String,
    profile: tokenization::TokenizationProfile,
    input: ValidatedTokenEncodeBatchInput,
}

pub struct PreparedTokenDecodeBatchItem {
    hashid: String,
    data: String,
}

pub struct PreparedTokenDecodeBatch {
    kid: String,
    profile: tokenization::TokenizationProfile,
    items: Vec<PreparedTokenDecodeBatchItem>,
}

pub struct EncodedTokenRecord {
    pub kid: String,
    pub hashid: String,
    pub data: String,
    pub output: TokenEncodeOutput,
}

pub struct EncodedTokenBatchRecord {
    pub kid: String,
    pub hashid: String,
    pub data: String,
}

pub struct EncodedTokenBatch {
    pub records: Vec<EncodedTokenBatchRecord>,
    pub output: TokenEncodeBatchOutput,
}

impl ValidatedTokenEncodeInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedTokenDecodeInput {
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn token(&self) -> &str {
        &self.token
    }
}

impl ValidatedTokenEncodeBatchInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedTokenDecodeBatchInput {
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn tokens(&self) -> impl Iterator<Item = &str> {
        self.items.iter().map(|item| item.token.as_str())
    }
}

impl TokenEncodeBatchOutput {
    pub fn items_len(&self) -> usize {
        self.items.len()
    }
}

impl TokenDecodeBatchOutput {
    pub fn items_len(&self) -> usize {
        self.items.len()
    }
}

pub fn parse_encode_input(request: Value) -> Result<TokenEncodeInput, DynError> {
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid token encode request"))
}

pub fn parse_decode_input(request: Value) -> Result<TokenDecodeInput, DynError> {
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid token decode request"))
}

pub fn parse_encode_batch_input(request: Value) -> Result<TokenEncodeBatchInput, DynError> {
    crate::ops::batch::reject_oversized_value(
        &request,
        crate::core::config::INTERNAL_TOKEN_BATCH,
        "token",
    )?;
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid token encode request"))
}

pub fn parse_decode_batch_input(request: Value) -> Result<TokenDecodeBatchInput, DynError> {
    crate::ops::batch::reject_oversized_value(
        &request,
        crate::core::config::INTERNAL_TOKEN_BATCH,
        "token",
    )?;
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid token decode request"))
}

pub fn validate_encode_input(
    input: TokenEncodeInput,
) -> Result<ValidatedTokenEncodeInput, DynError> {
    validation::validate_text_field("profile", &input.profile)?;
    validation::validate_text_field("plaintext", &input.plaintext)?;
    if let Some(metadata) = &input.metadata {
        validate_metadata(metadata)?;
    }

    Ok(ValidatedTokenEncodeInput {
        profile: input.profile,
        plaintext: Zeroizing::new(input.plaintext),
        metadata: input.metadata,
    })
}

pub fn validate_decode_input(
    input: TokenDecodeInput,
) -> Result<ValidatedTokenDecodeInput, DynError> {
    keys::validate_key_id(&input.kid)?;
    validation::validate_text_field("profile", &input.profile)?;
    validation::validate_text_field("token", &input.token)?;

    Ok(ValidatedTokenDecodeInput {
        kid: input.kid,
        profile: input.profile,
        token: Zeroizing::new(input.token),
    })
}

pub fn validate_encode_batch_input(
    input: TokenEncodeBatchInput,
) -> Result<ValidatedTokenEncodeBatchInput, DynError> {
    validation::validate_text_field("profile", &input.profile)?;
    crate::ops::batch::validate_len(
        input.items.len(),
        crate::core::config::INTERNAL_TOKEN_BATCH,
        "token",
    )?;
    let mut items = Vec::with_capacity(input.items.len());
    for (index, item) in input.items.into_iter().enumerate() {
        validation::validate_text_field("plaintext", &item.plaintext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        if let Some(metadata) = &item.metadata {
            validate_metadata(metadata).map_err(|err| {
                crate::error::with_prefix(&format!("batch item {index} failed"), err)
            })?;
        }
        items.push(ValidatedTokenEncodeBatchItem {
            plaintext: Zeroizing::new(item.plaintext),
            metadata: item.metadata,
        });
    }

    Ok(ValidatedTokenEncodeBatchInput {
        profile: input.profile,
        items,
    })
}

pub fn validate_decode_batch_input(
    input: TokenDecodeBatchInput,
) -> Result<ValidatedTokenDecodeBatchInput, DynError> {
    keys::validate_key_id(&input.kid)?;
    validation::validate_text_field("profile", &input.profile)?;
    crate::ops::batch::validate_len(
        input.items.len(),
        crate::core::config::INTERNAL_TOKEN_BATCH,
        "token",
    )?;
    let mut items = Vec::with_capacity(input.items.len());
    for (index, item) in input.items.into_iter().enumerate() {
        validation::validate_text_field("token", &item.token)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        items.push(ValidatedTokenDecodeBatchItem {
            token: Zeroizing::new(item.token),
        });
    }

    Ok(ValidatedTokenDecodeBatchInput {
        kid: input.kid,
        profile: input.profile,
        items,
    })
}

pub fn prepare_encode(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: tokenization::TokenizationProfile,
    input: ValidatedTokenEncodeInput,
) -> Result<PreparedTokenEncode, DynError> {
    if profile.kid() != kid {
        return Err(crate::error::forbidden(
            "tokenization profile is not authorized for this kid",
        ));
    }
    if input.plaintext.chars().count() > profile.max_plaintext_len() {
        return Err(crate::error::invalid_input(
            "plaintext length exceeds tokenization profile maximum",
        ));
    }
    let key = keys::get_loaded_key(keys_db_state, kid)?;
    keys::require_lifecycle_for_new_use(&key)?;

    Ok(PreparedTokenEncode {
        kid: kid.to_string(),
        profile,
        input,
    })
}

pub fn prepare_encode_batch(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: tokenization::TokenizationProfile,
    input: ValidatedTokenEncodeBatchInput,
) -> Result<PreparedTokenEncodeBatch, DynError> {
    if profile.kid() != kid {
        return Err(crate::error::forbidden(
            "tokenization profile is not authorized for this kid",
        ));
    }
    for (index, item) in input.items.iter().enumerate() {
        if item.plaintext.chars().count() > profile.max_plaintext_len() {
            return Err(crate::error::invalid_input(format!(
                "batch item {index} failed: plaintext length exceeds tokenization profile maximum"
            )));
        }
    }
    let key = keys::get_loaded_key(keys_db_state, kid)?;
    keys::require_lifecycle_for_new_use(&key)?;

    Ok(PreparedTokenEncodeBatch {
        kid: kid.to_string(),
        profile,
        input,
    })
}

pub fn prepare_decode(
    keys_db_state: &KeysDbState,
    profile: tokenization::TokenizationProfile,
    input: ValidatedTokenDecodeInput,
    data: String,
) -> Result<PreparedTokenDecode, DynError> {
    if profile.kid() != input.kid {
        return Err(crate::error::forbidden(
            "tokenization profile is not authorized for this kid",
        ));
    }
    let key = keys::get_loaded_key(keys_db_state, &input.kid)?;
    keys::require_lifecycle_for_decrypt_or_verify(&key)?;

    Ok(PreparedTokenDecode {
        kid: input.kid.clone(),
        profile,
        input,
        data,
    })
}

pub fn authorize_decode_batch(
    keys_db_state: &KeysDbState,
    profile: &tokenization::TokenizationProfile,
    kid: &str,
) -> Result<(), DynError> {
    if profile.kid() != kid {
        return Err(crate::error::forbidden(
            "tokenization profile is not authorized for this kid",
        ));
    }
    let key = keys::get_loaded_key(keys_db_state, kid)?;
    keys::require_lifecycle_for_decrypt_or_verify(&key)?;

    Ok(())
}

pub fn prepare_decode_batch(
    profile: tokenization::TokenizationProfile,
    kid: String,
    hashids: Vec<String>,
    rows: Vec<String>,
) -> Result<PreparedTokenDecodeBatch, DynError> {
    if rows.len() != hashids.len() {
        return Err(crate::error::internal(
            "token decode batch row count does not match hashid count",
        ));
    }
    let items = hashids
        .into_iter()
        .zip(rows)
        .map(|(hashid, data)| PreparedTokenDecodeBatchItem { hashid, data })
        .collect();

    Ok(PreparedTokenDecodeBatch {
        kid,
        profile,
        items,
    })
}

pub fn encode(prepared: PreparedTokenEncode) -> Result<EncodedTokenRecord, DynError> {
    let token = Zeroizing::new(tokenization::generate_token(&prepared.profile)?);
    let hashid = tokenization::hash_token(&prepared.profile, &token)?;
    let payload = tokenization::TokenDataPayload {
        profile: prepared.profile.name().to_string(),
        plaintext: (*prepared.input.plaintext).clone(),
        metadata: prepared.input.metadata,
        created_at: validation::current_timestamp()?,
    };
    let data = tokenization::encrypt_token_data(&prepared.profile, &hashid, &payload)?;
    info!(
        kid = %prepared.kid,
        profile = %prepared.profile.name(),
        plaintext_len = prepared.input.plaintext.chars().count(),
        "token encode completed"
    );

    Ok(EncodedTokenRecord {
        kid: prepared.kid.clone(),
        hashid,
        data,
        output: TokenEncodeOutput {
            kid: prepared.kid,
            profile: prepared.profile.name().to_string(),
            token: (*token).clone(),
        },
    })
}

pub fn encode_batch(prepared: PreparedTokenEncodeBatch) -> Result<EncodedTokenBatch, DynError> {
    let mut records = Vec::with_capacity(prepared.input.items.len());
    let mut items = Vec::with_capacity(prepared.input.items.len());
    for (index, item) in prepared.input.items.into_iter().enumerate() {
        let token = Zeroizing::new(tokenization::generate_token(&prepared.profile).map_err(
            |err| crate::error::with_prefix(&format!("batch item {index} failed"), err),
        )?);
        let hashid = tokenization::hash_token(&prepared.profile, &token)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        let payload = tokenization::TokenDataPayload {
            profile: prepared.profile.name().to_string(),
            plaintext: (*item.plaintext).clone(),
            metadata: item.metadata,
            created_at: validation::current_timestamp().map_err(|err| {
                crate::error::with_prefix(&format!("batch item {index} failed"), err)
            })?,
        };
        let data = tokenization::encrypt_token_data(&prepared.profile, &hashid, &payload)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        records.push(EncodedTokenBatchRecord {
            kid: prepared.kid.clone(),
            hashid,
            data,
        });
        items.push(TokenEncodeBatchOutputItem {
            token: (*token).clone(),
        });
    }
    info!(
        kid = %prepared.kid,
        profile = %prepared.profile.name(),
        items_count = items.len(),
        "token encode batch completed"
    );

    Ok(EncodedTokenBatch {
        records,
        output: TokenEncodeBatchOutput {
            kid: prepared.kid,
            profile: prepared.profile.name().to_string(),
            items,
        },
    })
}

pub fn decode(prepared: PreparedTokenDecode) -> Result<TokenDecodeOutput, DynError> {
    let hashid = tokenization::hash_token(&prepared.profile, prepared.input.token())?;
    let payload = tokenization::decrypt_token_data(&prepared.profile, &hashid, &prepared.data)?;
    info!(
        kid = %prepared.kid,
        profile = %prepared.profile.name(),
        token_len = prepared.input.token.chars().count(),
        "token decode completed"
    );

    Ok(TokenDecodeOutput {
        plaintext: payload.plaintext,
        metadata: payload.metadata,
    })
}

pub fn decode_batch(
    prepared: PreparedTokenDecodeBatch,
) -> Result<TokenDecodeBatchOutput, DynError> {
    let mut items = Vec::with_capacity(prepared.items.len());
    for (index, item) in prepared.items.into_iter().enumerate() {
        let payload = tokenization::decrypt_token_data(&prepared.profile, &item.hashid, &item.data)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        items.push(TokenDecodeBatchOutputItem {
            plaintext: SensitiveString::from(payload.plaintext),
            metadata: payload.metadata,
        });
    }
    info!(
        kid = %prepared.kid,
        profile = %prepared.profile.name(),
        items_count = items.len(),
        "token decode batch completed"
    );

    Ok(TokenDecodeBatchOutput {
        kid: prepared.kid,
        profile: prepared.profile.name().to_string(),
        items,
    })
}

fn validate_metadata(metadata: &Value) -> Result<(), DynError> {
    if !metadata.is_object() {
        return Err(crate::error::invalid_input(
            "metadata must be a JSON object when present",
        ));
    }
    let serialized = serde_json::to_string(metadata)?;
    if serialized.chars().count() > tokenization::TOKEN_METADATA_MAX_CHARS {
        return Err(crate::error::invalid_input(
            "metadata exceeds tokenization maximum length",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn encode_input(metadata: Option<Value>) -> TokenEncodeInput {
        TokenEncodeInput {
            profile: String::from("patient-id-token-v1"),
            plaintext: String::from("123456"),
            metadata,
        }
    }

    fn metadata_with_serialized_len(target: usize) -> Value {
        for len in 0..=target {
            let metadata = json!({"a": "x".repeat(len)});
            if serde_json::to_string(&metadata).unwrap().chars().count() == target {
                return metadata;
            }
        }
        panic!("could not build metadata with serialized len {target}");
    }

    fn validation_error(input: TokenEncodeInput) -> String {
        match validate_encode_input(input) {
            Ok(_) => panic!("metadata validation unexpectedly passed"),
            Err(err) => err.to_string(),
        }
    }

    fn encode_batch_validation_error(input: Value) -> String {
        match parse_encode_batch_input(input).and_then(validate_encode_batch_input) {
            Ok(_) => panic!("token batch validation unexpectedly passed"),
            Err(err) => err.to_string(),
        }
    }

    #[test]
    fn token_encode_metadata_absent_or_small_object_is_valid() {
        validate_encode_input(encode_input(None)).expect("metadata is optional");
        validate_encode_input(encode_input(Some(json!({"tenant": "acme"}))))
            .expect("small metadata object must validate");
    }

    #[test]
    fn token_encode_metadata_must_be_object() {
        assert_eq!(
            validation_error(encode_input(Some(json!(["not-object"])))),
            "metadata must be a JSON object when present"
        );
    }

    #[test]
    fn token_encode_metadata_accepts_exact_limit() {
        let metadata = metadata_with_serialized_len(tokenization::TOKEN_METADATA_MAX_CHARS);
        validate_encode_input(encode_input(Some(metadata))).expect("exact metadata limit passes");
    }

    #[test]
    fn token_encode_metadata_rejects_over_limit() {
        let metadata = metadata_with_serialized_len(tokenization::TOKEN_METADATA_MAX_CHARS + 1);

        assert_eq!(
            validation_error(encode_input(Some(metadata))),
            "metadata exceeds tokenization maximum length"
        );
    }

    #[test]
    fn validates_encode_batch_input() {
        let input = parse_encode_batch_input(json!({
            "profile": "patient-id-token-v1",
            "items": [
                {"plaintext": "123456"},
                {"plaintext": "654321", "metadata": {"tenant": "acme"}}
            ]
        }))
        .and_then(validate_encode_batch_input)
        .expect("valid token encode batch input must pass");

        assert_eq!(input.profile(), "patient-id-token-v1");
        assert_eq!(input.items.len(), 2);
    }

    #[test]
    fn validates_decode_batch_input() {
        let input = parse_decode_batch_input(json!({
            "kid": "a".repeat(64),
            "profile": "patient-id-token-v1",
            "items": [
                {"token": "tok_patient_abc"},
                {"token": "tok_patient_def"}
            ]
        }))
        .and_then(validate_decode_batch_input)
        .expect("valid token decode batch input must pass");

        assert_eq!(input.kid(), "a".repeat(64));
        assert_eq!(input.profile(), "patient-id-token-v1");
        assert_eq!(input.items.len(), 2);
    }

    #[test]
    fn rejects_empty_token_batch() {
        let err = encode_batch_validation_error(json!({
            "profile": "patient-id-token-v1",
            "items": []
        }));

        assert_eq!(err, "token batch items must not be empty");
    }

    #[test]
    fn rejects_oversized_token_batch() {
        let items = (0..=crate::core::config::INTERNAL_TOKEN_BATCH)
            .map(|_| json!({"plaintext": "123456"}))
            .collect::<Vec<_>>();
        let err = encode_batch_validation_error(json!({
            "profile": "patient-id-token-v1",
            "items": items
        }));

        assert_eq!(err, "token batch items exceeds maximum allowed value: 128");
    }

    #[test]
    fn rejects_token_batch_metadata_over_limit() {
        let metadata = metadata_with_serialized_len(tokenization::TOKEN_METADATA_MAX_CHARS + 1);
        let err = encode_batch_validation_error(json!({
            "profile": "patient-id-token-v1",
            "items": [{"plaintext": "123456", "metadata": metadata}]
        }));

        assert_eq!(
            err,
            "batch item 0 failed: metadata exceeds tokenization maximum length"
        );
    }

    #[test]
    fn token_decode_batch_output_serializes_plaintext_items() {
        let output = TokenDecodeBatchOutput {
            kid: "a".repeat(64),
            profile: String::from("patient-id-token-v1"),
            items: vec![
                TokenDecodeBatchOutputItem {
                    plaintext: SensitiveString::from(String::from("123456")),
                    metadata: None,
                },
                TokenDecodeBatchOutputItem {
                    plaintext: SensitiveString::from(String::from("654321")),
                    metadata: Some(json!({"tenant": "acme"})),
                },
            ],
        };
        let serialized = serde_json::to_value(output).expect("batch output must serialize");

        assert_eq!(
            serialized,
            json!({
                "kid": "a".repeat(64),
                "profile": "patient-id-token-v1",
                "items": [
                    {"plaintext": "123456"},
                    {"plaintext": "654321", "metadata": {"tenant": "acme"}}
                ]
            })
        );
    }
}
