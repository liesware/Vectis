use crate::core::{tokenization, validation};
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

pub struct EncodedTokenRecord {
    pub kid: String,
    pub hashid: String,
    pub data: String,
    pub output: TokenEncodeOutput,
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

pub fn parse_encode_input(request: Value) -> Result<TokenEncodeInput, DynError> {
    serde_json::from_value(request)
        .map_err(|_| crate::error::invalid_input("invalid token encode request"))
}

pub fn parse_decode_input(request: Value) -> Result<TokenDecodeInput, DynError> {
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
}
