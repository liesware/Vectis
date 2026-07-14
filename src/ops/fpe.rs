use crate::core::{fpe, validation};
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

#[derive(Serialize)]
pub struct FpeEncryptOutput {
    kid: String,
    profile: String,
    ciphertext: String,
}

#[derive(Serialize)]
pub struct FpeDecryptOutput {
    plaintext: String,
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

pub fn parse_encrypt_input(request: Value) -> Result<FpeEncryptInput, DynError> {
    serde_json::from_value(request).map_err(|_| crate::error::invalid_input("invalid fpe request"))
}

pub fn parse_decrypt_input(request: Value) -> Result<FpeDecryptInput, DynError> {
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

    Ok(FpeDecryptOutput { plaintext })
}
