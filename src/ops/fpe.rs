use crate::core::{fpe, sensitive::SensitiveString, validation};
use crate::error::DynError;
use crate::ops::keys::{self, KeysDbState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(test)]
use std::sync::Arc;
use tracing::info;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FpeEncryptInput {
    #[serde(rename = "ref")]
    ref_id: String,
    profile: String,
    plaintext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FpeDecryptInput {
    #[serde(rename = "ref")]
    ref_id: String,
    kid: String,
    profile: String,
    ciphertext: String,
    #[serde(default, deserialize_with = "fpe::deserialize_present")]
    tag: Option<String>,
    #[serde(default, deserialize_with = "fpe::deserialize_present")]
    subject: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FpeEncryptBatchItemInput {
    #[serde(rename = "ref")]
    ref_id: String,
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
    #[serde(rename = "ref")]
    ref_id: String,
    ciphertext: String,
    #[serde(default, deserialize_with = "fpe::deserialize_present")]
    tag: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FpeDecryptBatchInput {
    kid: String,
    profile: String,
    items: Vec<FpeDecryptBatchItemInput>,
    #[serde(default, deserialize_with = "fpe::deserialize_present")]
    subject: Option<String>,
}

#[derive(Serialize)]
pub struct FpeEncryptOutput {
    #[serde(rename = "ref")]
    ref_id: String,
    kid: String,
    profile: String,
    ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
}

#[derive(Serialize)]
pub struct FpeDecryptOutput {
    #[serde(rename = "ref")]
    ref_id: String,
    plaintext: SensitiveString,
}

#[derive(Serialize)]
pub struct FpeEncryptBatchOutputItem {
    #[serde(rename = "ref")]
    ref_id: String,
    ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
}

#[derive(Serialize)]
pub struct FpeEncryptBatchOutput {
    kid: String,
    profile: String,
    items: Vec<FpeEncryptBatchOutputItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
}

#[derive(Serialize)]
pub struct FpeDecryptBatchOutputItem {
    #[serde(rename = "ref")]
    ref_id: String,
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
    ref_id: String,
    profile: String,
    plaintext: Zeroizing<String>,
}

pub struct ValidatedFpeDecryptInput {
    ref_id: String,
    kid: String,
    profile: String,
    ciphertext: Zeroizing<String>,
    tag: Option<String>,
    subject: Option<String>,
}

pub struct ValidatedFpeEncryptBatchItem {
    ref_id: String,
    plaintext: Zeroizing<String>,
}

pub struct ValidatedFpeEncryptBatchInput {
    profile: String,
    items: Vec<ValidatedFpeEncryptBatchItem>,
}

pub struct ValidatedFpeDecryptBatchItem {
    ref_id: String,
    ciphertext: Zeroizing<String>,
    tag: Option<String>,
}

pub struct ValidatedFpeDecryptBatchInput {
    kid: String,
    profile: String,
    items: Vec<ValidatedFpeDecryptBatchItem>,
    subject: Option<String>,
}

pub struct PreparedFpeEncrypt {
    kid: String,
    profile: fpe::FpeContext,
    input: ValidatedFpeEncryptInput,
}

pub struct PreparedFpeDecrypt {
    kid: String,
    profile: fpe::FpeContext,
    input: ValidatedFpeDecryptInput,
}

pub struct PreparedFpeEncryptBatch {
    kid: String,
    profile: fpe::FpeContext,
    input: ValidatedFpeEncryptBatchInput,
}

pub struct PreparedFpeDecryptBatch {
    kid: String,
    profile: fpe::FpeContext,
    input: ValidatedFpeDecryptBatchInput,
}

impl ValidatedFpeEncryptInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedFpeDecryptInput {
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }
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
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }
}

pub fn parse_encrypt_input(request: Value) -> Result<FpeEncryptInput, DynError> {
    crate::ops::json::parse_json_request(request, "fpe request")
}

pub fn parse_decrypt_input(request: Value) -> Result<FpeDecryptInput, DynError> {
    crate::ops::json::parse_json_request(request, "fpe request")
}

pub fn parse_encrypt_batch_input(request: Value) -> Result<FpeEncryptBatchInput, DynError> {
    crate::ops::batch::reject_oversized_value(
        &request,
        crate::core::config::INTERNAL_FPE_BATCH,
        "fpe",
    )?;
    crate::ops::json::parse_json_request(request, "fpe request")
}

pub fn parse_decrypt_batch_input(request: Value) -> Result<FpeDecryptBatchInput, DynError> {
    crate::ops::batch::reject_oversized_value(
        &request,
        crate::core::config::INTERNAL_FPE_BATCH,
        "fpe",
    )?;
    crate::ops::json::parse_json_request(request, "fpe request")
}

pub fn validate_encrypt_input(
    input: FpeEncryptInput,
) -> Result<ValidatedFpeEncryptInput, DynError> {
    let ref_id = validation::validate_ref(&input.ref_id)?;
    validation::validate_aad_config_name("profile", &input.profile)?;
    validation::validate_text_field("plaintext", &input.plaintext)?;

    Ok(ValidatedFpeEncryptInput {
        ref_id,
        profile: input.profile,
        plaintext: Zeroizing::new(input.plaintext),
    })
}

pub fn validate_decrypt_input(
    input: FpeDecryptInput,
) -> Result<ValidatedFpeDecryptInput, DynError> {
    let ref_id = validation::validate_ref(&input.ref_id)?;
    keys::validate_key_id(&input.kid)?;
    validation::validate_aad_config_name("profile", &input.profile)?;
    validation::validate_text_field("ciphertext", &input.ciphertext)?;
    if let Some(tag) = &input.tag {
        fpe::validate_auth_tag(tag)?;
    }
    if let Some(subject) = &input.subject {
        crate::core::subjects::validate_subject(subject)?;
    }

    Ok(ValidatedFpeDecryptInput {
        ref_id,
        kid: input.kid,
        profile: input.profile,
        ciphertext: Zeroizing::new(input.ciphertext),
        tag: input.tag,
        subject: input.subject,
    })
}

pub fn validate_encrypt_batch_input(
    input: FpeEncryptBatchInput,
) -> Result<ValidatedFpeEncryptBatchInput, DynError> {
    validation::validate_aad_config_name("profile", &input.profile)?;
    crate::ops::batch::validate_len(
        input.items.len(),
        crate::core::config::INTERNAL_FPE_BATCH,
        "fpe",
    )?;
    let mut items = Vec::with_capacity(input.items.len());
    for (index, item) in input.items.into_iter().enumerate() {
        let ref_id = validation::validate_ref(&item.ref_id)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        validation::validate_text_field("plaintext", &item.plaintext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        items.push(ValidatedFpeEncryptBatchItem {
            ref_id,
            plaintext: Zeroizing::new(item.plaintext),
        });
    }
    crate::ops::batch::validate_unique_refs(items.iter().map(|item| item.ref_id.as_str()), "fpe")?;

    Ok(ValidatedFpeEncryptBatchInput {
        profile: input.profile,
        items,
    })
}

pub fn validate_decrypt_batch_input(
    input: FpeDecryptBatchInput,
) -> Result<ValidatedFpeDecryptBatchInput, DynError> {
    if let Some(subject) = &input.subject {
        crate::core::subjects::validate_subject(subject)?;
    }
    keys::validate_key_id(&input.kid)?;
    validation::validate_aad_config_name("profile", &input.profile)?;
    crate::ops::batch::validate_len(
        input.items.len(),
        crate::core::config::INTERNAL_FPE_BATCH,
        "fpe",
    )?;
    let mut items = Vec::with_capacity(input.items.len());
    for (index, item) in input.items.into_iter().enumerate() {
        let ref_id = validation::validate_ref(&item.ref_id)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        validation::validate_text_field("ciphertext", &item.ciphertext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        if let Some(tag) = &item.tag {
            fpe::validate_auth_tag(tag).map_err(|err| {
                crate::error::with_prefix(&format!("batch item {index} failed"), err)
            })?;
        }
        items.push(ValidatedFpeDecryptBatchItem {
            ref_id,
            ciphertext: Zeroizing::new(item.ciphertext),
            tag: item.tag,
        });
    }
    crate::ops::batch::validate_unique_refs(items.iter().map(|item| item.ref_id.as_str()), "fpe")?;

    Ok(ValidatedFpeDecryptBatchInput {
        kid: input.kid,
        profile: input.profile,
        items,
        subject: input.subject,
    })
}

pub fn prepare_encrypt(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: impl Into<fpe::FpeContext>,
    input: ValidatedFpeEncryptInput,
) -> Result<PreparedFpeEncrypt, DynError> {
    let profile = profile.into();
    keys::prepare_profile_use(
        keys_db_state,
        kid,
        profile.kid(),
        "fpe",
        keys::ProfileUse::NewUse,
    )?;

    profile.validate_mode(profile.subject())?;
    Ok(PreparedFpeEncrypt {
        kid: kid.to_string(),
        profile,
        input,
    })
}

pub fn prepare_decrypt(
    keys_db_state: &KeysDbState,
    profile: impl Into<fpe::FpeContext>,
    input: ValidatedFpeDecryptInput,
) -> Result<PreparedFpeDecrypt, DynError> {
    let profile = profile.into();
    keys::prepare_profile_use(
        keys_db_state,
        &input.kid,
        profile.kid(),
        "fpe",
        keys::ProfileUse::Verify,
    )?;

    profile.validate_mode(input.subject.as_deref())?;
    fpe::validate_tag_policy(&profile, input.tag.as_deref())?;
    Ok(PreparedFpeDecrypt {
        kid: input.kid.clone(),
        profile,
        input,
    })
}

pub fn prepare_encrypt_batch(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: impl Into<fpe::FpeContext>,
    input: ValidatedFpeEncryptBatchInput,
) -> Result<PreparedFpeEncryptBatch, DynError> {
    let profile = profile.into();
    keys::prepare_profile_use(
        keys_db_state,
        kid,
        profile.kid(),
        "fpe",
        keys::ProfileUse::NewUse,
    )?;

    profile.validate_mode(profile.subject())?;
    Ok(PreparedFpeEncryptBatch {
        kid: kid.to_string(),
        profile,
        input,
    })
}

pub fn prepare_decrypt_batch(
    keys_db_state: &KeysDbState,
    profile: impl Into<fpe::FpeContext>,
    input: ValidatedFpeDecryptBatchInput,
) -> Result<PreparedFpeDecryptBatch, DynError> {
    let profile = profile.into();
    keys::prepare_profile_use(
        keys_db_state,
        &input.kid,
        profile.kid(),
        "fpe",
        keys::ProfileUse::Verify,
    )?;

    profile.validate_mode(input.subject.as_deref())?;
    for (index, item) in input.items.iter().enumerate() {
        fpe::validate_tag_policy(&profile, item.tag.as_deref())
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
    }
    Ok(PreparedFpeDecryptBatch {
        kid: input.kid.clone(),
        profile,
        input,
    })
}

pub fn encrypt(prepared: PreparedFpeEncrypt) -> Result<FpeEncryptOutput, DynError> {
    let ciphertext = prepared.profile.encrypt(&prepared.input.plaintext)?;
    let tag = prepared.profile.generate_tag(&ciphertext)?;
    info!(
        kid = %prepared.kid,
        profile = %prepared.profile.name(),
        plaintext_len = prepared.input.plaintext.chars().count(),
        "fpe encrypt completed"
    );

    Ok(FpeEncryptOutput {
        ref_id: prepared.input.ref_id,
        kid: prepared.kid,
        profile: prepared.profile.name().to_string(),
        ciphertext,
        tag,
        subject: prepared.profile.subject().map(str::to_owned),
    })
}

pub fn decrypt(prepared: PreparedFpeDecrypt) -> Result<FpeDecryptOutput, DynError> {
    prepared
        .profile
        .verify_tag(&prepared.input.ciphertext, prepared.input.tag.as_deref())?;
    let plaintext = prepared.profile.decrypt(&prepared.input.ciphertext)?;
    info!(
        kid = %prepared.kid,
        profile = %prepared.profile.name(),
        ciphertext_len = prepared.input.ciphertext.chars().count(),
        "fpe decrypt completed"
    );

    Ok(FpeDecryptOutput {
        ref_id: prepared.input.ref_id,
        plaintext: SensitiveString::from(plaintext),
    })
}

pub fn encrypt_batch(prepared: PreparedFpeEncryptBatch) -> Result<FpeEncryptBatchOutput, DynError> {
    let mut items = Vec::with_capacity(prepared.input.items.len());
    for (index, item) in prepared.input.items.iter().enumerate() {
        let ciphertext = prepared
            .profile
            .encrypt(&item.plaintext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        let tag = prepared
            .profile
            .generate_tag(&ciphertext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        items.push(FpeEncryptBatchOutputItem {
            ref_id: item.ref_id.clone(),
            ciphertext,
            tag,
        });
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
        subject: prepared.profile.subject().map(str::to_owned),
    })
}

pub fn decrypt_batch(prepared: PreparedFpeDecryptBatch) -> Result<FpeDecryptBatchOutput, DynError> {
    // Authenticate the complete batch before recovering any plaintext.
    for (index, item) in prepared.input.items.iter().enumerate() {
        prepared
            .profile
            .verify_tag(&item.ciphertext, item.tag.as_deref())
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
    }
    let mut items = Vec::with_capacity(prepared.input.items.len());
    for (index, item) in prepared.input.items.iter().enumerate() {
        let plaintext = prepared
            .profile
            .decrypt(&item.ciphertext)
            .map_err(|err| crate::error::with_prefix(&format!("batch item {index} failed"), err))?;
        items.push(FpeDecryptBatchOutputItem {
            ref_id: item.ref_id.clone(),
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

    fn test_auth_profile(authenticated: bool) -> Arc<fpe::FpeProfile> {
        let definition: fpe::FpeProfileInput = serde_json::from_value(json!({"name":"auth-test", "kid":hex64('a'), "fpe_version":"fpe-ff1-2025", "alphabet_preset":"num", "preserve_characters":"-", "min_len":6, "max_len":32, "tweak_aad":"tenant=test", "authenticated":authenticated})).unwrap();
        fpe::validate_fpe_profiles(
            vec![definition],
            |_| true,
            |_| Ok(Zeroizing::new(vec![7; 32])),
            |_| Ok(Zeroizing::new(vec![9; 32])),
        )
        .unwrap()
        .get("auth-test")
        .unwrap()
    }

    #[test]
    fn authentication_is_checked_before_any_single_or_batch_decrypt() {
        let profile = test_auth_profile(true);
        let ciphertext = fpe::fpe_encrypt(&profile, "001-234").unwrap();
        let tag = fpe::generate_auth_tag(&profile, &ciphertext)
            .unwrap()
            .unwrap();
        let request = |tag: &str| {
            validate_decrypt_input(parse_decrypt_input(json!({"ref":"changed-ref", "kid":hex64('a'), "profile":"auth-test", "ciphertext":ciphertext, "tag":tag})).unwrap()).unwrap()
        };
        let mut wrong = tag.clone();
        wrong.replace_range(..1, if tag.starts_with('0') { "1" } else { "0" });
        fpe::reset_decrypt_calls();
        let failed = decrypt(PreparedFpeDecrypt {
            kid: hex64('a'),
            profile: profile.clone().into(),
            input: request(&wrong),
        });
        assert_eq!(
            failed.err().unwrap().to_string(),
            "fpe authentication failed"
        );
        assert_eq!(fpe::decrypt_calls(), 0);
        let valid = decrypt(PreparedFpeDecrypt {
            kid: hex64('a'),
            profile: profile.clone().into(),
            input: request(&tag),
        })
        .unwrap();
        assert_eq!(
            serde_json::to_value(valid).unwrap(),
            json!({"ref":"changed-ref","plaintext":"001-234"})
        );
        let input = validate_decrypt_batch_input(parse_decrypt_batch_input(json!({"kid":hex64('a'),"profile":"auth-test","items":[{"ref":"a","ciphertext":ciphertext,"tag":tag},{"ref":"b","ciphertext":ciphertext,"tag":wrong}]})).unwrap()).unwrap();
        fpe::reset_decrypt_calls();
        let failed = decrypt_batch(PreparedFpeDecryptBatch {
            kid: hex64('a'),
            profile: profile.into(),
            input,
        });
        assert_eq!(
            failed.err().unwrap().to_string(),
            "batch item 1 failed: fpe authentication failed"
        );
        assert_eq!(fpe::decrypt_calls(), 0);
    }

    #[test]
    fn tag_encoding_and_policy_are_strict_and_legacy_outputs_omit_tag() {
        let profile = test_auth_profile(true);
        let legacy = test_auth_profile(false);
        let ciphertext = "001-234";
        assert!(fpe::validate_tag_policy(&profile, None).is_err());
        assert!(fpe::validate_tag_policy(&legacy, Some(&"a".repeat(64))).is_err());
        for invalid in [
            json!(null),
            json!(true),
            json!(0),
            json!("a".repeat(63)),
            json!("a".repeat(65)),
            json!("A".repeat(64)),
            json!("g".repeat(64)),
            json!(format!("{} ", "a".repeat(63))),
        ] {
            assert!(parse_decrypt_input(json!({"ref":"test","kid":hex64('a'),"profile":"auth-test","ciphertext":ciphertext,"tag":invalid})).and_then(validate_decrypt_input).is_err());
        }
        for profile in [profile, legacy] {
            let input = validate_encrypt_input(
                parse_encrypt_input(
                    json!({"ref":"test","profile":"auth-test","plaintext":"001-234"}),
                )
                .unwrap(),
            )
            .unwrap();
            let output = encrypt(PreparedFpeEncrypt {
                kid: hex64('a'),
                profile: profile.clone().into(),
                input,
            })
            .unwrap();
            let value = serde_json::to_value(output).unwrap();
            assert_eq!(value.get("tag").is_some(), profile.authenticated());
        }
    }

    #[test]
    fn subject_input_is_strict_single_and_batch_and_forbidden_for_legacy() {
        let subject = hex64('b');
        for invalid in [
            json!(null),
            json!(true),
            json!("B".repeat(64)),
            json!("a".repeat(63)),
        ] {
            assert!(parse_decrypt_input(json!({"ref":"test","kid":hex64('a'),"profile":"auth-test","ciphertext":"001-234","subject":invalid})).and_then(validate_decrypt_input).is_err());
            assert!(parse_decrypt_batch_input(json!({"kid":hex64('a'),"profile":"auth-test","subject":invalid,"items":[{"ref":"test","ciphertext":"001-234"}]})).and_then(validate_decrypt_batch_input).is_err());
        }
        let profile = test_auth_profile(false);
        assert!(fpe::validate_subject_mode(&profile, Some(&subject)).is_err());
        let input = validate_decrypt_input(parse_decrypt_input(json!({"ref":"test","kid":hex64('a'),"profile":"auth-test","ciphertext":"001-234","subject":subject})).unwrap()).unwrap();
        assert_eq!(input.subject(), Some(subject.as_str()));
        let input = validate_decrypt_batch_input(parse_decrypt_batch_input(json!({"kid":hex64('a'),"profile":"auth-test","subject":subject,"items":[{"ref":"test","ciphertext":"001-234"}]})).unwrap()).unwrap();
        assert_eq!(input.subject(), Some(subject.as_str()));
    }

    fn encrypt_validation_error(profile: &str) -> String {
        match parse_encrypt_input(json!({
            "ref": "reg1",
            "profile": profile,
            "plaintext": "123456"
        }))
        .and_then(validate_encrypt_input)
        {
            Ok(_) => panic!("fpe encrypt validation unexpectedly passed"),
            Err(err) => err.to_string(),
        }
    }

    #[test]
    fn validates_profile_at_config_name_limit() {
        let profile = "a".repeat(crate::core::config::CONFIG_NAME_MAX_CHARS);
        let input = parse_encrypt_input(json!({
            "ref": "reg1",
            "profile": profile,
            "plaintext": "123456"
        }))
        .and_then(validate_encrypt_input)
        .expect("profile at config name limit must pass validation");

        assert_eq!(
            input.profile(),
            "a".repeat(crate::core::config::CONFIG_NAME_MAX_CHARS)
        );
    }

    #[test]
    fn rejects_profile_over_config_name_limit() {
        let profile = "a".repeat(crate::core::config::CONFIG_NAME_MAX_CHARS + 1);

        assert_eq!(
            encrypt_validation_error(&profile),
            "profile exceeds maximum allowed length: 128"
        );
    }

    #[test]
    fn rejects_profile_aad_delimiters() {
        assert_eq!(
            encrypt_validation_error("bad;profile"),
            "profile must not contain ';' or '='"
        );
        assert_eq!(
            encrypt_validation_error("bad=profile"),
            "profile must not contain ';' or '='"
        );
    }

    #[test]
    fn validates_encrypt_batch_input() {
        let input = parse_encrypt_batch_input(json!({
            "profile": "patient-id-decimal-v1",
            "items": [
                {"ref": "reg1", "plaintext": "123456"},
                {"ref": "reg2", "plaintext": "654321"}
            ]
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
            .map(|index| json!({"ref": format!("reg{index}"), "plaintext": "123456"}))
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
            "items": [
                {"ref": "reg1", "ciphertext": "123456"},
                {"ref": "reg2", "ciphertext": "654321"}
            ]
        }))
        .and_then(validate_decrypt_batch_input)
        .expect("valid decrypt batch input must pass");

        assert_eq!(input.kid(), hex64('a'));
        assert_eq!(input.profile(), "patient-id-decimal-v1");
        assert_eq!(input.items.len(), 2);
    }

    #[test]
    fn parse_fpe_input_preserves_unknown_field_detail() {
        let err = match parse_encrypt_input(json!({
            "ref": "reg1",
            "profile": "patient-id-decimal-v1",
            "plaintext": "123456",
            "sorpresa": true
        })) {
            Ok(_) => panic!("unknown fields must fail"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("invalid fpe request: unknown field")
        );
        assert!(err.to_string().contains("sorpresa"));
    }

    #[test]
    fn decrypt_output_serializes_plaintext() {
        let output = FpeDecryptOutput {
            ref_id: String::from("reg1"),
            plaintext: SensitiveString::from(String::from("123456")),
        };
        let serialized = serde_json::to_value(output).expect("decrypt output must serialize");

        assert_eq!(serialized, json!({"ref": "reg1", "plaintext": "123456"}));
    }

    #[test]
    fn decrypt_batch_output_serializes_plaintext_items() {
        let output = FpeDecryptBatchOutput {
            kid: hex64('a'),
            profile: String::from("patient-id-decimal-v1"),
            items: vec![
                FpeDecryptBatchOutputItem {
                    ref_id: String::from("reg1"),
                    plaintext: SensitiveString::from(String::from("123456")),
                },
                FpeDecryptBatchOutputItem {
                    ref_id: String::from("reg2"),
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
                    {"ref": "reg1", "plaintext": "123456"},
                    {"ref": "reg2", "plaintext": "654321"}
                ]
            })
        );
    }
}
