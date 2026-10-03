use crate::core::{
    storage::SubjectRow,
    subjects,
    tokenization::{SubjectMode, TokenizationProfile},
    validation,
};
use crate::error::DynError;
use crate::ops::keys::{self, KeysDbState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSubjectInput {
    profile: String,
    subject_name: String,
}

pub struct ValidatedCreateSubjectInput {
    profile: String,
    subject_name: Zeroizing<String>,
}

impl ValidatedCreateSubjectInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

pub struct PreparedCreateSubject {
    profile: Arc<TokenizationProfile>,
    input: ValidatedCreateSubjectInput,
}

#[derive(Serialize)]
pub struct CreateSubjectOutput {
    pub kid: String,
    pub profile: String,
    pub subject: String,
}

pub fn parse_create_input(value: Value) -> Result<CreateSubjectInput, DynError> {
    crate::ops::json::parse_json_request(value, "subject create request")
}

pub fn validate_create_input(
    input: CreateSubjectInput,
) -> Result<ValidatedCreateSubjectInput, DynError> {
    validation::validate_aad_config_name("profile", &input.profile)?;
    subjects::validate_subject_name(&input.subject_name)?;
    Ok(ValidatedCreateSubjectInput {
        profile: input.profile,
        subject_name: Zeroizing::new(input.subject_name),
    })
}

pub fn prepare_create(
    keys: &KeysDbState,
    kid: &str,
    profile: Arc<TokenizationProfile>,
    input: ValidatedCreateSubjectInput,
) -> Result<PreparedCreateSubject, DynError> {
    keys::validate_key_id(kid)?;
    if profile.subject_mode() != SubjectMode::Stored || profile.name() != input.profile {
        return Err(crate::error::invalid_input(
            "subject creation requires a stored tokenization profile",
        ));
    }
    keys::prepare_profile_use(
        keys,
        kid,
        profile.kid(),
        "tokenization",
        keys::ProfileUse::NewUse,
    )?;
    Ok(PreparedCreateSubject { profile, input })
}

pub fn subject_identifier(prepared: &PreparedCreateSubject) -> Result<String, DynError> {
    subjects::subject_id(&prepared.profile, &prepared.input.subject_name)
}

pub fn existing_output(prepared: &PreparedCreateSubject, subject: String) -> CreateSubjectOutput {
    CreateSubjectOutput {
        kid: prepared.profile.kid().to_owned(),
        profile: prepared.profile.name().to_owned(),
        subject,
    }
}

pub fn create(
    prepared: PreparedCreateSubject,
) -> Result<(SubjectRow, CreateSubjectOutput), DynError> {
    let subject = subjects::subject_id(&prepared.profile, &prepared.input.subject_name)?;
    let seed = subjects::create_seed(&prepared.profile, &subject)?;
    let kid = prepared.profile.kid().to_owned();
    let output = CreateSubjectOutput {
        kid: kid.clone(),
        profile: prepared.profile.name().to_owned(),
        subject: subject.clone(),
    };
    Ok((SubjectRow { kid, subject, seed }, output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn create_input_requires_bounded_aad_safe_fields_and_rejects_unknowns() {
        for field in ["profile", "subject_name"] {
            for value in [
                json!(""),
                json!(" "),
                json!("x".repeat(129)),
                json!("界".repeat(129)),
                json!("a;b"),
                json!("a=b"),
                json!("a\n"),
                json!(42),
                Value::Null,
            ] {
                let mut body = json!({"profile":"stored-v1", "subject_name":"synthetic"});
                body[field] = value;
                let error = parse_create_input(body)
                    .and_then(validate_create_input)
                    .err()
                    .unwrap();
                assert!(!error.to_string().chars().any(char::is_control));
            }
            for value in ["x".repeat(128), "界".repeat(128)] {
                let mut body = json!({"profile":"stored-v1", "subject_name":"synthetic"});
                body[field] = json!(value);
                assert!(
                    parse_create_input(body)
                        .and_then(validate_create_input)
                        .is_ok()
                );
            }
        }
        for field in ["seed", "cipher", "subject_mode", "extra"] {
            let mut body = json!({"profile":"stored-v1", "subject_name":"synthetic"});
            body[field] = json!("not accepted");
            assert!(parse_create_input(body).is_err());
        }
    }
}
