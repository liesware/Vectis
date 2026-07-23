use crate::core::{sensitive::SensitiveString, sharing, validation};
use crate::error::DynError;
use crate::ops::keys::{self, KeysDbState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareSplitInput {
    profile: String,
    plaintext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareCombineInput {
    kid: String,
    profile: String,
    shares: Vec<String>,
}

#[derive(Serialize)]
pub struct ShareSplitOutput {
    kid: String,
    profile: String,
    threshold: usize,
    set_id: String,
    shares: Vec<SensitiveString>,
}

#[derive(Serialize)]
pub struct ShareCombineOutput {
    kid: String,
    profile: String,
    set_id: String,
    plaintext: SensitiveString,
}

pub struct ValidatedShareSplitInput {
    profile: String,
    plaintext: Zeroizing<String>,
}

pub struct ValidatedShareCombineInput {
    kid: String,
    profile: String,
    shares: Vec<Zeroizing<String>>,
}

pub struct PreparedShareSplit {
    kid: String,
    profile: sharing::SharingProfile,
    input: ValidatedShareSplitInput,
}

pub struct PreparedShareCombine {
    kid: String,
    profile: sharing::SharingProfile,
    input: ValidatedShareCombineInput,
}

impl ShareSplitOutput {
    pub fn shares_len(&self) -> usize {
        self.shares.len()
    }
}

impl ValidatedShareSplitInput {
    pub fn profile(&self) -> &str {
        &self.profile
    }
}

impl ValidatedShareCombineInput {
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }
}

pub fn parse_split_input(request: Value) -> Result<ShareSplitInput, DynError> {
    crate::ops::json::parse_json_request(request, "shares split request")
}

pub fn parse_combine_input(request: Value) -> Result<ShareCombineInput, DynError> {
    crate::ops::json::parse_json_request(request, "shares combine request")
}

pub fn validate_split_input(input: ShareSplitInput) -> Result<ValidatedShareSplitInput, DynError> {
    validation::validate_aad_config_name("profile", &input.profile)?;
    validation::validate_text_field("plaintext", &input.plaintext)?;

    Ok(ValidatedShareSplitInput {
        profile: input.profile,
        plaintext: Zeroizing::new(input.plaintext),
    })
}

pub fn validate_combine_input(
    input: ShareCombineInput,
) -> Result<ValidatedShareCombineInput, DynError> {
    keys::validate_key_id(&input.kid)
        .map_err(|err| crate::error::invalid_input(format!("kid is invalid: {err}")))?;
    validation::validate_aad_config_name("profile", &input.profile)?;
    if input.shares.is_empty() {
        return Err(crate::error::invalid_input("shares must not be empty"));
    }
    if input.shares.len() > crate::core::config::INTERNAL_SHARE_MAX {
        return Err(crate::error::invalid_input(format!(
            "shares exceeds maximum allowed value: {}",
            crate::core::config::INTERNAL_SHARE_MAX
        )));
    }

    let mut shares = Vec::with_capacity(input.shares.len());
    for (index, share) in input.shares.into_iter().enumerate() {
        validation::validate_text_field("share", &share)
            .map_err(|err| crate::error::with_prefix(&format!("share {index} failed"), err))?;
        shares.push(Zeroizing::new(share));
    }

    Ok(ValidatedShareCombineInput {
        kid: input.kid,
        profile: input.profile,
        shares,
    })
}

pub fn prepare_split(
    keys_db_state: &KeysDbState,
    kid: &str,
    profile: sharing::SharingProfile,
    input: ValidatedShareSplitInput,
) -> Result<PreparedShareSplit, DynError> {
    keys::prepare_profile_use(
        keys_db_state,
        kid,
        profile.kid(),
        "sharing",
        keys::ProfileUse::NewUse,
    )?;
    validate_plaintext_len(&profile, &input.plaintext)?;

    Ok(PreparedShareSplit {
        kid: kid.to_string(),
        profile,
        input,
    })
}

pub fn prepare_combine(
    keys_db_state: &KeysDbState,
    profile: sharing::SharingProfile,
    input: ValidatedShareCombineInput,
) -> Result<PreparedShareCombine, DynError> {
    keys::prepare_profile_use(
        keys_db_state,
        input.kid(),
        profile.kid(),
        "sharing",
        keys::ProfileUse::Verify,
    )?;
    if input.shares.len() < profile.threshold() {
        return Err(crate::error::invalid_input(
            "not enough shares to meet sharing profile threshold",
        ));
    }

    Ok(PreparedShareCombine {
        kid: input.kid.clone(),
        profile,
        input,
    })
}

pub fn split(prepared: PreparedShareSplit) -> Result<ShareSplitOutput, DynError> {
    let set_id = sharing::new_set_id()?;
    let shares = sharing::split(&prepared.profile, prepared.input.plaintext.as_bytes())?
        .iter()
        .map(|share| sharing::encode_share(&prepared.profile, &set_id, share))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(SensitiveString::from)
        .collect();

    Ok(ShareSplitOutput {
        kid: prepared.kid,
        profile: prepared.input.profile,
        threshold: prepared.profile.threshold(),
        set_id,
        shares,
    })
}

pub fn combine(prepared: PreparedShareCombine) -> Result<ShareCombineOutput, DynError> {
    let mut set_id: Option<String> = None;
    let mut raw_shares = Vec::with_capacity(prepared.input.shares.len());
    for (index, encoded) in prepared.input.shares.iter().enumerate() {
        let (share_set_id, raw_share) = sharing::decode_share(&prepared.profile, encoded)
            .map_err(|err| crate::error::with_prefix(&format!("share {index} failed"), err))?;
        if let Some(expected) = &set_id {
            if expected != &share_set_id {
                return Err(crate::error::invalid_input(
                    "shares do not belong to the same sharing set",
                ));
            }
        } else {
            set_id = Some(share_set_id);
        }
        raw_shares.push(raw_share);
    }

    let plaintext = sharing::combine(&raw_shares, prepared.profile.threshold())?;
    if plaintext.len() > prepared.profile.max_secret_len() {
        return Err(crate::error::invalid_input(
            "reconstructed secret exceeds sharing profile maximum length",
        ));
    }
    let plaintext = String::from_utf8(plaintext.to_vec())
        .map_err(|_| crate::error::invalid_input("reconstructed secret is not valid UTF-8"))?;

    let set_id = set_id
        .ok_or_else(|| crate::error::internal("share set id is missing after combining shares"))?;

    Ok(ShareCombineOutput {
        kid: prepared.kid,
        profile: prepared.input.profile,
        set_id,
        plaintext: SensitiveString::from(plaintext),
    })
}

fn validate_plaintext_len(
    profile: &sharing::SharingProfile,
    plaintext: &str,
) -> Result<(), DynError> {
    if plaintext.len() > profile.max_secret_len() {
        return Err(crate::error::invalid_input(
            "plaintext exceeds sharing profile maximum length",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn profile() -> sharing::SharingProfile {
        let input = serde_json::from_value(json!({
            "name": "customer-secret-3of5-v1",
            "kid": KID,
            "threshold": 3,
            "shares": 5,
            "max_secret_len": 64,
            "context": "tenant=demo;purpose=sharing;version=1"
        }))
        .unwrap();
        sharing::validate_sharing_profiles(
            vec![input],
            |_| true,
            |_| Ok(String::from("SHA-3(256)")),
            |request| sharing::derive_sharing_key_for_profile(&"11".repeat(32), request),
        )
        .unwrap()
        .get("customer-secret-3of5-v1")
        .unwrap()
        .clone()
    }

    #[test]
    fn combines_any_threshold_subset() {
        let input = validate_split_input(
            parse_split_input(json!({
                "profile": "customer-secret-3of5-v1",
                "plaintext": "secret-value"
            }))
            .unwrap(),
        )
        .unwrap();
        let output = split(
            prepare_split(
                &keys::test_keys_state_with_lifecycle(KID, "active"),
                KID,
                profile(),
                input,
            )
            .unwrap(),
        )
        .unwrap();
        let output_json = serde_json::to_value(&output).unwrap();
        let shares = output_json["shares"].as_array().unwrap();
        let input = validate_combine_input(
            parse_combine_input(json!({
                "kid": KID,
                "profile": "customer-secret-3of5-v1",
                "shares": [shares[0], shares[2], shares[4]]
            }))
            .unwrap(),
        )
        .unwrap();
        let combined = combine(
            prepare_combine(
                &keys::test_keys_state_with_lifecycle(KID, "active"),
                profile(),
                input,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&combined).unwrap()["plaintext"],
            "secret-value"
        );
    }
}
