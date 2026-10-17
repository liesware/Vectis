use crate::{
    core::{deterministic_tokenization as core, subjects, validation},
    error::DynError,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodeInput {
    #[serde(rename = "ref")]
    ref_id: String,
    profile: String,
    plaintext: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodeInput {
    #[serde(rename = "ref")]
    ref_id: String,
    kid: String,
    profile: String,
    token: String,
    #[serde(default, deserialize_with = "deserialize_subject")]
    subject: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodeItem {
    #[serde(rename = "ref")]
    ref_id: String,
    plaintext: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodeItem {
    #[serde(rename = "ref")]
    ref_id: String,
    token: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodeBatch {
    profile: String,
    items: Vec<EncodeItem>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodeBatch {
    kid: String,
    profile: String,
    items: Vec<DecodeItem>,
    #[serde(default, deserialize_with = "deserialize_subject")]
    subject: Option<String>,
}
fn deserialize_subject<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}

pub struct Request {
    pub kid: String,
    pub profile: String,
    pub subject: Option<String>,
    pub decode: bool,
    pub batch: bool,
    items: Vec<Item>,
}
struct Item {
    ref_id: String,
    value: Zeroizing<String>,
}

pub fn parse_request(
    value: serde_json::Value,
    path: Option<(String, Option<String>)>,
    batch: bool,
) -> Result<Request, DynError> {
    if batch {
        super::batch::reject_oversized_value(
            &value,
            crate::core::config::INTERNAL_TOKEN_DETERMINISTIC_BATCH,
            "deterministic token",
        )?;
    }
    let mut request = match (path, batch) {
        (Some((kid, subject)), false) => {
            let input: EncodeInput =
                super::json::parse_json_request(value, "deterministic token request")?;
            Request {
                kid,
                subject,
                profile: input.profile,
                decode: false,
                batch,
                items: vec![Item {
                    ref_id: input.ref_id,
                    value: Zeroizing::new(input.plaintext),
                }],
            }
        }
        (Some((kid, subject)), true) => {
            let input: EncodeBatch =
                super::json::parse_json_request(value, "deterministic token request")?;
            Request {
                kid,
                subject,
                profile: input.profile,
                decode: false,
                batch,
                items: input
                    .items
                    .into_iter()
                    .map(|i| Item {
                        ref_id: i.ref_id,
                        value: Zeroizing::new(i.plaintext),
                    })
                    .collect(),
            }
        }
        (None, false) => {
            let input: DecodeInput =
                super::json::parse_json_request(value, "deterministic token request")?;
            Request {
                kid: input.kid,
                subject: input.subject,
                profile: input.profile,
                decode: true,
                batch,
                items: vec![Item {
                    ref_id: input.ref_id,
                    value: Zeroizing::new(input.token),
                }],
            }
        }
        (None, true) => {
            let input: DecodeBatch =
                super::json::parse_json_request(value, "deterministic token request")?;
            Request {
                kid: input.kid,
                subject: input.subject,
                profile: input.profile,
                decode: true,
                batch,
                items: input
                    .items
                    .into_iter()
                    .map(|i| Item {
                        ref_id: i.ref_id,
                        value: Zeroizing::new(i.token),
                    })
                    .collect(),
            }
        }
    };
    super::keys::validate_key_id(&request.kid)?;
    validation::validate_aad_config_name("profile", &request.profile)?;
    if let Some(subject) = &request.subject {
        subjects::validate_subject(subject)?;
    }
    if batch {
        super::batch::validate_len(
            request.items.len(),
            crate::core::config::INTERNAL_TOKEN_DETERMINISTIC_BATCH,
            "deterministic token",
        )?;
    }
    for (index, item) in request.items.iter_mut().enumerate() {
        item.ref_id =
            validation::validate_ref(&item.ref_id).map_err(|e| indexed(e, batch, index))?;
        if !request.decode {
            validation::validate_text_field("plaintext", &item.value)
                .map_err(|e| indexed(e, batch, index))?;
        }
        if request.decode {
            core::validate_token(&item.value).map_err(|e| indexed(e, batch, index))?;
        } else if item.value.len() > core::PLAINTEXT_MAX_CHARS * 4
            || item.value.chars().count() > core::PLAINTEXT_MAX_CHARS
        {
            return Err(indexed(
                crate::error::invalid_input("plaintext exceeds maximum allowed length: 16384"),
                batch,
                index,
            ));
        }
    }
    if batch {
        super::batch::validate_unique_refs(
            request.items.iter().map(|i| i.ref_id.as_str()),
            "deterministic token",
        )?;
    }
    Ok(request)
}
fn indexed(error: DynError, batch: bool, index: usize) -> DynError {
    if batch {
        crate::error::with_prefix(&format!("batch item {index} failed"), error)
    } else {
        error
    }
}

#[derive(Serialize)]
pub struct OutputItem {
    #[serde(rename = "ref")]
    ref_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plaintext: Option<crate::core::sensitive::SensitiveString>,
}
#[derive(Serialize)]
pub struct SingleOutput {
    kid: String,
    profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    #[serde(flatten)]
    item: OutputItem,
}
#[derive(Serialize)]
pub struct BatchOutput {
    kid: String,
    profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    items: Vec<OutputItem>,
}
#[derive(Serialize)]
#[serde(untagged)]
pub enum Output {
    Single(SingleOutput),
    Batch(BatchOutput),
}

pub struct Prepared {
    request: Request,
    context: core::DeterministicTokenContext,
}

pub fn prepare(
    keys_db_state: &super::keys::KeysDbState,
    request: Request,
    context: core::DeterministicTokenContext,
) -> Result<Prepared, DynError> {
    super::keys::prepare_profile_use(
        keys_db_state,
        &request.kid,
        context.kid(),
        "deterministic token",
        if request.decode {
            super::keys::ProfileUse::Verify
        } else {
            super::keys::ProfileUse::NewUse
        },
    )?;
    if request.kid != context.kid()
        || request.profile != context.profile_name()
        || request.subject.as_deref() != context.subject()
    {
        return Err(crate::error::invalid_input(
            "deterministic token context mismatch",
        ));
    }
    Ok(Prepared { request, context })
}

pub fn execute(prepared: Prepared) -> Result<Output, DynError> {
    let Prepared { request, context } = prepared;
    let mut items = Vec::with_capacity(request.items.len());
    for (index, item) in request.items.into_iter().enumerate() {
        let result = if request.decode {
            context.decode(&item.value).map(|plaintext| OutputItem {
                ref_id: item.ref_id,
                token: None,
                plaintext: Some(plaintext.into()),
            })
        } else {
            context.encode(&item.value).map(|token| OutputItem {
                ref_id: item.ref_id,
                token: Some(token),
                plaintext: None,
            })
        };
        items.push(result.map_err(|e| indexed(e, request.batch, index))?);
    }
    if request.batch {
        Ok(Output::Batch(BatchOutput {
            kid: request.kid,
            profile: request.profile,
            subject: request.subject,
            items,
        }))
    } else {
        Ok(Output::Single(SingleOutput {
            kid: request.kid,
            profile: request.profile,
            subject: request.subject,
            item: items.pop().expect("single input"),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn context() -> core::DeterministicTokenContext {
        core::DeterministicTokenContext::new(core::validate_profiles(serde_json::from_value(json!([{
            "name":"p","kid":"a".repeat(64),"context":"tenant=test","min_plaintext_len":1,"max_plaintext_len":16384
        }])).unwrap(), |_| true, |_| Ok(Zeroizing::new(vec![7;64]))).unwrap().get("p").unwrap()).unwrap()
    }
    #[test]
    fn batch_order_ref_independence_and_all_or_nothing() {
        let req = json!({"profile":"p","items":[{"ref":"one","plaintext":"same"},{"ref":"two","plaintext":"same"}]});
        let input = parse_request(req, Some(("a".repeat(64), None)), true).unwrap();
        let output = serde_json::to_value(
            execute(Prepared {
                request: input,
                context: context(),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(output["items"][0]["token"], output["items"][1]["token"]);
        let decode = json!({"kid":"a".repeat(64),"profile":"p","items":output["items"]});
        let input = parse_request(decode.clone(), None, true).unwrap();
        let result = serde_json::to_value(
            execute(Prepared {
                request: input,
                context: context(),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(result["items"][0]["ref"], "one");
        assert_eq!(result["items"][1]["plaintext"], "same");
        let mut bad = decode;
        let token = context().encode("other").unwrap();
        let (aad, ct) = token.split_once('.').unwrap();
        let mut bytes = ct.as_bytes().to_vec();
        bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
        bad["items"][1]["token"] = json!(format!("{aad}.{}", String::from_utf8(bytes).unwrap()));
        let input = parse_request(bad, None, true).unwrap();
        assert!(
            execute(Prepared {
                request: input,
                context: context(),
            })
            .err()
            .unwrap()
            .to_string()
            .starts_with("batch item 1 failed")
        );
    }
    #[test]
    fn rejects_invalid_shapes_subjects_and_refs() {
        for subject in [json!(null), json!(1), json!("UPPERCASE")] {
            let input = json!({"ref":"r","kid":"a".repeat(64),"profile":"p","token":"a.b","subject":subject});
            assert!(parse_request(input, None, false).is_err());
        }
        for items in [
            json!([]),
            json!([{"ref":"same","plaintext":"a"},{"ref":"same","plaintext":"b"}]),
            json!([{"ref":"r","plaintext":"a","metadata":{}}]),
        ] {
            assert!(
                parse_request(
                    json!({"profile":"p","items":items}),
                    Some(("a".repeat(64), None)),
                    true
                )
                .is_err()
            );
        }
        let input = json!({"profile":"p","items":vec![json!({"ref":"r","plaintext":"a"});129]});
        assert!(parse_request(input, Some(("a".repeat(64), None)), true).is_err());
    }
    #[test]
    fn prepare_enforces_lifecycle_and_binding() {
        let kid = "a".repeat(64);
        let encode = || {
            parse_request(
                json!({"ref":"r","profile":"p","plaintext":"x"}),
                Some((kid.clone(), None)),
                false,
            )
            .unwrap()
        };
        let token = serde_json::to_value(
            execute(Prepared {
                request: encode(),
                context: context(),
            })
            .unwrap(),
        )
        .unwrap()["token"]
            .as_str()
            .unwrap()
            .to_owned();
        let decode = || {
            parse_request(
                json!({"ref":"r","kid":kid.clone(),"profile":"p","token":token.clone()}),
                None,
                false,
            )
            .unwrap()
        };
        let active = crate::ops::keys::test_keys_state_with_lifecycle(&kid, "active");
        assert!(prepare(&active, encode(), context()).is_ok());
        assert!(prepare(&active, decode(), context()).is_ok());
        let retired = crate::ops::keys::test_keys_state_with_lifecycle(&kid, "retired");
        assert!(prepare(&retired, encode(), context()).is_err());
        assert!(prepare(&retired, decode(), context()).is_ok());
        let unknown = crate::ops::keys::test_keys_state_with_lifecycle(&"b".repeat(64), "active");
        assert!(prepare(&unknown, encode(), context()).is_err());
    }
}
