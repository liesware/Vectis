use crate::error::{DynError, invalid_input};
use serde::de::DeserializeOwned;
use serde_json::Value;

pub fn parse_json_request<T>(request: Value, context: &str) -> Result<T, DynError>
where
    T: DeserializeOwned,
{
    serde_json::from_value(request).map_err(|err| {
        invalid_input(format!(
            "invalid {context}: {}",
            redact_unexpected_value(&err.to_string())
        ))
    })
}

fn redact_unexpected_value(message: &str) -> String {
    let markers = ["invalid type: ", "invalid value: "];
    let Some(value_region_start) = markers
        .iter()
        .filter_map(|marker| message.find(marker).map(|pos| pos + marker.len()))
        .min()
    else {
        return message.to_string();
    };

    let region = &message[value_region_start..];
    let Some((open_offset, delimiter)) = region.char_indices().find(|&(_, c)| c == '`' || c == '"')
    else {
        return message.to_string();
    };

    let after_open = &region[open_offset + delimiter.len_utf8()..];
    let Some(close_offset) = after_open.find(delimiter) else {
        return message.to_string();
    };

    let value_start = value_region_start + open_offset;
    let value_end = value_start + delimiter.len_utf8() + close_offset + delimiter.len_utf8();

    let mut prefix_end = value_start;
    if message[..prefix_end].ends_with(' ') {
        prefix_end -= 1;
    }

    format!("{}{}", &message[..prefix_end], &message[value_end..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DemoInput {
        #[serde(rename = "value")]
        _value: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CountInput {
        #[serde(rename = "count")]
        _count: u32,
    }

    #[test]
    fn parse_json_request_preserves_unknown_field_name() {
        let err = match parse_json_request::<DemoInput>(
            json!({"value": "ok", "extra": true}),
            "demo request",
        ) {
            Ok(_) => panic!("unknown fields must fail"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("invalid demo request: unknown field")
        );
        assert!(err.to_string().contains("extra"));
    }

    #[test]
    fn parse_json_request_preserves_missing_field_name() {
        let err = match parse_json_request::<DemoInput>(json!({}), "demo request") {
            Ok(_) => panic!("missing field must fail"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("invalid demo request: missing field `value`")
        );
    }

    #[test]
    fn parse_json_request_redacts_numeric_value_on_type_mismatch() {
        let err = match parse_json_request::<DemoInput>(
            json!({"value": 4111111111111111i64}),
            "demo request",
        ) {
            Ok(_) => panic!("type mismatch must fail"),
            Err(err) => err,
        };
        let message = err.to_string();

        assert_eq!(
            message,
            "invalid demo request: invalid type: integer, expected a string"
        );
        assert!(!message.contains("4111111111111111"));
    }

    #[test]
    fn parse_json_request_redacts_string_value_on_type_mismatch() {
        let err = match parse_json_request::<CountInput>(
            json!({"count": "4111111111111111"}),
            "demo request",
        ) {
            Ok(_) => panic!("type mismatch must fail"),
            Err(err) => err,
        };
        let message = err.to_string();

        assert!(message.starts_with("invalid demo request: invalid type: string,"));
        assert!(!message.contains("4111111111111111"));
    }

    #[test]
    fn redact_unexpected_value_keeps_valueless_type_mismatch() {
        assert_eq!(
            redact_unexpected_value("invalid type: map, expected a string"),
            "invalid type: map, expected a string"
        );
    }

    #[test]
    fn redact_unexpected_value_ignores_value_inside_string_payload() {
        assert_eq!(
            redact_unexpected_value("invalid type: string \"x, expected y\", expected a sequence"),
            "invalid type: string, expected a sequence"
        );
    }
}
