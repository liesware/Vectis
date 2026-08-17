use crate::error::{DynError, invalid_json_input};
use serde::de::DeserializeOwned;
use serde_json::Value;

pub fn parse_json_request<T>(request: Value, context: &str) -> Result<T, DynError>
where
    T: DeserializeOwned,
{
    // Reject serde_json's reserved object keys on the raw request before
    // `from_value` runs: deserialization collapses a `$serde_json::private::*`
    // object into a Number/RawValue node, so the check must happen here to see
    // the key. This guards every endpoint at the input boundary.
    crate::core::validation::validate_canonical_json_value(context, &request)?;
    serde_json::from_value(request)
        .map_err(|error| invalid_json_input(&format!("invalid {context}"), &error))
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
    fn parse_json_request_strips_control_chars_from_unknown_field_name() {
        let field = String::from("bad\u{7f}field");
        let err = match parse_json_request::<DemoInput>(
            json!({"value": "ok", field: true}),
            "demo request",
        ) {
            Ok(_) => panic!("unknown fields must fail"),
            Err(err) => err,
        };
        let message = err.to_string();

        assert!(!message.chars().any(char::is_control));
        assert!(message.contains("badfield"));
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
}
