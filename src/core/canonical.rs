use crate::error::DynError;
use serde::Serialize;

pub fn canonical_json_v1<T: Serialize>(value: &T) -> Result<Vec<u8>, DynError> {
    let value = serde_json::to_value(value)?;
    Ok(serde_json::to_vec(&value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::collection::btree_map;
    use proptest::prelude::*;
    use serde_json::{Value, json};

    #[test]
    fn sorts_object_keys_and_compacts() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{ "b": "2", "a": "1", "c": { "z": "9", "y": "8" } }"#).unwrap();
        let canonical = canonical_json_v1(&value).unwrap();
        assert_eq!(canonical, br#"{"a":"1","b":"2","c":{"y":"8","z":"9"}}"#);
    }

    #[test]
    fn is_independent_of_input_key_order() {
        let first: serde_json::Value =
            serde_json::from_str(r#"{"a":"1","b":{"m":"1","n":"2"}}"#).unwrap();
        let second: serde_json::Value =
            serde_json::from_str(r#"{"b":{"n":"2","m":"1"},"a":"1"}"#).unwrap();
        assert_eq!(
            canonical_json_v1(&first).unwrap(),
            canonical_json_v1(&second).unwrap()
        );
    }

    #[test]
    fn preserves_array_order() {
        let value: serde_json::Value = serde_json::from_str(r#"{"xs":["c","a","b"]}"#).unwrap();
        let canonical = canonical_json_v1(&value).unwrap();
        assert_eq!(canonical, br#"{"xs":["c","a","b"]}"#);
    }

    proptest! {
        #[test]
        fn canonical_json_is_independent_of_object_insertion_order(
            entries in btree_map("[a-z]{1,8}", any::<i64>(), 1..32)
        ) {
            let mut first = serde_json::Map::new();
            for (key, value) in &entries {
                first.insert(key.clone(), json!(value));
            }

            let mut second = serde_json::Map::new();
            for (key, value) in entries.iter().rev() {
                second.insert(key.clone(), json!(value));
            }

            prop_assert_eq!(
                canonical_json_v1(&Value::Object(first)).unwrap(),
                canonical_json_v1(&Value::Object(second)).unwrap()
            );
        }

        #[test]
        fn canonical_json_output_is_parseable(
            entries in btree_map("[a-z]{1,8}", "[A-Za-z0-9 _.-]{0,32}", 0..32)
        ) {
            let value = json!({ "items": entries });
            let canonical = canonical_json_v1(&value).unwrap();
            let parsed: Value = serde_json::from_slice(&canonical).unwrap();

            prop_assert_eq!(parsed, value);
        }
    }
}
