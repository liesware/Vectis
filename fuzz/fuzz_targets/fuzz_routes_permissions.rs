#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

#[path = "common.rs"]
mod common;
use common::validate_fuzz_config_content;

fn strip_public_keys(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.remove("public_keys");
            for item in object.values_mut() {
                strip_public_keys(item);
            }
        }
        Value::Array(items) => {
            for item in items {
                strip_public_keys(item);
            }
        }
        _ => {}
    }
}

fn validate_config_value(value: Value) {
    let Ok(content) = serde_json::to_string(&value) else {
        return;
    };
    let _ = validate_fuzz_config_content(&content);
}

fuzz_target!(|data: &[u8]| {
    let Ok(mut value) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    strip_public_keys(&mut value);

    validate_config_value(value.clone());
    validate_config_value(json!({
        "version": "v1",
        "routes": value.clone(),
    }));
    validate_config_value(json!({
        "version": "v1",
        "remote_routes": value.clone(),
    }));
    validate_config_value(json!({
        "version": "v1",
        "permissions": value,
    }));
});
