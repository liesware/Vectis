#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};
use std::path::PathBuf;
use vectis::core::{config, config_file};

fn fuzz_config() -> config::AppConfig {
    config::AppConfig {
        http_bind_addr: "127.0.0.1:3000".parse().unwrap(),
        mode: String::from("dev"),
        server_scheme: String::from("http"),
        remote_scheme: String::from("http"),
        final_app_scheme: String::from("http"),
        public_addr: String::from("127.0.0.1:3000"),
        final_app_addr: String::from("127.0.0.1:3999"),
        final_app_path: String::from("/message"),
        tls_cert_path: None,
        tls_key_path: None,
        tls_skip_verify: false,
        config_path: PathBuf::from("config.json"),
        config_sign_path: PathBuf::from("config_sign.json"),
        api_key_hash: String::new(),
        protocol_version: String::from("v1"),
        storage_type: String::from("sqlite"),
        sqlite_path: PathBuf::from("data.db"),
        sender_hostname: String::from("sender.local"),
        receiver_hostname: String::from("receiver.local"),
        default_crypto_profile: String::from("hybrid-performance-v1"),
        crypto_policy: String::from("profile-only"),
        plaintext_message: String::new(),
        metrics_enabled: true,
    }
}

fn looks_loaded_kid(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

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
    let _ = config_file::validate_config_content(&content, &fuzz_config(), looks_loaded_kid);
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
