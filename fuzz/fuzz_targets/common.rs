// Shared helpers for fuzz targets that exercise config validation.
// Included with `#[path = "common.rs"] mod common;` — it is not a fuzz target
// itself (not listed as a [[bin]] in Cargo.toml).

use std::path::PathBuf;
use vectis::core::config;

pub fn fuzz_config() -> config::AppConfig {
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

pub fn looks_loaded_kid(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}
