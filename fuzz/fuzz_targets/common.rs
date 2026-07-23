// Shared helpers for native fuzz targets.
// Included with `#[path = "common.rs"] mod common;` — it is not a fuzz target
// itself (not listed as a [[bin]] in Cargo.toml).

use std::path::PathBuf;
use vectis::core::{commitments, config, config_file, fpe, mac, sharing, tokenization};
use vectis::error::DynError;
use zeroize::Zeroizing;

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
        postgres_dsn: String::new(),
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

fn dummy_fpe_key() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(vec![0u8; fpe::FPE_KEY_SIZE_BYTES])
}

fn dummy_tokenization_keys() -> tokenization::DerivedTokenizationKeys {
    tokenization::DerivedTokenizationKeys {
        hash_key: Zeroizing::new(vec![0u8; tokenization::TOKEN_KEY_SIZE_BYTES]),
        data_key: Zeroizing::new(vec![1u8; tokenization::TOKEN_KEY_SIZE_BYTES]),
        cipher_algorithm: String::from("AES-256/GCM"),
    }
}

fn dummy_hash_algorithm(_: &str) -> Result<String, DynError> {
    Ok(String::from("BLAKE2b(256)"))
}

fn dummy_mac_key(_: mac::MacKeyDerivationRequest<'_>) -> Result<mac::DerivedMacKey, DynError> {
    Ok(mac::DerivedMacKey {
        public_algorithm: String::from("HMAC(BLAKE2b(256))"),
        botan_algorithm: String::from("HMAC(BLAKE2b(256))"),
        mac_key: Zeroizing::new(vec![0u8; mac::MAC_KEY_SIZE_BYTES]),
    })
}

fn dummy_commitment_key(
    _: commitments::CommitmentKeyDerivationRequest<'_>,
) -> Result<commitments::DerivedCommitmentKey, DynError> {
    Ok(commitments::DerivedCommitmentKey {
        public_algorithm: String::from("HMAC(BLAKE2b(256))"),
        botan_algorithm: String::from("HMAC(BLAKE2b(256))"),
        commit_key: Zeroizing::new(vec![0u8; commitments::COMMITMENT_KEY_SIZE_BYTES]),
    })
}

fn dummy_sharing_key(
    _: sharing::SharingKeyDerivationRequest<'_>,
) -> Result<sharing::DerivedSharingKey, DynError> {
    Ok(sharing::DerivedSharingKey {
        public_algorithm: String::from("HMAC(BLAKE2b(256))"),
        botan_algorithm: String::from("HMAC(BLAKE2b(256))"),
        share_auth_key: Zeroizing::new(vec![0u8; sharing::SHARING_KEY_SIZE_BYTES]),
    })
}

pub fn validate_fuzz_config_content(content: &str) -> Result<config_file::ConfigState, DynError> {
    config_file::validate_config_content(
        content,
        &fuzz_config(),
        looks_loaded_kid,
        |_| Ok(dummy_fpe_key()),
        |_| Ok(dummy_tokenization_keys()),
        dummy_hash_algorithm,
        dummy_mac_key,
        dummy_commitment_key,
        dummy_sharing_key,
    )
}
