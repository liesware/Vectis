use crate::core::{crypto, validation};
use crate::error::DynError;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

pub const INTERNAL_KEYS_CIPHER: &str = "AES-256/GCM";
pub const INTERNAL_KEYS_KEY_SIZE_BYTES: usize = 32;
pub const INTERNAL_KEYS_NONCE_SIZE_BYTES: usize = 12;
pub const INTERNAL_KEYS_HASH: &str = "BLAKE2b(256)";
pub const INTERNAL_KEYS_EDDSA_ALGORITHM: &str = "Ed25519";
pub const INTERNAL_KEYS_XECDH_ALGORITHM: &str = "X25519";
pub const INTERNAL_KEYS_ML_DSA_VARIANT: &str = "ML-DSA-44";
pub const INTERNAL_KEYS_ML_KEM_VARIANT: &str = "ML-KEM-512";

pub struct AppConfig {
    pub http_bind_addr: SocketAddr,
    pub public_addr: String,
    pub final_app_addr: String,
    pub final_app_path: String,
    pub routes_path: PathBuf,
    pub api_key: String,
    pub protocol_version: String,
    pub storage_type: String,
    pub sqlite_path: PathBuf,
    pub sender_hostname: String,
    pub receiver_hostname: String,
    pub hash_algorithm: String,
    pub symmetric_algorithm: String,
    pub eddsa_algorithm: String,
    pub xecdh_algorithm: String,
    pub ml_dsa_variant: String,
    pub ml_kem_variant: String,
    pub plaintext_message: String,
}

pub fn app_config() -> Result<AppConfig, DynError> {
    let env_file = load_env_file(".env")?;
    let http_bind_addr = validation::validate_socket_addr(
        "HTTP_BIND_ADDR",
        &config_value(&env_file, "HTTP_BIND_ADDR", "127.0.0.1:3000"),
    )?;
    let public_addr = validation::validate_host_port(
        "PUBLIC_ADDR",
        &config_value(&env_file, "PUBLIC_ADDR", "127.0.0.1:3000"),
    )?;
    let final_app_addr = validation::validate_host_port(
        "FINAL_APP_ADDR",
        &config_value(&env_file, "FINAL_APP_ADDR", "localhost:3999"),
    )?;
    let final_app_path =
        validate_http_path(&config_value(&env_file, "FINAL_APP_PATH", "/message"))?;
    let routes_path = validate_routes_path(&config_value(&env_file, "ROUTES_PATH", "routes.json"))?;
    let api_key = config_value(&env_file, "APIKEY", "");
    let protocol_version = config_value(&env_file, "PROTOCOL_VERSION", "v1");
    let storage_type = config_value(&env_file, "STORAGE", "sqlite");
    let sqlite_path = validate_sqlite_path(&config_value(
        &env_file,
        "SQLITE_PATH",
        &default_sqlite_path(),
    ))?;
    let sender_hostname = config_value(&env_file, "SENDER_HOSTNAME", "localhost.local");
    let receiver_hostname = config_value(&env_file, "RECEIVER_HOSTNAME", "remotehost.local");
    let hash_algorithm = config_value(&env_file, "HASH", "BLAKE2b(512)");
    let symmetric_algorithm = config_value(&env_file, "SYMMETRIC", "ChaCha20Poly1305");
    let eddsa_algorithm = config_value(&env_file, "EDDSA", "Ed25519");
    let xecdh_algorithm = config_value(&env_file, "XECDH", "X25519");
    let ml_dsa_variant = config_value(&env_file, "ML_DSA_VARIANT", "ML-DSA-44");
    let ml_kem_variant = config_value(&env_file, "ML_KEM_VARIANT", "ML-KEM-512");
    let plaintext_message = config_value(
        &env_file,
        "PLAINTEXT_MESSAGE",
        "You are not special. You are not a beautiful and unique snowflake. You're the same decaying organic matter as everything else.",
    );

    validation::validate_allowed_value("PROTOCOL_VERSION", &protocol_version, &["v1"])?;
    validation::validate_allowed_value(
        "STORAGE",
        &storage_type,
        crate::core::storage::STORAGE_TYPES,
    )?;
    if !api_key.is_empty() {
        validation::validate_hash_hex_field("APIKEY", &api_key, INTERNAL_KEYS_HASH)?;
    }
    validation::validate_hostname("SENDER_HOSTNAME", &sender_hostname)?;
    validation::validate_hostname("RECEIVER_HOSTNAME", &receiver_hostname)?;
    validation::validate_allowed_value("HASH", &hash_algorithm, crypto::HASH_ALGORITHMS)?;
    validation::validate_allowed_value(
        "SYMMETRIC",
        &symmetric_algorithm,
        crypto::SYMMETRIC_ALGORITHMS,
    )?;
    validation::validate_allowed_value("EDDSA", &eddsa_algorithm, &["Ed25519", "Ed448"])?;
    validation::validate_allowed_value("XECDH", &xecdh_algorithm, &["X25519", "X448"])?;
    validation::validate_allowed_value(
        "ML_DSA_VARIANT",
        &ml_dsa_variant,
        &["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
    )?;
    validation::validate_allowed_value(
        "ML_KEM_VARIANT",
        &ml_kem_variant,
        &["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
    )?;
    validation::validate_text_field("PLAINTEXT_MESSAGE", &plaintext_message)?;

    Ok(AppConfig {
        http_bind_addr,
        public_addr,
        final_app_addr,
        final_app_path,
        routes_path,
        api_key,
        protocol_version,
        storage_type,
        sqlite_path,
        sender_hostname,
        receiver_hostname,
        hash_algorithm,
        symmetric_algorithm,
        eddsa_algorithm,
        xecdh_algorithm,
        ml_dsa_variant,
        ml_kem_variant,
        plaintext_message,
    })
}

pub fn validate_http_path_field(field: &str, value: &str) -> Result<String, DynError> {
    validation::validate_text_field(field, value)?;

    if !value.starts_with('/') {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{field} must start with /"),
        )));
    }

    if value.contains(' ') {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{field} must not contain spaces"),
        )));
    }

    Ok(value.to_string())
}

fn validate_http_path(value: &str) -> Result<String, DynError> {
    validate_http_path_field("FINAL_APP_PATH", value)
}

fn validate_routes_path(value: &str) -> Result<PathBuf, DynError> {
    validation::validate_text_field("ROUTES_PATH", value)?;

    Ok(PathBuf::from(value))
}

fn validate_sqlite_path(value: &str) -> Result<PathBuf, DynError> {
    validation::validate_text_field("SQLITE_PATH", value)?;

    let path = PathBuf::from(value);
    let metadata = fs::metadata(&path).map_err(|err| {
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("SQLITE_PATH must exist and be readable: {err}"),
        )) as DynError
    })?;

    if !metadata.is_file() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "SQLITE_PATH must point to a file",
        )));
    }

    if metadata.permissions().readonly() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "SQLITE_PATH must be writable",
        )));
    }

    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|err| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("SQLITE_PATH must allow read/write access: {err}"),
            )) as DynError
        })?;

    Ok(path)
}

fn default_sqlite_path() -> String {
    if cfg!(debug_assertions) {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("db")
            .join("data.db")
            .display()
            .to_string()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| Path::new(".").to_path_buf())
            .join("db")
            .join("data.db")
            .display()
            .to_string()
    }
}

fn load_env_file(path: &str) -> Result<HashMap<String, String>, DynError> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(err) => return Err(Box::new(err)),
    };

    let mut values = HashMap::new();

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        let key = key.trim();
        let value = clean_env_value(value.trim());

        values.insert(key.to_string(), value);
    }

    Ok(values)
}

fn config_value(env_file: &HashMap<String, String>, key: &str, default: &str) -> String {
    env::var(key)
        .ok()
        .or_else(|| env_file.get(key).cloned())
        .unwrap_or_else(|| default.to_string())
}

fn clean_env_value(value: &str) -> String {
    let quoted = (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\''));

    if quoted && value.len() >= 2 {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}
