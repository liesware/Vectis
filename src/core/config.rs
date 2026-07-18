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
pub const INTERNAL_KEYS_HKDF: &str = "HKDF(BLAKE2b(256))";
pub const INTERNAL_KEYS_HMAC: &str = "HMAC(BLAKE2b(256))";
pub const INTERNAL_KEYS_KMAC: &str = "KMAC-256";
pub const INTERNAL_KEYS_EDDSA_ALGORITHM: &str = "Ed25519";
pub const INTERNAL_KEYS_XECDH_ALGORITHM: &str = "X25519";
pub const INTERNAL_KEYS_ML_DSA_VARIANT: &str = "ML-DSA-44";
pub const INTERNAL_KEYS_ML_KEM_VARIANT: &str = "ML-KEM-512";
pub const INTERNAL_FPE_BATCH: usize = 128;
pub const INTERNAL_TOKEN_BATCH: usize = 128;
pub const INTERNAL_MAC_BATCH: usize = 128;
pub const INTERNAL_REF_MAX_CHARS: usize = 128;
pub const CONFIG_NAME_MAX_CHARS: usize = 128;
pub const FPE_TWEAK_AAD_MAX_CHARS: usize = 128;
pub const CRYPTO_PROFILES: &[&str] = &[
    "hybrid-performance-v1",
    "hybrid-standard-v1",
    "hybrid-high-assurance-v1",
    "hybrid-long-term-v1",
];
pub const CRYPTO_POLICIES: &[&str] = &["profile-only", "allow-overrides"];
pub const HTTP_SCHEMES: &[&str] = &["http", "https"];
pub const VECTIS_MODES: &[&str] = &["dev", "prod"];
pub const DEFAULT_INIT_KEYS_FILE: &str = "init.json";
pub const CONFIG_FILE_MAX_SIZE_BYTES: u64 = 8 * 1024 * 1024;
pub const CONFIG_SIGN_FILE_MAX_SIZE_BYTES: u64 = 1024 * 1024;

#[derive(Clone)]
pub struct AppConfig {
    pub http_bind_addr: SocketAddr,
    pub mode: String,
    pub server_scheme: String,
    pub remote_scheme: String,
    pub final_app_scheme: String,
    pub public_addr: String,
    pub final_app_addr: String,
    pub final_app_path: String,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub tls_skip_verify: bool,
    pub config_path: PathBuf,
    pub config_sign_path: PathBuf,
    pub api_key_hash: String,
    pub protocol_version: String,
    pub storage_type: String,
    pub sqlite_path: PathBuf,
    pub postgres_dsn: String,
    pub sender_hostname: String,
    pub receiver_hostname: String,
    pub default_crypto_profile: String,
    pub crypto_policy: String,
    pub plaintext_message: String,
    pub metrics_enabled: bool,
}

#[cfg(test)]
pub(crate) fn test_app_config() -> AppConfig {
    AppConfig {
        http_bind_addr: "127.0.0.1:0".parse().unwrap(),
        mode: String::from("dev"),
        server_scheme: String::from("http"),
        remote_scheme: String::from("http"),
        final_app_scheme: String::from("http"),
        public_addr: String::from("127.0.0.1:3000"),
        final_app_addr: String::from("localhost:3999"),
        final_app_path: String::from("/message"),
        tls_cert_path: None,
        tls_key_path: None,
        tls_skip_verify: false,
        config_path: PathBuf::from("config.json"),
        config_sign_path: PathBuf::from("config.json.sig"),
        api_key_hash: "a".repeat(64),
        protocol_version: String::from("v1"),
        storage_type: String::from("sqlite"),
        sqlite_path: PathBuf::from("vectis.db"),
        postgres_dsn: String::new(),
        sender_hostname: String::from("node-a"),
        receiver_hostname: String::from("node-b"),
        default_crypto_profile: String::from("hybrid-performance-v1"),
        crypto_policy: String::from("profile-only"),
        plaintext_message: String::from("hello"),
        metrics_enabled: true,
    }
}

pub fn app_config() -> Result<AppConfig, DynError> {
    let env_file = load_env_file(".env")?;
    let http_bind_addr = validation::validate_socket_addr(
        "VECTIS_HTTP_BIND_ADDR",
        &config_value(&env_file, "VECTIS_HTTP_BIND_ADDR", "127.0.0.1:3000"),
    )?;
    let mode = validate_vectis_mode(&config_value(&env_file, "VECTIS_MODE", "dev"))?;
    let server_scheme = transport_scheme_for_mode(&mode).to_string();
    let remote_scheme = transport_scheme_for_mode(&mode).to_string();
    let final_app_scheme = transport_scheme_for_mode(&mode).to_string();
    let public_addr = validation::validate_host_port(
        "VECTIS_PUBLIC_ADDR",
        &config_value(&env_file, "VECTIS_PUBLIC_ADDR", "127.0.0.1:3000"),
    )?;
    let final_app_addr = validation::validate_host_port(
        "VECTIS_FINAL_APP_ADDR",
        &config_value(&env_file, "VECTIS_FINAL_APP_ADDR", "localhost:3999"),
    )?;
    let final_app_path = validate_http_path(&config_value(
        &env_file,
        "VECTIS_FINAL_APP_PATH",
        "/message",
    ))?;
    let tls_cert_path = validate_optional_tls_path(
        "VECTIS_TLS_CERT_PATH",
        &config_value(&env_file, "VECTIS_TLS_CERT_PATH", ""),
    )?;
    let tls_key_path = validate_optional_tls_path(
        "VECTIS_TLS_KEY_PATH",
        &config_value(&env_file, "VECTIS_TLS_KEY_PATH", ""),
    )?;
    let tls_skip_verify = validate_bool_field(
        "VECTIS_TLS_SKIP_VERIFY",
        &config_value(&env_file, "VECTIS_TLS_SKIP_VERIFY", "false"),
    )?;
    let config_path = validate_config_path(
        "VECTIS_CONFIG_PATH",
        &config_value(&env_file, "VECTIS_CONFIG_PATH", "config.json"),
    )?;
    let config_sign_path = validate_config_path(
        "VECTIS_CONFIG_SIGN_PATH",
        &config_value(&env_file, "VECTIS_CONFIG_SIGN_PATH", "config_sign.json"),
    )?;
    let api_key_hash = config_value(&env_file, "VECTIS_APIKEY_HASH", "");
    let protocol_version = config_value(&env_file, "VECTIS_PROTOCOL_VERSION", "v1");
    let storage_type = config_value(&env_file, "VECTIS_STORAGE", "sqlite");
    let sqlite_path_value = config_value(&env_file, "VECTIS_SQLITE_PATH", &default_sqlite_path());
    let postgres_dsn = config_value(&env_file, "VECTIS_POSTGRES_DSN", "");
    let sender_hostname = config_value(&env_file, "VECTIS_SENDER_HOSTNAME", "localhost.local");
    let receiver_hostname = config_value(&env_file, "VECTIS_RECEIVER_HOSTNAME", "remotehost.local");
    let hash_algorithm = config_value(&env_file, "VECTIS_HASH", "BLAKE2b(256)");
    let symmetric_algorithm = config_value(&env_file, "VECTIS_SYMMETRIC", "ChaCha20Poly1305");
    let eddsa_algorithm = config_value(&env_file, "VECTIS_EDDSA", "Ed25519");
    let xecdh_algorithm = config_value(&env_file, "VECTIS_XECDH", "X25519");
    let ml_dsa_variant = config_value(&env_file, "VECTIS_ML_DSA_VARIANT", "ML-DSA-44");
    let ml_kem_variant = config_value(&env_file, "VECTIS_ML_KEM_VARIANT", "ML-KEM-512");
    let default_crypto_profile = config_value(
        &env_file,
        "VECTIS_DEFAULT_CRYPTO_PROFILE",
        "hybrid-performance-v1",
    );
    let crypto_policy = config_value(&env_file, "VECTIS_CRYPTO_POLICY", "profile-only");
    let metrics_enabled = validate_bool_field(
        "VECTIS_METRICS_ENABLED",
        &config_value(&env_file, "VECTIS_METRICS_ENABLED", "true"),
    )?;
    let plaintext_message = config_value(
        &env_file,
        "VECTIS_PLAINTEXT_MESSAGE",
        "You are not special. You are not a beautiful and unique snowflake. You're the same decaying organic matter as everything else.",
    );

    crate::core::protocol::validate_protocol_version("VECTIS_PROTOCOL_VERSION", &protocol_version)?;
    validate_tls_paths_for_mode(&mode, tls_cert_path.as_ref(), tls_key_path.as_ref())?;
    validation::validate_allowed_value(
        "VECTIS_STORAGE",
        &storage_type,
        crate::core::storage::STORAGE_TYPES,
    )?;
    let sqlite_path = if storage_type == "sqlite" {
        validate_sqlite_path(&sqlite_path_value)?
    } else {
        validate_storage_path_text("VECTIS_SQLITE_PATH", &sqlite_path_value)?
    };
    if storage_type == "postgres" {
        validate_postgres_dsn(&postgres_dsn)?;
    }
    if !api_key_hash.is_empty() {
        validation::validate_symmetric_key("VECTIS_APIKEY_HASH", &api_key_hash, 32)?;
    }
    validation::validate_hostname("VECTIS_SENDER_HOSTNAME", &sender_hostname)?;
    validation::validate_hostname("VECTIS_RECEIVER_HOSTNAME", &receiver_hostname)?;
    validation::validate_allowed_value("VECTIS_HASH", &hash_algorithm, crypto::HASH_ALGORITHMS)?;
    validation::validate_allowed_value(
        "VECTIS_SYMMETRIC",
        &symmetric_algorithm,
        crypto::SYMMETRIC_ALGORITHMS,
    )?;
    validation::validate_allowed_value("VECTIS_EDDSA", &eddsa_algorithm, &["Ed25519", "Ed448"])?;
    validation::validate_allowed_value("VECTIS_XECDH", &xecdh_algorithm, &["X25519", "X448"])?;
    validation::validate_allowed_value(
        "VECTIS_ML_DSA_VARIANT",
        &ml_dsa_variant,
        &["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
    )?;
    validation::validate_allowed_value(
        "VECTIS_ML_KEM_VARIANT",
        &ml_kem_variant,
        &["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
    )?;
    validation::validate_allowed_value(
        "VECTIS_DEFAULT_CRYPTO_PROFILE",
        &default_crypto_profile,
        CRYPTO_PROFILES,
    )?;
    validation::validate_allowed_value("VECTIS_CRYPTO_POLICY", &crypto_policy, CRYPTO_POLICIES)?;
    validation::validate_text_field("VECTIS_PLAINTEXT_MESSAGE", &plaintext_message)?;

    Ok(AppConfig {
        http_bind_addr,
        mode,
        server_scheme,
        remote_scheme,
        final_app_scheme,
        public_addr,
        final_app_addr,
        final_app_path,
        tls_cert_path,
        tls_key_path,
        tls_skip_verify,
        config_path,
        config_sign_path,
        api_key_hash,
        protocol_version,
        storage_type,
        sqlite_path,
        postgres_dsn,
        sender_hostname,
        receiver_hostname,
        default_crypto_profile,
        crypto_policy,
        plaintext_message,
        metrics_enabled,
    })
}

pub struct HttpClientConfig {
    pub mode: String,
    pub remote_scheme: String,
    pub final_app_scheme: String,
    pub tls_skip_verify: bool,
}

pub fn http_client_config() -> Result<HttpClientConfig, DynError> {
    let env_file = load_env_file(".env")?;
    let mode = validate_vectis_mode(&config_value(&env_file, "VECTIS_MODE", "dev"))?;
    let remote_scheme = transport_scheme_for_mode(&mode).to_string();
    let final_app_scheme = transport_scheme_for_mode(&mode).to_string();
    let tls_skip_verify = validate_bool_field(
        "VECTIS_TLS_SKIP_VERIFY",
        &config_value(&env_file, "VECTIS_TLS_SKIP_VERIFY", "false"),
    )?;

    Ok(HttpClientConfig {
        mode,
        remote_scheme,
        final_app_scheme,
        tls_skip_verify,
    })
}

pub fn init_keys_file_path() -> Result<PathBuf, DynError> {
    let env_file = load_env_file(".env")?;

    validate_config_path(
        "VECTIS_INIT_KEYS_FILE",
        &config_value(&env_file, "VECTIS_INIT_KEYS_FILE", DEFAULT_INIT_KEYS_FILE),
    )
}

pub fn validate_vectis_mode(value: &str) -> Result<String, DynError> {
    validation::validate_allowed_value("VECTIS_MODE", value, VECTIS_MODES)?;

    Ok(value.to_string())
}

pub fn transport_scheme_for_mode(mode: &str) -> &'static str {
    match mode {
        "prod" => "https",
        _ => "http",
    }
}

fn validate_tls_paths_for_mode(
    mode: &str,
    tls_cert_path: Option<&PathBuf>,
    tls_key_path: Option<&PathBuf>,
) -> Result<(), DynError> {
    if mode == "prod" && (tls_cert_path.is_none() || tls_key_path.is_none()) {
        return Err(crate::error::invalid_input(
            "VECTIS_TLS_CERT_PATH and VECTIS_TLS_KEY_PATH are required when VECTIS_MODE=prod",
        ));
    }

    Ok(())
}

pub fn validate_http_scheme(value: &str) -> Result<String, DynError> {
    validation::validate_allowed_value("HTTP scheme", value, HTTP_SCHEMES)?;

    Ok(value.to_string())
}

pub fn validate_http_path_field(field: &str, value: &str) -> Result<String, DynError> {
    validation::validate_text_field(field, value)?;

    if !value.starts_with('/') {
        return Err(crate::error::invalid_input(format!(
            "{field} must start with /"
        )));
    }

    if value.contains(' ') {
        return Err(crate::error::invalid_input(format!(
            "{field} must not contain spaces"
        )));
    }

    Ok(value.to_string())
}

fn validate_http_path(value: &str) -> Result<String, DynError> {
    validate_http_path_field("VECTIS_FINAL_APP_PATH", value)
}

fn validate_optional_tls_path(field: &str, value: &str) -> Result<Option<PathBuf>, DynError> {
    if value.trim().is_empty() {
        return Ok(None);
    }

    validation::validate_text_field(field, value)?;
    let path = PathBuf::from(value);
    let metadata = fs::metadata(&path).map_err(|err| {
        crate::error::invalid_input(format!("{field} must exist and be readable: {err}"))
    })?;

    if !metadata.is_file() {
        return Err(crate::error::invalid_input(format!(
            "{field} must point to a file"
        )));
    }

    fs::OpenOptions::new()
        .read(true)
        .open(&path)
        .map_err(|err| crate::error::forbidden(format!("{field} must allow read access: {err}")))?;

    Ok(Some(path))
}

pub fn validate_bool_field(field: &str, value: &str) -> Result<bool, DynError> {
    validation::validate_allowed_value(field, value, &["true", "false"])?;

    Ok(value == "true")
}

fn validate_config_path(field: &str, value: &str) -> Result<PathBuf, DynError> {
    validation::validate_text_field(field, value)?;

    Ok(PathBuf::from(value))
}

fn validate_storage_path_text(field: &str, value: &str) -> Result<PathBuf, DynError> {
    validation::validate_text_field(field, value)?;

    Ok(PathBuf::from(value))
}

fn validate_postgres_dsn(value: &str) -> Result<(), DynError> {
    validation::validate_text_field("VECTIS_POSTGRES_DSN", value)?;

    if !(value.starts_with("postgres://") || value.starts_with("postgresql://")) {
        return Err(crate::error::invalid_input(
            "VECTIS_POSTGRES_DSN must start with postgres:// or postgresql://",
        ));
    }

    Ok(())
}

fn validate_sqlite_path(value: &str) -> Result<PathBuf, DynError> {
    validation::validate_text_field("VECTIS_SQLITE_PATH", value)?;

    let path = PathBuf::from(value);
    let metadata = fs::metadata(&path).map_err(|err| {
        crate::error::invalid_input(format!(
            "VECTIS_SQLITE_PATH must exist and be readable: {err}"
        ))
    })?;

    if !metadata.is_file() {
        return Err(crate::error::invalid_input(
            "VECTIS_SQLITE_PATH must point to a file",
        ));
    }

    if metadata.permissions().readonly() {
        return Err(crate::error::forbidden(
            "VECTIS_SQLITE_PATH must be writable",
        ));
    }

    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|err| {
            crate::error::forbidden(format!(
                "VECTIS_SQLITE_PATH must allow read/write access: {err}"
            ))
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

pub fn load_env_file(path: &str) -> Result<HashMap<String, String>, DynError> {
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

pub fn config_value(env_file: &HashMap<String, String>, key: &str, default: &str) -> String {
    env::var(key)
        .ok()
        .or_else(|| env_file.get(key).cloned())
        .unwrap_or_else(|| default.to_string())
}

pub fn clean_env_value(value: &str) -> String {
    let quoted = (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\''));

    if quoted && value.len() >= 2 {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn dev_mode_uses_http() {
        let mode = validate_vectis_mode("dev").expect("dev mode must be valid");

        assert_eq!(transport_scheme_for_mode(&mode), "http");
    }

    #[test]
    fn prod_mode_uses_https() {
        let mode = validate_vectis_mode("prod").expect("prod mode must be valid");

        assert_eq!(transport_scheme_for_mode(&mode), "https");
    }

    #[test]
    fn invalid_mode_is_rejected() {
        assert!(validate_vectis_mode("staging").is_err());
    }

    #[test]
    fn prod_mode_requires_tls_cert_and_key_paths() {
        assert!(validate_tls_paths_for_mode("prod", None, None).is_err());
        assert!(
            validate_tls_paths_for_mode("prod", Some(&PathBuf::from("cert.pem")), None).is_err()
        );
        assert!(
            validate_tls_paths_for_mode("prod", None, Some(&PathBuf::from("key.pem"))).is_err()
        );
        assert!(
            validate_tls_paths_for_mode(
                "prod",
                Some(&PathBuf::from("cert.pem")),
                Some(&PathBuf::from("key.pem")),
            )
            .is_ok()
        );
    }

    #[test]
    fn dev_mode_does_not_require_tls_cert_or_key_paths() {
        assert!(validate_tls_paths_for_mode("dev", None, None).is_ok());
    }

    proptest! {
        #[test]
        fn validate_bool_field_accepts_only_true_or_false(value in "[A-Za-z0-9_-]{0,16}") {
            let result = validate_bool_field("flag", &value);

            prop_assert_eq!(result.is_ok(), matches!(value.as_str(), "true" | "false"));
            if value == "true" {
                prop_assert_eq!(result.unwrap(), true);
            } else if value == "false" {
                prop_assert_eq!(result.unwrap(), false);
            }
        }

        #[test]
        fn validate_http_scheme_accepts_only_http_or_https(value in "[A-Za-z0-9+.-]{0,16}") {
            let result = validate_http_scheme(&value);

            prop_assert_eq!(result.is_ok(), matches!(value.as_str(), "http" | "https"));
        }

        #[test]
        fn validate_vectis_mode_accepts_only_dev_or_prod(value in "[A-Za-z0-9_-]{0,16}") {
            let result = validate_vectis_mode(&value);

            prop_assert_eq!(result.is_ok(), matches!(value.as_str(), "dev" | "prod"));
        }

        #[test]
        fn validate_http_path_field_accepts_simple_absolute_paths(path in "/[A-Za-z0-9_./-]{0,63}") {
            prop_assert!(validate_http_path_field("path", &path).is_ok());
        }

        #[test]
        fn validate_http_path_field_rejects_invalid_shapes(value in "[A-Za-z0-9_./:-]{0,64}") {
            let invalid = [
                String::new(),
                value.clone(),
                format!("http://{value}"),
                format!("https://{value}"),
                format!("/{value} path"),
                format!("/{value}\n"),
            ];

            for item in invalid {
                if !item.is_empty() && item.starts_with('/') && !item.contains(' ') && !item.chars().any(char::is_control) {
                    continue;
                }
                prop_assert!(validate_http_path_field("path", &item).is_err());
            }
        }
    }
}
