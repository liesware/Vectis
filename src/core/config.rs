use crate::core::config_loader::ConfigLoader;
pub use crate::core::config_loader::{
    ENV_FILE_MAX_SIZE_BYTES, ENV_NAME_MAX_SIZE_BYTES, ENV_VALUE_MAX_SIZE_BYTES,
};
use crate::core::{crypto, validation};
use crate::error::DynError;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use zeroize::Zeroizing;

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
pub const INTERNAL_ROOT_KEY_HKDF_SALT: &[u8] = b"vectis/internal-keys/v1";
pub const INTERNAL_SLH_DSA_VARIANT: &str = "SLH-DSA-SHAKE-256s";
pub const INTERNAL_SLH_DSA_ARTIFACT_HASH: &str = "SHA-3(512)";
pub const INTERNAL_SLH_DSA_SIGN_MODE: &str = "Randomized";
pub const SLH_DSA_FILE_KEY_INFO: &[u8] = b"vectis/slh-dsa-file-key/v1";
pub const INTERNAL_FPE_BATCH: usize = 128;
pub const INTERNAL_TOKEN_BATCH: usize = 128;
pub const INTERNAL_TOKEN_DETERMINISTIC_BATCH: usize = 128;
pub const INTERNAL_MAC_BATCH: usize = 128;
pub const INTERNAL_INDEX_BATCH: usize = 128;
pub const INTERNAL_MASK_BATCH: usize = 128;
pub const INTERNAL_COMMIT_BATCH: usize = 128;
pub const INTERNAL_SHARE_MAX: usize = 32;
pub const INTERNAL_REF_MAX_CHARS: usize = 128;
pub const INTERNAL_HTTP_MAX_SIZE: usize = 2 * 1024 * 1024;
pub const INTERNAL_MESSAGE_PLAINTEXT_MAX_SIZE: usize = (1024 * 1024) - 1024;
pub const INTERNAL_HTTP_GRACE_SEC: u64 = 30;
pub const INTERNAL_HTTP_TIMEOUT_SEC: u64 = 30;
pub const DEFAULT_MAX_QUEUED_CRYPTO: usize = 128;
pub const DEFAULT_CRYPTO_QUEUE_TIMEOUT_MS: u64 = 1000;
pub const MAX_CRYPTO_QUEUE_TIMEOUT_MS: u64 = 30_000;
pub const INTERNAL_TIME_ATTEST_TIMEOUT_SEC: u64 = 5;
pub const INTERNAL_TIME_ATTEST_MIN_INTERVAL_US: i64 = 1_000_000;
pub const INTERNAL_TIME_ATTEST_MAX_ROUGHTIME_RESPONSE_BYTES: usize = 4096;
pub const STORAGE_ENVELOPE_MAX_CHARS: usize = 32_768;
pub const STORAGE_TOKEN_ENVELOPE_MAX_CHARS: usize = 131_072;
pub const TOKEN_DECODE_BATCH_MAX_ENVELOPE_BYTES: usize = 5 * 1024 * 1024;
pub const STORAGE_INDEX_DIGEST_MAX_CHARS: usize = 128;
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
pub const DEFAULT_INIT_PUBLIC_KEYS_FILE: &str = "init_pub.json";
pub const CONFIG_FILE_MAX_SIZE_BYTES: u64 = 8 * 1024 * 1024;
pub const CONFIG_SIGN_FILE_MAX_SIZE_BYTES: u64 = 1024 * 1024;
pub const INIT_KEYS_FILE_MAX_SIZE_BYTES: u64 = 64 * 1024;
pub const INIT_PUBLIC_KEYS_FILE_MAX_SIZE_BYTES: u64 = 64 * 1024;
pub const UNSEAL_KEY_FILE_MAX_SIZE_BYTES: u64 = 1024;
pub const SLH_DSA_PRIVATE_FILE_MAX_SIZE_BYTES: u64 = 64 * 1024;
pub const SLH_DSA_PUBLIC_FILE_MAX_SIZE_BYTES: u64 = 64 * 1024;
pub const SLH_DSA_SIGNATURE_FILE_MAX_SIZE_BYTES: u64 = 128 * 1024;
pub const AUDIT_CHAIN_RECORD_MAX_BYTES: usize = 16 * 1024;
pub const AUDIT_CHAIN_REASON_MAX_CHARS: usize = 256;
pub const AUDIT_CHAIN_CHANNEL_CAPACITY: usize = 1024;
pub const AUDIT_GROUP_COMMIT_MAX_COMMANDS: usize = 256;
pub const AUDIT_CHECKPOINT_EVENT_COUNT: u64 = 10_000;

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
    pub api_key_hash: Zeroizing<String>,
    pub protocol_version: String,
    pub storage_type: String,
    pub sqlite_path: PathBuf,
    pub postgres_dsn: Zeroizing<String>,
    pub sender_hostname: String,
    pub receiver_hostname: String,
    pub default_crypto_profile: String,
    pub crypto_policy: String,
    pub plaintext_message: Zeroizing<String>,
    pub metrics_enabled: bool,
    pub max_concurrent_crypto: usize,
    pub max_queued_crypto: usize,
    pub crypto_queue_timeout: std::time::Duration,
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
        api_key_hash: Zeroizing::new("a".repeat(64)),
        protocol_version: String::from("v1"),
        storage_type: String::from("sqlite"),
        sqlite_path: PathBuf::from("vectis.db"),
        postgres_dsn: Zeroizing::new(String::new()),
        sender_hostname: String::from("node-a"),
        receiver_hostname: String::from("node-b"),
        default_crypto_profile: String::from("hybrid-performance-v1"),
        crypto_policy: String::from("profile-only"),
        plaintext_message: Zeroizing::new(String::from("hello")),
        metrics_enabled: true,
        max_concurrent_crypto: 8,
        max_queued_crypto: DEFAULT_MAX_QUEUED_CRYPTO,
        crypto_queue_timeout: std::time::Duration::from_millis(DEFAULT_CRYPTO_QUEUE_TIMEOUT_MS),
    }
}

fn parse_max_concurrent_crypto(
    value: &str,
    default: impl FnOnce() -> usize,
) -> Result<usize, DynError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(default());
    }
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(crate::error::invalid_input(
            "VECTIS_MAX_CONCURRENT_CRYPTO must be a positive integer",
        ));
    }
    let parsed: usize = value.parse().map_err(|_| {
        crate::error::invalid_input("VECTIS_MAX_CONCURRENT_CRYPTO must be a positive integer")
    })?;
    if parsed == 0 {
        return Err(crate::error::invalid_input(
            "VECTIS_MAX_CONCURRENT_CRYPTO must be greater than zero",
        ));
    }
    if parsed > tokio::sync::Semaphore::MAX_PERMITS {
        return Err(crate::error::invalid_input(
            "VECTIS_MAX_CONCURRENT_CRYPTO exceeds the maximum supported value",
        ));
    }
    Ok(parsed)
}

fn parse_max_queued_crypto(value: &str) -> Result<usize, DynError> {
    let value = value.trim();
    let parsed: usize = value.parse().map_err(|_| {
        crate::error::invalid_input("VECTIS_MAX_QUEUED_CRYPTO must be a non-negative integer")
    })?;
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || parsed > tokio::sync::Semaphore::MAX_PERMITS
    {
        return Err(crate::error::invalid_input(
            "VECTIS_MAX_QUEUED_CRYPTO must be between 0 and the semaphore maximum",
        ));
    }
    Ok(parsed)
}

fn parse_crypto_queue_timeout(value: &str) -> Result<std::time::Duration, DynError> {
    let value = value.trim();
    let parsed: u64 = value.parse().map_err(|_| {
        crate::error::invalid_input("VECTIS_CRYPTO_QUEUE_TIMEOUT_MS must be a positive integer")
    })?;
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || !(1..=MAX_CRYPTO_QUEUE_TIMEOUT_MS).contains(&parsed)
    {
        return Err(crate::error::invalid_input(
            "VECTIS_CRYPTO_QUEUE_TIMEOUT_MS must be between 1 and 30000",
        ));
    }
    let duration = std::time::Duration::from_millis(parsed);
    std::time::Instant::now()
        .checked_add(duration)
        .ok_or_else(|| {
            crate::error::invalid_input(
                "VECTIS_CRYPTO_QUEUE_TIMEOUT_MS exceeds the supported duration",
            )
        })?;
    Ok(duration)
}

/// Only the defaults consumed while validating a signed config file.
pub struct LocalConfigSettings {
    pub config_path: PathBuf,
    pub config_sign_path: PathBuf,
    pub final_app_addr: String,
    pub final_app_path: String,
}

/// Storage selection is typed so an inactive backend cannot be used accidentally.
pub enum StorageConfig {
    Sqlite(PathBuf),
    Postgres(Zeroizing<String>),
}

pub struct NodeConfigSettings {
    pub local: LocalConfigSettings,
    pub storage: StorageConfig,
}

pub struct BootstrapConfig {
    pub protocol_version: String,
    pub sender_hostname: String,
    pub receiver_hostname: String,
    pub plaintext_message: Zeroizing<String>,
}

impl AppConfig {
    pub fn bootstrap_settings(&self) -> BootstrapConfig {
        BootstrapConfig {
            protocol_version: self.protocol_version.clone(),
            sender_hostname: self.sender_hostname.clone(),
            receiver_hostname: self.receiver_hostname.clone(),
            plaintext_message: self.plaintext_message.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoAdmissionConfig {
    pub max_concurrent_crypto: usize,
    pub max_queued_crypto: usize,
    pub crypto_queue_timeout: std::time::Duration,
}

impl CryptoAdmissionConfig {
    pub const MAX_PERMITS: usize = tokio::sync::Semaphore::MAX_PERMITS;
}

pub fn crypto_admission_config(loader: &ConfigLoader) -> Result<CryptoAdmissionConfig, DynError> {
    let max_concurrent_crypto = loader.parse(
        "VECTIS_MAX_CONCURRENT_CRYPTO",
        "must be empty or a positive integer within the semaphore maximum",
        |value| parse_max_concurrent_crypto(value, || loader.default_crypto_concurrency()),
    )?;
    let max_queued_crypto = loader.parse(
        "VECTIS_MAX_QUEUED_CRYPTO",
        "must be an integer between 0 and the semaphore maximum",
        parse_max_queued_crypto,
    )?;
    let crypto_queue_timeout = loader.parse(
        "VECTIS_CRYPTO_QUEUE_TIMEOUT_MS",
        "must be an integer between 1 and 30000",
        parse_crypto_queue_timeout,
    )?;
    Ok(CryptoAdmissionConfig {
        max_concurrent_crypto,
        max_queued_crypto,
        crypto_queue_timeout,
    })
}

pub fn app_config(loader: &ConfigLoader) -> Result<AppConfig, DynError> {
    let local = local_config(loader)?;
    let bootstrap = bootstrap_config(loader)?;
    let http_bind_addr =
        loader.parse("VECTIS_HTTP_BIND_ADDR", "must be a socket address", |v| {
            validation::validate_socket_addr("VECTIS_HTTP_BIND_ADDR", v)
        })?;
    let mode = loader.parse("VECTIS_MODE", "must be dev or prod", validate_vectis_mode)?;
    let server_scheme = transport_scheme_for_mode(&mode).to_owned();
    let tls_cert_path = loader.parse(
        "VECTIS_TLS_CERT_PATH",
        "must be an optional readable certificate file",
        |v| validate_optional_tls_path("VECTIS_TLS_CERT_PATH", v),
    )?;
    let tls_key_path = loader.parse(
        "VECTIS_TLS_KEY_PATH",
        "must be an optional readable key file",
        |v| validate_optional_tls_path("VECTIS_TLS_KEY_PATH", v),
    )?;
    validate_tls_paths_for_mode(&mode, tls_cert_path.as_ref(), tls_key_path.as_ref()).map_err(
        |_| {
            loader.error(
                if tls_cert_path.is_none() {
                    "VECTIS_TLS_CERT_PATH"
                } else {
                    "VECTIS_TLS_KEY_PATH"
                },
                "required in prod",
            )
        },
    )?;
    let tls_skip_verify = loader.parse("VECTIS_TLS_SKIP_VERIFY", "must be true or false", |v| {
        validate_bool_field("VECTIS_TLS_SKIP_VERIFY", v)
    })?;
    let (storage_type, sqlite_path, postgres_dsn) = match storage_config(loader)? {
        StorageConfig::Sqlite(path) => ("sqlite".into(), path, Zeroizing::new(String::new())),
        StorageConfig::Postgres(dsn) => ("postgres".into(), PathBuf::new(), dsn),
    };
    let api_key_hash = loader.parse(
        "VECTIS_APIKEY_HASH",
        "must be empty or a 32-byte hex hash",
        |v| {
            if !v.is_empty() {
                validation::validate_symmetric_key("VECTIS_APIKEY_HASH", v, 32)?;
            }
            Ok(Zeroizing::new(v.to_owned()))
        },
    )?;
    let public_addr = loader.parse("VECTIS_PUBLIC_ADDR", "must be host:port", |v| {
        validation::validate_host_port("VECTIS_PUBLIC_ADDR", v)
    })?;
    let default_crypto_profile = loader.parse(
        "VECTIS_DEFAULT_CRYPTO_PROFILE",
        "unsupported crypto profile",
        |v| {
            validation::validate_allowed_value(
                "VECTIS_DEFAULT_CRYPTO_PROFILE",
                v,
                CRYPTO_PROFILES,
            )?;
            Ok(v.to_owned())
        },
    )?;
    let crypto_policy = loader.parse("VECTIS_CRYPTO_POLICY", "unsupported crypto policy", |v| {
        validation::validate_allowed_value("VECTIS_CRYPTO_POLICY", v, CRYPTO_POLICIES)?;
        Ok(v.to_owned())
    })?;
    let metrics_enabled = loader.parse("VECTIS_METRICS_ENABLED", "must be true or false", |v| {
        validate_bool_field("VECTIS_METRICS_ENABLED", v)
    })?;
    let admission = crypto_admission_config(loader)?;
    for (name, allowed) in [
        ("VECTIS_HASH", crypto::HASH_ALGORITHMS),
        ("VECTIS_SYMMETRIC", crypto::SYMMETRIC_ALGORITHMS),
        ("VECTIS_EDDSA", &["Ed25519", "Ed448"][..]),
        ("VECTIS_XECDH", &["X25519", "X448"][..]),
        (
            "VECTIS_ML_DSA_VARIANT",
            &["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"][..],
        ),
        (
            "VECTIS_ML_KEM_VARIANT",
            &["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"][..],
        ),
    ] {
        loader.parse(name, "unsupported algorithm", |v| {
            validation::validate_allowed_value(name, v, allowed)
        })?;
    }
    Ok(AppConfig {
        http_bind_addr,
        mode,
        remote_scheme: server_scheme.clone(),
        final_app_scheme: server_scheme.clone(),
        server_scheme,
        public_addr,
        final_app_addr: local.final_app_addr,
        final_app_path: local.final_app_path,
        tls_cert_path,
        tls_key_path,
        tls_skip_verify,
        config_path: local.config_path,
        config_sign_path: local.config_sign_path,
        api_key_hash,
        protocol_version: bootstrap.protocol_version,
        storage_type,
        sqlite_path,
        postgres_dsn,
        sender_hostname: bootstrap.sender_hostname,
        receiver_hostname: bootstrap.receiver_hostname,
        default_crypto_profile,
        crypto_policy,
        plaintext_message: bootstrap.plaintext_message,
        metrics_enabled,
        max_concurrent_crypto: admission.max_concurrent_crypto,
        max_queued_crypto: admission.max_queued_crypto,
        crypto_queue_timeout: admission.crypto_queue_timeout,
    })
}

pub fn local_config(loader: &ConfigLoader) -> Result<LocalConfigSettings, DynError> {
    Ok(LocalConfigSettings {
        config_path: configured_path(loader, "VECTIS_CONFIG_PATH")?,
        config_sign_path: configured_path(loader, "VECTIS_CONFIG_SIGN_PATH")?,
        final_app_addr: loader.parse("VECTIS_FINAL_APP_ADDR", "must be host:port", |v| {
            validation::validate_host_port("VECTIS_FINAL_APP_ADDR", v)
        })?,
        final_app_path: loader.parse(
            "VECTIS_FINAL_APP_PATH",
            "must be an HTTP path",
            validate_http_path,
        )?,
    })
}

pub fn bootstrap_config(loader: &ConfigLoader) -> Result<BootstrapConfig, DynError> {
    Ok(BootstrapConfig {
        protocol_version: loader.parse(
            "VECTIS_PROTOCOL_VERSION",
            "unsupported protocol version",
            |v| {
                crate::core::protocol::validate_protocol_version("VECTIS_PROTOCOL_VERSION", v)?;
                Ok(v.to_owned())
            },
        )?,
        sender_hostname: loader.parse("VECTIS_SENDER_HOSTNAME", "must be a hostname", |v| {
            validation::validate_hostname("VECTIS_SENDER_HOSTNAME", v)?;
            Ok(v.to_owned())
        })?,
        receiver_hostname: loader.parse("VECTIS_RECEIVER_HOSTNAME", "must be a hostname", |v| {
            validation::validate_hostname("VECTIS_RECEIVER_HOSTNAME", v)?;
            Ok(v.to_owned())
        })?,
        plaintext_message: loader.parse(
            "VECTIS_PLAINTEXT_MESSAGE",
            "must be nonempty text without controls",
            |v| {
                validation::validate_text_field("VECTIS_PLAINTEXT_MESSAGE", v)?;
                Ok(Zeroizing::new(v.to_owned()))
            },
        )?,
    })
}

pub fn node_config(loader: &ConfigLoader) -> Result<NodeConfigSettings, DynError> {
    Ok(NodeConfigSettings {
        local: local_config(loader)?,
        storage: storage_config(loader)?,
    })
}

pub fn storage_config(loader: &ConfigLoader) -> Result<StorageConfig, DynError> {
    let storage = loader.parse("VECTIS_STORAGE", "must be sqlite or postgres", |v| {
        validation::validate_allowed_value(
            "VECTIS_STORAGE",
            v,
            crate::core::storage::STORAGE_TYPES,
        )?;
        Ok(v.to_owned())
    })?;
    if storage == "sqlite" {
        loader
            .parse(
                "VECTIS_SQLITE_PATH",
                "must be an existing readable writable SQLite file",
                validate_sqlite_path,
            )
            .map(StorageConfig::Sqlite)
    } else {
        loader
            .parse(
                "VECTIS_POSTGRES_DSN",
                "must be a valid PostgreSQL DSN",
                |v| {
                    validate_postgres_dsn(v)?;
                    Ok(Zeroizing::new(v.to_owned()))
                },
            )
            .map(StorageConfig::Postgres)
    }
}

pub struct HttpClientConfig {
    pub mode: String,
    pub remote_scheme: String,
    pub final_app_scheme: String,
    pub tls_skip_verify: bool,
}

pub fn http_client_config(loader: &ConfigLoader) -> Result<HttpClientConfig, DynError> {
    let mode = loader.parse("VECTIS_MODE", "must be dev or prod", validate_vectis_mode)?;
    let scheme = transport_scheme_for_mode(&mode).to_owned();
    let tls_skip_verify = loader.parse("VECTIS_TLS_SKIP_VERIFY", "must be true or false", |v| {
        validate_bool_field("VECTIS_TLS_SKIP_VERIFY", v)
    })?;
    Ok(HttpClientConfig {
        mode,
        remote_scheme: scheme.clone(),
        final_app_scheme: scheme,
        tls_skip_verify,
    })
}

pub fn configured_path(loader: &ConfigLoader, name: &str) -> Result<PathBuf, DynError> {
    loader.parse(name, "must be a nonempty path without controls", |v| {
        validate_config_path(name, v)
    })
}

pub fn init_keys_file_path(loader: &ConfigLoader) -> Result<PathBuf, DynError> {
    configured_path(loader, "VECTIS_INIT_KEYS_FILE")
}

pub fn init_public_keys_file_path(loader: &ConfigLoader) -> Result<PathBuf, DynError> {
    configured_path(loader, "VECTIS_INIT_PUBLIC_KEYS_FILE")
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

fn validate_postgres_dsn(value: &str) -> Result<(), DynError> {
    validation::validate_text_field("VECTIS_POSTGRES_DSN", value)?;

    if !(value.starts_with("postgres://") || value.starts_with("postgresql://")) {
        return Err(crate::error::invalid_input(
            "VECTIS_POSTGRES_DSN must start with postgres:// or postgresql://",
        ));
    }

    value
        .parse::<sqlx::postgres::PgConnectOptions>()
        .map_err(|_| crate::error::invalid_input("invalid PostgreSQL DSN"))?;

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

pub fn load_env_file(path: &str) -> Result<HashMap<String, String>, DynError> {
    crate::core::config_loader::load_env_file(path)
}

/// Validate only the file grammar; recognition and source policy belong to the loader.
pub fn validate_env_file_content(content: &str) -> Result<(), DynError> {
    crate::core::config_loader::validate_env_file_content(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::blocking::default_crypto_concurrency;
    use proptest::prelude::*;
    use std::fs;

    #[test]
    fn env_file_rejects_content_over_limit() {
        let path =
            std::env::temp_dir().join(format!("vectis-env-size-test-{}", std::process::id()));
        fs::write(&path, "a".repeat((ENV_FILE_MAX_SIZE_BYTES + 1) as usize))
            .expect("write oversized env file");

        assert!(load_env_file(path.to_str().expect("temporary path must be UTF-8")).is_err());
        let _ = fs::remove_file(path);
    }

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
    fn max_concurrent_crypto_parses_and_validates() {
        assert_eq!(
            parse_max_concurrent_crypto("5", default_crypto_concurrency)
                .expect("positive integer is valid"),
            5
        );
        // Empty falls back to a positive default derived from available cores.
        assert!(
            parse_max_concurrent_crypto("", default_crypto_concurrency)
                .expect("empty uses default")
                >= 1
        );
        assert!(
            parse_max_concurrent_crypto("  ", default_crypto_concurrency)
                .expect("blank uses default")
                >= 1
        );
        parse_max_concurrent_crypto("0", default_crypto_concurrency).expect_err("zero is rejected");
        parse_max_concurrent_crypto("abc", default_crypto_concurrency)
            .expect_err("non-numeric is rejected");
        // Sign-prefixed inputs are rejected, matching the queued and timeout parsers.
        parse_max_concurrent_crypto("+1", default_crypto_concurrency)
            .expect_err("leading plus is rejected");
        parse_max_concurrent_crypto("-1", default_crypto_concurrency)
            .expect_err("leading minus is rejected");
        parse_max_concurrent_crypto(&usize::MAX.to_string(), default_crypto_concurrency)
            .expect_err("value above the semaphore maximum is rejected");
    }

    #[test]
    fn crypto_queue_limits_validate_bounds_and_strict_inputs() {
        assert_eq!(parse_max_queued_crypto("0").unwrap(), 0);
        assert_eq!(
            parse_max_queued_crypto("128").unwrap(),
            DEFAULT_MAX_QUEUED_CRYPTO
        );
        assert_eq!(
            parse_max_queued_crypto(&tokio::sync::Semaphore::MAX_PERMITS.to_string()).unwrap(),
            tokio::sync::Semaphore::MAX_PERMITS
        );
        assert!(
            parse_max_queued_crypto(&(tokio::sync::Semaphore::MAX_PERMITS + 1).to_string())
                .is_err()
        );
        for value in [
            "",
            " ",
            "-1",
            "+1",
            "1.5",
            "true",
            "abc",
            "99999999999999999999999999999",
        ] {
            assert!(parse_max_queued_crypto(value).is_err(), "{value:?}");
            assert!(parse_crypto_queue_timeout(value).is_err(), "{value:?}");
        }
        assert!(parse_crypto_queue_timeout("0").is_err());
        assert!(parse_crypto_queue_timeout("30001").is_err());
        assert_eq!(
            parse_crypto_queue_timeout("1").unwrap(),
            std::time::Duration::from_millis(1)
        );
        assert_eq!(
            parse_crypto_queue_timeout("30000").unwrap(),
            std::time::Duration::from_secs(30)
        );
    }

    #[test]
    fn admission_extraction_preserves_values_errors_and_sources() {
        for name in [
            "VECTIS_MAX_CONCURRENT_CRYPTO",
            "VECTIS_MAX_QUEUED_CRYPTO",
            "VECTIS_CRYPTO_QUEUE_TIMEOUT_MS",
        ] {
            for value in [
                "",
                " ",
                "0",
                "1",
                "+1",
                " 5 ",
                "128",
                "30000",
                "30001",
                "-1",
                "abc",
                "999999999999999999999999999",
                "4096",
            ] {
                for process in [false, true] {
                    let file = format!("# line\n{name}={}", if process { "1" } else { value });
                    let loader = ConfigLoader::from_sources(&file, |key| {
                        (process && key == name).then(|| value.into())
                    })
                    .unwrap();
                    let reference = (|| -> Result<CryptoAdmissionConfig, DynError> {
                        Ok(CryptoAdmissionConfig {
                            max_concurrent_crypto: loader.parse(
                                "VECTIS_MAX_CONCURRENT_CRYPTO",
                                "must be empty or a positive integer within the semaphore maximum",
                                |v| {
                                    parse_max_concurrent_crypto(v, || {
                                        loader.default_crypto_concurrency()
                                    })
                                },
                            )?,
                            max_queued_crypto: loader.parse(
                                "VECTIS_MAX_QUEUED_CRYPTO",
                                "must be an integer between 0 and the semaphore maximum",
                                parse_max_queued_crypto,
                            )?,
                            crypto_queue_timeout: loader.parse(
                                "VECTIS_CRYPTO_QUEUE_TIMEOUT_MS",
                                "must be an integer between 1 and 30000",
                                parse_crypto_queue_timeout,
                            )?,
                        })
                    })();
                    assert_eq!(
                        crypto_admission_config(&loader).map_err(|e| e.to_string()),
                        reference.map_err(|e| e.to_string()),
                        "{name}, process={process}"
                    );
                }
            }
        }
        let loader = ConfigLoader::from_sources("", |_| None).unwrap();
        let defaults = crypto_admission_config(&loader).unwrap();
        assert_eq!(
            defaults.max_concurrent_crypto,
            crate::core::config_loader::SYNTHETIC_CRYPTO_CONCURRENCY
        );
        assert_eq!(defaults.max_queued_crypto, DEFAULT_MAX_QUEUED_CRYPTO);
        assert_eq!(
            defaults.crypto_queue_timeout.as_millis(),
            DEFAULT_CRYPTO_QUEUE_TIMEOUT_MS as u128
        );
    }

    #[test]
    fn server_uses_extracted_admission_settings() {
        let path =
            std::env::temp_dir().join(format!("vectis-admission-config-{}", std::process::id()));
        fs::write(&path, "").unwrap();
        let loader = ConfigLoader::from_sources(
            "VECTIS_MAX_CONCURRENT_CRYPTO=3\nVECTIS_MAX_QUEUED_CRYPTO=0\nVECTIS_CRYPTO_QUEUE_TIMEOUT_MS=7",
            |key| (key == "VECTIS_SQLITE_PATH").then(|| path.as_os_str().to_owned()),
        ).unwrap();
        let admission = crypto_admission_config(&loader).unwrap();
        let result = app_config(&loader);
        fs::remove_file(path).unwrap();
        let app = result.unwrap();
        assert_eq!(app.max_concurrent_crypto, admission.max_concurrent_crypto);
        assert_eq!(app.max_queued_crypto, admission.max_queued_crypto);
        assert_eq!(app.crypto_queue_timeout, admission.crypto_queue_timeout);
    }

    #[test]
    fn crypto_queue_environment_precedence() {
        const CHILD: &str = "VECTIS_TEST_QUEUE_PRECEDENCE";
        if let Ok(mode) = std::env::var(CHILD) {
            let content = if mode == "defaults" {
                ""
            } else {
                "VECTIS_MAX_QUEUED_CRYPTO=7\nVECTIS_CRYPTO_QUEUE_TIMEOUT_MS=250\n"
            };
            let loader =
                ConfigLoader::from_sources(content, |name| std::env::var_os(name)).unwrap();
            let admission = crypto_admission_config(&loader);
            match mode.as_str() {
                "defaults" => {
                    let admission = admission.unwrap();
                    assert_eq!(admission.max_queued_crypto, 128);
                    assert_eq!(admission.crypto_queue_timeout.as_millis(), 1000);
                }
                "file" => {
                    let admission = admission.unwrap();
                    assert_eq!(admission.max_queued_crypto, 7);
                    assert_eq!(admission.crypto_queue_timeout.as_millis(), 250);
                }
                "process" => {
                    let admission = admission.unwrap();
                    assert_eq!(admission.max_queued_crypto, 3);
                    assert_eq!(admission.crypto_queue_timeout.as_millis(), 99);
                }
                "empty" => {
                    assert!(admission.is_err());
                }
                _ => panic!("unknown test mode"),
            }
            return;
        }
        for mode in ["defaults", "file", "process", "empty"] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "core::config::tests::crypto_queue_environment_precedence",
                ])
                .env(CHILD, mode)
                .env_remove("VECTIS_MAX_CONCURRENT_CRYPTO")
                .env_remove("VECTIS_MAX_QUEUED_CRYPTO")
                .env_remove("VECTIS_CRYPTO_QUEUE_TIMEOUT_MS");
            if mode == "process" || mode == "empty" {
                command
                    .env(
                        "VECTIS_MAX_QUEUED_CRYPTO",
                        if mode == "empty" { "" } else { "3" },
                    )
                    .env(
                        "VECTIS_CRYPTO_QUEUE_TIMEOUT_MS",
                        if mode == "empty" { "" } else { "99" },
                    );
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "precedence mode {mode}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
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
