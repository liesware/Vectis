//! Invocation-scoped sources. Resolution and semantic validation remain lazy.
mod env_file;

use crate::core::{blocking, files};
use crate::error::{DynError, invalid_input};
use env_file::FileValue;
pub use env_file::{ENV_FILE_MAX_SIZE_BYTES, ENV_NAME_MAX_SIZE_BYTES, ENV_VALUE_MAX_SIZE_BYTES};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Host-independent default used only by synthetic sources.
pub const SYNTHETIC_CRYPTO_CONCURRENCY: usize = 4;

#[derive(Clone, Copy)]
pub enum EmptyPolicy {
    Allowed,
    Rejected,
    Default,
}

pub struct Variable {
    pub name: &'static str,
    pub default: &'static str,
    pub allow_file: bool,
    pub empty: EmptyPolicy,
}

macro_rules! variables {
    ($($name:literal => $default:literal, $empty:ident),* $(,)?) => {
        pub const VARIABLES: &[Variable] = &[
            $(Variable { name: $name, default: $default, allow_file: true, empty: EmptyPolicy::$empty },)*
            Variable { name: "VECTIS_UNSEAL_KEY", default: "", allow_file: false, empty: EmptyPolicy::Rejected },
        ];
    };
}

variables! {
    "VECTIS_MODE" => "dev", Rejected,
    "VECTIS_HTTP_BIND_ADDR" => "127.0.0.1:3000", Rejected,
    "VECTIS_PUBLIC_ADDR" => "127.0.0.1:3000", Rejected,
    "VECTIS_FINAL_APP_ADDR" => "localhost:3999", Rejected,
    "VECTIS_FINAL_APP_PATH" => "/message", Rejected,
    "VECTIS_TLS_CERT_PATH" => "", Allowed,
    "VECTIS_TLS_KEY_PATH" => "", Allowed,
    "VECTIS_TLS_SKIP_VERIFY" => "false", Rejected,
    "VECTIS_CONFIG_PATH" => "config.json", Rejected,
    "VECTIS_CONFIG_SIGN_PATH" => "config_sign.json", Rejected,
    "VECTIS_APIKEY_HASH" => "", Allowed,
    "VECTIS_PROTOCOL_VERSION" => "v1", Rejected,
    "VECTIS_STORAGE" => "sqlite", Rejected,
    "VECTIS_SQLITE_PATH" => "", Rejected,
    "VECTIS_POSTGRES_DSN" => "", Rejected,
    "VECTIS_SENDER_HOSTNAME" => "localhost.local", Rejected,
    "VECTIS_RECEIVER_HOSTNAME" => "remotehost.local", Rejected,
    "VECTIS_HASH" => "BLAKE2b(256)", Rejected,
    "VECTIS_SYMMETRIC" => "ChaCha20Poly1305", Rejected,
    "VECTIS_EDDSA" => "Ed25519", Rejected,
    "VECTIS_XECDH" => "X25519", Rejected,
    "VECTIS_ML_DSA_VARIANT" => "ML-DSA-44", Rejected,
    "VECTIS_ML_KEM_VARIANT" => "ML-KEM-512", Rejected,
    "VECTIS_DEFAULT_CRYPTO_PROFILE" => "hybrid-performance-v1", Rejected,
    "VECTIS_CRYPTO_POLICY" => "profile-only", Rejected,
    "VECTIS_METRICS_ENABLED" => "true", Rejected,
    "VECTIS_MAX_CONCURRENT_CRYPTO" => "", Default,
    "VECTIS_MAX_QUEUED_CRYPTO" => "128", Rejected,
    "VECTIS_CRYPTO_QUEUE_TIMEOUT_MS" => "1000", Rejected,
    "VECTIS_PLAINTEXT_MESSAGE" => "You are not special. You are not a beautiful and unique snowflake. You're the same decaying organic matter as everything else.", Rejected,
    "VECTIS_INIT_KEYS_FILE" => "init.json", Rejected,
    "VECTIS_INIT_PUBLIC_KEYS_FILE" => "init_pub.json", Rejected,
    "VECTIS_UNSEAL_KEY_FILE" => ".unseal_key", Rejected,
    "VECTIS_API_URL" => "http://127.0.0.1:3000", Rejected,
    "VECTIS_APIKEY" => "", Allowed,
    "VECTIS_TIMEOUT_SECONDS" => "30", Rejected,
    "VECTIS_LOG_LEVEL" => "info", Rejected,
    "VECTIS_LOG_TARGET" => "file", Rejected,
    "VECTIS_LOG_DIR" => "logs", Rejected,
    "VECTIS_LOG_FILE" => "vectis.log", Rejected,
    "VECTIS_AUDIT_LOG_FILE" => "audit.log", Rejected,
}

// Rust's native encoding preserves non-Unicode values on Unix and Windows.
struct NativeValue(Zeroizing<Vec<u8>>);

impl NativeValue {
    fn capture(value: OsString) -> Self {
        Self(Zeroizing::new(value.into_encoded_bytes()))
    }

    fn text(&self) -> Option<Zeroizing<String>> {
        std::str::from_utf8(&self.0)
            .ok()
            .map(|s| Zeroizing::new(s.to_owned()))
    }
}

pub struct ConfigLoader {
    process: HashMap<&'static str, NativeValue>,
    file: HashMap<String, FileValue>,
    sqlite_default: Zeroizing<String>,
    crypto_default: Option<usize>,
}

impl ConfigLoader {
    pub fn capture() -> Result<Self, DynError> {
        let file = read_protected_env_file(".env")?;
        Self::with_file(
            file,
            |name| std::env::var_os(name),
            default_sqlite_path(),
            None,
        )
    }

    /// Synthetic sources for tests and fuzzing; never reads the filesystem or environment.
    pub fn from_sources(
        content: &str,
        process: impl FnMut(&str) -> Option<OsString>,
    ) -> Result<Self, DynError> {
        Self::with_file(
            env_file::parse_protected_env_content(content)?,
            process,
            "db/data.db".into(),
            Some(SYNTHETIC_CRYPTO_CONCURRENCY),
        )
    }

    fn with_file(
        file: HashMap<String, FileValue>,
        mut process: impl FnMut(&str) -> Option<OsString>,
        sqlite_default: String,
        crypto_default: Option<usize>,
    ) -> Result<Self, DynError> {
        // File policy is unconditional, including assignments overridden by the process.
        for (name, entry) in &file {
            let variable = VARIABLES.iter().find(|v| v.name == name);
            if variable.is_none() || !variable.is_some_and(|v| v.allow_file) {
                return Err(invalid_input(format!(
                    "{name} (env_file line {}): unknown variable or prohibited source",
                    entry.line
                )));
            }
        }
        Ok(Self {
            process: VARIABLES
                .iter()
                .filter_map(|v| process(v.name).map(|value| (v.name, NativeValue::capture(value))))
                .collect(),
            file,
            sqlite_default: Zeroizing::new(sqlite_default),
            crypto_default,
        })
    }

    pub fn source(&self, name: &str) -> String {
        if self.process.contains_key(name) {
            "process".into()
        } else if let Some(entry) = self.file.get(name) {
            format!("env_file line {}", entry.line)
        } else {
            "default".into()
        }
    }

    pub fn is_present(&self, name: &str) -> bool {
        self.process.contains_key(name) || self.file.contains_key(name)
    }

    pub(crate) fn default_crypto_concurrency(&self) -> usize {
        self.crypto_default
            .unwrap_or_else(blocking::default_crypto_concurrency)
    }

    pub fn error(&self, name: &str, reason: &str) -> DynError {
        invalid_input(format!("{name} ({}): {reason}", self.source(name)))
    }

    pub fn value(&self, name: &str) -> Result<Zeroizing<String>, DynError> {
        let variable = VARIABLES
            .iter()
            .find(|v| v.name == name)
            .ok_or_else(|| crate::error::internal("unregistered configuration variable"))?;
        let value = if let Some(value) = self.process.get(name) {
            value
                .text()
                .ok_or_else(|| self.error(name, "must be Unicode"))?
        } else if let Some(entry) = self.file.get(name) {
            Zeroizing::new(entry.value.to_string())
        } else if name == "VECTIS_SQLITE_PATH" {
            self.sqlite_default.clone()
        } else {
            Zeroizing::new(variable.default.to_owned())
        };
        if value.len() > ENV_VALUE_MAX_SIZE_BYTES {
            return Err(self.error(name, "exceeds maximum value size of 4096 UTF-8 bytes"));
        }
        if value.is_empty() && matches!(variable.empty, EmptyPolicy::Rejected) {
            return Err(self.error(name, "must not be empty"));
        }
        Ok(value)
    }

    pub fn parse<T>(
        &self,
        name: &str,
        reason: &str,
        validate: impl FnOnce(&str) -> Result<T, DynError>,
    ) -> Result<T, DynError> {
        let value = self.value(name)?;
        validate(&value).map_err(|_| self.error(name, reason))
    }
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
        std::env::current_dir()
            .unwrap_or_else(|_| Path::new(".").to_path_buf())
            .join("db")
            .join("data.db")
            .display()
            .to_string()
    }
}

fn read_protected_env_file(path: &str) -> Result<HashMap<String, FileValue>, DynError> {
    let content = files::read_bounded_secret_utf8_file(
        Path::new(path),
        ".env",
        ENV_FILE_MAX_SIZE_BYTES,
        files::MissingFilePolicy::Optional,
    )?
    .unwrap_or_default();

    env_file::parse_protected_env_content(&content)
}

pub(crate) fn load_env_file(path: &str) -> Result<HashMap<String, String>, DynError> {
    Ok(read_protected_env_file(path)?
        .into_iter()
        .map(|(key, entry)| (key, entry.value.to_string()))
        .collect())
}

pub(crate) fn validate_env_file_content(content: &str) -> Result<(), DynError> {
    env_file::parse_protected_env_content(content).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config;

    fn loader(content: &str) -> ConfigLoader {
        ConfigLoader::from_sources(content, |_| None).unwrap()
    }

    #[test]
    fn real_defaults_use_shared_host_capacity_and_build_specific_sqlite_path() {
        let captured =
            ConfigLoader::with_file(HashMap::new(), |_| None, default_sqlite_path(), None).unwrap();
        let expected_path = if cfg!(debug_assertions) {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/db/data.db")
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("db/data.db")
        };
        assert_eq!(
            captured.value("VECTIS_SQLITE_PATH").unwrap().as_str(),
            expected_path.display().to_string()
        );
        assert_eq!(captured.source("VECTIS_SQLITE_PATH"), "default");
        assert_eq!(
            captured.default_crypto_concurrency(),
            blocking::default_crypto_concurrency()
        );
    }

    #[test]
    fn synthetic_defaults_preserve_resolution_and_explicit_empty_provenance() {
        let defaults = loader("");
        assert_eq!(
            defaults.value("VECTIS_SQLITE_PATH").unwrap().as_str(),
            "db/data.db"
        );
        assert_eq!(defaults.source("VECTIS_SQLITE_PATH"), "default");
        assert!(
            defaults
                .value("VECTIS_MAX_CONCURRENT_CRYPTO")
                .unwrap()
                .is_empty()
        );
        assert_eq!(defaults.default_crypto_concurrency(), 4);
        for content in ["", "VECTIS_MAX_CONCURRENT_CRYPTO="] {
            let captured = loader(content);
            assert_eq!(
                config::crypto_admission_config(&captured)
                    .unwrap()
                    .max_concurrent_crypto,
                4
            );
            assert_eq!(
                captured.source("VECTIS_MAX_CONCURRENT_CRYPTO"),
                if content.is_empty() {
                    "default"
                } else {
                    "env_file line 1"
                }
            );
        }
        let explicit = ConfigLoader::from_sources("VECTIS_MAX_CONCURRENT_CRYPTO=7", |name| {
            (name == "VECTIS_MAX_CONCURRENT_CRYPTO").then(|| "".into())
        })
        .unwrap();
        assert_eq!(explicit.source("VECTIS_MAX_CONCURRENT_CRYPTO"), "process");
        assert_eq!(
            config::crypto_admission_config(&explicit)
                .unwrap()
                .max_concurrent_crypto,
            4
        );
        assert!(
            loader("VECTIS_SQLITE_PATH=")
                .value("VECTIS_SQLITE_PATH")
                .is_err()
        );
    }

    #[test]
    fn precedence_and_source_metadata_do_not_hide_explicit_empty_values() {
        let captured = ConfigLoader::from_sources(
            "# comment\nVECTIS_MAX_QUEUED_CRYPTO=7\nVECTIS_APIKEY=\n",
            |name| (name == "VECTIS_MAX_QUEUED_CRYPTO").then(|| "0".into()),
        )
        .unwrap();
        assert_eq!(
            captured.value("VECTIS_MAX_QUEUED_CRYPTO").unwrap().as_str(),
            "0"
        );
        assert_eq!(captured.source("VECTIS_MAX_QUEUED_CRYPTO"), "process");
        assert_eq!(captured.source("VECTIS_APIKEY"), "env_file line 3");
        assert_eq!(captured.source("VECTIS_TIMEOUT_SECONDS"), "default");
        let empty = ConfigLoader::from_sources("VECTIS_MODE=dev", |_| Some("".into())).unwrap();
        assert!(empty.value("VECTIS_MODE").is_err());
        assert!(empty.value("VECTIS_APIKEY").unwrap().is_empty());
        assert!(
            empty
                .value("VECTIS_MAX_CONCURRENT_CRYPTO")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn file_policy_is_unconditional_but_process_auxiliaries_are_ignored() {
        for content in ["VECTIS_UNKNOWN=canary", "VECTIS_UNSEAL_KEY=canary"] {
            let error = ConfigLoader::from_sources(content, |_| Some("override".into()))
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains("env_file line 1"));
            assert!(!error.contains("canary"));
        }
        let captured = ConfigLoader::from_sources("", |name| {
            assert!(VARIABLES.iter().any(|v| v.name == name));
            None
        })
        .unwrap();
        assert_eq!(captured.value("VECTIS_MODE").unwrap().as_str(), "dev");
    }

    #[test]
    fn oversized_process_values_are_checked_only_when_consumed() {
        let big = "x".repeat(ENV_VALUE_MAX_SIZE_BYTES + 1);
        let captured = ConfigLoader::from_sources("", |name| {
            (name == "VECTIS_POSTGRES_DSN").then(|| big.clone().into())
        })
        .unwrap();
        assert!(crate::core::logging::logging_config(&captured).is_ok());
        let error = captured
            .value("VECTIS_POSTGRES_DSN")
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("process"));
        assert!(!error.contains(&big));
        let exact = "x".repeat(ENV_VALUE_MAX_SIZE_BYTES);
        assert!(
            ConfigLoader::from_sources("", |_| Some(exact.clone().into()))
                .unwrap()
                .value("VECTIS_APIKEY")
                .is_ok()
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_is_not_absence_or_lossy_text() {
        use std::os::unix::ffi::OsStringExt;
        let captured =
            ConfigLoader::from_sources("VECTIS_POSTGRES_DSN=postgres://fallback/db", |name| {
                (name == "VECTIS_POSTGRES_DSN").then(|| OsString::from_vec(b"canary\xff".to_vec()))
            })
            .unwrap();
        assert!(crate::core::logging::logging_config(&captured).is_ok());
        let error = captured
            .value("VECTIS_POSTGRES_DSN")
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("process"));
        assert!(error.contains("Unicode"));
        assert!(!error.contains("canary"));
        assert!(!error.contains("fallback"));
    }

    #[test]
    fn overwritten_values_skip_semantics_but_not_file_structure_or_limits() {
        let captured = ConfigLoader::from_sources("VECTIS_MODE=invalid-canary", |name| {
            (name == "VECTIS_MODE").then(|| "dev".into())
        })
        .unwrap();
        assert!(config::http_client_config(&captured).is_ok());
        for content in [
            "VECTIS_MODE=dev\nVECTIS_MODE=prod".to_owned(),
            format!("VECTIS_MODE={}", "x".repeat(4097)),
        ] {
            assert!(ConfigLoader::from_sources(&content, |_| Some("dev".into())).is_err());
        }
    }

    #[test]
    fn captured_sources_are_stable_and_validators_cannot_reflect_values() {
        let mut source = OsString::from("bad-secret-canary");
        let captured =
            ConfigLoader::from_sources("", |name| (name == "VECTIS_MODE").then(|| source.clone()))
                .unwrap();
        source.clear();
        source.push("dev");
        let error = config::http_client_config(&captured)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("VECTIS_MODE (process)"));
        assert!(!error.contains("secret-canary"));
        assert_eq!(
            captured.value("VECTIS_MODE").unwrap().as_str(),
            "bad-secret-canary"
        );
    }

    #[test]
    fn purpose_specific_constructors_ignore_unrelated_settings() {
        let captured = loader(
            "VECTIS_MODE=prod\nVECTIS_SQLITE_PATH=/missing\nVECTIS_POSTGRES_DSN=invalid\nVECTIS_TLS_CERT_PATH=/missing\nVECTIS_TLS_KEY_PATH=/missing",
        );
        assert!(config::http_client_config(&captured).is_ok());
        assert!(config::bootstrap_config(&captured).is_ok());
        assert!(config::local_config(&captured).is_ok());
        let postgres = loader(
            "VECTIS_STORAGE=postgres\nVECTIS_POSTGRES_DSN=postgres://user:password@localhost/db\nVECTIS_SQLITE_PATH=",
        );
        assert!(config::node_config(&postgres).is_ok());
        let invalid = loader(
            "VECTIS_STORAGE=postgres\nVECTIS_POSTGRES_DSN=postgres://user:secret-canary@localhost:bad/db",
        );
        let error = config::node_config(&invalid).err().unwrap().to_string();
        assert!(error.contains("VECTIS_POSTGRES_DSN (env_file line 2)"));
        assert!(!error.contains("secret-canary"));
    }

    #[test]
    fn catalog_has_unique_names_and_documented_empty_policy() {
        let mut seen = std::collections::HashSet::new();
        for variable in VARIABLES {
            assert!(seen.insert(variable.name));
            assert!(variable.default.len() <= ENV_VALUE_MAX_SIZE_BYTES);
        }
        let captured = loader("VECTIS_LOG_LEVEL= WARNING \nVECTIS_LOG_TARGET= STDOUT ");
        assert!(crate::core::logging::logging_config(&captured).is_ok());
        for text in [
            "VECTIS_LOG_LEVEL=secret-canary",
            "VECTIS_LOG_TARGET=secret-canary",
        ] {
            let error = crate::core::logging::logging_config(&loader(text))
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains("env_file line 1"));
            assert!(!error.contains("secret-canary"));
        }
    }

    #[test]
    fn secrets_remain_protected_in_sources_and_typed_results() {
        fn protected(_: &Zeroizing<String>) {}
        let captured = loader(
            "VECTIS_STORAGE=postgres\nVECTIS_POSTGRES_DSN=postgres://user:secret@localhost/db",
        );
        protected(&captured.file["VECTIS_POSTGRES_DSN"].value);
        protected(&captured.value("VECTIS_POSTGRES_DSN").unwrap());
        match config::storage_config(&captured).unwrap() {
            config::StorageConfig::Postgres(dsn) => protected(&dsn),
            _ => panic!("expected postgres"),
        }
        protected(
            &config::bootstrap_config(&captured)
                .unwrap()
                .plaintext_message,
        );
    }
}
