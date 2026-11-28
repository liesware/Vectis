use std::collections::HashMap;
use std::error::Error;
use std::io;

pub type DynError = Box<dyn Error + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigErrorCategory {
    Internal,
    Storage,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConfigSource {
    Process,
    EnvFile {
        line: usize,
    },
    #[default]
    Default,
}

impl std::fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Process => f.write_str("process"),
            Self::EnvFile { line } => write!(f, "env_file line {line}"),
            Self::Default => f.write_str("default"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigOrigin {
    pub name: &'static str,
    pub source: ConfigSource,
}

impl std::fmt::Display for ConfigOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.source)
    }
}

#[derive(Debug, Default)]
pub struct ConfigOrigins(HashMap<&'static str, ConfigSource>);

impl ConfigOrigins {
    pub fn new(entries: impl IntoIterator<Item = (&'static str, ConfigSource)>) -> Self {
        Self(entries.into_iter().collect())
    }

    pub fn source(&self, name: &str) -> ConfigSource {
        self.0.get(name).copied().unwrap_or_default()
    }

    pub fn origin(&self, name: &'static str) -> ConfigOrigin {
        ConfigOrigin {
            name,
            source: self.source(name),
        }
    }
}

impl ConfigOrigin {
    pub fn internal_context(self, reason: &'static str, err: &(dyn Error + 'static)) -> DynError {
        self.context(reason, err, ConfigErrorCategory::Internal)
    }

    pub fn context(
        self,
        reason: &'static str,
        err: &(dyn Error + 'static),
        category: ConfigErrorCategory,
    ) -> DynError {
        config_error(&[self], reason, err, category)
    }
}

pub fn config_error(
    origins: &[ConfigOrigin],
    reason: &'static str,
    err: &(dyn Error + 'static),
    category: ConfigErrorCategory,
) -> DynError {
    let message = config_error_message(origins, reason, err);
    match category {
        ConfigErrorCategory::Internal => internal(message),
        ConfigErrorCategory::Storage => storage(message),
    }
}

fn config_error_message(
    origins: &[ConfigOrigin],
    reason: &'static str,
    err: &(dyn Error + 'static),
) -> String {
    let context = origins
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let message = format!("{context}: {reason}");
    match config_io_error_kind(err) {
        Some(kind) => format!("{message} ({kind:?})"),
        None => message,
    }
}

fn config_io_error_kind(err: &(dyn Error + 'static)) -> Option<io::ErrorKind> {
    let mut current = Some(err);
    for _ in 0..8 {
        let error = current?;
        if let Some(io_error) = error.downcast_ref::<io::Error>() {
            return Some(io_error.kind());
        }
        current = error.source();
    }
    None
}

pub const UNTRUSTED_ERROR_DETAIL_MAX_CHARS: usize = 256;
const SANITIZED_SERDE_FALLBACK: &str = "invalid JSON";

#[derive(Clone, Debug, thiserror::Error)]
pub enum VectisError {
    #[error("token decode batch exceeds maximum allowed envelope size")]
    TokenDecodeBatchTooLarge,
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    InvalidSignature(String),
    #[error("{0}")]
    ConfigSignatureStale(String),
    #[error("{0}")]
    RemoteUnreachable(String),
    #[error("{0}")]
    Storage(String),
    #[error("{0}")]
    Overloaded(String),
    #[error("{0}")]
    Internal(String),
}

pub fn invalid_input(message: impl Into<String>) -> DynError {
    Box::new(VectisError::InvalidInput(message.into()))
}

pub fn not_found(message: impl Into<String>) -> DynError {
    Box::new(VectisError::NotFound(message.into()))
}

pub fn conflict(message: impl Into<String>) -> DynError {
    Box::new(VectisError::Conflict(message.into()))
}

pub fn forbidden(message: impl Into<String>) -> DynError {
    Box::new(VectisError::Forbidden(message.into()))
}

pub fn invalid_signature(message: impl Into<String>) -> DynError {
    Box::new(VectisError::InvalidSignature(message.into()))
}

pub fn config_signature_stale(message: impl Into<String>) -> DynError {
    Box::new(VectisError::ConfigSignatureStale(message.into()))
}

pub fn remote_unreachable(message: impl Into<String>) -> DynError {
    Box::new(VectisError::RemoteUnreachable(message.into()))
}

pub fn storage(message: impl Into<String>) -> DynError {
    Box::new(VectisError::Storage(message.into()))
}

pub fn overloaded(message: impl Into<String>) -> DynError {
    Box::new(VectisError::Overloaded(message.into()))
}

pub fn internal(message: impl Into<String>) -> DynError {
    Box::new(VectisError::Internal(message.into()))
}

#[cfg(test)]
mod config_context_tests {
    use super::*;

    fn assert_category(err: &DynError, category: ConfigErrorCategory) {
        assert!(matches!(
            (category, err.downcast_ref::<VectisError>()),
            (
                ConfigErrorCategory::Internal,
                Some(VectisError::Internal(_))
            ) | (ConfigErrorCategory::Storage, Some(VectisError::Storage(_)))
        ));
    }

    #[derive(Debug)]
    struct WrappedError(DynError);

    impl std::fmt::Display for WrappedError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("secret-canary")
        }
    }

    impl Error for WrappedError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    #[test]
    fn sqlx_io_causes_add_diagnostics_without_changing_error_categories() {
        let origin = ConfigOrigin {
            name: "VECTIS_POSTGRES_DSN",
            source: ConfigSource::EnvFile { line: 5 },
        };
        for kind in [
            io::ErrorKind::NotFound,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::TimedOut,
        ] {
            for depth in 0..=3 {
                let mut cause: DynError = Box::new(sqlx::Error::Io(io::Error::new(
                    kind,
                    "postgres://user:secret-canary@host/db",
                )));
                for _ in 0..depth {
                    cause = Box::new(WrappedError(cause));
                }
                for category in [ConfigErrorCategory::Internal, ConfigErrorCategory::Storage] {
                    let contextual = origin.context("could not connect", cause.as_ref(), category);
                    assert_category(&contextual, category);
                    assert_eq!(
                        contextual.to_string(),
                        format!(
                            "VECTIS_POSTGRES_DSN (env_file line 5): could not connect ({kind:?})"
                        )
                    );
                    let internal = origin.internal_context("could not connect", cause.as_ref());
                    assert_category(&internal, ConfigErrorCategory::Internal);
                    assert_eq!(internal.to_string(), contextual.to_string());
                }
            }
        }
    }

    #[test]
    fn io_diagnostic_traversal_includes_the_root_and_stops_at_eight_errors() {
        let origin = ConfigOrigins::default().origin("VECTIS_SQLITE_PATH");
        let mut cause: DynError = Box::new(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "secret-canary",
        ));
        for wrappers in 0..=8 {
            let expected = if wrappers < 8 {
                "VECTIS_SQLITE_PATH (default): could not connect (ConnectionRefused)"
            } else {
                "VECTIS_SQLITE_PATH (default): could not connect"
            };
            for category in [ConfigErrorCategory::Internal, ConfigErrorCategory::Storage] {
                let err = origin.context("could not connect", cause.as_ref(), category);
                assert_category(&err, category);
                assert_eq!(err.to_string(), expected);
            }
            cause = Box::new(WrappedError(cause));
        }
    }

    #[test]
    fn cyclic_error_causes_are_bounded_and_never_formatted() {
        #[derive(Debug)]
        struct Cyclic(std::sync::atomic::AtomicUsize);
        impl std::fmt::Display for Cyclic {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                panic!("must not format external causes")
            }
        }
        impl Error for Cyclic {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Some(self)
            }
        }
        let origin = ConfigOrigins::default().origin("VECTIS_POSTGRES_DSN");
        for category in [ConfigErrorCategory::Internal, ConfigErrorCategory::Storage] {
            let cause = Cyclic(std::sync::atomic::AtomicUsize::new(0));
            let err = origin.context("could not connect", &cause, category);
            assert_category(&err, category);
            assert_eq!(
                err.to_string(),
                "VECTIS_POSTGRES_DSN (default): could not connect"
            );
            assert_eq!(cause.0.load(std::sync::atomic::Ordering::Relaxed), 8);
        }
    }

    #[test]
    fn operational_context_always_is_internal_and_never_reflects_values() {
        for source in [
            ConfigSource::Process,
            ConfigSource::EnvFile { line: 8 },
            ConfigSource::Default,
        ] {
            let origin = ConfigOrigin {
                name: "VECTIS_CONFIG_SIGN_PATH",
                source,
            };
            let errors = [
                not_found("secret-canary"),
                forbidden("secret-canary"),
                invalid_input("secret-canary"),
                internal("secret-canary"),
                Box::new(io::Error::new(io::ErrorKind::NotFound, "secret-canary")) as DynError,
                Box::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "secret-canary",
                )) as DynError,
                Box::new(io::Error::other("secret-canary")) as DynError,
            ];
            for err in errors {
                let result =
                    origin.internal_context("could not read config signature file", err.as_ref());
                assert!(matches!(
                    result.downcast_ref::<VectisError>(),
                    Some(VectisError::Internal(_))
                ));
                let message = result.to_string();
                assert!(
                    message.starts_with(&format!("{origin}: could not read config signature file"))
                );
                assert!(!message.contains("secret-canary"));
                if let Some(io_error) = err.downcast_ref::<io::Error>() {
                    assert!(message.ends_with(&format!("({:?})", io_error.kind())));
                }
            }
        }
    }

    #[test]
    fn context_uses_selected_category_for_every_vectis_variant() {
        let errors = [
            Box::new(VectisError::TokenDecodeBatchTooLarge) as DynError,
            invalid_input("secret-canary"),
            not_found("secret-canary"),
            conflict("secret-canary"),
            forbidden("secret-canary"),
            invalid_signature("secret-canary"),
            config_signature_stale("secret-canary"),
            remote_unreachable("secret-canary"),
            storage("secret-canary"),
            overloaded("secret-canary"),
            internal("secret-canary"),
        ];
        for source in [
            ConfigSource::Process,
            ConfigSource::EnvFile { line: 7 },
            ConfigSource::Default,
        ] {
            let origin = ConfigOrigin {
                name: "VECTIS_CONFIG_PATH",
                source,
            };
            for err in &errors {
                for category in [ConfigErrorCategory::Internal, ConfigErrorCategory::Storage] {
                    let contextual = origin.context("could not read file", err.as_ref(), category);
                    assert_category(&contextual, category);
                    assert_eq!(
                        contextual.to_string(),
                        format!("{origin}: could not read file")
                    );
                    assert!(!contextual.to_string().contains("secret-canary"));
                    let internal = origin.internal_context("could not read file", err.as_ref());
                    assert_category(&internal, ConfigErrorCategory::Internal);
                    assert_eq!(internal.to_string(), contextual.to_string());
                }
            }
        }
    }

    #[test]
    fn io_and_unknown_errors_use_safe_categories() {
        let origin = ConfigOrigins::default().origin("VECTIS_POSTGRES_DSN");
        for kind in [
            io::ErrorKind::NotFound,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::ConnectionRefused,
        ] {
            let err = io::Error::new(kind, "postgres://user:secret-canary@host/db");
            for category in [ConfigErrorCategory::Internal, ConfigErrorCategory::Storage] {
                let contextual = origin.context("could not connect", &err, category);
                assert_category(&contextual, category);
                assert_eq!(
                    contextual.to_string(),
                    format!("{origin}: could not connect ({kind:?})")
                );
                assert!(!contextual.to_string().contains("secret-canary"));
            }
        }
        let driver = sqlx::Error::Protocol("secret-canary".into());
        for category in [ConfigErrorCategory::Internal, ConfigErrorCategory::Storage] {
            let contextual = origin.context("incompatible schema", &driver, category);
            assert_category(&contextual, category);
            assert_eq!(
                contextual.to_string(),
                format!("{origin}: incompatible schema")
            );
            assert!(!contextual.to_string().contains("secret-canary"));
        }
    }
}

pub fn sanitized_serde_json_error_detail(error: &serde_json::Error) -> String {
    sanitize_untrusted_error_detail(&redact_serde_value(&error.to_string()))
}

pub fn invalid_json_input(context: &str, error: &serde_json::Error) -> DynError {
    invalid_input(format!(
        "{context}: {}",
        sanitized_serde_json_error_detail(error)
    ))
}

pub(crate) fn sanitize_untrusted_error_detail(detail: &str) -> String {
    let cleaned: String = detail
        .chars()
        .filter(|character| !character.is_control())
        .collect();
    let bounded: String = cleaned
        .chars()
        .take(UNTRUSTED_ERROR_DETAIL_MAX_CHARS)
        .collect();

    if bounded.trim().is_empty() {
        String::from(SANITIZED_SERDE_FALLBACK)
    } else {
        bounded
    }
}

fn redact_serde_value(message: &str) -> String {
    let markers = ["invalid type: ", "invalid value: "];
    let Some(value_region_start) = markers
        .iter()
        .filter_map(|marker| message.find(marker).map(|position| position + marker.len()))
        .min()
    else {
        return String::from(message);
    };

    let value_region = &message[value_region_start..];
    let Some((open_offset, delimiter)) = value_region
        .char_indices()
        .find(|&(_, character)| character == '`' || character == '"')
    else {
        return String::from(message);
    };

    let after_open = &value_region[open_offset + delimiter.len_utf8()..];
    let Some(close_offset) = after_open.find(delimiter) else {
        return String::from(message);
    };

    let value_start = value_region_start + open_offset;
    let value_end = value_start + delimiter.len_utf8() + close_offset + delimiter.len_utf8();
    let prefix = message[..value_start].trim_end();

    format!("{prefix}{}", &message[value_end..])
}

pub fn with_prefix(prefix: &str, err: DynError) -> DynError {
    match err.downcast_ref::<VectisError>() {
        Some(VectisError::TokenDecodeBatchTooLarge) => err,
        Some(VectisError::InvalidInput(message)) => invalid_input(format!("{prefix}: {message}")),
        Some(VectisError::NotFound(message)) => not_found(format!("{prefix}: {message}")),
        Some(VectisError::Conflict(message)) => conflict(format!("{prefix}: {message}")),
        Some(VectisError::Forbidden(message)) => forbidden(format!("{prefix}: {message}")),
        Some(VectisError::InvalidSignature(message)) => {
            invalid_signature(format!("{prefix}: {message}"))
        }
        Some(VectisError::ConfigSignatureStale(message)) => {
            config_signature_stale(format!("{prefix}: {message}"))
        }
        Some(VectisError::RemoteUnreachable(message)) => {
            remote_unreachable(format!("{prefix}: {message}"))
        }
        Some(VectisError::Storage(message)) => storage(format!("{prefix}: {message}")),
        Some(VectisError::Overloaded(message)) => overloaded(format!("{prefix}: {message}")),
        Some(VectisError::Internal(message)) => internal(format!("{prefix}: {message}")),
        None => internal(format!("{prefix}: {err}")),
    }
}

pub fn is_config_signature_stale(err: &(dyn Error + Send + Sync + 'static)) -> bool {
    matches!(
        err.downcast_ref::<VectisError>(),
        Some(VectisError::ConfigSignatureStale(_))
    )
}

pub fn is_not_found(err: &(dyn Error + Send + Sync + 'static)) -> bool {
    if matches!(
        err.downcast_ref::<VectisError>(),
        Some(VectisError::NotFound(_))
    ) {
        return true;
    }

    err.downcast_ref::<io::Error>()
        .is_some_and(|err| err.kind() == io::ErrorKind::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitized_serde_detail_removes_control_characters_from_field_names() {
        let error = serde_json::from_str::<serde_json::Value>("{\"field\\u007f\":}")
            .expect_err("JSON must fail");
        let detail = sanitized_serde_json_error_detail(&error);

        assert!(!detail.chars().any(char::is_control));
    }

    #[test]
    fn sanitized_serde_detail_redacts_type_values() {
        let error = serde_json::from_str::<String>("4111111111111111")
            .expect_err("number must not deserialize as a string");
        let detail = sanitized_serde_json_error_detail(&error);

        assert!(!detail.contains("4111111111111111"));
    }

    #[test]
    fn untrusted_error_detail_is_bounded_and_uses_fallback() {
        assert_eq!(
            sanitize_untrusted_error_detail("\u{7f}\n\r"),
            "invalid JSON"
        );
        assert_eq!(
            sanitize_untrusted_error_detail(&"x".repeat(UNTRUSTED_ERROR_DETAIL_MAX_CHARS + 1))
                .chars()
                .count(),
            UNTRUSTED_ERROR_DETAIL_MAX_CHARS
        );
    }
}
