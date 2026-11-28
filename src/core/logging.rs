use crate::core::{config_loader::ConfigLoader, validation};
use crate::error::{self, ConfigOrigins, DynError};
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::sync::Arc;
use tracing::{Level, info};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

struct OperationalWriter<W, D> {
    inner: W,
    origin: crate::error::ConfigOrigin,
    diagnostics: D,
    reported: HashSet<io::ErrorKind>,
}

impl<W: Write, D: Write> OperationalWriter<W, D> {
    fn new(inner: W, origin: crate::error::ConfigOrigin, diagnostics: D) -> Self {
        Self {
            inner,
            origin,
            diagnostics,
            reported: HashSet::new(),
        }
    }

    fn result<T>(&mut self, result: io::Result<T>, reason: &'static str) -> io::Result<T> {
        result.map_err(|err| {
            let safe = self
                .origin
                .context(reason, &err, error::ConfigErrorCategory::Internal);
            if self.reported.insert(err.kind()) {
                let _ = writeln!(&mut self.diagnostics, "{safe}");
            }
            io::Error::new(err.kind(), safe.to_string())
        })
    }
}

impl<W: Write, D: Write> Write for OperationalWriter<W, D> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let result = self.inner.write(bytes);
        self.result(result, "could not write operational log")
    }

    fn flush(&mut self) -> io::Result<()> {
        let result = self.inner.flush();
        self.result(result, "could not flush operational log")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogFileName(String);

impl LogFileName {
    pub fn parse(value: &str) -> Result<Self, DynError> {
        validation::validate_text_field("log file name", value)?;
        if matches!(value, "." | "..")
            || value.contains(['/', '\\'])
            || std::path::Path::new(value).is_absolute()
        {
            return Err(error::invalid_input(
                "must be a file name without path separators",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for LogFileName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
const DEFAULT_LOG_TARGET: &str = "file";

pub struct LoggingConfig {
    pub origins: Arc<ConfigOrigins>,
    pub level: Level,
    pub dir: String,
    pub file: LogFileName,
    pub audit_file: LogFileName,
    pub target: LogTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogTarget {
    File,
    Stdout,
}

impl std::fmt::Display for LogTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File => f.write_str("file"),
            Self::Stdout => f.write_str("stdout"),
        }
    }
}

pub struct LoggingGuards {
    _operational: WorkerGuard,
}

pub fn init_logging(loader: &ConfigLoader) -> Result<LoggingGuards, crate::error::DynError> {
    let config = logging_config(loader)?;

    let (operational_writer, operational_guard) = match config.target {
        LogTarget::File => {
            fs::create_dir_all(&config.dir).map_err(|err| {
                config.origins.origin("VECTIS_LOG_DIR").context(
                    "could not create log directory",
                    &err,
                    error::ConfigErrorCategory::Internal,
                )
            })?;

            let operational_appender = tracing_appender::rolling::RollingFileAppender::builder()
                .rotation(tracing_appender::rolling::Rotation::DAILY)
                .filename_prefix(config.file.as_str())
                .build(&config.dir)
                .map_err(|err| {
                    config.origins.origin("VECTIS_LOG_FILE").context(
                        "could not open operational log",
                        &err,
                        error::ConfigErrorCategory::Internal,
                    )
                })?;
            let (operational_writer, operational_guard) =
                tracing_appender::non_blocking(OperationalWriter::new(
                    operational_appender,
                    config.origins.origin("VECTIS_LOG_FILE"),
                    io::stderr(),
                ));

            (operational_writer, operational_guard)
        }
        LogTarget::Stdout => {
            let (operational_writer, operational_guard) =
                tracing_appender::non_blocking(std::io::stdout());
            (operational_writer, operational_guard)
        }
    };

    let level = config.level;
    let operational_layer = fmt::layer()
        .json()
        .with_writer(operational_writer)
        .with_filter(filter_fn(move |metadata| {
            metadata.is_span() || *metadata.level() <= level
        }));

    let subscriber = tracing_subscriber::registry().with(operational_layer);

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| crate::error::internal("could not initialize logging"))?;
    info!(
        log_level = %config.level,
        log_target = %config.target,
        log_dir = %config.dir,
        log_file = %config.file,
        audit_file = %config.audit_file,
        "logging initialized"
    );

    Ok(LoggingGuards {
        _operational: operational_guard,
    })
}

pub fn logging_config(loader: &ConfigLoader) -> Result<LoggingConfig, crate::error::DynError> {
    let level = loader.parse("VECTIS_LOG_LEVEL", "unsupported log level", parse_log_level)?;
    let target = loader.parse(
        "VECTIS_LOG_TARGET",
        "unsupported log target",
        parse_log_target,
    )?;
    let text = |name| {
        loader.parse(name, "must be nonempty text without controls", |v| {
            validation::validate_text_field(name, v)?;
            Ok(v.to_owned())
        })
    };
    let dir = text("VECTIS_LOG_DIR")?;
    let file = loader.parse(
        "VECTIS_LOG_FILE",
        "must be a file name without path separators",
        LogFileName::parse,
    )?;
    let audit_file = loader.parse(
        "VECTIS_AUDIT_LOG_FILE",
        "must be a file name without path separators",
        LogFileName::parse,
    )?;
    if target == LogTarget::File
        && (audit_file == file || audit_file.as_str().starts_with(&format!("{file}.")))
    {
        return Err(loader.error(
            "VECTIS_AUDIT_LOG_FILE",
            "must not equal VECTIS_LOG_FILE or start with its name followed by '.'",
        ));
    }
    Ok(LoggingConfig {
        origins: loader.origins(),
        level,
        target,
        dir,
        file,
        audit_file,
    })
}

fn parse_log_level(value: &str) -> Result<Level, crate::error::DynError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "trace" => Ok(Level::TRACE),
        "debug" => Ok(Level::DEBUG),
        "info" => Ok(Level::INFO),
        "warn" | "warning" => Ok(Level::WARN),
        "error" => Ok(Level::ERROR),
        _ => Err(crate::error::invalid_input("unsupported log level")),
    }
}

fn parse_log_target(value: &str) -> Result<LogTarget, crate::error::DynError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "file" => Ok(LogTarget::File),
        "stdout" => Ok(LogTarget::Stdout),
        _ => Err(crate::error::invalid_input("unsupported log target")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_names_cannot_use_the_operational_file_namespace() {
        for audit in [
            "secret-canary.log",
            "secret-canary.log.2026-11-27",
            "secret-canary.log.backup",
        ] {
            for from_file in [false, true] {
                let content = if from_file {
                    format!(
                        "# synthetic\nVECTIS_LOG_FILE=secret-canary.log\nVECTIS_AUDIT_LOG_FILE={audit}"
                    )
                } else {
                    String::new()
                };
                let loader = ConfigLoader::from_sources(&content, |name| {
                    if from_file {
                        return None;
                    }
                    match name {
                        "VECTIS_LOG_FILE" => Some("secret-canary.log".into()),
                        "VECTIS_AUDIT_LOG_FILE" => Some(audit.into()),
                        _ => None,
                    }
                })
                .unwrap();
                let err = logging_config(&loader)
                    .err()
                    .expect("reserved audit name must fail")
                    .to_string();
                let source = if from_file {
                    "env_file line 3"
                } else {
                    "process"
                };
                assert_eq!(
                    err,
                    format!(
                        "VECTIS_AUDIT_LOG_FILE ({source}): must not equal VECTIS_LOG_FILE or start with its name followed by '.'"
                    )
                );
                assert!(!err.contains("secret-canary"));
            }
        }
    }

    #[test]
    fn independent_names_and_stdout_preserve_exact_names() {
        for (target, audit) in [
            ("file", "audit.log"),
            ("file", "vectis.logx"),
            ("file", "Vectis.log.2026-11-27"),
            ("file", " vectis.log.backup "),
            ("stdout", "vectis.log"),
            ("stdout", "vectis.log.2026-11-27"),
            ("stdout", "vectis.log.backup"),
        ] {
            let loader = ConfigLoader::from_sources("", |name| match name {
                "VECTIS_LOG_TARGET" => Some(target.into()),
                "VECTIS_AUDIT_LOG_FILE" => Some(audit.into()),
                _ => None,
            })
            .unwrap();
            assert_eq!(logging_config(&loader).unwrap().audit_file.as_str(), audit);
        }
        let invalid = ConfigLoader::from_sources(
            "VECTIS_LOG_TARGET=stdout\nVECTIS_AUDIT_LOG_FILE=../x",
            |_| None,
        )
        .unwrap();
        assert!(logging_config(&invalid).is_err());
    }

    #[test]
    fn file_names_are_not_paths_and_preserve_valid_text() {
        for value in [
            "", " ", ".", "..", "../x", "a/b", "a\\b", "/tmp/x", "a\n", "a\0",
        ] {
            assert!(LogFileName::parse(value).is_err(), "{value:?}");
        }
        for value in [
            "vectis.log",
            ".hidden",
            "a..b",
            " ordinary name.log ",
            "é.log",
        ] {
            assert_eq!(LogFileName::parse(value).unwrap().as_str(), value);
        }
    }

    #[test]
    fn operational_writer_errors_are_sanitized() {
        struct Failing;
        impl Write for Failing {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "secret-canary",
                ))
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("secret-canary"))
            }
        }
        let mut writer = OperationalWriter::new(
            Failing,
            ConfigOrigins::default().origin("VECTIS_LOG_FILE"),
            Vec::new(),
        );
        for err in [
            writer.write(b"event").unwrap_err(),
            writer.flush().unwrap_err(),
        ] {
            assert!(err.to_string().contains("VECTIS_LOG_FILE (default)"));
            assert!(!err.to_string().contains("secret-canary"));
        }
    }

    struct ScriptedWriter {
        outcomes: std::collections::VecDeque<Option<io::ErrorKind>>,
        calls: usize,
    }

    impl ScriptedWriter {
        fn result(&mut self) -> io::Result<()> {
            self.calls += 1;
            match self.outcomes.pop_front().expect("expected an operation") {
                Some(kind) => Err(io::Error::new(kind, "secret-canary")),
                None => Ok(()),
            }
        }
    }

    impl Write for ScriptedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.result().map(|()| bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.result()
        }
    }

    #[test]
    fn operational_diagnostics_are_once_per_kind_across_writes_flushes_and_recovery() {
        let first = io::ErrorKind::PermissionDenied;
        let second = io::ErrorKind::Other;
        let origin = ConfigOrigins::default().origin("VECTIS_LOG_FILE");
        let mut writer = OperationalWriter::new(
            ScriptedWriter {
                outcomes: [
                    Some(first),
                    Some(first),
                    None,
                    Some(second),
                    Some(first),
                    None,
                    Some(second),
                ]
                .into(),
                calls: 0,
            },
            origin,
            Vec::new(),
        );
        assert_eq!(writer.write(b"a").unwrap_err().kind(), first);
        assert_eq!(writer.flush().unwrap_err().kind(), first);
        assert_eq!(writer.write(b"recovered").unwrap(), 9);
        assert_eq!(writer.flush().unwrap_err().kind(), second);
        assert_eq!(writer.write(b"b").unwrap_err().kind(), first);
        writer.flush().unwrap();
        assert_eq!(writer.write(b"c").unwrap_err().kind(), second);
        assert_eq!(writer.inner.calls, 7);
        let diagnostics = String::from_utf8(writer.diagnostics).unwrap();
        assert_eq!(diagnostics.lines().count(), 2);
        assert!(diagnostics.contains("(PermissionDenied)"));
        assert!(diagnostics.contains("(Other)"));
        assert!(!diagnostics.contains("secret-canary"));
    }

    #[test]
    fn failed_diagnostics_do_not_panic_or_retry_reported_kinds() {
        struct ClosedDiagnostics {
            attempts: usize,
        }
        impl Write for ClosedDiagnostics {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.attempts += 1;
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "secret-canary"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let origin = ConfigOrigins::default().origin("VECTIS_LOG_FILE");
        let mut writer = OperationalWriter::new(
            ScriptedWriter {
                outcomes: [Some(io::ErrorKind::Other); 3].into(),
                calls: 0,
            },
            origin,
            ClosedDiagnostics { attempts: 0 },
        );
        for _ in 0..2 {
            assert_eq!(writer.write(b"a").unwrap_err().kind(), io::ErrorKind::Other);
        }
        assert_eq!(writer.flush().unwrap_err().kind(), io::ErrorKind::Other);
        assert_eq!(writer.diagnostics.attempts, 1);
        assert_eq!(writer.inner.calls, 3);
    }

    #[test]
    fn log_target_defaults_to_file() {
        assert_eq!(
            parse_log_target(DEFAULT_LOG_TARGET).unwrap(),
            LogTarget::File
        );
    }

    #[test]
    fn log_target_accepts_file() {
        assert_eq!(parse_log_target("file").unwrap(), LogTarget::File);
    }

    #[test]
    fn log_target_accepts_stdout() {
        assert_eq!(parse_log_target("stdout").unwrap(), LogTarget::Stdout);
    }

    #[test]
    fn log_target_invalid_value_is_rejected() {
        assert!(parse_log_target("journald").is_err());
    }
}
