use crate::core::{config_loader::ConfigLoader, validation};
use std::fs;
use tracing::{Level, info};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

#[cfg(test)]
const DEFAULT_LOG_TARGET: &str = "file";

pub struct LoggingConfig {
    pub level: Level,
    pub dir: String,
    pub file: String,
    pub audit_file: String,
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
            fs::create_dir_all(&config.dir)
                .map_err(|_| crate::error::internal("could not create log directory"))?;

            let operational_appender = tracing_appender::rolling::RollingFileAppender::builder()
                .rotation(tracing_appender::rolling::Rotation::DAILY)
                .filename_prefix(&config.file)
                .build(&config.dir)
                .map_err(|_| loader.error("VECTIS_LOG_FILE", "could not open operational log"))?;
            let (operational_writer, operational_guard) =
                tracing_appender::non_blocking(operational_appender);

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
        // Spans always pass so request_id/method/path correlation survives at WARN+.
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
    Ok(LoggingConfig {
        level,
        target,
        dir: text("VECTIS_LOG_DIR")?,
        file: text("VECTIS_LOG_FILE")?,
        audit_file: text("VECTIS_AUDIT_LOG_FILE")?,
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
