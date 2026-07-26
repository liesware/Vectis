use crate::core::config;
use std::collections::HashMap;
use std::env;
use std::fs;
use tracing::{Level, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_LOG_DIR: &str = "logs";
const DEFAULT_LOG_FILE: &str = "vectis.log";
const DEFAULT_AUDIT_LOG_FILE: &str = "audit.log";
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

pub fn init_logging() -> LoggingGuards {
    let config = logging_config();

    let (operational_writer, operational_guard) = match config.target {
        LogTarget::File => {
            fs::create_dir_all(&config.dir).expect("failed to create log directory");

            let operational_appender = tracing_appender::rolling::daily(&config.dir, &config.file);
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

    tracing::subscriber::set_global_default(subscriber).expect("failed to set tracing subscriber");
    info!(
        log_level = %config.level,
        log_target = %config.target,
        log_dir = %config.dir,
        log_file = %config.file,
        audit_file = %config.audit_file,
        "logging initialized"
    );

    LoggingGuards {
        _operational: operational_guard,
    }
}

pub fn logging_config() -> LoggingConfig {
    // Runs during logging bootstrap, before the tracing subscriber exists, so a
    // rejected .env (oversized or invalid UTF-8) is reported to stderr rather
    // than silently falling back to default logging.
    let env_file = config::load_env_file(".env").unwrap_or_else(|err| {
        eprintln!("warning: failed to read .env for logging configuration, using defaults: {err}");
        HashMap::new()
    });
    let level_text = config_value(&env_file, "VECTIS_LOG_LEVEL", DEFAULT_LOG_LEVEL);
    let level = parse_log_level(&level_text);
    let dir = config_value(&env_file, "VECTIS_LOG_DIR", DEFAULT_LOG_DIR);
    let file = config_value(&env_file, "VECTIS_LOG_FILE", DEFAULT_LOG_FILE);
    let audit_file = config_value(&env_file, "VECTIS_AUDIT_LOG_FILE", DEFAULT_AUDIT_LOG_FILE);
    let target = parse_log_target(&config_value(
        &env_file,
        "VECTIS_LOG_TARGET",
        DEFAULT_LOG_TARGET,
    ));

    LoggingConfig {
        level,
        dir,
        file,
        audit_file,
        target,
    }
}

fn parse_log_level(value: &str) -> Level {
    match value.trim().to_ascii_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" | "warning" => Level::WARN,
        "error" => Level::ERROR,
        _ => {
            warn!(value, "invalid VECTIS_LOG_LEVEL, falling back to info");
            Level::INFO
        }
    }
}

fn parse_log_target(value: &str) -> LogTarget {
    match value.trim().to_ascii_lowercase().as_str() {
        "file" => LogTarget::File,
        "stdout" => LogTarget::Stdout,
        _ => {
            warn!(value, "invalid VECTIS_LOG_TARGET, falling back to file");
            LogTarget::File
        }
    }
}

fn config_value(env_file: &HashMap<String, String>, key: &str, default: &str) -> String {
    env::var(key)
        .ok()
        .or_else(|| env_file.get(key).cloned())
        .unwrap_or_else(|| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_target_defaults_to_file() {
        assert_eq!(parse_log_target(DEFAULT_LOG_TARGET), LogTarget::File);
    }

    #[test]
    fn log_target_accepts_file() {
        assert_eq!(parse_log_target("file"), LogTarget::File);
    }

    #[test]
    fn log_target_accepts_stdout() {
        assert_eq!(parse_log_target("stdout"), LogTarget::Stdout);
    }

    #[test]
    fn log_target_invalid_value_falls_back_to_file() {
        assert_eq!(parse_log_target("journald"), LogTarget::File);
    }
}
