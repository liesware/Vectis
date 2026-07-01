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

pub const AUDIT_TARGET: &str = "vectis::audit";

pub struct LoggingConfig {
    pub level: Level,
    pub dir: String,
    pub file: String,
    pub audit_file: String,
}

pub struct LoggingGuards {
    _operational: WorkerGuard,
    _audit: WorkerGuard,
}

pub fn init_logging() -> LoggingGuards {
    let config = logging_config();
    fs::create_dir_all(&config.dir).expect("failed to create log directory");

    let operational_appender = tracing_appender::rolling::daily(&config.dir, &config.file);
    let (operational_writer, operational_guard) =
        tracing_appender::non_blocking(operational_appender);

    let audit_appender = tracing_appender::rolling::daily(&config.dir, &config.audit_file);
    let (audit_writer, audit_guard) = tracing_appender::non_blocking(audit_appender);

    let level = config.level;
    let operational_layer = fmt::layer()
        .json()
        .with_writer(operational_writer)
        .with_filter(filter_fn(move |metadata| {
            metadata.is_span()
                || (metadata.target() != AUDIT_TARGET && *metadata.level() <= level)
        }));

    let audit_layer = fmt::layer()
        .json()
        .with_writer(audit_writer)
        .with_filter(filter_fn(|metadata| {
            metadata.is_span() || metadata.target() == AUDIT_TARGET
        }));

    let subscriber = tracing_subscriber::registry()
        .with(operational_layer)
        .with(audit_layer);

    tracing::subscriber::set_global_default(subscriber).expect("failed to set tracing subscriber");
    info!(
        log_level = %config.level,
        log_dir = %config.dir,
        log_file = %config.file,
        audit_file = %config.audit_file,
        "logging initialized"
    );

    LoggingGuards {
        _operational: operational_guard,
        _audit: audit_guard,
    }
}

pub fn logging_config() -> LoggingConfig {
    let env_file = load_env_file(".env").unwrap_or_default();
    let level_text = config_value(&env_file, "VECTIS_LOG_LEVEL", DEFAULT_LOG_LEVEL);
    let level = parse_log_level(&level_text);
    let dir = config_value(&env_file, "VECTIS_LOG_DIR", DEFAULT_LOG_DIR);
    let file = config_value(&env_file, "VECTIS_LOG_FILE", DEFAULT_LOG_FILE);
    let audit_file = config_value(&env_file, "VECTIS_AUDIT_LOG_FILE", DEFAULT_AUDIT_LOG_FILE);

    LoggingConfig {
        level,
        dir,
        file,
        audit_file,
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

fn load_env_file(path: &str) -> Result<HashMap<String, String>, std::io::Error> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(err) => return Err(err),
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

        values.insert(key.trim().to_string(), clean_env_value(value.trim()));
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
