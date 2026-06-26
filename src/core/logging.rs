use std::collections::HashMap;
use std::env;
use std::fs;
use tracing::{Level, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::FmtSubscriber;

const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_LOG_DIR: &str = "logs";
const DEFAULT_LOG_FILE: &str = "vectis.log";

pub struct LoggingConfig {
    pub level: Level,
    pub dir: String,
    pub file: String,
}

pub fn init_logging() -> WorkerGuard {
    let config = logging_config();
    fs::create_dir_all(&config.dir).expect("failed to create log directory");
    let file_appender = tracing_appender::rolling::daily(&config.dir, &config.file);
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let subscriber = FmtSubscriber::builder()
        .with_max_level(config.level)
        .with_writer(non_blocking)
        .json()
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("failed to set tracing subscriber");
    info!(
        log_level = %config.level,
        log_dir = %config.dir,
        log_file = %config.file,
        "logging initialized"
    );

    guard
}

pub fn logging_config() -> LoggingConfig {
    let env_file = load_env_file(".env").unwrap_or_default();
    let level_text = config_value(&env_file, "VECTIS_LOG_LEVEL", DEFAULT_LOG_LEVEL);
    let level = parse_log_level(&level_text);
    let dir = config_value(&env_file, "VECTIS_LOG_DIR", DEFAULT_LOG_DIR);
    let file = config_value(&env_file, "VECTIS_LOG_FILE", DEFAULT_LOG_FILE);

    LoggingConfig { level, dir, file }
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
