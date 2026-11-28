use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use vectis::core::{
    config,
    config_loader::{ConfigLoader, VARIABLES},
    logging,
};
use vectis::error::{ConfigSource, DynError};

#[derive(Clone, Copy)]
enum Consumer {
    App,
    Logging,
    Path,
    Client,
    Unseal,
}

struct Contract {
    name: &'static str,
    meaning: &'static str,
    condition: &'static str,
    consumer: Consumer,
    valid: &'static str,
    invalid: &'static str,
}

macro_rules! contracts {
    ($($name:literal, $meaning:literal, $condition:literal, $consumer:ident, $valid:literal, $invalid:literal;)*) => {
        const CONTRACTS: &[Contract] = &[$(Contract { name: concat!("VECTIS_", $name), meaning: $meaning,
            condition: $condition, consumer: Consumer::$consumer, valid: $valid, invalid: $invalid },)*];
    };
}

contracts! {
    "MODE", "transport mode", "server or HTTP client", App, "dev", "secret-canary";
    "HTTP_BIND_ADDR", "listen socket", "serve", App, "127.0.0.1:3000", "secret-canary";
    "PUBLIC_ADDR", "public authority", "serve", App, "localhost:3000", "secret-canary";
    "FINAL_APP_ADDR", "forwarding authority", "local node configuration", App, "localhost:3999", "secret-canary";
    "FINAL_APP_PATH", "forwarding path", "local node configuration", App, "/message", "secret-canary";
    "TLS_CERT_PATH", "certificate path", "nonempty server TLS setting", App, "@file", "/secret-canary/missing";
    "TLS_KEY_PATH", "private key path", "nonempty server TLS setting", App, "@file", "/secret-canary/missing";
    "TLS_SKIP_VERIFY", "TLS verification policy", "HTTP client", App, "false", "secret-canary";
    "CONFIG_PATH", "signed configuration path", "local node configuration", App, "config.json", "";
    "CONFIG_SIGN_PATH", "configuration signature path", "local node configuration", App, "config-sign.json", "";
    "APIKEY_HASH", "root authentication digest", "serve", App, "", "secret-canary";
    "PROTOCOL_VERSION", "wire protocol", "bootstrap", App, "v1", "secret-canary";
    "STORAGE", "backend selector", "storage consumer", App, "sqlite", "secret-canary";
    "SQLITE_PATH", "SQLite file", "active SQLite backend", App, "@file", "/secret-canary/missing";
    "POSTGRES_DSN", "PostgreSQL connection string", "active PostgreSQL backend", App, "postgres://user:password@localhost/db", "secret-canary";
    "SENDER_HOSTNAME", "sender identity", "bootstrap", App, "localhost.local", "secret-canary/host";
    "RECEIVER_HOSTNAME", "receiver identity", "bootstrap", App, "remotehost.local", "secret-canary/host";
    "HASH", "hash algorithm", "serve", App, "BLAKE2b(256)", "secret-canary";
    "SYMMETRIC", "AEAD algorithm", "serve", App, "ChaCha20Poly1305", "secret-canary";
    "EDDSA", "signature algorithm", "serve", App, "Ed25519", "secret-canary";
    "XECDH", "agreement algorithm", "serve", App, "X25519", "secret-canary";
    "ML_DSA_VARIANT", "PQ signature variant", "serve", App, "ML-DSA-44", "secret-canary";
    "ML_KEM_VARIANT", "PQ KEM variant", "serve", App, "ML-KEM-512", "secret-canary";
    "DEFAULT_CRYPTO_PROFILE", "key creation profile", "serve", App, "hybrid-performance-v1", "secret-canary";
    "CRYPTO_POLICY", "override policy", "serve", App, "profile-only", "secret-canary";
    "METRICS_ENABLED", "metrics switch", "serve", App, "true", "secret-canary";
    "MAX_CONCURRENT_CRYPTO", "active worker capacity", "crypto admission", App, "4", "secret-canary";
    "MAX_QUEUED_CRYPTO", "waiting capacity", "crypto admission", App, "128", "secret-canary";
    "CRYPTO_QUEUE_TIMEOUT_MS", "queue deadline", "crypto admission", App, "1000", "secret-canary";
    "PLAINTEXT_MESSAGE", "bootstrap plaintext", "bootstrap", App, "synthetic message", "";
    "INIT_KEYS_FILE", "private init path", "init consumer", Path, "init.json", "";
    "INIT_PUBLIC_KEYS_FILE", "public init path", "init consumer", Path, "init_pub.json", "";
    "UNSEAL_KEY_FILE", "unseal file path", "unseal consumer", Path, ".unseal_key", "";
    "API_URL", "CLI endpoint", "CLI HTTP command", Client, "http://127.0.0.1:9", "secret-canary";
    "APIKEY", "CLI credential", "authenticated CLI command", Client, "", "secret-canary";
    "TIMEOUT_SECONDS", "CLI deadline", "CLI HTTP command", Client, "30", "secret-canary";
    "LOG_LEVEL", "operational severity", "logging initialization", Logging, "info", "secret-canary";
    "LOG_TARGET", "operational destination", "logging initialization", Logging, "file", "secret-canary";
    "LOG_DIR", "log directory", "file logging or audit", Logging, "logs", "";
    "LOG_FILE", "operational basename", "logging initialization", Logging, "ordinary name.log", "../secret-canary";
    "AUDIT_LOG_FILE", "audit basename", "logging initialization", Logging, "audit.log", "../secret-canary";
    "UNSEAL_KEY", "unseal secret", "process source only", Unseal, "", "secret-canary";
}

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Lab(PathBuf);
impl Lab {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vectis-config-contract-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::write(path.join("fixture"), "synthetic").unwrap();
        Self(path)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vectis"));
        command.current_dir(&self.0);
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("VECTIS_") {
                command.env_remove(key);
            }
        }
        command.env("VECTIS_LOG_TARGET", "stdout");
        command
    }

    fn initialize(&self) -> String {
        let output = self.command().arg("init").output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("VECTIS_UNSEAL_KEY=").map(str::to_owned))
            .unwrap()
    }

    fn assert_error(&self, output: Output, name: &str, source: &str) -> String {
        assert!(!output.status.success());
        let message = String::from_utf8(output.stderr).unwrap();
        assert!(message.contains(&format!("{name} ({source})")), "{message}");
        assert!(!message.contains("secret-canary"), "{message}");
        message
    }
}

#[tokio::test]
async fn delayed_file_storage_tls_and_bind_failures_keep_provenance() {
    use std::os::unix::fs::PermissionsExt;
    let lab = Lab::new();
    let unseal = lab.initialize();
    let database = lab.0.join("runtime.db");
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&database)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("../src/db/sqlite_schema.sql"))
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let serve = || {
        let mut command = lab.command();
        command
            .env("VECTIS_UNSEAL_KEY", &unseal)
            .env("VECTIS_SQLITE_PATH", &database)
            .arg("serve");
        command
    };
    for (name, value) in [
        ("VECTIS_INIT_KEYS_FILE", lab.0.join("secret-canary-missing")),
        ("VECTIS_CONFIG_PATH", lab.0.clone()),
        ("VECTIS_SQLITE_PATH", lab.0.join("fixture")),
    ] {
        lab.assert_error(serve().env(name, value).output().unwrap(), name, "process");
    }
    let private = lab.0.join("init.json");
    fs::set_permissions(&private, fs::Permissions::from_mode(0o644)).unwrap();
    lab.assert_error(
        serve().output().unwrap(),
        "VECTIS_INIT_KEYS_FILE",
        "default",
    );
    fs::set_permissions(&private, fs::Permissions::from_mode(0o600)).unwrap();

    for (name, filename, reason) in [
        (
            "VECTIS_INIT_KEYS_FILE",
            "init.json",
            "could not read init keys file",
        ),
        (
            "VECTIS_INIT_PUBLIC_KEYS_FILE",
            "init_pub.json",
            "could not read init public keys file",
        ),
        (
            "VECTIS_CONFIG_PATH",
            "config.json",
            "could not read config file",
        ),
    ] {
        let path = lab.0.join(filename);
        let original = fs::read(&path).ok();
        let permissions = fs::metadata(&path)
            .map(|metadata| metadata.permissions())
            .unwrap_or_else(|_| fs::Permissions::from_mode(0o600));
        fs::write(&path, b"secret-canary\xff").unwrap();
        fs::set_permissions(&path, permissions.clone()).unwrap();
        let consumer = || {
            if name == "VECTIS_INIT_PUBLIC_KEYS_FILE" {
                let mut command = lab.command();
                command.args(["audit", "verify", "--file", "unused.jsonl"]);
                command
            } else {
                serve()
            }
        };
        for source in ["default", "process", "env_file line 2"] {
            if source == "env_file line 2" {
                fs::write(
                    lab.0.join(".env"),
                    format!("# synthetic\n{name}={filename}\n"),
                )
                .unwrap();
            }
            let mut command = consumer();
            if source == "process" {
                command.env(name, &path);
            }
            let message = lab.assert_error(command.output().unwrap(), name, source);
            assert!(message.contains(&format!(": {reason}")), "{message}");
            assert!(!message.contains("size limit"));
            if source == "env_file line 2" {
                fs::remove_file(lab.0.join(".env")).unwrap();
            }
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read(&path).is_err() {
            let message = lab.assert_error(
                consumer().env(name, &path).output().unwrap(),
                name,
                "process",
            );
            assert!(message.contains(&format!(": {reason}")), "{message}");
            assert!(!message.contains("size limit"));
        }
        fs::set_permissions(&path, permissions).unwrap();
        match original {
            Some(bytes) => fs::write(&path, bytes).unwrap(),
            None => fs::remove_file(&path).unwrap(),
        }
    }

    let audit_directory = lab.0.join("audit-logs");
    fs::create_dir(&audit_directory).unwrap();
    let audit_path = audit_directory.join("audit.log");
    let target = lab.0.join("secret-canary-target");
    for existing in [true, false] {
        if existing {
            fs::write(&target, b"unchanged").unwrap();
        }
        std::os::unix::fs::symlink(&target, &audit_path).unwrap();
        lab.assert_error(
            serve()
                .env("VECTIS_LOG_TARGET", "file")
                .env("VECTIS_LOG_DIR", &audit_directory)
                .env("VECTIS_AUDIT_LOG_FILE", "audit.log")
                .output()
                .unwrap(),
            "VECTIS_AUDIT_LOG_FILE",
            "process",
        );
        assert_eq!(target.exists(), existing);
        if existing {
            assert_eq!(fs::read(&target).unwrap(), b"unchanged");
            fs::remove_file(&target).unwrap();
        }
        fs::remove_file(&audit_path).unwrap();
    }

    lab.assert_error(
        lab.command()
            .env(
                "VECTIS_INIT_PUBLIC_KEYS_FILE",
                lab.0.join("secret-canary-missing"),
            )
            .args(["audit", "verify", "--file", "unused.jsonl"])
            .output()
            .unwrap(),
        "VECTIS_INIT_PUBLIC_KEYS_FILE",
        "process",
    );
    lab.assert_error(
        lab.command()
            .env(
                "VECTIS_CONFIG_PATH",
                lab.0.join("secret-canary-parent/config.json"),
            )
            .args(["config", "init"])
            .output()
            .unwrap(),
        "VECTIS_CONFIG_PATH",
        "process",
    );

    fs::write(lab.0.join("config.json"), r#"{"version":"v1"}"#).unwrap();
    lab.assert_error(
        lab.command()
            .env("VECTIS_UNSEAL_KEY", &unseal)
            .env("VECTIS_SQLITE_PATH", &database)
            .env(
                "VECTIS_CONFIG_SIGN_PATH",
                lab.0.join("secret-canary-parent/sign.json"),
            )
            .args(["config", "sign"])
            .output()
            .unwrap(),
        "VECTIS_CONFIG_SIGN_PATH",
        "process",
    );
    lab.assert_error(
        serve().output().unwrap(),
        "VECTIS_CONFIG_SIGN_PATH",
        "default",
    );
    fs::remove_file(lab.0.join("config.json")).unwrap();

    let cert = lab.0.join("secret-canary-cert.pem");
    let key = lab.0.join("secret-canary-key.pem");
    fs::write(&cert, "secret-canary invalid certificate").unwrap();
    fs::write(&key, "secret-canary invalid key").unwrap();
    let error = lab.assert_error(
        serve()
            .env("VECTIS_MODE", "prod")
            .env("VECTIS_TLS_CERT_PATH", &cert)
            .env("VECTIS_TLS_KEY_PATH", &key)
            .output()
            .unwrap(),
        "VECTIS_TLS_CERT_PATH",
        "process",
    );
    assert!(error.contains("VECTIS_TLS_KEY_PATH (process)"));

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    lab.assert_error(
        serve()
            .env(
                "VECTIS_HTTP_BIND_ADDR",
                listener.local_addr().unwrap().to_string(),
            )
            .output()
            .unwrap(),
        "VECTIS_HTTP_BIND_ADDR",
        "process",
    );

    for name in ["VECTIS_INIT_KEYS_FILE", "VECTIS_INIT_PUBLIC_KEYS_FILE"] {
        let output = lab
            .command()
            .env("VECTIS_INIT_KEYS_FILE", lab.0.join("new-init.json"))
            .env(
                "VECTIS_INIT_PUBLIC_KEYS_FILE",
                lab.0.join("new-public.json"),
            )
            .env(name, lab.0.join("secret-canary-parent/missing.json"))
            .arg("init")
            .output()
            .unwrap();
        lab.assert_error(output, name, "process");
        assert!(!lab.0.join("new-init.json").exists());
    }
}

#[tokio::test]
async fn postgres_initialization_errors_are_sanitized_without_a_server() {
    let origins = vectis::error::ConfigOrigins::new([(
        "VECTIS_POSTGRES_DSN",
        ConfigSource::EnvFile { line: 3 },
    )]);
    let settings = config::StorageConfig::Postgres(zeroize::Zeroizing::new(
        "postgres://user:secret-canary@[invalid/db".into(),
    ));
    let result =
        vectis::core::storage::StorageState::from_config_with_origins(&settings, &origins).await;
    let err = result
        .err()
        .expect("invalid DSN must fail before connecting");
    assert!(matches!(
        err.downcast_ref::<vectis::error::VectisError>(),
        Some(vectis::error::VectisError::Storage(_))
    ));
    assert_eq!(
        err.to_string(),
        "VECTIS_POSTGRES_DSN (env_file line 3): could not connect to configured PostgreSQL storage"
    );
}
impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn every_registered_variable_has_an_independent_contract() {
    let expected: BTreeSet<_> = VARIABLES.iter().map(|v| v.name).collect();
    let actual: BTreeSet<_> = CONTRACTS.iter().map(|v| v.name).collect();
    assert_eq!(expected, actual);
    assert_eq!(actual.len(), CONTRACTS.len());
    for row in CONTRACTS {
        assert!(!row.meaning.is_empty() && !row.condition.is_empty());
    }
}

#[test]
fn consumers_validate_effective_values_with_metadata_only_origins() {
    let lab = Lab::new();
    let fixture = lab.0.join("fixture").to_str().unwrap().to_owned();
    for row in CONTRACTS {
        for valid in [true, false] {
            let value = if valid { row.valid } else { row.invalid };
            let value = if value == "@file" {
                fixture.as_str()
            } else {
                value
            };
            for file_source in [false, true] {
                if matches!(row.consumer, Consumer::Unseal | Consumer::Client) {
                    continue;
                }
                let content = if file_source {
                    format!("# synthetic\n{}='{value}'", row.name)
                } else {
                    String::new()
                };
                let loader = ConfigLoader::from_sources(&content, |name| {
                    if name == row.name && !file_source {
                        return Some(OsString::from(value));
                    }
                    if name == "VECTIS_SQLITE_PATH" && row.name != name {
                        return Some(OsString::from(&fixture));
                    }
                    if name == "VECTIS_STORAGE" && row.name == "VECTIS_POSTGRES_DSN" {
                        return Some("postgres".into());
                    }
                    None
                })
                .unwrap();
                let origins = loader.origins();
                assert!(Arc::ptr_eq(&origins, &loader.origins()));
                let result: Result<(), DynError> = match row.consumer {
                    Consumer::App => config::app_config(&loader).map(|_| ()),
                    Consumer::Logging => logging::logging_config(&loader).map(|_| ()),
                    Consumer::Path => config::configured_path(&loader, row.name).map(|_| ()),
                    _ => unreachable!(),
                };
                assert_eq!(
                    result.is_ok(),
                    valid,
                    "{}: {:?}",
                    row.name,
                    result.as_ref().err().map(|e| e.to_string())
                );
                if !valid {
                    let message = result.unwrap_err().to_string();
                    let source = if file_source {
                        "env_file line 2"
                    } else {
                        "process"
                    };
                    assert!(
                        message.contains(&format!("{} ({source})", row.name)),
                        "{message}"
                    );
                    assert!(!message.contains("secret-canary"));
                }
                drop(loader);
                assert_eq!(
                    origins.source(row.name),
                    if file_source {
                        ConfigSource::EnvFile { line: 2 }
                    } else {
                        ConfigSource::Process
                    }
                );
            }
        }
    }
}

#[test]
fn cli_consumers_sanitize_invalid_values_and_missing_credentials() {
    let lab = Lab::new();
    for row in CONTRACTS
        .iter()
        .filter(|row| matches!(row.consumer, Consumer::Client | Consumer::Unseal))
    {
        let mut command = lab.command();
        command.env(row.name, row.invalid);
        if matches!(row.consumer, Consumer::Unseal) {
            command.args(["init", "pub"]);
        } else {
            command.args(["keys", "list"]);
        }
        lab.assert_error(command.output().unwrap(), row.name, "process");
    }
    lab.assert_error(
        lab.command().args(["keys", "reload"]).output().unwrap(),
        "VECTIS_APIKEY",
        "default",
    );
    let output = lab
        .command()
        .env("VECTIS_API_URL", "http://user:secret-canary@127.0.0.1:9")
        .args(["health", "ready"])
        .output()
        .unwrap();
    lab.assert_error(output, "VECTIS_API_URL", "process");
}

#[test]
fn cli_response_read_errors_do_not_echo_urls_or_response_content() {
    use std::io::{Read, Write};
    let lab = Lab::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut buffer = [0; 4096];
        assert!(socket.read(&mut buffer).unwrap() > 0);
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nsecret-canary",
            )
            .unwrap();
    });
    let output = lab
        .command()
        .env(
            "VECTIS_API_URL",
            format!("http://user:secret-canary@{address}"),
        )
        .args(["health", "ready"])
        .output()
        .unwrap();
    server.join().unwrap();
    let message = lab.assert_error(output, "VECTIS_API_URL", "process");
    assert!(message.contains("could not read Vectis response"));
}

#[test]
fn log_paths_fail_safely_without_escaping_and_unused_values_are_deferred() {
    let lab = Lab::new();
    for name in ["VECTIS_LOG_FILE", "VECTIS_AUDIT_LOG_FILE"] {
        for value in [
            "../secret-canary",
            "a/b",
            "a\\b",
            "/secret-canary",
            ".",
            "..",
            "a\n",
        ] {
            let output = lab
                .command()
                .env(name, value)
                .args(["version", "--output", "json"])
                .output()
                .unwrap();
            lab.assert_error(output, name, "process");
        }
    }
    let output = lab
        .command()
        .env("VECTIS_LOG_TARGET", "file")
        .env("VECTIS_LOG_DIR", lab.0.join("logs"))
        .env("VECTIS_LOG_FILE", "secret-canary".repeat(100))
        .arg("version")
        .output()
        .unwrap();
    lab.assert_error(output, "VECTIS_LOG_FILE", "process");
    let output = lab
        .command()
        .env("VECTIS_LOG_TARGET", "file")
        .env("VECTIS_LOG_DIR", lab.0.join("fixture"))
        .arg("version")
        .output()
        .unwrap();
    lab.assert_error(output, "VECTIS_LOG_DIR", "process");
    fs::write(
        lab.0.join(".env"),
        format!(
            "# synthetic\nVECTIS_LOG_FILE='{}'\n",
            "secret-canary".repeat(100)
        ),
    )
    .unwrap();
    let output = lab
        .command()
        .env("VECTIS_LOG_TARGET", "file")
        .env("VECTIS_LOG_DIR", lab.0.join("logs"))
        .arg("version")
        .output()
        .unwrap();
    lab.assert_error(output, "VECTIS_LOG_FILE", "env_file line 2");
    fs::remove_file(lab.0.join(".env")).unwrap();
    for name in [
        "VECTIS_POSTGRES_DSN",
        "VECTIS_TLS_CERT_PATH",
        "VECTIS_API_URL",
        "VECTIS_CONFIG_PATH",
    ] {
        assert!(
            lab.command()
                .env(name, "secret-canary")
                .arg("version")
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    assert!(!lab.0.join("secret-canary").exists());
}

#[test]
fn conflicting_log_names_fail_before_any_files_are_created() {
    for from_file in [false, true] {
        for audit in [
            "secret-canary.log",
            "secret-canary.log.2026-11-27",
            "secret-canary.log.backup",
        ] {
            let lab = Lab::new();
            let logs = lab.0.join("uncreated-logs");
            if from_file {
                fs::write(lab.0.join(".env"), format!("# synthetic\nVECTIS_LOG_FILE=secret-canary.log\nVECTIS_AUDIT_LOG_FILE={audit}")).unwrap();
            }
            let mut command = lab.command();
            command
                .env("VECTIS_LOG_TARGET", "file")
                .env("VECTIS_LOG_DIR", &logs);
            if !from_file {
                command
                    .env("VECTIS_LOG_FILE", "secret-canary.log")
                    .env("VECTIS_AUDIT_LOG_FILE", audit);
            }
            let output = command
                .args(["version", "--output", "json"])
                .output()
                .unwrap();
            lab.assert_error(
                output,
                "VECTIS_AUDIT_LOG_FILE",
                if from_file {
                    "env_file line 3"
                } else {
                    "process"
                },
            );
            assert!(!logs.exists());
            assert!(
                lab.command()
                    .env("VECTIS_LOG_TARGET", "stdout")
                    .env("VECTIS_LOG_FILE", "secret-canary.log")
                    .env("VECTIS_AUDIT_LOG_FILE", audit)
                    .arg("version")
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
            assert!(!logs.exists());
        }
    }
}
