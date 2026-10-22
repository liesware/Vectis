use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use vectis::core::config::{ENV_FILE_MAX_SIZE_BYTES, load_env_file};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "vectis-env-tests-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn env_reader_enforces_file_boundaries_and_utf8() {
    let directory = TestDirectory::new();
    let path = directory.0.join(".env");
    let path_text = path.to_str().unwrap();
    assert!(load_env_file(path_text).unwrap().is_empty());

    let content = format!(
        "VECTIS_VALID=yes\n#{}",
        "x".repeat(ENV_FILE_MAX_SIZE_BYTES as usize - 18)
    );
    assert_eq!(content.len() as u64, ENV_FILE_MAX_SIZE_BYTES);
    fs::write(&path, &content).unwrap();
    assert_eq!(load_env_file(path_text).unwrap()["VECTIS_VALID"], "yes");
    fs::write(&path, format!("{content}x")).unwrap();
    assert!(load_env_file(path_text).is_err());

    fs::write(&path, b"VECTIS_VALID=secret\xff").unwrap();
    let error = load_env_file(path_text).unwrap_err().to_string();
    assert!(error.contains(".env"));
    assert!(!error.contains("secret"));

    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(load_env_file(path_text).is_err());
}

#[test]
fn env_reader_reports_unreadable_files() {
    let directory = TestDirectory::new();
    let path = directory.0.join(".env");
    fs::write(&path, "VECTIS_VALID=secret").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    // Privileged runners can read mode-000 files; do not assert an OS restriction there.
    if fs::read(&path).is_err() {
        let error = load_env_file(path.to_str().unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains(".env"));
        assert!(!error.contains("secret"));
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn invalid_env_stops_cli_before_logging_even_with_environment_override() {
    let invalid_files = [
        "VECTIS_APIKEY=secret-canary\ninvalid-secret-canary\n"
            .as_bytes()
            .to_vec(),
        b"VECTIS_MODE='secret-canary\n".to_vec(),
        b"VECTIS_MODE=secret-canary\nVECTIS_MODE=secret-canary\n".to_vec(),
        b"VECTIS_APIKEY=secret-canary\xff".to_vec(),
        vec![b'x'; ENV_FILE_MAX_SIZE_BYTES as usize + 1],
    ];
    for content in invalid_files {
        for (root_command, json) in [
            ("version", false),
            ("version", true),
            ("serve", false),
            ("serve", true),
        ] {
            let directory = TestDirectory::new();
            fs::write(directory.0.join(".env"), &content).unwrap();
            let log_directory = directory.0.join("should-not-exist");
            let mut command = Command::new(env!("CARGO_BIN_EXE_vectis"));
            command.current_dir(&directory.0).arg(root_command);
            if json {
                command.args(["--output", "json"]);
            }
            let inherited: Vec<_> = std::env::vars_os()
                .map(|(key, _)| key)
                .filter(|key| key.to_string_lossy().starts_with("VECTIS_"))
                .collect();
            for key in inherited {
                command.env_remove(key);
            }
            let output = command
                .env("VECTIS_MODE", "dev")
                .env("VECTIS_APIKEY", "a".repeat(64))
                .env("VECTIS_LOG_DIR", &log_directory)
                .env("VECTIS_LOG_TARGET", "file")
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            assert!(!log_directory.exists());
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(!stderr.contains("secret-canary"));
            assert!(!stderr.contains("using defaults"));
            if json {
                let value: serde_json::Value = serde_json::from_str(&stderr).unwrap();
                assert!(value["error"].as_str().unwrap().contains(".env"));
            } else {
                assert!(stderr.starts_with("Error: "));
                assert!(stderr.contains(".env"));
            }
        }
    }
}

#[test]
fn valid_or_missing_env_allows_logging_and_cli_startup() {
    for content in [None, Some(""), Some("VECTIS_LOG_LEVEL='warning'\r\n")] {
        let directory = TestDirectory::new();
        if let Some(content) = content {
            fs::write(directory.0.join(".env"), content).unwrap();
        }
        let output = Command::new(env!("CARGO_BIN_EXE_vectis"))
            .current_dir(&directory.0)
            .args(["version", "--output", "json"])
            .env("VECTIS_LOG_DIR", directory.0.join("logs"))
            .env("VECTIS_LOG_TARGET", "file")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(directory.0.join("logs").is_dir());
    }
}

fn isolated_command(directory: &TestDirectory) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vectis"));
    command.current_dir(&directory.0);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("VECTIS_") {
            command.env_remove(name);
        }
    }
    command
        .env("VECTIS_LOG_TARGET", "file")
        .env("VECTIS_LOG_DIR", directory.0.join("logs"));
    command
}

#[test]
fn strict_file_policy_and_logging_fail_before_creating_logs() {
    for content in [
        "VECTIS_UNRECOGNIZED=secret-canary",
        "VECTIS_UNSEAL_KEY=secret-canary",
        "VECTIS_LOG_LEVEL=secret-canary",
        "VECTIS_LOG_TARGET=secret-canary",
    ] {
        for json in [false, true] {
            let directory = TestDirectory::new();
            fs::write(directory.0.join(".env"), content).unwrap();
            let mut command = isolated_command(&directory);
            command.env_remove("VECTIS_LOG_TARGET");
            command.arg("version");
            if json {
                command.args(["--output", "json"]);
            }
            let output = command
                .env("VECTIS_UNSEAL_KEY", "a".repeat(64))
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            assert!(!directory.0.join("logs").exists());
            let error = String::from_utf8(output.stderr).unwrap();
            assert!(!error.contains("secret-canary"));
            assert!(error.contains("env_file line 1"));
            if json {
                serde_json::from_str::<serde_json::Value>(&error).unwrap();
            }
        }
    }
}

#[test]
fn version_does_not_consume_server_settings_and_unknown_process_variables() {
    use std::os::unix::ffi::OsStringExt;
    for invalid in [
        std::ffi::OsString::from("postgres://user:secret-canary@localhost:bad/db"),
        std::ffi::OsString::from_vec(b"secret-canary\xff".to_vec()),
        std::ffi::OsString::from("x".repeat(4097)),
    ] {
        let directory = TestDirectory::new();
        let output = isolated_command(&directory)
            .args(["version", "--output", "json"])
            .env("VECTIS_MODE", "prod")
            .env("VECTIS_POSTGRES_DSN", invalid)
            .env("VECTIS_SQLITE_PATH", "/missing")
            .env("VECTIS_TLS_CERT_PATH", "/missing")
            .env("VECTIS_BIN", "auxiliary")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    }
}

#[test]
fn local_config_editing_and_bootstrap_do_not_require_server_configuration() {
    let directory = TestDirectory::new();
    for args in [vec!["config", "init"], vec!["config", "list"], vec!["init"]] {
        let output = isolated_command(&directory)
            .args(&args)
            .env("VECTIS_MODE", "prod")
            .env("VECTIS_SQLITE_PATH", "/missing")
            .env("VECTIS_TLS_CERT_PATH", "/missing")
            .env("VECTIS_TLS_KEY_PATH", "/missing")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn cli_rejects_invalid_effective_values_without_fallback_or_secret_echo() {
    use std::os::unix::ffi::OsStringExt;
    let invalid = [
        (
            "VECTIS_TIMEOUT_SECONDS",
            std::ffi::OsString::from("18446744073709551615"),
        ),
        ("VECTIS_APIKEY", std::ffi::OsString::from("secret-canary")),
        (
            "VECTIS_APIKEY",
            std::ffi::OsString::from_vec(b"secret-canary\xff".to_vec()),
        ),
        ("VECTIS_API_URL", std::ffi::OsString::from("secret-canary")),
    ];
    for (name, value) in invalid {
        let directory = TestDirectory::new();
        fs::write(
            directory.0.join(".env"),
            "VECTIS_APIKEY=\nVECTIS_TIMEOUT_SECONDS=30\nVECTIS_API_URL=http://127.0.0.1:3000",
        )
        .unwrap();
        let output = isolated_command(&directory)
            .args(["health", "ready", "--output", "json"])
            .env(name, value)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        let error = error["error"].as_str().unwrap();
        assert!(error.contains(name));
        assert!(error.contains("process"));
        assert!(!error.contains("secret-canary"));
    }
}

#[test]
fn logging_open_errors_do_not_panic_or_reflect_configured_values() {
    let directory = TestDirectory::new();
    let output = isolated_command(&directory)
        .args(["version", "--output", "json"])
        .env(
            "VECTIS_LOG_FILE",
            format!("secret-canary-{}", "x".repeat(512)),
        )
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    let error = error["error"].as_str().unwrap();
    assert!(error.contains("VECTIS_LOG_FILE (process)"));
    assert!(!error.contains("secret-canary"));
}
