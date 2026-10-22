use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use vectis::core::{
    config::{self, CryptoAdmissionConfig},
    config_loader::{ConfigLoader, SYNTHETIC_CRYPTO_CONCURRENCY},
    logging,
};

use crate::config_checks as checks;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    ProcessPrecedence,
    FilePrecedence,
    InvalidOverride,
    EmptyPolicy,
    UnusedValue,
    FilePolicy,
    Admission,
    Snapshot,
    RawFile,
}

pub const SCENARIOS: [Scenario; 9] = [
    Scenario::ProcessPrecedence,
    Scenario::FilePrecedence,
    Scenario::InvalidOverride,
    Scenario::EmptyPolicy,
    Scenario::UnusedValue,
    Scenario::FilePolicy,
    Scenario::Admission,
    Scenario::Snapshot,
    Scenario::RawFile,
];

pub struct Frame<'a> {
    pub scenario: Scenario,
    pub choice: usize,
    pub file: &'a [u8],
    pub process: &'a [u8],
}

pub fn decode(data: &[u8]) -> Frame<'_> {
    let mut header = [0; 5];
    let count = data.len().min(header.len());
    header[..count].copy_from_slice(&data[..count]);
    let length = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
    let payload = data.get(5..).unwrap_or_default();
    let (file, process) = payload.split_at(length.min(payload.len()));
    Frame {
        scenario: SCENARIOS[header[0] as usize % SCENARIOS.len()],
        choice: header[0] as usize / SCENARIOS.len(),
        file,
        process,
    }
}

fn sources(file: &str, name: &str, bytes: &[u8]) -> Result<ConfigLoader, vectis::error::DynError> {
    ConfigLoader::from_sources(file, |key| {
        (key == name).then(|| OsString::from_vec(bytes.to_vec()))
    })
}

fn defaults() -> CryptoAdmissionConfig {
    checks::checked(config::crypto_admission_config(
        &checks::checked(ConfigLoader::from_sources("", |_| None)).unwrap(),
    ))
    .unwrap()
}

fn process_precedence(bytes: &[u8]) {
    let loader =
        checks::checked(sources("VECTIS_APIKEY=file-value", "VECTIS_APIKEY", bytes)).unwrap();
    assert_eq!(loader.source("VECTIS_APIKEY"), "process");
    assert!(loader.is_present("VECTIS_APIKEY"));
    match std::str::from_utf8(bytes) {
        Ok(value) if value.len() <= config::ENV_VALUE_MAX_SIZE_BYTES => {
            assert_eq!(
                checks::checked(loader.value("VECTIS_APIKEY"))
                    .unwrap()
                    .as_str(),
                value
            );
        }
        _ => {
            checks::rejected(loader.value("VECTIS_APIKEY"));
        }
    }
}

fn file_precedence() {
    let loader = checks::checked(ConfigLoader::from_sources(
        "# control\nVECTIS_MODE=prod",
        |_| None,
    ))
    .unwrap();
    assert_eq!(loader.source("VECTIS_MODE"), "env_file line 2");
    assert_eq!(
        checks::checked(config::http_client_config(&loader))
            .unwrap()
            .mode,
        "prod"
    );
    assert_eq!(loader.source("VECTIS_TLS_SKIP_VERIFY"), "default");
    assert!(!loader.is_present("VECTIS_TLS_SKIP_VERIFY"));
}

fn invalid_override(bytes: &[u8]) {
    let loader = checks::checked(sources("VECTIS_MODE=dev", "VECTIS_MODE", bytes)).unwrap();
    let result = checks::checked(config::http_client_config(&loader));
    match bytes {
        b"dev" | b"prod" => assert_eq!(result.unwrap().mode.as_bytes(), bytes),
        _ => {
            assert!(checks::rejected(result).contains("VECTIS_MODE (process)"));
        }
    }
    let secret = checks::checked(sources(
        "VECTIS_MODE=dev",
        "VECTIS_MODE",
        checks::CANARY.as_bytes(),
    ))
    .unwrap();
    checks::rejected(config::http_client_config(&secret));
}

fn empty_policy() {
    let absent = checks::checked(ConfigLoader::from_sources("", |_| None)).unwrap();
    assert!(!absent.is_present("VECTIS_MAX_CONCURRENT_CRYPTO"));
    assert_eq!(absent.source("VECTIS_MAX_CONCURRENT_CRYPTO"), "default");
    let empty = checks::checked(sources(
        "VECTIS_MAX_CONCURRENT_CRYPTO=9",
        "VECTIS_MAX_CONCURRENT_CRYPTO",
        b"",
    ))
    .unwrap();
    assert_eq!(
        checks::checked(config::crypto_admission_config(&empty))
            .unwrap()
            .max_concurrent_crypto,
        SYNTHETIC_CRYPTO_CONCURRENCY
    );
    assert_eq!(empty.source("VECTIS_MAX_CONCURRENT_CRYPTO"), "process");
    for name in ["VECTIS_MAX_QUEUED_CRYPTO", "VECTIS_CRYPTO_QUEUE_TIMEOUT_MS"] {
        let empty = checks::checked(sources(&format!("{name}=1"), name, b"")).unwrap();
        assert!(checks::rejected(config::crypto_admission_config(&empty)).contains("process"));
    }
}

fn unused_value(bytes: &[u8]) {
    let loader = checks::checked(sources("", "VECTIS_POSTGRES_DSN", bytes)).unwrap();
    assert_eq!(loader.source("VECTIS_POSTGRES_DSN"), "process");
    checks::checked(logging::logging_config(&loader)).unwrap();
    checks::checked(config::http_client_config(&loader)).unwrap();
    checks::checked(config::bootstrap_config(&loader)).unwrap();
    let secret = checks::checked(sources(
        "",
        "VECTIS_POSTGRES_DSN",
        checks::CANARY.as_bytes(),
    ))
    .unwrap();
    checks::checked(logging::logging_config(&secret)).unwrap();
}

fn file_policy() {
    for name in ["VECTIS_UNKNOWN_SETTING", "VECTIS_UNSEAL_KEY"] {
        let file = format!("{name}={}", checks::CANARY);
        let message = checks::rejected(sources(&file, name, b"override"));
        assert!(message.contains(name));
        assert!(message.contains("env_file line 1"));
    }
}

fn admission(bytes: &[u8], choice: usize) {
    let expected = defaults();
    assert_eq!(expected.max_concurrent_crypto, SYNTHETIC_CRYPTO_CONCURRENCY);
    assert_eq!(
        expected.max_queued_crypto,
        config::DEFAULT_MAX_QUEUED_CRYPTO
    );
    assert_eq!(
        expected.crypto_queue_timeout.as_millis(),
        config::DEFAULT_CRYPTO_QUEUE_TIMEOUT_MS as u128
    );
    let names = [
        "VECTIS_MAX_CONCURRENT_CRYPTO",
        "VECTIS_MAX_QUEUED_CRYPTO",
        "VECTIS_CRYPTO_QUEUE_TIMEOUT_MS",
    ];
    let name = names[choice % names.len()];
    let loader = checks::checked(sources(&format!("{name}=1"), name, bytes)).unwrap();
    let result = checks::checked(config::crypto_admission_config(&loader));
    // All three reject signs; only C accepts an empty value as the default.
    let parsed = std::str::from_utf8(bytes)
        .ok()
        .filter(|v| v.len() <= config::ENV_VALUE_MAX_SIZE_BYTES)
        .map(str::trim);
    let expected_number = match parsed {
        Some("") if choice.is_multiple_of(3) => Some(SYNTHETIC_CRYPTO_CONCURRENCY as u64),
        Some(text) => text.parse::<u64>().ok().filter(|number| match choice % 3 {
            0 => {
                !text.is_empty()
                    && text.bytes().all(|b| b.is_ascii_digit())
                    && *number > 0
                    && *number <= semaphore_max() as u64
            }
            1 => {
                !text.is_empty()
                    && text.bytes().all(|b| b.is_ascii_digit())
                    && *number <= semaphore_max() as u64
            }
            _ => {
                !text.is_empty()
                    && text.bytes().all(|b| b.is_ascii_digit())
                    && (1..=config::MAX_CRYPTO_QUEUE_TIMEOUT_MS).contains(number)
            }
        }),
        None => None,
    };
    match expected_number {
        None => {
            assert!(checks::rejected(result).contains(name));
        }
        Some(number) => {
            let actual = result.unwrap();
            match choice % 3 {
                0 => assert_eq!(actual.max_concurrent_crypto as u64, number),
                1 => assert_eq!(actual.max_queued_crypto as u64, number),
                _ => assert_eq!(actual.crypto_queue_timeout.as_millis(), number as u128),
            }
        }
    }
}

fn semaphore_max() -> usize {
    CryptoAdmissionConfig::MAX_PERMITS
}

fn snapshot(bytes: &[u8]) {
    let mut source = OsString::from_vec(bytes.to_vec());
    let mut file = String::from("VECTIS_MODE=prod");
    let loader = checks::checked(ConfigLoader::from_sources(&file, |name| {
        (name == "VECTIS_APIKEY").then(|| source.clone())
    }))
    .unwrap();
    source.clear();
    source.push("changed");
    file.clear();
    file.push_str("VECTIS_MODE=dev");
    assert_eq!(
        checks::checked(loader.value("VECTIS_MODE"))
            .unwrap()
            .as_str(),
        "prod"
    );
    assert_eq!(loader.source("VECTIS_MODE"), "env_file line 1");
    match std::str::from_utf8(bytes) {
        Ok(value) if value.len() <= config::ENV_VALUE_MAX_SIZE_BYTES => {
            assert_eq!(
                checks::checked(loader.value("VECTIS_APIKEY"))
                    .unwrap()
                    .as_str(),
                value
            );
        }
        _ => {
            checks::rejected(loader.value("VECTIS_APIKEY"));
        }
    }
}

fn raw_file(bytes: &[u8], process: &[u8]) {
    match std::str::from_utf8(bytes) {
        Ok(file) => match checks::checked(sources(file, "VECTIS_APIKEY", process)) {
            Ok(loader) => {
                assert_eq!(loader.source("VECTIS_APIKEY"), "process");
                let _ = checks::checked(logging::logging_config(&loader));
                let _ = checks::checked(config::http_client_config(&loader));
                let _ = checks::checked(config::bootstrap_config(&loader));
                let _ = checks::checked(config::crypto_admission_config(&loader));
                let _ = checks::checked(loader.value("VECTIS_APIKEY"));
                assert!(bytes.len() as u64 <= config::ENV_FILE_MAX_SIZE_BYTES);
            }
            Err(error) => {
                let message = error.to_string();
                assert!(
                    message.contains(".env") || message.contains("env_file"),
                    "loader construction error must identify its file source"
                );
            }
        },
        Err(_) => {
            // The file reader owns UTF-8 rejection; still exercise independent process bytes.
            unused_value(process);
        }
    }
}

pub fn exercise(data: &[u8]) -> Scenario {
    let frame = decode(data);
    process_precedence(frame.process);
    match frame.scenario {
        Scenario::ProcessPrecedence => {}
        Scenario::FilePrecedence => file_precedence(),
        Scenario::InvalidOverride => invalid_override(frame.process),
        Scenario::EmptyPolicy => empty_policy(),
        Scenario::UnusedValue => unused_value(frame.process),
        Scenario::FilePolicy => file_policy(),
        Scenario::Admission => admission(frame.process, frame.choice),
        Scenario::Snapshot => snapshot(frame.process),
        Scenario::RawFile => raw_file(frame.file, frame.process),
    }
    frame.scenario
}
