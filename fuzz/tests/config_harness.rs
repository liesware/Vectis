#[path = "../fuzz_targets/config_checks.rs"]
mod config_checks;
use config_checks as checks;
#[path = "../fuzz_targets/env_harness.rs"]
mod env_harness;
#[path = "../fuzz_targets/loader_harness.rs"]
mod loader_harness;

use loader_harness::{SCENARIOS, Scenario, decode, exercise};
use vectis::core::{config, config_loader::ConfigLoader};

fn framed(selector: u8, file: &[u8], process: &[u8]) -> Vec<u8> {
    let mut result = vec![selector];
    result.extend_from_slice(&(file.len() as u32).to_le_bytes());
    result.extend_from_slice(file);
    result.extend_from_slice(process);
    result
}

#[test]
fn framing_keeps_sources_independent() {
    let input = framed(8, b"VECTIS_MODE=prod", b"dev\xff");
    let decoded = decode(&input);
    assert_eq!(decoded.scenario, Scenario::RawFile);
    assert_eq!(decoded.file, b"VECTIS_MODE=prod");
    assert_eq!(decoded.process, b"dev\xff");
    exercise(&input);
}

#[test]
fn short_headers_and_excessive_lengths_are_total() {
    for length in 0..5 {
        let bytes = vec![255; length];
        let frame = decode(&bytes);
        assert!(frame.file.is_empty());
        assert!(frame.process.is_empty());
        exercise(&bytes);
    }
    let frame = decode(&[8, 255, 255, 255, 255, b'x', b'y']);
    assert_eq!(frame.file, b"xy");
    assert!(frame.process.is_empty());
    exercise(&[8, 255, 255, 255, 255, b'x', b'y']);
}

#[test]
fn every_scenario_and_admission_variable_is_reachable() {
    for (index, expected) in SCENARIOS.iter().enumerate() {
        for process in [b"".as_slice(), b"prod", b"secret\xff", b"0", b" 1 ", b"+2"] {
            let bytes = framed(index as u8, b"VECTIS_MODE=dev", process);
            assert_eq!(exercise(&bytes), *expected);
        }
    }
    for variable in 0..3 {
        for value in [
            "",
            " ",
            "0",
            "1",
            "+1",
            "128",
            "30000",
            "30001",
            "-1",
            "18446744073709551615",
            "999999999999999999999",
            "\t5\n",
        ] {
            assert_eq!(
                exercise(&framed(
                    (6 + variable * SCENARIOS.len()) as u8,
                    b"",
                    value.as_bytes()
                )),
                Scenario::Admission
            );
        }
    }
}

#[test]
fn invalid_file_utf8_does_not_skip_process_oracles() {
    for (index, scenario) in SCENARIOS.iter().enumerate() {
        let bytes = framed(index as u8, b"\xff", b"\xff\x00");
        assert_eq!(exercise(&bytes), *scenario);
    }
}

#[test]
fn parser_and_loader_cover_exact_and_oversized_files() {
    for length in [65536, 65537] {
        let mut file = vec![b'x'; length];
        file[0] = b'#';
        env_harness::exercise(&file);
        assert_eq!(
            config::validate_env_file_content(std::str::from_utf8(&file).unwrap()).is_ok(),
            length == 65536
        );
        exercise(&framed(8, &file, b""));
    }
}

#[test]
fn process_values_cover_size_and_native_unicode_boundaries() {
    for value in [vec![b'x'; 4096], vec![b'x'; 4097], vec![255; 4097]] {
        for selector in [0, 2, 4, 6, 7, 8] {
            exercise(&framed(selector, b"", &value));
        }
    }
}

#[test]
fn grammar_does_not_apply_loader_policy() {
    for file in ["VECTIS_UNKNOWN=value", "VECTIS_UNSEAL_KEY=value"] {
        assert!(config::validate_env_file_content(file).is_ok());
        assert!(ConfigLoader::from_sources(file, |_| None).is_err());
        env_harness::exercise(file.as_bytes());
    }
}

#[test]
fn committed_seeds_pass_their_harnesses() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds");
    for target in ["fuzz_env_file", "fuzz_config_loader"] {
        let mut count = 0;
        for entry in std::fs::read_dir(root.join(target)).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            match target {
                "fuzz_env_file" => env_harness::exercise(&bytes),
                _ => {
                    exercise(&bytes);
                }
            }
            count += 1;
        }
        assert!(count > 0);
    }
}

#[test]
fn hygiene_checker_accepts_clean_errors() {
    checks::rejected::<(), _>(Err("safe error"));
}

#[test]
#[should_panic(expected = "exposed canary")]
fn canary_oracle_detects_leakage() {
    checks::rejected::<(), _>(Err(checks::CANARY));
}

#[test]
#[should_panic]
fn control_character_oracle_detects_leakage() {
    checks::rejected::<(), _>(Err("bad\nerror"));
}

#[test]
#[should_panic(expected = "invalid configuration was accepted")]
fn rejection_oracle_detects_unexpected_success() {
    checks::rejected::<(), &str>(Ok(()));
}
