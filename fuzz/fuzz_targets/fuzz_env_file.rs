#![no_main]

use libfuzzer_sys::fuzz_target;

mod config_checks;
mod env_harness;

fuzz_target!(|data: &[u8]| env_harness::exercise(data));
