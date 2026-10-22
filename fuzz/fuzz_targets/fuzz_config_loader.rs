#![no_main]

use libfuzzer_sys::fuzz_target;

mod config_checks;
mod loader_harness;

fuzz_target!(|data: &[u8]| {
    loader_harness::exercise(data);
});
