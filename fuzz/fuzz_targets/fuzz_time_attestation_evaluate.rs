#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::json;
use std::sync::LazyLock;
use vectis::core::time_attestation::{
    self, EffectiveTimeAttestationConfig, NtsObservation, RoughtimeObservation,
};

static CONFIG: LazyLock<EffectiveTimeAttestationConfig> =
    LazyLock::new(EffectiveTimeAttestationConfig::defaults);

fn take_u64(data: &[u8], cursor: &mut usize) -> u64 {
    let mut buf = [0u8; 8];
    for slot in buf.iter_mut() {
        if *cursor < data.len() {
            *slot = data[*cursor];
            *cursor += 1;
        }
    }
    u64::from_le_bytes(buf)
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = 0;
    let local_start_us = take_u64(data, &mut cursor);
    let local_end_us = take_u64(data, &mut cursor);
    let nts = NtsObservation {
        offset_us: take_u64(data, &mut cursor) as i64,
        round_trip_us: take_u64(data, &mut cursor),
        authenticated: data.first().is_some_and(|byte| byte & 1 == 1),
    };
    let roughtime = RoughtimeObservation {
        midpoint_us: take_u64(data, &mut cursor),
        radius_us: take_u64(data, &mut cursor),
        verified: data.first().is_some_and(|byte| byte & 2 == 2),
        nonce_b64: String::new(),
        response_b64: String::new(),
    };

    let output =
        time_attestation::evaluate_time_attestation(local_start_us, local_end_us, &CONFIG, nts, roughtime);

    let view = serde_json::to_value(&output).expect("time attestation output must serialize");

    let acceptable = time_attestation::output_is_acceptable(&output);
    assert_eq!(
        json!(acceptable),
        view["server_clock"]["acceptable"],
        "output_is_acceptable must match the serialized acceptable flag"
    );

    if acceptable {
        assert_eq!(
            view["server_clock"]["local_within_roughtime_interval"],
            json!(true),
            "an acceptable verdict must have the local bracket within the Roughtime interval"
        );
        assert_eq!(
            view["server_clock"]["nts_within_roughtime_interval"],
            json!(true),
            "an acceptable verdict must have the NTS bracket within the Roughtime interval"
        );
    }
});
