#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::json;
use std::sync::LazyLock;
use vectis::core::time_attestation::{
    self, EffectiveTimeAttestationConfig, NtsObservation, RoughtimeObservation,
};

// The byte-level parsing of NTS and Roughtime replies lives in vetted external
// crates (rkik_nts / roughtime); Vectis only consumes their structured results.
// What Vectis owns is `evaluate_time_attestation`: the acceptability arithmetic
// over observations a malicious or compromised time server fully controls
// (offset, round-trip, Roughtime midpoint/radius) plus the local bracket. This
// target drives that path with adversarial values and asserts two things:
//   * it never panics (all arithmetic must stay saturating / overflow-safe), and
//   * the acceptability verdict is internally consistent.
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

    // Must not panic for any adversarial observation.
    let output =
        time_attestation::evaluate_time_attestation(local_start_us, local_end_us, &CONFIG, nts, roughtime);

    // The Serialize path must also survive adversarial values.
    let view = serde_json::to_value(&output).expect("time attestation output must serialize");

    // `output_is_acceptable` must agree with the serialized verdict.
    let acceptable = time_attestation::output_is_acceptable(&output);
    assert_eq!(
        json!(acceptable),
        view["server_clock"]["acceptable"],
        "output_is_acceptable must match the serialized acceptable flag"
    );

    // A verdict of "acceptable" is defined to require that both the local and
    // NTS-corrected brackets overlap the Roughtime interval. This invariant is a
    // direct consequence of the acceptability formula, so it must always hold.
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
