#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use vectis::core::canonical;

// serde_json stores any JSON number that does not fit in i64/u64 as an f64, and
// the f64 -> shortest-string -> f64 round-trip is not bit-stable for every value.
// canonical_json_v1 is only ever applied to Vectis' typed payloads (config,
// tokens, envelopes), whose fields are strings — no signed payload contains a
// floating-point number. So the idempotence invariant is asserted only for
// float-free JSON; float-containing arbitrary input is still canonicalized (to
// catch panics) but not required to be idempotent.
fn contains_float(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.is_f64(),
        Value::Array(items) => items.iter().any(contains_float),
        Value::Object(object) => object.values().any(contains_float),
        _ => false,
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return;
    };

    let Ok(first) = canonical::canonical_json_v1(&value) else {
        return;
    };

    if contains_float(&value) {
        return;
    }

    let reparsed: Value = serde_json::from_slice(&first).expect("canonical JSON must parse");
    let second = canonical::canonical_json_v1(&reparsed).expect("canonical JSON must re-encode");

    assert_eq!(first, second);
});
