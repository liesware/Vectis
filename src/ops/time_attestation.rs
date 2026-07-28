//! Time-attestation orchestration lives in `core::time_attestation` because it
//! has no request body, KID, profile, or storage state.
pub use crate::core::time_attestation::{
    EffectiveTimeAttestationConfig, TimeAttestationConfigInput, TimeAttestationOutput,
    evaluate_time_attestation, local_unix_us, output_is_acceptable, query_nts, query_roughtime,
    resolve_time_attestation,
};
