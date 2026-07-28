use crate::core::{config, validation};
use crate::error::DynError;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const TIME_ATTESTATION_VERSION: &str = "vectis-time-attestation-v1";
pub const DEFAULT_TIME_PROVIDER: &str = "cloudflare";
pub const SUPPORTED_TIME_PROVIDERS: &[&str] = &[DEFAULT_TIME_PROVIDER];
pub const DEFAULT_NTS_SERVER: &str = "time.cloudflare.com";
pub const DEFAULT_ROUGHTIME_SERVER: &str = "roughtime.cloudflare.com:2003";
pub const DEFAULT_ROUGHTIME_PUBLIC_KEY: &str = "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=";
pub const DEFAULT_MAX_CLOCK_SKEW_MS: u64 = 1_000;
pub const DEFAULT_MAX_ROUND_TRIP_MS: u64 = 2_000;
pub const DEFAULT_MAX_ROUGHTIME_RADIUS_MS: u64 = 2_000;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimeAttestationConfigInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nts_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roughtime_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roughtime_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_clock_skew_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_round_trip_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_roughtime_radius_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EffectiveTimeAttestationConfig {
    provider: String,
    nts_server: String,
    roughtime_server: String,
    roughtime_public_key: String,
    max_clock_skew_ms: u64,
    max_round_trip_ms: u64,
    max_roughtime_radius_ms: u64,
}

impl EffectiveTimeAttestationConfig {
    pub fn defaults() -> Self {
        Self {
            provider: DEFAULT_TIME_PROVIDER.to_string(),
            nts_server: DEFAULT_NTS_SERVER.to_string(),
            roughtime_server: DEFAULT_ROUGHTIME_SERVER.to_string(),
            roughtime_public_key: DEFAULT_ROUGHTIME_PUBLIC_KEY.to_string(),
            max_clock_skew_ms: DEFAULT_MAX_CLOCK_SKEW_MS,
            max_round_trip_ms: DEFAULT_MAX_ROUND_TRIP_MS,
            max_roughtime_radius_ms: DEFAULT_MAX_ROUGHTIME_RADIUS_MS,
        }
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }
    pub fn nts_server(&self) -> &str {
        &self.nts_server
    }
    pub fn roughtime_server(&self) -> &str {
        &self.roughtime_server
    }
    pub fn roughtime_public_key(&self) -> &str {
        &self.roughtime_public_key
    }
    pub fn max_clock_skew_ms(&self) -> u64 {
        self.max_clock_skew_ms
    }
    pub fn max_round_trip_ms(&self) -> u64 {
        self.max_round_trip_ms
    }
    pub fn max_roughtime_radius_ms(&self) -> u64 {
        self.max_roughtime_radius_ms
    }
}

pub fn resolve_time_attestation(
    input: Option<TimeAttestationConfigInput>,
) -> Result<EffectiveTimeAttestationConfig, DynError> {
    let input = input.unwrap_or_default();
    let defaults = EffectiveTimeAttestationConfig::defaults();
    let effective = EffectiveTimeAttestationConfig {
        provider: input.provider.unwrap_or(defaults.provider),
        nts_server: input.nts_server.unwrap_or(defaults.nts_server),
        roughtime_server: input.roughtime_server.unwrap_or(defaults.roughtime_server),
        roughtime_public_key: input
            .roughtime_public_key
            .unwrap_or(defaults.roughtime_public_key),
        max_clock_skew_ms: input
            .max_clock_skew_ms
            .unwrap_or(defaults.max_clock_skew_ms),
        max_round_trip_ms: input
            .max_round_trip_ms
            .unwrap_or(defaults.max_round_trip_ms),
        max_roughtime_radius_ms: input
            .max_roughtime_radius_ms
            .unwrap_or(defaults.max_roughtime_radius_ms),
    };
    validate_effective_config(&effective)?;
    Ok(effective)
}

fn validate_effective_config(value: &EffectiveTimeAttestationConfig) -> Result<(), DynError> {
    validation::validate_config_name("time_attestation.provider", &value.provider)?;
    if !SUPPORTED_TIME_PROVIDERS.contains(&value.provider.as_str()) {
        return Err(crate::error::invalid_input(format!(
            "time_attestation.provider is not supported: {}",
            value.provider
        )));
    }
    validation::validate_hostname("time_attestation.nts_server", &value.nts_server)?;
    validation::validate_host_port("time_attestation.roughtime_server", &value.roughtime_server)?;
    let key = base64::engine::general_purpose::STANDARD
        .decode(&value.roughtime_public_key)
        .map_err(|_| {
            crate::error::invalid_input(
                "time_attestation.roughtime_public_key must be valid base64",
            )
        })?;
    if key.len() != 32 {
        return Err(crate::error::invalid_input(
            "time_attestation.roughtime_public_key must decode to 32 bytes",
        ));
    }
    for (field, number) in [
        (
            "time_attestation.max_clock_skew_ms",
            value.max_clock_skew_ms,
        ),
        (
            "time_attestation.max_round_trip_ms",
            value.max_round_trip_ms,
        ),
        (
            "time_attestation.max_roughtime_radius_ms",
            value.max_roughtime_radius_ms,
        ),
    ] {
        if number == 0 || number > 60_000 {
            return Err(crate::error::invalid_input(format!(
                "{field} must be between 1 and 60000"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct NtsObservation {
    pub offset_us: i64,
    pub round_trip_us: u64,
    pub authenticated: bool,
}

#[derive(Clone, Debug)]
pub struct RoughtimeObservation {
    pub midpoint_us: u64,
    pub radius_us: u64,
    pub verified: bool,
    pub nonce_b64: String,
    pub response_b64: String,
}

#[derive(Serialize)]
pub struct TimeAttestationOutput {
    version: &'static str,
    provider: String,
    sources: TimeSourcesOutput,
    server_clock: ServerClockOutput,
}

#[derive(Serialize)]
struct TimeSourcesOutput {
    system: SystemTimeOutput,
    nts: NtsOutput,
    roughtime: RoughtimeOutput,
}
#[derive(Serialize)]
struct SystemTimeOutput {
    unix_us: String,
}
#[derive(Serialize)]
struct NtsOutput {
    authenticated: bool,
    server: String,
    offset_us: String,
    round_trip_us: String,
}
#[derive(Serialize)]
struct RoughtimeOutput {
    verified: bool,
    server: String,
    midpoint_us: String,
    radius_us: String,
    earliest_us: String,
    latest_us: String,
    nonce_b64: String,
    response_b64: String,
}
#[derive(Serialize)]
struct ServerClockOutput {
    acceptable: bool,
    max_allowed_skew_ms: u64,
    local_vs_nts_skew_ms: f64,
    local_within_roughtime_interval: bool,
    nts_within_roughtime_interval: bool,
}

pub fn evaluate_time_attestation(
    local_start_us: u64,
    local_end_us: u64,
    config: &EffectiveTimeAttestationConfig,
    nts: NtsObservation,
    roughtime: RoughtimeObservation,
) -> TimeAttestationOutput {
    let local_sample =
        local_start_us.saturating_add(local_end_us.saturating_sub(local_start_us) / 2);
    let earliest_us = roughtime.midpoint_us.saturating_sub(roughtime.radius_us);
    let latest_us = roughtime.midpoint_us.saturating_add(roughtime.radius_us);
    // The server stamped its time at some instant inside the local [start, end] bracket, so a
    // correct clock is one whose bracket overlaps the Roughtime interval; a single-point sample
    // would wrongly reject a correct clock by up to the query latency.
    let local_within = local_start_us <= latest_us && earliest_us <= local_end_us;
    let nts_start = signed_add(local_start_us, nts.offset_us);
    let nts_end = signed_add(local_end_us, nts.offset_us);
    let nts_within = nts_start <= latest_us && earliest_us <= nts_end;
    let acceptable = nts.offset_us.unsigned_abs() <= config.max_clock_skew_ms.saturating_mul(1_000)
        && nts.round_trip_us <= config.max_round_trip_ms.saturating_mul(1_000)
        && roughtime.radius_us <= config.max_roughtime_radius_ms.saturating_mul(1_000)
        && local_within
        && nts_within;

    TimeAttestationOutput {
        version: TIME_ATTESTATION_VERSION,
        provider: config.provider.clone(),
        sources: TimeSourcesOutput {
            system: SystemTimeOutput {
                unix_us: local_sample.to_string(),
            },
            nts: NtsOutput {
                authenticated: nts.authenticated,
                server: config.nts_server.clone(),
                offset_us: nts.offset_us.to_string(),
                round_trip_us: nts.round_trip_us.to_string(),
            },
            roughtime: RoughtimeOutput {
                verified: roughtime.verified,
                server: config.roughtime_server.clone(),
                midpoint_us: roughtime.midpoint_us.to_string(),
                radius_us: roughtime.radius_us.to_string(),
                earliest_us: earliest_us.to_string(),
                latest_us: latest_us.to_string(),
                nonce_b64: roughtime.nonce_b64,
                response_b64: roughtime.response_b64,
            },
        },
        server_clock: ServerClockOutput {
            acceptable,
            max_allowed_skew_ms: config.max_clock_skew_ms,
            local_vs_nts_skew_ms: nts.offset_us as f64 / 1_000.0,
            local_within_roughtime_interval: local_within,
            nts_within_roughtime_interval: nts_within,
        },
    }
}

pub fn output_is_acceptable(output: &TimeAttestationOutput) -> bool {
    output.server_clock.acceptable
}

pub fn local_unix_us() -> Result<u64, DynError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| crate::error::internal("system clock is before the Unix epoch"))?;
    u64::try_from(elapsed.as_micros())
        .map_err(|_| crate::error::internal("system clock value is out of range"))
}

pub async fn query_nts(
    config: &EffectiveTimeAttestationConfig,
) -> Result<NtsObservation, DynError> {
    let client_config = rkik_nts::NtsClientConfig::new(config.nts_server())
        .with_timeout(Duration::from_secs(
            config::INTERNAL_TIME_ATTEST_TIMEOUT_SEC,
        ))
        .with_max_retries(0);
    let mut client = rkik_nts::NtsClient::new(client_config);
    client
        .connect()
        .await
        .map_err(|err| nts_source_error("key establishment", config.nts_server(), err))?;
    let snapshot = client
        .get_time()
        .await
        .map_err(|err| nts_source_error("authenticated request", config.nts_server(), err))?;
    if !snapshot.authenticated {
        return Err(crate::error::internal("NTS response was not authenticated"));
    }
    Ok(NtsObservation {
        offset_us: server_minus_local_us(snapshot.system_time, snapshot.network_time)?,
        round_trip_us: duration_to_us(snapshot.round_trip_delay)?,
        authenticated: true,
    })
}

fn server_minus_local_us(
    system_time: SystemTime,
    network_time: SystemTime,
) -> Result<i64, DynError> {
    match network_time.duration_since(system_time) {
        Ok(offset) => i64::try_from(offset.as_micros())
            .map_err(|_| crate::error::internal("NTS offset is out of range")),
        Err(error) => i64::try_from(error.duration().as_micros())
            .map(|offset| -offset)
            .map_err(|_| crate::error::internal("NTS offset is out of range")),
    }
}

fn duration_to_us(duration: Duration) -> Result<u64, DynError> {
    u64::try_from(duration.as_micros())
        .map_err(|_| crate::error::internal("NTS round trip is out of range"))
}

fn nts_source_error(stage: &str, server: &str, err: impl std::fmt::Display) -> DynError {
    crate::error::internal(format!("NTS {stage} failed for {server}: {err}"))
}

pub async fn query_roughtime(
    config: &EffectiveTimeAttestationConfig,
) -> Result<RoughtimeObservation, DynError> {
    let addresses: Vec<_> = tokio::net::lookup_host(config.roughtime_server())
        .await
        .map(|items| items.collect())
        .map_err(|_| crate::error::internal("Roughtime source unavailable"))?;
    let address = addresses
        .first()
        .copied()
        .ok_or_else(|| crate::error::internal("Roughtime source unavailable"))?;
    let bind = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|_| crate::error::internal("Roughtime source unavailable"))?;
    let nonce = roughtime::Nonce::random()
        .map_err(|_| crate::error::internal("Roughtime nonce generation failed"))?;
    let request = roughtime::build_request(&nonce);
    socket
        .send_to(&request, address)
        .await
        .map_err(|_| crate::error::internal("Roughtime source unavailable"))?;
    let mut response = vec![0u8; config::INTERNAL_TIME_ATTEST_MAX_ROUGHTIME_RESPONSE_BYTES];
    let (length, source) = socket
        .recv_from(&mut response)
        .await
        .map_err(|_| crate::error::internal("Roughtime source unavailable"))?;
    if !addresses.contains(&source) {
        return Err(crate::error::internal("Roughtime response source mismatch"));
    }
    response.truncate(length);
    let verified = roughtime::verify_response(&response, &nonce, config.roughtime_public_key())
        .map_err(|_| crate::error::internal("Roughtime verification failed"))?;
    Ok(RoughtimeObservation {
        midpoint_us: verified.midpoint_micros,
        radius_us: u64::from(verified.radius_micros),
        // Reaching here means verify_response accepted the signed Roughtime reply.
        verified: true,
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce.as_bytes()),
        response_b64: base64::engine::general_purpose::STANDARD.encode(response),
    })
}

fn signed_add(value: u64, delta: i64) -> u64 {
    if delta.is_negative() {
        value.saturating_sub(delta.unsigned_abs())
    } else {
        value.saturating_add(delta as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nts_source_errors_preserve_the_stage_server_and_cause() {
        let err = nts_source_error(
            "key establishment",
            "time.cloudflare.com",
            "connection refused",
        );
        assert_eq!(
            err.to_string(),
            "NTS key establishment failed for time.cloudflare.com: connection refused"
        );
    }

    #[test]
    fn defaults_and_partial_overrides_are_valid() {
        let config = resolve_time_attestation(Some(TimeAttestationConfigInput {
            max_clock_skew_ms: Some(50),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(config.max_clock_skew_ms(), 50);
        assert_eq!(config.nts_server(), DEFAULT_NTS_SERVER);
    }

    #[test]
    fn evaluation_distinguishes_unacceptable_clock() {
        let config = EffectiveTimeAttestationConfig::defaults();
        let output = evaluate_time_attestation(
            1_000_000,
            1_000_000,
            &config,
            NtsObservation {
                offset_us: 42,
                round_trip_us: 18_400,
                authenticated: true,
            },
            RoughtimeObservation {
                midpoint_us: 1_000_000,
                radius_us: 1_000,
                verified: true,
                nonce_b64: "a".into(),
                response_b64: "b".into(),
            },
        );
        assert!(output_is_acceptable(&output));
        let output = evaluate_time_attestation(
            1_000_000,
            1_000_000,
            &config,
            NtsObservation {
                offset_us: 2_000_000,
                round_trip_us: 18_400,
                authenticated: true,
            },
            RoughtimeObservation {
                midpoint_us: 1_000_000,
                radius_us: 1_000,
                verified: true,
                nonce_b64: "a".into(),
                response_b64: "b".into(),
            },
        );
        assert!(!output_is_acceptable(&output));
    }

    #[test]
    fn rejects_invalid_public_key_and_numeric_bounds() {
        let err = resolve_time_attestation(Some(TimeAttestationConfigInput {
            roughtime_public_key: Some(String::from("not-base64")),
            ..Default::default()
        }))
        .expect_err("invalid Roughtime public key must fail");
        assert_eq!(
            err.to_string(),
            "time_attestation.roughtime_public_key must be valid base64"
        );

        let err = resolve_time_attestation(Some(TimeAttestationConfigInput {
            max_round_trip_ms: Some(0),
            ..Default::default()
        }))
        .expect_err("zero time limit must fail");
        assert_eq!(
            err.to_string(),
            "time_attestation.max_round_trip_ms must be between 1 and 60000"
        );
    }

    #[test]
    fn provider_requires_a_config_name_and_a_supported_adapter() {
        let valid = resolve_time_attestation(Some(TimeAttestationConfigInput {
            provider: Some(String::from("cloudflare")),
            ..Default::default()
        }))
        .expect("the Cloudflare adapter must remain supported");
        assert_eq!(valid.provider(), DEFAULT_TIME_PROVIDER);

        for provider in [
            String::new(),
            String::from("bad\nprovider"),
            "p".repeat(129),
        ] {
            let err = resolve_time_attestation(Some(TimeAttestationConfigInput {
                provider: Some(provider),
                ..Default::default()
            }))
            .expect_err("invalid provider name must fail");
            assert!(err.to_string().starts_with("time_attestation.provider"));
        }

        let err = resolve_time_attestation(Some(TimeAttestationConfigInput {
            provider: Some(String::from("ntp-pool")),
            ..Default::default()
        }))
        .expect_err("a well-formed provider without an adapter must fail");
        assert_eq!(
            err.to_string(),
            "time_attestation.provider is not supported: ntp-pool"
        );
    }

    #[test]
    fn evaluation_requires_round_trip_radius_and_interval_agreement() {
        let config = EffectiveTimeAttestationConfig::defaults();
        let output = evaluate_time_attestation(
            1_000_000,
            1_000_000,
            &config,
            NtsObservation {
                offset_us: 1,
                round_trip_us: 2_000_001,
                authenticated: true,
            },
            RoughtimeObservation {
                midpoint_us: 1_000_000,
                radius_us: 1,
                verified: true,
                nonce_b64: String::from("nonce"),
                response_b64: String::from("response"),
            },
        );
        assert!(!output_is_acceptable(&output));

        let output = evaluate_time_attestation(
            1_000_000,
            1_000_000,
            &config,
            NtsObservation {
                offset_us: 1,
                round_trip_us: 1,
                authenticated: true,
            },
            RoughtimeObservation {
                midpoint_us: 2_000_000,
                radius_us: 1,
                verified: true,
                nonce_b64: String::from("nonce"),
                response_b64: String::from("response"),
            },
        );
        assert!(!output_is_acceptable(&output));
    }

    #[test]
    fn roughtime_interval_uses_local_bracket_overlap() {
        let config = EffectiveTimeAttestationConfig::defaults();
        let roughtime = || RoughtimeObservation {
            midpoint_us: 1_001_000,
            radius_us: 1_000, // interval [1_000_000, 1_002_000]
            verified: true,
            nonce_b64: String::from("nonce"),
            response_b64: String::from("response"),
        };
        let nts = || NtsObservation {
            offset_us: 0,
            round_trip_us: 1,
            authenticated: true,
        };
        // Bracket whose midpoint (999_250) is outside the interval but overlaps it.
        let overlapping =
            evaluate_time_attestation(998_000, 1_000_500, &config, nts(), roughtime());
        assert!(overlapping.server_clock.local_within_roughtime_interval);
        // Bracket entirely below the interval must not overlap.
        let disjoint = evaluate_time_attestation(990_000, 995_000, &config, nts(), roughtime());
        assert!(!disjoint.server_clock.local_within_roughtime_interval);
    }

    #[test]
    fn output_serializes_the_public_contract() {
        let value = serde_json::to_value(evaluate_time_attestation(
            1_000_000,
            1_000_000,
            &EffectiveTimeAttestationConfig::defaults(),
            NtsObservation {
                offset_us: 42,
                round_trip_us: 10,
                authenticated: true,
            },
            RoughtimeObservation {
                midpoint_us: 1_000_000,
                radius_us: 1_000,
                verified: true,
                nonce_b64: String::from("nonce"),
                response_b64: String::from("response"),
            },
        ))
        .unwrap();
        assert_eq!(value["version"], TIME_ATTESTATION_VERSION);
        assert_eq!(value["sources"]["nts"]["authenticated"], true);
        assert_eq!(value["sources"]["roughtime"]["verified"], true);
        assert!(value["sources"]["nts"].get("stratum").is_none());
    }

    #[test]
    fn nts_time_conversion_preserves_microseconds_and_server_minus_local_sign() {
        let local = UNIX_EPOCH + Duration::from_secs(1);
        let server_ahead = local + Duration::from_micros(42);
        let server_behind = local - Duration::from_micros(42);

        assert_eq!(server_minus_local_us(local, server_ahead).unwrap(), 42);
        assert_eq!(server_minus_local_us(local, server_behind).unwrap(), -42);
        assert_eq!(
            duration_to_us(Duration::from_micros(18_400)).unwrap(),
            18_400
        );
    }

    #[tokio::test]
    #[ignore = "requires network access to Cloudflare NTS"]
    async fn cloudflare_nts_smoke_test() {
        let observation = query_nts(&EffectiveTimeAttestationConfig::defaults())
            .await
            .expect("Cloudflare NTS must complete an authenticated exchange");
        assert!(observation.authenticated);
    }
}
