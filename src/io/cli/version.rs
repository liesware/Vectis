use crate::core::{config, crypto, fpe, protocol, tokenization, validation};
use crate::error::DynError;
use crate::io::cli::{
    help_catalog,
    http::{OutputFormat, invalid_input, print_response},
};
use serde_json::{Value, json};

const PROGRAM_NAME: &str = "vectis";

pub const EDDSA_ALGORITHMS: &[&str] = &["Ed25519", "Ed448"];
pub const XECDH_ALGORITHMS: &[&str] = &["X25519", "X448"];
pub const ML_DSA_VARIANTS: &[&str] = &["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];
pub const ML_KEM_VARIANTS: &[&str] = &["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];
pub const FPE_VERSIONS: &[&str] = &[fpe::FPE_VERSION_FF1_2025];
pub const TOKENIZATION_VERSIONS: &[&str] = &[tokenization::TOKENIZATION_VERSION_RANDOM_V1];

pub fn run(args: Vec<String>) -> Result<(), DynError> {
    let (output, rest) = parse_output_option(args)?;
    if has_help_token(&rest) {
        print!("{}", help_catalog::render_help_path(&["version"]));
        return Ok(());
    }
    expect_no_args(&rest)?;

    let payload = version_payload();
    print_response(&serde_json::to_string(&payload)?, output)
}

pub fn version_payload() -> Value {
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_version": protocol::PROTOCOL_VERSION_V1,
        "internal_primitives": {
            "cipher": config::INTERNAL_KEYS_CIPHER,
            "hash": config::INTERNAL_KEYS_HASH,
            "hkdf": config::INTERNAL_KEYS_HKDF,
            "hmac": config::INTERNAL_KEYS_HMAC,
        },
        "crypto_profiles": config::CRYPTO_PROFILES,
        "crypto_policies": config::CRYPTO_POLICIES,
        "algorithms": {
            "hash": crypto::HASH_ALGORITHMS,
            "symmetric": crypto::SYMMETRIC_ALGORITHMS,
            "eddsa": EDDSA_ALGORITHMS,
            "xecdh": XECDH_ALGORITHMS,
            "ml_dsa": ML_DSA_VARIANTS,
            "ml_kem": ML_KEM_VARIANTS,
            "fpe": FPE_VERSIONS,
            "tokenization": TOKENIZATION_VERSIONS,
        }
    })
}

fn parse_output_option(args: Vec<String>) -> Result<(OutputFormat, Vec<String>), DynError> {
    let mut output = OutputFormat::Yaml;
    let mut rest = Vec::with_capacity(args.len());
    let mut index = 0;

    while index < args.len() {
        if args[index] == "--output" {
            let value = next_flag_value(&args, index, "--output")?;
            validation::validate_allowed_value("output", value, &["yaml", "json"])?;
            output = match value {
                "yaml" => OutputFormat::Yaml,
                "json" => OutputFormat::Json,
                _ => unreachable!("output was already validated"),
            };
            index += 2;
        } else {
            rest.push(args[index].clone());
            index += 1;
        }
    }

    Ok((output, rest))
}

fn expect_no_args(args: &[String]) -> Result<(), DynError> {
    if !args.is_empty() {
        return Err(invalid_input(format!(
            "version does not accept extra arguments; run `{PROGRAM_NAME} help version` for usage"
        )));
    }

    Ok(())
}

fn has_help_token(args: &[String]) -> bool {
    args.iter()
        .any(|arg| matches!(arg.as_str(), "help" | "-h" | "--help"))
}

fn next_flag_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, DynError> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| invalid_input(format!("{flag} requires a value")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn has_help_token_detects_version_help_tokens() {
        assert!(has_help_token(&strings(&["--help"])));
        assert!(has_help_token(&strings(&["-h"])));
        assert!(has_help_token(&strings(&["help"])));
        assert!(has_help_token(&strings(&["--output", "json", "--help"])));
    }

    #[test]
    fn has_help_token_rejects_similar_values() {
        assert!(!has_help_token(&strings(&["--helpful"])));
        assert!(!has_help_token(&strings(&["helpful"])));
    }

    #[test]
    fn version_payload_contains_crate_and_protocol_versions() {
        let payload = version_payload();
        assert_eq!(payload["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(payload["protocol_version"], protocol::PROTOCOL_VERSION_V1);
        assert_eq!(
            payload["internal_primitives"]["hkdf"],
            config::INTERNAL_KEYS_HKDF
        );
        assert_eq!(
            payload["internal_primitives"]["hmac"],
            config::INTERNAL_KEYS_HMAC
        );
    }

    #[test]
    fn version_payload_lists_supported_profiles_and_algorithms() {
        let payload = version_payload();
        assert_eq!(payload["crypto_profiles"][0], config::CRYPTO_PROFILES[0]);
        assert_eq!(payload["crypto_policies"][0], config::CRYPTO_POLICIES[0]);
        assert!(
            payload["algorithms"]["hash"]
                .as_array()
                .unwrap()
                .contains(&json!("SHA-256"))
        );
        assert!(
            payload["algorithms"]["symmetric"]
                .as_array()
                .unwrap()
                .contains(&json!("AES-256/GCM"))
        );
        assert!(
            payload["algorithms"]["eddsa"]
                .as_array()
                .unwrap()
                .contains(&json!("Ed448"))
        );
        assert!(
            payload["algorithms"]["xecdh"]
                .as_array()
                .unwrap()
                .contains(&json!("X448"))
        );
        assert!(
            payload["algorithms"]["ml_dsa"]
                .as_array()
                .unwrap()
                .contains(&json!("ML-DSA-87"))
        );
        assert!(
            payload["algorithms"]["ml_kem"]
                .as_array()
                .unwrap()
                .contains(&json!("ML-KEM-1024"))
        );
        assert_eq!(payload["algorithms"]["fpe"][0], fpe::FPE_VERSION_FF1_2025);
        assert_eq!(
            payload["algorithms"]["tokenization"][0],
            tokenization::TOKENIZATION_VERSION_RANDOM_V1
        );
    }
}
