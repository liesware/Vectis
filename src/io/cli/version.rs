// Copyright 2026 Eduardo Lopez
// SPDX-License-Identifier: Apache-2.0

use crate::core::{config, project, protocol, validation};
use crate::error::DynError;
use crate::io::cli::{
    help_catalog,
    http::{OutputFormat, invalid_input, print_serializable_response},
};
use serde::Serialize;

const PROGRAM_NAME: &str = "vectis";

#[derive(Serialize)]
struct VersionOutput {
    name: &'static str,
    build_status: &'static str,
    version: &'static str,
    protocol_version: &'static str,
    license: &'static str,
    copyright: &'static str,
    project: &'static str,
    profiles: &'static [&'static str],
    capabilities: &'static [&'static str],
}

pub fn run(args: Vec<String>) -> Result<(), DynError> {
    let (output, rest) = parse_output_option(args)?;
    if has_help_token(&rest) {
        print!("{}", help_catalog::render_help_path(&["version"]));
        return Ok(());
    }
    expect_no_args(&rest)?;

    print_serializable_response(&version_payload(), output)
}

fn version_payload() -> VersionOutput {
    VersionOutput {
        name: project::NAME,
        build_status: project::BUILD_STATUS,
        version: project::VERSION,
        protocol_version: protocol::PROTOCOL_VERSION_V1,
        license: project::LICENSE,
        copyright: project::COPYRIGHT,
        project: project::REPOSITORY,
        profiles: config::CRYPTO_PROFILES,
        capabilities: project::CAPABILITIES,
    }
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
        assert_eq!(payload.name, project::NAME);
        assert_eq!(payload.build_status, project::BUILD_STATUS);
        assert_eq!(payload.version, project::VERSION);
        assert_eq!(payload.protocol_version, protocol::PROTOCOL_VERSION_V1);
        assert_eq!(payload.license, project::LICENSE);
        assert_eq!(payload.copyright, project::COPYRIGHT);
        assert_eq!(payload.project, project::REPOSITORY);
    }

    #[test]
    fn version_payload_lists_supported_profiles_and_capabilities() {
        let payload = version_payload();
        assert_eq!(payload.profiles, config::CRYPTO_PROFILES);
        assert_eq!(payload.capabilities, project::CAPABILITIES);
    }

    #[test]
    fn serialized_version_fields_follow_contract_order() {
        let payload = version_payload();
        let json = serde_json::to_string(&payload).unwrap();
        let yaml = yaml_serde::to_string(&payload).unwrap();
        let expected_fields = [
            "name",
            "build_status",
            "version",
            "protocol_version",
            "license",
            "copyright",
            "project",
            "profiles",
            "capabilities",
        ];

        for output in [&json, &yaml] {
            let mut previous = 0;
            for field in expected_fields {
                let position = output
                    .find(field)
                    .unwrap_or_else(|| panic!("missing field {field}"));
                assert!(position >= previous, "{field} is out of order");
                previous = position;
            }
        }
    }
}
