use crate::core::validation;
use crate::error::DynError;
use crate::{io::cli::init, ops};

const PROGRAM_NAME: &str = "vectis";

#[derive(Clone, Copy)]
enum OutputFormat {
    Json,
    Yaml,
}

pub fn run(args: Vec<String>) -> Result<(), DynError> {
    if is_help_request(&args) {
        print_help();
        return Ok(());
    }

    let (command, rest) = split_subcommand(args, "apikey command")?;

    match command.as_str() {
        "create" => run_create(rest),
        _ => Err(invalid_input(format!("unknown apikey command: {command}"))),
    }
}

pub fn print_help() {
    println!("Usage:");
    println!("  {PROGRAM_NAME} apikey create [--output <yaml|json>]");
    println!();
    println!("Creates a new client API key and its server-side verifier.");
    println!();
    println!(
        "This is a local command. It decrypts VECTIS_INIT_KEYS_FILE, derives the internal API auth key,"
    );
    println!("prints the new values, and does not write files or call the HTTP API.");
    println!();
    println!("Output:");
    println!("  VECTIS_APIKEY         Client secret sent as X-API-Key");
    println!("  VECTIS_APIKEY_HASH    Server-side HMAC verifier for protected endpoints");
    println!();
    println!("Options:");
    println!("  --output yaml         YAML output, default");
    println!("  --output json         Pretty JSON output");
    println!();
    println!("Required local material:");
    println!("  VECTIS_INIT_KEYS_FILE Encrypted local init key material, default init.json");
    println!("  VECTIS_UNSEAL_KEY     64 hex characters, or");
    println!("  VECTIS_UNSEAL_KEY_FILE Path to unseal key file, default .unseal_key");
}

fn run_create(args: Vec<String>) -> Result<(), DynError> {
    let (output, rest) = parse_output_option(args)?;
    expect_no_args(&rest, "apikey create")?;

    let init_state = init::load_init_state()?;
    let output_value = ops::apikey::create_api_key(&init_state)?;

    match output {
        OutputFormat::Json => {
            println!("{{");
            println!(
                "  \"VECTIS_APIKEY\": \"{}\",",
                output_value.api_key.as_str()
            );
            println!(
                "  \"VECTIS_APIKEY_HASH\": \"{}\"",
                output_value.api_key_hash.as_str()
            );
            println!("}}");
        }
        OutputFormat::Yaml => {
            println!("VECTIS_APIKEY: {}", output_value.api_key.as_str());
            println!("VECTIS_APIKEY_HASH: {}", output_value.api_key_hash.as_str());
        }
    }

    Ok(())
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

fn split_subcommand(mut args: Vec<String>, field: &str) -> Result<(String, Vec<String>), DynError> {
    if args.is_empty() {
        return Err(invalid_input(format!(
            "missing {field}; run `{PROGRAM_NAME} help apikey` for usage"
        )));
    }

    let first = args.remove(0);
    validation::validate_text_field(field, &first)?;

    Ok((first, args))
}

fn expect_no_args(args: &[String], command: &str) -> Result<(), DynError> {
    if !args.is_empty() {
        return Err(invalid_input(format!(
            "{command} does not accept extra arguments; run `{PROGRAM_NAME} help apikey` for usage"
        )));
    }

    Ok(())
}

fn next_flag_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, DynError> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| invalid_input(format!("{flag} requires a value")))
}

fn is_help_request(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("help" | "-h" | "--help")
    )
}

fn invalid_input(message: impl Into<String>) -> DynError {
    crate::error::invalid_input(message.into())
}
