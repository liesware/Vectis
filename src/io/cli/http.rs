use crate::core::{config, validation};
use crate::error::DynError;
use crate::io::cli::{config_editor, init};
use crate::ops;
use reqwest::{Method, Url};
use serde_json::{Map, Value, json};
use std::fs;
use std::path::Path;
use std::time::Duration;

const DEFAULT_API_URL: &str = "http://127.0.0.1:3000";
const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
const PROGRAM_NAME: &str = "vectis";

pub async fn run(command: &str, args: Vec<String>) -> Result<(), DynError> {
    if is_help_request(&args) {
        print_help(command);
        return Ok(());
    }

    let (output, args) = parse_output_option(args)?;

    match command {
        "health" => run_health(args, output).await,
        "test" => run_test(args, output).await,
        "keys" => run_keys(args, output).await,
        "lifecycle" => run_lifecycle(args, output).await,
        "routes" => run_routes(args, output).await,
        "remote-routes" => run_remote_routes(args, output).await,
        "permissions" => run_permissions(args, output).await,
        "config" => run_config(args, output).await,
        "pub" => run_pub(args, output).await,
        "sign" => run_sign(args, output).await,
        "message" => run_message(args, output).await,
        _ => Err(invalid_input(format!("unknown command: {command}"))),
    }
}

pub fn print_help(command: &str) {
    match command {
        "health" => print_health_help(),
        "test" => print_test_help(),
        "keys" => print_keys_help(),
        "lifecycle" => print_lifecycle_help(),
        "routes" => print_routes_help(),
        "remote-routes" => print_remote_routes_help(),
        "permissions" => print_permissions_help(),
        "config" => print_config_help(),
        "pub" => print_pub_help(),
        "sign" => print_sign_help(),
        "message" => print_message_help(),
        _ => print_http_help(),
    }
}

#[derive(Clone, Copy)]
pub(super) enum OutputFormat {
    Json,
    Yaml,
}

async fn run_health(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let target = expect_one(args, "health target")?;
    validation::validate_allowed_value("health target", &target, &["startup", "live", "ready"])?;

    let client = CliHttpClient::from_env()?;
    client
        .send(
            Method::GET,
            &format!("/healthz/{target}"),
            false,
            None,
            output,
        )
        .await
}

async fn run_test(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let target = expect_one(args, "test target")?;
    let path = if target == "init" {
        String::from("/self-test/init")
    } else {
        validate_kid("kid", &target)?;
        format!("/self-test/keys/{target}")
    };

    let client = CliHttpClient::from_env()?;
    client.send(Method::GET, &path, true, None, output).await
}

async fn run_keys(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (subcommand, rest) = split_subcommand(args, "keys command")?;
    let client = CliHttpClient::from_env()?;

    match subcommand.as_str() {
        "list" => {
            expect_no_args(&rest, "keys list")?;
            client.send(Method::GET, "/keys", false, None, output).await
        }
        "reload" => {
            expect_no_args(&rest, "keys reload")?;
            client
                .send(Method::POST, "/keys/reload", true, None, output)
                .await
        }
        "properties" => {
            let path = if rest.is_empty() {
                String::from("/keys/properties")
            } else {
                let kid = expect_one(rest, "kid")?;
                validate_kid("kid", &kid)?;
                format!("/keys/properties/{kid}")
            };
            client.send(Method::GET, &path, true, None, output).await
        }
        "create" => {
            let body = parse_keys_create_body(rest)?;
            client
                .send(Method::POST, "/keys", true, Some(body), output)
                .await
        }
        _ => Err(invalid_input(format!("unknown keys command: {subcommand}"))),
    }
}

async fn run_lifecycle(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (kid, rest) = split_subcommand(args, "kid")?;
    validate_kid("kid", &kid)?;
    let body = parse_lifecycle_body(rest)?;

    let client = CliHttpClient::from_env()?;
    client
        .send(
            Method::POST,
            &format!("/lifecycle/{kid}"),
            true,
            Some(body),
            output,
        )
        .await
}

async fn run_routes(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (subcommand, rest) = split_subcommand(args, "routes command")?;
    expect_no_args(&rest, &format!("routes {subcommand}"))?;
    let client = CliHttpClient::from_env()?;
    match subcommand.as_str() {
        "list" => {
            client
                .send(Method::GET, "/routes", true, None, output)
                .await
        }
        _ => Err(invalid_input(format!(
            "unknown routes command: {subcommand}"
        ))),
    }
}

async fn run_remote_routes(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (subcommand, rest) = split_subcommand(args, "remote-routes command")?;
    expect_no_args(&rest, &format!("remote-routes {subcommand}"))?;
    let client = CliHttpClient::from_env()?;
    match subcommand.as_str() {
        "list" => {
            client
                .send(Method::GET, "/remote-routes", true, None, output)
                .await
        }
        _ => Err(invalid_input(format!(
            "unknown remote-routes command: {subcommand}"
        ))),
    }
}

async fn run_permissions(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (subcommand, rest) = split_subcommand(args, "permissions command")?;
    expect_no_args(&rest, &format!("permissions {subcommand}"))?;
    let client = CliHttpClient::from_env()?;
    match subcommand.as_str() {
        "list" => {
            client
                .send(Method::GET, "/permissions", true, None, output)
                .await
        }
        _ => Err(invalid_input(format!(
            "unknown permissions command: {subcommand}"
        ))),
    }
}

async fn run_config(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (subcommand, rest) = split_subcommand(args, "config command")?;
    match subcommand.as_str() {
        "init" => {
            expect_no_args(&rest, "config init")?;
            config_editor::init_config(output)
        }
        "sign" => {
            expect_no_args(&rest, "config sign")?;
            run_config_sign(output)
        }
        "list" => {
            expect_no_args(&rest, "config list")?;
            run_config_list(output)
        }
        "reload" => {
            expect_no_args(&rest, "config reload")?;
            let client = CliHttpClient::from_env()?;
            client
                .send(Method::POST, "/config/reload", true, None, output)
                .await
        }
        "routes" => config_editor::run_routes(rest, output).await,
        "remote-routes" => config_editor::run_remote_routes(rest, output).await,
        "permissions" => config_editor::run_permissions(rest, output).await,
        _ => Err(invalid_input(format!(
            "unknown config command: {subcommand}"
        ))),
    }
}

fn run_config_sign(output: OutputFormat) -> Result<(), DynError> {
    let config = config::app_config()?;
    let init_state = init::load_init_state()?;
    let config_content =
        crate::core::config_file::read_config_file(&config.config_path).map_err(|err| {
            invalid_input(format!(
                "VECTIS_CONFIG_PATH could not be read from {}: {err}",
                config.config_path.display()
            ))
        })?;
    let token = ops::sign::sign_config_file(&init_state, &config.config_path, &config_content)?;
    let config_sign_path = crate::core::config_file::config_signature_path(
        &config.config_path,
        &config.config_sign_path,
    );
    let token_json = serde_json::to_string_pretty(&token)?;
    fs::write(&config_sign_path, token_json)?;

    print_response(
        &serde_json::to_string(&json!({
            "status": "updated",
            "config_path": config.config_path.display().to_string(),
            "config_sign_path": config_sign_path.display().to_string(),
        }))?,
        output,
    )
}

fn run_config_list(output: OutputFormat) -> Result<(), DynError> {
    let config = config::app_config()?;
    let config_content =
        crate::core::config_file::read_config_file(&config.config_path).map_err(|err| {
            invalid_input(format!(
                "VECTIS_CONFIG_PATH could not be read from {}: {err}",
                config.config_path.display()
            ))
        })?;
    let value: Value = serde_json::from_str(&config_content)
        .map_err(|err| invalid_input(format!("config file must be valid JSON: {err}")))?;

    print_response(&serde_json::to_string(&value)?, output)
}

async fn run_pub(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let kid = expect_one(args, "kid")?;
    validate_kid("kid", &kid)?;

    let client = CliHttpClient::from_env()?;
    client
        .send(Method::GET, &format!("/pub/{kid}"), false, None, output)
        .await
}

async fn run_sign(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (subcommand, rest) = split_subcommand(args, "sign command or kid")?;
    let client = CliHttpClient::from_env()?;

    if subcommand == "verify" {
        let body = parse_json_source(rest)?;
        return client
            .send(
                Method::POST,
                "/sign/verification",
                false,
                Some(body),
                output,
            )
            .await;
    }

    validate_kid("kid", &subcommand)?;
    let body = parse_json_source(rest)?;
    client
        .send(
            Method::POST,
            &format!("/sign/{subcommand}"),
            true,
            Some(body),
            output,
        )
        .await
}

async fn run_message(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (subcommand, rest) = split_subcommand(args, "message command")?;
    let client = CliHttpClient::from_env()?;

    match subcommand.as_str() {
        "send" => {
            let (kid, rest) = split_subcommand(rest, "sender kid")?;
            validate_kid("sender_kid", &kid)?;
            let body = parse_json_source(rest)?;
            client
                .send(
                    Method::POST,
                    &format!("/message/{kid}"),
                    true,
                    Some(body),
                    output,
                )
                .await
        }
        "receive" => {
            let body = parse_json_source(rest)?;
            client
                .send(Method::POST, "/message", false, Some(body), output)
                .await
        }
        "decrypt" => {
            let body = parse_json_source(rest)?;
            client
                .send(Method::POST, "/message/decrypt", true, Some(body), output)
                .await
        }
        "internal" => run_internal_message(rest, &client, output).await,
        _ => Err(invalid_input(format!(
            "unknown message command: {subcommand}"
        ))),
    }
}

async fn run_internal_message(
    args: Vec<String>,
    client: &CliHttpClient,
    output: OutputFormat,
) -> Result<(), DynError> {
    let (subcommand, rest) = split_subcommand(args, "message internal command")?;

    match subcommand.as_str() {
        "encrypt" => {
            let (kid, rest) = split_subcommand(rest, "kid")?;
            validate_kid("kid", &kid)?;
            let body = parse_json_source(rest)?;
            client
                .send(
                    Method::POST,
                    &format!("/message/internal/encrypt/{kid}"),
                    true,
                    Some(body),
                    output,
                )
                .await
        }
        "decrypt" => {
            let body = parse_json_source(rest)?;
            client
                .send(
                    Method::POST,
                    "/message/internal/decrypt",
                    true,
                    Some(body),
                    output,
                )
                .await
        }
        _ => Err(invalid_input(format!(
            "unknown message internal command: {subcommand}"
        ))),
    }
}

struct CliHttpClient {
    client: reqwest::Client,
    base_url: Url,
    api_key: String,
}

impl CliHttpClient {
    fn from_env() -> Result<Self, DynError> {
        let env_file = config::load_env_file(".env")?;
        let base_url = validate_api_url(&config::config_value(
            &env_file,
            "VECTIS_API_URL",
            DEFAULT_API_URL,
        ))?;
        let timeout_seconds = config::config_value(
            &env_file,
            "VECTIS_TIMEOUT_SECONDS",
            &DEFAULT_TIMEOUT_SECONDS.to_string(),
        )
        .parse::<u64>()
        .map_err(|err| {
            invalid_input(format!("VECTIS_TIMEOUT_SECONDS must be an integer: {err}"))
        })?;
        if timeout_seconds == 0 {
            return Err(invalid_input(
                "VECTIS_TIMEOUT_SECONDS must be greater than 0",
            ));
        }

        let api_key = config::config_value(&env_file, "VECTIS_APIKEY", "");
        if !api_key.is_empty() {
            validation::validate_hash_hex_field(
                "VECTIS_APIKEY",
                &api_key,
                config::INTERNAL_KEYS_HASH,
            )?;
        }
        let tls_skip_verify = config::validate_bool_field(
            "VECTIS_TLS_SKIP_VERIFY",
            &config::config_value(&env_file, "VECTIS_TLS_SKIP_VERIFY", "false"),
        )?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .danger_accept_invalid_certs(tls_skip_verify)
            .build()?;

        Ok(Self {
            client,
            base_url,
            api_key,
        })
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        auth: bool,
        body: Option<Value>,
        output: OutputFormat,
    ) -> Result<(), DynError> {
        let url = self.base_url.join(path.trim_start_matches('/'))?;
        let mut request = self.client.request(method, url);

        if auth {
            if self.api_key.is_empty() {
                return Err(invalid_input("VECTIS_APIKEY is required for this command"));
            }
            request = request.header("X-API-Key", &self.api_key);
        }

        if let Some(body) = body {
            request = request.json(&body);
        }

        let response = request.send().await?;
        let status = response.status();
        let payload = response.text().await?;

        if !status.is_success() {
            return Err(invalid_input(format!("HTTP {status}: {payload}")));
        }

        print_response(&payload, output)
    }
}

fn parse_keys_create_body(args: Vec<String>) -> Result<Value, DynError> {
    let mut tag = None;
    let mut profile = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--tag" => {
                let value = next_flag_value(&args, index, "--tag")?;
                validation::validate_text_field("tag", value)?;
                tag = Some(value.to_string());
                index += 2;
            }
            "--profile" => {
                let value = next_flag_value(&args, index, "--profile")?;
                validation::validate_allowed_value("profile", value, config::CRYPTO_PROFILES)?;
                profile = Some(value.to_string());
                index += 2;
            }
            value => {
                return Err(invalid_input(format!(
                    "unknown keys create option: {value}"
                )));
            }
        }
    }

    let mut body = Map::new();
    if let Some(tag) = tag {
        body.insert("tag".to_string(), Value::String(tag));
    }
    if let Some(profile) = profile {
        body.insert("profile".to_string(), Value::String(profile));
    }

    Ok(Value::Object(body))
}

fn parse_lifecycle_body(args: Vec<String>) -> Result<Value, DynError> {
    let mut status = None;
    let mut reason = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--status" => {
                let value = next_flag_value(&args, index, "--status")?;
                validation::validate_allowed_value(
                    "status",
                    value,
                    &["active", "disabled", "retired", "compromised", "destroyed"],
                )?;
                status = Some(value.to_string());
                index += 2;
            }
            "--reason" => {
                let value = next_flag_value(&args, index, "--reason")?;
                validation::validate_text_field("reason", value)?;
                reason = Some(value.to_string());
                index += 2;
            }
            value => {
                return Err(invalid_input(format!("unknown lifecycle option: {value}")));
            }
        }
    }

    let status = status.ok_or_else(|| invalid_input("--status is required"))?;
    let reason = reason.ok_or_else(|| invalid_input("--reason is required"))?;

    Ok(json!({
        "status": status,
        "reason": reason,
    }))
}

fn parse_json_source(args: Vec<String>) -> Result<Value, DynError> {
    if args.len() != 2 {
        return Err(invalid_input(
            "expected exactly --json <json> or --file <path>",
        ));
    }

    let value = match args[0].as_str() {
        "--json" => serde_json::from_str::<Value>(&args[1]).map_err(|err| {
            invalid_input(format!("--json must contain a valid JSON object: {err}"))
        })?,
        "--file" => {
            let path = Path::new(&args[1]);
            let metadata = fs::metadata(path).map_err(|err| {
                invalid_input(format!("--file must point to a readable file: {err}"))
            })?;
            if !metadata.is_file() {
                return Err(invalid_input("--file must point to a file"));
            }
            let content = fs::read_to_string(path).map_err(|err| {
                invalid_input(format!("--file must point to a readable UTF-8 file: {err}"))
            })?;
            serde_json::from_str::<Value>(&content).map_err(|err| {
                invalid_input(format!("--file must contain a valid JSON object: {err}"))
            })?
        }
        value => return Err(invalid_input(format!("unknown JSON input option: {value}"))),
    };

    if !value.is_object() {
        return Err(invalid_input("JSON input must be an object"));
    }

    Ok(value)
}

fn validate_api_url(value: &str) -> Result<Url, DynError> {
    validation::validate_text_field("VECTIS_API_URL", value)?;
    let mut url = Url::parse(value)
        .map_err(|err| invalid_input(format!("VECTIS_API_URL must be a valid URL: {err}")))?;

    validation::validate_allowed_value("VECTIS_API_URL scheme", url.scheme(), &["http", "https"])?;
    if url.host_str().is_none() {
        return Err(invalid_input("VECTIS_API_URL must include a host"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid_input(
            "VECTIS_API_URL must not include query or fragment",
        ));
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }

    Ok(url)
}

fn validate_kid(field: &str, value: &str) -> Result<(), DynError> {
    validation::validate_hash_hex_field(field, value, config::INTERNAL_KEYS_HASH)
}

fn parse_output_option(args: Vec<String>) -> Result<(OutputFormat, Vec<String>), DynError> {
    let mut output = OutputFormat::Yaml;
    let mut rest = Vec::with_capacity(args.len());
    let mut index = 0;

    while index < args.len() {
        if args[index] == "--output" {
            let value = next_flag_value(&args, index, "--output")?;
            output = parse_output_format(value)?;
            index += 2;
        } else {
            rest.push(args[index].clone());
            index += 1;
        }
    }

    Ok((output, rest))
}

fn parse_output_format(value: &str) -> Result<OutputFormat, DynError> {
    validation::validate_allowed_value("output", value, &["yaml", "json"])?;

    match value {
        "yaml" => Ok(OutputFormat::Yaml),
        "json" => Ok(OutputFormat::Json),
        _ => unreachable!("output was already validated"),
    }
}

fn expect_one(args: Vec<String>, field: &str) -> Result<String, DynError> {
    if args.len() != 1 {
        return Err(invalid_input(format!(
            "expected exactly one {field}; run `{PROGRAM_NAME} help` for usage"
        )));
    }

    Ok(args[0].clone())
}

fn expect_no_args(args: &[String], command: &str) -> Result<(), DynError> {
    if !args.is_empty() {
        return Err(invalid_input(format!(
            "{command} does not accept extra arguments; run `{PROGRAM_NAME} help` for usage"
        )));
    }

    Ok(())
}

fn split_subcommand(mut args: Vec<String>, field: &str) -> Result<(String, Vec<String>), DynError> {
    if args.is_empty() {
        return Err(invalid_input(format!(
            "missing {field}; run `{PROGRAM_NAME} help` for usage"
        )));
    }

    let first = args.remove(0);
    validation::validate_text_field(field, &first)?;

    Ok((first, args))
}

fn next_flag_value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, DynError> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| invalid_input(format!("{flag} requires a value")))
}

pub(super) fn print_response(payload: &str, output: OutputFormat) -> Result<(), DynError> {
    if payload.trim().is_empty() {
        return Ok(());
    }

    match serde_json::from_str::<Value>(payload) {
        Ok(value) => match output {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
            OutputFormat::Yaml => print!("{}", serde_yaml::to_string(&value)?),
        },
        Err(_) => println!("{payload}"),
    }

    Ok(())
}

pub(super) fn invalid_input(message: impl Into<String>) -> DynError {
    crate::error::invalid_input(message.into())
}

fn is_help_request(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("help" | "-h" | "--help")
    )
}

fn print_http_help() {
    println!("HTTP client commands:");
    println!("  {PROGRAM_NAME} health <startup|live|ready> [--output <yaml|json>]");
    println!("  {PROGRAM_NAME} test init");
    println!("  {PROGRAM_NAME} test <kid>");
    println!("  {PROGRAM_NAME} keys create [--tag <tag>] [--profile <profile>]");
    println!("  {PROGRAM_NAME} keys list");
    println!("  {PROGRAM_NAME} keys properties [kid]");
    println!("  {PROGRAM_NAME} keys reload");
    println!("  {PROGRAM_NAME} lifecycle <kid> --status <status> --reason <reason>");
    println!("  {PROGRAM_NAME} routes list");
    println!("  {PROGRAM_NAME} remote-routes list");
    println!("  {PROGRAM_NAME} permissions list");
    println!("  {PROGRAM_NAME} config sign");
    println!("  {PROGRAM_NAME} config list");
    println!("  {PROGRAM_NAME} config reload");
    println!("  {PROGRAM_NAME} config routes <add|get|update|delete>");
    println!("  {PROGRAM_NAME} config remote-routes <add|get|update|delete>");
    println!("  {PROGRAM_NAME} config permissions <add|get|update|delete|grant|revoke>");
    println!("  {PROGRAM_NAME} pub <kid>");
    println!("  {PROGRAM_NAME} sign <kid> (--json <json>|--file <path>)");
    println!("  {PROGRAM_NAME} sign verify (--json <json>|--file <path>)");
    println!("  {PROGRAM_NAME} message send <sender_kid> (--json <json>|--file <path>)");
    println!("  {PROGRAM_NAME} message receive (--json <json>|--file <path>)");
    println!("  {PROGRAM_NAME} message decrypt (--json <json>|--file <path>)");
    println!("  {PROGRAM_NAME} message internal encrypt <kid> (--json <json>|--file <path>)");
    println!("  {PROGRAM_NAME} message internal decrypt (--json <json>|--file <path>)");
    println!();
    println!("Output:");
    println!("  --output yaml         YAML output, default");
    println!("  --output json         Pretty JSON output");
}

fn print_health_help() {
    println!("Usage:");
    println!("  {PROGRAM_NAME} health startup");
    println!("  {PROGRAM_NAME} health live");
    println!("  {PROGRAM_NAME} health ready");
    println!();
    println!("Calls public health probe endpoints.");
    println!();
    println!("Endpoints:");
    println!("  startup               GET /healthz/startup");
    println!("  live                  GET /healthz/live");
    println!("  ready                 GET /healthz/ready");
    println!();
    println!("Environment:");
    println!("  VECTIS_API_URL        API base URL, default {DEFAULT_API_URL}");
    println!("  VECTIS_TIMEOUT_SECONDS Request timeout, default {DEFAULT_TIMEOUT_SECONDS}");
    print_output_help();
}

fn print_test_help() {
    println!("Usage:");
    println!("  {PROGRAM_NAME} test init");
    println!("  {PROGRAM_NAME} test <kid>");
    println!();
    println!("Calls protected key validation endpoints.");
    println!();
    println!("Arguments:");
    println!("  kid                   64-character hex key id");
    println!();
    println!("Endpoints:");
    println!("  init                  GET /self-test/init");
    println!("  <kid>                 GET /self-test/keys/{{kid}}");
    println!();
    println!("Required environment:");
    println!("  VECTIS_APIKEY         64-character hex API key");
    print_output_help();
}

fn print_keys_help() {
    println!("Usage:");
    println!("  {PROGRAM_NAME} keys create [--tag <tag>] [--profile <profile>]");
    println!("  {PROGRAM_NAME} keys list");
    println!("  {PROGRAM_NAME} keys properties");
    println!("  {PROGRAM_NAME} keys properties <kid>");
    println!("  {PROGRAM_NAME} keys reload");
    println!();
    println!("Creates, lists, or reloads operational keys through the HTTP API.");
    println!();
    println!("Commands:");
    println!("  create                POST /keys, requires VECTIS_APIKEY");
    println!("  list                  GET /keys, public");
    println!("  properties            GET /keys/properties, requires VECTIS_APIKEY");
    println!("  properties <kid>      GET /keys/properties/{{kid}}, requires VECTIS_APIKEY");
    println!("  reload                POST /keys/reload, requires VECTIS_APIKEY");
    println!();
    println!("Create options:");
    println!("  --tag <tag>           Optional label for the key");
    println!("  --profile <profile>   Optional crypto profile");
    println!();
    println!("Profiles:");
    println!("  hybrid-performance-v1");
    println!("  hybrid-high-assurance-v1");
    println!("  hybrid-long-term-v1");
    println!();
    println!("Examples:");
    println!("  {PROGRAM_NAME} keys create --tag payments --profile hybrid-high-assurance-v1");
    println!("  {PROGRAM_NAME} keys list");
    println!("  {PROGRAM_NAME} keys properties");
    println!("  {PROGRAM_NAME} keys properties <kid>");
    println!("  {PROGRAM_NAME} keys reload");
    print_output_help();
}

fn print_lifecycle_help() {
    println!("Usage:");
    println!("  {PROGRAM_NAME} lifecycle <kid> --status <status> --reason <reason>");
    println!();
    println!("Updates encrypted lifecycle metadata for an operational key.");
    println!();
    println!("Arguments:");
    println!("  kid                   64-character hex key id");
    println!();
    println!("Options:");
    println!("  --status <status>     active, disabled, retired, compromised, or destroyed");
    println!("  --reason <reason>     Non-empty reason for the lifecycle change");
    println!();
    println!("Endpoint:");
    println!("  POST /lifecycle/{{kid}}, requires VECTIS_APIKEY");
    println!();
    println!("Examples:");
    println!("  {PROGRAM_NAME} lifecycle <kid> --status disabled --reason maintenance");
    println!("  {PROGRAM_NAME} lifecycle <kid> --status active --reason restored");
    print_output_help();
}

fn print_routes_help() {
    println!("Usage:");
    println!("  {PROGRAM_NAME} routes list");
    println!();
    println!("Lists final app routes currently loaded in memory.");
    println!();
    println!("Commands:");
    println!("  list                  GET /routes, requires VECTIS_APIKEY");
    println!();
    println!("Behavior:");
    println!("  list                  Returns routes currently loaded in memory");
    println!();
    println!("Notes:");
    println!("  Use `{PROGRAM_NAME} config reload` to reload the unified signed config.");
    print_output_help();
}

fn print_remote_routes_help() {
    println!("Usage:");
    println!("  {PROGRAM_NAME} remote-routes list");
    println!();
    println!("Lists authorized remote Vectis routes currently loaded in memory.");
    println!();
    println!("Commands:");
    println!("  list                  GET /remote-routes, requires VECTIS_APIKEY");
    println!();
    println!("Behavior:");
    println!("  list                  Returns remote routes currently loaded in memory");
    println!();
    println!("Notes:");
    println!("  Use `{PROGRAM_NAME} config reload` to reload the unified signed config.");
    print_output_help();
}

fn print_permissions_help() {
    println!("Usage:");
    println!("  {PROGRAM_NAME} permissions list");
    println!();
    println!("Lists effective API key permissions currently loaded in memory.");
    println!();
    println!("Commands:");
    println!("  list                  GET /permissions, requires admin VECTIS_APIKEY");
    println!();
    println!("Behavior:");
    println!("  list                  Returns active permission clients without apikey_hash");
    println!();
    println!("Notes:");
    println!("  Use `{PROGRAM_NAME} config reload` to reload the unified signed config.");
    print_output_help();
}

fn print_config_help() {
    println!("Usage:");
    println!("  {PROGRAM_NAME} config init");
    println!("  {PROGRAM_NAME} config sign");
    println!("  {PROGRAM_NAME} config list");
    println!("  {PROGRAM_NAME} config reload");
    println!(
        "  {PROGRAM_NAME} config routes add --name <name> --kid <kid> --final-app-addr <host:port> --final-app-path <path>"
    );
    println!("  {PROGRAM_NAME} config routes get <name>");
    println!(
        "  {PROGRAM_NAME} config routes update <name> [--kid <kid>] [--final-app-addr <host:port>] [--final-app-path <path>]"
    );
    println!("  {PROGRAM_NAME} config routes delete <name>");
    println!(
        "  {PROGRAM_NAME} config remote-routes add --name <name> --remote-kid <kid> --remote-addr <host:port> --allowed-local-kid <kid|*> [--status active|disabled]"
    );
    println!("  {PROGRAM_NAME} config remote-routes get <name>");
    println!(
        "  {PROGRAM_NAME} config remote-routes update <name> [--remote-kid <kid>] [--remote-addr <host:port>] [--allowed-local-kid <kid|*>...] [--status active|disabled]"
    );
    println!("  {PROGRAM_NAME} config remote-routes delete <name>");
    println!(
        "  {PROGRAM_NAME} config permissions add --client <client> --apikey-hash <hex> [--status active|disabled|revoked]"
    );
    println!("  {PROGRAM_NAME} config permissions get <client>");
    println!(
        "  {PROGRAM_NAME} config permissions update <client> [--apikey-hash <hex>] [--status active|disabled|revoked]"
    );
    println!("  {PROGRAM_NAME} config permissions delete <client>");
    println!("  {PROGRAM_NAME} config permissions grant <client> --kid <kid|*> --action <action>");
    println!("  {PROGRAM_NAME} config permissions revoke <client> --kid <kid|*> --action <action>");
    println!();
    println!("Signs, prints, reloads, or edits the unified signed config file.");
    println!();
    println!("Commands:");
    println!("  init                  Creates an empty VECTIS_CONFIG_PATH skeleton (local)");
    println!("  sign                  Signs VECTIS_CONFIG_PATH with init keys (local)");
    println!("  list                  Prints VECTIS_CONFIG_PATH (local)");
    println!("  reload                POST /config/reload, requires admin VECTIS_APIKEY");
    println!("  routes                Edits local config routes by unique name");
    println!("  remote-routes         Edits local config remote_routes by unique name");
    println!("  permissions           Edits local config permissions by unique client");
    println!();
    println!("Behavior:");
    println!("  edit commands modify VECTIS_CONFIG_PATH only");
    println!("  remote-routes add fetches public keys from remote /pub/{{kid}}");
    println!("  remote-routes update re-fetches keys when remote_kid or remote_addr changes");
    println!("  quote \"*\" for wildcard KIDs so the shell does not expand it");
    println!("  permissions add/update manages clients and apikey_hash");
    println!("  permissions grant/revoke only manages kid/action grants");
    println!("  edit commands do not sign or reload automatically");
    println!();
    println!("Environment:");
    println!("  VECTIS_CONFIG_PATH      Config JSON path, default config.json");
    println!("  VECTIS_CONFIG_SIGN_PATH Signature JSON path, default config_sign.json");
    println!();
    println!("Examples:");
    println!("  {PROGRAM_NAME} config init");
    println!("  {PROGRAM_NAME} config sign");
    println!("  {PROGRAM_NAME} config reload");
    println!(
        "  {PROGRAM_NAME} config routes add --name app-a --kid <kid> --final-app-addr 127.0.0.1:3999 --final-app-path /message"
    );
    println!(
        "  {PROGRAM_NAME} config remote-routes add --name clinic-b --remote-kid <kid> --remote-addr vectis-b.example.com:443 --allowed-local-kid \"*\" --status active"
    );
    println!(
        "  {PROGRAM_NAME} config permissions add --client \"Acme App\" --apikey-hash <hex> --status active"
    );
    println!("  {PROGRAM_NAME} config permissions grant \"Acme App\" --kid \"*\" --action admin");
    println!("  {PROGRAM_NAME} config permissions grant \"Acme App\" --kid <kid> --action message");
    print_output_help();
}

fn print_pub_help() {
    println!("Usage:");
    println!("  {PROGRAM_NAME} pub <kid>");
    println!();
    println!("Fetches public key material for a local operational key.");
    println!();
    println!("Arguments:");
    println!("  kid                   64-character hex key id");
    println!();
    println!("Endpoint:");
    println!("  GET /pub/{{kid}}");
    print_output_help();
}

fn print_sign_help() {
    println!("Usage:");
    println!("  {PROGRAM_NAME} sign <kid> --json '<json>'");
    println!("  {PROGRAM_NAME} sign <kid> --file sign-request.json");
    println!("  {PROGRAM_NAME} sign verify --json '<json>'");
    println!("  {PROGRAM_NAME} sign verify --file token.json");
    println!();
    println!("Creates or verifies hybrid timestamp signatures.");
    println!();
    println!("Sign request JSON:");
    println!(r#"  {{"message_hash":{{"alg":"SHA-256","hex":"<64 hex chars>"}}}}"#);
    println!();
    println!("Endpoints:");
    println!("  sign <kid>            POST /sign/{{kid}}, requires VECTIS_APIKEY");
    println!("  sign verify           POST /sign/verification, public");
    println!();
    println!("Input options:");
    println!("  --json <json>         JSON object as a shell argument");
    println!("  --file <path>         Path to a JSON file");
    print_output_help();
}

fn print_message_help() {
    println!("Usage:");
    println!("  {PROGRAM_NAME} message send <sender_kid> --json '<json>'");
    println!("  {PROGRAM_NAME} message send <sender_kid> --file send-message.json");
    println!("  {PROGRAM_NAME} message receive --json '<json>'");
    println!("  {PROGRAM_NAME} message receive --file envelope.json");
    println!("  {PROGRAM_NAME} message decrypt --json '<json>'");
    println!("  {PROGRAM_NAME} message decrypt --file encrypted-message.json");
    println!("  {PROGRAM_NAME} message internal encrypt <kid> --json '<json>'");
    println!("  {PROGRAM_NAME} message internal encrypt <kid> --file plaintext.json");
    println!("  {PROGRAM_NAME} message internal decrypt --json '<json>'");
    println!("  {PROGRAM_NAME} message internal decrypt --file internal-message.json");
    println!();
    println!(
        "Sends protected messages, receives envelopes, and encrypts/decrypts internal messages."
    );
    println!();
    println!("Common JSON examples:");
    println!(r#"  send:              {{"recipient_kid":"<kid>","message":"hello vectis"}}"#);
    println!(r#"  internal encrypt:  {{"plaintext":"hello vectis"}}"#);
    println!();
    println!("Endpoints:");
    println!("  send                  POST /message/{{sender_kid}}, requires VECTIS_APIKEY");
    println!("  receive               POST /message, public");
    println!("  decrypt               POST /message/decrypt, requires VECTIS_APIKEY");
    println!(
        "  internal encrypt      POST /message/internal/encrypt/{{kid}}, requires VECTIS_APIKEY"
    );
    println!("  internal decrypt      POST /message/internal/decrypt, requires VECTIS_APIKEY");
    println!();
    println!("Input options:");
    println!("  --json <json>         JSON object as a shell argument");
    println!("  --file <path>         Path to a JSON file");
    print_output_help();
}

fn print_output_help() {
    println!();
    println!("Output:");
    println!("  --output yaml         YAML output, default");
    println!("  --output json         Pretty JSON output");
}
