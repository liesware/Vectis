use crate::core::{config, validation};
use crate::error::DynError;
use reqwest::{Method, Url};
use serde_json::{Map, Value};
use std::fs;
use std::io;
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

    match command {
        "health" => run_health(args).await,
        "test" => run_test(args).await,
        "keys" => run_keys(args).await,
        "pub" => run_pub(args).await,
        "sign" => run_sign(args).await,
        "message" => run_message(args).await,
        _ => Err(invalid_input(format!("unknown command: {command}"))),
    }
}

pub fn print_help(command: &str) {
    match command {
        "health" => print_health_help(),
        "test" => print_test_help(),
        "keys" => print_keys_help(),
        "pub" => print_pub_help(),
        "sign" => print_sign_help(),
        "message" => print_message_help(),
        _ => print_http_help(),
    }
}

async fn run_health(args: Vec<String>) -> Result<(), DynError> {
    let target = expect_one(args, "health target")?;
    validation::validate_allowed_value("health target", &target, &["startup", "live", "ready"])?;

    let client = CliHttpClient::from_env()?;
    client
        .send(Method::GET, &format!("/healthz/{target}"), false, None)
        .await
}

async fn run_test(args: Vec<String>) -> Result<(), DynError> {
    let target = expect_one(args, "test target")?;
    let path = if target == "init" {
        String::from("/self-test/init")
    } else {
        validate_kid("kid", &target)?;
        format!("/self-test/keys/{target}")
    };

    let client = CliHttpClient::from_env()?;
    client.send(Method::GET, &path, true, None).await
}

async fn run_keys(args: Vec<String>) -> Result<(), DynError> {
    let (subcommand, rest) = split_subcommand(args, "keys command")?;
    let client = CliHttpClient::from_env()?;

    match subcommand.as_str() {
        "list" => {
            expect_no_args(&rest, "keys list")?;
            client.send(Method::GET, "/keys", false, None).await
        }
        "reload" => {
            expect_no_args(&rest, "keys reload")?;
            client.send(Method::POST, "/keys/reload", true, None).await
        }
        "create" => {
            let body = parse_keys_create_body(rest)?;
            client.send(Method::POST, "/keys", true, Some(body)).await
        }
        _ => Err(invalid_input(format!("unknown keys command: {subcommand}"))),
    }
}

async fn run_pub(args: Vec<String>) -> Result<(), DynError> {
    let kid = expect_one(args, "kid")?;
    validate_kid("kid", &kid)?;

    let client = CliHttpClient::from_env()?;
    client
        .send(Method::GET, &format!("/pub/{kid}"), false, None)
        .await
}

async fn run_sign(args: Vec<String>) -> Result<(), DynError> {
    let (subcommand, rest) = split_subcommand(args, "sign command or kid")?;
    let client = CliHttpClient::from_env()?;

    if subcommand == "verify" {
        let body = parse_json_source(rest)?;
        return client
            .send(Method::POST, "/sign/verification", false, Some(body))
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
        )
        .await
}

async fn run_message(args: Vec<String>) -> Result<(), DynError> {
    let (subcommand, rest) = split_subcommand(args, "message command")?;
    let client = CliHttpClient::from_env()?;

    match subcommand.as_str() {
        "send" => {
            let (kid, rest) = split_subcommand(rest, "sender kid")?;
            validate_kid("sender_kid", &kid)?;
            let body = parse_json_source(rest)?;
            client
                .send(Method::POST, &format!("/message/{kid}"), true, Some(body))
                .await
        }
        "receive" => {
            let body = parse_json_source(rest)?;
            client
                .send(Method::POST, "/message", false, Some(body))
                .await
        }
        "decrypt" => {
            let body = parse_json_source(rest)?;
            client
                .send(Method::POST, "/message/decrypt", true, Some(body))
                .await
        }
        "internal" => run_internal_message(rest, &client).await,
        _ => Err(invalid_input(format!(
            "unknown message command: {subcommand}"
        ))),
    }
}

async fn run_internal_message(args: Vec<String>, client: &CliHttpClient) -> Result<(), DynError> {
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
                )
                .await
        }
        "decrypt" => {
            let body = parse_json_source(rest)?;
            client
                .send(Method::POST, "/message/internal/decrypt", true, Some(body))
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

        let api_key = config::config_value(&env_file, "APIKEY", "");
        if !api_key.is_empty() {
            validation::validate_hash_hex_field("APIKEY", &api_key, config::INTERNAL_KEYS_HASH)?;
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
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
    ) -> Result<(), DynError> {
        let url = self.base_url.join(path.trim_start_matches('/'))?;
        let mut request = self.client.request(method, url);

        if auth {
            if self.api_key.is_empty() {
                return Err(invalid_input("APIKEY is required for this command"));
            }
            request = request.header("Authorization", &self.api_key);
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

        print_response(&payload)
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

fn print_response(payload: &str) -> Result<(), DynError> {
    if payload.trim().is_empty() {
        return Ok(());
    }

    match serde_json::from_str::<Value>(payload) {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
        Err(_) => println!("{payload}"),
    }

    Ok(())
}

fn invalid_input(message: impl Into<String>) -> DynError {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

fn is_help_request(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("help" | "-h" | "--help")
    )
}

fn print_http_help() {
    println!("HTTP client commands:");
    println!("  {PROGRAM_NAME} health <startup|live|ready>");
    println!("  {PROGRAM_NAME} test init");
    println!("  {PROGRAM_NAME} test <kid>");
    println!("  {PROGRAM_NAME} keys create [--tag <tag>] [--profile <profile>]");
    println!("  {PROGRAM_NAME} keys list");
    println!("  {PROGRAM_NAME} keys reload");
    println!("  {PROGRAM_NAME} pub <kid>");
    println!("  {PROGRAM_NAME} sign <kid> (--json <json>|--file <path>)");
    println!("  {PROGRAM_NAME} sign verify (--json <json>|--file <path>)");
    println!("  {PROGRAM_NAME} message send <sender_kid> (--json <json>|--file <path>)");
    println!("  {PROGRAM_NAME} message receive (--json <json>|--file <path>)");
    println!("  {PROGRAM_NAME} message decrypt (--json <json>|--file <path>)");
    println!("  {PROGRAM_NAME} message internal encrypt <kid> (--json <json>|--file <path>)");
    println!("  {PROGRAM_NAME} message internal decrypt (--json <json>|--file <path>)");
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
    println!("  APIKEY                64-character hex API key");
}

fn print_keys_help() {
    println!("Usage:");
    println!("  {PROGRAM_NAME} keys create [--tag <tag>] [--profile <profile>]");
    println!("  {PROGRAM_NAME} keys list");
    println!("  {PROGRAM_NAME} keys reload");
    println!();
    println!("Creates, lists, or reloads operational keys through the HTTP API.");
    println!();
    println!("Commands:");
    println!("  create                POST /keys, requires APIKEY");
    println!("  list                  GET /keys, public");
    println!("  reload                POST /keys/reload, requires APIKEY");
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
    println!("  {PROGRAM_NAME} keys reload");
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
    println!("  sign <kid>            POST /sign/{{kid}}, requires APIKEY");
    println!("  sign verify           POST /sign/verification, public");
    println!();
    println!("Input options:");
    println!("  --json <json>         JSON object as a shell argument");
    println!("  --file <path>         Path to a JSON file");
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
    println!(
        r#"  send:              {{"recipient_host":"127.0.0.1:3000","recipient_kid":"<kid>","message":"hello vectis"}}"#
    );
    println!(r#"  internal encrypt:  {{"plaintext":"hello vectis"}}"#);
    println!();
    println!("Endpoints:");
    println!("  send                  POST /message/{{sender_kid}}, requires APIKEY");
    println!("  receive               POST /message, public");
    println!("  decrypt               POST /message/decrypt, requires APIKEY");
    println!("  internal encrypt      POST /message/internal/encrypt/{{kid}}, requires APIKEY");
    println!("  internal decrypt      POST /message/internal/decrypt, requires APIKEY");
    println!();
    println!("Input options:");
    println!("  --json <json>         JSON object as a shell argument");
    println!("  --file <path>         Path to a JSON file");
}
