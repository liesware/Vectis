use crate::core::{config, storage::StorageState, validation};
use crate::error::DynError;
use crate::io::cli::{config_editor, help_catalog, init};
use crate::ops;
use reqwest::{Method, Url};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::fs;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

const DEFAULT_API_URL: &str = "http://127.0.0.1:3000";
const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
const PROGRAM_NAME: &str = "vectis";

type CommandFuture = Pin<Box<dyn Future<Output = Result<(), DynError>>>>;
type CommandHandler = fn(Vec<String>, OutputFormat) -> CommandFuture;

struct HttpCommand {
    name: &'static str,
    handler: CommandHandler,
}

struct ConfigCommand {
    name: &'static str,
    handler: CommandHandler,
}

macro_rules! boxed_command {
    ($wrapper:ident, $handler:path) => {
        fn $wrapper(args: Vec<String>, output: OutputFormat) -> CommandFuture {
            Box::pin($handler(args, output))
        }
    };
}

const HTTP_COMMANDS: &[HttpCommand] = &[
    HttpCommand::new("health", command_health),
    HttpCommand::new("test", command_test),
    HttpCommand::new("keys", command_keys),
    HttpCommand::new("lifecycle", command_lifecycle),
    HttpCommand::new("routes", command_routes),
    HttpCommand::new("remote-routes", command_remote_routes),
    HttpCommand::new("permissions", command_permissions),
    HttpCommand::new("config", command_config),
    HttpCommand::new("pub", command_pub),
    HttpCommand::new("sign", command_sign),
    HttpCommand::new("fpe", command_fpe),
    HttpCommand::new("token", command_token),
    HttpCommand::new("mac", command_mac),
    HttpCommand::new("index", command_index),
    HttpCommand::new("mask", command_mask),
    HttpCommand::new("commit", command_commit),
    HttpCommand::new("message", command_message),
];

const CONFIG_COMMANDS: &[ConfigCommand] = &[
    ConfigCommand::new("init", config_command_init),
    ConfigCommand::new("validate", config_command_validate),
    ConfigCommand::new("sign", config_command_sign),
    ConfigCommand::new("list", config_command_list),
    ConfigCommand::new("reload", config_command_reload),
    ConfigCommand::new("routes", config_command_routes),
    ConfigCommand::new("remote-routes", config_command_remote_routes),
    ConfigCommand::new("permissions", config_command_permissions),
    ConfigCommand::new("fpe", config_command_fpe),
    ConfigCommand::new("token", config_command_token),
    ConfigCommand::new("mac", config_command_mac),
    ConfigCommand::new("masking", config_command_masking),
    ConfigCommand::new("commitment", config_command_commitment),
];

impl HttpCommand {
    const fn new(name: &'static str, handler: CommandHandler) -> Self {
        Self { name, handler }
    }
}

impl ConfigCommand {
    const fn new(name: &'static str, handler: CommandHandler) -> Self {
        Self { name, handler }
    }
}

pub async fn run(command: &str, args: Vec<String>) -> Result<(), DynError> {
    if let Some(path) = help_request_path(command, &args) {
        print_help_path(&path);
        return Ok(());
    }

    let (output, args) = parse_output_option(args)?;

    let command = find_http_command(command)
        .ok_or_else(|| invalid_input(format!("unknown command: {command}")))?;
    (command.handler)(args, output).await
}

pub fn print_help(command: &str) {
    print_help_path(&[command]);
}

pub fn print_help_path(path: &[&str]) {
    print!("{}", help_catalog::render_help_path(path));
}

pub fn root_help_command_names() -> &'static [&'static str] {
    help_catalog::EXECUTABLE_COMMANDS
}

pub fn http_help_command_names() -> &'static [&'static str] {
    help_catalog::HTTP_COMMANDS
}

pub fn has_help_path(path: &[&str]) -> bool {
    help_catalog::command_help_path(path).is_some()
}

#[derive(Clone, Copy)]
pub(super) enum OutputFormat {
    Json,
    Yaml,
}

fn find_http_command(name: &str) -> Option<&'static HttpCommand> {
    debug_assert_eq!(
        HTTP_COMMANDS.len(),
        help_catalog::HTTP_COMMANDS.len(),
        "HTTP dispatch table and help catalog command counts must match"
    );
    HTTP_COMMANDS.iter().find(|command| command.name == name)
}

fn find_config_command(name: &str) -> Option<&'static ConfigCommand> {
    debug_assert_eq!(
        CONFIG_COMMANDS.len(),
        help_catalog::CONFIG_COMMANDS.len(),
        "config dispatch table and help catalog command counts must match"
    );
    CONFIG_COMMANDS.iter().find(|command| command.name == name)
}

boxed_command!(command_health, run_health);
boxed_command!(command_test, run_test);
boxed_command!(command_keys, run_keys);
boxed_command!(command_lifecycle, run_lifecycle);
boxed_command!(command_routes, run_routes);
boxed_command!(command_remote_routes, run_remote_routes);
boxed_command!(command_permissions, run_permissions);
boxed_command!(command_config, run_config);
boxed_command!(command_pub, run_pub);
boxed_command!(command_sign, run_sign);
boxed_command!(command_fpe, run_fpe);
boxed_command!(command_token, run_token);
boxed_command!(command_mac, run_mac);
boxed_command!(command_index, run_index);
boxed_command!(command_mask, run_mask);
boxed_command!(command_commit, run_commit);
boxed_command!(command_message, run_message);

fn config_command_init(args: Vec<String>, output: OutputFormat) -> CommandFuture {
    Box::pin(async move {
        expect_no_args(&args, "config init")?;
        config_editor::init_config(output)
    })
}

fn config_command_sign(args: Vec<String>, output: OutputFormat) -> CommandFuture {
    Box::pin(async move {
        expect_no_args(&args, "config sign")?;
        run_config_sign(output).await
    })
}

fn config_command_validate(args: Vec<String>, output: OutputFormat) -> CommandFuture {
    Box::pin(async move {
        expect_no_args(&args, "config validate")?;
        run_config_validate(output).await
    })
}

fn config_command_list(args: Vec<String>, output: OutputFormat) -> CommandFuture {
    Box::pin(async move {
        expect_no_args(&args, "config list")?;
        run_config_list(output)
    })
}

fn config_command_reload(args: Vec<String>, output: OutputFormat) -> CommandFuture {
    Box::pin(async move {
        expect_no_args(&args, "config reload")?;
        let client = CliHttpClient::from_env()?;
        client
            .send(Method::POST, "/config/reload", true, None, output)
            .await
    })
}

boxed_command!(config_command_routes, config_editor::run_routes);
boxed_command!(
    config_command_remote_routes,
    config_editor::run_remote_routes
);
boxed_command!(config_command_permissions, config_editor::run_permissions);
boxed_command!(config_command_fpe, config_editor::run_config_fpe);
boxed_command!(config_command_token, config_editor::run_config_token);
boxed_command!(config_command_mac, config_editor::run_config_mac);
boxed_command!(config_command_masking, config_editor::run_config_masking);
boxed_command!(
    config_command_commitment,
    config_editor::run_config_commitment
);

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
    let command = find_config_command(&subcommand)
        .ok_or_else(|| invalid_input(format!("unknown config command: {subcommand}")))?;
    (command.handler)(rest, output).await
}

#[derive(Serialize)]
struct ConfigValidationOutput {
    status: &'static str,
    config_path: String,
    keys_loaded: usize,
    routes_loaded: usize,
    remote_routes_loaded: usize,
    clients_loaded: usize,
    fpe_profiles_loaded: usize,
    tokenization_profiles_loaded: usize,
    mac_profiles_loaded: usize,
    masking_profiles_loaded: usize,
    commitment_profiles_loaded: usize,
}

async fn validate_config_for_local_node() -> Result<
    (
        config::AppConfig,
        ops::init::ValidatedInitState,
        String,
        ConfigValidationOutput,
    ),
    DynError,
> {
    let config = config::app_config()?;
    let init_state = init::load_init_state()?;
    let config_content =
        crate::core::config_file::read_config_file(&config.config_path).map_err(|err| {
            invalid_input(format!(
                "VECTIS_CONFIG_PATH could not be read from {}: {err}",
                config.config_path.display()
            ))
        })?;
    let internal_keys = ops::internal_keys::InternalDerivedKeysState::from_init_state(&init_state)?;
    let storage = StorageState::new(&config).await?;
    let keys_db_state = ops::keys::load_keys_db_state(&storage, &internal_keys).await?;
    let config_state = crate::core::config_file::validate_config_content(
        &config_content,
        &config,
        |kid| keys_db_state.contains_id(kid),
        |request| {
            let loaded_key = keys_db_state.get(request.kid).ok_or_else(|| {
                invalid_input(format!(
                    "fpe profile references kid not loaded in memory: {}",
                    request.kid
                ))
            })?;
            crate::core::fpe::derive_fpe_key_for_profile(
                loaded_key.keys().symmetric().key_hex(),
                request,
            )
        },
        |request| {
            let loaded_key = keys_db_state.get(request.kid).ok_or_else(|| {
                invalid_input(format!(
                    "tokenization profile references kid not loaded in memory: {}",
                    request.kid
                ))
            })?;
            crate::core::tokenization::derive_tokenization_keys(
                loaded_key.keys().symmetric().key_hex(),
                loaded_key.keys().symmetric().variant(),
                request,
            )
        },
        |kid| {
            let loaded_key = keys_db_state.get(kid).ok_or_else(|| {
                invalid_input(format!(
                    "mac profile references kid not loaded in memory: {kid}"
                ))
            })?;
            Ok(loaded_key.key_material().hash_variant().to_string())
        },
        |request| {
            let loaded_key = keys_db_state.get(request.kid).ok_or_else(|| {
                invalid_input(format!(
                    "mac profile references kid not loaded in memory: {}",
                    request.kid
                ))
            })?;
            crate::core::mac::derive_mac_key_for_profile(
                loaded_key.keys().symmetric().key_hex(),
                request,
            )
        },
        |request| {
            let loaded_key = keys_db_state.get(request.kid).ok_or_else(|| {
                invalid_input(format!(
                    "commitment profile references kid not loaded in memory: {}",
                    request.kid
                ))
            })?;
            crate::core::commitments::derive_commitment_key_for_profile(
                loaded_key.keys().symmetric().key_hex(),
                request,
            )
        },
    )?;
    let output = ConfigValidationOutput {
        status: "valid",
        config_path: config.config_path.display().to_string(),
        keys_loaded: keys_db_state.len(),
        routes_loaded: config_state.routes.len(),
        remote_routes_loaded: config_state.remote_routes.len(),
        clients_loaded: config_state.permissions.len(),
        fpe_profiles_loaded: config_state.fpe_profiles.len(),
        tokenization_profiles_loaded: config_state.tokenization_profiles.len(),
        mac_profiles_loaded: config_state.mac_profiles.len(),
        masking_profiles_loaded: config_state.masking_profiles.len(),
        commitment_profiles_loaded: config_state.commitment_profiles.len(),
    };

    Ok((config, init_state, config_content, output))
}

async fn run_config_validate(output: OutputFormat) -> Result<(), DynError> {
    let (_, _, _, validation) = validate_config_for_local_node().await?;

    print_response(&serde_json::to_string(&validation)?, output)
}

async fn run_config_sign(output: OutputFormat) -> Result<(), DynError> {
    let (config, init_state, config_content, validation) = validate_config_for_local_node().await?;
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
            "keys_loaded": validation.keys_loaded,
            "routes_loaded": validation.routes_loaded,
            "remote_routes_loaded": validation.remote_routes_loaded,
            "clients_loaded": validation.clients_loaded,
            "fpe_profiles_loaded": validation.fpe_profiles_loaded,
            "tokenization_profiles_loaded": validation.tokenization_profiles_loaded,
            "mac_profiles_loaded": validation.mac_profiles_loaded,
            "masking_profiles_loaded": validation.masking_profiles_loaded,
            "commitment_profiles_loaded": validation.commitment_profiles_loaded,
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

async fn run_fpe(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (subcommand, rest) = split_subcommand(args, "fpe command")?;
    let client = CliHttpClient::from_env()?;

    match subcommand.as_str() {
        "encrypt" => {
            let (kid, rest) = split_subcommand(rest, "kid")?;
            validate_kid("kid", &kid)?;
            let body = parse_json_source(rest)?;
            client
                .send(
                    Method::POST,
                    &format!("/fpe/encrypt/{kid}"),
                    true,
                    Some(body),
                    output,
                )
                .await
        }
        "decrypt" => {
            let body = parse_json_source(rest)?;
            client
                .send(Method::POST, "/fpe/decrypt", true, Some(body), output)
                .await
        }
        _ => Err(invalid_input(format!("unknown fpe command: {subcommand}"))),
    }
}

async fn run_token(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (subcommand, rest) = split_subcommand(args, "token command")?;
    let client = CliHttpClient::from_env()?;

    match subcommand.as_str() {
        "encode" => {
            let (kid, rest) = split_subcommand(rest, "kid")?;
            validate_kid("kid", &kid)?;
            let body = parse_json_source(rest)?;
            client
                .send(
                    Method::POST,
                    &format!("/token/encode/{kid}"),
                    true,
                    Some(body),
                    output,
                )
                .await
        }
        "decode" => {
            let body = parse_json_source(rest)?;
            client
                .send(Method::POST, "/token/decode", true, Some(body), output)
                .await
        }
        _ => Err(invalid_input(format!(
            "unknown token command: {subcommand}"
        ))),
    }
}

async fn run_mac(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (subcommand, rest) = split_subcommand(args, "mac command")?;
    let client = CliHttpClient::from_env()?;

    match subcommand.as_str() {
        "create" => {
            let (kid, rest) = split_subcommand(rest, "kid")?;
            validate_kid("kid", &kid)?;
            let body = parse_json_source(rest)?;
            client
                .send(
                    Method::POST,
                    &format!("/mac/{kid}"),
                    true,
                    Some(body),
                    output,
                )
                .await
        }
        "verify" => {
            let body = parse_json_source(rest)?;
            client
                .send(Method::POST, "/mac/verify", true, Some(body), output)
                .await
        }
        _ => Err(invalid_input(format!("unknown mac command: {subcommand}"))),
    }
}

async fn run_index(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (subcommand, rest) = split_subcommand(args, "index command")?;
    let client = CliHttpClient::from_env()?;

    match subcommand.as_str() {
        "create" => {
            let (kid, rest) = split_subcommand(rest, "kid")?;
            validate_kid("kid", &kid)?;
            let body = parse_json_source(rest)?;
            client
                .send(
                    Method::POST,
                    &format!("/index/{kid}"),
                    true,
                    Some(body),
                    output,
                )
                .await
        }
        "verify" => {
            let body = parse_json_source(rest)?;
            client
                .send(Method::POST, "/index/verify", true, Some(body), output)
                .await
        }
        _ => Err(invalid_input(format!(
            "unknown index command: {subcommand}"
        ))),
    }
}

async fn run_mask(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (kid, rest) = split_subcommand(args, "kid")?;
    validate_kid("kid", &kid)?;
    let body = parse_json_source(rest)?;
    let client = CliHttpClient::from_env()?;
    client
        .send(
            Method::POST,
            &format!("/mask/{kid}"),
            true,
            Some(body),
            output,
        )
        .await
}

async fn run_commit(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (subcommand, rest) = split_subcommand(args, "commit command")?;
    let client = CliHttpClient::from_env()?;

    match subcommand.as_str() {
        "create" => {
            let (kid, rest) = split_subcommand(rest, "kid")?;
            validate_kid("kid", &kid)?;
            let body = parse_json_source(rest)?;
            client
                .send(
                    Method::POST,
                    &format!("/commit/{kid}"),
                    true,
                    Some(body),
                    output,
                )
                .await
        }
        "verify" => {
            let body = parse_json_source(rest)?;
            client
                .send(Method::POST, "/commit/verify", true, Some(body), output)
                .await
        }
        _ => Err(invalid_input(format!(
            "unknown commit command: {subcommand}"
        ))),
    }
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
            OutputFormat::Yaml => print!("{}", yaml_serde::to_string(&value)?),
        },
        Err(_) => println!("{payload}"),
    }

    Ok(())
}

pub(super) fn invalid_input(message: impl Into<String>) -> DynError {
    crate::error::invalid_input(message.into())
}

fn is_help_token(value: &str, index: usize) -> bool {
    matches!(value, "-h" | "--help") || (value == "help" && index == 0)
}

fn help_request_path<'a>(command: &'a str, args: &'a [String]) -> Option<Vec<&'a str>> {
    let mut path = Vec::with_capacity(args.len() + 1);
    path.push(command);
    append_help_path_args(&mut path, args).then_some(path)
}

fn append_help_path_args<'a>(path: &mut Vec<&'a str>, args: &'a [String]) -> bool {
    let mut index = 0;
    let mut found_help = false;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--" {
            break;
        } else if is_help_token(arg, index) {
            found_help = true;
            index += 1;
        } else if flag_consumes_value(arg) {
            index += 2;
        } else {
            path.push(arg);
            index += 1;
        }
    }
    found_help
}

fn flag_consumes_value(flag: &str) -> bool {
    matches!(
        flag,
        "--output"
            | "--tag"
            | "--profile"
            | "--status"
            | "--reason"
            | "--file"
            | "--json"
            | "--name"
            | "--kid"
            | "--final-app-addr"
            | "--final-app-path"
            | "--remote-kid"
            | "--remote-addr"
            | "--allowed-local-kid"
            | "--client"
            | "--apikey-hash"
            | "--action"
            | "--alphabet"
            | "--min-len"
            | "--max-len"
            | "--tweak-aad"
            | "--fpe-version"
            | "--token-prefix"
            | "--token-len"
            | "--max-plaintext-len"
            | "--context"
            | "--visible-first"
            | "--visible-last"
            | "--mask-char"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn dispatch_names() -> Vec<&'static str> {
        HTTP_COMMANDS.iter().map(|command| command.name).collect()
    }

    fn config_dispatch_names() -> Vec<&'static str> {
        CONFIG_COMMANDS.iter().map(|command| command.name).collect()
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn help_request_path_detects_free_help_tokens() {
        assert_eq!(
            help_request_path("keys", &strings(&["create", "--help"])).unwrap(),
            vec!["keys", "create"]
        );
        assert_eq!(
            help_request_path("keys", &strings(&["create", "-h", "--tag", "demo"])).unwrap(),
            vec!["keys", "create"]
        );
        assert_eq!(
            help_request_path("keys", &strings(&["help"])).unwrap(),
            vec!["keys"]
        );
    }

    #[test]
    fn help_request_path_ignores_help_like_values() {
        assert!(help_request_path("keys", &strings(&["--helpful"])).is_none());
        assert!(help_request_path("keys", &strings(&["create", "helpful"])).is_none());
        assert!(help_request_path("keys", &strings(&["create", "help"])).is_none());
        assert!(help_request_path("keys", &strings(&["create", "--tag", "help"])).is_none());
        assert!(help_request_path("lifecycle", &strings(&["a", "--reason", "help"])).is_none());
        assert!(
            help_request_path("config", &strings(&["permissions", "delete", "help"])).is_none()
        );
        assert!(
            help_request_path(
                "config",
                &strings(&[
                    "permissions",
                    "add",
                    "--client",
                    "help",
                    "--apikey-hash",
                    "d"
                ])
            )
            .is_none()
        );
    }

    #[test]
    fn help_request_path_stops_at_double_dash() {
        assert!(help_request_path("keys", &strings(&["create", "--", "--help"])).is_none());
    }

    #[test]
    fn help_path_removes_help_and_flag_values() {
        let args = strings(&["create", "--output", "json", "--help"]);
        assert_eq!(
            help_request_path("keys", &args).unwrap(),
            vec!["keys", "create"]
        );

        let args = strings(&["routes", "add", "--help", "--output", "yaml"]);
        assert_eq!(
            help_request_path("config", &args).unwrap(),
            vec!["config", "routes", "add"]
        );
    }

    #[test]
    fn help_path_renders_most_specific_available_help() {
        let sign_args = strings(&[
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--help",
        ]);
        let sign_path = help_request_path("sign", &sign_args).unwrap();
        let sign_help = help_catalog::render_help_path(&sign_path);
        assert!(sign_help.contains("vectis sign <kid>"));
        assert!(!sign_help.contains("vectis <command> [options]"));

        let keys_args = strings(&["create", "--help"]);
        let keys_path = help_request_path("keys", &keys_args).unwrap();
        let keys_help = help_catalog::render_help_path(&keys_path);
        assert!(keys_help.contains("vectis keys create"));
        assert!(!keys_help.contains("vectis <command> [options]"));

        let routes_args = strings(&["routes", "add", "--help"]);
        let routes_path = help_request_path("config", &routes_args).unwrap();
        let routes_help = help_catalog::render_help_path(&routes_path);
        assert!(routes_help.contains("vectis config routes add"));

        let token_args = strings(&["token", "add", "--help"]);
        let token_path = help_request_path("config", &token_args).unwrap();
        let token_help = help_catalog::render_help_path(&token_path);
        assert!(token_help.contains("vectis config token add --name <name>"));
    }

    #[test]
    fn http_dispatch_table_has_no_duplicate_names() {
        let mut seen = HashSet::new();
        for name in dispatch_names() {
            assert!(seen.insert(name), "duplicate HTTP command dispatch: {name}");
        }
    }

    #[test]
    fn http_dispatch_table_matches_help_catalog() {
        let dispatch = dispatch_names();

        for name in help_catalog::HTTP_COMMANDS {
            assert!(
                dispatch.contains(name),
                "{name} is listed in HTTP help catalog but missing from dispatch"
            );
        }

        for name in dispatch {
            assert!(
                help_catalog::HTTP_COMMANDS.contains(&name),
                "{name} is dispatched but missing from HTTP help catalog"
            );
        }
    }

    #[test]
    fn key_catalog_commands_are_dispatched() {
        for name in ["config", "fpe", "token", "index"] {
            assert!(
                find_http_command(name).is_some(),
                "{name} must remain in HTTP dispatch"
            );
            assert!(
                help_catalog::HTTP_COMMANDS.contains(&name),
                "{name} must remain in HTTP help catalog"
            );
        }
    }

    #[test]
    fn config_dispatch_table_has_no_duplicate_names() {
        let mut seen = HashSet::new();
        for name in config_dispatch_names() {
            assert!(
                seen.insert(name),
                "duplicate config command dispatch: {name}"
            );
        }
    }

    #[test]
    fn config_dispatch_table_matches_help_catalog() {
        let dispatch = config_dispatch_names();

        for name in help_catalog::CONFIG_COMMANDS {
            assert!(
                dispatch.contains(name),
                "{name} is listed in config help catalog but missing from dispatch"
            );
        }

        for name in dispatch {
            assert!(
                help_catalog::CONFIG_COMMANDS.contains(&name),
                "{name} is dispatched but missing from config help catalog"
            );
        }
    }

    #[test]
    fn key_config_catalog_commands_are_dispatched() {
        for name in ["routes", "remote-routes", "permissions", "fpe", "token"] {
            assert!(
                find_config_command(name).is_some(),
                "{name} must remain in config dispatch"
            );
            assert!(
                help_catalog::CONFIG_COMMANDS.contains(&name),
                "{name} must remain in config help catalog"
            );
        }
    }
}
