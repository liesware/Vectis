mod core;
mod error;
mod io;
mod ops;

use crate::error::DynError;
use std::env;
use tracing::{error, info};

const PROGRAM_NAME: &str = "vectis";

#[tokio::main]
async fn main() -> Result<(), DynError> {
    let _guard = core::logging::init_logging();

    let mut args = env::args();
    let _program = args.next();

    match args.next().as_deref() {
        Some("serve") => {
            info!("validating encrypted init file before starting http service");
            let init_state = io::cli::init::load_init_state()?;
            println!("Key status: Validated");
            info!("starting http service");

            if let Err(err) = io::http::run(init_state).await {
                error!(error = %err, "application failed");
                return Err(err);
            }

            info!("application finished successfully");
        }
        Some("init") => match args.next().as_deref() {
            Some("help" | "-h" | "--help") => print_init_help(),
            Some(command) => {
                eprintln!("unknown init command: {command}\n");
                print_init_help();
            }
            None => {
                info!("initializing local key material");
                let path = io::cli::init::run_init()?;

                println!("created {path}");
                info!(path, "init completed successfully");
            }
        },
        Some(
            command @ ("health" | "test" | "keys" | "lifecycle" | "routes" | "pub" | "sign"
            | "message"),
        ) => {
            io::cli::http::run(command, args.collect()).await?;
        }
        Some("help") => match args.next().as_deref() {
            Some(command) => print_command_help(command),
            None => print_help(),
        },
        Some("-h" | "--help") | None => print_help(),
        Some(command) => {
            eprintln!("unknown command: {command}\n");
            print_help();
        }
    }

    Ok(())
}

fn print_help() {
    println!("Usage:");
    println!("  {PROGRAM_NAME} <command> [options]");
    println!("  {PROGRAM_NAME} help [command]");
    println!();
    println!("Commands:");
    println!("  serve                 Start the HTTP service");
    println!("  init                  Generate local key material in init.json");
    println!("  health                Call the health probe endpoints");
    println!("  test                  Call protected test endpoints through HTTP");
    println!("  keys                  Create, list, or reload operational keys through HTTP");
    println!("  lifecycle             Update operational key lifecycle metadata");
    println!("  routes                List, reload, or sign final app routes");
    println!("  pub                   Fetch public keys through HTTP");
    println!("  sign                  Create or verify timestamp signatures through HTTP");
    println!("  message               Send, receive, encrypt, or decrypt messages through HTTP");
    println!();
    println!("Examples:");
    println!("  {PROGRAM_NAME} init");
    println!("  {PROGRAM_NAME} serve");
    println!("  {PROGRAM_NAME} health ready");
    println!("  {PROGRAM_NAME} keys create --tag payments --profile hybrid-high-assurance-v1");
    println!("  {PROGRAM_NAME} lifecycle <kid> --status disabled --reason maintenance");
    println!("  {PROGRAM_NAME} routes list");
    println!("  {PROGRAM_NAME} sign <kid> --file sign-request.json");
    println!();
    println!("Help:");
    println!("  {PROGRAM_NAME} help init");
    println!("  {PROGRAM_NAME} help health");
    println!("  {PROGRAM_NAME} help test");
    println!("  {PROGRAM_NAME} help keys");
    println!("  {PROGRAM_NAME} help lifecycle");
    println!("  {PROGRAM_NAME} help routes");
    println!("  {PROGRAM_NAME} help pub");
    println!("  {PROGRAM_NAME} help sign");
    println!("  {PROGRAM_NAME} help message");
    println!();
    println!("Environment:");
    println!("  VECTIS_API_URL        API base URL, default http://127.0.0.1:3000");
    println!("  VECTIS_APIKEY         Required for protected API commands");
    println!("  VECTIS_TIMEOUT_SECONDS Request timeout, default 30");
}

fn print_command_help(command: &str) {
    match command {
        "serve" => print_serve_help(),
        "init" => print_init_help(),
        "health" | "test" | "keys" | "lifecycle" | "routes" | "pub" | "sign" | "message" => {
            io::cli::http::print_help(command)
        }
        "-h" | "--help" | "help" => print_help(),
        command => {
            eprintln!("unknown help command: {command}\n");
            print_help();
        }
    }
}

fn print_serve_help() {
    println!("Usage:");
    println!("  {PROGRAM_NAME} serve");
    println!();
    println!("Starts the Vectis HTTP service.");
    println!();
    println!("Before the server starts, Vectis decrypts and validates init.json.");
    println!("Provide VECTIS_UNSEAL_KEY, VECTIS_UNSEAL_KEY_FILE, or type it at the hidden prompt.");
    println!();
    println!("Required files:");
    println!("  init.json             Encrypted local init key material");
    println!("  src/db/data.db        Default SQLite database in debug builds");
    println!();
    println!("Common environment:");
    println!("  VECTIS_UNSEAL_KEY     64 hex characters, not read from .env");
    println!("  VECTIS_UNSEAL_KEY_FILE Path to unseal key file, default .unseal_key");
    println!("  VECTIS_HTTP_BIND_ADDR Listen address, default 127.0.0.1:3000");
    println!("  VECTIS_APIKEY         Required by protected endpoints");
}

fn print_init_help() {
    println!("Usage:");
    println!("  {PROGRAM_NAME} init");
    println!();
    println!("Generates local bootstrap key material and writes encrypted init.json.");
    println!();
    println!("Output:");
    println!("  init.json             Encrypted key file");
    println!("  VECTIS_UNSEAL_KEY=... Key used later by serve to decrypt init.json");
    println!("  VECTIS_APIKEY=...     API key for protected HTTP endpoints");
    println!();
    println!("Security:");
    println!("  Do not store VECTIS_UNSEAL_KEY in .env for production.");
}
