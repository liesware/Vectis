mod core;
mod error;
mod io;
mod ops;

use crate::error::DynError;
use std::env;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), DynError> {
    let _guard = core::logging::init_logging();

    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| String::from("tmp"));

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
            Some(command) => {
                eprintln!("unknown init command: {command}\n");
                print_help(&program);
            }
            None => {
                info!("initializing local key material");
                let path = io::cli::init::run_init()?;

                println!("created {path}");
                info!(path, "init completed successfully");
            }
        },
        Some("test") => match args.next() {
            Some(command) if command == "init" => {
                if let Some(extra) = args.next() {
                    eprintln!("unexpected argument for test init: {extra}\n");
                    print_help(&program);
                    return Ok(());
                }

                info!("testing local init key material");
                io::cli::test::run_init_test().await?;
                info!("init test completed successfully");
            }
            Some(id) => {
                if let Some(extra) = args.next() {
                    eprintln!("unexpected argument for test {id}: {extra}\n");
                    print_help(&program);
                    return Ok(());
                }

                info!(id, "testing stored ops key material");
                io::cli::test::run_key_test(&id).await?;
                info!(id, "stored ops key test completed successfully");
            }
            None => {
                eprintln!("missing test target\n");
                print_help(&program);
            }
        },
        Some("-h" | "--help") | None => print_help(&program),
        Some(command) => {
            eprintln!("unknown command: {command}\n");
            print_help(&program);
        }
    }

    Ok(())
}

fn print_help(program: &str) {
    println!("Usage:");
    println!("  {program} serve");
    println!("  {program} init");
    println!("  {program} test init");
    println!("  {program} test <id>");
    println!();
    println!("Commands:");
    println!("  serve           Start the HTTP service");
    println!("  init            Generate local key material in init.json");
    println!("  test init       Validate local key material from init.json");
    println!("  test <id>       Validate stored key material from configured storage");
}
