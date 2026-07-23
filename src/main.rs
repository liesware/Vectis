use std::env;
use std::process;
use tracing::{error, info};
use vectis::error::{self, DynError};
use vectis::{core, io};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RootCommandKind {
    Serve,
    Init,
    Apikey,
    Version,
    Http,
}

struct RootCommand {
    name: &'static str,
    kind: RootCommandKind,
}

const ROOT_COMMANDS: &[RootCommand] = &[
    RootCommand::new("serve", RootCommandKind::Serve),
    RootCommand::new("init", RootCommandKind::Init),
    RootCommand::new("apikey", RootCommandKind::Apikey),
    RootCommand::new("version", RootCommandKind::Version),
    RootCommand::new("health", RootCommandKind::Http),
    RootCommand::new("test", RootCommandKind::Http),
    RootCommand::new("keys", RootCommandKind::Http),
    RootCommand::new("lifecycle", RootCommandKind::Http),
    RootCommand::new("routes", RootCommandKind::Http),
    RootCommand::new("remote-routes", RootCommandKind::Http),
    RootCommand::new("permissions", RootCommandKind::Http),
    RootCommand::new("config", RootCommandKind::Http),
    RootCommand::new("pub", RootCommandKind::Http),
    RootCommand::new("sign", RootCommandKind::Http),
    RootCommand::new("fpe", RootCommandKind::Http),
    RootCommand::new("token", RootCommandKind::Http),
    RootCommand::new("mac", RootCommandKind::Http),
    RootCommand::new("index", RootCommandKind::Http),
    RootCommand::new("commit", RootCommandKind::Http),
    RootCommand::new("mask", RootCommandKind::Http),
    RootCommand::new("message", RootCommandKind::Http),
];

impl RootCommand {
    const fn new(name: &'static str, kind: RootCommandKind) -> Self {
        Self { name, kind }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CliErrorFormat {
    Human,
    Json,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let error_format = detect_error_format(&args);
    if let Err(err) = real_main(args).await {
        print_cli_error(err.as_ref(), error_format);
        process::exit(1);
    }
}

async fn real_main(args: Vec<String>) -> Result<(), DynError> {
    let _guard = core::logging::init_logging();

    let mut args = args.into_iter();
    let _program = args.next();

    match args.next().as_deref() {
        Some(command) if command != "help" && command != "-h" && command != "--help" => {
            let Some(root_command) = find_root_command(command) else {
                return Err(error::invalid_input(format!("unknown command: {command}")));
            };
            run_root_command(root_command, command, args.collect()).await?;
        }
        Some("help") => match args.next() {
            Some(command) => {
                let mut help_args = vec![command];
                help_args.extend(args);
                print_command_help(help_args);
            }
            None => print_help(),
        },
        Some("-h" | "--help") | None => print_help(),
        Some(command) => {
            return Err(error::invalid_input(format!("unknown command: {command}")));
        }
    }

    Ok(())
}

fn detect_error_format(args: &[String]) -> CliErrorFormat {
    if args
        .windows(2)
        .any(|window| window[0] == "--output" && window[1] == "json")
    {
        CliErrorFormat::Json
    } else {
        CliErrorFormat::Human
    }
}

fn print_cli_error(err: &(dyn std::error::Error + 'static), format: CliErrorFormat) {
    eprintln!("{}", render_cli_error(err, format));
}

fn render_cli_error(err: &(dyn std::error::Error + 'static), format: CliErrorFormat) -> String {
    match format {
        CliErrorFormat::Human => format!("Error: {err}"),
        CliErrorFormat::Json => {
            let payload = serde_json::json!({ "error": err.to_string() });
            payload.to_string()
        }
    }
}

fn find_root_command(name: &str) -> Option<&'static RootCommand> {
    debug_assert_eq!(
        ROOT_COMMANDS.len(),
        io::cli::http::root_help_command_names().len(),
        "root dispatch table and help catalog command counts must match"
    );
    ROOT_COMMANDS.iter().find(|command| command.name == name)
}

async fn run_root_command(
    command: &RootCommand,
    name: &str,
    args: Vec<String>,
) -> Result<(), DynError> {
    match command.kind {
        RootCommandKind::Serve => run_serve_command(args).await,
        RootCommandKind::Init => run_init(args),
        RootCommandKind::Apikey => io::cli::apikey::run(args),
        RootCommandKind::Version => io::cli::version::run(args),
        RootCommandKind::Http => io::cli::http::run(name, args).await,
    }
}

async fn run_serve_command(args: Vec<String>) -> Result<(), DynError> {
    if matches!(
        args.first().map(String::as_str),
        Some("help" | "-h" | "--help")
    ) {
        io::cli::http::print_help("serve");
        return Ok(());
    }

    run_serve().await
}

async fn run_serve() -> Result<(), DynError> {
    info!("validating encrypted init file before starting http service");
    let init_state = io::cli::init::load_init_state()?;
    println!("[OK] Boot");
    info!("starting http service");

    if let Err(err) = io::http::run(init_state).await {
        error!(error = %err, "application failed");
        return Err(err);
    }

    info!("application finished successfully");
    Ok(())
}

fn run_init(args: Vec<String>) -> Result<(), DynError> {
    match args.first().map(String::as_str) {
        Some("help" | "-h" | "--help") => io::cli::http::print_help("init"),
        Some(command) => {
            eprintln!("unknown init command: {command}\n");
            io::cli::http::print_help("init");
        }
        None => {
            info!("initializing local key material");
            let path = io::cli::init::run_init()?;

            println!("created {path}");
            info!(path, "init completed successfully");
        }
    }

    Ok(())
}

fn print_help() {
    io::cli::http::print_help_path(&[]);
}

fn print_command_help(args: Vec<String>) {
    let Some(command) = args.first().map(String::as_str) else {
        print_help();
        return;
    };

    match command {
        "-h" | "--help" | "help" => print_help(),
        command if find_root_command(command).is_some() => {
            let path: Vec<&str> = args.iter().map(String::as_str).collect();
            io::cli::http::print_help_path(&path);
        }
        command => {
            eprintln!("unknown help command: {command}\n");
            print_help();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn root_dispatch_names() -> Vec<&'static str> {
        ROOT_COMMANDS.iter().map(|command| command.name).collect()
    }

    #[test]
    fn root_dispatch_table_has_no_duplicate_names() {
        let mut seen = HashSet::new();
        for name in root_dispatch_names() {
            assert!(seen.insert(name), "duplicate root command dispatch: {name}");
        }
    }

    #[test]
    fn root_dispatch_table_matches_help_catalog() {
        let dispatch = root_dispatch_names();

        for name in io::cli::http::root_help_command_names() {
            assert!(
                dispatch.contains(name),
                "{name} is listed in root help catalog but missing from dispatch"
            );
        }

        for name in dispatch {
            assert!(
                io::cli::http::root_help_command_names().contains(&name),
                "{name} is dispatched but missing from root help catalog"
            );
        }
    }

    #[test]
    fn every_root_command_has_catalog_help() {
        for name in root_dispatch_names() {
            assert!(
                io::cli::http::has_help_path(&[name]),
                "{name} root command must have catalog help"
            );
        }
    }

    #[test]
    fn http_root_commands_delegate_to_http() {
        for name in io::cli::http::http_help_command_names() {
            let command = find_root_command(name).expect("HTTP root command must be dispatched");
            assert_eq!(
                command.kind,
                RootCommandKind::Http,
                "{name} must delegate to HTTP CLI dispatch"
            );
        }
    }

    #[test]
    fn version_root_command_is_local() {
        let command =
            find_root_command("version").expect("version root command must be dispatched");
        assert_eq!(command.kind, RootCommandKind::Version);
    }

    #[tokio::test]
    async fn unknown_root_command_returns_error() {
        let err = real_main(vec![
            String::from("vectis"),
            String::from("definitely-not-a-command"),
        ])
        .await
        .expect_err("unknown root command must fail");

        assert_eq!(err.to_string(), "unknown command: definitely-not-a-command");
    }

    #[test]
    fn detects_json_error_format_from_output_flag() {
        let args = vec![
            String::from("vectis"),
            String::from("config"),
            String::from("routes"),
            String::from("add"),
            String::from("--output"),
            String::from("json"),
        ];
        assert_eq!(detect_error_format(&args), CliErrorFormat::Json);

        let args = vec![
            String::from("vectis"),
            String::from("config"),
            String::from("--output"),
            String::from("yaml"),
        ];
        assert_eq!(detect_error_format(&args), CliErrorFormat::Human);
    }

    #[test]
    fn renders_json_cli_errors() {
        let err = crate::core::validation::validate_text_field("field", "")
            .expect_err("empty text must fail");
        let rendered = render_cli_error(err.as_ref(), CliErrorFormat::Json);
        let value: serde_json::Value =
            serde_json::from_str(&rendered).expect("error must render JSON");
        assert_eq!(value["error"], "field must not be empty");

        let human = render_cli_error(err.as_ref(), CliErrorFormat::Human);
        assert_eq!(human, "Error: field must not be empty");
    }

    #[test]
    fn renders_unknown_command_as_json_error() {
        let err = error::invalid_input("unknown command: typo");
        let rendered = render_cli_error(err.as_ref(), CliErrorFormat::Json);
        let value: serde_json::Value =
            serde_json::from_str(&rendered).expect("error must render JSON");

        assert_eq!(value["error"], "unknown command: typo");
    }
}
