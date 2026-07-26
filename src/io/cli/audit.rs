use crate::core::{audit_chain, validation};
use crate::error::DynError;
use crate::io::cli::{help_catalog, http};
use std::path::PathBuf;

pub fn run(args: Vec<String>) -> Result<(), DynError> {
    let (output, command, file) = parse_args(args)?;
    if command == "help" {
        print!("{}", help_catalog::render_help_path(&["audit"]));
        return Ok(());
    }
    if command != "verify" {
        return Err(crate::error::invalid_input(format!(
            "unknown audit command: {command}"
        )));
    }
    let file =
        file.ok_or_else(|| crate::error::invalid_input("audit verify requires --file <path>"))?;
    let result = audit_chain::verify_file(&file)?;
    http::print_serializable_response(&result, output)
}

fn parse_args(
    args: Vec<String>,
) -> Result<(http::OutputFormat, String, Option<PathBuf>), DynError> {
    let mut output = http::OutputFormat::Yaml;
    let mut command = None;
    let mut file = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--output" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| crate::error::invalid_input("--output requires a value"))?;
                validation::validate_allowed_value("output", value, &["yaml", "json"])?;
                output = if value == "json" {
                    http::OutputFormat::Json
                } else {
                    http::OutputFormat::Yaml
                };
                index += 2;
            }
            "--file" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| crate::error::invalid_input("--file requires a value"))?;
                if file.replace(PathBuf::from(value)).is_some() {
                    return Err(crate::error::invalid_input(
                        "--file may be specified only once",
                    ));
                }
                index += 2;
            }
            "help" | "-h" | "--help" if command.is_none() => {
                return Ok((output, String::from("help"), file));
            }
            value if value.starts_with('-') => {
                return Err(crate::error::invalid_input(format!(
                    "unknown audit option: {value}"
                )));
            }
            value => {
                if command.replace(value.to_string()).is_some() {
                    return Err(crate::error::invalid_input(
                        "audit accepts exactly one command; run `vectis help audit` for usage",
                    ));
                }
                index += 1;
            }
        }
    }

    Ok((
        output,
        command.ok_or_else(|| crate::error::invalid_input("missing audit command"))?,
        file,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_requires_verify_file_and_rejects_unknown_options() {
        assert!(run(vec![String::from("verify")]).is_err());
        let err = run(vec![String::from("verify"), String::from("--bogus")]).unwrap_err();
        assert_eq!(err.to_string(), "unknown audit option: --bogus");
    }
}
