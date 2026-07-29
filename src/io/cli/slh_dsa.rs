use crate::core::{config, files};
use crate::error::DynError;
use crate::io::cli::{help_catalog, http, init};
use crate::ops;
use std::path::{Path, PathBuf};

pub fn run(args: Vec<String>) -> Result<(), DynError> {
    let parsed = parse_args(args)?;
    if parsed.command == "help" {
        print!("{}", help_catalog::render_help_path(&["slh-dsa"]));
        return Ok(());
    }
    match parsed.command.as_str() {
        "create" => run_create(parsed),
        "sign" => run_sign(parsed),
        "verify" => run_verify(parsed),
        command => Err(crate::error::invalid_input(format!(
            "unknown slh-dsa command: {command}"
        ))),
    }
}

struct Args {
    command: String,
    out: Option<PathBuf>,
    key: Option<PathBuf>,
    input: Option<PathBuf>,
    signature: Option<PathBuf>,
    output: http::OutputFormat,
}

fn parse_args(args: Vec<String>) -> Result<Args, DynError> {
    let mut output = http::OutputFormat::Yaml;
    let mut command = None;
    let mut out = None;
    let mut key = None;
    let mut input = None;
    let mut signature = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--output" => {
                output =
                    output_format(args.get(index + 1).ok_or_else(|| {
                        crate::error::invalid_input("--output requires a value")
                    })?)?;
                index += 2;
            }
            "--out" => {
                set_path(&mut out, args.get(index + 1), "--out")?;
                index += 2;
            }
            "--key" => {
                set_path(&mut key, args.get(index + 1), "--key")?;
                index += 2;
            }
            "--input" => {
                set_path(&mut input, args.get(index + 1), "--input")?;
                index += 2;
            }
            "--signature" => {
                set_path(&mut signature, args.get(index + 1), "--signature")?;
                index += 2;
            }
            "help" | "-h" | "--help" if command.is_none() => {
                return Ok(Args {
                    command: String::from("help"),
                    out,
                    key,
                    input,
                    signature,
                    output,
                });
            }
            value if value.starts_with('-') => {
                return Err(crate::error::invalid_input(format!(
                    "unknown slh-dsa option: {value}"
                )));
            }
            value => {
                if command.replace(value.to_string()).is_some() {
                    return Err(crate::error::invalid_input(
                        "slh-dsa accepts exactly one command; run `vectis help slh-dsa` for usage",
                    ));
                }
                index += 1;
            }
        }
    }
    Ok(Args {
        command: command.ok_or_else(|| crate::error::invalid_input("missing slh-dsa command"))?,
        out,
        key,
        input,
        signature,
        output,
    })
}

fn set_path(
    slot: &mut Option<PathBuf>,
    value: Option<&String>,
    flag: &str,
) -> Result<(), DynError> {
    let value =
        value.ok_or_else(|| crate::error::invalid_input(format!("{flag} requires a value")))?;
    if value.starts_with('-') {
        return Err(crate::error::invalid_input(format!(
            "unknown slh-dsa option: {value}"
        )));
    }
    if slot.replace(PathBuf::from(value)).is_some() {
        return Err(crate::error::invalid_input(format!(
            "{flag} may be specified only once"
        )));
    }
    Ok(())
}

fn output_format(value: &str) -> Result<http::OutputFormat, DynError> {
    match value {
        "yaml" => Ok(http::OutputFormat::Yaml),
        "json" => Ok(http::OutputFormat::Json),
        _ => Err(crate::error::invalid_input(
            "output must be one of: yaml, json",
        )),
    }
}

fn run_create(args: Args) -> Result<(), DynError> {
    reject_unused(&args, &["out"], "create")?;
    let prefix = args
        .out
        .ok_or_else(|| crate::error::invalid_input("slh-dsa create requires --out <prefix>"))?;
    let private_path = derived_path(&prefix, "-slh-dsa.enc")?;
    let public_path = derived_path(&prefix, "-slh-dsa.pub")?;
    if private_path == public_path || private_path.try_exists()? || public_path.try_exists()? {
        return Err(crate::error::invalid_input(
            "SLH-DSA key files already exist; refusing to overwrite",
        ));
    }
    let init_state = init::load_init_state()?;
    let (output, private_json, public_json) = ops::slh_dsa::create(&init_state)?;
    files::write_new_file_atomically(
        &private_path,
        private_json.as_bytes(),
        0o600,
        "SLH-DSA private key file",
    )?;
    if let Err(error) = files::write_new_file_atomically(
        &public_path,
        public_json.as_bytes(),
        0o644,
        "SLH-DSA public key file",
    ) {
        let rollback =
            files::remove_created_file_and_sync(&private_path, "SLH-DSA private key file");
        return match rollback {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(crate::error::internal(format!(
                "{error}; rollback failed: {rollback_error}"
            ))),
        };
    }
    let value = serde_json::json!({"kid": output.kid, "algorithm": output.algorithm, "private_key_file": private_path, "public_key_file": public_path});
    http::print_serializable_response(&value, args.output)
}

fn run_sign(args: Args) -> Result<(), DynError> {
    reject_unused(&args, &["key", "input", "out"], "sign")?;
    let key_path = required(args.key, "slh-dsa sign requires --key <encrypted-key>")?;
    let input = required(args.input, "slh-dsa sign requires --input <artifact>")?;
    let out = required(args.out, "slh-dsa sign requires --out <signature>")?;
    if out.try_exists()? {
        return Err(crate::error::invalid_input(
            "SLH-DSA signature file already exists; refusing to overwrite",
        ));
    }
    files::validate_file_mode(
        &key_path,
        files::SENSITIVE_FILE_FORBIDDEN_MODE_BITS,
        "SLH-DSA key file must be a regular file",
        "SLH-DSA private key file permissions are too open",
    )?;
    let key_content = read_utf8(
        &key_path,
        "SLH-DSA private key file",
        config::SLH_DSA_PRIVATE_FILE_MAX_SIZE_BYTES,
    )?;
    let init_state = init::load_init_state()?;
    let (output, signature) = ops::slh_dsa::sign(&init_state, &key_content, &input)?;
    files::write_new_file_atomically(&out, signature.as_bytes(), 0o644, "SLH-DSA signature file")?;
    let value = serde_json::json!({"kid": output.kid, "algorithm": output.algorithm, "message_hash_alg": output.message_hash_alg, "message_hash": output.message_hash, "signature_file": out});
    http::print_serializable_response(&value, args.output)
}

fn run_verify(args: Args) -> Result<(), DynError> {
    reject_unused(&args, &["key", "input", "signature"], "verify")?;
    let key_path = required(args.key, "slh-dsa verify requires --key <public-key>")?;
    let input = required(args.input, "slh-dsa verify requires --input <artifact>")?;
    let signature_path = required(
        args.signature,
        "slh-dsa verify requires --signature <signature>",
    )?;
    files::validate_file_mode(
        &key_path,
        files::PUBLIC_FILE_FORBIDDEN_MODE_BITS,
        "SLH-DSA key file must be a regular file",
        "SLH-DSA public key file permissions are too open",
    )?;
    let key_content = read_utf8(
        &key_path,
        "SLH-DSA public key file",
        config::SLH_DSA_PUBLIC_FILE_MAX_SIZE_BYTES,
    )?;
    let signature = read_utf8(
        &signature_path,
        "SLH-DSA signature file",
        config::SLH_DSA_SIGNATURE_FILE_MAX_SIZE_BYTES,
    )?;
    let output = ops::slh_dsa::verify(&key_content, &input, &signature)?;
    http::print_serializable_response(&output, args.output)
}

fn required(value: Option<PathBuf>, message: &str) -> Result<PathBuf, DynError> {
    value.ok_or_else(|| crate::error::invalid_input(message))
}

fn reject_unused(args: &Args, allowed: &[&str], command: &str) -> Result<(), DynError> {
    let supplied = [
        ("out", args.out.is_some()),
        ("key", args.key.is_some()),
        ("input", args.input.is_some()),
        ("signature", args.signature.is_some()),
    ];
    for (name, present) in supplied {
        if present && !allowed.contains(&name) {
            return Err(crate::error::invalid_input(format!(
                "slh-dsa {command} does not accept --{name}"
            )));
        }
    }
    Ok(())
}

fn derived_path(prefix: &Path, suffix: &str) -> Result<PathBuf, DynError> {
    let name = prefix
        .file_name()
        .ok_or_else(|| crate::error::invalid_input("SLH-DSA output prefix must name a file"))?;
    Ok(prefix.with_file_name(format!("{}{}", name.to_string_lossy(), suffix)))
}

fn read_utf8(path: &Path, label: &str, limit: u64) -> Result<String, DynError> {
    files::read_bounded_utf8_file(path, label, limit, files::MissingFilePolicy::Required)?
        .ok_or_else(|| crate::error::internal("required file unexpectedly absent"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn parser_rejects_unknown_flags_before_positional_confusion() {
        let err = match parse_args(strings(&["create", "--bogus"])) {
            Ok(_) => panic!("unknown flag must fail"),
            Err(err) => err,
        };
        assert_eq!(err.to_string(), "unknown slh-dsa option: --bogus");
    }

    #[test]
    fn parser_accepts_each_command_shape() {
        assert_eq!(
            parse_args(strings(&["create", "--out", "signing"]))
                .unwrap()
                .command,
            "create"
        );
        assert_eq!(
            parse_args(strings(&[
                "sign", "--key", "key", "--input", "input", "--out", "sig"
            ]))
            .unwrap()
            .command,
            "sign"
        );
        assert_eq!(
            parse_args(strings(&[
                "verify",
                "--key",
                "key",
                "--input",
                "input",
                "--signature",
                "sig"
            ]))
            .unwrap()
            .command,
            "verify"
        );
    }
}
