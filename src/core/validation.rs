use crate::core::crypto;
use crate::error::DynError;
use std::env;
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;
use zeroize::Zeroizing;

const DEFAULT_UNSEAL_KEY_FILE: &str = ".unseal_key";

pub fn build_aad(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(";")
}

pub fn validate_aad_value(field: &str, value: &str) -> Result<(), DynError> {
    validate_text_field(field, value)?;

    if value.contains(';') || value.contains('=') {
        return Err(crate::error::invalid_input(format!(
            "{field} must not contain ';' or '='"
        )));
    }

    Ok(())
}

pub fn validate_symmetric_key(
    field: &str,
    key_hex: &str,
    key_size_bytes: usize,
) -> Result<(), DynError> {
    validate_hex_field(field, key_hex)?;

    let expected_hex_len = key_size_bytes * 2;
    if key_hex.len() != expected_hex_len {
        return Err(crate::error::invalid_input(format!(
            "{field} must be {expected_hex_len} hex characters for a {key_size_bytes}-byte symmetric key, got {}",
            key_hex.len(),
        )));
    }

    Ok(())
}

pub fn validate_encrypted_payload(
    ciphertext_field: &str,
    ciphertext_hex: &str,
    nonce_field: &str,
    nonce_hex: &str,
    aad_field: &str,
    aad: &str,
    nonce_size_bytes: usize,
) -> Result<(), DynError> {
    validate_hex_field(ciphertext_field, ciphertext_hex)?;

    if ciphertext_hex.len() < 32 {
        return Err(crate::error::invalid_input(format!(
            "{ciphertext_field} must include at least a 16-byte authentication tag"
        )));
    }

    validate_hex_field(nonce_field, nonce_hex)?;

    let expected_nonce_hex_len = nonce_size_bytes * 2;
    if nonce_hex.len() != expected_nonce_hex_len {
        return Err(crate::error::invalid_input(format!(
            "{nonce_field} must be {expected_nonce_hex_len} hex characters for a {nonce_size_bytes}-byte nonce, got {}",
            nonce_hex.len()
        )));
    }

    if aad.trim().is_empty() {
        return Err(crate::error::invalid_input(format!(
            "{aad_field} must not be empty"
        )));
    }

    Ok(())
}

pub fn validate_text_field(field: &str, value: &str) -> Result<(), DynError> {
    if value.trim().is_empty() {
        return Err(crate::error::invalid_input(format!(
            "{field} must not be empty"
        )));
    }

    if value.chars().any(char::is_control) {
        return Err(crate::error::invalid_input(format!(
            "{field} must not contain control characters"
        )));
    }

    Ok(())
}

pub fn validate_socket_addr(field: &str, value: &str) -> Result<SocketAddr, DynError> {
    validate_text_field(field, value)?;

    value.parse::<SocketAddr>().map_err(|err| {
        crate::error::invalid_input(format!("{field} must be a valid socket address: {err}"))
    })
}

pub fn validate_host_port(field: &str, value: &str) -> Result<String, DynError> {
    validate_text_field(field, value)?;

    if value.parse::<SocketAddr>().is_ok() {
        return Ok(value.to_string());
    }

    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(crate::error::invalid_input(format!(
            "{field} must be a valid host:port value"
        )));
    };

    validate_hostname(&format!("{field}.host"), host)?;
    let port = port.parse::<u16>().map_err(|err| {
        crate::error::invalid_input(format!("{field}.port must be a valid TCP port: {err}"))
    })?;
    if port == 0 {
        return Err(crate::error::invalid_input(format!(
            "{field}.port must be greater than 0"
        )));
    }

    Ok(value.to_string())
}

pub fn validate_hostname(field: &str, value: &str) -> Result<(), DynError> {
    validate_text_field(field, value)?;

    if value.eq_ignore_ascii_case("localhost") || value.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    addr::parse_domain_name(value).map_err(|err| {
        crate::error::invalid_input(format!(
            "{field} must be a valid hostname or IP address: {err}"
        ))
    })?;

    Ok(())
}

pub fn validate_allowed_value(
    field: &str,
    value: &str,
    allowed_values: &[&str],
) -> Result<(), DynError> {
    validate_text_field(field, value)?;

    if allowed_values.contains(&value) {
        Ok(())
    } else {
        Err(crate::error::invalid_input(format!(
            "{field} must be one of {}",
            allowed_values.join(", ")
        )))
    }
}

pub fn validate_hex_field(field: &str, value: &str) -> Result<(), DynError> {
    if value.is_empty() {
        return Err(crate::error::invalid_input(format!(
            "{field} must not be empty"
        )));
    }

    if !value.len().is_multiple_of(2) {
        return Err(crate::error::invalid_input(format!(
            "{field} must have an even number of hex characters"
        )));
    }

    if !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(crate::error::invalid_input(format!(
            "{field} must contain only hexadecimal characters"
        )));
    }

    Ok(())
}

pub fn validate_hash_hex_field(
    field: &str,
    value: &str,
    hash_algorithm: &str,
) -> Result<(), DynError> {
    validate_allowed_value("hash_algorithm", hash_algorithm, crypto::HASH_ALGORITHMS)?;
    validate_hex_field(field, value)?;

    let expected_hex_len = crypto::hash_bytes(hash_algorithm, &[])?.len() * 2;
    if value.len() != expected_hex_len {
        return Err(crate::error::invalid_input(format!(
            "{field} must be {expected_hex_len} hex characters for {hash_algorithm}, got {}",
            value.len()
        )));
    }

    Ok(())
}

pub fn current_timestamp() -> Result<String, DynError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| {
            crate::error::invalid_input(format!("system time is before UNIX_EPOCH: {err}"))
        })?
        .as_secs();

    Ok(timestamp.to_string())
}

pub fn read_hidden_text(prompt: &str) -> Result<Zeroizing<String>, DynError> {
    let config = rpassword::ConfigBuilder::new()
        .password_feedback_hide()
        .build();
    let key = Zeroizing::new(rpassword::prompt_password_with_config(prompt, config)?);

    Ok(Zeroizing::new(key.trim().to_string()))
}

pub fn read_unseal_key(prompt: &str) -> Result<Zeroizing<String>, DynError> {
    let key = match env::var("VECTIS_UNSEAL_KEY") {
        Ok(value) => {
            info!("reading init unseal key from VECTIS_UNSEAL_KEY");
            Zeroizing::new(value.trim().to_string())
        }
        Err(env::VarError::NotPresent) => {
            if let Some(key) = read_unseal_key_file()? {
                key
            } else {
                info!("reading init unseal key from hidden prompt");
                read_hidden_text(prompt)?
            }
        }
        Err(err) => {
            return Err(crate::error::invalid_input(format!(
                "VECTIS_UNSEAL_KEY could not be read: {err}"
            )));
        }
    };

    validate_symmetric_key("VECTIS_UNSEAL_KEY", &key, 32)?;

    Ok(key)
}

fn read_unseal_key_file() -> Result<Option<Zeroizing<String>>, DynError> {
    let (path, explicit_path) = unseal_key_file_path()?;
    match fs::read_to_string(&path) {
        Ok(value) => {
            info!(path = %path.display(), "reading init unseal key from file");
            let key = Zeroizing::new(value.trim().to_string());
            validate_symmetric_key("VECTIS_UNSEAL_KEY_FILE", &key, 32)?;

            Ok(Some(key))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound && !explicit_path => Ok(None),
        Err(err) => Err(Box::new(io::Error::new(
            err.kind(),
            format!(
                "VECTIS_UNSEAL_KEY_FILE could not be read from {}: {err}",
                path.display()
            ),
        ))),
    }
}

fn unseal_key_file_path() -> Result<(PathBuf, bool), DynError> {
    match env::var("VECTIS_UNSEAL_KEY_FILE") {
        Ok(value) => {
            validate_text_field("VECTIS_UNSEAL_KEY_FILE", &value)?;

            Ok((PathBuf::from(value), true))
        }
        Err(env::VarError::NotPresent) => {
            if let Some(value) = env_file_value("VECTIS_UNSEAL_KEY_FILE")? {
                validate_text_field("VECTIS_UNSEAL_KEY_FILE", &value)?;

                Ok((PathBuf::from(value), true))
            } else {
                Ok((PathBuf::from(DEFAULT_UNSEAL_KEY_FILE), false))
            }
        }
        Err(err) => Err(crate::error::invalid_input(format!(
            "VECTIS_UNSEAL_KEY_FILE could not be read: {err}"
        ))),
    }
}

fn env_file_value(key: &str) -> Result<Option<String>, DynError> {
    let content = match fs::read_to_string(".env") {
        Ok(content) => content,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(Box::new(err)),
    };

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((env_key, value)) = line.split_once('=') else {
            continue;
        };

        if env_key.trim() == key {
            return Ok(Some(clean_env_value(value.trim())));
        }
    }

    Ok(None)
}

fn clean_env_value(value: &str) -> String {
    let quoted = (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\''));

    if quoted && value.len() >= 2 {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn expected_hash_hex_len(algorithm: &str) -> usize {
        match algorithm {
            "BLAKE2b(160)" => 40,
            "BLAKE2b(224)" | "SHA-224" | "SHA-3(224)" => 56,
            "BLAKE2b(256)" | "SHA-256" | "SHA-512-256" | "SHA-3(256)" => 64,
            "BLAKE2b(384)" | "SHA-384" | "SHA-3(384)" => 96,
            "BLAKE2b(512)" | "SHA-512" | "SHA-3(512)" | "Whirlpool" => 128,
            _ => unreachable!("test must use supported hash algorithms"),
        }
    }

    #[test]
    fn validate_text_field_rejects_control_and_empty() {
        for value in [
            "",
            "   ",
            "\u{0}",
            "\u{1d}",
            "\u{7f}",
            "\u{8a}",
            "before\u{1d}after",
            "line\nbreak",
            "tab\tstop",
        ] {
            assert!(
                validate_text_field("field", value).is_err(),
                "must reject {value:?}"
            );
        }
    }

    #[test]
    fn validate_text_field_accepts_unicode_and_long_text() {
        for value in ["café", "naïve", "日本語のテキスト", "with emoji 🔥"] {
            assert!(
                validate_text_field("field", value).is_ok(),
                "must accept {value:?}"
            );
        }
        assert!(validate_text_field("field", &"a".repeat(100_000)).is_ok());
    }

    #[test]
    fn validate_hex_field_rejects_non_hex_and_bad_length() {
        for value in [
            "", "a", "AAA", "gg", "café", "aa\u{1d}", "aa bb", "0xdead", "  ",
        ] {
            assert!(
                validate_hex_field("hex", value).is_err(),
                "must reject {value:?}"
            );
        }
        assert!(validate_hex_field("hex", "deadBEEF00").is_ok());
    }

    #[test]
    fn validate_host_port_rejects_malformed_and_control() {
        for value in [
            "",
            "   ",
            "nocolon",
            "host:notaport",
            "host:0",
            "host:99999",
            "\u{1d}host:80",
            "host:8\u{0}0",
        ] {
            assert!(
                validate_host_port("addr", value).is_err(),
                "must reject {value:?}"
            );
        }
        assert!(validate_host_port("addr", "127.0.0.1:3000").is_ok());
        assert!(validate_host_port("addr", "localhost:80").is_ok());
    }

    #[test]
    fn validate_aad_value_rejects_delimiters() {
        for value in ["a;b", "a=b", "tag;", "=", ";", "x=y;z", "ctrl\u{1d}", ""] {
            assert!(
                validate_aad_value("tag", value).is_err(),
                "must reject {value:?}"
            );
        }
        for value in ["plain", "café🔥", "with space", "dash-under_dot."] {
            assert!(
                validate_aad_value("tag", value).is_ok(),
                "must accept {value:?}"
            );
        }
    }

    #[test]
    fn validate_allowed_value_rejects_control_and_unlisted() {
        let allowed = ["active", "disabled"];
        for value in [
            "",
            "\u{1d}",
            "active\u{0}",
            "activ",
            "ACTIVE",
            "unknown",
            "café",
        ] {
            assert!(
                validate_allowed_value("status", value, &allowed).is_err(),
                "must reject {value:?}"
            );
        }
        assert!(validate_allowed_value("status", "active", &allowed).is_ok());
    }

    proptest! {
        #[test]
        fn validate_text_field_accepts_non_empty_text(value in "[A-Za-z0-9_.-][A-Za-z0-9 _.-]{0,63}") {
            prop_assert!(validate_text_field("field", &value).is_ok());
        }

        #[test]
        fn validate_text_field_rejects_empty_or_control_chars(prefix in "[A-Za-z0-9 _.-]{0,16}", suffix in "[A-Za-z0-9 _.-]{0,16}", control in 0u8..=31) {
            prop_assert!(validate_text_field("field", "").is_err());
            let value = format!("{prefix}{}{suffix}", char::from(control));
            prop_assert!(validate_text_field("field", &value).is_err());
        }

        #[test]
        fn validate_hex_field_accepts_even_hex(value in "([0-9a-fA-F]{2}){1,64}") {
            prop_assert!(validate_hex_field("hex", &value).is_ok());
        }

        #[test]
        fn validate_hex_field_rejects_invalid_shapes(value in "[0-9a-fA-F]{0,63}") {
            if value.is_empty() || !value.len().is_multiple_of(2) {
                prop_assert!(validate_hex_field("hex", &value).is_err());
            }
            let invalid = format!("{value}zz");
            prop_assert!(validate_hex_field("hex", &invalid).is_err());
        }

        #[test]
        fn validate_hash_hex_field_enforces_algorithm_length(algorithm in prop::sample::select(crypto::HASH_ALGORITHMS)) {
            let expected_len = expected_hash_hex_len(algorithm);
            let valid = "a".repeat(expected_len);
            prop_assert!(validate_hash_hex_field("hash", &valid, algorithm).is_ok());

            let short = "a".repeat(expected_len.saturating_sub(2));
            prop_assert!(validate_hash_hex_field("hash", &short, algorithm).is_err());

            let long = "a".repeat(expected_len + 2);
            prop_assert!(validate_hash_hex_field("hash", &long, algorithm).is_err());
        }

        #[test]
        fn validate_host_port_accepts_localhost_ip_and_domain(port in 1u16..=65535) {
            let localhost = format!("localhost:{port}");
            let ip = format!("127.0.0.1:{port}");
            let domain = format!("vectis-{port}.example.com:{port}");

            prop_assert!(validate_host_port("addr", &localhost).is_ok());
            prop_assert!(validate_host_port("addr", &ip).is_ok());
            prop_assert!(validate_host_port("addr", &domain).is_ok());
        }

        #[test]
        fn validate_host_port_rejects_malformed_values(value in "[A-Za-z0-9.:/_-]{0,64}") {
            let invalid = [
                String::new(),
                String::from("localhost"),
                String::from("localhost:0"),
                String::from("localhost:notaport"),
                String::from("http://localhost:3000"),
                format!("{value}\n"),
            ];

            for item in invalid {
                prop_assert!(validate_host_port("addr", &item).is_err());
            }
        }

        #[test]
        fn build_aad_is_deterministic_and_order_sensitive(
            first_key in "[a-z]{1,8}",
            first_value in "[A-Za-z0-9_.-]{1,16}",
            second_key in "[a-z]{1,8}",
            second_value in "[A-Za-z0-9_.-]{1,16}"
        ) {
            prop_assume!(first_key != second_key || first_value != second_value);

            let first = build_aad(&[(&first_key, &first_value), (&second_key, &second_value)]);
            let repeated = build_aad(&[(&first_key, &first_value), (&second_key, &second_value)]);
            let reversed = build_aad(&[(&second_key, &second_value), (&first_key, &first_value)]);

            prop_assert_eq!(&first, &repeated);
            prop_assert_eq!(
                &first,
                &format!("{first_key}={first_value};{second_key}={second_value}")
            );
            prop_assert_ne!(&first, &reversed);
        }
    }
}
