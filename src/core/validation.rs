use crate::core::crypto;
use crate::error::DynError;
use std::env;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;
use zeroize::Zeroizing;

pub fn build_aad(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(";")
}

pub fn validate_symmetric_key(
    field: &str,
    key_hex: &str,
    key_size_bytes: usize,
) -> Result<(), DynError> {
    validate_hex_field(field, key_hex)?;

    let expected_hex_len = key_size_bytes * 2;
    if key_hex.len() != expected_hex_len {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{field} must be {expected_hex_len} hex characters for a {key_size_bytes}-byte symmetric key, got {}",
                key_hex.len(),
            ),
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
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{ciphertext_field} must include at least a 16-byte authentication tag"),
        )));
    }

    validate_hex_field(nonce_field, nonce_hex)?;

    let expected_nonce_hex_len = nonce_size_bytes * 2;
    if nonce_hex.len() != expected_nonce_hex_len {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{nonce_field} must be {expected_nonce_hex_len} hex characters for a {nonce_size_bytes}-byte nonce, got {}",
                nonce_hex.len()
            ),
        )));
    }

    if aad.trim().is_empty() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{aad_field} must not be empty"),
        )));
    }

    Ok(())
}

pub fn validate_text_field(field: &str, value: &str) -> Result<(), DynError> {
    if value.trim().is_empty() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} must not be empty"),
        )));
    }

    if value.chars().any(char::is_control) {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} must not contain control characters"),
        )));
    }

    Ok(())
}

pub fn validate_socket_addr(field: &str, value: &str) -> Result<SocketAddr, DynError> {
    validate_text_field(field, value)?;

    value.parse::<SocketAddr>().map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} must be a valid socket address: {err}"),
        )) as DynError
    })
}

pub fn validate_host_port(field: &str, value: &str) -> Result<String, DynError> {
    validate_text_field(field, value)?;

    if value.parse::<SocketAddr>().is_ok() {
        return Ok(value.to_string());
    }

    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} must be a valid host:port value"),
        )));
    };

    validate_hostname(&format!("{field}.host"), host)?;
    let port = port.parse::<u16>().map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field}.port must be a valid TCP port: {err}"),
        )) as DynError
    })?;
    if port == 0 {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field}.port must be greater than 0"),
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
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} must be a valid hostname or IP address: {err}"),
        )) as DynError
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
        Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} must be one of {}", allowed_values.join(", ")),
        )))
    }
}

pub fn validate_hex_field(field: &str, value: &str) -> Result<(), DynError> {
    if value.is_empty() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} must not be empty"),
        )));
    }

    if value.len() % 2 != 0 {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} must have an even number of hex characters"),
        )));
    }

    if !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{field} must contain only hexadecimal characters"),
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
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{field} must be {expected_hex_len} hex characters for {hash_algorithm}, got {}",
                value.len()
            ),
        )));
    }

    Ok(())
}

pub fn current_timestamp() -> Result<String, DynError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("system time is before UNIX_EPOCH: {err}"),
            )) as DynError
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
    let key = match env::var("UNSEAL_KEY") {
        Ok(value) => {
            info!("reading init unseal key from UNSEAL_KEY");
            Zeroizing::new(value.trim().to_string())
        }
        Err(env::VarError::NotPresent) => {
            info!("reading init unseal key from hidden prompt");
            read_hidden_text(prompt)?
        }
        Err(err) => {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("UNSEAL_KEY could not be read: {err}"),
            )));
        }
    };

    validate_symmetric_key("UNSEAL_KEY", &key, 32)?;

    Ok(key)
}
