use crate::core::crypto;
use crate::error::DynError;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub fn build_aad(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(";")
}

pub fn build_validated_aad(fields: &[(&str, &str)]) -> Result<String, DynError> {
    for (key, value) in fields {
        validate_aad_key("aad key", key)?;
        validate_aad_value(&format!("aad.{key}"), value)?;
    }

    Ok(build_aad(fields))
}

fn reject_aad_delimiters(field: &str, value: &str) -> Result<(), DynError> {
    if value.contains(';') || value.contains('=') {
        return Err(crate::error::invalid_input(format!(
            "{field} must not contain ';' or '='"
        )));
    }

    Ok(())
}

pub fn validate_aad_value(field: &str, value: &str) -> Result<(), DynError> {
    validate_text_field(field, value)?;
    reject_aad_delimiters(field, value)
}

pub fn validate_aad_key(field: &str, key: &str) -> Result<(), DynError> {
    validate_text_field(field, key)?;
    if key
        .chars()
        .all(|item| item.is_ascii_alphanumeric() || matches!(item, '_' | '.' | '-'))
    {
        return Ok(());
    }

    Err(crate::error::invalid_input(format!(
        "{field} contains invalid characters"
    )))
}

pub(crate) fn parse_aad_fields(aad: &str) -> Result<Vec<(String, String)>, DynError> {
    validate_text_field("aad", aad)?;

    let mut fields = Vec::new();
    for part in aad.split(';') {
        let mut pieces = part.split('=');
        let (Some(key), Some(value), None) = (pieces.next(), pieces.next(), pieces.next()) else {
            return Err(crate::error::invalid_input(
                "aad must contain key=value fields",
            ));
        };
        validate_aad_key("aad key", key)?;
        validate_aad_value("aad value", value)?;
        fields.push((key.to_string(), value.to_string()));
    }

    Ok(fields)
}

pub(crate) fn aad_field<'a>(
    fields: &'a [(String, String)],
    key: &str,
) -> Result<&'a str, DynError> {
    fields
        .iter()
        .find(|(field_key, _)| field_key == key)
        .map(|(_, value)| value.as_str())
        .ok_or_else(|| crate::error::invalid_input(format!("aad missing {key}")))
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

pub fn validate_config_name(field: &str, value: &str) -> Result<(), DynError> {
    validate_text_field(field, value)?;
    let max = crate::core::config::CONFIG_NAME_MAX_CHARS;
    if value.chars().count() > max {
        return Err(crate::error::invalid_input(format!(
            "{field} exceeds maximum allowed length: {max}"
        )));
    }

    Ok(())
}

pub fn validate_aad_config_name(field: &str, value: &str) -> Result<(), DynError> {
    validate_config_name(field, value)?;
    reject_aad_delimiters(field, value)
}

pub fn validate_labels(field: &str, value: &str, max_chars: usize) -> Result<(), DynError> {
    validate_text_field(field, value)?;
    if value.chars().count() > max_chars {
        return Err(crate::error::invalid_input(format!(
            "{field} exceeds maximum allowed length: {max_chars}"
        )));
    }

    let mut seen = HashSet::new();
    for label in value.split(';') {
        let Some((key, label_value)) = label.split_once('=') else {
            return Err(crate::error::invalid_input(format!(
                "{field} labels must use key=value format"
            )));
        };
        if key.is_empty() {
            return Err(crate::error::invalid_input(format!(
                "{field} label key must not be empty"
            )));
        }
        if label_value.is_empty() {
            return Err(crate::error::invalid_input(format!(
                "{field} label value must not be empty"
            )));
        }
        if label_value.contains('=') {
            return Err(crate::error::invalid_input(format!(
                "{field} label value must not contain '='"
            )));
        }
        if !key
            .chars()
            .all(|item| item.is_ascii_alphanumeric() || matches!(item, '_' | '.' | '-'))
        {
            return Err(crate::error::invalid_input(format!(
                "{field} label key contains invalid characters"
            )));
        }
        if !seen.insert(key) {
            return Err(crate::error::invalid_input(format!(
                "{field} label keys must be unique"
            )));
        }
    }

    Ok(())
}

pub fn validate_ref(value: &str) -> Result<String, DynError> {
    validate_text_field("ref", value)?;
    let max = crate::core::config::INTERNAL_REF_MAX_CHARS;
    if value.chars().count() > max {
        return Err(crate::error::invalid_input(format!(
            "ref exceeds maximum allowed length: {max}"
        )));
    }

    Ok(value.to_string())
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
    fn validate_config_name_enforces_text_and_length() {
        let max = crate::core::config::CONFIG_NAME_MAX_CHARS;
        assert!(validate_config_name("config.name", &"a".repeat(max)).is_ok());

        let err = validate_config_name("config.name", &"a".repeat(max + 1))
            .expect_err("overlong config names must fail");
        assert_eq!(
            err.to_string(),
            "config.name exceeds maximum allowed length: 128"
        );

        assert_eq!(
            validate_config_name("config.name", "")
                .unwrap_err()
                .to_string(),
            "config.name must not be empty"
        );
        assert_eq!(
            validate_config_name("config.name", "bad\nname")
                .unwrap_err()
                .to_string(),
            "config.name must not contain control characters"
        );
    }

    #[test]
    fn validate_aad_config_name_enforces_length_and_delimiters() {
        let max = crate::core::config::CONFIG_NAME_MAX_CHARS;
        assert!(validate_aad_config_name("fpe_profiles.name", &"a".repeat(max)).is_ok());

        assert_eq!(
            validate_aad_config_name("fpe_profiles.name", &"a".repeat(max + 1))
                .unwrap_err()
                .to_string(),
            "fpe_profiles.name exceeds maximum allowed length: 128"
        );
        assert_eq!(
            validate_aad_config_name("fpe_profiles.name", "bad;name")
                .unwrap_err()
                .to_string(),
            "fpe_profiles.name must not contain ';' or '='"
        );
        assert_eq!(
            validate_aad_config_name("fpe_profiles.name", "bad=name")
                .unwrap_err()
                .to_string(),
            "fpe_profiles.name must not contain ';' or '='"
        );
    }

    #[test]
    fn validate_labels_accepts_structured_key_value_pairs() {
        let value = "tenant=acme;field=patient_id;version=1";
        assert!(validate_labels("labels", value, value.chars().count()).is_ok());
    }

    #[test]
    fn validate_labels_rejects_invalid_shapes() {
        let cases = [
            ("", "labels must not be empty"),
            (
                "tenant=acme\n",
                "labels must not contain control characters",
            ),
            ("tenant", "labels labels must use key=value format"),
            ("=acme", "labels label key must not be empty"),
            ("tenant=", "labels label value must not be empty"),
            (
                "tenant=acme=extra",
                "labels label value must not contain '='",
            ),
            (
                "tenant name=acme",
                "labels label key contains invalid characters",
            ),
            (
                "tenant=acme;tenant=other",
                "labels label keys must be unique",
            ),
        ];

        for (value, expected) in cases {
            let err =
                validate_labels("labels", value, 128).expect_err("invalid labels value must fail");
            assert_eq!(err.to_string(), expected);
        }

        let err =
            validate_labels("labels", &"a".repeat(129), 128).expect_err("overlong labels fail");
        assert_eq!(
            err.to_string(),
            "labels exceeds maximum allowed length: 128"
        );
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
    fn build_validated_aad_matches_build_aad_for_valid_fields() {
        let fields = [
            ("tenant", "acme"),
            ("field", "patient_id"),
            ("version", "1"),
        ];

        assert_eq!(
            build_validated_aad(&fields).expect("valid AAD fields must build"),
            build_aad(&fields)
        );
        assert_eq!(
            build_validated_aad(&fields).expect("valid AAD fields must build"),
            "tenant=acme;field=patient_id;version=1"
        );
    }

    #[test]
    fn build_validated_aad_rejects_delimiters_in_values() {
        for value in ["acme;field=evil", "acme=extra"] {
            let err = build_validated_aad(&[("tenant", value)])
                .expect_err("AAD values with delimiters must fail");
            assert_eq!(err.to_string(), "aad.tenant must not contain ';' or '='");
        }
    }

    #[test]
    fn build_validated_aad_rejects_empty_or_control_values() {
        for value in ["", "acme\n"] {
            assert!(
                build_validated_aad(&[("tenant", value)]).is_err(),
                "must reject {value:?}"
            );
        }
    }

    #[test]
    fn build_validated_aad_allows_expected_key_chars() {
        let fields = [
            ("tokenization_version", "token-random-v1"),
            ("cipher_alg", "AES-256/GCM"),
            ("profile.name-1", "patient-id-token-v1"),
        ];

        assert_eq!(
            build_validated_aad(&fields).expect("expected key chars must be valid"),
            "tokenization_version=token-random-v1;cipher_alg=AES-256/GCM;profile.name-1=patient-id-token-v1"
        );
    }

    #[test]
    fn build_validated_aad_rejects_invalid_keys() {
        for key in ["", "bad key", "bad/key", "bad;key", "bad=key", "bad\nkey"] {
            assert!(
                build_validated_aad(&[(key, "value")]).is_err(),
                "must reject {key:?}"
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
