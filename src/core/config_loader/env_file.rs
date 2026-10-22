//! Pure .env grammar and protected parsed values; source policy belongs to the loader.
use crate::error::DynError;
use std::collections::HashMap;
use zeroize::Zeroizing;

pub const ENV_FILE_MAX_SIZE_BYTES: u64 = 64 * 1024;
pub const ENV_NAME_MAX_SIZE_BYTES: usize = 128;
pub const ENV_VALUE_MAX_SIZE_BYTES: usize = 4096;

pub(super) struct FileValue {
    pub(super) value: Zeroizing<String>,
    pub(super) line: usize,
}

fn env_parse_error(line: usize, reason: &str) -> DynError {
    crate::error::invalid_input(format!(".env line {line}: {reason}"))
}

fn trim_env_whitespace(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

#[cfg(test)]
fn parse_env_content(content: &str) -> Result<HashMap<String, String>, DynError> {
    Ok(parse_protected_env_content(content)?
        .into_iter()
        .map(|(key, entry)| (key, entry.value.to_string()))
        .collect())
}

pub(super) fn parse_protected_env_content(
    content: &str,
) -> Result<HashMap<String, FileValue>, DynError> {
    if content.len() as u64 > ENV_FILE_MAX_SIZE_BYTES {
        return Err(crate::error::invalid_input(
            ".env exceeds maximum file size",
        ));
    }
    let mut values = HashMap::new();
    let mut first_lines = HashMap::new();

    for (index, record) in content.split_inclusive('\n').enumerate() {
        let line_number = index + 1;
        let line = match record.strip_suffix('\n') {
            Some(line) => line.strip_suffix('\r').unwrap_or(line),
            None => record,
        };
        if line.contains('\0') || line.contains('\r') {
            return Err(env_parse_error(
                line_number,
                "NUL or isolated carriage return",
            ));
        }
        let line = trim_env_whitespace(line);

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(env_parse_error(
                line_number,
                "expected KEY=VALUE assignment",
            ));
        };
        let key = trim_env_whitespace(key);
        if key.len() > ENV_NAME_MAX_SIZE_BYTES {
            return Err(env_parse_error(
                line_number,
                &format!("variable name exceeds {ENV_NAME_MAX_SIZE_BYTES} bytes"),
            ));
        }
        let valid_name = key.strip_prefix("VECTIS_").is_some_and(|suffix| {
            suffix
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_uppercase)
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        });
        if !valid_name {
            return Err(env_parse_error(
                line_number,
                "invalid VECTIS_ variable name",
            ));
        }
        if let Some(first_line) = first_lines.get(key) {
            return Err(env_parse_error(
                line_number,
                &format!("duplicate variable; first defined on line {first_line}"),
            ));
        }

        let value = trim_env_whitespace(value);
        let value = match value.as_bytes().first() {
            Some(quote @ (b'\'' | b'"')) => {
                let remainder = &value[1..];
                let end = remainder
                    .find(char::from(*quote))
                    .ok_or_else(|| env_parse_error(line_number, "unterminated quoted value"))?;
                if !trim_env_whitespace(&remainder[end + 1..]).is_empty() {
                    return Err(env_parse_error(
                        line_number,
                        "unexpected content after closing quote",
                    ));
                }
                &remainder[..end]
            }
            _ => value,
        };
        if value.len() > ENV_VALUE_MAX_SIZE_BYTES {
            return Err(env_parse_error(
                line_number,
                &format!("variable value exceeds {ENV_VALUE_MAX_SIZE_BYTES} bytes"),
            ));
        }
        first_lines.insert(key, line_number);
        values.insert(
            key.to_string(),
            FileValue {
                value: Zeroizing::new(value.to_string()),
                line: line_number,
            },
        );
    }

    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn grammar_accepts_unknown_names_and_preserves_source_lines() {
        let parsed = parse_protected_env_content("# comment\n\nVECTIS_UNKNOWN_123_=value").unwrap();
        assert_eq!(parsed["VECTIS_UNKNOWN_123_"].line, 3);
        assert_eq!(parsed["VECTIS_UNKNOWN_123_"].value.as_str(), "value");
    }

    #[test]
    fn file_byte_limit_is_inclusive() {
        let exact = format!("#{}", "a".repeat(ENV_FILE_MAX_SIZE_BYTES as usize - 1));
        assert!(parse_protected_env_content(&exact).unwrap().is_empty());
        assert_eq!(
            parse_protected_env_content(&(exact + "a"))
                .err()
                .unwrap()
                .to_string(),
            ".env exceeds maximum file size"
        );
    }

    #[test]
    fn env_file_duplicate_keys_are_rejected_with_both_lines() {
        for second_value in ["/a", "/b"] {
            let error = parse_env_content(&format!(
                "# comment\nVECTIS_UNSEAL_KEY_FILE=/a\n\nVECTIS_UNSEAL_KEY_FILE={second_value}\n"
            ))
            .unwrap_err()
            .to_string();
            assert_eq!(
                error,
                ".env line 4: duplicate variable; first defined on line 2"
            );
        }
    }

    #[test]
    fn env_parser_preserves_values_and_accepts_line_endings() {
        let source = concat!(
            "\t # comment\r\n\r\n",
            " \tVECTIS_A \t= \t unquoted text='value' # literal=a=b\t \r\n",
            "VECTIS_B='  quoted\tvalue  '\r\n",
            "VECTIS_C=\"a'b#=c\" \t\n",
            "VECTIS_D=${NAME}$(command)\\n\n",
            "VECTIS_E=\nVECTIS_F=''\nVECTIS_G=\"\"\n",
            "VECTIS_UNKNOWN_123_=literal",
        );
        let parsed = parse_env_content(source).unwrap();
        for (name, value) in [
            ("VECTIS_A", "unquoted text='value' # literal=a=b"),
            ("VECTIS_B", "  quoted\tvalue  "),
            ("VECTIS_C", "a'b#=c"),
            ("VECTIS_D", "${NAME}$(command)\\n"),
            ("VECTIS_E", ""),
            ("VECTIS_F", ""),
            ("VECTIS_G", ""),
            ("VECTIS_UNKNOWN_123_", "literal"),
        ] {
            assert_eq!(parsed.get(name).map(String::as_str), Some(value));
        }
        assert!(parse_env_content("").unwrap().is_empty());
        assert!(parse_env_content(" \t\n# comment").unwrap().is_empty());
    }

    #[test]
    fn env_parser_rejects_invalid_structure_without_reflecting_input() {
        const SECRET: &str = "sensitive-canary";
        for line in [
            SECRET.to_string(),
            format!("={SECRET}"),
            format!("PATH={SECRET}"),
            format!("VECTIS_={SECRET}"),
            format!("VECTIS_1KEY={SECRET}"),
            format!("VECTIS_lower={SECRET}"),
            format!("VECTIS_BAD NAME={SECRET}"),
            format!("VECTIS_BAD-NAME={SECRET}"),
            format!("VECTIS_{SECRET}=value"),
            format!("export VECTIS_A={SECRET}"),
            format!("\u{a0}VECTIS_A={SECRET}"),
            format!("VECTIS_A='{SECRET}"),
            format!("VECTIS_A=\"{SECRET}"),
            format!("VECTIS_A='{SECRET}' trailing"),
            format!("VECTIS_A='{SECRET}' # comment"),
            format!("VECTIS_A=\"{SECRET}\\\"more\""),
            format!("VECTIS_A={SECRET}\0"),
            format!("VECTIS_A={SECRET}\r"),
            format!("VECTIS_A={SECRET}\rmore"),
            format!("# {SECRET}\0"),
        ] {
            let error = parse_env_content(&format!("VECTIS_VALID=first\n{line}"))
                .unwrap_err()
                .to_string();
            assert!(error.starts_with(".env line 2:"));
            assert!(!error.contains(SECRET));
            assert!(!error.contains("first"));
            assert!(!error.chars().any(char::is_control));
        }
        assert!(parse_env_content("VECTIS_A='first\nsecond'").is_err());
        assert!(parse_env_content("VECTIS_A=valid\ninvalid\nVECTIS_B=valid").is_err());
        assert_eq!(
            parse_env_content("# comment\r\nVECTIS_A=valid\r\ninvalid")
                .unwrap_err()
                .to_string(),
            ".env line 3: expected KEY=VALUE assignment"
        );
    }

    #[test]
    fn env_parser_enforces_inclusive_byte_limits() {
        let name = format!("VECTIS_{}", "A".repeat(ENV_NAME_MAX_SIZE_BYTES - 7));
        let value = "a".repeat(ENV_VALUE_MAX_SIZE_BYTES);
        assert!(parse_env_content(&format!("{name}={value}")).is_ok());
        assert!(parse_env_content(&format!("{name}A=value")).is_err());
        assert!(parse_env_content(&format!("VECTIS_A={value}a")).is_err());
        assert!(parse_env_content(&format!("VECTIS_A=\t\"{value}\" \t")).is_ok());
        let unicode = "\u{e9}".repeat(ENV_VALUE_MAX_SIZE_BYTES / 2);
        let parsed = parse_env_content(&format!("VECTIS_A='{unicode}'")).unwrap();
        assert_eq!(parsed["VECTIS_A"], unicode);
        assert!(parse_env_content(&format!("VECTIS_A='{unicode}a'")).is_err());
        assert!(
            parse_env_content(&format!("VECTIS_A={}", "a".repeat(4097)))
                .unwrap_err()
                .to_string()
                .contains("4096 bytes")
        );
    }

    #[test]
    fn env_dist_matches_the_strict_grammar() {
        let parsed = parse_env_content(include_str!("../../../env.dist")).unwrap();
        assert_eq!(parsed["VECTIS_TLS_CERT_PATH"], "");
        assert_eq!(parsed["VECTIS_MAX_CONCURRENT_CRYPTO"], "");
        assert!(parsed["VECTIS_PLAINTEXT_MESSAGE"].contains("You're"));
    }

    proptest! {
        #[test]
        fn env_parser_preserves_quoted_unicode_values(value in r"[^\x00\r\n']{0,128}") {
            let parsed = parse_env_content(&format!("VECTIS_GENERATED='{value}'")).unwrap();
            prop_assert_eq!(parsed["VECTIS_GENERATED"].as_str(), value.as_str());
        }

        #[test]
        fn env_parser_handles_arbitrary_utf8_without_panicking(content in any::<String>()) {
            if let Ok(values) = parse_env_content(&content) {
                for (name, value) in values {
                    prop_assert!(name.starts_with("VECTIS_"));
                    prop_assert!(name.len() <= ENV_NAME_MAX_SIZE_BYTES);
                    prop_assert!(value.len() <= ENV_VALUE_MAX_SIZE_BYTES);
                }
            }
        }

    }
}
