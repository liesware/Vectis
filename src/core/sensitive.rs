use serde::{Serialize, Serializer};
use std::fmt;
use zeroize::Zeroizing;

pub struct SensitiveString(Zeroizing<String>);

impl From<String> for SensitiveString {
    fn from(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl fmt::Debug for SensitiveString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Serialize for SensitiveString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_string_serializes_as_string() {
        let value = SensitiveString::from(String::from("123456"));
        let serialized = serde_json::to_string(&value).expect("sensitive string must serialize");

        assert_eq!(serialized, "\"123456\"");
    }

    #[test]
    fn sensitive_string_debug_is_redacted() {
        let value = SensitiveString::from(String::from("123456"));

        assert_eq!(format!("{value:?}"), "<redacted>");
    }
}
