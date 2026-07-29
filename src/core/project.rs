// SPDX-FileCopyrightText: 2026 Eduardo Lopez
// SPDX-License-Identifier: Apache-2.0

pub const NAME: &str = env!("CARGO_PKG_NAME");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const LICENSE: &str = env!("CARGO_PKG_LICENSE");
pub const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");
pub const COPYRIGHT: &str = "Copyright 2026 Eduardo Lopez";
pub const DEVELOPER: &str = "Liesware";
pub const BUILD_STATUS: &str = "Experimental Build";
pub const CAPABILITIES: &[&str] = &[
    "protected-messages",
    "hybrid-signatures",
    "internal-encryption",
    "fpe",
    "tokenization",
    "mac",
    "blind-indexes",
    "masking",
    "commitments",
    "secret-sharing",
    "slh-dsa-artifact-signing",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_metadata_matches_cargo_manifest() {
        assert_eq!(NAME, "vectis");
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(LICENSE, "Apache-2.0");
        assert_eq!(REPOSITORY, "https://github.com/liesware/Vectis");
        assert_eq!(COPYRIGHT, "Copyright 2026 Eduardo Lopez");
        assert_eq!(DEVELOPER, "Liesware");
        assert_eq!(BUILD_STATUS, "Experimental Build");
        assert!(CAPABILITIES.contains(&"fpe"));
        assert!(CAPABILITIES.contains(&"secret-sharing"));
        assert!(CAPABILITIES.contains(&"slh-dsa-artifact-signing"));
    }
}
