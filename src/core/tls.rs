// Copyright 2026 Eduardo Lopez
// SPDX-License-Identifier: Apache-2.0

use std::sync::Once;

static INSTALL: Once = Once::new();

pub fn ensure_crypto_provider() {
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_provider_installation_is_idempotent() {
        ensure_crypto_provider();
        ensure_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());

        let _client = rustls::ClientConfig::builder();
        let _server = rustls::ServerConfig::builder();
    }
}
