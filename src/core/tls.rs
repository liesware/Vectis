// Copyright 2026 Eduardo Lopez
// SPDX-License-Identifier: Apache-2.0

use std::sync::Once;

static INSTALL: Once = Once::new();

/// Installs `ring` as the process-wide rustls `CryptoProvider`.
///
/// With both `ring` and `aws-lc-rs` compiled in (via axum-server, roughtime,
/// and reqwest), rustls cannot auto-select a provider, so the no-arg
/// `ServerConfig`/`ClientConfig` builders panic unless a default is installed.
/// Call this before building any rustls config — not only at the CLI
/// entrypoint — so library embedders, examples, and in-process tests are
/// covered too. Idempotent and cheap after the first call; safe from any thread.
pub fn ensure_crypto_provider() {
    INSTALL.call_once(|| {
        // An `Err` here only means a default is already installed — the exact
        // state we want — so there is nothing to surface.
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
