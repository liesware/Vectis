use crate::core::{canonical, config, permissions, protocol, remote_routes, routes};
use crate::error::DynError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use zeroize::Zeroize;

#[derive(Deserialize, Serialize)]
pub struct ConfigFile {
    version: String,
    #[serde(default)]
    routes: Vec<routes::RouteInput>,
    #[serde(default)]
    remote_routes: Vec<remote_routes::RemoteRouteInput>,
    #[serde(default)]
    permissions: Vec<permissions::PermissionClientInput>,
}

pub struct ConfigState {
    pub routes: routes::RoutesState,
    pub remote_routes: remote_routes::RemoteRoutesState,
    pub permissions: permissions::PermissionsState,
}

impl Zeroize for ConfigState {
    fn zeroize(&mut self) {
        self.permissions.zeroize();
    }
}

pub fn config_signature_path(path: &Path, configured_path: &Path) -> PathBuf {
    if configured_path.is_absolute() {
        configured_path.to_path_buf()
    } else if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        parent.join(configured_path)
    } else {
        configured_path.to_path_buf()
    }
}

pub fn canonical_config_json(content: &str) -> Result<String, DynError> {
    let config_file: ConfigFile = serde_json::from_str(content).map_err(|err| {
        crate::error::invalid_input(format!("config file must be valid JSON: {err}"))
    })?;
    protocol::validate_protocol_version("config.version", &config_file.version)?;

    Ok(String::from_utf8(canonical::canonical_json_v1(
        &config_file,
    )?)?)
}

pub fn read_config_file(path: &Path) -> Result<String, DynError> {
    read_limited_config_file(path, config::CONFIG_FILE_MAX_SIZE_BYTES, "config file")
}

pub fn read_config_signature_file(path: &Path) -> Result<String, DynError> {
    read_limited_config_file(
        path,
        config::CONFIG_SIGN_FILE_MAX_SIZE_BYTES,
        "config signature file",
    )
}

pub fn load_config_state(
    config: &config::AppConfig,
    verify_config: impl Fn(&Path, &str) -> Result<(), DynError>,
    is_loaded_kid: impl Fn(&str) -> bool,
) -> ConfigState {
    match load_config_file(&config.config_path, verify_config, config, &is_loaded_kid) {
        Ok(state) => {
            info!(
                config_path = %config.config_path.display(),
                routes_loaded = state.routes.len(),
                remote_routes_loaded = state.remote_routes.len(),
                clients_loaded = state.permissions.len(),
                "signed config loaded"
            );
            state
        }
        Err(err) => {
            warn!(
                config_path = %config.config_path.display(),
                error = %err,
                "signed config unavailable, using empty defaults"
            );
            empty_config_state(config)
        }
    }
}

pub fn reload_config_state(
    config: &config::AppConfig,
    verify_config: impl Fn(&Path, &str) -> Result<(), DynError>,
    is_loaded_kid: impl Fn(&str) -> bool,
) -> Result<ConfigState, DynError> {
    match load_config_file(&config.config_path, verify_config, config, &is_loaded_kid) {
        Ok(state) => Ok(state),
        Err(err) if crate::error::is_not_found(err.as_ref()) => Ok(empty_config_state(config)),
        Err(err) => Err(err),
    }
}

fn load_config_file(
    path: &Path,
    verify_config: impl Fn(&Path, &str) -> Result<(), DynError>,
    config: &config::AppConfig,
    is_loaded_kid: &impl Fn(&str) -> bool,
) -> Result<ConfigState, DynError> {
    let content = read_config_file(path)?;
    verify_config(path, &content)?;
    let config_file: ConfigFile = serde_json::from_str(&content).map_err(|err| {
        crate::error::invalid_input(format!("config file must be valid JSON: {err}"))
    })?;
    protocol::validate_protocol_version("config.version", &config_file.version)?;

    let validated_routes = routes::validate_routes(config_file.routes, is_loaded_kid)?;
    let validated_remote_routes =
        remote_routes::validate_remote_routes(config_file.remote_routes, is_loaded_kid)?;
    let validated_permissions =
        permissions::validate_permission_clients(config_file.permissions, is_loaded_kid)?;

    Ok(ConfigState {
        routes: routes::RoutesState::from_parts(
            config.final_app_addr.clone(),
            config.final_app_path.clone(),
            validated_routes,
        ),
        remote_routes: remote_routes::RemoteRoutesState::from_routes(validated_remote_routes),
        permissions: validated_permissions,
    })
}

fn empty_config_state(config: &config::AppConfig) -> ConfigState {
    ConfigState {
        routes: routes::RoutesState::from_parts(
            config.final_app_addr.clone(),
            config.final_app_path.clone(),
            Vec::new(),
        ),
        remote_routes: remote_routes::RemoteRoutesState::default(),
        permissions: permissions::PermissionsState::default(),
    }
}

fn read_limited_config_file(
    path: &Path,
    max_size_bytes: u64,
    label: &str,
) -> Result<String, DynError> {
    let metadata = fs::metadata(path).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            crate::error::not_found(format!("{label} does not exist"))
        } else {
            Box::new(err) as DynError
        }
    })?;

    if !metadata.is_file() {
        return Err(crate::error::invalid_input(format!(
            "{label} must point to a file"
        )));
    }

    if metadata.len() > max_size_bytes {
        return Err(crate::error::invalid_input(format!(
            "{label} exceeds maximum allowed size"
        )));
    }

    fs::read_to_string(path).map_err(|err| Box::new(err) as DynError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique_path(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "vectis_cfgtest_{}_{tag}_{seq}.json",
            std::process::id()
        ))
    }

    fn test_config(config_path: PathBuf) -> config::AppConfig {
        config::AppConfig {
            http_bind_addr: "127.0.0.1:3000".parse().unwrap(),
            mode: String::from("dev"),
            server_scheme: String::from("http"),
            remote_scheme: String::from("http"),
            final_app_scheme: String::from("http"),
            public_addr: String::from("localhost:3000"),
            final_app_addr: String::from("localhost:3999"),
            final_app_path: String::from("/message"),
            tls_cert_path: None,
            tls_key_path: None,
            tls_skip_verify: false,
            config_path,
            config_sign_path: PathBuf::from("config_sign.json"),
            api_key_hash: String::new(),
            protocol_version: String::from("v1"),
            storage_type: String::from("sqlite"),
            sqlite_path: PathBuf::from("data.db"),
            sender_hostname: String::from("a"),
            receiver_hostname: String::from("b"),
            default_crypto_profile: String::from("hybrid-performance-v1"),
            crypto_policy: String::from("profile-only"),
            plaintext_message: String::new(),
            metrics_enabled: true,
        }
    }

    #[test]
    fn canonical_config_json_is_order_independent() {
        let a = r#"{"version":"v1","routes":[],"remote_routes":[],"permissions":[]}"#;
        let b = r#"{"permissions":[],"remote_routes":[],"routes":[],"version":"v1"}"#;
        assert_eq!(
            canonical_config_json(a).unwrap(),
            canonical_config_json(b).unwrap()
        );
    }

    #[test]
    fn canonical_config_json_rejects_unsupported_version() {
        let bad = r#"{"version":"v2","routes":[],"remote_routes":[],"permissions":[]}"#;
        assert!(canonical_config_json(bad).is_err());
    }

    #[test]
    fn canonical_config_json_rejects_invalid_json() {
        assert!(canonical_config_json("{ not json").is_err());
    }

    #[test]
    fn load_config_state_is_lenient_when_missing() {
        let config = test_config(unique_path("load_missing"));
        let state = load_config_state(&config, |_, _| Ok(()), |_| true);
        assert_eq!(state.routes.len(), 0);
        assert_eq!(state.remote_routes.len(), 0);
        assert_eq!(state.permissions.len(), 0);
    }

    #[test]
    fn reload_config_state_returns_empty_when_missing() {
        let config = test_config(unique_path("reload_missing"));
        let state = reload_config_state(&config, |_, _| Ok(()), |_| true).unwrap();
        assert_eq!(state.routes.len(), 0);
    }

    #[test]
    fn reload_config_state_propagates_verify_error() {
        let path = unique_path("reload_verify_err");
        fs::write(
            &path,
            r#"{"version":"v1","routes":[],"remote_routes":[],"permissions":[]}"#,
        )
        .unwrap();
        let config = test_config(path.clone());
        let result = reload_config_state(
            &config,
            |_, _| Err(crate::error::invalid_signature("bad signature")),
            |_| true,
        );
        let _ = fs::remove_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn reload_config_state_rejects_oversized_config_file() {
        let path = unique_path("oversized_config");
        let file = fs::File::create(&path).unwrap();
        file.set_len(config::CONFIG_FILE_MAX_SIZE_BYTES + 1)
            .unwrap();
        drop(file);

        let config = test_config(path.clone());
        let result = reload_config_state(&config, |_, _| Ok(()), |_| true);

        let _ = fs::remove_file(&path);
        let err = match result {
            Ok(_) => panic!("oversized config file must be rejected"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("config file exceeds maximum allowed size"));
    }

    #[test]
    fn read_config_signature_file_rejects_oversized_signature_file() {
        let path = unique_path("oversized_config_sign");
        let file = fs::File::create(&path).unwrap();
        file.set_len(config::CONFIG_SIGN_FILE_MAX_SIZE_BYTES + 1)
            .unwrap();
        drop(file);

        let result = read_config_signature_file(&path);

        let _ = fs::remove_file(&path);
        let err = result.unwrap_err().to_string();
        assert!(err.contains("config signature file exceeds maximum allowed size"));
    }

    #[test]
    fn read_config_file_accepts_small_file() {
        let path = unique_path("small_config");
        let content = r#"{"version":"v1","routes":[],"remote_routes":[],"permissions":[]}"#;
        fs::write(&path, content).unwrap();

        let result = read_config_file(&path).unwrap();

        let _ = fs::remove_file(&path);
        assert_eq!(result, content);
    }
}
