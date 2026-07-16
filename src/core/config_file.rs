use crate::core::{
    canonical, config, fpe, permissions, protocol, remote_routes, routes, tokenization,
};
use crate::error::DynError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize, Serialize)]
pub struct ConfigFile {
    version: String,
    #[serde(default)]
    routes: Vec<routes::RouteInput>,
    #[serde(default)]
    remote_routes: Vec<remote_routes::RemoteRouteInput>,
    #[serde(default)]
    permissions: Vec<permissions::PermissionClientInput>,
    #[serde(default)]
    fpe_profiles: Vec<fpe::FpeProfileInput>,
    #[serde(default)]
    tokenization_profiles: Vec<tokenization::TokenizationProfileInput>,
}

pub struct ConfigState {
    pub routes: routes::RoutesState,
    pub remote_routes: remote_routes::RemoteRoutesState,
    pub permissions: permissions::PermissionsState,
    pub fpe_profiles: fpe::FpeProfilesState,
    pub tokenization_profiles: tokenization::TokenizationProfilesState,
}

impl Zeroize for ConfigState {
    fn zeroize(&mut self) {
        self.permissions.zeroize();
        self.fpe_profiles.zeroize();
        self.tokenization_profiles.zeroize();
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

pub fn validate_config_content(
    content: &str,
    config: &config::AppConfig,
    is_loaded_kid: impl Fn(&str) -> bool,
    derive_fpe_key: impl Fn(fpe::FpeKeyDerivationRequest<'_>) -> Result<Zeroizing<Vec<u8>>, DynError>,
    derive_tokenization_keys: impl Fn(
        tokenization::TokenizationKeyDerivationRequest<'_>,
    ) -> Result<tokenization::DerivedTokenizationKeys, DynError>,
) -> Result<ConfigState, DynError> {
    let config_file: ConfigFile = serde_json::from_str(content).map_err(|err| {
        crate::error::invalid_input(format!("config file must be valid JSON: {err}"))
    })?;
    validate_config_file(
        config_file,
        config,
        &is_loaded_kid,
        &derive_fpe_key,
        &derive_tokenization_keys,
    )
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
    derive_fpe_key: impl Fn(fpe::FpeKeyDerivationRequest<'_>) -> Result<Zeroizing<Vec<u8>>, DynError>,
    derive_tokenization_keys: impl Fn(
        tokenization::TokenizationKeyDerivationRequest<'_>,
    ) -> Result<tokenization::DerivedTokenizationKeys, DynError>,
) -> Result<ConfigState, DynError> {
    match load_config_file(
        &config.config_path,
        verify_config,
        config,
        &is_loaded_kid,
        &derive_fpe_key,
        &derive_tokenization_keys,
    ) {
        Ok(state) => {
            info!(
                config_path = %config.config_path.display(),
                routes_loaded = state.routes.len(),
                remote_routes_loaded = state.remote_routes.len(),
                clients_loaded = state.permissions.len(),
                "signed config loaded"
            );
            Ok(state)
        }
        Err(err) if crate::error::is_not_found(err.as_ref()) => {
            warn!(
                config_path = %config.config_path.display(),
                error = %err,
                "signed config unavailable, using empty defaults"
            );
            Ok(empty_config_state(config))
        }
        Err(err) => Err(err),
    }
}

pub fn reload_config_state(
    config: &config::AppConfig,
    verify_config: impl Fn(&Path, &str) -> Result<(), DynError>,
    is_loaded_kid: impl Fn(&str) -> bool,
    derive_fpe_key: impl Fn(fpe::FpeKeyDerivationRequest<'_>) -> Result<Zeroizing<Vec<u8>>, DynError>,
    derive_tokenization_keys: impl Fn(
        tokenization::TokenizationKeyDerivationRequest<'_>,
    ) -> Result<tokenization::DerivedTokenizationKeys, DynError>,
) -> Result<ConfigState, DynError> {
    match load_config_file(
        &config.config_path,
        verify_config,
        config,
        &is_loaded_kid,
        &derive_fpe_key,
        &derive_tokenization_keys,
    ) {
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
    derive_fpe_key: &impl Fn(fpe::FpeKeyDerivationRequest<'_>) -> Result<Zeroizing<Vec<u8>>, DynError>,
    derive_tokenization_keys: &impl Fn(
        tokenization::TokenizationKeyDerivationRequest<'_>,
    ) -> Result<tokenization::DerivedTokenizationKeys, DynError>,
) -> Result<ConfigState, DynError> {
    let content = read_config_file(path)?;
    verify_config(path, &content)?;
    let config_file: ConfigFile = serde_json::from_str(&content).map_err(|err| {
        crate::error::invalid_input(format!("config file must be valid JSON: {err}"))
    })?;
    validate_config_file(
        config_file,
        config,
        is_loaded_kid,
        derive_fpe_key,
        derive_tokenization_keys,
    )
}

fn validate_config_file(
    config_file: ConfigFile,
    config: &config::AppConfig,
    is_loaded_kid: &impl Fn(&str) -> bool,
    derive_fpe_key: &impl Fn(fpe::FpeKeyDerivationRequest<'_>) -> Result<Zeroizing<Vec<u8>>, DynError>,
    derive_tokenization_keys: &impl Fn(
        tokenization::TokenizationKeyDerivationRequest<'_>,
    ) -> Result<tokenization::DerivedTokenizationKeys, DynError>,
) -> Result<ConfigState, DynError> {
    protocol::validate_protocol_version("config.version", &config_file.version)?;

    let validated_routes = routes::validate_routes(config_file.routes, is_loaded_kid)?;
    let validated_remote_routes =
        remote_routes::validate_remote_routes(config_file.remote_routes, is_loaded_kid)?;
    let validated_permissions =
        permissions::validate_permission_clients(config_file.permissions, is_loaded_kid)?;
    let validated_fpe_profiles =
        fpe::validate_fpe_profiles(config_file.fpe_profiles, is_loaded_kid, derive_fpe_key)?;
    let validated_tokenization_profiles = tokenization::validate_tokenization_profiles(
        config_file.tokenization_profiles,
        is_loaded_kid,
        derive_tokenization_keys,
    )?;

    Ok(ConfigState {
        routes: routes::RoutesState::from_parts(
            config.final_app_addr.clone(),
            config.final_app_path.clone(),
            validated_routes,
        ),
        remote_routes: remote_routes::RemoteRoutesState::from_routes(validated_remote_routes),
        permissions: validated_permissions,
        fpe_profiles: validated_fpe_profiles,
        tokenization_profiles: validated_tokenization_profiles,
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
        fpe_profiles: fpe::FpeProfilesState::default(),
        tokenization_profiles: tokenization::TokenizationProfilesState::default(),
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
            crate::error::internal(format!("{label} could not be read"))
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

    fs::read_to_string(path).map_err(|err| match err.kind() {
        io::ErrorKind::NotFound => crate::error::not_found(format!("{label} does not exist")),
        io::ErrorKind::InvalidData => {
            crate::error::invalid_input(format!("{label} is not valid UTF-8"))
        }
        _ => crate::error::internal(format!("{label} could not be read")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique_path(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "vectis_cfgtest_{}_{tag}_{seq}.json",
            std::process::id()
        ))
    }

    fn dummy_fpe_key() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(vec![0u8; fpe::FPE_KEY_SIZE_BYTES])
    }

    fn dummy_tokenization_keys() -> tokenization::DerivedTokenizationKeys {
        tokenization::DerivedTokenizationKeys {
            hash_key: Zeroizing::new(vec![0u8; tokenization::TOKEN_KEY_SIZE_BYTES]),
            data_key: Zeroizing::new(vec![1u8; tokenization::TOKEN_KEY_SIZE_BYTES]),
            cipher_algorithm: String::from("AES-256/GCM"),
        }
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
            postgres_dsn: String::new(),
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
        let state = load_config_state(
            &config,
            |_, _| Ok(()),
            |_| true,
            |_| Ok(dummy_fpe_key()),
            |_| Ok(dummy_tokenization_keys()),
        )
        .unwrap();
        assert_eq!(state.routes.len(), 0);
        assert_eq!(state.remote_routes.len(), 0);
        assert_eq!(state.permissions.len(), 0);
    }

    #[test]
    fn load_config_state_propagates_verify_error() {
        let path = unique_path("load_verify_err");
        fs::write(
            &path,
            r#"{"version":"v1","routes":[],"remote_routes":[],"permissions":[]}"#,
        )
        .unwrap();
        let config = test_config(path.clone());
        let result = load_config_state(
            &config,
            |_, _| Err(crate::error::invalid_signature("bad signature")),
            |_| true,
            |_| Ok(dummy_fpe_key()),
            |_| Ok(dummy_tokenization_keys()),
        );
        let _ = fs::remove_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn load_config_state_rejects_invalid_json() {
        let path = unique_path("load_invalid_json");
        fs::write(&path, "{ not json").unwrap();
        let config = test_config(path.clone());
        let result = load_config_state(
            &config,
            |_, _| Ok(()),
            |_| true,
            |_| Ok(dummy_fpe_key()),
            |_| Ok(dummy_tokenization_keys()),
        );
        let _ = fs::remove_file(&path);
        let err = match result {
            Ok(_) => panic!("invalid config JSON must be rejected"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("config file must be valid JSON"));
    }

    #[test]
    fn load_config_state_rejects_oversized_config_file() {
        let path = unique_path("load_oversized_config");
        let file = fs::File::create(&path).unwrap();
        file.set_len(config::CONFIG_FILE_MAX_SIZE_BYTES + 1)
            .unwrap();
        drop(file);

        let config = test_config(path.clone());
        let result = load_config_state(
            &config,
            |_, _| Ok(()),
            |_| true,
            |_| Ok(dummy_fpe_key()),
            |_| Ok(dummy_tokenization_keys()),
        );

        let _ = fs::remove_file(&path);
        let err = match result {
            Ok(_) => panic!("oversized config file must be rejected"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("config file exceeds maximum allowed size"));
    }

    #[test]
    fn reload_config_state_returns_empty_when_missing() {
        let config = test_config(unique_path("reload_missing"));
        let state = reload_config_state(
            &config,
            |_, _| Ok(()),
            |_| true,
            |_| Ok(dummy_fpe_key()),
            |_| Ok(dummy_tokenization_keys()),
        )
        .unwrap();
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
            |_| Ok(dummy_fpe_key()),
            |_| Ok(dummy_tokenization_keys()),
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
        let result = reload_config_state(
            &config,
            |_, _| Ok(()),
            |_| true,
            |_| Ok(dummy_fpe_key()),
            |_| Ok(dummy_tokenization_keys()),
        );

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

    proptest! {
        #[test]
        fn canonical_config_json_stays_stable_for_equivalent_empty_config(
            include_routes in any::<bool>(),
            include_remote_routes in any::<bool>(),
            include_permissions in any::<bool>()
        ) {
            let mut first = serde_json::Map::new();
            first.insert(String::from("version"), json!("v1"));
            if include_routes {
                first.insert(String::from("routes"), json!([]));
            }
            if include_remote_routes {
                first.insert(String::from("remote_routes"), json!([]));
            }
            if include_permissions {
                first.insert(String::from("permissions"), json!([]));
            }

            let second = json!({
                "permissions": if include_permissions { json!([]) } else { json!(null) },
                "remote_routes": if include_remote_routes { json!([]) } else { json!(null) },
                "routes": if include_routes { json!([]) } else { json!(null) },
                "version": "v1"
            });
            let mut second_object = second.as_object().unwrap().clone();
            if !include_permissions {
                second_object.remove("permissions");
            }
            if !include_remote_routes {
                second_object.remove("remote_routes");
            }
            if !include_routes {
                second_object.remove("routes");
            }

            let first_json = serde_json::to_string(&first).unwrap();
            let second_json = serde_json::to_string(&second_object).unwrap();
            let canonical = canonical_config_json(&first_json).unwrap();

            prop_assert_eq!(&canonical, &canonical_config_json(&second_json).unwrap());
            prop_assert!(serde_json::from_str::<serde_json::Value>(&canonical).is_ok());
            prop_assert_eq!(&canonical, &canonical_config_json(&canonical).unwrap());
        }
    }

    #[test]
    fn validate_config_content_accepts_minimal_empty_config() {
        let config = test_config(PathBuf::from("config.json"));
        let state = validate_config_content(
            r#"{"version":"v1"}"#,
            &config,
            |_| true,
            |_| Ok(dummy_fpe_key()),
            |_| Ok(dummy_tokenization_keys()),
        )
        .unwrap();

        assert!(state.routes.is_empty());
        assert!(state.remote_routes.is_empty());
        assert!(state.permissions.is_empty());
    }

    #[test]
    fn validate_config_content_rejects_malformed_sections() {
        let config = test_config(PathBuf::from("config.json"));

        assert!(
            validate_config_content(
                r#"{"version":"v2"}"#,
                &config,
                |_| true,
                |_| { Ok(dummy_fpe_key()) },
                |_| Ok(dummy_tokenization_keys()),
            )
            .is_err()
        );
        assert!(
            validate_config_content(
                r#"{"version":"v1","routes":{}}"#,
                &config,
                |_| true,
                |_| Ok(dummy_fpe_key()),
                |_| Ok(dummy_tokenization_keys()),
            )
            .is_err()
        );
        assert!(
            validate_config_content(
                r#"{"version":"v1","remote_routes":{}}"#,
                &config,
                |_| true,
                |_| Ok(dummy_fpe_key()),
                |_| Ok(dummy_tokenization_keys()),
            )
            .is_err()
        );
        assert!(
            validate_config_content(
                r#"{"version":"v1","permissions":{}}"#,
                &config,
                |_| true,
                |_| Ok(dummy_fpe_key()),
                |_| Ok(dummy_tokenization_keys()),
            )
            .is_err()
        );
    }
}
