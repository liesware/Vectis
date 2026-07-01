use crate::core::{canonical, crypto, protocol, validation};
use crate::error::DynError;
use crate::ops::keys;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use zeroize::Zeroize;

pub const PERMISSION_ACTIONS: &[&str] = &[
    "admin",
    "keys",
    "lifecycle",
    "self-test",
    "sign",
    "message",
    "metrics",
];
const GLOBAL_PERMISSION_ACTIONS: &[&str] = &["metrics"];

#[derive(Clone)]
pub struct AuthenticatedClient {
    client: String,
    apikey_hash: String,
    root: bool,
    admin: bool,
}

#[derive(Clone, Default)]
pub struct PermissionsState {
    clients: Vec<PermissionClient>,
    by_hash: HashMap<String, usize>,
}

#[derive(Clone)]
struct PermissionClient {
    client: String,
    apikey_hash: String,
    admin: bool,
    permissions: Vec<KidPermission>,
}

#[derive(Clone)]
struct KidPermission {
    kid: String,
    actions: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct PermissionsFile {
    version: String,
    clients: Vec<PermissionClientInput>,
}

#[derive(Deserialize, Serialize)]
struct PermissionClientInput {
    client: String,
    apikey_hash: String,
    status: String,
    permissions: Vec<KidPermissionInput>,
}

#[derive(Deserialize, Serialize)]
struct KidPermissionInput {
    kid: String,
    actions: Vec<String>,
}

impl AuthenticatedClient {
    pub fn root(apikey_hash: String) -> Self {
        Self {
            client: String::from("root"),
            apikey_hash,
            root: true,
            admin: true,
        }
    }

    fn from_permission_client(client: &PermissionClient) -> Self {
        Self {
            client: client.client.clone(),
            apikey_hash: client.apikey_hash.clone(),
            root: false,
            admin: client.admin,
        }
    }

    pub fn is_root(&self) -> bool {
        self.root
    }

    pub fn is_admin(&self) -> bool {
        self.admin
    }

    pub fn apikey_hash(&self) -> &str {
        &self.apikey_hash
    }

    pub fn client_name(&self) -> &str {
        &self.client
    }

    pub fn fingerprint(&self) -> &str {
        &self.apikey_hash[..self.apikey_hash.len().min(8)]
    }
}

impl Zeroize for AuthenticatedClient {
    fn zeroize(&mut self) {
        self.client.zeroize();
        self.apikey_hash.zeroize();
        self.root = false;
        self.admin = false;
    }
}

impl PermissionsState {
    fn from_clients(clients: Vec<PermissionClient>) -> Self {
        let by_hash = clients
            .iter()
            .enumerate()
            .map(|(index, client)| (client.apikey_hash.clone(), index))
            .collect();

        Self { clients, by_hash }
    }

    pub fn len(&self) -> usize {
        self.clients.len()
    }

    pub fn authenticate_hash(&self, apikey_hash: &str) -> Option<AuthenticatedClient> {
        let candidate = apikey_hash.as_bytes();
        let mut matched: Option<usize> = None;
        for (index, client) in self.clients.iter().enumerate() {
            if crypto::constant_time_eq(client.apikey_hash.as_bytes(), candidate) {
                matched = Some(index);
            }
        }
        matched
            .and_then(|index| self.clients.get(index))
            .map(AuthenticatedClient::from_permission_client)
    }

    pub fn require_permission(
        &self,
        client: &AuthenticatedClient,
        kid: Option<&str>,
        action: &str,
    ) -> Result<(), DynError> {
        validation::validate_allowed_value("permission action", action, PERMISSION_ACTIONS)?;

        if client.is_root() || client.is_admin() {
            return Ok(());
        }

        let Some(permission_client) = self
            .by_hash
            .get(client.apikey_hash())
            .and_then(|index| self.clients.get(*index))
        else {
            return permission_denied("api key is not authorized");
        };

        if is_global_permission_action(action) {
            if permission_client.permissions.iter().any(|permission| {
                permission.kid == "*" && permission.actions.iter().any(|item| item == action)
            }) {
                return Ok(());
            }

            return permission_denied("api key does not have permission for this endpoint");
        }

        let Some(kid) = kid else {
            return permission_denied("admin permission is required for this endpoint");
        };
        keys::validate_key_id(kid)?;

        if permission_client.permissions.iter().any(|permission| {
            permission.kid == kid && permission.actions.iter().any(|item| item == action)
        }) {
            return Ok(());
        }

        permission_denied("api key does not have permission for this kid")
    }

    pub fn reload_from_file(
        &self,
        path: &Path,
        verify_permissions: impl Fn(&Path, &str) -> Result<(), DynError>,
        is_loaded_kid: impl Fn(&str) -> bool,
    ) -> Result<PermissionsState, DynError> {
        match load_permissions_file(path, verify_permissions, is_loaded_kid) {
            Ok(state) => Ok(state),
            Err(err) if is_not_found_error(err.as_ref()) => Ok(PermissionsState::default()),
            Err(err) => Err(err),
        }
    }
}

impl Zeroize for PermissionsState {
    fn zeroize(&mut self) {
        self.clients.zeroize();
        for (mut apikey_hash, _) in self.by_hash.drain() {
            apikey_hash.zeroize();
        }
    }
}

impl Zeroize for PermissionClient {
    fn zeroize(&mut self) {
        self.client.zeroize();
        self.apikey_hash.zeroize();
        self.admin = false;
        self.permissions.zeroize();
    }
}

impl Zeroize for KidPermission {
    fn zeroize(&mut self) {
        self.kid.zeroize();
        self.actions.zeroize();
    }
}

pub fn load_permissions_state(
    path: &Path,
    verify_permissions: impl Fn(&Path, &str) -> Result<(), DynError>,
    is_loaded_kid: impl Fn(&str) -> bool,
) -> Result<PermissionsState, DynError> {
    match load_permissions_file(path, verify_permissions, is_loaded_kid) {
        Ok(state) => {
            info!(
                permissions_path = %path.display(),
                clients_loaded = state.len(),
                "permissions loaded"
            );
            Ok(state)
        }
        Err(err) if is_not_found_error(err.as_ref()) => {
            warn!(
                permissions_path = %path.display(),
                "permissions file does not exist, only root api key is authorized"
            );
            Ok(PermissionsState::default())
        }
        Err(err) => Err(err),
    }
}

fn load_permissions_file(
    path: &Path,
    verify_permissions: impl Fn(&Path, &str) -> Result<(), DynError>,
    is_loaded_kid: impl Fn(&str) -> bool,
) -> Result<PermissionsState, DynError> {
    let content = fs::read_to_string(path).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            Box::new(io::Error::new(
                io::ErrorKind::NotFound,
                "permissions file does not exist",
            )) as DynError
        } else {
            Box::new(err) as DynError
        }
    })?;
    verify_permissions(path, &content)?;
    let permissions_file: PermissionsFile = serde_json::from_str(&content).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("permissions file must be valid JSON: {err}"),
        )) as DynError
    })?;

    validate_permissions_file(permissions_file, is_loaded_kid)
}

pub fn permissions_signature_path(path: &Path, configured_path: &Path) -> PathBuf {
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

pub fn canonical_permissions_json(content: &str) -> Result<String, DynError> {
    let permissions_file: PermissionsFile = serde_json::from_str(content).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("permissions file must be valid JSON: {err}"),
        )) as DynError
    })?;
    protocol::validate_protocol_version("permissions.version", &permissions_file.version)?;

    Ok(String::from_utf8(canonical::canonical_json_v1(&permissions_file)?)?)
}

fn validate_permissions_file(
    permissions_file: PermissionsFile,
    is_loaded_kid: impl Fn(&str) -> bool,
) -> Result<PermissionsState, DynError> {
    protocol::validate_protocol_version("permissions.version", &permissions_file.version)?;

    let mut seen_clients = HashSet::new();
    let mut seen_hashes = HashSet::new();
    let mut clients = Vec::new();

    for client in permissions_file.clients {
        validation::validate_text_field("permissions.client", &client.client)?;
        validation::validate_symmetric_key("permissions.apikey_hash", &client.apikey_hash, 32)?;
        validation::validate_allowed_value(
            "permissions.status",
            &client.status,
            &["active", "disabled", "revoked"],
        )?;

        if !seen_clients.insert(client.client.clone()) {
            return invalid_permissions(format!(
                "permissions file has duplicated client: {}",
                client.client
            ));
        }
        if !seen_hashes.insert(client.apikey_hash.clone()) {
            return invalid_permissions("permissions file has duplicated apikey_hash");
        }

        if client.status != "active" {
            continue;
        }

        let has_admin = client
            .permissions
            .iter()
            .any(|permission| permission.actions.iter().any(|action| action == "admin"));

        if has_admin {
            validate_actions(&client.permissions)?;
            warn!(
                client = %client.client,
                "admin permission detected; kid-scoped permissions for this client are ignored"
            );
            clients.push(PermissionClient {
                client: client.client,
                apikey_hash: client.apikey_hash,
                admin: true,
                permissions: Vec::new(),
            });
            continue;
        }

        let mut seen_kids = HashSet::new();
        let mut permissions = Vec::new();
        for permission in client.permissions {
            if !seen_kids.insert(permission.kid.clone()) {
                return invalid_permissions(format!(
                    "permissions file has duplicated kid for client {}: {}",
                    client.client, permission.kid
                ));
            }

            let actions = validate_action_list(permission.actions)?;
            if permission.kid == "*" {
                validate_global_actions(&actions)?;
            } else {
                keys::validate_key_id(&permission.kid).map_err(|err| {
                    Box::new(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("permissions.kid is invalid: {err}"),
                    )) as DynError
                })?;
                if !is_loaded_kid(&permission.kid) {
                    return invalid_permissions(format!(
                        "permissions file references kid not loaded in memory: {}",
                        permission.kid
                    ));
                }
            }
            permissions.push(KidPermission {
                kid: permission.kid,
                actions,
            });
        }

        clients.push(PermissionClient {
            client: client.client,
            apikey_hash: client.apikey_hash,
            admin: false,
            permissions,
        });
    }

    Ok(PermissionsState::from_clients(clients))
}

fn validate_actions(permissions: &[KidPermissionInput]) -> Result<(), DynError> {
    for permission in permissions {
        let _ = validate_action_list(permission.actions.clone())?;
    }

    Ok(())
}

fn validate_action_list(actions: Vec<String>) -> Result<Vec<String>, DynError> {
    if actions.is_empty() {
        return invalid_permissions("permissions.actions must not be empty");
    }

    let mut seen = HashSet::new();
    let mut validated = Vec::with_capacity(actions.len());
    for action in actions {
        validation::validate_allowed_value("permissions.actions", &action, PERMISSION_ACTIONS)?;
        if !seen.insert(action.clone()) {
            return invalid_permissions(format!("duplicated permission action: {action}"));
        }
        validated.push(action);
    }

    Ok(validated)
}

fn validate_global_actions(actions: &[String]) -> Result<(), DynError> {
    for action in actions {
        if !is_global_permission_action(action) {
            return invalid_permissions(format!(
                "permission action {action} cannot use wildcard kid"
            ));
        }
    }

    Ok(())
}

fn is_global_permission_action(action: &str) -> bool {
    GLOBAL_PERMISSION_ACTIONS.contains(&action)
}

fn permission_denied(message: &str) -> Result<(), DynError> {
    Err(Box::new(io::Error::new(
        io::ErrorKind::PermissionDenied,
        message,
    )))
}

fn invalid_permissions<T>(message: impl Into<String>) -> Result<T, DynError> {
    Err(Box::new(io::Error::new(
        io::ErrorKind::InvalidInput,
        message.into(),
    )))
}

fn is_not_found_error(err: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    err.downcast_ref::<io::Error>()
        .is_some_and(|err| err.kind() == io::ErrorKind::NotFound)
}
