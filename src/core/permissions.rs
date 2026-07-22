use crate::core::{crypto, validation};
use crate::error::DynError;
use crate::ops::keys;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::warn;
use zeroize::Zeroize;

pub const PERMISSION_ACTIONS: &[&str] = &[
    "admin",
    "keys",
    "lifecycle",
    "self-test",
    "sign",
    "message",
    "fpe-encrypt",
    "fpe-decrypt",
    "token-encode",
    "token-decode",
    "mac-create",
    "mac-verify",
    "index-create",
    "index-verify",
    "mask",
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

#[derive(Serialize)]
pub struct ListPermissionsOutput {
    clients: Vec<PermissionClientOutput>,
}

#[derive(Serialize)]
struct PermissionClientOutput {
    client: String,
    admin: bool,
    permissions: Vec<KidPermissionOutput>,
}

#[derive(Serialize)]
struct KidPermissionOutput {
    kid: String,
    actions: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PermissionClientInput {
    client: String,
    apikey_hash: String,
    status: String,
    permissions: Vec<KidPermissionInput>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    pub fn list(&self) -> ListPermissionsOutput {
        ListPermissionsOutput {
            clients: self
                .clients
                .iter()
                .map(PermissionClientOutput::from_permission_client)
                .collect(),
        }
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
}

impl PermissionClientOutput {
    fn from_permission_client(client: &PermissionClient) -> Self {
        let permissions = if client.admin {
            vec![KidPermissionOutput {
                kid: String::from("*"),
                actions: vec![String::from("admin")],
            }]
        } else {
            client
                .permissions
                .iter()
                .map(|permission| KidPermissionOutput {
                    kid: permission.kid.clone(),
                    actions: permission.actions.clone(),
                })
                .collect()
        };

        Self {
            client: client.client.clone(),
            admin: client.admin,
            permissions,
        }
    }
}

impl ListPermissionsOutput {
    pub fn clients_len(&self) -> usize {
        self.clients.len()
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

pub(crate) fn validate_permission_clients(
    client_inputs: Vec<PermissionClientInput>,
    is_loaded_kid: impl Fn(&str) -> bool,
) -> Result<PermissionsState, DynError> {
    let mut seen_clients = HashSet::new();
    let mut seen_hashes = HashSet::new();
    let mut clients = Vec::new();

    for client in client_inputs {
        validation::validate_config_name("permissions.client", &client.client)?;
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
                    crate::error::invalid_input(format!("permissions.kid is invalid: {err}"))
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
    Err(crate::error::forbidden(message))
}

fn invalid_permissions<T>(message: impl Into<String>) -> Result<T, DynError> {
    Err(crate::error::invalid_input(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn hex64(seed: char) -> String {
        String::from(seed).repeat(64)
    }

    fn client(
        name: &str,
        apikey_hash: &str,
        status: &str,
        permissions: serde_json::Value,
    ) -> PermissionClientInput {
        serde_json::from_value(json!({
            "client": name,
            "apikey_hash": apikey_hash,
            "status": status,
            "permissions": permissions
        }))
        .unwrap()
    }

    #[test]
    fn accepts_active_client_with_loaded_kid() {
        let clients = vec![client(
            "app",
            &hex64('1'),
            "active",
            json!([{"kid": hex64('a'), "actions": ["message"]}]),
        )];
        let state = validate_permission_clients(clients, |_| true).unwrap();
        assert_eq!(state.len(), 1);
        let authed = state.authenticate_hash(&hex64('1')).unwrap();
        assert!(!authed.is_admin());
    }

    #[test]
    fn accepts_wildcard_kid_with_global_action() {
        let clients = vec![client(
            "m",
            &hex64('2'),
            "active",
            json!([{"kid": "*", "actions": ["metrics"]}]),
        )];
        assert!(validate_permission_clients(clients, |_| true).is_ok());
    }

    #[test]
    fn rejects_wildcard_kid_with_non_global_action() {
        let clients = vec![client(
            "m",
            &hex64('2'),
            "active",
            json!([{"kid": "*", "actions": ["message"]}]),
        )];
        assert!(validate_permission_clients(clients, |_| true).is_err());
    }

    #[test]
    fn accepts_fpe_and_token_actions_only_for_explicit_kid() {
        let clients = vec![client(
            "fpe",
            &hex64('8'),
            "active",
            json!([{"kid": hex64('a'), "actions": ["fpe-encrypt", "fpe-decrypt", "token-encode", "token-decode", "mac-create", "mac-verify", "index-create", "index-verify"]}]),
        )];
        let state = validate_permission_clients(clients, |_| true).unwrap();
        let authed = state.authenticate_hash(&hex64('8')).unwrap();

        assert!(
            state
                .require_permission(&authed, Some(&hex64('a')), "fpe-encrypt")
                .is_ok()
        );
        assert!(
            state
                .require_permission(&authed, Some(&hex64('a')), "fpe-decrypt")
                .is_ok()
        );
        assert!(
            state
                .require_permission(&authed, Some(&hex64('a')), "token-encode")
                .is_ok()
        );
        assert!(
            state
                .require_permission(&authed, Some(&hex64('a')), "token-decode")
                .is_ok()
        );
        assert!(
            state
                .require_permission(&authed, Some(&hex64('a')), "mac-create")
                .is_ok()
        );
        assert!(
            state
                .require_permission(&authed, Some(&hex64('a')), "mac-verify")
                .is_ok()
        );
        assert!(
            state
                .require_permission(&authed, Some(&hex64('a')), "index-create")
                .is_ok()
        );
        assert!(
            state
                .require_permission(&authed, Some(&hex64('a')), "index-verify")
                .is_ok()
        );

        let wildcard = vec![client(
            "token-wildcard",
            &hex64('9'),
            "active",
            json!([{"kid": "*", "actions": ["mac-create"]}]),
        )];
        assert!(validate_permission_clients(wildcard, |_| true).is_err());
    }

    #[test]
    fn admin_becomes_admin_client_without_kid_permissions() {
        let clients = vec![client(
            "root-like",
            &hex64('3'),
            "active",
            json!([{"kid": hex64('a'), "actions": ["admin"]}]),
        )];
        let state = validate_permission_clients(clients, |_| true).unwrap();
        assert!(state.authenticate_hash(&hex64('3')).unwrap().is_admin());
    }

    #[test]
    fn rejects_duplicate_client_name() {
        let clients = vec![
            client("dup", &hex64('4'), "active", json!([])),
            client("dup", &hex64('5'), "active", json!([])),
        ];
        assert!(validate_permission_clients(clients, |_| true).is_err());
    }

    #[test]
    fn client_name_is_limited_to_config_name_max_chars() {
        let max = crate::core::config::CONFIG_NAME_MAX_CHARS;
        let accepted = vec![client(&"a".repeat(max), &hex64('4'), "active", json!([]))];
        assert!(validate_permission_clients(accepted, |_| true).is_ok());

        let rejected = vec![client(
            &"a".repeat(max + 1),
            &hex64('4'),
            "active",
            json!([]),
        )];
        let err = match validate_permission_clients(rejected, |_| true) {
            Ok(_) => panic!("overlong client name must fail validation"),
            Err(err) => err,
        };
        assert_eq!(
            err.to_string(),
            "permissions.client exceeds maximum allowed length: 128"
        );
    }

    #[test]
    fn rejects_duplicate_apikey_hash() {
        let clients = vec![
            client("a", &hex64('6'), "active", json!([])),
            client("b", &hex64('6'), "active", json!([])),
        ];
        assert!(validate_permission_clients(clients, |_| true).is_err());
    }

    #[test]
    fn rejects_wrong_length_apikey_hash() {
        let clients = vec![client("a", "aa", "active", json!([]))];
        assert!(validate_permission_clients(clients, |_| true).is_err());
    }

    #[test]
    fn rejects_invalid_status() {
        let clients = vec![client("a", &hex64('7'), "banned", json!([]))];
        assert!(validate_permission_clients(clients, |_| true).is_err());
    }

    #[test]
    fn rejects_explicit_kid_not_loaded() {
        let clients = vec![client(
            "a",
            &hex64('8'),
            "active",
            json!([{"kid": hex64('a'), "actions": ["message"]}]),
        )];
        assert!(validate_permission_clients(clients, |_| false).is_err());
    }

    #[test]
    fn omits_disabled_and_revoked_clients() {
        let clients = vec![
            client("d", &hex64('1'), "disabled", json!([])),
            client("r", &hex64('2'), "revoked", json!([])),
        ];
        let state = validate_permission_clients(clients, |_| true).unwrap();
        assert_eq!(state.len(), 0);
        assert!(state.authenticate_hash(&hex64('1')).is_none());
    }

    proptest! {
        #[test]
        fn admin_clients_have_effective_global_access(seed in "[0-9a-f]{1}") {
            let hash = seed.repeat(64);
            let clients = vec![client(
                "admin",
                &hash,
                "active",
                json!([{"kid": hex64('a'), "actions": ["admin", "message"]}]),
            )];
            let state = validate_permission_clients(clients, |_| true).unwrap();
            let authed = state.authenticate_hash(&hash).unwrap();

            prop_assert!(authed.is_admin());
            prop_assert!(state.require_permission(&authed, None, "keys").is_ok());
            prop_assert!(state.require_permission(&authed, Some(&hex64('b')), "message").is_ok());
        }

        #[test]
        fn wildcard_kid_only_accepts_global_actions(action in prop::sample::select(PERMISSION_ACTIONS)) {
            let clients = vec![client(
                "app",
                &hex64('1'),
                "active",
                json!([{"kid": "*", "actions": [action]}]),
            )];
            let result = validate_permission_clients(clients, |_| true);

            prop_assert_eq!(result.is_ok(), action == "admin" || is_global_permission_action(action));
        }

        #[test]
        fn invalid_actions_are_rejected(action in "[A-Za-z0-9_-]{1,32}") {
            prop_assume!(!PERMISSION_ACTIONS.contains(&action.as_str()));
            let clients = vec![client(
                "app",
                &hex64('1'),
                "active",
                json!([{"kid": hex64('a'), "actions": [action]}]),
            )];

            prop_assert!(validate_permission_clients(clients, |_| true).is_err());
        }

        #[test]
        fn apikey_hash_must_be_64_hex(hash in "[0-9a-fA-F]{0,80}") {
            prop_assume!(hash.len() != 64);
            let clients = vec![client(
                "app",
                &hash,
                "active",
                json!([{"kid": hex64('a'), "actions": ["message"]}]),
            )];

            prop_assert!(validate_permission_clients(clients, |_| true).is_err());
        }

        #[test]
        fn kid_scoped_permission_requires_matching_kid_and_action(
            allowed_kid in "[0-9a-f]{64}",
            other_kid in "[0-9a-f]{64}",
            action in prop::sample::select(&["keys", "lifecycle", "self-test", "sign", "message"])
        ) {
            prop_assume!(allowed_kid != other_kid);
            let hash = hex64('1');
            let clients = vec![client(
                "app",
                &hash,
                "active",
                json!([{"kid": allowed_kid, "actions": [action]}]),
            )];
            let state = validate_permission_clients(clients, |_| true).unwrap();
            let authed = state.authenticate_hash(&hash).unwrap();

            prop_assert!(state.require_permission(&authed, Some(&allowed_kid), action).is_ok());
            prop_assert!(state.require_permission(&authed, Some(&other_kid), action).is_err());
            prop_assert!(state.require_permission(&authed, None, action).is_err());
        }

        #[test]
        fn metrics_permission_is_global_and_does_not_require_kid(kid in "[0-9a-f]{64}") {
            let hash = hex64('1');
            let clients = vec![client(
                "metrics",
                &hash,
                "active",
                json!([{"kid": "*", "actions": ["metrics"]}]),
            )];
            let state = validate_permission_clients(clients, |_| true).unwrap();
            let authed = state.authenticate_hash(&hash).unwrap();

            prop_assert!(state.require_permission(&authed, None, "metrics").is_ok());
            prop_assert!(state.require_permission(&authed, Some(&kid), "metrics").is_ok());
            prop_assert!(state.require_permission(&authed, Some(&kid), "message").is_err());
        }
    }

    #[test]
    fn permission_hash_index_matches_clients() {
        let clients = vec![
            PermissionClient {
                client: String::from("a"),
                apikey_hash: hex64('1'),
                admin: false,
                permissions: vec![KidPermission {
                    kid: hex64('a'),
                    actions: vec![String::from("message")],
                }],
            },
            PermissionClient {
                client: String::from("b"),
                apikey_hash: hex64('2'),
                admin: false,
                permissions: vec![KidPermission {
                    kid: hex64('b'),
                    actions: vec![String::from("sign")],
                }],
            },
        ];
        let state = PermissionsState::from_clients(clients.clone());

        for (index, client) in clients.iter().enumerate() {
            assert_eq!(state.by_hash.get(&client.apikey_hash), Some(&index));
            assert_eq!(
                state
                    .authenticate_hash(&client.apikey_hash)
                    .unwrap()
                    .client_name(),
                client.client
            );
        }
    }
}
