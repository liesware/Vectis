use crate::core::{crypto, validation};
use crate::error::DynError;
use crate::ops::keys;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

const REMOTE_ROUTE_ML_KEM_SHARED_KEY_SIZE_BYTES: usize = 32;

#[derive(Clone, Serialize)]
pub struct RemoteRoute {
    remote_kid: String,
    name: String,
    remote_addr: String,
    allowed_local_kids: Vec<String>,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_keys: Option<PeerPublicKeys>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PeerPublicKeys {
    pub eddsa: PeerDerKey,
    pub xecdh: PeerRawKey,
    #[serde(rename = "ml-dsa")]
    pub ml_dsa: PeerDerKey,
    #[serde(rename = "ml-kem")]
    pub ml_kem: PeerDerKey,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PeerDerKey {
    pub alg: String,
    pub public_key_der_hex: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PeerRawKey {
    pub alg: String,
    pub public_key_hex: String,
}

#[derive(Serialize)]
pub struct ListRemoteRoutesOutput {
    routes: Vec<RemoteRoute>,
}

impl ListRemoteRoutesOutput {
    pub fn routes_len(&self) -> usize {
        self.routes.len()
    }
}

#[derive(Default)]
pub struct RemoteRoutesState {
    routes: Vec<RemoteRoute>,
    by_remote_kid: HashMap<String, usize>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct RemoteRouteInput {
    remote_kid: String,
    name: String,
    remote_addr: String,
    allowed_local_kids: Vec<String>,
    status: String,
    #[serde(default)]
    public_keys: Option<PeerPublicKeys>,
}

impl RemoteRoutesState {
    pub(crate) fn from_routes(routes: Vec<RemoteRoute>) -> Self {
        let by_remote_kid = routes
            .iter()
            .enumerate()
            .map(|(index, route)| (route.remote_kid.clone(), index))
            .collect();

        Self {
            routes,
            by_remote_kid,
        }
    }

    pub fn route_for(
        &self,
        sender_kid: &str,
        recipient_kid: &str,
    ) -> Result<RemoteRoute, DynError> {
        let route = self
            .by_remote_kid
            .get(recipient_kid)
            .and_then(|index| self.routes.get(*index))
            .cloned()
            .ok_or_else(|| crate::error::not_found("recipient route not found"))?;

        if route.status != "active" {
            return Err(crate::error::forbidden("recipient route is disabled"));
        }

        if !route.allows_local_kid(sender_kid) {
            return Err(crate::error::forbidden(
                "sender kid is not allowed for recipient route",
            ));
        }

        Ok(route)
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub fn public_keys_for(&self, kid: &str) -> Option<&PeerPublicKeys> {
        self.by_remote_kid
            .get(kid)
            .and_then(|index| self.routes.get(*index))
            .filter(|route| route.status == "active")
            .and_then(|route| route.public_keys.as_ref())
    }

    pub fn list(&self) -> ListRemoteRoutesOutput {
        ListRemoteRoutesOutput {
            routes: self.routes.clone(),
        }
    }
}

impl RemoteRoute {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn remote_addr(&self) -> &str {
        &self.remote_addr
    }

    pub fn public_keys(&self) -> Option<&PeerPublicKeys> {
        self.public_keys.as_ref()
    }

    fn allows_local_kid(&self, sender_kid: &str) -> bool {
        self.allowed_local_kids
            .iter()
            .any(|allowed_kid| allowed_kid == "*" || allowed_kid == sender_kid)
    }
}

pub(crate) fn validate_remote_routes(
    routes: Vec<RemoteRouteInput>,
    local_kid_exists: impl Fn(&str) -> bool,
) -> Result<Vec<RemoteRoute>, DynError> {
    let mut seen = HashSet::new();
    let mut validated = Vec::with_capacity(routes.len());

    for route in routes {
        keys::KeyId::parse(&route.remote_kid).map_err(|err| {
            crate::error::invalid_input(format!("remote_routes.remote_kid is invalid: {err}"))
        })?;

        if !seen.insert(route.remote_kid.clone()) {
            return Err(crate::error::invalid_input(format!(
                "remote routes file has duplicated remote_kid: {}",
                route.remote_kid
            )));
        }

        validation::validate_text_field("remote_routes.name", &route.name)?;
        let remote_addr =
            validation::validate_host_port("remote_routes.remote_addr", &route.remote_addr)?;
        validation::validate_allowed_value(
            "remote_routes.status",
            &route.status,
            &["active", "disabled"],
        )?;
        validate_allowed_local_kids(&route.allowed_local_kids, &local_kid_exists)?;
        if let Some(public_keys) = &route.public_keys {
            validate_peer_public_keys(public_keys)?;
        }

        validated.push(RemoteRoute {
            remote_kid: route.remote_kid,
            name: route.name,
            remote_addr,
            allowed_local_kids: route.allowed_local_kids,
            status: route.status,
            public_keys: route.public_keys,
        });
    }

    Ok(validated)
}

fn validate_peer_public_keys(keys: &PeerPublicKeys) -> Result<(), DynError> {
    validation::validate_allowed_value(
        "remote_routes.public_keys.eddsa.alg",
        &keys.eddsa.alg,
        &["Ed25519", "Ed448"],
    )?;
    validation::validate_hex_field(
        "remote_routes.public_keys.eddsa.public_key_der_hex",
        &keys.eddsa.public_key_der_hex,
    )?;
    crypto::validate_der_public_key_hex(
        "remote_routes.public_keys.eddsa.public_key_der_hex",
        &keys.eddsa.public_key_der_hex,
    )?;
    validation::validate_allowed_value(
        "remote_routes.public_keys.xecdh.alg",
        &keys.xecdh.alg,
        &["X25519", "X448"],
    )?;
    validation::validate_hex_field(
        "remote_routes.public_keys.xecdh.public_key_hex",
        &keys.xecdh.public_key_hex,
    )?;
    crypto::validate_x_key_agreement_public_key_hex(
        "remote_routes.public_keys.xecdh.public_key_hex",
        &keys.xecdh.alg,
        &keys.xecdh.public_key_hex,
    )?;
    validation::validate_allowed_value(
        "remote_routes.public_keys.ml-dsa.alg",
        &keys.ml_dsa.alg,
        &["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
    )?;
    validation::validate_hex_field(
        "remote_routes.public_keys.ml-dsa.public_key_der_hex",
        &keys.ml_dsa.public_key_der_hex,
    )?;
    crypto::validate_der_public_key_hex(
        "remote_routes.public_keys.ml-dsa.public_key_der_hex",
        &keys.ml_dsa.public_key_der_hex,
    )?;
    validation::validate_allowed_value(
        "remote_routes.public_keys.ml-kem.alg",
        &keys.ml_kem.alg,
        &["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
    )?;
    validation::validate_hex_field(
        "remote_routes.public_keys.ml-kem.public_key_der_hex",
        &keys.ml_kem.public_key_der_hex,
    )?;
    crypto::validate_ml_kem_public_key_hex(
        "remote_routes.public_keys.ml-kem.public_key_der_hex",
        &keys.ml_kem.public_key_der_hex,
        REMOTE_ROUTE_ML_KEM_SHARED_KEY_SIZE_BYTES,
    )?;

    Ok(())
}

fn validate_allowed_local_kids(
    allowed_local_kids: &[String],
    local_kid_exists: impl Fn(&str) -> bool,
) -> Result<(), DynError> {
    if allowed_local_kids.is_empty() {
        return Err(crate::error::invalid_input(
            "remote_routes.allowed_local_kids must not be empty",
        ));
    }

    let has_wildcard = allowed_local_kids.iter().any(|kid| kid == "*");
    if has_wildcard && allowed_local_kids.len() > 1 {
        return Err(crate::error::invalid_input(
            "remote_routes.allowed_local_kids wildcard cannot be mixed with explicit kids",
        ));
    }
    if has_wildcard {
        return Ok(());
    }

    let mut seen = HashSet::new();
    for kid in allowed_local_kids {
        keys::KeyId::parse(kid).map_err(|err| {
            crate::error::invalid_input(format!(
                "remote_routes.allowed_local_kids contains invalid kid: {err}"
            ))
        })?;

        if !seen.insert(kid.clone()) {
            return Err(crate::error::invalid_input(format!(
                "remote_routes.allowed_local_kids has duplicated kid: {kid}"
            )));
        }

        if !local_kid_exists(kid) {
            return Err(crate::error::invalid_input(format!(
                "remote_routes.allowed_local_kids contains unloaded kid: {kid}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::key_material::{KeyMaterialSpec, create_key_material};
    use proptest::prelude::*;
    use serde_json::json;
    use std::sync::OnceLock;

    fn kid(seed: char) -> String {
        String::from(seed).repeat(64)
    }

    fn valid_public_keys() -> serde_json::Value {
        static PUBLIC_KEYS: OnceLock<serde_json::Value> = OnceLock::new();

        PUBLIC_KEYS
            .get_or_init(|| {
                let material = create_key_material(&KeyMaterialSpec {
                    hash_algorithm: String::from("BLAKE2b(256)"),
                    symmetric_algorithm: String::from("AES-256/GCM"),
                    eddsa_algorithm: String::from("Ed25519"),
                    xecdh_algorithm: String::from("X25519"),
                    ml_dsa_variant: String::from("ML-DSA-44"),
                    ml_kem_variant: String::from("ML-KEM-512"),
                })
                .unwrap();

                json!({
                    "eddsa": {
                        "alg": material.keys().eddsa().variant(),
                        "public_key_der_hex": material.keys().eddsa().public_key_der_hex()
                    },
                    "xecdh": {
                        "alg": material.keys().xecdh().variant(),
                        "public_key_hex": material.keys().xecdh().public_key_hex()
                    },
                    "ml-dsa": {
                        "alg": material.keys().ml_dsa().variant(),
                        "public_key_der_hex": material.keys().ml_dsa().public_key_der_hex()
                    },
                    "ml-kem": {
                        "alg": material.keys().ml_kem().variant(),
                        "public_key_der_hex": material.keys().ml_kem().public_key_der_hex()
                    }
                })
            })
            .clone()
    }

    fn route_input(
        remote_kid: &str,
        status: &str,
        public_keys: Option<serde_json::Value>,
    ) -> RemoteRouteInput {
        let mut value = json!({
            "remote_kid": remote_kid,
            "name": "peer",
            "remote_addr": "127.0.0.1:3002",
            "allowed_local_kids": ["*"],
            "status": status
        });
        if let Some(keys) = public_keys {
            value
                .as_object_mut()
                .unwrap()
                .insert(String::from("public_keys"), keys);
        }
        serde_json::from_value(value).unwrap()
    }

    fn state_with(
        remote_kid: &str,
        status: &str,
        public_keys: Option<serde_json::Value>,
    ) -> RemoteRoutesState {
        let validated =
            validate_remote_routes(vec![route_input(remote_kid, status, public_keys)], |_| true)
                .unwrap();
        RemoteRoutesState::from_routes(validated)
    }

    #[test]
    fn accepts_routes_with_and_without_public_keys() {
        let routes = vec![
            route_input(&kid('a'), "active", Some(valid_public_keys())),
            route_input(&kid('b'), "disabled", None),
        ];
        assert_eq!(validate_remote_routes(routes, |_| true).unwrap().len(), 2);
    }

    #[test]
    fn rejects_duplicate_remote_kid() {
        let routes = vec![
            route_input(&kid('a'), "active", None),
            route_input(&kid('a'), "active", None),
        ];
        assert!(validate_remote_routes(routes, |_| true).is_err());
    }

    #[test]
    fn rejects_invalid_status() {
        let routes = vec![route_input(&kid('a'), "paused", None)];
        assert!(validate_remote_routes(routes, |_| true).is_err());
    }

    #[test]
    fn rejects_invalid_public_key_alg() {
        let mut keys = valid_public_keys();
        keys["eddsa"]["alg"] = json!("RSA");
        let routes = vec![route_input(&kid('a'), "active", Some(keys))];
        assert!(validate_remote_routes(routes, |_| true).is_err());
    }

    #[test]
    fn rejects_invalid_public_key_hex() {
        let mut keys = valid_public_keys();
        keys["xecdh"]["public_key_hex"] = json!("zz");
        let routes = vec![route_input(&kid('a'), "active", Some(keys))];
        assert!(validate_remote_routes(routes, |_| true).is_err());
    }

    #[test]
    fn rejects_invalid_eddsa_public_key_der() {
        let mut keys = valid_public_keys();
        keys["eddsa"]["public_key_der_hex"] = json!("aa");
        let routes = vec![route_input(&kid('a'), "active", Some(keys))];
        assert!(validate_remote_routes(routes, |_| true).is_err());
    }

    #[test]
    fn rejects_invalid_ml_dsa_public_key_der() {
        let mut keys = valid_public_keys();
        keys["ml-dsa"]["public_key_der_hex"] = json!("aa");
        let routes = vec![route_input(&kid('a'), "active", Some(keys))];
        assert!(validate_remote_routes(routes, |_| true).is_err());
    }

    #[test]
    fn rejects_invalid_ml_kem_public_key_der() {
        let mut keys = valid_public_keys();
        keys["ml-kem"]["public_key_der_hex"] = json!("aa");
        let routes = vec![route_input(&kid('a'), "active", Some(keys))];
        assert!(validate_remote_routes(routes, |_| true).is_err());
    }

    #[test]
    fn rejects_wrong_x25519_public_key_size() {
        let mut keys = valid_public_keys();
        keys["xecdh"]["public_key_hex"] = json!("aa");
        let routes = vec![route_input(&kid('a'), "active", Some(keys))];
        assert!(validate_remote_routes(routes, |_| true).is_err());
    }

    #[test]
    fn rejects_wrong_x448_public_key_size() {
        let mut keys = valid_public_keys();
        keys["xecdh"]["alg"] = json!("X448");
        keys["xecdh"]["public_key_hex"] = json!("aa");
        let routes = vec![route_input(&kid('a'), "active", Some(keys))];
        assert!(validate_remote_routes(routes, |_| true).is_err());
    }

    #[test]
    fn public_keys_for_active_with_keys_returns_some() {
        let state = state_with(&kid('a'), "active", Some(valid_public_keys()));
        assert!(state.public_keys_for(&kid('a')).is_some());
    }

    #[test]
    fn public_keys_for_disabled_returns_none() {
        let state = state_with(&kid('a'), "disabled", Some(valid_public_keys()));
        assert!(state.public_keys_for(&kid('a')).is_none());
    }

    #[test]
    fn public_keys_for_active_without_keys_returns_none() {
        let state = state_with(&kid('a'), "active", None);
        assert!(state.public_keys_for(&kid('a')).is_none());
    }

    #[test]
    fn public_keys_for_unknown_kid_returns_none() {
        let state = state_with(&kid('a'), "active", Some(valid_public_keys()));
        assert!(state.public_keys_for(&kid('b')).is_none());
    }

    proptest! {
        #[test]
        fn wildcard_allowed_local_kids_allows_any_sender(sender in "[0-9a-f]{64}") {
            let route = RemoteRoute {
                remote_kid: kid('a'),
                name: String::from("peer"),
                remote_addr: String::from("127.0.0.1:3002"),
                allowed_local_kids: vec![String::from("*")],
                status: String::from("active"),
                public_keys: None,
            };

            prop_assert!(route.allows_local_kid(&sender));
        }

        #[test]
        fn explicit_allowed_local_kids_match_only_listed_sender(sender in "[0-9a-f]{64}", other in "[0-9a-f]{64}") {
            prop_assume!(sender != other);
            let route = RemoteRoute {
                remote_kid: kid('a'),
                name: String::from("peer"),
                remote_addr: String::from("127.0.0.1:3002"),
                allowed_local_kids: vec![sender.clone()],
                status: String::from("active"),
                public_keys: None,
            };

            prop_assert!(route.allows_local_kid(&sender));
            prop_assert!(!route.allows_local_kid(&other));
        }

        #[test]
        fn status_accepts_only_active_or_disabled(status in "[A-Za-z0-9_-]{1,32}") {
            let routes = vec![route_input(&kid('a'), &status, None)];
            let result = validate_remote_routes(routes, |_| true);

            prop_assert_eq!(result.is_ok(), matches!(status.as_str(), "active" | "disabled"));
        }

        #[test]
        fn route_for_requires_active_status_and_allowed_sender(
            sender in "[0-9a-f]{64}",
            other_sender in "[0-9a-f]{64}",
            remote_kid in "[0-9a-f]{64}",
            status in prop::sample::select(&["active", "disabled"])
        ) {
            prop_assume!(sender != other_sender);
            let route = RemoteRoute {
                remote_kid: remote_kid.clone(),
                name: String::from("peer"),
                remote_addr: String::from("127.0.0.1:3002"),
                allowed_local_kids: vec![sender.clone()],
                status: status.to_string(),
                public_keys: None,
            };
            let state = RemoteRoutesState::from_routes(vec![route]);

            prop_assert_eq!(
                state.route_for(&sender, &remote_kid).is_ok(),
                status == "active"
            );
            prop_assert!(state.route_for(&other_sender, &remote_kid).is_err());
            prop_assert!(state.route_for(&sender, &kid('f')).is_err());
        }

        #[test]
        fn validate_allowed_local_kids_requires_loaded_explicit_kids(
            sender in "[0-9a-f]{64}",
            loaded in any::<bool>()
        ) {
            let route: RemoteRouteInput = serde_json::from_value(json!({
                "remote_kid": kid('a'),
                "name": "peer",
                "remote_addr": "127.0.0.1:3002",
                "allowed_local_kids": [sender],
                "status": "active"
            }))
            .unwrap();

            let result = validate_remote_routes(vec![route], |kid| loaded && kid == sender);

            prop_assert_eq!(result.is_ok(), loaded);
        }
    }

    #[test]
    fn rejects_wildcard_mixed_with_explicit_kids() {
        let mut value = json!({
            "remote_kid": kid('a'),
            "name": "peer",
            "remote_addr": "127.0.0.1:3002",
            "allowed_local_kids": ["*", kid('b')],
            "status": "active"
        });
        let route: RemoteRouteInput = serde_json::from_value(value.take()).unwrap();

        assert!(validate_remote_routes(vec![route], |_| true).is_err());
    }

    #[test]
    fn rejects_duplicated_allowed_local_kids() {
        let explicit_kid = kid('b');
        let mut value = json!({
            "remote_kid": kid('a'),
            "name": "peer",
            "remote_addr": "127.0.0.1:3002",
            "allowed_local_kids": [explicit_kid, explicit_kid],
            "status": "active"
        });
        let route: RemoteRouteInput = serde_json::from_value(value.take()).unwrap();

        assert!(validate_remote_routes(vec![route], |_| true).is_err());
    }

    #[test]
    fn remote_route_index_matches_linear_lookup() {
        let first = RemoteRoute {
            remote_kid: kid('a'),
            name: String::from("a"),
            remote_addr: String::from("127.0.0.1:3001"),
            allowed_local_kids: vec![String::from("*")],
            status: String::from("active"),
            public_keys: None,
        };
        let second = RemoteRoute {
            remote_kid: kid('b'),
            name: String::from("b"),
            remote_addr: String::from("127.0.0.1:3002"),
            allowed_local_kids: vec![String::from("*")],
            status: String::from("active"),
            public_keys: None,
        };
        let routes = vec![first, second];
        let state = RemoteRoutesState::from_routes(routes.clone());

        for (index, route) in routes.iter().enumerate() {
            assert_eq!(state.by_remote_kid.get(&route.remote_kid), Some(&index));
            assert_eq!(
                state
                    .route_for(&kid('c'), &route.remote_kid)
                    .unwrap()
                    .remote_addr(),
                route.remote_addr
            );
        }
    }
}
