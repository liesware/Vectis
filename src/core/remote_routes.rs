use crate::core::validation;
use crate::error::DynError;
use crate::ops::keys;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io;

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
            .ok_or_else(|| {
                Box::new(io::Error::new(
                    io::ErrorKind::NotFound,
                    "recipient route not found",
                )) as DynError
            })?;

        if route.status != "active" {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "recipient route is disabled",
            )));
        }

        if !route.allows_local_kid(sender_kid) {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "sender kid is not allowed for recipient route",
            )));
        }

        Ok(route)
    }

    pub fn len(&self) -> usize {
        self.routes.len()
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
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("remote_routes.remote_kid is invalid: {err}"),
            )) as DynError
        })?;

        if !seen.insert(route.remote_kid.clone()) {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "remote routes file has duplicated remote_kid: {}",
                    route.remote_kid
                ),
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
    validation::validate_allowed_value(
        "remote_routes.public_keys.xecdh.alg",
        &keys.xecdh.alg,
        &["X25519", "X448"],
    )?;
    validation::validate_hex_field(
        "remote_routes.public_keys.xecdh.public_key_hex",
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
    validation::validate_allowed_value(
        "remote_routes.public_keys.ml-kem.alg",
        &keys.ml_kem.alg,
        &["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
    )?;
    validation::validate_hex_field(
        "remote_routes.public_keys.ml-kem.public_key_der_hex",
        &keys.ml_kem.public_key_der_hex,
    )?;

    Ok(())
}

fn validate_allowed_local_kids(
    allowed_local_kids: &[String],
    local_kid_exists: impl Fn(&str) -> bool,
) -> Result<(), DynError> {
    if allowed_local_kids.is_empty() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "remote_routes.allowed_local_kids must not be empty",
        )));
    }

    let has_wildcard = allowed_local_kids.iter().any(|kid| kid == "*");
    if has_wildcard && allowed_local_kids.len() > 1 {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "remote_routes.allowed_local_kids wildcard cannot be mixed with explicit kids",
        )));
    }
    if has_wildcard {
        return Ok(());
    }

    let mut seen = HashSet::new();
    for kid in allowed_local_kids {
        keys::KeyId::parse(kid).map_err(|err| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("remote_routes.allowed_local_kids contains invalid kid: {err}"),
            )) as DynError
        })?;

        if !seen.insert(kid.clone()) {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("remote_routes.allowed_local_kids has duplicated kid: {kid}"),
            )));
        }

        if !local_kid_exists(kid) {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("remote_routes.allowed_local_kids contains unloaded kid: {kid}"),
            )));
        }
    }

    Ok(())
}
