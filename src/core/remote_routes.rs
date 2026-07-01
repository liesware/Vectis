use crate::core::validation;
use crate::error::DynError;
use crate::ops::keys;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

#[derive(Clone, Serialize)]
pub struct RemoteRoute {
    remote_kid: String,
    name: String,
    remote_addr: String,
    allowed_local_kids: Vec<String>,
    status: String,
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
struct RemoteRoutesFile {
    routes: Vec<RemoteRouteInput>,
}

#[derive(Deserialize, Serialize)]
struct RemoteRouteInput {
    remote_kid: String,
    name: String,
    remote_addr: String,
    allowed_local_kids: Vec<String>,
    status: String,
}

impl RemoteRoutesState {
    fn from_routes(routes: Vec<RemoteRoute>) -> Self {
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

    pub fn list(&self) -> ListRemoteRoutesOutput {
        ListRemoteRoutesOutput {
            routes: self.routes.clone(),
        }
    }

    pub fn reload_from_file(
        &self,
        path: &Path,
        verify_routes: impl Fn(&Path, &str) -> Result<(), DynError>,
        local_kid_exists: impl Fn(&str) -> bool,
    ) -> Result<RemoteRoutesState, DynError> {
        let routes = match load_remote_routes_file(path, verify_routes, local_kid_exists) {
            Ok(routes) => routes,
            Err(err) if is_not_found_error(err.as_ref()) => Vec::new(),
            Err(err) => return Err(err),
        };

        Ok(RemoteRoutesState::from_routes(routes))
    }
}

impl RemoteRoute {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn remote_addr(&self) -> &str {
        &self.remote_addr
    }

    fn allows_local_kid(&self, sender_kid: &str) -> bool {
        self.allowed_local_kids
            .iter()
            .any(|allowed_kid| allowed_kid == "*" || allowed_kid == sender_kid)
    }
}

pub fn load_remote_routes_state(
    path: &Path,
    verify_routes: impl Fn(&Path, &str) -> Result<(), DynError>,
    local_kid_exists: impl Fn(&str) -> bool,
) -> RemoteRoutesState {
    match load_remote_routes_file(path, verify_routes, local_kid_exists) {
        Ok(routes) => {
            info!(
                remote_routes_path = %path.display(),
                remote_routes_loaded = routes.len(),
                "remote routes loaded"
            );
            RemoteRoutesState::from_routes(routes)
        }
        Err(err) => {
            warn!(
                remote_routes_path = %path.display(),
                error = %err,
                "remote routes unavailable, using empty remote route list"
            );
            RemoteRoutesState::default()
        }
    }
}

fn load_remote_routes_file(
    path: &Path,
    verify_routes: impl Fn(&Path, &str) -> Result<(), DynError>,
    local_kid_exists: impl Fn(&str) -> bool,
) -> Result<Vec<RemoteRoute>, DynError> {
    let content = fs::read_to_string(path).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            Box::new(io::Error::new(
                io::ErrorKind::NotFound,
                "remote routes file does not exist",
            )) as DynError
        } else {
            Box::new(err) as DynError
        }
    })?;
    verify_routes(path, &content)?;
    let routes_file: RemoteRoutesFile = serde_json::from_str(&content).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("remote routes file must be valid JSON: {err}"),
        )) as DynError
    })?;

    validate_remote_routes(routes_file.routes, local_kid_exists)
}

pub fn remote_routes_signature_path(path: &Path, configured_path: &Path) -> PathBuf {
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

pub fn canonical_remote_routes_json(content: &str) -> Result<String, DynError> {
    let routes_file: RemoteRoutesFile = serde_json::from_str(content).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("remote routes file must be valid JSON: {err}"),
        )) as DynError
    })?;

    Ok(serde_json::to_string(&routes_file)?)
}

fn is_not_found_error(err: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    err.downcast_ref::<io::Error>()
        .is_some_and(|err| err.kind() == io::ErrorKind::NotFound)
}

fn validate_remote_routes(
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

        validated.push(RemoteRoute {
            remote_kid: route.remote_kid,
            name: route.name,
            remote_addr,
            allowed_local_kids: route.allowed_local_kids,
            status: route.status,
        });
    }

    Ok(validated)
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
