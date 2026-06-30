use crate::core::validation;
use crate::error::DynError;
use crate::ops::keys;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

#[derive(Clone, Serialize)]
pub struct RemoteRoute {
    kid: String,
    name: String,
    remote_addr: String,
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
}

#[derive(Deserialize, Serialize)]
struct RemoteRoutesFile {
    routes: Vec<RemoteRouteInput>,
}

#[derive(Deserialize, Serialize)]
struct RemoteRouteInput {
    kid: String,
    name: String,
    remote_addr: String,
}

impl RemoteRoutesState {
    pub fn route_for(&self, kid: &str) -> Result<RemoteRoute, DynError> {
        self.routes
            .iter()
            .find(|route| route.kid == kid)
            .cloned()
            .ok_or_else(|| {
                Box::new(io::Error::new(
                    io::ErrorKind::NotFound,
                    "recipient route not found",
                )) as DynError
            })
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
    ) -> Result<RemoteRoutesState, DynError> {
        let routes = match load_remote_routes_file(path, verify_routes) {
            Ok(routes) => routes,
            Err(err) if is_not_found_error(err.as_ref()) => Vec::new(),
            Err(err) => return Err(err),
        };

        Ok(RemoteRoutesState { routes })
    }
}

impl RemoteRoute {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn remote_addr(&self) -> &str {
        &self.remote_addr
    }
}

pub fn load_remote_routes_state(
    path: &Path,
    verify_routes: impl Fn(&Path, &str) -> Result<(), DynError>,
) -> RemoteRoutesState {
    match load_remote_routes_file(path, verify_routes) {
        Ok(routes) => {
            info!(
                remote_routes_path = %path.display(),
                remote_routes_loaded = routes.len(),
                "remote routes loaded"
            );
            RemoteRoutesState { routes }
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

    validate_remote_routes(routes_file.routes)
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

fn validate_remote_routes(routes: Vec<RemoteRouteInput>) -> Result<Vec<RemoteRoute>, DynError> {
    let mut seen = HashSet::new();
    let mut validated = Vec::with_capacity(routes.len());

    for route in routes {
        keys::KeyId::parse(&route.kid).map_err(|err| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("remote_routes.kid is invalid: {err}"),
            )) as DynError
        })?;

        if !seen.insert(route.kid.clone()) {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("remote routes file has duplicated kid: {}", route.kid),
            )));
        }

        validation::validate_text_field("remote_routes.name", &route.name)?;
        let remote_addr =
            validation::validate_host_port("remote_routes.remote_addr", &route.remote_addr)?;

        validated.push(RemoteRoute {
            kid: route.kid,
            name: route.name,
            remote_addr,
        });
    }

    Ok(validated)
}
