use crate::core::{config, validation};
use crate::error::DynError;
use crate::ops::keys;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;
use tracing::{info, warn};

#[derive(Clone)]
pub struct FinalAppRoute {
    kid: String,
    final_app_addr: String,
    final_app_path: String,
}

pub struct RoutesState {
    default_addr: String,
    default_path: String,
    routes: Vec<FinalAppRoute>,
}

#[derive(Deserialize)]
struct RoutesFile {
    routes: Vec<RouteInput>,
}

#[derive(Deserialize)]
struct RouteInput {
    kid: String,
    final_app_addr: String,
    final_app_path: String,
}

impl RoutesState {
    pub fn route_for(&self, kid: &str) -> FinalAppRoute {
        self.routes
            .iter()
            .find(|route| route.kid == kid)
            .cloned()
            .unwrap_or_else(|| FinalAppRoute {
                kid: kid.to_string(),
                final_app_addr: self.default_addr.clone(),
                final_app_path: self.default_path.clone(),
            })
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }
}

impl FinalAppRoute {
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn final_app_addr(&self) -> &str {
        &self.final_app_addr
    }

    pub fn final_app_path(&self) -> &str {
        &self.final_app_path
    }
}

pub fn load_routes_state(config: &config::AppConfig) -> RoutesState {
    match load_routes_file(&config.routes_path) {
        Ok(routes) => {
            info!(
                routes_path = %config.routes_path.display(),
                routes_loaded = routes.len(),
                "final app routes loaded"
            );
            RoutesState {
                default_addr: config.final_app_addr.clone(),
                default_path: config.final_app_path.clone(),
                routes,
            }
        }
        Err(err) => {
            warn!(
                routes_path = %config.routes_path.display(),
                error = %err,
                final_app_addr = %config.final_app_addr,
                final_app_path = %config.final_app_path,
                "final app routes unavailable, using default route"
            );
            RoutesState {
                default_addr: config.final_app_addr.clone(),
                default_path: config.final_app_path.clone(),
                routes: Vec::new(),
            }
        }
    }
}

fn load_routes_file(path: &Path) -> Result<Vec<FinalAppRoute>, DynError> {
    let content = fs::read_to_string(path).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            Box::new(io::Error::new(
                io::ErrorKind::NotFound,
                "routes file does not exist",
            )) as DynError
        } else {
            Box::new(err) as DynError
        }
    })?;
    let routes_file: RoutesFile = serde_json::from_str(&content).map_err(|err| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("routes file must be valid JSON: {err}"),
        )) as DynError
    })?;

    validate_routes(routes_file.routes)
}

fn validate_routes(routes: Vec<RouteInput>) -> Result<Vec<FinalAppRoute>, DynError> {
    let mut seen = HashSet::new();
    let mut validated = Vec::with_capacity(routes.len());

    for route in routes {
        keys::KeyId::parse(&route.kid)?;
        if !seen.insert(route.kid.clone()) {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("routes file has duplicated kid: {}", route.kid),
            )));
        }

        let final_app_addr =
            validation::validate_host_port("routes.final_app_addr", &route.final_app_addr)?;
        let final_app_path =
            config::validate_http_path_field("routes.final_app_path", &route.final_app_path)?;

        validated.push(FinalAppRoute {
            kid: route.kid,
            final_app_addr,
            final_app_path,
        });
    }

    Ok(validated)
}
