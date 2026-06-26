use crate::core::{config, validation};
use crate::error::DynError;
use crate::ops::keys;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;
use tracing::{info, warn};

#[derive(Clone, Serialize)]
pub struct FinalAppRoute {
    kid: String,
    final_app_addr: String,
    final_app_path: String,
}

#[derive(Serialize)]
pub struct ListRoutesOutput {
    routes: Vec<FinalAppRoute>,
}

impl ListRoutesOutput {
    pub fn routes_len(&self) -> usize {
        self.routes.len()
    }
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

    pub fn list(&self) -> ListRoutesOutput {
        ListRoutesOutput {
            routes: self.routes.clone(),
        }
    }

    pub fn reload_from_file(
        &self,
        path: &Path,
        is_loaded_kid: impl Fn(&str) -> bool,
    ) -> Result<RoutesState, DynError> {
        let routes = match load_routes_file(path, is_loaded_kid) {
            Ok(routes) => routes,
            Err(err) if is_not_found_error(err.as_ref()) => Vec::new(),
            Err(err) => return Err(err),
        };

        Ok(RoutesState {
            default_addr: self.default_addr.clone(),
            default_path: self.default_path.clone(),
            routes,
        })
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

pub fn load_routes_state(
    config: &config::AppConfig,
    is_loaded_kid: impl Fn(&str) -> bool,
) -> RoutesState {
    match load_routes_file(&config.routes_path, is_loaded_kid) {
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

fn load_routes_file(
    path: &Path,
    is_loaded_kid: impl Fn(&str) -> bool,
) -> Result<Vec<FinalAppRoute>, DynError> {
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

    validate_routes(routes_file.routes, is_loaded_kid)
}

fn is_not_found_error(err: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    err.downcast_ref::<io::Error>()
        .is_some_and(|err| err.kind() == io::ErrorKind::NotFound)
}

fn validate_routes(
    routes: Vec<RouteInput>,
    is_loaded_kid: impl Fn(&str) -> bool,
) -> Result<Vec<FinalAppRoute>, DynError> {
    let mut seen = HashSet::new();
    let mut validated = Vec::with_capacity(routes.len());

    for route in routes {
        keys::KeyId::parse(&route.kid)?;
        if !is_loaded_kid(&route.kid) {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "routes file references kid not loaded in memory: {}",
                    route.kid
                ),
            )));
        }

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
