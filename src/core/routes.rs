use crate::core::{config, validation};
use crate::error::DynError;
use crate::ops::keys;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io;

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

#[derive(Deserialize, Serialize)]
pub(crate) struct RouteInput {
    kid: String,
    final_app_addr: String,
    final_app_path: String,
}

impl RoutesState {
    pub(crate) fn from_parts(
        default_addr: String,
        default_path: String,
        routes: Vec<FinalAppRoute>,
    ) -> Self {
        Self {
            default_addr,
            default_path,
            routes,
        }
    }

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

pub(crate) fn validate_routes(
    routes: Vec<RouteInput>,
    is_loaded_kid: impl Fn(&str) -> bool,
) -> Result<Vec<FinalAppRoute>, DynError> {
    let mut seen = HashSet::new();
    let mut validated = Vec::with_capacity(routes.len());

    for route in routes {
        keys::KeyId::parse(&route.kid).map_err(|err| {
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("routes.kid is invalid: {err}"),
            )) as DynError
        })?;
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
