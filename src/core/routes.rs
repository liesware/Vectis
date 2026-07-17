use crate::core::{config, validation};
use crate::error::DynError;
use crate::ops::keys;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Serialize)]
pub struct FinalAppRoute {
    kid: String,
    name: String,
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
    name: String,
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
                name: String::from("default-final-app"),
                final_app_addr: self.default_addr.clone(),
                final_app_path: self.default_path.clone(),
            })
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
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

    pub fn name(&self) -> &str {
        &self.name
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
    let mut seen_kids = HashSet::new();
    let mut seen_names = HashSet::new();
    let mut validated = Vec::with_capacity(routes.len());

    for route in routes {
        keys::KeyId::parse(&route.kid)
            .map_err(|err| crate::error::invalid_input(format!("routes.kid is invalid: {err}")))?;
        if !is_loaded_kid(&route.kid) {
            return Err(crate::error::invalid_input(format!(
                "routes file references kid not loaded in memory: {}",
                route.kid
            )));
        }

        if !seen_kids.insert(route.kid.clone()) {
            return Err(crate::error::invalid_input(format!(
                "routes file has duplicated kid: {}",
                route.kid
            )));
        }

        validation::validate_config_name("routes.name", &route.name)?;
        if !seen_names.insert(route.name.clone()) {
            return Err(crate::error::invalid_input(format!(
                "routes file has duplicated name: {}",
                route.name
            )));
        }
        let final_app_addr =
            validation::validate_host_port("routes.final_app_addr", &route.final_app_addr)?;
        let final_app_path =
            config::validate_http_path_field("routes.final_app_path", &route.final_app_path)?;

        validated.push(FinalAppRoute {
            kid: route.kid,
            name: route.name,
            final_app_addr,
            final_app_path,
        });
    }

    Ok(validated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn kid(seed: char) -> String {
        String::from(seed).repeat(64)
    }

    fn route_input(kid: &str, final_app_addr: &str) -> RouteInput {
        route_input_with_path(kid, final_app_addr, "/message")
    }

    fn route_input_with_path(kid: &str, final_app_addr: &str, final_app_path: &str) -> RouteInput {
        serde_json::from_value(json!({
            "kid": kid,
            "name": "final-app",
            "final_app_addr": final_app_addr,
            "final_app_path": final_app_path
        }))
        .unwrap()
    }

    fn route_input_with_name(kid: &str, name: &str) -> RouteInput {
        serde_json::from_value(json!({
            "kid": kid,
            "name": name,
            "final_app_addr": "localhost:3999",
            "final_app_path": "/message"
        }))
        .unwrap()
    }

    #[test]
    fn accepts_valid_route_for_loaded_kid() {
        let routes = vec![route_input(&kid('a'), "127.0.0.1:3999")];
        assert_eq!(validate_routes(routes, |_| true).unwrap().len(), 1);
    }

    #[test]
    fn rejects_unloaded_kid() {
        let routes = vec![route_input(&kid('a'), "127.0.0.1:3999")];
        assert!(validate_routes(routes, |_| false).is_err());
    }

    #[test]
    fn rejects_invalid_final_app_addr() {
        let routes = vec![route_input(&kid('a'), "not-a-host-port")];
        assert!(validate_routes(routes, |_| true).is_err());
    }

    #[test]
    fn rejects_invalid_name() {
        let routes = vec![route_input_with_name(&kid('a'), "")];
        assert!(validate_routes(routes, |_| true).is_err());
    }

    #[test]
    fn route_name_is_limited_to_config_name_max_chars() {
        let max = crate::core::config::CONFIG_NAME_MAX_CHARS;
        let accepted = vec![route_input_with_name(&kid('a'), &"a".repeat(max))];
        assert!(validate_routes(accepted, |_| true).is_ok());

        let rejected = vec![route_input_with_name(&kid('a'), &"a".repeat(max + 1))];
        let err = match validate_routes(rejected, |_| true) {
            Ok(_) => panic!("overlong route name must fail validation"),
            Err(err) => err,
        };
        assert_eq!(
            err.to_string(),
            "routes.name exceeds maximum allowed length: 128"
        );
    }

    #[test]
    fn rejects_missing_name() {
        let route = serde_json::from_value::<RouteInput>(json!({
            "kid": kid('a'),
            "final_app_addr": "localhost:3999",
            "final_app_path": "/message"
        }));

        assert!(route.is_err());
    }

    #[test]
    fn rejects_duplicate_name() {
        let routes = vec![
            route_input_with_name(&kid('a'), "same-name"),
            route_input_with_name(&kid('b'), "same-name"),
        ];
        assert!(validate_routes(routes, |_| true).is_err());
    }

    #[test]
    fn rejects_duplicate_kid() {
        let routes = vec![
            route_input(&kid('a'), "127.0.0.1:3999"),
            route_input(&kid('a'), "127.0.0.1:4000"),
        ];
        assert!(validate_routes(routes, |_| true).is_err());
    }

    proptest! {
        #[test]
        fn validates_route_when_kid_is_loaded(
            route_kid in "[0-9a-f]{64}",
            port in 1u16..=65535,
            path in "/[A-Za-z0-9_./-]{0,32}"
        ) {
            let addr = format!("localhost:{port}");
            let routes = vec![route_input_with_path(&route_kid, &addr, &path)];

            prop_assert!(validate_routes(routes, |kid| kid == route_kid).is_ok());
        }

        #[test]
        fn rejects_invalid_route_inputs(
            route_kid in "[0-9a-f]{64}",
            bad_kid in "[A-Za-z0-9]{0,63}",
            bad_path in "[A-Za-z0-9_.-]{0,32}"
        ) {
            prop_assume!(bad_kid.len() != 64 || !bad_kid.chars().all(|item| item.is_ascii_hexdigit()));

            prop_assert!(validate_routes(vec![route_input(&bad_kid, "localhost:3999")], |_| true).is_err());
            prop_assert!(validate_routes(vec![route_input(&route_kid, "not-a-host-port")], |_| true).is_err());
            prop_assert!(
                validate_routes(
                    vec![route_input_with_path(&route_kid, "localhost:3999", &bad_path)],
                    |_| true
                )
                .is_err()
            );
            prop_assert!(validate_routes(vec![route_input(&route_kid, "localhost:3999")], |_| false).is_err());
        }

        #[test]
        fn route_for_returns_specific_route_or_default(route_kid in "[0-9a-f]{64}", other_kid in "[0-9a-f]{64}") {
            prop_assume!(route_kid != other_kid);
            let route = FinalAppRoute {
                kid: route_kid.clone(),
                name: String::from("specific-final-app"),
                final_app_addr: String::from("localhost:4001"),
                final_app_path: String::from("/specific"),
            };
            let state = RoutesState::from_parts(
                String::from("localhost:3999"),
                String::from("/default"),
                vec![route],
            );

            let specific = state.route_for(&route_kid);
            prop_assert_eq!(specific.name(), "specific-final-app");
            prop_assert_eq!(specific.final_app_addr(), "localhost:4001");
            prop_assert_eq!(specific.final_app_path(), "/specific");

            let fallback = state.route_for(&other_kid);
            prop_assert_eq!(fallback.kid(), other_kid);
            prop_assert_eq!(fallback.name(), "default-final-app");
            prop_assert_eq!(fallback.final_app_addr(), "localhost:3999");
            prop_assert_eq!(fallback.final_app_path(), "/default");
        }

        #[test]
        fn duplicate_kids_are_rejected(route_kid in "[0-9a-f]{64}", port in 1u16..=65535) {
            let routes = vec![
                route_input(&route_kid, "localhost:3999"),
                route_input(&route_kid, &format!("localhost:{port}")),
            ];

            prop_assert!(validate_routes(routes, |_| true).is_err());
        }
    }
}
