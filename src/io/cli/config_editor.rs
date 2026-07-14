use super::http::{OutputFormat, invalid_input, print_response};
use crate::core::{config, config_file, permissions, validation};
use crate::error::DynError;
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::fs;
use std::time::Duration;

const CONFIG_EDIT_REMINDER: &str = "run `vectis config sign`, then `vectis config reload`";
const DEFAULT_REMOTE_ROUTE_STATUS: &str = "active";
const DEFAULT_PERMISSION_STATUS: &str = "active";
const DEFAULT_TIMEOUT_SECONDS: u64 = 30;

struct LocalConfig {
    app: config::AppConfig,
    value: Value,
}

pub fn init_config(output: OutputFormat) -> Result<(), DynError> {
    let app = config::app_config()?;
    match fs::metadata(&app.config_path) {
        Ok(_) => {
            return Err(invalid_input(
                "config file already exists; refusing to overwrite; delete it manually before running config init again",
            ));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(Box::new(err)),
    }

    let local = LocalConfig {
        app,
        value: empty_config(),
    };
    validate_local_config(&local)?;
    write_local_config(&local)?;
    print_json_value(
        &response_with_reminder(json!({
            "status": "created",
            "config_path": local.app.config_path.display().to_string(),
        })),
        output,
    )
}

pub async fn run_routes(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (command, rest) = split_command(args, "config routes command")?;
    match command.as_str() {
        "add" => mutate_config(output, |local| route_add(local, rest)).await,
        "get" => read_config(output, |local| route_get(local, rest)).await,
        "update" => mutate_config(output, |local| route_update(local, rest)).await,
        "delete" => mutate_config(output, |local| route_delete(local, rest)).await,
        _ => Err(invalid_input(format!(
            "unknown config routes command: {command}"
        ))),
    }
}

pub async fn run_remote_routes(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (command, rest) = split_command(args, "config remote-routes command")?;
    match command.as_str() {
        "add" => remote_route_add(rest, output).await,
        "get" => read_config(output, |local| remote_route_get(local, rest)).await,
        "update" => remote_route_update(rest, output).await,
        "delete" => mutate_config(output, |local| remote_route_delete(local, rest)).await,
        _ => Err(invalid_input(format!(
            "unknown config remote-routes command: {command}"
        ))),
    }
}

pub async fn run_permissions(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (command, rest) = split_command(args, "config permissions command")?;
    match command.as_str() {
        "add" => mutate_config(output, |local| permission_add(local, rest)).await,
        "get" => read_config(output, |local| permission_get(local, rest)).await,
        "update" => mutate_config(output, |local| permission_update(local, rest)).await,
        "delete" => mutate_config(output, |local| permission_delete(local, rest)).await,
        "grant" => mutate_config(output, |local| permission_grant(local, rest)).await,
        "revoke" => mutate_config(output, |local| permission_revoke(local, rest)).await,
        _ => Err(invalid_input(format!(
            "unknown config permissions command: {command}"
        ))),
    }
}

async fn read_config(
    output: OutputFormat,
    action: impl FnOnce(&LocalConfig) -> Result<Value, DynError>,
) -> Result<(), DynError> {
    let local = load_local_config()?;
    let response = action(&local)?;
    print_json_value(&response, output)
}

async fn mutate_config(
    output: OutputFormat,
    action: impl FnOnce(&mut LocalConfig) -> Result<Value, DynError>,
) -> Result<(), DynError> {
    let mut local = load_local_config()?;
    let response = action(&mut local)?;
    validate_local_config(&local)?;
    write_local_config(&local)?;
    print_json_value(&response_with_reminder(response), output)
}

async fn remote_route_add(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let mut local = load_local_config()?;
    let route = parse_remote_route_add(args)?;

    ensure_unique_field(
        array_mut(&mut local.value, "remote_routes")?,
        "name",
        &route.name,
    )?;

    let public_keys = fetch_public_keys(&route.remote_addr, &route.remote_kid).await?;
    let value = json!({
        "remote_kid": route.remote_kid,
        "name": route.name,
        "remote_addr": route.remote_addr,
        "allowed_local_kids": route.allowed_local_kids,
        "status": route.status,
        "public_keys": public_keys,
    });
    array_mut(&mut local.value, "remote_routes")?.push(value.clone());

    validate_local_config(&local)?;
    write_local_config(&local)?;
    print_json_value(
        &response_with_reminder(json!({
            "status": "added",
            "section": "remote_routes",
            "item": value,
        })),
        output,
    )
}

async fn remote_route_update(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (name, rest) = split_name_and_rest(args, "remote route name")?;
    validate_text("name", &name)?;

    let mut update = parse_remote_route_update(rest)?;
    let mut local = load_local_config()?;
    let route = find_by_field_mut(array_mut(&mut local.value, "remote_routes")?, "name", &name)?;
    let needs_key_import = update.remote_kid.is_some() || update.remote_addr.is_some();

    if let Some(remote_kid) = update.remote_kid.take() {
        set_string(route, "remote_kid", remote_kid)?;
    }
    if let Some(remote_addr) = update.remote_addr.take() {
        set_string(route, "remote_addr", remote_addr)?;
    }
    if let Some(allowed_local_kids) = update.allowed_local_kids.take() {
        set_array(route, "allowed_local_kids", allowed_local_kids)?;
    }
    if let Some(status) = update.status.take() {
        set_string(route, "status", status)?;
    }

    if needs_key_import {
        let remote_addr = required_string(route, "remote_addr")?.to_string();
        let remote_kid = required_string(route, "remote_kid")?.to_string();
        let public_keys = fetch_public_keys(&remote_addr, &remote_kid).await?;
        set_value(route, "public_keys", public_keys)?;
    }
    let item = route.clone();

    validate_local_config(&local)?;
    write_local_config(&local)?;
    print_json_value(
        &response_with_reminder(json!({
            "status": "updated",
            "section": "remote_routes",
            "item": item,
        })),
        output,
    )
}

fn route_add(local: &mut LocalConfig, args: Vec<String>) -> Result<Value, DynError> {
    let route = parse_route_add(args)?;
    ensure_unique_field(array_mut(&mut local.value, "routes")?, "name", &route.name)?;
    let value = json!({
        "kid": route.kid,
        "name": route.name,
        "final_app_addr": route.final_app_addr,
        "final_app_path": route.final_app_path,
    });
    array_mut(&mut local.value, "routes")?.push(value.clone());

    Ok(json!({
        "status": "added",
        "section": "routes",
        "item": value,
    }))
}

fn route_get(local: &LocalConfig, args: Vec<String>) -> Result<Value, DynError> {
    let name = expect_one(args, "route name")?;
    validate_text("name", &name)?;
    let route = find_by_field(array_ref(&local.value, "routes")?, "name", &name)?;
    Ok(route.clone())
}

fn route_update(local: &mut LocalConfig, args: Vec<String>) -> Result<Value, DynError> {
    let (name, rest) = split_name_and_rest(args, "route name")?;
    validate_text("name", &name)?;
    let mut update = parse_route_update(rest)?;
    let route = find_by_field_mut(array_mut(&mut local.value, "routes")?, "name", &name)?;

    if let Some(kid) = update.kid.take() {
        set_string(route, "kid", kid)?;
    }
    if let Some(final_app_addr) = update.final_app_addr.take() {
        set_string(route, "final_app_addr", final_app_addr)?;
    }
    if let Some(final_app_path) = update.final_app_path.take() {
        set_string(route, "final_app_path", final_app_path)?;
    }

    Ok(json!({
        "status": "updated",
        "section": "routes",
        "item": route,
    }))
}

fn route_delete(local: &mut LocalConfig, args: Vec<String>) -> Result<Value, DynError> {
    let name = expect_one(args, "route name")?;
    validate_text("name", &name)?;
    let removed = remove_by_field(array_mut(&mut local.value, "routes")?, "name", &name)?;

    Ok(json!({
        "status": "deleted",
        "section": "routes",
        "item": removed,
    }))
}

fn remote_route_get(local: &LocalConfig, args: Vec<String>) -> Result<Value, DynError> {
    let name = expect_one(args, "remote route name")?;
    validate_text("name", &name)?;
    let route = find_by_field(array_ref(&local.value, "remote_routes")?, "name", &name)?;
    Ok(route.clone())
}

fn remote_route_delete(local: &mut LocalConfig, args: Vec<String>) -> Result<Value, DynError> {
    let name = expect_one(args, "remote route name")?;
    validate_text("name", &name)?;
    let removed = remove_by_field(array_mut(&mut local.value, "remote_routes")?, "name", &name)?;

    Ok(json!({
        "status": "deleted",
        "section": "remote_routes",
        "item": removed,
    }))
}

fn permission_add(local: &mut LocalConfig, args: Vec<String>) -> Result<Value, DynError> {
    let permission = parse_permission_add(args)?;
    ensure_unique_field(
        array_mut(&mut local.value, "permissions")?,
        "client",
        &permission.client,
    )?;
    let value = json!({
        "client": permission.client,
        "apikey_hash": permission.apikey_hash,
        "status": permission.status,
        "permissions": [],
    });
    array_mut(&mut local.value, "permissions")?.push(value.clone());

    Ok(json!({
        "status": "added",
        "section": "permissions",
        "item": value,
    }))
}

fn permission_get(local: &LocalConfig, args: Vec<String>) -> Result<Value, DynError> {
    let client = expect_one(args, "client")?;
    validate_text("client", &client)?;
    let permission = find_by_field(array_ref(&local.value, "permissions")?, "client", &client)?;
    Ok(permission.clone())
}

fn permission_update(local: &mut LocalConfig, args: Vec<String>) -> Result<Value, DynError> {
    let (client, rest) = split_name_and_rest(args, "client")?;
    validate_text("client", &client)?;
    let mut update = parse_permission_update(rest)?;
    let permission = find_by_field_mut(
        array_mut(&mut local.value, "permissions")?,
        "client",
        &client,
    )?;

    if let Some(apikey_hash) = update.apikey_hash.take() {
        set_string(permission, "apikey_hash", apikey_hash)?;
    }
    if let Some(status) = update.status.take() {
        set_string(permission, "status", status)?;
    }

    Ok(json!({
        "status": "updated",
        "section": "permissions",
        "item": permission,
    }))
}

fn permission_delete(local: &mut LocalConfig, args: Vec<String>) -> Result<Value, DynError> {
    let client = expect_one(args, "client")?;
    validate_text("client", &client)?;
    let removed = remove_by_field(
        array_mut(&mut local.value, "permissions")?,
        "client",
        &client,
    )?;

    Ok(json!({
        "status": "deleted",
        "section": "permissions",
        "item": removed,
    }))
}

fn permission_grant(local: &mut LocalConfig, args: Vec<String>) -> Result<Value, DynError> {
    let (client, rest) = split_name_and_rest(args, "client")?;
    validate_text("client", &client)?;
    let grant = parse_permission_grant(rest)?;
    let permission = find_by_field_mut(
        array_mut(&mut local.value, "permissions")?,
        "client",
        &client,
    )?;
    let permissions = object_mut(permission)?
        .entry("permissions")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| invalid_input("permissions.permissions must be an array"))?;

    let entry = match permissions
        .iter_mut()
        .find(|entry| entry.get("kid").and_then(Value::as_str) == Some(grant.kid.as_str()))
    {
        Some(entry) => entry,
        None => {
            permissions.push(json!({"kid": grant.kid, "actions": []}));
            permissions
                .last_mut()
                .ok_or_else(|| invalid_input("permission could not be created"))?
        }
    };

    let actions = object_mut(entry)?
        .entry("actions")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| invalid_input("permissions.actions must be an array"))?;
    if !actions
        .iter()
        .any(|action| action.as_str() == Some(grant.action.as_str()))
    {
        actions.push(Value::String(grant.action));
    }

    Ok(json!({
        "status": "updated",
        "section": "permissions",
        "item": permission,
    }))
}

fn permission_revoke(local: &mut LocalConfig, args: Vec<String>) -> Result<Value, DynError> {
    let (client, rest) = split_name_and_rest(args, "client")?;
    validate_text("client", &client)?;
    let grant = parse_permission_grant(rest)?;
    let permission = find_by_field_mut(
        array_mut(&mut local.value, "permissions")?,
        "client",
        &client,
    )?;
    let permissions = object_mut(permission)?
        .get_mut("permissions")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid_input("permissions.permissions must be an array"))?;
    let entry = find_by_field_mut(permissions, "kid", &grant.kid)?;
    let actions = object_mut(entry)?
        .get_mut("actions")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid_input("permissions.actions must be an array"))?;
    let before = actions.len();
    actions.retain(|action| action.as_str() != Some(grant.action.as_str()));
    if actions.len() == before {
        return Err(invalid_input("permission action not found"));
    }
    permissions.retain(|entry| {
        entry
            .get("actions")
            .and_then(Value::as_array)
            .is_some_and(|actions| !actions.is_empty())
    });

    Ok(json!({
        "status": "updated",
        "section": "permissions",
        "item": permission,
    }))
}

#[derive(Default)]
struct RouteAdd {
    name: String,
    kid: String,
    final_app_addr: String,
    final_app_path: String,
}

#[derive(Default)]
struct RouteUpdate {
    kid: Option<String>,
    final_app_addr: Option<String>,
    final_app_path: Option<String>,
}

#[derive(Default)]
struct RemoteRouteAdd {
    name: String,
    remote_kid: String,
    remote_addr: String,
    allowed_local_kids: Vec<String>,
    status: String,
}

#[derive(Default)]
struct RemoteRouteUpdate {
    remote_kid: Option<String>,
    remote_addr: Option<String>,
    allowed_local_kids: Option<Vec<String>>,
    status: Option<String>,
}

#[derive(Default)]
struct PermissionAdd {
    client: String,
    apikey_hash: String,
    status: String,
}

#[derive(Default)]
struct PermissionUpdate {
    apikey_hash: Option<String>,
    status: Option<String>,
}

struct PermissionGrant {
    kid: String,
    action: String,
}

fn parse_route_add(args: Vec<String>) -> Result<RouteAdd, DynError> {
    let mut parsed = RouteAdd::default();
    let mut seen = HashSet::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--name" => parsed.name = flag_once(&args, &mut seen, &mut index, "--name")?,
            "--kid" => parsed.kid = flag_once(&args, &mut seen, &mut index, "--kid")?,
            "--final-app-addr" => {
                parsed.final_app_addr = flag_once(&args, &mut seen, &mut index, "--final-app-addr")?
            }
            "--final-app-path" => {
                parsed.final_app_path = flag_once(&args, &mut seen, &mut index, "--final-app-path")?
            }
            value => return Err(invalid_input(format!("unknown routes add option: {value}"))),
        }
    }

    validate_text("name", &parsed.name)?;
    validate_kid("kid", &parsed.kid)?;
    parsed.final_app_addr =
        validation::validate_host_port("final_app_addr", &parsed.final_app_addr)?;
    parsed.final_app_path =
        config::validate_http_path_field("final_app_path", &parsed.final_app_path)?;
    require_non_empty(&parsed.name, "--name")?;
    require_non_empty(&parsed.kid, "--kid")?;
    require_non_empty(&parsed.final_app_addr, "--final-app-addr")?;
    require_non_empty(&parsed.final_app_path, "--final-app-path")?;

    Ok(parsed)
}

fn parse_route_update(args: Vec<String>) -> Result<RouteUpdate, DynError> {
    let mut parsed = RouteUpdate::default();
    let mut seen = HashSet::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--kid" => {
                parsed.kid = Some(validate_kid_value(
                    "kid",
                    &flag_once(&args, &mut seen, &mut index, "--kid")?,
                )?)
            }
            "--final-app-addr" => {
                let value = flag_once(&args, &mut seen, &mut index, "--final-app-addr")?;
                parsed.final_app_addr =
                    Some(validation::validate_host_port("final_app_addr", &value)?);
            }
            "--final-app-path" => {
                let value = flag_once(&args, &mut seen, &mut index, "--final-app-path")?;
                parsed.final_app_path =
                    Some(config::validate_http_path_field("final_app_path", &value)?);
            }
            value => {
                return Err(invalid_input(format!(
                    "unknown routes update option: {value}"
                )));
            }
        }
    }

    if parsed.kid.is_none() && parsed.final_app_addr.is_none() && parsed.final_app_path.is_none() {
        return Err(invalid_input("routes update requires at least one field"));
    }

    Ok(parsed)
}

fn parse_remote_route_add(args: Vec<String>) -> Result<RemoteRouteAdd, DynError> {
    let mut parsed = RemoteRouteAdd {
        status: String::from(DEFAULT_REMOTE_ROUTE_STATUS),
        ..RemoteRouteAdd::default()
    };
    let mut seen = HashSet::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--name" => parsed.name = flag_once(&args, &mut seen, &mut index, "--name")?,
            "--remote-kid" => {
                parsed.remote_kid = flag_once(&args, &mut seen, &mut index, "--remote-kid")?
            }
            "--remote-addr" => {
                parsed.remote_addr = flag_once(&args, &mut seen, &mut index, "--remote-addr")?
            }
            "--allowed-local-kid" => {
                parsed.allowed_local_kids.push(flag_value(
                    &args,
                    &mut index,
                    "--allowed-local-kid",
                )?);
            }
            "--status" => parsed.status = flag_once(&args, &mut seen, &mut index, "--status")?,
            value => {
                return Err(invalid_input(format!(
                    "unknown remote-routes add option: {value}"
                )));
            }
        }
    }

    validate_remote_route_parts(
        &parsed.name,
        &parsed.remote_kid,
        &parsed.remote_addr,
        &parsed.allowed_local_kids,
        &parsed.status,
    )?;

    Ok(parsed)
}

fn parse_remote_route_update(args: Vec<String>) -> Result<RemoteRouteUpdate, DynError> {
    let mut parsed = RemoteRouteUpdate::default();
    let mut seen = HashSet::new();
    let mut allowed = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--remote-kid" => {
                let value = flag_once(&args, &mut seen, &mut index, "--remote-kid")?;
                parsed.remote_kid = Some(validate_kid_value("remote_kid", &value)?);
            }
            "--remote-addr" => {
                let value = flag_once(&args, &mut seen, &mut index, "--remote-addr")?;
                parsed.remote_addr = Some(validation::validate_host_port("remote_addr", &value)?);
            }
            "--allowed-local-kid" => {
                allowed.push(flag_value(&args, &mut index, "--allowed-local-kid")?);
            }
            "--status" => {
                let value = flag_once(&args, &mut seen, &mut index, "--status")?;
                validate_remote_route_status(&value)?;
                parsed.status = Some(value);
            }
            value => {
                return Err(invalid_input(format!(
                    "unknown remote-routes update option: {value}"
                )));
            }
        }
    }

    if !allowed.is_empty() {
        validate_allowed_local_kids(&allowed)?;
        parsed.allowed_local_kids = Some(allowed);
    }

    if parsed.remote_kid.is_none()
        && parsed.remote_addr.is_none()
        && parsed.allowed_local_kids.is_none()
        && parsed.status.is_none()
    {
        return Err(invalid_input(
            "remote-routes update requires at least one field",
        ));
    }

    Ok(parsed)
}

fn parse_permission_add(args: Vec<String>) -> Result<PermissionAdd, DynError> {
    let mut parsed = PermissionAdd {
        status: String::from(DEFAULT_PERMISSION_STATUS),
        ..PermissionAdd::default()
    };
    let mut seen = HashSet::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--client" => parsed.client = flag_once(&args, &mut seen, &mut index, "--client")?,
            "--apikey-hash" => {
                parsed.apikey_hash = flag_once(&args, &mut seen, &mut index, "--apikey-hash")?
            }
            "--status" => parsed.status = flag_once(&args, &mut seen, &mut index, "--status")?,
            value => {
                return Err(invalid_input(format!(
                    "unknown permissions add option: {value}"
                )));
            }
        }
    }

    validate_text("client", &parsed.client)?;
    validate_apikey_hash(&parsed.apikey_hash)?;
    validate_permission_status(&parsed.status)?;
    require_non_empty(&parsed.client, "--client")?;
    require_non_empty(&parsed.apikey_hash, "--apikey-hash")?;

    Ok(parsed)
}

fn parse_permission_update(args: Vec<String>) -> Result<PermissionUpdate, DynError> {
    let mut parsed = PermissionUpdate::default();
    let mut seen = HashSet::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--apikey-hash" => {
                let value = flag_once(&args, &mut seen, &mut index, "--apikey-hash")?;
                validate_apikey_hash(&value)?;
                parsed.apikey_hash = Some(value);
            }
            "--status" => {
                let value = flag_once(&args, &mut seen, &mut index, "--status")?;
                validate_permission_status(&value)?;
                parsed.status = Some(value);
            }
            value => {
                return Err(invalid_input(format!(
                    "unknown permissions update option: {value}"
                )));
            }
        }
    }

    if parsed.apikey_hash.is_none() && parsed.status.is_none() {
        return Err(invalid_input(
            "permissions update requires at least one field",
        ));
    }

    Ok(parsed)
}

fn parse_permission_grant(args: Vec<String>) -> Result<PermissionGrant, DynError> {
    let mut kid = None;
    let mut action = None;
    let mut seen = HashSet::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--kid" => kid = Some(flag_once(&args, &mut seen, &mut index, "--kid")?),
            "--action" => action = Some(flag_once(&args, &mut seen, &mut index, "--action")?),
            value => {
                return Err(invalid_input(format!(
                    "unknown permissions grant/revoke option: {value}"
                )));
            }
        }
    }

    let kid = kid.ok_or_else(|| invalid_input("--kid is required"))?;
    let action = action.ok_or_else(|| invalid_input("--action is required"))?;
    validate_permission_kid(&kid)?;
    validation::validate_allowed_value("action", &action, permissions::PERMISSION_ACTIONS)?;

    Ok(PermissionGrant { kid, action })
}

fn load_local_config() -> Result<LocalConfig, DynError> {
    let app = config::app_config()?;
    let value = match config_file::read_config_file(&app.config_path) {
        Ok(content) => serde_json::from_str::<Value>(&content)
            .map_err(|err| invalid_input(format!("config file must be valid JSON: {err}")))?,
        Err(err) if crate::error::is_not_found(err.as_ref()) => {
            return Err(invalid_input(format!(
                "VECTIS_CONFIG_PATH could not be read from {}; run `vectis config init` first",
                app.config_path.display()
            )));
        }
        Err(err) => return Err(err),
    };

    let mut local = LocalConfig { app, value };
    ensure_config_shape(&mut local.value)?;
    Ok(local)
}

fn empty_config() -> Value {
    json!({
        "version": "v1",
        "routes": [],
        "remote_routes": [],
        "permissions": [],
    })
}

fn ensure_config_shape(value: &mut Value) -> Result<(), DynError> {
    let object = object_mut(value)?;
    object
        .entry("version")
        .or_insert_with(|| Value::String(String::from("v1")));
    ensure_section_array(object, "routes")?;
    ensure_section_array(object, "remote_routes")?;
    ensure_section_array(object, "permissions")?;
    Ok(())
}

fn ensure_section_array(object: &mut Map<String, Value>, section: &str) -> Result<(), DynError> {
    match object.get(section) {
        Some(Value::Array(_)) => Ok(()),
        Some(_) => Err(invalid_input(format!("config.{section} must be an array"))),
        None => {
            object.insert(section.to_string(), Value::Array(Vec::new()));
            Ok(())
        }
    }
}

fn validate_local_config(local: &LocalConfig) -> Result<(), DynError> {
    let content = serde_json::to_string(&local.value)?;
    config_file::validate_config_content(
        &content,
        &local.app,
        |_| true,
        |_, _, _| {
            Ok(zeroize::Zeroizing::new(vec![
            0u8;
            crate::core::fpe::FPE_KEY_SIZE_BYTES
        ]))
        },
    )?;
    Ok(())
}

fn write_local_config(local: &LocalConfig) -> Result<(), DynError> {
    fs::write(
        &local.app.config_path,
        serde_json::to_string_pretty(&local.value)?,
    )?;
    Ok(())
}

async fn fetch_public_keys(remote_addr: &str, remote_kid: &str) -> Result<Value, DynError> {
    validation::validate_host_port("remote_addr", remote_addr)?;
    validate_kid("remote_kid", remote_kid)?;

    let http_config = config::http_client_config()?;
    let url = format!(
        "{}://{}/pub/{}",
        http_config.remote_scheme, remote_addr, remote_kid
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECONDS))
        .danger_accept_invalid_certs(http_config.tls_skip_verify)
        .build()?;
    let response = client.get(url).send().await?;
    let status = response.status();
    let payload = response.text().await?;
    if !status.is_success() {
        return Err(invalid_input(format!(
            "remote /pub/{remote_kid} failed with HTTP {status}: {payload}"
        )));
    }

    let value: Value = serde_json::from_str(&payload)
        .map_err(|err| invalid_input(format!("remote /pub response must be valid JSON: {err}")))?;
    value
        .get("keys")
        .filter(|keys| keys.is_object())
        .cloned()
        .ok_or_else(|| invalid_input("remote /pub response must include keys object"))
}

fn validate_remote_route_parts(
    name: &str,
    remote_kid: &str,
    remote_addr: &str,
    allowed_local_kids: &[String],
    status: &str,
) -> Result<(), DynError> {
    validate_text("name", name)?;
    validate_kid("remote_kid", remote_kid)?;
    validation::validate_host_port("remote_addr", remote_addr)?;
    validate_allowed_local_kids(allowed_local_kids)?;
    validate_remote_route_status(status)?;
    require_non_empty(name, "--name")?;
    require_non_empty(remote_kid, "--remote-kid")?;
    require_non_empty(remote_addr, "--remote-addr")?;
    Ok(())
}

fn validate_allowed_local_kids(kids: &[String]) -> Result<(), DynError> {
    if kids.is_empty() {
        return Err(invalid_input("--allowed-local-kid is required"));
    }
    let has_wildcard = kids.iter().any(|kid| kid == "*");
    if has_wildcard && kids.len() > 1 {
        return Err(invalid_input(
            "--allowed-local-kid * cannot be mixed with explicit kids",
        ));
    }

    let mut seen = HashSet::new();
    for kid in kids {
        validate_permission_kid(kid)?;
        if !seen.insert(kid) {
            return Err(invalid_input(format!(
                "duplicated --allowed-local-kid: {kid}"
            )));
        }
    }

    Ok(())
}

fn validate_remote_route_status(status: &str) -> Result<(), DynError> {
    validation::validate_allowed_value("status", status, &["active", "disabled"])
}

fn validate_permission_status(status: &str) -> Result<(), DynError> {
    validation::validate_allowed_value("status", status, &["active", "disabled", "revoked"])
}

fn validate_permission_kid(kid: &str) -> Result<(), DynError> {
    if kid == "*" {
        return Ok(());
    }
    validate_kid("kid", kid)
}

fn validate_kid(field: &str, value: &str) -> Result<(), DynError> {
    validation::validate_hash_hex_field(field, value, config::INTERNAL_KEYS_HASH)
}

fn validate_kid_value(field: &str, value: &str) -> Result<String, DynError> {
    validate_kid(field, value)?;
    Ok(value.to_string())
}

fn validate_apikey_hash(value: &str) -> Result<(), DynError> {
    validation::validate_symmetric_key("apikey_hash", value, 32)
}

fn validate_text(field: &str, value: &str) -> Result<(), DynError> {
    validation::validate_text_field(field, value)
}

fn require_non_empty(value: &str, flag: &str) -> Result<(), DynError> {
    if value.is_empty() {
        return Err(invalid_input(format!("{flag} is required")));
    }
    Ok(())
}

fn array_ref<'a>(value: &'a Value, section: &str) -> Result<&'a Vec<Value>, DynError> {
    value
        .get(section)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_input(format!("config.{section} must be an array")))
}

fn array_mut<'a>(value: &'a mut Value, section: &str) -> Result<&'a mut Vec<Value>, DynError> {
    value
        .get_mut(section)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid_input(format!("config.{section} must be an array")))
}

fn object_mut(value: &mut Value) -> Result<&mut Map<String, Value>, DynError> {
    value
        .as_object_mut()
        .ok_or_else(|| invalid_input("config item must be an object"))
}

fn find_by_field<'a>(
    items: &'a [Value],
    field: &str,
    expected: &str,
) -> Result<&'a Value, DynError> {
    let matches: Vec<&Value> = items
        .iter()
        .filter(|item| item.get(field).and_then(Value::as_str) == Some(expected))
        .collect();
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(invalid_input(format!("{field} not found: {expected}"))),
        _ => Err(invalid_input(format!(
            "multiple records found with {field}: {expected}"
        ))),
    }
}

fn find_by_field_mut<'a>(
    items: &'a mut [Value],
    field: &str,
    expected: &str,
) -> Result<&'a mut Value, DynError> {
    let mut found = None;
    let mut count = 0;
    for (index, item) in items.iter().enumerate() {
        if item.get(field).and_then(Value::as_str) == Some(expected) {
            found = Some(index);
            count += 1;
        }
    }

    match (count, found) {
        (1, Some(index)) => Ok(&mut items[index]),
        (0, _) => Err(invalid_input(format!("{field} not found: {expected}"))),
        _ => Err(invalid_input(format!(
            "multiple records found with {field}: {expected}"
        ))),
    }
}

fn remove_by_field(items: &mut Vec<Value>, field: &str, expected: &str) -> Result<Value, DynError> {
    let matches: Vec<usize> = items
        .iter()
        .enumerate()
        .filter_map(|(index, item)| {
            (item.get(field).and_then(Value::as_str) == Some(expected)).then_some(index)
        })
        .collect();

    match matches.len() {
        1 => Ok(items.remove(matches[0])),
        0 => Err(invalid_input(format!("{field} not found: {expected}"))),
        _ => Err(invalid_input(format!(
            "multiple records found with {field}: {expected}"
        ))),
    }
}

fn ensure_unique_field(items: &[Value], field: &str, expected: &str) -> Result<(), DynError> {
    if items
        .iter()
        .any(|item| item.get(field).and_then(Value::as_str) == Some(expected))
    {
        return Err(invalid_input(format!(
            "record already exists with {field}: {expected}"
        )));
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, DynError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input(format!("{field} must be a string")))
}

fn set_string(value: &mut Value, field: &str, item: String) -> Result<(), DynError> {
    object_mut(value)?.insert(field.to_string(), Value::String(item));
    Ok(())
}

fn set_array(value: &mut Value, field: &str, items: Vec<String>) -> Result<(), DynError> {
    object_mut(value)?.insert(
        field.to_string(),
        Value::Array(items.into_iter().map(Value::String).collect()),
    );
    Ok(())
}

fn set_value(value: &mut Value, field: &str, item: Value) -> Result<(), DynError> {
    object_mut(value)?.insert(field.to_string(), item);
    Ok(())
}

fn split_command(mut args: Vec<String>, field: &str) -> Result<(String, Vec<String>), DynError> {
    if args.is_empty() {
        return Err(invalid_input(format!("missing {field}")));
    }
    let command = args.remove(0);
    validate_text(field, &command)?;
    Ok((command, args))
}

fn split_name_and_rest(
    mut args: Vec<String>,
    field: &str,
) -> Result<(String, Vec<String>), DynError> {
    if args.is_empty() {
        return Err(invalid_input(format!("missing {field}")));
    }
    let name = args.remove(0);
    Ok((name, args))
}

fn expect_one(args: Vec<String>, field: &str) -> Result<String, DynError> {
    if args.len() != 1 {
        return Err(invalid_input(format!("expected exactly one {field}")));
    }
    Ok(args[0].clone())
}

fn flag_once(
    args: &[String],
    seen: &mut HashSet<String>,
    index: &mut usize,
    flag: &str,
) -> Result<String, DynError> {
    if !seen.insert(flag.to_string()) {
        return Err(invalid_input(format!("{flag} can only be provided once")));
    }
    flag_value(args, index, flag)
}

fn flag_value(args: &[String], index: &mut usize, flag: &str) -> Result<String, DynError> {
    let value = args
        .get(*index + 1)
        .ok_or_else(|| invalid_input(format!("{flag} requires a value")))?
        .clone();
    *index += 2;
    Ok(value)
}

fn response_with_reminder(mut response: Value) -> Value {
    if let Some(object) = response.as_object_mut() {
        object.insert(
            String::from("next"),
            Value::String(String::from(CONFIG_EDIT_REMINDER)),
        );
    }
    response
}

fn print_json_value(value: &Value, output: OutputFormat) -> Result<(), DynError> {
    print_response(&serde_json::to_string(value)?, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_config() -> LocalConfig {
        LocalConfig {
            app: config::AppConfig {
                http_bind_addr: "127.0.0.1:3000".parse().unwrap(),
                mode: String::from("dev"),
                server_scheme: String::from("http"),
                remote_scheme: String::from("http"),
                final_app_scheme: String::from("http"),
                public_addr: String::from("127.0.0.1:3000"),
                final_app_addr: String::from("127.0.0.1:3999"),
                final_app_path: String::from("/message"),
                tls_cert_path: None,
                tls_key_path: None,
                tls_skip_verify: false,
                config_path: "config.json".into(),
                config_sign_path: "config_sign.json".into(),
                api_key_hash: String::new(),
                protocol_version: String::from("v1"),
                storage_type: String::from("sqlite"),
                sqlite_path: "src/db/data.db".into(),
                postgres_dsn: String::new(),
                sender_hostname: String::from("localhost.local"),
                receiver_hostname: String::from("remotehost.local"),
                default_crypto_profile: String::from("hybrid-performance-v1"),
                crypto_policy: String::from("profile-only"),
                plaintext_message: String::from("hello"),
                metrics_enabled: true,
            },
            value: empty_config(),
        }
    }

    #[test]
    fn duplicate_field_is_rejected() {
        let items = vec![json!({"name": "app"})];
        assert!(ensure_unique_field(&items, "name", "app").is_err());
        assert!(ensure_unique_field(&items, "name", "other").is_ok());
    }

    #[test]
    fn allowed_local_kids_rejects_mixed_wildcard() {
        let kids = vec![String::from("*"), String::from("a").repeat(64)];
        assert!(validate_allowed_local_kids(&kids).is_err());
    }

    #[test]
    fn remove_by_field_requires_single_match() {
        let mut items = vec![json!({"name": "a"}), json!({"name": "a"})];
        assert!(remove_by_field(&mut items, "name", "a").is_err());
    }

    #[test]
    fn route_add_and_get_use_name() {
        let mut local = local_config();
        let kid = "a".repeat(64);
        route_add(
            &mut local,
            vec![
                String::from("--name"),
                String::from("app-a"),
                String::from("--kid"),
                kid,
                String::from("--final-app-addr"),
                String::from("localhost:3999"),
                String::from("--final-app-path"),
                String::from("/message"),
            ],
        )
        .unwrap();

        let route = route_get(&local, vec![String::from("app-a")]).unwrap();
        assert_eq!(route["name"], "app-a");
    }

    #[test]
    fn permission_grant_and_revoke_updates_actions() {
        let mut local = local_config();
        permission_add(
            &mut local,
            vec![
                String::from("--client"),
                String::from("app-a"),
                String::from("--apikey-hash"),
                "b".repeat(64),
            ],
        )
        .unwrap();
        permission_grant(
            &mut local,
            vec![
                String::from("app-a"),
                String::from("--kid"),
                "a".repeat(64),
                String::from("--action"),
                String::from("message"),
            ],
        )
        .unwrap();
        permission_revoke(
            &mut local,
            vec![
                String::from("app-a"),
                String::from("--kid"),
                "a".repeat(64),
                String::from("--action"),
                String::from("message"),
            ],
        )
        .unwrap();

        let item = permission_get(&local, vec![String::from("app-a")]).unwrap();
        assert_eq!(item["permissions"].as_array().unwrap().len(), 0);
    }
}
