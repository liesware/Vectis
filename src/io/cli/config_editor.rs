use super::http::{OutputFormat, invalid_input, print_response};
use crate::core::{
    commitments, config, config_file, fpe, mac, masking, permissions, tokenization, validation,
};
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

type ParsedFieldValidator = fn(&Map<String, Value>) -> Result<(), DynError>;

#[derive(Clone, Copy)]
struct SectionSpec {
    cli_name: &'static str,
    json_section: &'static str,
    key_field: &'static str,
    item_name: &'static str,
    command_context: &'static str,
    fields: &'static [FieldSpec],
    add_defaults: &'static [DefaultField],
    parsed_validator: Option<ParsedFieldValidator>,
}

#[derive(Clone, Copy)]
struct FieldSpec {
    flag: &'static str,
    json_field: &'static str,
    kind: FieldKind,
    cardinality: FieldCardinality,
    required_on_add: bool,
    mutable_on_update: bool,
    default_on_add: Option<DefaultValue>,
}

#[derive(Clone, Copy)]
struct DefaultField {
    json_field: &'static str,
    value: DefaultValue,
}

#[derive(Clone, Copy)]
enum DefaultValue {
    String(&'static str),
    EmptyArray,
}

#[derive(Clone, Copy)]
enum FieldKind {
    ConfigName,
    Kid,
    RemoteKid,
    HostPort,
    FinalAppPath,
    ApiKeyHash,
    PermissionStatus,
    RemoteRouteStatus,
    PermissionKid,
    PermissionAction,
    Usize,
    FpeProfileName,
    FpeVersion,
    FpeAlphabet,
    FpeTweakAad,
    TokenProfileName,
    TokenPrefix,
    MacProfileName,
    MacContext,
    MaskingProfileName,
    MaskChar,
    CommitmentProfileName,
    CommitmentContext,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FieldCardinality {
    One,
    Many,
}

const ROUTES_SECTION: SectionSpec = SectionSpec {
    cli_name: "routes",
    json_section: "routes",
    key_field: "name",
    item_name: "route name",
    command_context: "routes",
    fields: &[
        FieldSpec {
            flag: "--name",
            json_field: "name",
            kind: FieldKind::ConfigName,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: false,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--kid",
            json_field: "kid",
            kind: FieldKind::Kid,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--final-app-addr",
            json_field: "final_app_addr",
            kind: FieldKind::HostPort,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--final-app-path",
            json_field: "final_app_path",
            kind: FieldKind::FinalAppPath,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
    ],
    add_defaults: &[],
    parsed_validator: None,
};

const REMOTE_ROUTES_SECTION: SectionSpec = SectionSpec {
    cli_name: "remote-routes",
    json_section: "remote_routes",
    key_field: "name",
    item_name: "remote route name",
    command_context: "remote-routes",
    fields: &[
        FieldSpec {
            flag: "--name",
            json_field: "name",
            kind: FieldKind::ConfigName,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: false,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--remote-kid",
            json_field: "remote_kid",
            kind: FieldKind::RemoteKid,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--remote-addr",
            json_field: "remote_addr",
            kind: FieldKind::HostPort,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--allowed-local-kid",
            json_field: "allowed_local_kids",
            kind: FieldKind::PermissionKid,
            cardinality: FieldCardinality::Many,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--status",
            json_field: "status",
            kind: FieldKind::RemoteRouteStatus,
            cardinality: FieldCardinality::One,
            required_on_add: false,
            mutable_on_update: true,
            default_on_add: Some(DefaultValue::String(DEFAULT_REMOTE_ROUTE_STATUS)),
        },
    ],
    add_defaults: &[],
    parsed_validator: None,
};

const PERMISSION_GRANT_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        flag: "--kid",
        json_field: "kid",
        kind: FieldKind::PermissionKid,
        cardinality: FieldCardinality::One,
        required_on_add: true,
        mutable_on_update: true,
        default_on_add: None,
    },
    FieldSpec {
        flag: "--action",
        json_field: "action",
        kind: FieldKind::PermissionAction,
        cardinality: FieldCardinality::One,
        required_on_add: true,
        mutable_on_update: true,
        default_on_add: None,
    },
];

const PERMISSIONS_SECTION: SectionSpec = SectionSpec {
    cli_name: "permissions",
    json_section: "permissions",
    key_field: "client",
    item_name: "client",
    command_context: "permissions",
    fields: &[
        FieldSpec {
            flag: "--client",
            json_field: "client",
            kind: FieldKind::ConfigName,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: false,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--apikey-hash",
            json_field: "apikey_hash",
            kind: FieldKind::ApiKeyHash,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--status",
            json_field: "status",
            kind: FieldKind::PermissionStatus,
            cardinality: FieldCardinality::One,
            required_on_add: false,
            mutable_on_update: true,
            default_on_add: Some(DefaultValue::String(DEFAULT_PERMISSION_STATUS)),
        },
    ],
    add_defaults: &[DefaultField {
        json_field: "permissions",
        value: DefaultValue::EmptyArray,
    }],
    parsed_validator: None,
};

const FPE_PROFILES_SECTION: SectionSpec = SectionSpec {
    cli_name: "fpe",
    json_section: "fpe_profiles",
    key_field: "name",
    item_name: "fpe profile name",
    command_context: "config fpe",
    fields: &[
        FieldSpec {
            flag: "--name",
            json_field: "name",
            kind: FieldKind::FpeProfileName,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: false,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--kid",
            json_field: "kid",
            kind: FieldKind::Kid,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--fpe-version",
            json_field: "fpe_version",
            kind: FieldKind::FpeVersion,
            cardinality: FieldCardinality::One,
            required_on_add: false,
            mutable_on_update: true,
            default_on_add: Some(DefaultValue::String(fpe::FPE_VERSION_FF1_2025)),
        },
        FieldSpec {
            flag: "--alphabet",
            json_field: "alphabet",
            kind: FieldKind::FpeAlphabet,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--min-len",
            json_field: "min_len",
            kind: FieldKind::Usize,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--max-len",
            json_field: "max_len",
            kind: FieldKind::Usize,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--tweak-aad",
            json_field: "tweak_aad",
            kind: FieldKind::FpeTweakAad,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
    ],
    add_defaults: &[],
    parsed_validator: Some(validate_fpe_profile_parsed_fields),
};

const TOKENIZATION_PROFILES_SECTION: SectionSpec = SectionSpec {
    cli_name: "token",
    json_section: "tokenization_profiles",
    key_field: "name",
    item_name: "tokenization profile name",
    command_context: "config token",
    fields: &[
        FieldSpec {
            flag: "--name",
            json_field: "name",
            kind: FieldKind::TokenProfileName,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: false,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--kid",
            json_field: "kid",
            kind: FieldKind::Kid,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--token-prefix",
            json_field: "token_prefix",
            kind: FieldKind::TokenPrefix,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--token-len",
            json_field: "token_len",
            kind: FieldKind::Usize,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--max-plaintext-len",
            json_field: "max_plaintext_len",
            kind: FieldKind::Usize,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
    ],
    add_defaults: &[],
    parsed_validator: Some(validate_tokenization_profile_parsed_fields),
};

const MAC_PROFILES_SECTION: SectionSpec = SectionSpec {
    cli_name: "mac",
    json_section: "mac_profiles",
    key_field: "name",
    item_name: "mac profile name",
    command_context: "config mac",
    fields: &[
        FieldSpec {
            flag: "--name",
            json_field: "name",
            kind: FieldKind::MacProfileName,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: false,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--kid",
            json_field: "kid",
            kind: FieldKind::Kid,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--context",
            json_field: "context",
            kind: FieldKind::MacContext,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
    ],
    add_defaults: &[],
    parsed_validator: None,
};

const MASKING_PROFILES_SECTION: SectionSpec = SectionSpec {
    cli_name: "masking",
    json_section: "masking_profiles",
    key_field: "name",
    item_name: "masking profile name",
    command_context: "config masking",
    fields: &[
        FieldSpec {
            flag: "--name",
            json_field: "name",
            kind: FieldKind::MaskingProfileName,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: false,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--kid",
            json_field: "kid",
            kind: FieldKind::Kid,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--visible-first",
            json_field: "visible_first",
            kind: FieldKind::Usize,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--visible-last",
            json_field: "visible_last",
            kind: FieldKind::Usize,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--mask-char",
            json_field: "mask_char",
            kind: FieldKind::MaskChar,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--min-len",
            json_field: "min_len",
            kind: FieldKind::Usize,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--max-len",
            json_field: "max_len",
            kind: FieldKind::Usize,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
    ],
    add_defaults: &[],
    parsed_validator: Some(validate_masking_profile_parsed_fields),
};

const COMMITMENT_PROFILES_SECTION: SectionSpec = SectionSpec {
    cli_name: "commitment",
    json_section: "commitment_profiles",
    key_field: "name",
    item_name: "commitment profile name",
    command_context: "config commitment",
    fields: &[
        FieldSpec {
            flag: "--name",
            json_field: "name",
            kind: FieldKind::CommitmentProfileName,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: false,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--kid",
            json_field: "kid",
            kind: FieldKind::Kid,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--context",
            json_field: "context",
            kind: FieldKind::CommitmentContext,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--max-plaintext-len",
            json_field: "max_plaintext_len",
            kind: FieldKind::Usize,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
        FieldSpec {
            flag: "--opening-len",
            json_field: "opening_len",
            kind: FieldKind::Usize,
            cardinality: FieldCardinality::One,
            required_on_add: true,
            mutable_on_update: true,
            default_on_add: None,
        },
    ],
    add_defaults: &[],
    parsed_validator: Some(validate_commitment_profile_parsed_fields),
};

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
    run_basic_section_command(&ROUTES_SECTION, &command, rest, output).await
}

pub async fn run_remote_routes(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (command, rest) = split_command(args, "config remote-routes command")?;
    match command.as_str() {
        "list" => section_list_command(&REMOTE_ROUTES_SECTION, rest, output).await,
        "add" => remote_route_add(rest, output).await,
        "get" => section_get_command(&REMOTE_ROUTES_SECTION, rest, output).await,
        "update" => remote_route_update(rest, output).await,
        "delete" => section_delete_command(&REMOTE_ROUTES_SECTION, rest, output).await,
        _ => Err(invalid_input(format!(
            "unknown config remote-routes command: {command}"
        ))),
    }
}

pub async fn run_permissions(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (command, rest) = split_command(args, "config permissions command")?;
    match command.as_str() {
        "grant" => mutate_config(output, |local| permission_grant(local, rest)).await,
        "revoke" => mutate_config(output, |local| permission_revoke(local, rest)).await,
        _ => run_basic_section_command(&PERMISSIONS_SECTION, &command, rest, output).await,
    }
}

pub async fn run_config_fpe(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (command, rest) = split_command(args, "config fpe command")?;
    run_basic_section_command(&FPE_PROFILES_SECTION, &command, rest, output).await
}

pub async fn run_config_token(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (command, rest) = split_command(args, "config token command")?;
    run_basic_section_command(&TOKENIZATION_PROFILES_SECTION, &command, rest, output).await
}

pub async fn run_config_mac(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (command, rest) = split_command(args, "config mac command")?;
    run_basic_section_command(&MAC_PROFILES_SECTION, &command, rest, output).await
}

pub async fn run_config_masking(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let (command, rest) = split_command(args, "config masking command")?;
    run_basic_section_command(&MASKING_PROFILES_SECTION, &command, rest, output).await
}

pub async fn run_config_commitment(
    args: Vec<String>,
    output: OutputFormat,
) -> Result<(), DynError> {
    let (command, rest) = split_command(args, "config commitment command")?;
    run_basic_section_command(&COMMITMENT_PROFILES_SECTION, &command, rest, output).await
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

async fn run_basic_section_command(
    spec: &'static SectionSpec,
    command: &str,
    rest: Vec<String>,
    output: OutputFormat,
) -> Result<(), DynError> {
    match command {
        "list" => section_list_command(spec, rest, output).await,
        "add" => section_add_command(spec, rest, output).await,
        "get" => section_get_command(spec, rest, output).await,
        "update" => section_update_command(spec, rest, output).await,
        "delete" => section_delete_command(spec, rest, output).await,
        _ => Err(invalid_input(format!(
            "unknown config {} command: {command}",
            spec.cli_name
        ))),
    }
}

async fn section_list_command(
    spec: &'static SectionSpec,
    args: Vec<String>,
    output: OutputFormat,
) -> Result<(), DynError> {
    expect_no_args(args, &format!("config {} list", spec.cli_name))?;
    read_config(output, |local| section_list(local, spec)).await
}

async fn section_add_command(
    spec: &'static SectionSpec,
    args: Vec<String>,
    output: OutputFormat,
) -> Result<(), DynError> {
    mutate_config(output, |local| {
        let value = parse_section_add(spec, args)?;
        section_add_value(local, spec, value)
    })
    .await
}

async fn section_get_command(
    spec: &'static SectionSpec,
    args: Vec<String>,
    output: OutputFormat,
) -> Result<(), DynError> {
    read_config(output, |local| section_get(local, spec, args)).await
}

async fn section_update_command(
    spec: &'static SectionSpec,
    args: Vec<String>,
    output: OutputFormat,
) -> Result<(), DynError> {
    mutate_config(output, |local| section_update(local, spec, args)).await
}

async fn section_delete_command(
    spec: &'static SectionSpec,
    args: Vec<String>,
    output: OutputFormat,
) -> Result<(), DynError> {
    mutate_config(output, |local| section_delete(local, spec, args)).await
}

fn section_list(local: &LocalConfig, spec: &SectionSpec) -> Result<Value, DynError> {
    Ok(Value::Array(
        array_ref(&local.value, spec.json_section)?.to_vec(),
    ))
}

fn section_add_value(
    local: &mut LocalConfig,
    spec: &SectionSpec,
    value: Value,
) -> Result<Value, DynError> {
    let key = required_string(&value, spec.key_field)?.to_string();
    ensure_unique_field(
        array_mut(&mut local.value, spec.json_section)?,
        spec.key_field,
        &key,
    )?;
    array_mut(&mut local.value, spec.json_section)?.push(value.clone());

    Ok(section_response("added", spec, value))
}

fn section_get(
    local: &LocalConfig,
    spec: &SectionSpec,
    args: Vec<String>,
) -> Result<Value, DynError> {
    let key = expect_one(args, spec.item_name)?;
    validate_text(spec.key_field, &key)?;
    Ok(find_by_field(
        array_ref(&local.value, spec.json_section)?,
        spec.key_field,
        &key,
    )?
    .clone())
}

fn section_update(
    local: &mut LocalConfig,
    spec: &SectionSpec,
    args: Vec<String>,
) -> Result<Value, DynError> {
    let (key, rest) = split_name_and_rest(args, spec.item_name)?;
    validate_text(spec.key_field, &key)?;
    let update = parse_section_update(spec, rest)?;
    let item = find_by_field_mut(
        array_mut(&mut local.value, spec.json_section)?,
        spec.key_field,
        &key,
    )?;
    object_mut(item)?.extend(update);

    Ok(section_response("updated", spec, item.clone()))
}

fn section_delete(
    local: &mut LocalConfig,
    spec: &SectionSpec,
    args: Vec<String>,
) -> Result<Value, DynError> {
    let key = expect_one(args, spec.item_name)?;
    validate_text(spec.key_field, &key)?;
    let removed = remove_by_field(
        array_mut(&mut local.value, spec.json_section)?,
        spec.key_field,
        &key,
    )?;

    Ok(section_response("deleted", spec, removed))
}

fn section_response(status: &str, spec: &SectionSpec, item: Value) -> Value {
    json!({
        "status": status,
        "section": spec.json_section,
        "item": item,
    })
}

fn parse_section_add(spec: &SectionSpec, args: Vec<String>) -> Result<Value, DynError> {
    let mut parsed = parse_section_fields(spec, "add", args, false)?;
    for field in spec.fields {
        if parsed.contains_key(field.json_field) {
            continue;
        }
        if let Some(default) = field.default_on_add {
            parsed.insert(field.json_field.to_string(), default.to_value());
        } else if field.required_on_add {
            return Err(invalid_input(format!("{} is required", field.flag)));
        }
    }
    for default in spec.add_defaults {
        parsed
            .entry(default.json_field.to_string())
            .or_insert_with(|| default.value.to_value());
    }
    validate_parsed_field_combinations(spec, &parsed)?;
    Ok(Value::Object(parsed))
}

fn parse_section_update(
    spec: &SectionSpec,
    args: Vec<String>,
) -> Result<Map<String, Value>, DynError> {
    let parsed = parse_section_fields(spec, "update", args, true)?;
    if parsed.is_empty() {
        return Err(invalid_input(format!(
            "{} update requires at least one field",
            spec.command_context
        )));
    }
    validate_parsed_field_combinations(spec, &parsed)?;
    Ok(parsed)
}

fn validate_parsed_field_combinations(
    spec: &SectionSpec,
    parsed: &Map<String, Value>,
) -> Result<(), DynError> {
    if let Some(kids) = parsed.get("allowed_local_kids") {
        let kids = kids
            .as_array()
            .ok_or_else(|| invalid_input("allowed_local_kids must be an array"))?
            .iter()
            .map(|kid| {
                kid.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| invalid_input("allowed_local_kids must contain strings"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        validate_allowed_local_kids(&kids)?;
    }
    if let Some(validator) = spec.parsed_validator {
        validator(parsed)?;
    }
    Ok(())
}

fn validate_tokenization_profile_parsed_fields(
    parsed: &Map<String, Value>,
) -> Result<(), DynError> {
    let token_len = optional_usize_field(parsed, "token_len")?;
    let max_plaintext_len = optional_usize_field(parsed, "max_plaintext_len")?;

    match (token_len, max_plaintext_len) {
        (Some(token_len), Some(max_plaintext_len)) => {
            tokenization::validate_token_lengths(token_len, max_plaintext_len)
        }
        (Some(token_len), None) => {
            tokenization::validate_token_lengths(token_len, tokenization::TOKEN_PLAINTEXT_MAX_LEN)
        }
        (None, Some(max_plaintext_len)) => tokenization::validate_token_lengths(
            tokenization::TOKEN_LEN_MIN_BYTES,
            max_plaintext_len,
        ),
        (None, None) => Ok(()),
    }
}

fn validate_fpe_profile_parsed_fields(parsed: &Map<String, Value>) -> Result<(), DynError> {
    let min_len = optional_usize_field(parsed, "min_len")?;
    let max_len = optional_usize_field(parsed, "max_len")?;

    match (min_len, max_len) {
        (Some(min_len), Some(max_len)) => fpe::validate_fpe_length_bounds(min_len, max_len),
        (Some(min_len), None) => fpe::validate_fpe_min_len(min_len),
        (None, Some(max_len)) => fpe::validate_fpe_max_len(max_len),
        (None, None) => Ok(()),
    }
}

fn validate_masking_profile_parsed_fields(parsed: &Map<String, Value>) -> Result<(), DynError> {
    let visible_first = optional_usize_field(parsed, "visible_first")?;
    let visible_last = optional_usize_field(parsed, "visible_last")?;
    let min_len = optional_usize_field(parsed, "min_len")?;
    let max_len = optional_usize_field(parsed, "max_len")?;

    match (visible_first, visible_last, min_len, max_len) {
        (Some(visible_first), Some(visible_last), Some(min_len), Some(max_len)) => {
            masking::validate_masking_lengths(visible_first, visible_last, min_len, max_len)
        }
        (None, None, Some(min_len), Some(max_len)) => {
            masking::validate_masking_lengths(0, 0, min_len, max_len)
        }
        (None, None, Some(min_len), None) => {
            masking::validate_masking_lengths(0, 0, min_len, masking::MASKING_PLAINTEXT_MAX_LEN)
        }
        (None, None, None, Some(max_len)) => masking::validate_masking_lengths(0, 0, 1, max_len),
        _ => Ok(()),
    }
}

fn validate_commitment_profile_parsed_fields(parsed: &Map<String, Value>) -> Result<(), DynError> {
    if let Some(max_plaintext_len) = optional_usize_field(parsed, "max_plaintext_len")? {
        commitments::validate_commitment_plaintext_len(max_plaintext_len)?;
    }
    if let Some(opening_len) = optional_usize_field(parsed, "opening_len")? {
        commitments::validate_commitment_opening_len(opening_len)?;
    }
    Ok(())
}

fn optional_usize_field(
    parsed: &Map<String, Value>,
    field: &str,
) -> Result<Option<usize>, DynError> {
    let Some(value) = parsed.get(field) else {
        return Ok(None);
    };
    let value = value
        .as_u64()
        .ok_or_else(|| invalid_input(format!("{field} must be an unsigned integer")))?;
    usize::try_from(value)
        .map(Some)
        .map_err(|_| invalid_input(format!("{field} is too large")))
}

fn parse_section_fields(
    spec: &SectionSpec,
    operation: &str,
    args: Vec<String>,
    update: bool,
) -> Result<Map<String, Value>, DynError> {
    parse_fields(spec.fields, spec.command_context, operation, args, update)
}

fn parse_fields(
    fields: &[FieldSpec],
    command_context: &str,
    operation: &str,
    args: Vec<String>,
    update: bool,
) -> Result<Map<String, Value>, DynError> {
    let mut parsed = Map::new();
    let mut seen = HashSet::new();
    let mut index = 0;

    while index < args.len() {
        let flag = args[index].as_str();
        let field = fields
            .iter()
            .find(|field| field.flag == flag && (!update || field.mutable_on_update))
            .ok_or_else(|| {
                invalid_input(format!(
                    "unknown {} {} option: {flag}",
                    command_context, operation
                ))
            })?;
        let raw = match field.cardinality {
            FieldCardinality::One => flag_once(&args, &mut seen, &mut index, field.flag)?,
            FieldCardinality::Many => flag_value(&args, &mut index, field.flag)?,
        };
        let value = parse_field_value(field, &raw)?;
        match field.cardinality {
            FieldCardinality::One => {
                parsed.insert(field.json_field.to_string(), value);
            }
            FieldCardinality::Many => {
                parsed
                    .entry(field.json_field.to_string())
                    .or_insert_with(|| Value::Array(Vec::new()))
                    .as_array_mut()
                    .ok_or_else(|| invalid_input(format!("{} must be an array", field.json_field)))?
                    .push(value);
            }
        }
    }

    Ok(parsed)
}

fn parse_field_value(field: &FieldSpec, raw: &str) -> Result<Value, DynError> {
    match field.kind {
        FieldKind::ConfigName => {
            validation::validate_config_name(field.json_field, raw)?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::Kid => Ok(Value::String(validate_kid_value(field.json_field, raw)?)),
        FieldKind::RemoteKid => Ok(Value::String(validate_kid_value("remote_kid", raw)?)),
        FieldKind::HostPort => Ok(Value::String(validation::validate_host_port(
            field.json_field,
            raw,
        )?)),
        FieldKind::FinalAppPath => Ok(Value::String(config::validate_http_path_field(
            field.json_field,
            raw,
        )?)),
        FieldKind::ApiKeyHash => {
            validate_apikey_hash(raw)?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::PermissionStatus => {
            validate_permission_status(raw)?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::RemoteRouteStatus => {
            validate_remote_route_status(raw)?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::PermissionKid => {
            validate_permission_kid(raw)?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::PermissionAction => {
            validation::validate_allowed_value("action", raw, permissions::PERMISSION_ACTIONS)?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::Usize => Ok(Value::Number(parse_usize_flag(field.flag, raw)?.into())),
        FieldKind::FpeProfileName => {
            validation::validate_aad_config_name("fpe_profiles.name", raw)?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::FpeVersion => {
            fpe::validate_fpe_version(raw)?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::FpeAlphabet => {
            fpe::validate_fpe_alphabet(raw)?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::FpeTweakAad => {
            validation::validate_labels(
                "fpe_profiles.tweak_aad",
                raw,
                crate::core::config::FPE_TWEAK_AAD_MAX_CHARS,
            )?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::TokenProfileName => {
            validation::validate_aad_config_name("tokenization_profiles.name", raw)?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::TokenPrefix => {
            tokenization::validate_token_prefix(raw)?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::MacProfileName => {
            validation::validate_aad_config_name("mac_profiles.name", raw)?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::MacContext => {
            validation::validate_labels("mac_profiles.context", raw, mac::MAC_CONTEXT_MAX_CHARS)?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::MaskingProfileName => {
            validation::validate_aad_config_name("masking_profiles.name", raw)?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::MaskChar => {
            masking::validate_mask_char(raw)?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::CommitmentProfileName => {
            validation::validate_aad_config_name("commitment_profiles.name", raw)?;
            Ok(Value::String(raw.to_string()))
        }
        FieldKind::CommitmentContext => {
            validation::validate_labels(
                "commitment_profiles.context",
                raw,
                commitments::COMMITMENT_CONTEXT_MAX_CHARS,
            )?;
            Ok(Value::String(raw.to_string()))
        }
    }
}

impl DefaultValue {
    fn to_value(self) -> Value {
        match self {
            DefaultValue::String(value) => Value::String(value.to_string()),
            DefaultValue::EmptyArray => Value::Array(Vec::new()),
        }
    }
}

async fn remote_route_add(args: Vec<String>, output: OutputFormat) -> Result<(), DynError> {
    let mut local = load_local_config()?;
    let mut value = parse_section_add(&REMOTE_ROUTES_SECTION, args)?;
    let route = value
        .as_object_mut()
        .ok_or_else(|| invalid_input("remote route must be an object"))?;
    let name = required_map_string(route, "name")?.to_string();
    let remote_addr = required_map_string(route, "remote_addr")?.to_string();
    let remote_kid = required_map_string(route, "remote_kid")?.to_string();

    ensure_unique_field(array_mut(&mut local.value, "remote_routes")?, "name", &name)?;

    let public_keys = fetch_public_keys(&remote_addr, &remote_kid).await?;
    route.insert(String::from("public_keys"), public_keys);
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

    let update = parse_section_update(&REMOTE_ROUTES_SECTION, rest)?;
    let mut local = load_local_config()?;
    let route = find_by_field_mut(array_mut(&mut local.value, "remote_routes")?, "name", &name)?;
    let needs_key_import = update.contains_key("remote_kid") || update.contains_key("remote_addr");

    object_mut(route)?.extend(update);

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

fn permission_grant(local: &mut LocalConfig, args: Vec<String>) -> Result<Value, DynError> {
    let (client, rest) = split_name_and_rest(args, "client")?;
    validate_text("client", &client)?;
    let grant = parse_permission_action_fields(rest)?;
    let kid = required_map_string(&grant, "kid")?.to_string();
    let action = required_map_string(&grant, "action")?.to_string();
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
        .find(|entry| entry.get("kid").and_then(Value::as_str) == Some(kid.as_str()))
    {
        Some(entry) => entry,
        None => {
            permissions.push(json!({"kid": kid, "actions": []}));
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
        .any(|current| current.as_str() == Some(action.as_str()))
    {
        actions.push(Value::String(action));
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
    let grant = parse_permission_action_fields(rest)?;
    let kid = required_map_string(&grant, "kid")?.to_string();
    let action = required_map_string(&grant, "action")?.to_string();
    let permission = find_by_field_mut(
        array_mut(&mut local.value, "permissions")?,
        "client",
        &client,
    )?;
    let permissions = object_mut(permission)?
        .get_mut("permissions")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid_input("permissions.permissions must be an array"))?;
    let entry = find_by_field_mut(permissions, "kid", &kid)?;
    let actions = object_mut(entry)?
        .get_mut("actions")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid_input("permissions.actions must be an array"))?;
    let before = actions.len();
    actions.retain(|current| current.as_str() != Some(action.as_str()));
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

fn parse_permission_action_fields(args: Vec<String>) -> Result<Map<String, Value>, DynError> {
    let parsed = parse_fields(
        PERMISSION_GRANT_FIELDS,
        "permissions grant/revoke",
        "option",
        args,
        false,
    )?;
    for field in PERMISSION_GRANT_FIELDS {
        if field.required_on_add && !parsed.contains_key(field.json_field) {
            return Err(invalid_input(format!("{} is required", field.flag)));
        }
    }
    Ok(parsed)
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
        "fpe_profiles": [],
        "tokenization_profiles": [],
        "mac_profiles": [],
        "masking_profiles": [],
        "commitment_profiles": [],
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
    ensure_section_array(object, "fpe_profiles")?;
    ensure_section_array(object, "tokenization_profiles")?;
    ensure_section_array(object, "mac_profiles")?;
    ensure_section_array(object, "masking_profiles")?;
    ensure_section_array(object, "commitment_profiles")?;
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
        |_| {
            Ok(zeroize::Zeroizing::new(vec![
            0u8;
            crate::core::fpe::FPE_KEY_SIZE_BYTES
        ]))
        },
        |_| {
            Ok(crate::core::tokenization::DerivedTokenizationKeys {
                hash_key: zeroize::Zeroizing::new(vec![
                    0u8;
                    crate::core::tokenization::TOKEN_KEY_SIZE_BYTES
                ]),
                data_key: zeroize::Zeroizing::new(vec![
                    1u8;
                    crate::core::tokenization::TOKEN_KEY_SIZE_BYTES
                ]),
                cipher_algorithm: String::from("AES-256/GCM"),
            })
        },
        |_| Ok(String::from("BLAKE2b(256)")),
        |_| {
            Ok(crate::core::mac::DerivedMacKey {
                public_algorithm: String::from("HMAC(BLAKE2b(256))"),
                botan_algorithm: String::from("HMAC(BLAKE2b(256))"),
                mac_key: zeroize::Zeroizing::new(vec![0u8; crate::core::mac::MAC_KEY_SIZE_BYTES]),
            })
        },
        |_| {
            Ok(crate::core::commitments::DerivedCommitmentKey {
                public_algorithm: String::from("HMAC(BLAKE2b(256))"),
                botan_algorithm: String::from("HMAC(BLAKE2b(256))"),
                commit_key: zeroize::Zeroizing::new(vec![
                    0u8;
                    crate::core::commitments::COMMITMENT_KEY_SIZE_BYTES
                ]),
            })
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

fn required_map_string<'a>(
    value: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, DynError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input(format!("{field} must be a string")))
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

fn expect_no_args(args: Vec<String>, command: &str) -> Result<(), DynError> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(invalid_input(format!(
            "{command} does not accept arguments"
        )))
    }
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

fn parse_usize_flag(flag: &str, value: &str) -> Result<usize, DynError> {
    value
        .parse::<usize>()
        .map_err(|_| invalid_input(format!("{flag} must be a positive integer")))
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

    fn valid_token_profile_args(token_len: &str, max_plaintext_len: &str) -> Vec<String> {
        vec![
            String::from("--name"),
            String::from("patient-token"),
            String::from("--kid"),
            "a".repeat(64),
            String::from("--token-prefix"),
            String::from("tok_patient"),
            String::from("--token-len"),
            String::from(token_len),
            String::from("--max-plaintext-len"),
            String::from(max_plaintext_len),
        ]
    }

    fn valid_mac_profile_args(name: &str) -> Vec<String> {
        vec![
            String::from("--name"),
            String::from(name),
            String::from("--kid"),
            "a".repeat(64),
            String::from("--context"),
            String::from("tenant=mx;field=pan;purpose=blind-index;version=1"),
        ]
    }

    fn valid_fpe_profile_args(name: &str, min_len: &str, max_len: &str) -> Vec<String> {
        vec![
            String::from("--name"),
            String::from(name),
            String::from("--kid"),
            "a".repeat(64),
            String::from("--alphabet"),
            String::from("0123456789"),
            String::from("--min-len"),
            String::from(min_len),
            String::from("--max-len"),
            String::from(max_len),
            String::from("--tweak-aad"),
            String::from("tenant=acme"),
        ]
    }

    #[test]
    fn remove_by_field_requires_single_match() {
        let mut items = vec![json!({"name": "a"}), json!({"name": "a"})];
        assert!(remove_by_field(&mut items, "name", "a").is_err());
    }

    #[test]
    fn field_parser_rejects_missing_duplicate_unknown_and_immutable_flags() {
        let missing = parse_section_add(
            &ROUTES_SECTION,
            vec![
                String::from("--name"),
                String::from("app-a"),
                String::from("--kid"),
                "a".repeat(64),
                String::from("--final-app-addr"),
                String::from("localhost:3999"),
            ],
        )
        .expect_err("missing required path must fail");
        assert_eq!(missing.to_string(), "--final-app-path is required");

        let duplicate = parse_section_add(
            &ROUTES_SECTION,
            vec![
                String::from("--name"),
                String::from("app-a"),
                String::from("--name"),
                String::from("app-b"),
            ],
        )
        .expect_err("duplicate flag must fail");
        assert_eq!(duplicate.to_string(), "--name can only be provided once");

        let unknown = parse_section_add(
            &ROUTES_SECTION,
            vec![String::from("--unknown"), String::from("value")],
        )
        .expect_err("unknown flag must fail");
        assert_eq!(unknown.to_string(), "unknown routes add option: --unknown");

        let immutable = parse_section_update(
            &ROUTES_SECTION,
            vec![String::from("--name"), String::from("app-b")],
        )
        .expect_err("immutable field must fail on update");
        assert_eq!(
            immutable.to_string(),
            "unknown routes update option: --name"
        );
    }

    #[test]
    fn config_editor_rejects_overlong_config_names_inline() {
        let name = "a".repeat(crate::core::config::CONFIG_NAME_MAX_CHARS + 1);
        let cases = vec![
            (
                &ROUTES_SECTION,
                vec![
                    String::from("--name"),
                    name.clone(),
                    String::from("--kid"),
                    "a".repeat(64),
                    String::from("--final-app-addr"),
                    String::from("localhost:3999"),
                    String::from("--final-app-path"),
                    String::from("/message"),
                ],
                "name exceeds maximum allowed length: 128",
            ),
            (
                &REMOTE_ROUTES_SECTION,
                vec![
                    String::from("--name"),
                    name.clone(),
                    String::from("--remote-kid"),
                    "b".repeat(64),
                    String::from("--remote-addr"),
                    String::from("localhost:3001"),
                    String::from("--allowed-local-kid"),
                    String::from("*"),
                ],
                "name exceeds maximum allowed length: 128",
            ),
            (
                &PERMISSIONS_SECTION,
                vec![
                    String::from("--client"),
                    name.clone(),
                    String::from("--apikey-hash"),
                    "c".repeat(64),
                ],
                "client exceeds maximum allowed length: 128",
            ),
            (
                &FPE_PROFILES_SECTION,
                valid_fpe_profile_args(&name, "6", "32"),
                "fpe_profiles.name exceeds maximum allowed length: 128",
            ),
            (
                &TOKENIZATION_PROFILES_SECTION,
                {
                    let mut args = valid_token_profile_args("32", "1024");
                    args[1] = name;
                    args
                },
                "tokenization_profiles.name exceeds maximum allowed length: 128",
            ),
        ];

        for (section, args, expected) in cases {
            let err = parse_section_add(section, args)
                .expect_err("overlong config name must fail in parser");
            assert_eq!(err.to_string(), expected);
        }
    }

    #[test]
    fn field_parser_applies_defaults_and_rejects_empty_update() {
        let permission = parse_section_add(
            &PERMISSIONS_SECTION,
            vec![
                String::from("--client"),
                String::from("app-a"),
                String::from("--apikey-hash"),
                "b".repeat(64),
            ],
        )
        .expect("permission must parse");
        assert_eq!(permission["status"], DEFAULT_PERMISSION_STATUS);
        assert_eq!(permission["permissions"].as_array().unwrap().len(), 0);

        let err = parse_section_update(&PERMISSIONS_SECTION, Vec::new())
            .expect_err("empty update must fail");
        assert_eq!(
            err.to_string(),
            "permissions update requires at least one field"
        );
    }

    #[test]
    fn special_parser_accepts_repeated_allowed_local_kids() {
        let parsed = parse_section_add(
            &REMOTE_ROUTES_SECTION,
            vec![
                String::from("--name"),
                String::from("clinic-b"),
                String::from("--remote-kid"),
                "b".repeat(64),
                String::from("--remote-addr"),
                String::from("localhost:3001"),
                String::from("--allowed-local-kid"),
                "a".repeat(64),
                String::from("--allowed-local-kid"),
                "c".repeat(64),
            ],
        )
        .expect("remote route must parse");
        assert_eq!(parsed["status"], DEFAULT_REMOTE_ROUTE_STATUS);
        assert_eq!(parsed["allowed_local_kids"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn special_parser_rejects_bad_allowed_local_kid_combinations() {
        let err = parse_section_add(
            &REMOTE_ROUTES_SECTION,
            vec![
                String::from("--name"),
                String::from("clinic-b"),
                String::from("--remote-kid"),
                "b".repeat(64),
                String::from("--remote-addr"),
                String::from("localhost:3001"),
            ],
        )
        .expect_err("missing allowed local kid must fail");
        assert_eq!(err.to_string(), "--allowed-local-kid is required");

        let err = parse_section_add(
            &REMOTE_ROUTES_SECTION,
            vec![
                String::from("--name"),
                String::from("clinic-b"),
                String::from("--remote-kid"),
                "b".repeat(64),
                String::from("--remote-addr"),
                String::from("localhost:3001"),
                String::from("--allowed-local-kid"),
                String::from("*"),
                String::from("--allowed-local-kid"),
                "a".repeat(64),
            ],
        )
        .expect_err("wildcard mixed with explicit kid must fail");
        assert_eq!(
            err.to_string(),
            "--allowed-local-kid * cannot be mixed with explicit kids"
        );
    }

    #[test]
    fn special_parser_update_accepts_only_allowed_local_kids() {
        let parsed = parse_section_update(
            &REMOTE_ROUTES_SECTION,
            vec![
                String::from("--allowed-local-kid"),
                "a".repeat(64),
                String::from("--allowed-local-kid"),
                "b".repeat(64),
            ],
        )
        .expect("allowed local kid only update must parse");
        assert_eq!(parsed["allowed_local_kids"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn permission_grant_parser_rejects_missing_required_fields() {
        let missing_kid =
            parse_permission_action_fields(vec![String::from("--action"), String::from("message")])
                .expect_err("missing kid must fail");
        assert_eq!(missing_kid.to_string(), "--kid is required");

        let missing_action =
            parse_permission_action_fields(vec![String::from("--kid"), "a".repeat(64)])
                .expect_err("missing action must fail");
        assert_eq!(missing_action.to_string(), "--action is required");
    }

    #[test]
    fn route_add_and_get_use_name() {
        let mut local = local_config();
        let kid = "a".repeat(64);
        let value = parse_section_add(
            &ROUTES_SECTION,
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
        section_add_value(&mut local, &ROUTES_SECTION, value).unwrap();

        let route = section_get(&local, &ROUTES_SECTION, vec![String::from("app-a")]).unwrap();
        assert_eq!(route["name"], "app-a");
    }

    #[test]
    fn generic_section_update_delete_and_missing_target_work() {
        let mut local = local_config();
        let value = parse_section_add(
            &ROUTES_SECTION,
            vec![
                String::from("--name"),
                String::from("app-a"),
                String::from("--kid"),
                "a".repeat(64),
                String::from("--final-app-addr"),
                String::from("localhost:3999"),
                String::from("--final-app-path"),
                String::from("/message"),
            ],
        )
        .unwrap();
        section_add_value(&mut local, &ROUTES_SECTION, value).unwrap();

        section_update(
            &mut local,
            &ROUTES_SECTION,
            vec![
                String::from("app-a"),
                String::from("--final-app-addr"),
                String::from("localhost:4999"),
            ],
        )
        .unwrap();
        let route = section_get(&local, &ROUTES_SECTION, vec![String::from("app-a")]).unwrap();
        assert_eq!(route["final_app_addr"], "localhost:4999");

        assert!(section_get(&local, &ROUTES_SECTION, vec![String::from("missing")]).is_err());
        let deleted = section_delete(&mut local, &ROUTES_SECTION, vec![String::from("app-a")])
            .expect("route should delete");
        assert_eq!(deleted["status"], "deleted");
        assert!(array_ref(&local.value, "routes").unwrap().is_empty());
    }

    #[test]
    fn permission_grant_and_revoke_updates_actions() {
        let mut local = local_config();
        let value = parse_section_add(
            &PERMISSIONS_SECTION,
            vec![
                String::from("--client"),
                String::from("app-a"),
                String::from("--apikey-hash"),
                "b".repeat(64),
            ],
        )
        .unwrap();
        section_add_value(&mut local, &PERMISSIONS_SECTION, value).unwrap();
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

        let item = section_get(&local, &PERMISSIONS_SECTION, vec![String::from("app-a")]).unwrap();
        assert_eq!(item["permissions"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn fpe_profile_add_get_update_and_delete_use_name() {
        let mut local = local_config();
        let value = parse_section_add(
            &FPE_PROFILES_SECTION,
            vec![
                String::from("--name"),
                String::from("patient-id"),
                String::from("--kid"),
                "a".repeat(64),
                String::from("--alphabet"),
                String::from("0123456789"),
                String::from("--min-len"),
                String::from("6"),
                String::from("--max-len"),
                String::from("32"),
                String::from("--tweak-aad"),
                String::from("tenant=acme;field=patient_id;version=1"),
            ],
        )
        .unwrap();
        section_add_value(&mut local, &FPE_PROFILES_SECTION, value).unwrap();

        let profile = section_get(
            &local,
            &FPE_PROFILES_SECTION,
            vec![String::from("patient-id")],
        )
        .unwrap();
        assert_eq!(profile["kid"], "a".repeat(64));

        section_update(
            &mut local,
            &FPE_PROFILES_SECTION,
            vec![
                String::from("patient-id"),
                String::from("--max-len"),
                String::from("40"),
            ],
        )
        .unwrap();
        let profile = section_get(
            &local,
            &FPE_PROFILES_SECTION,
            vec![String::from("patient-id")],
        )
        .unwrap();
        assert_eq!(profile["max_len"], 40);

        section_delete(
            &mut local,
            &FPE_PROFILES_SECTION,
            vec![String::from("patient-id")],
        )
        .unwrap();
        assert!(array_ref(&local.value, "fpe_profiles").unwrap().is_empty());
    }

    #[test]
    fn token_profile_add_get_update_and_delete_use_name() {
        let mut local = local_config();
        let value = parse_section_add(
            &TOKENIZATION_PROFILES_SECTION,
            valid_token_profile_args("32", "1024"),
        )
        .unwrap();
        section_add_value(&mut local, &TOKENIZATION_PROFILES_SECTION, value).unwrap();

        let profile = section_get(
            &local,
            &TOKENIZATION_PROFILES_SECTION,
            vec![String::from("patient-token")],
        )
        .unwrap();
        assert_eq!(profile["kid"], "a".repeat(64));

        section_update(
            &mut local,
            &TOKENIZATION_PROFILES_SECTION,
            vec![
                String::from("patient-token"),
                String::from("--max-plaintext-len"),
                String::from("512"),
            ],
        )
        .unwrap();
        let profile = section_get(
            &local,
            &TOKENIZATION_PROFILES_SECTION,
            vec![String::from("patient-token")],
        )
        .unwrap();
        assert_eq!(profile["max_plaintext_len"], 512);

        section_delete(
            &mut local,
            &TOKENIZATION_PROFILES_SECTION,
            vec![String::from("patient-token")],
        )
        .unwrap();
        assert!(
            array_ref(&local.value, "tokenization_profiles")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn token_profile_rejects_invalid_lengths_inline() {
        let short_token_len = parse_section_add(
            &TOKENIZATION_PROFILES_SECTION,
            valid_token_profile_args("4", "1024"),
        )
        .expect_err("short token length must fail during parsing");
        assert_eq!(
            short_token_len.to_string(),
            "tokenization_profiles.token_len must be at least 32"
        );

        let invalid_plaintext_len = parse_section_add(
            &TOKENIZATION_PROFILES_SECTION,
            valid_token_profile_args("32", "0"),
        )
        .expect_err("invalid plaintext length must fail during parsing");
        assert_eq!(
            invalid_plaintext_len.to_string(),
            "tokenization_profiles.max_plaintext_len must be between 1 and 1024"
        );
    }

    #[test]
    fn token_profile_rejects_overlong_prefix_inline() {
        let mut args = valid_token_profile_args("32", "1024");
        args[5] = "a".repeat(crate::core::tokenization::TOKEN_PREFIX_MAX_CHARS + 1);
        let err = parse_section_add(&TOKENIZATION_PROFILES_SECTION, args)
            .expect_err("overlong token prefix must fail during parsing");
        assert_eq!(
            err.to_string(),
            "tokenization_profiles.token_prefix exceeds maximum allowed length: 16"
        );
    }

    #[test]
    fn token_profile_update_rejects_invalid_lengths_before_mutation() {
        let mut local = local_config();
        let value = parse_section_add(
            &TOKENIZATION_PROFILES_SECTION,
            valid_token_profile_args("32", "1024"),
        )
        .unwrap();
        section_add_value(&mut local, &TOKENIZATION_PROFILES_SECTION, value).unwrap();

        let before = local.value.clone();
        let short_token_len = section_update(
            &mut local,
            &TOKENIZATION_PROFILES_SECTION,
            vec![
                String::from("patient-token"),
                String::from("--token-len"),
                String::from("4"),
            ],
        )
        .expect_err("invalid token length must fail before mutation");
        assert_eq!(
            short_token_len.to_string(),
            "tokenization_profiles.token_len must be at least 32"
        );
        assert_eq!(local.value, before);

        let invalid_plaintext_len = section_update(
            &mut local,
            &TOKENIZATION_PROFILES_SECTION,
            vec![
                String::from("patient-token"),
                String::from("--max-plaintext-len"),
                String::from("0"),
            ],
        )
        .expect_err("invalid plaintext length must fail before mutation");
        assert_eq!(
            invalid_plaintext_len.to_string(),
            "tokenization_profiles.max_plaintext_len must be between 1 and 1024"
        );
        assert_eq!(local.value, before);
    }

    #[test]
    fn token_profile_update_rejects_overlong_prefix_before_mutation() {
        let mut local = local_config();
        let value = parse_section_add(
            &TOKENIZATION_PROFILES_SECTION,
            valid_token_profile_args("32", "1024"),
        )
        .unwrap();
        section_add_value(&mut local, &TOKENIZATION_PROFILES_SECTION, value).unwrap();

        let before = local.value.clone();
        let err = section_update(
            &mut local,
            &TOKENIZATION_PROFILES_SECTION,
            vec![
                String::from("patient-token"),
                String::from("--token-prefix"),
                "a".repeat(crate::core::tokenization::TOKEN_PREFIX_MAX_CHARS + 1),
            ],
        )
        .expect_err("overlong token prefix must fail before mutation");
        assert_eq!(
            err.to_string(),
            "tokenization_profiles.token_prefix exceeds maximum allowed length: 16"
        );
        assert_eq!(local.value, before);
    }

    #[test]
    fn mac_profile_add_get_update_and_delete_use_name() {
        let mut local = local_config();
        let value =
            parse_section_add(&MAC_PROFILES_SECTION, valid_mac_profile_args("pan-mac")).unwrap();
        section_add_value(&mut local, &MAC_PROFILES_SECTION, value).unwrap();

        let profile =
            section_get(&local, &MAC_PROFILES_SECTION, vec![String::from("pan-mac")]).unwrap();
        assert_eq!(profile["kid"], "a".repeat(64));

        section_update(
            &mut local,
            &MAC_PROFILES_SECTION,
            vec![
                String::from("pan-mac"),
                String::from("--context"),
                String::from("tenant=mx;field=pan;purpose=blind-index;version=2"),
            ],
        )
        .unwrap();
        let profile =
            section_get(&local, &MAC_PROFILES_SECTION, vec![String::from("pan-mac")]).unwrap();
        assert_eq!(
            profile["context"],
            "tenant=mx;field=pan;purpose=blind-index;version=2"
        );

        section_delete(
            &mut local,
            &MAC_PROFILES_SECTION,
            vec![String::from("pan-mac")],
        )
        .unwrap();
        assert!(array_ref(&local.value, "mac_profiles").unwrap().is_empty());
    }

    #[test]
    fn mac_profile_rejects_invalid_context_inline() {
        let mut args = valid_mac_profile_args("pan-mac");
        args[5] = String::from("tenant");
        let err = parse_section_add(&MAC_PROFILES_SECTION, args)
            .expect_err("malformed MAC context must fail during parsing");
        assert_eq!(
            err.to_string(),
            "mac_profiles.context labels must use key=value format"
        );
    }

    #[test]
    fn token_profile_name_must_be_aad_safe() {
        let err = parse_section_add(
            &TOKENIZATION_PROFILES_SECTION,
            vec![
                String::from("--name"),
                String::from("bad=name"),
                String::from("--kid"),
                "a".repeat(64),
                String::from("--token-prefix"),
                String::from("tok_patient"),
                String::from("--token-len"),
                String::from("32"),
                String::from("--max-plaintext-len"),
                String::from("1024"),
            ],
        )
        .expect_err("token profile name must reject AAD delimiters");

        assert_eq!(
            err.to_string(),
            "tokenization_profiles.name must not contain ';' or '='"
        );
    }

    #[test]
    fn fpe_profile_name_must_be_aad_safe() {
        for name in ["bad=name", "bad;name"] {
            let err = parse_section_add(
                &FPE_PROFILES_SECTION,
                vec![
                    String::from("--name"),
                    String::from(name),
                    String::from("--kid"),
                    "a".repeat(64),
                    String::from("--alphabet"),
                    String::from("0123456789"),
                    String::from("--min-len"),
                    String::from("6"),
                    String::from("--max-len"),
                    String::from("32"),
                    String::from("--tweak-aad"),
                    String::from("tenant=acme"),
                ],
            )
            .expect_err("FPE profile name must reject AAD delimiters");

            assert_eq!(
                err.to_string(),
                "fpe_profiles.name must not contain ';' or '='"
            );
        }
    }

    #[test]
    fn fpe_profile_rejects_invalid_fields() {
        assert!(
            parse_section_add(
                &FPE_PROFILES_SECTION,
                vec![
                    String::from("--name"),
                    String::from("patient-id"),
                    String::from("--kid"),
                    String::from("bad"),
                    String::from("--alphabet"),
                    String::from("0123456789"),
                    String::from("--min-len"),
                    String::from("6"),
                    String::from("--max-len"),
                    String::from("32"),
                    String::from("--tweak-aad"),
                    String::from("tenant=acme"),
                ]
            )
            .is_err()
        );
        assert!(
            parse_section_add(
                &FPE_PROFILES_SECTION,
                vec![
                    String::from("--name"),
                    String::from("patient-id"),
                    String::from("--kid"),
                    "a".repeat(64),
                    String::from("--alphabet"),
                    String::from("001234"),
                    String::from("--min-len"),
                    String::from("6"),
                    String::from("--max-len"),
                    String::from("32"),
                    String::from("--tweak-aad"),
                    String::from("tenant=acme"),
                ]
            )
            .is_err()
        );

        let invalid_tweak = parse_section_add(
            &FPE_PROFILES_SECTION,
            vec![
                String::from("--name"),
                String::from("patient-id"),
                String::from("--kid"),
                "a".repeat(64),
                String::from("--alphabet"),
                String::from("0123456789"),
                String::from("--min-len"),
                String::from("6"),
                String::from("--max-len"),
                String::from("32"),
                String::from("--tweak-aad"),
                String::from("tenant"),
            ],
        )
        .expect_err("malformed FPE tweak AAD must fail during parsing");
        assert_eq!(
            invalid_tweak.to_string(),
            "fpe_profiles.tweak_aad labels must use key=value format"
        );
    }

    #[test]
    fn fpe_profile_rejects_invalid_lengths_inline() {
        let short_min_len = parse_section_add(
            &FPE_PROFILES_SECTION,
            valid_fpe_profile_args("patient-id", "5", "32"),
        )
        .expect_err("short min length must fail during parsing");
        assert_eq!(
            short_min_len.to_string(),
            "fpe_profiles.min_len must be at least 6"
        );

        let oversized_max_len = parse_section_add(
            &FPE_PROFILES_SECTION,
            valid_fpe_profile_args("patient-id", "6", "1025"),
        )
        .expect_err("oversized max length must fail during parsing");
        assert_eq!(
            oversized_max_len.to_string(),
            "fpe_profiles.max_len exceeds maximum allowed value"
        );

        let invalid_bounds = parse_section_add(
            &FPE_PROFILES_SECTION,
            valid_fpe_profile_args("patient-id", "10", "9"),
        )
        .expect_err("max length below min length must fail during parsing");
        assert_eq!(
            invalid_bounds.to_string(),
            "fpe_profiles.max_len must be greater than or equal to min_len"
        );
    }

    #[test]
    fn fpe_profile_update_rejects_invalid_lengths_before_mutation() {
        let mut local = local_config();
        let value = parse_section_add(
            &FPE_PROFILES_SECTION,
            valid_fpe_profile_args("patient-id", "6", "32"),
        )
        .expect("seed profile must parse");
        section_add_value(&mut local, &FPE_PROFILES_SECTION, value).unwrap();

        let before = local.value.clone();
        let short_min_len = section_update(
            &mut local,
            &FPE_PROFILES_SECTION,
            vec![
                String::from("patient-id"),
                String::from("--min-len"),
                String::from("5"),
            ],
        )
        .expect_err("short min length must fail before mutation");
        assert_eq!(
            short_min_len.to_string(),
            "fpe_profiles.min_len must be at least 6"
        );
        assert_eq!(local.value, before);

        let oversized_max_len = section_update(
            &mut local,
            &FPE_PROFILES_SECTION,
            vec![
                String::from("patient-id"),
                String::from("--max-len"),
                String::from("1025"),
            ],
        )
        .expect_err("oversized max length must fail before mutation");
        assert_eq!(
            oversized_max_len.to_string(),
            "fpe_profiles.max_len exceeds maximum allowed value"
        );
        assert_eq!(local.value, before);
    }

    #[test]
    fn fpe_profile_domain_stays_in_full_config_validation() {
        let mut domain_local = local_config();
        let small_domain = parse_section_add(
            &FPE_PROFILES_SECTION,
            vec![
                String::from("--name"),
                String::from("small-domain"),
                String::from("--kid"),
                "a".repeat(64),
                String::from("--alphabet"),
                String::from("ABCDEF"),
                String::from("--min-len"),
                String::from("6"),
                String::from("--max-len"),
                String::from("32"),
                String::from("--tweak-aad"),
                String::from("tenant=acme"),
            ],
        )
        .expect("field parser only validates field-local values");
        section_add_value(&mut domain_local, &FPE_PROFILES_SECTION, small_domain).unwrap();
        assert_eq!(
            validate_local_config(&domain_local)
                .unwrap_err()
                .to_string(),
            "fpe profile domain is too small for FF1"
        );
    }

    #[test]
    fn fpe_profile_update_uses_full_config_validation_for_domain() {
        let mut local = local_config();
        let value = parse_section_add(
            &FPE_PROFILES_SECTION,
            vec![
                String::from("--name"),
                String::from("binary-id"),
                String::from("--kid"),
                "a".repeat(64),
                String::from("--alphabet"),
                String::from("01"),
                String::from("--min-len"),
                String::from("20"),
                String::from("--max-len"),
                String::from("32"),
                String::from("--tweak-aad"),
                String::from("tenant=acme;field=binary_id;version=1"),
            ],
        )
        .unwrap();
        section_add_value(&mut local, &FPE_PROFILES_SECTION, value).unwrap();
        validate_local_config(&local).expect("seed profile must validate");

        section_update(
            &mut local,
            &FPE_PROFILES_SECTION,
            vec![
                String::from("binary-id"),
                String::from("--min-len"),
                String::from("6"),
            ],
        )
        .expect("parser must not invent radix for partial update");

        let err = validate_local_config(&local)
            .expect_err("full config validation must reject the small binary domain");
        assert_eq!(err.to_string(), "fpe profile domain is too small for FF1");
    }
}
