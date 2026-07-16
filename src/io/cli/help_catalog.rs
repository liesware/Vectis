#[cfg(test)]
const DEFAULT_API_URL: &str = "http://127.0.0.1:3000";
#[cfg(test)]
const DEFAULT_TIMEOUT_SECONDS: &str = "30";

pub(crate) const EXECUTABLE_COMMANDS: &[&str] = &[
    "serve",
    "init",
    "apikey",
    "version",
    "health",
    "test",
    "keys",
    "lifecycle",
    "routes",
    "remote-routes",
    "permissions",
    "config",
    "pub",
    "sign",
    "fpe",
    "token",
    "message",
];

pub(crate) const HTTP_COMMANDS: &[&str] = &[
    "health",
    "test",
    "keys",
    "lifecycle",
    "routes",
    "remote-routes",
    "permissions",
    "config",
    "pub",
    "sign",
    "fpe",
    "token",
    "message",
];

pub(crate) const CONFIG_COMMANDS: &[&str] = &[
    "init",
    "validate",
    "sign",
    "list",
    "reload",
    "routes",
    "remote-routes",
    "permissions",
    "fpe",
    "token",
];

#[cfg(test)]
const HELP_COMMANDS: &[&str] = EXECUTABLE_COMMANDS;

pub(crate) struct CommandHelp {
    key: &'static str,
    heading: &'static str,
    usage: &'static [&'static str],
    summary: Option<&'static str>,
    sections: &'static [HelpSection],
    output: bool,
}

pub(crate) struct HelpSection {
    title: &'static str,
    lines: &'static [&'static str],
}

#[cfg(test)]
pub(crate) struct CommandLine {
    command: &'static str,
    description: &'static str,
}

#[cfg(test)]
impl CommandLine {
    const fn new(command: &'static str, description: &'static str) -> Self {
        Self {
            command,
            description,
        }
    }

    fn render(&self, out: &mut String) {
        out.push_str("  ");
        out.push_str(self.command);
        if !self.description.is_empty() {
            let padding = 22usize.saturating_sub(self.command.len());
            for _ in 0..padding {
                out.push(' ');
            }
            out.push_str(self.description);
        }
        out.push('\n');
    }
}

#[cfg(test)]
pub(crate) fn render_help(command: &str) -> String {
    render_command(command_help(command).unwrap_or_else(root_help))
}

pub(crate) fn render_help_path(path: &[&str]) -> String {
    debug_assert!(
        EXECUTABLE_COMMANDS.contains(&"serve"),
        "root executable command catalog must be initialized"
    );
    let fallback = if path.first() == Some(&"config") {
        config_help
    } else {
        root_help
    };
    render_command(best_help_path(path).unwrap_or_else(fallback))
}

pub(crate) fn root_help() -> &'static CommandHelp {
    &ROOT_HELP
}

pub(crate) fn config_help() -> &'static CommandHelp {
    &CONFIG_HELP
}

#[cfg(test)]
pub(crate) fn command_help(command: &str) -> Option<&'static CommandHelp> {
    command_help_path(&[command])
}

pub(crate) fn command_help_path(path: &[&str]) -> Option<&'static CommandHelp> {
    let key = path.join(" ");
    COMMAND_HELPS.iter().find(|help| help.key == key)
}

fn best_help_path(path: &[&str]) -> Option<&'static CommandHelp> {
    for len in (1..=path.len()).rev() {
        if let Some(help) = command_help_path(&path[..len]) {
            return Some(help);
        }
    }

    None
}

fn render_command(help: &CommandHelp) -> String {
    let mut out = String::new();
    out.push_str(help.heading);
    out.push('\n');
    for line in help.usage {
        out.push_str("  ");
        out.push_str(line);
        out.push('\n');
    }
    if let Some(summary) = help.summary {
        out.push('\n');
        out.push_str(summary);
        out.push('\n');
    }
    for section in help.sections {
        out.push('\n');
        out.push_str(section.title);
        out.push('\n');
        for line in section.lines {
            out.push_str(line);
            out.push('\n');
        }
    }
    if help.output {
        out.push('\n');
        out.push_str("Output:\n");
        out.push_str("  --output yaml         YAML output, default\n");
        out.push_str("  --output json         Pretty JSON output\n");
    }
    out
}

#[cfg(test)]
macro_rules! command_lines {
    ($($command:expr => $description:expr),+ $(,)?) => {{
        &[
            $(CommandLine::new($command, $description)),+
        ]
    }};
}

#[cfg(test)]
macro_rules! rendered_command_lines {
    ($($command:expr => $description:expr),+ $(,)?) => {{
        const LINES: &[CommandLine] = command_lines!($($command => $description),+);
        LINES
    }};
}

#[cfg(test)]
fn render_command_lines(lines: &[CommandLine]) -> Vec<String> {
    let mut rendered = Vec::with_capacity(lines.len());
    for line in lines {
        let mut out = String::new();
        line.render(&mut out);
        rendered.push(out.trim_end().to_string());
    }
    rendered
}

const ROOT_USAGE: &[&str] = &["vectis <command> [options]", "vectis help [command]"];

const ROOT_HELP: CommandHelp = CommandHelp {
    key: "",
    heading: "Usage:",
    usage: ROOT_USAGE,
    summary: None,
    sections: &[
        HelpSection {
            title: "Commands:",
            lines: &[
                "  serve                 Start the HTTP service",
                "  init                  Generate local key material in VECTIS_INIT_KEYS_FILE",
                "  apikey                Create additional local API keys",
                "  version               Print local build and compatibility information",
                "  health                Call the health probe endpoints",
                "  test                  Call protected test endpoints through HTTP",
                "  keys                  Create, list, or reload operational keys through HTTP",
                "  lifecycle             Update operational key lifecycle metadata",
                "  routes                List final app routes",
                "  remote-routes         List remote Vectis routes",
                "  permissions           List loaded API key permissions",
                "  config                Validate, sign, list, or reload the unified signed config",
                "  pub                   Fetch public keys through HTTP",
                "  sign                  Create or verify timestamp signatures through HTTP",
                "  fpe                   Encrypt or decrypt field values through HTTP",
                "  token                 Encode or decode reversible random tokens through HTTP",
                "  message               Send, receive, encrypt, or decrypt messages through HTTP",
            ],
        },
        HelpSection {
            title: "Examples:",
            lines: &[
                "  vectis init",
                "  vectis apikey create",
                "  vectis version --output json",
                "  vectis serve",
                "  vectis health ready",
                "  vectis keys create --tag payments --profile hybrid-high-assurance-v1",
                "  vectis lifecycle <kid> --status disabled --reason maintenance",
                "  vectis routes list",
                "  vectis config validate",
                "  vectis config sign",
                "  vectis sign <kid> --file sign-request.json",
                "  vectis fpe encrypt <kid> --file fpe-encrypt.json",
                "  vectis token encode <kid> --file token-encode.json",
            ],
        },
        HelpSection {
            title: "Help:",
            lines: &[
                "  vectis help init",
                "  vectis help apikey",
                "  vectis help version",
                "  vectis help health",
                "  vectis help test",
                "  vectis help keys",
                "  vectis help lifecycle",
                "  vectis help routes",
                "  vectis help remote-routes",
                "  vectis help permissions",
                "  vectis help config",
                "  vectis help config token",
                "  vectis help pub",
                "  vectis help sign",
                "  vectis help fpe",
                "  vectis help token",
                "  vectis help message",
            ],
        },
        HelpSection {
            title: "Environment:",
            lines: &[
                "  VECTIS_API_URL        API base URL, default http://127.0.0.1:3000",
                "  VECTIS_APIKEY         Client secret for protected API commands",
                "  VECTIS_TIMEOUT_SECONDS Request timeout, default 30",
                "  VECTIS_TLS_SKIP_VERIFY Disable outbound TLS verification for HTTPS clients",
            ],
        },
    ],
    output: false,
};

const SERVE_HELP: CommandHelp = CommandHelp {
    key: "serve",
    heading: "Usage:",
    usage: &["vectis serve"],
    summary: Some("Starts the Vectis HTTP service."),
    sections: &[
        HelpSection {
            title: "Startup:",
            lines: &[
                "Before the server starts, Vectis decrypts and validates VECTIS_INIT_KEYS_FILE.",
                "Provide VECTIS_UNSEAL_KEY, VECTIS_UNSEAL_KEY_FILE, or type it at the hidden prompt.",
            ],
        },
        HelpSection {
            title: "Required files:",
            lines: &[
                "  VECTIS_INIT_KEYS_FILE Encrypted local init key material, default init.json",
                "  src/db/data.db        Default SQLite database in debug builds",
            ],
        },
        HelpSection {
            title: "Common environment:",
            lines: &[
                "  VECTIS_UNSEAL_KEY     64 hex characters, not read from .env",
                "  VECTIS_UNSEAL_KEY_FILE Path to unseal key file, default .unseal_key",
                "  VECTIS_HTTP_BIND_ADDR Listen address, default 127.0.0.1:3000",
                "  VECTIS_MODE           dev uses http, prod uses https, default dev",
                "  VECTIS_TLS_CERT_PATH  PEM certificate path when VECTIS_MODE=prod",
                "  VECTIS_TLS_KEY_PATH   PEM private key path when VECTIS_MODE=prod",
                "  VECTIS_APIKEY_HASH    Required by protected endpoints",
            ],
        },
    ],
    output: false,
};

const INIT_HELP: CommandHelp = CommandHelp {
    key: "init",
    heading: "Usage:",
    usage: &["vectis init"],
    summary: Some(
        "Generates local bootstrap key material and writes encrypted VECTIS_INIT_KEYS_FILE.",
    ),
    sections: &[
        HelpSection {
            title: "Behavior:",
            lines: &["If the file already exists, init refuses to overwrite it."],
        },
        HelpSection {
            title: "Output:",
            lines: &[
                "  VECTIS_INIT_KEYS_FILE Encrypted key file, default init.json",
                "  VECTIS_UNSEAL_KEY=... Key used later by serve to decrypt the configured init keys file",
                "  VECTIS_APIKEY=...     Client API key for protected HTTP endpoints",
                "  VECTIS_APIKEY_HASH=... Server-side API key hash for protected HTTP endpoints",
            ],
        },
        HelpSection {
            title: "Security:",
            lines: &[
                "  Delete the configured init keys file manually before reinitializing.",
                "  Do not store VECTIS_UNSEAL_KEY in .env for production.",
            ],
        },
    ],
    output: false,
};

const APIKEY_HELP: CommandHelp = CommandHelp {
    key: "apikey",
    heading: "Usage:",
    usage: &["vectis apikey create [--output <yaml|json>]"],
    summary: Some("Creates a new client API key and its server-side verifier."),
    sections: &[
        HelpSection {
            title: "Behavior:",
            lines: &[
                "This is a local command. It decrypts VECTIS_INIT_KEYS_FILE, derives the internal API auth key,",
                "prints the new values, and does not write files or call the HTTP API.",
            ],
        },
        HelpSection {
            title: "Output:",
            lines: &[
                "  VECTIS_APIKEY         Client secret sent as X-API-Key",
                "  VECTIS_APIKEY_HASH    Server-side HMAC verifier for protected endpoints",
            ],
        },
        HelpSection {
            title: "Options:",
            lines: &[
                "  --output yaml         YAML output, default",
                "  --output json         Pretty JSON output",
            ],
        },
        HelpSection {
            title: "Required local material:",
            lines: &[
                "  VECTIS_INIT_KEYS_FILE Encrypted local init key material, default init.json",
                "  VECTIS_UNSEAL_KEY     64 hex characters, or",
                "  VECTIS_UNSEAL_KEY_FILE Path to unseal key file, default .unseal_key",
            ],
        },
    ],
    output: false,
};

const VERSION_HELP: CommandHelp = CommandHelp {
    key: "version",
    heading: "Usage:",
    usage: &["vectis version [--output <yaml|json>]"],
    summary: Some("Prints local Vectis build and compatibility information."),
    sections: &[
        HelpSection {
            title: "Behavior:",
            lines: &[
                "This is a local command. It does not read .env, init material, unseal keys, storage,",
                "signed config, or the network.",
            ],
        },
        HelpSection {
            title: "Output fields:",
            lines: &[
                "  version               Cargo package version",
                "  protocol_version      Supported Vectis protocol version",
                "  internal_primitives   Internal hash, HKDF, HMAC, and cipher constants",
                "  crypto_profiles       Supported key generation profiles",
                "  crypto_policies       Supported crypto policy modes",
                "  algorithms            Supported hash, cipher, signature, KEM, FPE, and token versions",
            ],
        },
    ],
    output: true,
};

const HEALTH_HELP: CommandHelp = CommandHelp {
    key: "health",
    heading: "Usage:",
    usage: &[
        "vectis health startup",
        "vectis health live",
        "vectis health ready",
    ],
    summary: Some("Calls public health probe endpoints."),
    sections: &[
        HelpSection {
            title: "Endpoints:",
            lines: &[
                "  startup               GET /healthz/startup",
                "  live                  GET /healthz/live",
                "  ready                 GET /healthz/ready",
            ],
        },
        HelpSection {
            title: "Environment:",
            lines: &[
                "  VECTIS_API_URL        API base URL, default http://127.0.0.1:3000",
                "  VECTIS_TIMEOUT_SECONDS Request timeout, default 30",
            ],
        },
    ],
    output: true,
};

const TEST_HELP: CommandHelp = CommandHelp {
    key: "test",
    heading: "Usage:",
    usage: &["vectis test init", "vectis test <kid>"],
    summary: Some("Calls protected key validation endpoints."),
    sections: &[
        HelpSection {
            title: "Arguments:",
            lines: &["  kid                   64-character hex key id"],
        },
        HelpSection {
            title: "Endpoints:",
            lines: &[
                "  init                  GET /self-test/init",
                "  <kid>                 GET /self-test/keys/{kid}",
            ],
        },
        HelpSection {
            title: "Required environment:",
            lines: &["  VECTIS_APIKEY         64-character hex API key"],
        },
    ],
    output: true,
};

const KEYS_HELP: CommandHelp = CommandHelp {
    key: "keys",
    heading: "Usage:",
    usage: &[
        "vectis keys create [--tag <tag>] [--profile <profile>]",
        "vectis keys list",
        "vectis keys properties",
        "vectis keys properties <kid>",
        "vectis keys reload",
    ],
    summary: Some("Creates, lists, or reloads operational keys through the HTTP API."),
    sections: &[
        HelpSection {
            title: "Commands:",
            lines: &[
                "  create                POST /keys, requires VECTIS_APIKEY",
                "  list                  GET /keys, public",
                "  properties            GET /keys/properties, requires VECTIS_APIKEY",
                "  properties <kid>      GET /keys/properties/{kid}, requires VECTIS_APIKEY",
                "  reload                POST /keys/reload, requires VECTIS_APIKEY",
            ],
        },
        HelpSection {
            title: "Create options:",
            lines: &[
                "  --tag <tag>           Optional label for the key",
                "  --profile <profile>   Optional crypto profile",
            ],
        },
        HelpSection {
            title: "Profiles:",
            lines: &[
                "  hybrid-performance-v1",
                "  hybrid-high-assurance-v1",
                "  hybrid-long-term-v1",
            ],
        },
        HelpSection {
            title: "Examples:",
            lines: &[
                "  vectis keys create --tag payments --profile hybrid-high-assurance-v1",
                "  vectis keys list",
                "  vectis keys properties",
                "  vectis keys properties <kid>",
                "  vectis keys reload",
            ],
        },
    ],
    output: true,
};

const LIFECYCLE_HELP: CommandHelp = CommandHelp {
    key: "lifecycle",
    heading: "Usage:",
    usage: &["vectis lifecycle <kid> --status <status> --reason <reason>"],
    summary: Some("Updates encrypted lifecycle metadata for an operational key."),
    sections: &[
        HelpSection {
            title: "Arguments:",
            lines: &["  kid                   64-character hex key id"],
        },
        HelpSection {
            title: "Options:",
            lines: &[
                "  --status <status>     active, disabled, retired, compromised, or destroyed",
                "  --reason <reason>     Non-empty reason for the lifecycle change",
            ],
        },
        HelpSection {
            title: "Endpoint:",
            lines: &["  POST /lifecycle/{kid}, requires VECTIS_APIKEY"],
        },
        HelpSection {
            title: "Examples:",
            lines: &[
                "  vectis lifecycle <kid> --status disabled --reason maintenance",
                "  vectis lifecycle <kid> --status active --reason restored",
            ],
        },
    ],
    output: true,
};

const ROUTES_HELP: CommandHelp = CommandHelp {
    key: "routes",
    heading: "Usage:",
    usage: &["vectis routes list"],
    summary: Some("Lists final app routes currently loaded in memory."),
    sections: &[
        HelpSection {
            title: "Commands:",
            lines: &["  list                  GET /routes, requires VECTIS_APIKEY"],
        },
        HelpSection {
            title: "Behavior:",
            lines: &["  list                  Returns routes currently loaded in memory"],
        },
        HelpSection {
            title: "Notes:",
            lines: &["  Use `vectis config reload` to reload the unified signed config."],
        },
    ],
    output: true,
};

const REMOTE_ROUTES_HELP: CommandHelp = CommandHelp {
    key: "remote-routes",
    heading: "Usage:",
    usage: &["vectis remote-routes list"],
    summary: Some("Lists authorized remote Vectis routes currently loaded in memory."),
    sections: &[
        HelpSection {
            title: "Commands:",
            lines: &["  list                  GET /remote-routes, requires VECTIS_APIKEY"],
        },
        HelpSection {
            title: "Behavior:",
            lines: &["  list                  Returns remote routes currently loaded in memory"],
        },
        HelpSection {
            title: "Notes:",
            lines: &["  Use `vectis config reload` to reload the unified signed config."],
        },
    ],
    output: true,
};

const PERMISSIONS_HELP: CommandHelp = CommandHelp {
    key: "permissions",
    heading: "Usage:",
    usage: &["vectis permissions list"],
    summary: Some("Lists effective API key permissions currently loaded in memory."),
    sections: &[
        HelpSection {
            title: "Commands:",
            lines: &["  list                  GET /permissions, requires admin VECTIS_APIKEY"],
        },
        HelpSection {
            title: "Behavior:",
            lines: &[
                "  list                  Returns active permission clients without apikey_hash",
            ],
        },
        HelpSection {
            title: "Notes:",
            lines: &["  Use `vectis config reload` to reload the unified signed config."],
        },
    ],
    output: true,
};

const CONFIG_HELP: CommandHelp = CommandHelp {
    key: "config",
    heading: "Usage:",
    usage: &[
        "vectis config init",
        "vectis config validate",
        "vectis config sign",
        "vectis config list",
        "vectis config reload",
        "vectis config routes list",
        "vectis config routes add --name <name> --kid <kid> --final-app-addr <host:port> --final-app-path <path>",
        "vectis config routes get <name>",
        "vectis config routes update <name> [--kid <kid>] [--final-app-addr <host:port>] [--final-app-path <path>]",
        "vectis config routes delete <name>",
        "vectis config remote-routes list",
        "vectis config remote-routes add --name <name> --remote-kid <kid> --remote-addr <host:port> --allowed-local-kid <kid|*> [--status active|disabled]",
        "vectis config remote-routes get <name>",
        "vectis config remote-routes update <name> [--remote-kid <kid>] [--remote-addr <host:port>] [--allowed-local-kid <kid|*>...] [--status active|disabled]",
        "vectis config remote-routes delete <name>",
        "vectis config permissions list",
        "vectis config permissions add --client <client> --apikey-hash <hex> [--status active|disabled|revoked]",
        "vectis config permissions get <client>",
        "vectis config permissions update <client> [--apikey-hash <hex>] [--status active|disabled|revoked]",
        "vectis config permissions delete <client>",
        "vectis config permissions grant <client> --kid <kid|*> --action <action>",
        "vectis config permissions revoke <client> --kid <kid|*> --action <action>",
        "vectis config fpe list",
        "vectis config fpe add --name <name> --kid <kid> --alphabet <chars> --min-len <n> --max-len <n> --tweak-aad <aad> [--fpe-version fpe-ff1-2025]",
        "vectis config fpe get <name>",
        "vectis config fpe update <name> [--kid <kid>] [--alphabet <chars>] [--min-len <n>] [--max-len <n>] [--tweak-aad <aad>] [--fpe-version fpe-ff1-2025]",
        "vectis config fpe delete <name>",
        "vectis config token list",
        "vectis config token add --name <name> --kid <kid> --token-prefix <prefix> --token-len <n> --max-plaintext-len <n> [--tokenization-version token-random-v1]",
        "vectis config token get <name>",
        "vectis config token update <name> [--kid <kid>] [--token-prefix <prefix>] [--token-len <n>] [--max-plaintext-len <n>] [--tokenization-version token-random-v1]",
        "vectis config token delete <name>",
    ],
    summary: Some("Validates, signs, prints, reloads, or edits the unified signed config file."),
    sections: &[
        HelpSection {
            title: "Commands:",
            lines: &[
                "  init                  Creates an empty VECTIS_CONFIG_PATH skeleton (local)",
                "  validate              Validates VECTIS_CONFIG_PATH against local init/storage/keys",
                "  sign                  Validates and signs VECTIS_CONFIG_PATH with init keys (local)",
                "  list                  Prints VECTIS_CONFIG_PATH (local)",
                "  reload                POST /config/reload, requires admin VECTIS_APIKEY",
                "  routes                Edits local config routes by unique name",
                "  remote-routes         Edits local config remote_routes by unique name",
                "  permissions           Edits local config permissions by unique client",
                "  fpe                   Edits local config FPE profiles by unique name",
                "  token                 Edits local config tokenization profiles by unique name",
            ],
        },
        HelpSection {
            title: "Behavior:",
            lines: &[
                "  edit commands modify VECTIS_CONFIG_PATH only",
                "  config validate is local; it opens configured storage and does not read config_sign.json",
                "  config sign validates first and does not write config_sign.json if validation fails",
                "  remote-routes add fetches public keys from remote /pub/{kid}",
                "  remote-routes update re-fetches keys when remote_kid or remote_addr changes",
                "  quote \"*\" for wildcard KIDs so the shell does not expand it",
                "  permissions add/update manages clients and apikey_hash",
                "  permissions grant/revoke only manages kid/action grants",
                "  section list commands print one local config array only",
                "  config fpe edits signed FPE field profiles; min_len must be at least 6",
                "  config token edits signed reversible tokenization profiles",
                "  edit commands do not sign or reload automatically",
            ],
        },
        HelpSection {
            title: "Environment:",
            lines: &[
                "  VECTIS_CONFIG_PATH      Config JSON path, default config.json",
                "  VECTIS_CONFIG_SIGN_PATH Signature JSON path, default config_sign.json",
            ],
        },
        HelpSection {
            title: "Examples:",
            lines: &[
                "  vectis config init",
                "  vectis config validate",
                "  vectis config sign",
                "  vectis config reload",
                "  vectis config routes list",
                "  vectis config routes add --name app-a --kid <kid> --final-app-addr 127.0.0.1:3999 --final-app-path /message",
                "  vectis config remote-routes add --name clinic-b --remote-kid <kid> --remote-addr vectis-b.example.com:443 --allowed-local-kid \"*\" --status active",
                "  vectis config permissions add --client \"Acme App\" --apikey-hash <hex> --status active",
                "  vectis config permissions grant \"Acme App\" --kid \"*\" --action admin",
                "  vectis config permissions grant \"Acme App\" --kid <kid> --action message",
                "  vectis config fpe add --name patient-id-decimal-v1 --kid <kid> --alphabet 0123456789 --min-len 6 --max-len 32 --tweak-aad tenant=acme\\;field=patient_id\\;version=1",
                "  vectis config token add --name patient-id-token-v1 --kid <kid> --token-prefix tok_patient --token-len 32 --max-plaintext-len 1024",
            ],
        },
    ],
    output: true,
};

const CONFIG_ROUTES_HELP: CommandHelp = CommandHelp {
    key: "config routes",
    heading: "Usage:",
    usage: &[
        "vectis config routes list",
        "vectis config routes add --name <name> --kid <kid> --final-app-addr <host:port> --final-app-path <path>",
        "vectis config routes get <name>",
        "vectis config routes update <name> [--kid <kid>] [--final-app-addr <host:port>] [--final-app-path <path>]",
        "vectis config routes delete <name>",
    ],
    summary: Some("Lists or edits local config routes by unique name."),
    sections: &[
        HelpSection {
            title: "Behavior:",
            lines: &[
                "  edits VECTIS_CONFIG_PATH only",
                "  name must be unique",
                "  run `vectis config sign`, then `vectis config reload` after edits",
            ],
        },
        HelpSection {
            title: "Example:",
            lines: &[
                "  vectis config routes add --name app-a --kid <kid> --final-app-addr 127.0.0.1:3999 --final-app-path /message",
            ],
        },
    ],
    output: true,
};

const CONFIG_REMOTE_ROUTES_HELP: CommandHelp = CommandHelp {
    key: "config remote-routes",
    heading: "Usage:",
    usage: &[
        "vectis config remote-routes list",
        "vectis config remote-routes add --name <name> --remote-kid <kid> --remote-addr <host:port> --allowed-local-kid <kid|*> [--status active|disabled]",
        "vectis config remote-routes get <name>",
        "vectis config remote-routes update <name> [--remote-kid <kid>] [--remote-addr <host:port>] [--allowed-local-kid <kid|*>...] [--status active|disabled]",
        "vectis config remote-routes delete <name>",
    ],
    summary: Some("Lists or edits local config remote_routes by unique name."),
    sections: &[
        HelpSection {
            title: "Behavior:",
            lines: &[
                "  edits VECTIS_CONFIG_PATH only",
                "  add fetches public keys from remote /pub/{kid}",
                "  update re-fetches keys when remote_kid or remote_addr changes",
                "  quote \"*\" for wildcard KIDs so the shell does not expand it",
            ],
        },
        HelpSection {
            title: "Example:",
            lines: &[
                "  vectis config remote-routes add --name clinic-b --remote-kid <kid> --remote-addr vectis-b.example.com:443 --allowed-local-kid \"*\" --status active",
            ],
        },
    ],
    output: true,
};

const CONFIG_PERMISSIONS_HELP: CommandHelp = CommandHelp {
    key: "config permissions",
    heading: "Usage:",
    usage: &[
        "vectis config permissions list",
        "vectis config permissions add --client <client> --apikey-hash <hex> [--status active|disabled|revoked]",
        "vectis config permissions get <client>",
        "vectis config permissions update <client> [--apikey-hash <hex>] [--status active|disabled|revoked]",
        "vectis config permissions delete <client>",
        "vectis config permissions grant <client> --kid <kid|*> --action <action>",
        "vectis config permissions revoke <client> --kid <kid|*> --action <action>",
    ],
    summary: Some("Lists or edits local config permissions by unique client."),
    sections: &[
        HelpSection {
            title: "Behavior:",
            lines: &[
                "  edits VECTIS_CONFIG_PATH only",
                "  add/update manages clients and apikey_hash",
                "  grant/revoke only manages kid/action grants",
                "  wildcard KIDs are only valid for global actions",
            ],
        },
        HelpSection {
            title: "Examples:",
            lines: &[
                "  vectis config permissions add --client \"Acme App\" --apikey-hash <hex> --status active",
                "  vectis config permissions grant \"Acme App\" --kid <kid> --action message",
            ],
        },
    ],
    output: true,
};

const CONFIG_FPE_HELP: CommandHelp = CommandHelp {
    key: "config fpe",
    heading: "Usage:",
    usage: &[
        "vectis config fpe list",
        "vectis config fpe add --name <name> --kid <kid> --alphabet <chars> --min-len <n> --max-len <n> --tweak-aad <aad> [--fpe-version fpe-ff1-2025]",
        "vectis config fpe get <name>",
        "vectis config fpe update <name> [--kid <kid>] [--alphabet <chars>] [--min-len <n>] [--max-len <n>] [--tweak-aad <aad>] [--fpe-version fpe-ff1-2025]",
        "vectis config fpe delete <name>",
    ],
    summary: Some("Lists or edits local config FPE profiles by unique name."),
    sections: &[
        HelpSection {
            title: "Behavior:",
            lines: &[
                "  edits fpe_profiles in VECTIS_CONFIG_PATH only",
                "  min_len must be at least 6",
                "  run `vectis config sign`, then `vectis config reload` after edits",
            ],
        },
        HelpSection {
            title: "Example:",
            lines: &[
                "  vectis config fpe add --name patient-id-decimal-v1 --kid <kid> --alphabet 0123456789 --min-len 6 --max-len 32 --tweak-aad tenant=acme\\;field=patient_id\\;version=1",
            ],
        },
    ],
    output: true,
};

const CONFIG_TOKEN_HELP: CommandHelp = CommandHelp {
    key: "config token",
    heading: "Usage:",
    usage: &[
        "vectis config token list",
        "vectis config token add --name <name> --kid <kid> --token-prefix <prefix> --token-len <n> --max-plaintext-len <n> [--tokenization-version token-random-v1]",
        "vectis config token get <name>",
        "vectis config token update <name> [--kid <kid>] [--token-prefix <prefix>] [--token-len <n>] [--max-plaintext-len <n>] [--tokenization-version token-random-v1]",
        "vectis config token delete <name>",
    ],
    summary: Some("Lists or edits local config tokenization profiles by unique name."),
    sections: &[
        HelpSection {
            title: "Behavior:",
            lines: &[
                "  edits tokenization_profiles in VECTIS_CONFIG_PATH only",
                "  token_len must be at least 32",
                "  run `vectis config sign`, then `vectis config reload` after edits",
            ],
        },
        HelpSection {
            title: "Example:",
            lines: &[
                "  vectis config token add --name patient-id-token-v1 --kid <kid> --token-prefix tok_patient --token-len 32 --max-plaintext-len 1024",
            ],
        },
    ],
    output: true,
};

const PUB_HELP: CommandHelp = CommandHelp {
    key: "pub",
    heading: "Usage:",
    usage: &["vectis pub <kid>"],
    summary: Some("Fetches public key material for a local operational key."),
    sections: &[
        HelpSection {
            title: "Arguments:",
            lines: &["  kid                   64-character hex key id"],
        },
        HelpSection {
            title: "Endpoint:",
            lines: &["  GET /pub/{kid}"],
        },
    ],
    output: true,
};

const SIGN_HELP: CommandHelp = CommandHelp {
    key: "sign",
    heading: "Usage:",
    usage: &[
        "vectis sign <kid> --json '<json>'",
        "vectis sign <kid> --file sign-request.json",
        "vectis sign verify --json '<json>'",
        "vectis sign verify --file token.json",
    ],
    summary: Some("Creates or verifies hybrid timestamp signatures."),
    sections: &[
        HelpSection {
            title: "Sign request JSON:",
            lines: &[r#"  {"message_hash":{"alg":"SHA-256","hex":"<64 hex chars>"}}"#],
        },
        HelpSection {
            title: "Endpoints:",
            lines: &[
                "  sign <kid>            POST /sign/{kid}, requires VECTIS_APIKEY",
                "  sign verify           POST /sign/verification, public",
            ],
        },
        HelpSection {
            title: "Input options:",
            lines: &[
                "  --json <json>         JSON object as a shell argument",
                "  --file <path>         Path to a JSON file",
            ],
        },
    ],
    output: true,
};

const FPE_HELP: CommandHelp = CommandHelp {
    key: "fpe",
    heading: "Usage:",
    usage: &[
        "vectis fpe encrypt <kid> --json '<json>'",
        "vectis fpe encrypt <kid> --file fpe-encrypt.json",
        "vectis fpe decrypt --json '<json>'",
        "vectis fpe decrypt --file fpe-decrypt.json",
    ],
    summary: Some("Encrypts or decrypts field values with signed-config FPE profiles."),
    sections: &[
        HelpSection {
            title: "Encrypt request JSON:",
            lines: &[r#"  {"profile":"patient-id-decimal-v1","plaintext":"123456"}"#],
        },
        HelpSection {
            title: "Decrypt request JSON:",
            lines: &[
                r#"  {"kid":"<kid>","profile":"patient-id-decimal-v1","ciphertext":"<value>"}"#,
            ],
        },
        HelpSection {
            title: "Endpoints:",
            lines: &[
                "  encrypt <kid>         POST /fpe/encrypt/{kid}, requires VECTIS_APIKEY",
                "  decrypt               POST /fpe/decrypt, requires VECTIS_APIKEY",
            ],
        },
        HelpSection {
            title: "Input options:",
            lines: &[
                "  --json <json>         JSON object as a shell argument",
                "  --file <path>         Path to a JSON file",
            ],
        },
    ],
    output: true,
};

const TOKEN_HELP: CommandHelp = CommandHelp {
    key: "token",
    heading: "Usage:",
    usage: &[
        "vectis token encode <kid> --json '<json>'",
        "vectis token encode <kid> --file token-encode.json",
        "vectis token decode --json '<json>'",
        "vectis token decode --file token-decode.json",
    ],
    summary: Some(
        "Encodes or decodes reversible random tokens with signed-config tokenization profiles.",
    ),
    sections: &[
        HelpSection {
            title: "Encode request JSON:",
            lines: &[r#"  {"profile":"patient-id-token-v1","plaintext":"123456","metadata":{}}"#],
        },
        HelpSection {
            title: "Decode request JSON:",
            lines: &[
                r#"  {"kid":"<kid>","profile":"patient-id-token-v1","token":"tok_patient_..."}"#,
            ],
        },
        HelpSection {
            title: "Endpoints:",
            lines: &[
                "  encode <kid>          POST /token/encode/{kid}, requires VECTIS_APIKEY",
                "  decode                POST /token/decode, requires VECTIS_APIKEY",
            ],
        },
        HelpSection {
            title: "Input options:",
            lines: &[
                "  --json <json>         JSON object as a shell argument",
                "  --file <path>         Path to a JSON file",
            ],
        },
    ],
    output: true,
};

const MESSAGE_HELP: CommandHelp = CommandHelp {
    key: "message",
    heading: "Usage:",
    usage: &[
        "vectis message send <sender_kid> --json '<json>'",
        "vectis message send <sender_kid> --file send-message.json",
        "vectis message receive --json '<json>'",
        "vectis message receive --file envelope.json",
        "vectis message decrypt --json '<json>'",
        "vectis message decrypt --file encrypted-message.json",
        "vectis message internal encrypt <kid> --json '<json>'",
        "vectis message internal encrypt <kid> --file plaintext.json",
        "vectis message internal decrypt --json '<json>'",
        "vectis message internal decrypt --file internal-message.json",
    ],
    summary: Some(
        "Sends protected messages, receives envelopes, and encrypts/decrypts internal messages.",
    ),
    sections: &[
        HelpSection {
            title: "Common JSON examples:",
            lines: &[
                r#"  send:              {"recipient_kid":"<kid>","message":"hello vectis"}"#,
                r#"  internal encrypt:  {"plaintext":"hello vectis"}"#,
            ],
        },
        HelpSection {
            title: "Endpoints:",
            lines: &[
                "  send                  POST /message/{sender_kid}, requires VECTIS_APIKEY",
                "  receive               POST /message, public",
                "  decrypt               POST /message/decrypt, requires VECTIS_APIKEY",
                "  internal encrypt      POST /message/internal/encrypt/{kid}, requires VECTIS_APIKEY",
                "  internal decrypt      POST /message/internal/decrypt, requires VECTIS_APIKEY",
            ],
        },
        HelpSection {
            title: "Input options:",
            lines: &[
                "  --json <json>         JSON object as a shell argument",
                "  --file <path>         Path to a JSON file",
            ],
        },
    ],
    output: true,
};

const COMMAND_HELPS: &[CommandHelp] = &[
    SERVE_HELP,
    INIT_HELP,
    APIKEY_HELP,
    VERSION_HELP,
    HEALTH_HELP,
    TEST_HELP,
    KEYS_HELP,
    LIFECYCLE_HELP,
    ROUTES_HELP,
    REMOTE_ROUTES_HELP,
    PERMISSIONS_HELP,
    CONFIG_HELP,
    CONFIG_ROUTES_HELP,
    CONFIG_REMOTE_ROUTES_HELP,
    CONFIG_PERMISSIONS_HELP,
    CONFIG_FPE_HELP,
    CONFIG_TOKEN_HELP,
    PUB_HELP,
    SIGN_HELP,
    FPE_HELP,
    TOKEN_HELP,
    MESSAGE_HELP,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_dispatch_commands_have_help() {
        for command in EXECUTABLE_COMMANDS {
            assert!(
                command_help(command).is_some(),
                "{command} dispatch command must have help"
            );
        }
    }

    #[test]
    fn all_http_commands_have_help() {
        for command in HTTP_COMMANDS {
            assert!(
                command_help(command).is_some(),
                "{command} HTTP command must have help"
            );
        }
    }

    #[test]
    fn all_help_commands_are_dispatch_commands() {
        for command in HELP_COMMANDS {
            assert!(
                EXECUTABLE_COMMANDS.contains(command),
                "{command} help command must be dispatched"
            );
        }
    }

    #[test]
    fn all_config_dispatch_commands_have_help() {
        let help = render_command(config_help());
        for command in CONFIG_COMMANDS {
            assert!(
                help.contains(&format!("  {command}")),
                "{command} config command must appear in config help"
            );
        }
    }

    #[test]
    fn root_help_lists_config_token() {
        let help = render_help("");
        assert!(
            help.contains(
                "  version               Print local build and compatibility information"
            )
        );
        assert!(
            help.contains("  fpe                   Encrypt or decrypt field values through HTTP")
        );
        assert!(help.contains(
            "  token                 Encode or decode reversible random tokens through HTTP"
        ));
        assert!(help.contains("vectis help config token"));
    }

    #[test]
    fn config_help_lists_token_usage_commands() {
        let help = render_help("config");
        assert!(help.contains("vectis config token list"));
        assert!(help.contains("vectis config token add --name <name>"));
        assert!(help.contains("vectis config token update <name>"));
        assert!(help.contains("vectis config fpe list"));
    }

    #[test]
    fn nested_config_help_lists_section_usage() {
        let token_help = render_help_path(&["config", "token"]);
        assert!(token_help.contains("vectis config token add --name <name>"));
        assert!(token_help.contains("tokenization_profiles"));

        let fpe_help = render_help_path(&["config", "fpe"]);
        assert!(fpe_help.contains("vectis config fpe add --name <name>"));
        assert!(fpe_help.contains("fpe_profiles"));
    }

    #[test]
    fn help_path_uses_longest_known_prefix() {
        let sign_help = render_help_path(&["sign", "verify"]);
        assert!(sign_help.contains("vectis sign <kid>"));
        assert!(!sign_help.contains("vectis <command> [options]"));

        let keys_help = render_help_path(&["keys", "create"]);
        assert!(keys_help.contains("vectis keys create"));
        assert!(!keys_help.contains("vectis <command> [options]"));

        let token_help = render_help_path(&["config", "token", "add"]);
        assert!(token_help.contains("vectis config token add --name <name>"));
        assert!(token_help.contains("tokenization_profiles"));
    }

    #[test]
    fn command_help_unknown_falls_back_to_root() {
        assert_eq!(render_help("unknown"), render_help(""));
    }

    #[test]
    fn unknown_config_section_help_falls_back_to_config() {
        assert_eq!(render_help_path(&["config", "nope"]), render_help("config"));
        assert_eq!(
            render_help_path(&["config", "nope", "extra"]),
            render_help("config")
        );
    }

    #[test]
    fn unknown_non_config_help_path_falls_back_to_root() {
        assert_eq!(render_help_path(&["unknown", "extra"]), render_help(""));
    }

    #[test]
    fn command_line_renderer_aligns_description() {
        let lines =
            render_command_lines(rendered_command_lines!("token" => "Edits token profiles"));
        assert_eq!(lines, vec!["  token                 Edits token profiles"]);
    }

    #[test]
    fn default_constants_match_rendered_health_help() {
        let help = render_help("health");
        assert!(help.contains(DEFAULT_API_URL));
        assert!(help.contains(DEFAULT_TIMEOUT_SECONDS));
    }
}
