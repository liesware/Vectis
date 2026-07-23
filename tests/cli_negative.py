#!/usr/bin/env python3
import json
import sqlite3
import tempfile
from pathlib import Path

from cli_support import (
    APIKEY_HASH_A,
    KID_A,
    KID_B,
    APIKEY_HASH_B,
    assert_config_unchanged,
    config_bytes,
    empty_config,
    init_config,
    init_material,
    isolated_env,
    run_case,
    run_cli,
    run_cli_json,
    require,
    require_summary,
    write_config,
)


def expect_unchanged_failure(env, args):
    before = config_bytes(env)
    run_cli(args, env, expect_success=False)
    assert_config_unchanged(env, before)


def expect_json_error(env, args):
    result = run_cli([*args, "--output", "json"], env, expect_success=False)
    require(result.stdout == "", "JSON error command must not write stdout")
    try:
        payload = json.loads(result.stderr)
    except json.JSONDecodeError as err:
        raise AssertionError(f"stderr must be JSON: {result.stderr}") from err
    require(isinstance(payload.get("error"), str), "JSON error must include error string")
    require(payload["error"], "JSON error string must not be empty")
    return payload


def expect_unknown_option(env, args, expected):
    result = run_cli(args, env, expect_success=False)
    require(result.stdout == "", "unknown option command must not write stdout")
    require(expected in result.stderr, f"stderr must contain {expected}: {result.stderr}")
    for misleading in ["kid must", "not found", "must be hex", "must have"]:
        require(
            misleading not in result.stderr,
            f"stderr must not contain misleading parser error {misleading}: {result.stderr}",
        )


def expect_json_unknown_option(env, args, expected):
    payload = expect_json_error(env, args)
    require(expected in payload["error"], f"JSON error must contain {expected}: {payload}")
    for misleading in ["kid must", "not found", "must be hex", "must have"]:
        require(
            misleading not in payload["error"],
            f"JSON error must not contain misleading parser error {misleading}: {payload}",
        )
    return payload


def unused_local_url():
    return "http://127.0.0.1:9"


def expect_server_down_json_error(env):
    test_env = env.copy()
    base_url = unused_local_url()
    test_env["VECTIS_API_URL"] = base_url
    result = run_cli(
        ["health", "ready", "--output", "json"],
        test_env,
        expect_success=False,
    )
    require(result.stdout == "", "server down JSON error must not write stdout")
    payload = json.loads(result.stderr)
    expected = f"cannot reach Vectis at {base_url}"
    require(
        expected in payload.get("error", ""),
        f"JSON server down error must mention base URL: {payload}",
    )
    require(
        "is the server running? (VECTIS_API_URL)" in payload["error"],
        f"JSON server down error must mention VECTIS_API_URL: {payload}",
    )
    require(
        "error sending request" not in payload["error"],
        f"JSON server down error must hide reqwest detail: {payload}",
    )


def expect_server_down_human_error(env):
    test_env = env.copy()
    base_url = unused_local_url()
    test_env["VECTIS_API_URL"] = base_url
    result = run_cli(["health", "ready"], test_env, expect_success=False)
    require(result.stdout == "", "server down human error must not write stdout")
    require(
        f"Error: cannot reach Vectis at {base_url}" in result.stderr,
        f"human server down error must mention base URL: {result.stderr}",
    )
    require(
        "is the server running? (VECTIS_API_URL)" in result.stderr,
        f"human server down error must mention VECTIS_API_URL: {result.stderr}",
    )
    require(
        "error sending request" not in result.stderr,
        f"human server down error must hide reqwest detail: {result.stderr}",
    )


def seed_route(env):
    run_cli_json(
        [
            "config",
            "routes",
            "add",
            "--name",
            "app-a",
            "--kid",
            KID_A,
            "--final-app-addr",
            "localhost:3999",
            "--final-app-path",
            "/message",
        ],
        env,
    )


def seed_permission(env):
    run_cli_json(
        [
            "config",
            "permissions",
            "add",
            "--client",
            "client-a",
            "--apikey-hash",
            APIKEY_HASH_A,
            "--status",
            "active",
        ],
        env,
    )


def seed_remote_route(env):
    config = empty_config()
    config["remote_routes"] = [
        {
            "remote_kid": KID_B,
            "name": "peer-a",
            "remote_addr": "localhost:3000",
            "allowed_local_kids": ["*"],
            "status": "active",
        }
    ]
    write_config(env, config)


def seed_fpe_profile(env):
    run_cli_json(
        [
            "config",
            "fpe",
            "add",
            "--name",
            "patient-id-decimal-v1",
            "--kid",
            KID_A,
            "--alphabet",
            "0123456789",
            "--min-len",
            "6",
            "--max-len",
            "32",
            "--tweak-aad",
            "tenant=acme;field=patient_id;version=1",
        ],
        env,
    )


def seed_token_profile(env):
    run_cli_json(
        [
            "config",
            "token",
            "add",
            "--name",
            "patient-id-token-v1",
            "--kid",
            KID_A,
            "--token-prefix",
            "tok_patient",
            "--token-len",
            "32",
            "--max-plaintext-len",
            "1024",
        ],
        env,
    )


def seed_mac_profile(env):
    run_cli_json(
        [
            "config",
            "mac",
            "add",
            "--name",
            "pan-blind-index-v1",
            "--kid",
            KID_A,
            "--context",
            "tenant=mx;field=pan;purpose=blind-index;version=1",
        ],
        env,
    )


def seed_binary_fpe_profile(env):
    config = empty_config()
    config["fpe_profiles"] = [
        {
            "name": "binary-id",
            "fpe_version": "fpe-ff1-2025",
            "alphabet": "01",
            "min_len": 20,
            "max_len": 32,
            "tweak_aad": "tenant=acme;field=binary_id;version=1",
            "kid": KID_A,
        }
    ]
    write_config(env, config)


def main():
    counters = {"passed": 0}
    print("CLI negative:", flush=True)
    with tempfile.TemporaryDirectory() as tmpdir:
        env = isolated_env(tmpdir)

        def route_add_missing_config():
            expect_unchanged_failure(
                env,
                [
                    "config",
                    "routes",
                    "add",
                    "--name",
                    "missing-config-route",
                    "--kid",
                    KID_A,
                    "--final-app-addr",
                    "localhost:3999",
                    "--final-app-path",
                    "/message",
                ],
            )

        def permission_add_missing_config():
            expect_unchanged_failure(
                env,
                [
                    "config",
                    "permissions",
                    "add",
                    "--client",
                    "missing-config-client",
                    "--apikey-hash",
                    APIKEY_HASH_A,
                ],
            )

        def remote_route_add_missing_config():
            expect_unchanged_failure(
                env,
                [
                    "config",
                    "remote-routes",
                    "add",
                    "--name",
                    "missing-config-peer",
                    "--remote-kid",
                    KID_A,
                    "--remote-addr",
                    "127.0.0.1:1",
                    "--allowed-local-kid",
                    "*",
                ],
            )

        def fpe_profile_add_missing_config():
            expect_unchanged_failure(
                env,
                [
                    "config",
                    "fpe",
                    "add",
                    "--name",
                    "missing-config-fpe",
                    "--kid",
                    KID_A,
                    "--alphabet",
                    "0123456789",
                    "--min-len",
                    "6",
                    "--max-len",
                    "32",
                    "--tweak-aad",
                    "tenant=acme",
                ],
            )

        def token_profile_add_missing_config():
            expect_unchanged_failure(
                env,
                [
                    "config",
                    "token",
                    "add",
                    "--name",
                    "missing-config-token",
                    "--kid",
                    KID_A,
                    "--token-prefix",
                    "tok_patient",
                    "--token-len",
                    "32",
                    "--max-plaintext-len",
                    "1024",
                ],
            )

        def mac_profile_add_missing_config():
            expect_unchanged_failure(
                env,
                [
                    "config",
                    "mac",
                    "add",
                    "--name",
                    "missing-config-mac",
                    "--kid",
                    KID_A,
                    "--context",
                    "tenant=mx;field=pan;purpose=blind-index;version=1",
                ],
            )

        def masking_profile_add_missing_config():
            expect_unchanged_failure(
                env,
                [
                    "config",
                    "masking",
                    "add",
                    "--name",
                    "missing-config-mask",
                    "--kid",
                    KID_A,
                    "--visible-first",
                    "0",
                    "--visible-last",
                    "4",
                    "--mask-char",
                    "*",
                    "--min-len",
                    "12",
                    "--max-len",
                    "19",
                ],
            )

        def route_list_missing_config():
            run_cli(["config", "routes", "list"], env, expect_success=False)

        def permission_list_missing_config():
            run_cli(["config", "permissions", "list"], env, expect_success=False)

        def remote_route_list_missing_config():
            run_cli(["config", "remote-routes", "list"], env, expect_success=False)

        def fpe_profile_list_missing_config():
            run_cli(["config", "fpe", "list"], env, expect_success=False)

        def token_profile_list_missing_config():
            run_cli(["config", "token", "list"], env, expect_success=False)

        def mac_profile_list_missing_config():
            run_cli(["config", "mac", "list"], env, expect_success=False)

        def masking_profile_list_missing_config():
            run_cli(["config", "masking", "list"], env, expect_success=False)

        def config_json_error_goes_to_stderr():
            payload = expect_json_error(env, ["config", "routes", "add"])
            require(
                "VECTIS_CONFIG_PATH" in payload["error"],
                "JSON error must describe config failure",
            )

        def apikey_json_error_goes_to_stderr():
            expect_json_error(env, ["apikey", "create"])

        def config_init_existing_file():
            init_config(env)
            before = config_bytes(env)
            run_cli(["config", "init"], env, expect_success=False)
            assert_config_unchanged(env, before)

        def config_sign_invalid_config_does_not_write_signature():
            init_material(env)
            config = empty_config()
            config["routes"] = [
                {
                    "name": "missing-key-route",
                    "kid": KID_A,
                    "final_app_addr": "localhost:3999",
                    "final_app_path": "/message",
                }
            ]
            write_config(env, config)
            sign_path = Path(env["VECTIS_CONFIG_SIGN_PATH"])
            sign_path.write_text("sentinel\n", encoding="utf-8")
            run_cli(["config", "sign"], env, expect_success=False)
            require(
                sign_path.read_text(encoding="utf-8") == "sentinel\n",
                "config sign must not rewrite signature when validation fails",
            )
            write_config(env, empty_config())

        def config_sign_empty_sqlite_schema_reports_path():
            init_material(env)
            write_config(env, empty_config())
            empty_db = Path(env["VECTIS_SQLITE_PATH"]).with_name("empty-schema.db")
            with sqlite3.connect(empty_db):
                pass
            local_env = env.copy()
            local_env["VECTIS_SQLITE_PATH"] = str(empty_db)
            payload = expect_json_error(local_env, ["config", "sign"])
            require(
                "sqlite schema is missing opskeys table" in payload["error"],
                f"schema error must describe missing opskeys table: {payload}",
            )
            require(
                str(empty_db) in payload["error"],
                f"schema error must include sqlite path: {payload}",
            )

        def duplicate_route_name():
            seed_route(env)
            expect_unchanged_failure(
                env,
                [
                    "config",
                    "routes",
                    "add",
                    "--name",
                    "app-a",
                    "--kid",
                    KID_B,
                    "--final-app-addr",
                    "localhost:4999",
                    "--final-app-path",
                    "/message",
                ],
            )

        def duplicate_permission_client():
            seed_permission(env)
            expect_unchanged_failure(
                env,
                [
                    "config",
                    "permissions",
                    "add",
                    "--client",
                    "client-a",
                    "--apikey-hash",
                    APIKEY_HASH_B,
                ],
            )

        def duplicate_remote_route_name():
            seed_remote_route(env)
            expect_unchanged_failure(
                env,
                [
                    "config",
                    "remote-routes",
                    "add",
                    "--name",
                    "peer-a",
                    "--remote-kid",
                    KID_A,
                    "--remote-addr",
                    "127.0.0.1:1",
                    "--allowed-local-kid",
                    "*",
                ],
            )

        def duplicate_fpe_profile_name():
            seed_fpe_profile(env)
            expect_unchanged_failure(
                env,
                [
                    "config",
                    "fpe",
                    "add",
                    "--name",
                    "patient-id-decimal-v1",
                    "--kid",
                    KID_B,
                    "--alphabet",
                    "abcdef",
                    "--min-len",
                    "6",
                    "--max-len",
                    "16",
                    "--tweak-aad",
                    "tenant=other",
                ],
            )

        def duplicate_token_profile_name():
            seed_token_profile(env)
            expect_unchanged_failure(
                env,
                [
                    "config",
                    "token",
                    "add",
                    "--name",
                    "patient-id-token-v1",
                    "--kid",
                    KID_B,
                    "--token-prefix",
                    "tok_other",
                    "--token-len",
                    "32",
                    "--max-plaintext-len",
                    "1024",
                ],
            )

        def duplicate_mac_profile_name():
            seed_mac_profile(env)
            expect_unchanged_failure(
                env,
                [
                    "config",
                    "mac",
                    "add",
                    "--name",
                    "pan-blind-index-v1",
                    "--kid",
                    KID_B,
                    "--context",
                    "tenant=mx;field=pan;purpose=blind-index;version=2",
                ],
            )

        def binary_fpe_profile_update_invalid_domain():
            seed_binary_fpe_profile(env)
            expect_unchanged_failure(
                env,
                ["config", "fpe", "update", "binary-id", "--min-len", "6"],
            )

        def runtime_positional_flags_are_unknown_options():
            cases = [
                (
                    ["sign", "--bogus"],
                    "unknown sign option: --bogus",
                ),
                (
                    ["fpe", "encrypt", "--profile", "card", "--value", "4111111111111111"],
                    "unknown fpe encrypt option: --profile",
                ),
                (
                    ["token", "encode", "--profile", "patient"],
                    "unknown token encode option: --profile",
                ),
                (
                    ["mac", "create", "--profile", "pan"],
                    "unknown mac create option: --profile",
                ),
                (
                    ["index", "create", "--profile", "pan"],
                    "unknown index create option: --profile",
                ),
                (
                    ["commit", "create", "--profile", "pan"],
                    "unknown commit create option: --profile",
                ),
                (
                    ["mask", "--profile", "pan"],
                    "unknown mask option: --profile",
                ),
                (
                    ["message", "send", "--profile", "pan"],
                    "unknown message send option: --profile",
                ),
                (
                    ["message", "internal", "encrypt", "--profile", "pan"],
                    "unknown message internal encrypt option: --profile",
                ),
                (
                    ["lifecycle", "--reason", "maintenance"],
                    "unknown lifecycle option: --reason",
                ),
            ]
            for args, expected in cases:
                expect_unknown_option(env, args, expected)

        def config_positional_flags_are_unknown_options():
            with tempfile.TemporaryDirectory() as config_tmpdir:
                local_env = isolated_env(config_tmpdir)
                init_config(local_env)
                before = config_bytes(local_env)
                cases = [
                    (
                        ["config", "routes", "get", "--bogus"],
                        "unknown config routes get option: --bogus",
                    ),
                    (
                        ["config", "routes", "update", "--bogus", "--kid", KID_A],
                        "unknown config routes update option: --bogus",
                    ),
                    (
                        ["config", "routes", "delete", "--bogus"],
                        "unknown config routes delete option: --bogus",
                    ),
                    (
                        ["config", "remote-routes", "update", "--bogus", "--remote-kid", KID_A],
                        "unknown config remote-routes update option: --bogus",
                    ),
                    (
                        [
                            "config",
                            "permissions",
                            "grant",
                            "--bogus",
                            "--kid",
                            KID_A,
                            "--action",
                            "message",
                        ],
                        "unknown config permissions grant option: --bogus",
                    ),
                    (
                        [
                            "config",
                            "permissions",
                            "revoke",
                            "--bogus",
                            "--kid",
                            KID_A,
                            "--action",
                            "message",
                        ],
                        "unknown config permissions revoke option: --bogus",
                    ),
                ]
                for args, expected in cases:
                    expect_json_unknown_option(local_env, args, expected)
                    assert_config_unchanged(local_env, before)

        cases = [
            (
                "runtime positional flags are rejected as unknown options",
                runtime_positional_flags_are_unknown_options,
            ),
            (
                "config positional flags are rejected as unknown options",
                config_positional_flags_are_unknown_options,
            ),
            (
                "server down emits JSON CLI error",
                lambda: expect_server_down_json_error(env),
            ),
            (
                "server down emits human CLI error",
                lambda: expect_server_down_human_error(env),
            ),
            ("config routes add fails when config is missing", route_add_missing_config),
            (
                "config permissions add fails when config is missing",
                permission_add_missing_config,
            ),
            (
                "config remote-routes add fails when config is missing",
                remote_route_add_missing_config,
            ),
            (
                "config fpe add fails when config is missing",
                fpe_profile_add_missing_config,
            ),
            (
                "config token add fails when config is missing",
                token_profile_add_missing_config,
            ),
            (
                "config mac add fails when config is missing",
                mac_profile_add_missing_config,
            ),
            (
                "config masking add fails when config is missing",
                masking_profile_add_missing_config,
            ),
            ("config routes list fails when config is missing", route_list_missing_config),
            (
                "config permissions list fails when config is missing",
                permission_list_missing_config,
            ),
            (
                "config remote-routes list fails when config is missing",
                remote_route_list_missing_config,
            ),
            ("config fpe list fails when config is missing", fpe_profile_list_missing_config),
            ("config token list fails when config is missing", token_profile_list_missing_config),
            ("config mac list fails when config is missing", mac_profile_list_missing_config),
            (
                "config masking list fails when config is missing",
                masking_profile_list_missing_config,
            ),
            ("config --output json errors are machine readable", config_json_error_goes_to_stderr),
            ("apikey --output json errors are machine readable", apikey_json_error_goes_to_stderr),
            (
                "config remote-routes import-keys is not a command",
                lambda: run_cli(
                    ["config", "remote-routes", "import-keys", "clinic-b"],
                    env,
                    expect_success=False,
                ),
            ),
            (
                "config fpe-profiles is not a command",
                lambda: run_cli(
                    ["config", "fpe-profiles", "get", "patient-id-decimal-v1"],
                    env,
                    expect_success=False,
                ),
            ),
            ("config init existing file fails without rewrite", config_init_existing_file),
            (
                "config sign validates before writing signature",
                config_sign_invalid_config_does_not_write_signature,
            ),
            (
                "config sign empty sqlite schema reports path",
                config_sign_empty_sqlite_schema_reports_path,
            ),
            ("duplicate routes.name fails without rewrite", duplicate_route_name),
            ("duplicate permissions.client fails without rewrite", duplicate_permission_client),
            ("duplicate remote_routes.name fails without rewrite", duplicate_remote_route_name),
            ("duplicate fpe_profiles.name fails without rewrite", duplicate_fpe_profile_name),
            (
                "duplicate tokenization_profiles.name fails without rewrite",
                duplicate_token_profile_name,
            ),
            ("duplicate mac_profiles.name fails without rewrite", duplicate_mac_profile_name),
            (
                "invalid mac context fails without rewrite",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "mac",
                        "add",
                        "--name",
                        "bad-mac-context",
                        "--kid",
                        KID_A,
                        "--context",
                        "tenant",
                    ],
                ),
            ),
            (
                "oversized tokenization token_prefix fails without rewrite",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "token",
                        "add",
                        "--name",
                        "bad-token-prefix",
                        "--kid",
                        KID_A,
                        "--token-prefix",
                        "a" * 17,
                        "--token-len",
                        "32",
                        "--max-plaintext-len",
                        "1024",
                    ],
                ),
            ),
            (
                "invalid route kid fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "routes",
                        "add",
                        "--name",
                        "bad-kid",
                        "--kid",
                        "not-hex",
                        "--final-app-addr",
                        "localhost:3999",
                        "--final-app-path",
                        "/message",
                    ],
                ),
            ),
            (
                "invalid final app address fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "routes",
                        "add",
                        "--name",
                        "bad-addr",
                        "--kid",
                        KID_A,
                        "--final-app-addr",
                        "http://localhost:3999",
                        "--final-app-path",
                        "/message",
                    ],
                ),
            ),
            (
                "invalid final app path fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "routes",
                        "add",
                        "--name",
                        "bad-path",
                        "--kid",
                        KID_A,
                        "--final-app-addr",
                        "localhost:3999",
                        "--final-app-path",
                        "message",
                    ],
                ),
            ),
            (
                "routes get missing name fails",
                lambda: run_cli(["config", "routes", "get", "missing"], env, expect_success=False),
            ),
            (
                "routes update missing name fails",
                lambda: expect_unchanged_failure(
                    env,
                    ["config", "routes", "update", "missing", "--final-app-path", "/x"],
                ),
            ),
            (
                "routes delete missing name fails",
                lambda: expect_unchanged_failure(
                    env, ["config", "routes", "delete", "missing"]
                ),
            ),
            (
                "invalid remote route kid fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "remote-routes",
                        "add",
                        "--name",
                        "bad-remote-kid",
                        "--remote-kid",
                        "bad",
                        "--remote-addr",
                        "localhost:3000",
                        "--allowed-local-kid",
                        "*",
                    ],
                ),
            ),
            (
                "invalid remote address fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "remote-routes",
                        "add",
                        "--name",
                        "bad-remote-addr",
                        "--remote-kid",
                        KID_A,
                        "--remote-addr",
                        "http://localhost:3000",
                        "--allowed-local-kid",
                        "*",
                    ],
                ),
            ),
            (
                "invalid allowed local kid fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "remote-routes",
                        "add",
                        "--name",
                        "bad-local-kid",
                        "--remote-kid",
                        KID_A,
                        "--remote-addr",
                        "localhost:3000",
                        "--allowed-local-kid",
                        "bad",
                    ],
                ),
            ),
            (
                "wildcard mixed with explicit allowed local kid fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "remote-routes",
                        "add",
                        "--name",
                        "bad-wildcard",
                        "--remote-kid",
                        KID_A,
                        "--remote-addr",
                        "localhost:3000",
                        "--allowed-local-kid",
                        "*",
                        "--allowed-local-kid",
                        KID_B,
                    ],
                ),
            ),
            (
                "unavailable remote pub fails without rewrite",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "remote-routes",
                        "add",
                        "--name",
                        "offline-peer",
                        "--remote-kid",
                        KID_A,
                        "--remote-addr",
                        "127.0.0.1:1",
                        "--allowed-local-kid",
                        "*",
                    ],
                ),
            ),
            (
                "invalid api key hash fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "permissions",
                        "add",
                        "--client",
                        "bad-hash",
                        "--apikey-hash",
                        "not-hex",
                    ],
                ),
            ),
            (
                "invalid fpe profile kid fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "fpe",
                        "add",
                        "--name",
                        "bad-fpe-kid",
                        "--kid",
                        "bad",
                        "--alphabet",
                        "0123456789",
                        "--min-len",
                        "6",
                        "--max-len",
                        "32",
                        "--tweak-aad",
                        "tenant=acme",
                    ],
                ),
            ),
            (
                "invalid fpe profile name fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "fpe",
                        "add",
                        "--name",
                        "bad=name",
                        "--kid",
                        KID_A,
                        "--alphabet",
                        "0123456789",
                        "--min-len",
                        "6",
                        "--max-len",
                        "32",
                        "--tweak-aad",
                        "tenant=acme",
                    ],
                ),
            ),
            (
                "invalid fpe alphabet fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "fpe",
                        "add",
                        "--name",
                        "bad-fpe-alphabet",
                        "--kid",
                        KID_A,
                        "--alphabet",
                        "001234",
                        "--min-len",
                        "6",
                        "--max-len",
                        "32",
                        "--tweak-aad",
                        "tenant=acme",
                    ],
                ),
            ),
            (
                "invalid fpe domain fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "fpe",
                        "add",
                        "--name",
                        "bad-fpe-domain",
                        "--kid",
                        KID_A,
                        "--alphabet",
                        "ABCDEF",
                        "--min-len",
                        "6",
                        "--max-len",
                        "32",
                        "--tweak-aad",
                        "tenant=acme",
                    ],
                ),
            ),
            (
                "invalid fpe update domain fails without rewrite",
                binary_fpe_profile_update_invalid_domain,
            ),
            (
                "invalid fpe version fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "fpe",
                        "add",
                        "--name",
                        "bad-fpe-version",
                        "--kid",
                        KID_A,
                        "--fpe-version",
                        "fpe-ff1-legacy",
                        "--alphabet",
                        "0123456789",
                        "--min-len",
                        "6",
                        "--max-len",
                        "32",
                        "--tweak-aad",
                        "tenant=acme",
                    ],
                ),
            ),
            (
                "invalid fpe min length fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "fpe",
                        "add",
                        "--name",
                        "bad-fpe-min-len",
                        "--kid",
                        KID_A,
                        "--alphabet",
                        "0123456789",
                        "--min-len",
                        "5",
                        "--max-len",
                        "32",
                        "--tweak-aad",
                        "tenant=acme",
                    ],
                ),
            ),
            (
                "invalid fpe max length fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "fpe",
                        "add",
                        "--name",
                        "bad-fpe-max-len",
                        "--kid",
                        KID_A,
                        "--alphabet",
                        "0123456789",
                        "--min-len",
                        "6",
                        "--max-len",
                        "5",
                        "--tweak-aad",
                        "tenant=acme",
                    ],
                ),
            ),
            (
                "oversized fpe max length fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "fpe",
                        "add",
                        "--name",
                        "oversized-fpe-max-len",
                        "--kid",
                        KID_A,
                        "--alphabet",
                        "0123456789",
                        "--min-len",
                        "6",
                        "--max-len",
                        "1025",
                        "--tweak-aad",
                        "tenant=acme",
                    ],
                ),
            ),
            (
                "fpe profile get missing name fails",
                lambda: run_cli(
                    ["config", "fpe", "get", "missing"],
                    env,
                    expect_success=False,
                ),
            ),
            (
                "fpe profile update missing name fails",
                lambda: expect_unchanged_failure(
                    env,
                    ["config", "fpe", "update", "missing", "--max-len", "32"],
                ),
            ),
            (
                "fpe profile delete missing name fails",
                lambda: expect_unchanged_failure(
                    env, ["config", "fpe", "delete", "missing"]
                ),
            ),
            (
                "invalid permission status fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "permissions",
                        "add",
                        "--client",
                        "bad-status",
                        "--apikey-hash",
                        APIKEY_HASH_A,
                        "--status",
                        "paused",
                    ],
                ),
            ),
            (
                "invalid permission action fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "permissions",
                        "grant",
                        "client-a",
                        "--kid",
                        KID_A,
                        "--action",
                        "unknown",
                    ],
                ),
            ),
            (
                "permissions get missing client fails",
                lambda: run_cli(
                    ["config", "permissions", "get", "missing"],
                    env,
                    expect_success=False,
                ),
            ),
            (
                "permissions update missing client fails",
                lambda: expect_unchanged_failure(
                    env,
                    ["config", "permissions", "update", "missing", "--status", "active"],
                ),
            ),
            (
                "permissions delete missing client fails",
                lambda: expect_unchanged_failure(
                    env, ["config", "permissions", "delete", "missing"]
                ),
            ),
            (
                "permissions grant missing client fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "permissions",
                        "grant",
                        "missing",
                        "--kid",
                        KID_A,
                        "--action",
                        "message",
                    ],
                ),
            ),
            (
                "permissions revoke missing client fails",
                lambda: expect_unchanged_failure(
                    env,
                    [
                        "config",
                        "permissions",
                        "revoke",
                        "missing",
                        "--kid",
                        KID_A,
                        "--action",
                        "message",
                    ],
                ),
            ),
        ]

        for name, func in cases:
            run_case(counters, name, func)

    require_summary("cli_negative", counters["passed"], 0)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(f"ERROR: {err}", flush=True)
        raise SystemExit(1)
