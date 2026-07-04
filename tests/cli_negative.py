#!/usr/bin/env python3
import tempfile

from cli_support import (
    APIKEY_HASH_A,
    KID_A,
    KID_B,
    APIKEY_HASH_B,
    assert_config_unchanged,
    config_bytes,
    empty_config,
    init_config,
    isolated_env,
    run_case,
    run_cli,
    run_cli_json,
    require_summary,
    write_config,
)


def expect_unchanged_failure(env, args):
    before = config_bytes(env)
    run_cli(args, env, expect_success=False)
    assert_config_unchanged(env, before)


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

        def config_init_existing_file():
            init_config(env)
            before = config_bytes(env)
            run_cli(["config", "init"], env, expect_success=False)
            assert_config_unchanged(env, before)

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

        cases = [
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
                "config remote-routes import-keys is not a command",
                lambda: run_cli(
                    ["config", "remote-routes", "import-keys", "clinic-b"],
                    env,
                    expect_success=False,
                ),
            ),
            ("config init existing file fails without rewrite", config_init_existing_file),
            ("duplicate routes.name fails without rewrite", duplicate_route_name),
            ("duplicate permissions.client fails without rewrite", duplicate_permission_client),
            ("duplicate remote_routes.name fails without rewrite", duplicate_remote_route_name),
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
