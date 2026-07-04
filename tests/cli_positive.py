#!/usr/bin/env python3
import argparse
import tempfile
import urllib.parse

from cli_support import (
    APIKEY_HASH_A,
    KID_A,
    KID_B,
    init_config,
    isolated_env,
    read_config,
    require,
    require_next,
    require_summary,
    run_case,
    run_cli_json,
)


def config_init_case(env):
    response = init_config(env)
    require(response["status"] == "created", "config init must report created")
    require(response["config_path"].endswith("config.json"), "config init must report config path")
    require_next(response)
    config = read_config(env)
    require(
        config == {"version": "v1", "routes": [], "remote_routes": [], "permissions": []},
        "config init must write the minimal skeleton",
    )


def route_cases(env):
    response = run_cli_json(
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
    require(response["status"] == "added", "route add must report added")
    require_next(response)

    config = read_config(env)
    require(config["routes"][0]["name"] == "app-a", "route name must be stored")

    response = run_cli_json(["config", "routes", "get", "app-a"], env)
    require(response["kid"] == KID_A, "route get must return route")

    response = run_cli_json(
        ["config", "routes", "update", "app-a", "--final-app-path", "/updated"],
        env,
    )
    require(response["status"] == "updated", "route update must report updated")
    require_next(response)
    require(
        read_config(env)["routes"][0]["final_app_path"] == "/updated",
        "route update must persist final_app_path",
    )

    response = run_cli_json(["config", "routes", "delete", "app-a"], env)
    require(response["status"] == "deleted", "route delete must report deleted")
    require_next(response)
    require(read_config(env)["routes"] == [], "route delete must remove route")


def permission_cases(env):
    response = run_cli_json(
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
    require(response["status"] == "added", "permission add must report added")
    require_next(response)

    response = run_cli_json(["config", "permissions", "get", "client-a"], env)
    require(response["client"] == "client-a", "permission get must return client")

    response = run_cli_json(
        ["config", "permissions", "update", "client-a", "--status", "disabled"],
        env,
    )
    require(response["item"]["status"] == "disabled", "permission update must persist status")
    require_next(response)

    response = run_cli_json(
        ["config", "permissions", "update", "client-a", "--status", "active"],
        env,
    )
    require(response["item"]["status"] == "active", "permission update must restore active")

    response = run_cli_json(
        [
            "config",
            "permissions",
            "grant",
            "client-a",
            "--kid",
            KID_A,
            "--action",
            "message",
        ],
        env,
    )
    require(response["status"] == "updated", "permission grant must report updated")
    require_next(response)
    permissions = read_config(env)["permissions"][0]["permissions"]
    require(permissions[0]["kid"] == KID_A, "permission grant must store kid")
    require(permissions[0]["actions"] == ["message"], "permission grant must store action")

    response = run_cli_json(
        [
            "config",
            "permissions",
            "revoke",
            "client-a",
            "--kid",
            KID_A,
            "--action",
            "message",
        ],
        env,
    )
    require(response["status"] == "updated", "permission revoke must report updated")
    require_next(response)
    require(
        read_config(env)["permissions"][0]["permissions"] == [],
        "permission revoke must remove empty grant",
    )

    response = run_cli_json(["config", "permissions", "delete", "client-a"], env)
    require(response["status"] == "deleted", "permission delete must report deleted")
    require_next(response)
    require(read_config(env)["permissions"] == [], "permission delete must remove client")


def config_list_case(env):
    response = run_cli_json(
        [
            "config",
            "routes",
            "add",
            "--name",
            "app-list",
            "--kid",
            KID_B,
            "--final-app-addr",
            "localhost:4999",
            "--final-app-path",
            "/message",
        ],
        env,
    )
    require_next(response)

    response = run_cli_json(["config", "list"], env)
    require(response["version"] == "v1", "config list must return version")
    require(response["routes"][0]["name"] == "app-list", "config list must include route")


def remote_route_dynamic_import(env, base_url, apikey):
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme != "http" or not parsed.netloc:
        print("Remote route dynamic import: SKIPPED (requires http --base-url)", flush=True)
        return False

    from http_support import Client, KEY_CASES, create_key

    client = Client(base_url, apikey)
    kid = create_key(client, KEY_CASES[0])

    response = run_cli_json(
        [
            "config",
            "remote-routes",
            "add",
            "--name",
            "peer-a",
            "--remote-kid",
            kid,
            "--remote-addr",
            parsed.netloc,
            "--allowed-local-kid",
            "*",
        ],
        env,
    )
    require(response["status"] == "added", "remote route add must report added")
    require_next(response)
    route = read_config(env)["remote_routes"][0]
    require(route["public_keys"], "remote route add must import public_keys")
    require(route["remote_kid"] == kid, "remote route add must store remote kid")
    return True


def main():
    parser = argparse.ArgumentParser(description="Run positive Vectis CLI tests.")
    parser.add_argument("--base-url")
    parser.add_argument("--apikey")
    args = parser.parse_args()

    counters = {"passed": 0}
    print("CLI positive:", flush=True)
    with tempfile.TemporaryDirectory() as tmpdir:
        env = isolated_env(tmpdir)

        run_case(counters, "config init creates skeleton", lambda: config_init_case(env))
        run_case(counters, "config routes add/get/update/delete", lambda: route_cases(env))
        run_case(
            counters,
            "config permissions add/get/update/grant/revoke/delete",
            lambda: permission_cases(env),
        )
        run_case(counters, "config list reads edited config", lambda: config_list_case(env))

        if args.base_url and args.apikey:
            added = remote_route_dynamic_import(env, args.base_url, args.apikey)
            if added:
                counters["passed"] += 1
                print("- config remote-routes add imports public keys: OK", flush=True)
        else:
            print(
                "Remote route dynamic import: SKIPPED (no --base-url/--apikey)",
                flush=True,
            )

    require_summary("cli_positive", counters["passed"], 0)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(f"ERROR: {err}", flush=True)
        raise SystemExit(1)
