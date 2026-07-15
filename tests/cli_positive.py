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
        config
        == {
            "version": "v1",
            "routes": [],
            "remote_routes": [],
            "permissions": [],
            "fpe_profiles": [],
            "tokenization_profiles": [],
        },
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

    response = run_cli_json(["config", "routes", "list"], env)
    require(isinstance(response, list), "route list must return an array")
    require(response[0]["name"] == "app-a", "route list must include route")

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

    response = run_cli_json(["config", "permissions", "list"], env)
    require(isinstance(response, list), "permission list must return an array")
    require(response[0]["client"] == "client-a", "permission list must include client")

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


def fpe_profile_cases(env):
    response = run_cli_json(
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
    require(response["status"] == "added", "fpe profile add must report added")
    require_next(response)

    profile = read_config(env)["fpe_profiles"][0]
    require(profile["name"] == "patient-id-decimal-v1", "fpe profile name must be stored")
    require(profile["fpe_version"] == "fpe-ff1-2025", "fpe profile version must default")

    response = run_cli_json(["config", "fpe", "get", "patient-id-decimal-v1"], env)
    require(response["kid"] == KID_A, "fpe profile get must return profile")

    response = run_cli_json(["config", "fpe", "list"], env)
    require(isinstance(response, list), "fpe profile list must return an array")
    require(
        response[0]["name"] == "patient-id-decimal-v1",
        "fpe profile list must include profile",
    )

    response = run_cli_json(
        [
            "config",
            "fpe",
            "update",
            "patient-id-decimal-v1",
            "--max-len",
            "40",
            "--tweak-aad",
            "tenant=acme;field=patient_id;version=2",
        ],
        env,
    )
    require(response["status"] == "updated", "fpe profile update must report updated")
    require_next(response)
    profile = read_config(env)["fpe_profiles"][0]
    require(profile["max_len"] == 40, "fpe profile update must persist max_len")
    require(
        profile["tweak_aad"].endswith("version=2"),
        "fpe profile update must persist tweak_aad",
    )

    response = run_cli_json(["config", "fpe", "delete", "patient-id-decimal-v1"], env)
    require(response["status"] == "deleted", "fpe profile delete must report deleted")
    require_next(response)
    require(read_config(env)["fpe_profiles"] == [], "fpe profile delete must remove profile")


def token_profile_cases(env):
    response = run_cli_json(
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
    require(response["status"] == "added", "token profile add must report added")
    require_next(response)

    profile = read_config(env)["tokenization_profiles"][0]
    require(profile["name"] == "patient-id-token-v1", "token profile name must be stored")
    require(
        profile["tokenization_version"] == "token-random-v1",
        "token profile version must default",
    )

    response = run_cli_json(["config", "token", "get", "patient-id-token-v1"], env)
    require(response["kid"] == KID_A, "token profile get must return profile")

    response = run_cli_json(["config", "token", "list"], env)
    require(isinstance(response, list), "token profile list must return an array")
    require(
        response[0]["name"] == "patient-id-token-v1",
        "token profile list must include profile",
    )

    response = run_cli_json(
        [
            "config",
            "token",
            "update",
            "patient-id-token-v1",
            "--max-plaintext-len",
            "512",
        ],
        env,
    )
    require(response["status"] == "updated", "token profile update must report updated")
    require_next(response)
    profile = read_config(env)["tokenization_profiles"][0]
    require(
        profile["max_plaintext_len"] == 512,
        "token profile update must persist max_plaintext_len",
    )

    response = run_cli_json(["config", "token", "delete", "patient-id-token-v1"], env)
    require(response["status"] == "deleted", "token profile delete must report deleted")
    require_next(response)
    require(
        read_config(env)["tokenization_profiles"] == [],
        "token profile delete must remove profile",
    )


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
    response = run_cli_json(["config", "remote-routes", "list"], env)
    require(isinstance(response, list), "remote route list must return an array")
    require(response[0]["name"] == "peer-a", "remote route list must include route")
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
        run_case(
            counters,
            "config fpe add/get/update/delete",
            lambda: fpe_profile_cases(env),
        )
        run_case(
            counters,
            "config token add/get/update/delete",
            lambda: token_profile_cases(env),
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
