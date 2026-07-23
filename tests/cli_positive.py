#!/usr/bin/env python3
import argparse
import tempfile
import urllib.parse

from cli_support import (
    APIKEY_HASH_A,
    APIKEY_HASH_B,
    KID_A,
    KID_B,
    init_config,
    init_material,
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
            "mac_profiles": [],
            "masking_profiles": [],
            "commitment_profiles": [],
            "sharing_profiles": [],
        },
        "config init must write the minimal skeleton",
    )


def config_validate_case(env):
    init_material(env)
    response = run_cli_json(["config", "validate"], env)
    require(response["status"] == "valid", "config validate must report valid")
    require(response["config_path"].endswith("config.json"), "validate must report config path")
    require(response["keys_loaded"] == 0, "empty test DB must have no loaded keys")
    require(response["routes_loaded"] == 0, "empty config must have no routes")
    require(response["remote_routes_loaded"] == 0, "empty config must have no remote routes")
    require(response["clients_loaded"] == 0, "empty config must have no permission clients")
    require(response["fpe_profiles_loaded"] == 0, "empty config must have no FPE profiles")
    require(
        response["tokenization_profiles_loaded"] == 0,
        "empty config must have no tokenization profiles",
    )
    require(response["mac_profiles_loaded"] == 0, "empty config must have no MAC profiles")
    require(
        response["masking_profiles_loaded"] == 0,
        "empty config must have no masking profiles",
    )
    require(
        response["commitment_profiles_loaded"] == 0,
        "empty config must have no commitment profiles",
    )


def version_case(env):
    response = run_cli_json(["version"], env)
    require(isinstance(response["version"], str), "version must include crate version")
    require(response["protocol_version"] == "v1", "version must include protocol v1")
    require(
        "hybrid-performance-v1" in response["crypto_profiles"],
        "version must include supported crypto profiles",
    )
    require(
        "hybrid-standard-v1" in response["crypto_profiles"],
        "version must include standard crypto profile",
    )
    require(
        "profile-only" in response["crypto_policies"],
        "version must include supported crypto policies",
    )
    primitives = response["internal_primitives"]
    require(primitives["hash"] == "BLAKE2b(256)", "version must include internal hash")
    require(primitives["hkdf"] == "HKDF(BLAKE2b(256))", "version must include internal HKDF")
    require(primitives["hmac"] == "HMAC(BLAKE2b(256))", "version must include internal HMAC")
    require(primitives["cipher"] == "AES-256/GCM", "version must include internal cipher")
    algorithms = response["algorithms"]
    require("SHA-256" in algorithms["hash"], "version must include supported hashes")
    require(
        "AES-256/GCM" in algorithms["symmetric"],
        "version must include supported symmetric ciphers",
    )
    require("Ed448" in algorithms["eddsa"], "version must include supported EdDSA algorithms")
    require("X448" in algorithms["xecdh"], "version must include supported XECDH algorithms")
    require("ML-DSA-87" in algorithms["ml_dsa"], "version must include supported ML-DSA variants")
    require("ML-KEM-1024" in algorithms["ml_kem"], "version must include supported ML-KEM variants")
    require("fpe-ff1-2025" in algorithms["fpe"], "version must include supported FPE versions")
    require(
        "token-random-v1" in algorithms["tokenization"],
        "version must include supported tokenization versions",
    )
    require(
        "HMAC(<ops-key-hash>)" in algorithms["mac"],
        "version must include HMAC MAC algorithm",
    )
    require("KMAC-224" in algorithms["mac"], "version must include KMAC-224")
    require("KMAC-256" in algorithms["mac"], "version must include supported MAC algorithms")
    require("KMAC-384" in algorithms["mac"], "version must include KMAC-384")
    require("KMAC-512" in algorithms["mac"], "version must include KMAC-512")


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
            "help",
            "--apikey-hash",
            APIKEY_HASH_B,
        ],
        env,
    )
    require(response["status"] == "added", "permission add must accept client named help")
    require_next(response)
    response = run_cli_json(["config", "permissions", "delete", "help"], env)
    require(response["status"] == "deleted", "permission delete must remove help client")
    require_next(response)

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
        "tokenization_version" not in profile,
        "token profile must not store tokenization_version",
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


def mac_profile_cases(env):
    response = run_cli_json(
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
    require(response["status"] == "added", "mac profile add must report added")
    require_next(response)

    profile = read_config(env)["mac_profiles"][0]
    require(profile["name"] == "pan-blind-index-v1", "mac profile name must be stored")
    require(profile["kid"] == KID_A, "mac profile kid must be stored")

    response = run_cli_json(["config", "mac", "get", "pan-blind-index-v1"], env)
    require(response["context"].startswith("tenant=mx"), "mac profile get must return profile")

    response = run_cli_json(["config", "mac", "list"], env)
    require(isinstance(response, list), "mac profile list must return an array")
    require(response[0]["name"] == "pan-blind-index-v1", "mac profile list must include profile")

    response = run_cli_json(
        [
            "config",
            "mac",
            "update",
            "pan-blind-index-v1",
            "--context",
            "tenant=mx;field=pan;purpose=blind-index;version=2",
        ],
        env,
    )
    require(response["status"] == "updated", "mac profile update must report updated")
    require_next(response)
    profile = read_config(env)["mac_profiles"][0]
    require(profile["context"].endswith("version=2"), "mac profile update must persist context")

    response = run_cli_json(["config", "mac", "delete", "pan-blind-index-v1"], env)
    require(response["status"] == "deleted", "mac profile delete must report deleted")
    require_next(response)
    require(read_config(env)["mac_profiles"] == [], "mac profile delete must remove profile")


def masking_profile_cases(env):
    response = run_cli_json(
        [
            "config",
            "masking",
            "add",
            "--name",
            "pan-display-v1",
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
        env,
    )
    require(response["status"] == "added", "masking profile add must report added")
    require_next(response)

    profile = read_config(env)["masking_profiles"][0]
    require(profile["name"] == "pan-display-v1", "masking profile name must be stored")
    require(profile["kid"] == KID_A, "masking profile kid must be stored")

    response = run_cli_json(["config", "masking", "get", "pan-display-v1"], env)
    require(response["mask_char"] == "*", "masking profile get must return profile")

    response = run_cli_json(["config", "masking", "list"], env)
    require(isinstance(response, list), "masking profile list must return an array")
    require(response[0]["name"] == "pan-display-v1", "masking profile list must include profile")

    response = run_cli_json(
        [
            "config",
            "masking",
            "update",
            "pan-display-v1",
            "--visible-first",
            "6",
        ],
        env,
    )
    require(response["status"] == "updated", "masking profile update must report updated")
    require_next(response)
    profile = read_config(env)["masking_profiles"][0]
    require(profile["visible_first"] == 6, "masking profile update must persist visible_first")

    response = run_cli_json(["config", "masking", "delete", "pan-display-v1"], env)
    require(response["status"] == "deleted", "masking profile delete must report deleted")
    require_next(response)
    require(
        read_config(env)["masking_profiles"] == [],
        "masking profile delete must remove profile",
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

        run_case(counters, "version prints local compatibility info", lambda: version_case(env))
        run_case(counters, "config init creates skeleton", lambda: config_init_case(env))
        run_case(counters, "config validate checks local node state", lambda: config_validate_case(env))
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
        run_case(
            counters,
            "config mac add/get/update/delete",
            lambda: mac_profile_cases(env),
        )
        run_case(
            counters,
            "config masking add/get/update/delete",
            lambda: masking_profile_cases(env),
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
