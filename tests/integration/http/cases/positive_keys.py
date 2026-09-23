"""Positive HTTP helpers for one capability domain."""

import base64
import hashlib
import json

from lib.assertions import require, require_hex, require_kid
from lib.fixtures import create_key, host_from_base_url, start_final_app
from lib.positive_support import KEY_CASES, reload_config, write_test_remote_routes, write_test_routes
from lib.casekit import CaseSet
from lib.results import CaseResult

from .positive_output import print_create_key

cases = CaseSet()

def validate_test_response(response, case):
    require(response.get("timestamp"), "test response must include timestamp")
    require(response.get("aad"), "test response must include aad")

    expected_variants = {
        "eddsa": case["eddsa_algorithm"],
        "xecdh": case["xecdh_algorithm"],
        "ml-dsa": case["ml_dsa_variant"],
        "ml-kem": case["ml_kem_variant"],
    }
    for field, variant in expected_variants.items():
        block = response.get(field)
        require(isinstance(block, dict), f"test.{field} must be an object")
        require(block.get("variant") == variant, f"test.{field}.variant mismatch")
        require(block.get("valid") is True, f"test.{field}.valid must be true")


def validate_message_response(response, case):
    message = response.get("message")
    require(isinstance(message, dict), "message.message must be an object")
    require(message.get("valid") is True, "message.message.valid must be true")

    expected_variants = {
        "symmetric": case["symmetric_algorithm"],
        "eddsa": case["eddsa_algorithm"],
        "xecdh": case["xecdh_algorithm"],
        "ml-dsa": case["ml_dsa_variant"],
        "ml-kem": case["ml_kem_variant"],
    }
    for field, variant in expected_variants.items():
        block = response.get(field)
        require(isinstance(block, dict), f"message.{field} must be an object")
        require(block.get("variant") == variant, f"message.{field}.variant mismatch")
        require(block.get("valid") is True, f"message.{field}.valid must be true")


def validate_pub_response(response, case):
    require(response.get("info"), "pub response must include info")
    keys = response.get("keys")
    require(isinstance(keys, dict), "pub.keys must be an object")

    expected = {
        "eddsa": ("alg", case["eddsa_algorithm"], "public_key_der_hex"),
        "xecdh": ("alg", case["xecdh_algorithm"], "public_key_hex"),
        "ml-dsa": ("alg", case["ml_dsa_variant"], "public_key_der_hex"),
        "ml-kem": ("alg", case["ml_kem_variant"], "public_key_der_hex"),
    }
    for field, (alg_field, alg, key_field) in expected.items():
        block = keys.get(field)
        require(isinstance(block, dict), f"pub.keys.{field} must be an object")
        require(block.get(alg_field) == alg, f"pub.keys.{field}.{alg_field} mismatch")
        require_hex(block.get(key_field), f"pub.keys.{field}.{key_field}")


def validate_keys_list(response, key_ids):
    require(isinstance(response, dict), "keys list response must be an object")
    keys = response.get("keys")
    require(isinstance(keys, list), "keys list response.keys must be an array")
    by_kid = {}
    for item in keys:
        require(isinstance(item, dict), "keys list item must be an object")
        kid = item.get("kid")
        info = item.get("info")
        require_kid(kid, "keys list item kid")
        require(isinstance(info, str) and info, "keys list item info must be a non-empty string")
        by_kid[kid] = info

    for key_id in key_ids:
        require(key_id in by_kid, f"keys list must include {key_id}")


def validate_keys_properties_list(response, key_ids):
    require(isinstance(response, dict), "keys properties response must be an object")
    keys = response.get("keys")
    require(isinstance(keys, list), "keys properties response.keys must be an array")
    by_kid = {}
    for item in keys:
        require(isinstance(item, dict), "keys properties item must be an object")
        kid = item.get("kid")
        require_kid(kid, "keys properties item kid")
        require(isinstance(item.get("info"), str) and item["info"], "keys properties item info")
        require(
            isinstance(item.get("properties_info"), str) and item["properties_info"],
            "keys properties item properties_info",
        )
        properties = item.get("properties")
        require(isinstance(properties, dict), "keys properties item properties must be an object")
        require(properties.get("version") == 1, "keys properties version must be 1")
        require(
            properties.get("profile")
            in {
                "hybrid-performance-v1",
                "hybrid-standard-v1",
                "hybrid-high-assurance-v1",
                "hybrid-long-term-v1",
                "custom",
            },
            "keys properties profile must be supported",
        )
        require(isinstance(properties.get("tag"), str) and properties["tag"], "keys properties tag")
        require(
            isinstance(properties.get("created_at"), str) and properties["created_at"],
            "keys properties created_at",
        )
        lifecycle = properties.get("lifecycle")
        require(isinstance(lifecycle, dict), "keys properties lifecycle must be an object")
        require(
            lifecycle.get("status")
            in {"active", "disabled", "retired", "compromised", "destroyed"},
            "keys properties lifecycle.status",
        )
        require(
            isinstance(lifecycle.get("reason"), str) and lifecycle["reason"],
            "keys properties lifecycle.reason",
        )
        require(
            isinstance(lifecycle.get("changed_at"), str) and lifecycle["changed_at"],
            "keys properties lifecycle.changed_at",
        )
        require("access" not in properties, "keys properties must not expose access")
        by_kid[kid] = properties

    for key_id in key_ids:
        require(key_id in by_kid, f"keys properties must include {key_id}")


def validate_key_properties_item(response, key_id, expected_status=None):
    require(isinstance(response, dict), "key properties response must be an object")
    require(response.get("kid") == key_id, "key properties kid mismatch")
    require(isinstance(response.get("info"), str) and response["info"], "key properties info")
    require(
        isinstance(response.get("properties_info"), str) and response["properties_info"],
        "key properties properties_info",
    )
    properties = response.get("properties")
    require(isinstance(properties, dict), "key properties properties must be an object")
    require("access" not in properties, "key properties must not expose access")
    lifecycle = properties.get("lifecycle")
    require(isinstance(lifecycle, dict), "key properties lifecycle must be an object")
    if expected_status is not None:
        require(
            lifecycle.get("status") == expected_status,
            f"key properties lifecycle.status must be {expected_status}",
        )
    return properties


def validate_lifecycle_response(response, key_id, expected_status):
    require(isinstance(response, dict), "lifecycle response must be an object")
    require(response.get("kid") == key_id, "lifecycle response kid mismatch")
    lifecycle = response.get("lifecycle")
    require(isinstance(lifecycle, dict), "lifecycle response lifecycle must be an object")
    require(
        lifecycle.get("status") == expected_status,
        f"lifecycle status must be {expected_status}",
    )
    require(
        isinstance(lifecycle.get("reason"), str) and lifecycle["reason"],
        "lifecycle reason must be a non-empty string",
    )
    require(
        isinstance(lifecycle.get("changed_at"), str) and lifecycle["changed_at"],
        "lifecycle changed_at must be a non-empty string",
    )


def validate_routes_list(response):
    require(isinstance(response, dict), "routes list response must be an object")
    routes = response.get("routes")
    require(isinstance(routes, list), "routes list response.routes must be an array")
    for item in routes:
        require(isinstance(item, dict), "routes list item must be an object")
        require_kid(item.get("kid"), "routes list item kid")
        require(
            isinstance(item.get("name"), str) and item["name"],
            "routes list item name must be a non-empty string",
        )
        require(
            isinstance(item.get("final_app_addr"), str) and item["final_app_addr"],
            "routes list item final_app_addr must be a non-empty string",
        )
        require(
            isinstance(item.get("final_app_path"), str) and item["final_app_path"].startswith("/"),
            "routes list item final_app_path must start with /",
        )


def validate_remote_routes_list(response):
    require(isinstance(response, dict), "remote routes list response must be an object")
    routes = response.get("routes")
    require(isinstance(routes, list), "remote routes list response.routes must be an array")
    for item in routes:
        require(isinstance(item, dict), "remote routes list item must be an object")
        require_kid(item.get("remote_kid"), "remote routes list item remote_kid")
        require(
            isinstance(item.get("name"), str) and item["name"],
            "remote routes list item name must be a non-empty string",
        )
        require(
            isinstance(item.get("remote_addr"), str) and item["remote_addr"],
            "remote routes list item remote_addr must be a non-empty string",
        )
        allowed_local_kids = item.get("allowed_local_kids")
        require(
            isinstance(allowed_local_kids, list) and allowed_local_kids,
            "remote routes list item allowed_local_kids must be a non-empty array",
        )
        for allowed_kid in allowed_local_kids:
            if allowed_kid != "*":
                require_kid(allowed_kid, "remote routes list item allowed_local_kids kid")
        require(
            item.get("status") in ("active", "disabled"),
            "remote routes list item status must be active or disabled",
        )
        if "public_keys" in item:
            validate_remote_route_public_keys(item["public_keys"])


def validate_remote_route_public_keys(block, case=None):
    require(isinstance(block, dict), "remote route public_keys must be an object")
    fields = {
        "eddsa": ("public_key_der_hex", "eddsa_algorithm"),
        "xecdh": ("public_key_hex", "xecdh_algorithm"),
        "ml-dsa": ("public_key_der_hex", "ml_dsa_variant"),
        "ml-kem": ("public_key_der_hex", "ml_kem_variant"),
    }
    for field, (key_field, case_key) in fields.items():
        sub = block.get(field)
        require(isinstance(sub, dict), f"remote route public_keys.{field} must be an object")
        require(
            isinstance(sub.get("alg"), str) and sub["alg"],
            f"remote route public_keys.{field}.alg must be a non-empty string",
        )
        if case is not None:
            require(
                sub.get("alg") == case[case_key],
                f"remote route public_keys.{field}.alg mismatch",
            )
        require_hex(sub.get(key_field), f"remote route public_keys.{field}.{key_field}")


def assert_no_apikey_hash(value):
    if isinstance(value, dict):
        require("apikey_hash" not in value, "permissions output must not expose apikey_hash")
        for item in value.values():
            assert_no_apikey_hash(item)
    elif isinstance(value, list):
        for item in value:
            assert_no_apikey_hash(item)


def validate_permissions_list(response):
    clients = response.get("clients")
    require(isinstance(clients, list), "permissions.clients must be a list")
    assert_no_apikey_hash(response)

    for client in clients:
        require(isinstance(client.get("client"), str), "permissions.client must be string")
        require(isinstance(client.get("admin"), bool), "permissions.admin must be bool")
        permissions = client.get("permissions")
        require(isinstance(permissions, list), "permissions.permissions must be list")
        for permission in permissions:
            require(isinstance(permission.get("kid"), str), "permissions.kid must be string")
            actions = permission.get("actions")
            require(isinstance(actions, list), "permissions.actions must be list")
            require(actions, "permissions.actions must not be empty")
            for action in actions:
                require(isinstance(action, str), "permissions.actions item must be string")

    return clients


@cases('positive.keys.create')
def run_keys(ctx):
    client = ctx.client
    if ctx.final_app is None:
        ctx.final_app = start_final_app(ctx.final_app_addr)

    created = []
    rows = []
    for crypto_case in KEY_CASES:
        key_id = create_key(client, crypto_case)
        created.append((key_id, crypto_case))
        rows.extend(
            (
                (crypto_case["xecdh_algorithm"], key_id),
                (crypto_case["eddsa_algorithm"], key_id),
                (crypto_case["ml_dsa_variant"], key_id),
                (crypto_case["ml_kem_variant"], key_id),
            )
        )
    ctx.artifacts["positive.keys"] = created
    ctx.artifacts["positive.recipient_host"] = host_from_base_url(ctx.base_url)
    print_create_key(rows)
    return CaseResult(passed=len(rows))


@cases('positive.keys.inventory')
def run_key_inventory(ctx):
    client = ctx.client
    created = ctx.artifacts["positive.keys"]
    key_ids = [key_id for key_id, _ in created]
    validate_keys_list(client.get("/keys"), key_ids)
    print("List keys: OK\n")
    validate_keys_properties_list(client.get("/keys/properties", auth=True), key_ids)
    print("List keys properties: OK\n")
    return CaseResult(passed=2)


@cases('positive.keys.lifecycle')
def run_key_lifecycle(ctx):
    client = ctx.client
    key_id = ctx.artifacts["positive.keys"][0][0]
    validate_key_properties_item(client.get(f"/keys/properties/{key_id}", auth=True), key_id, "active")
    print("Get key properties: OK\n")
    validate_lifecycle_response(
        client.post(f"/lifecycle/{key_id}", {"status": "disabled", "reason": "positive test maintenance window"}, auth=True),
        key_id,
        "disabled",
    )
    validate_key_properties_item(client.get(f"/keys/properties/{key_id}", auth=True), key_id, "disabled")
    validate_lifecycle_response(
        client.post(f"/lifecycle/{key_id}", {"status": "active", "reason": "positive test restored"}, auth=True),
        key_id,
        "active",
    )
    print("Update lifecycle: OK\n")
    validate_keys_properties_list(
        client.post("/keys/reload", {}, auth=True),
        [key_id for key_id, _ in ctx.artifacts["positive.keys"]],
    )
    print("Reload keys: OK\n")
    return CaseResult(passed=3)


@cases('positive.routes')
def run_routes(ctx):
    client = ctx.client
    created = ctx.artifacts["positive.keys"]
    key_ids = [key_id for key_id, _ in created]
    write_test_routes(ctx, key_ids)
    reload_config(ctx)
    print("Reload config: OK\n")
    validate_routes_list(client.get("/routes", auth=True))
    print("List routes: OK\n")
    write_test_remote_routes(ctx, key_ids)
    reload_config(ctx)
    print("Reload remote routes config: OK\n")
    validate_remote_routes_list(client.get("/remote-routes", auth=True))
    print("List remote routes: OK\n")
    return CaseResult(passed=4)


@cases('positive.remote-public-keys')
def run_remote_public_keys(ctx):
    client = ctx.client
    key_id, crypto_case = ctx.artifacts["positive.keys"][0]
    peer_pub = client.get(f"/pub/{key_id}")
    ctx.config_data["remote_routes"] = [{
        "remote_kid": key_id,
        "name": "positive-peer-keys",
        "remote_addr": ctx.artifacts["positive.recipient_host"],
        "allowed_local_kids": ["*"],
        "status": "active",
        "public_keys": peer_pub["keys"],
    }]
    ctx.write_config()
    reload_config(ctx)
    listed = client.get("/remote-routes", auth=True)
    validate_remote_routes_list(listed)
    route = next((item for item in listed["routes"] if item.get("remote_kid") == key_id), None)
    require(route is not None and "public_keys" in route, "peer remote route must expose public_keys")
    validate_remote_route_public_keys(route["public_keys"], crypto_case)
    print("Remote route public_keys round-trip: OK\n")
    write_test_remote_routes(ctx, [item[0] for item in ctx.artifacts["positive.keys"]])
    reload_config(ctx)
    return CaseResult()


CASES = cases.tuple()
