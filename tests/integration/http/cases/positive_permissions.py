"""Positive HTTP helpers for one capability domain."""

import base64
import hashlib
import json

from lib.assertions import require
from lib.client import Client
from lib.fixtures import create_api_key_pair
from lib.positive_support import reload_config
from lib.casekit import CaseSet
from lib.results import CaseResult

from .positive_output import print_section
from .positive_health import validate_metrics, validate_init
from .positive_keys import validate_permissions_list, validate_routes_list
from .positive_messages import encrypt_internal_message

cases = CaseSet()

def validate_permissions_flow(ctx, key_id, case):
    base_url = ctx.base_url
    root_client = ctx.client
    limited_key, limited_hash = create_api_key_pair()
    admin_key, admin_hash = create_api_key_pair()
    metrics_key, metrics_hash = create_api_key_pair()
    # This positive flow extends the configuration prepared by earlier cases.
    # ``ctx.set_permissions`` intentionally isolates negative test input and
    # would erase the remote routes needed by the following messages case.
    ctx.config_data["permissions"] = [
        {
            "client": "positive-limited-message",
            "apikey_hash": limited_hash,
            "status": "active",
            "permissions": [
                {
                    "kid": key_id,
                    "actions": ["message"],
                }
            ],
        },
        {
            "client": "positive-metrics",
            "apikey_hash": metrics_hash,
            "status": "active",
            "permissions": [
                {
                    "kid": "*",
                    "actions": ["metrics"],
                }
            ],
        },
        {
            "client": "positive-admin",
            "apikey_hash": admin_hash,
            "status": "active",
            "permissions": [
                {
                    "kid": "*",
                    "actions": ["admin"],
                }
            ],
        },
    ]
    require(ctx.config_data["routes"], "permissions flow must preserve configured routes")
    require(
        ctx.config_data["remote_routes"],
        "permissions flow must preserve configured remote routes",
    )
    ctx.write_config()
    reload_config(ctx)

    limited_client = Client(base_url, limited_key)
    admin_client = Client(base_url, admin_key)
    metrics_client = Client(base_url, metrics_key)

    root_permissions = validate_permissions_list(root_client.get("/permissions", auth=True))
    admin_permissions = validate_permissions_list(admin_client.get("/permissions", auth=True))
    require(len(root_permissions) == 3, "root permissions list must include active clients")
    require(len(admin_permissions) == 3, "admin permissions list must include active clients")
    admin_entry = next(
        (client for client in root_permissions if client.get("client") == "positive-admin"),
        None,
    )
    require(admin_entry is not None, "permissions list must include admin client")
    require(admin_entry.get("admin") is True, "permissions list admin flag must be true")
    require(
        admin_entry.get("permissions") == [{"kid": "*", "actions": ["admin"]}],
        "permissions list must expose effective admin permission",
    )

    limited_result = encrypt_internal_message(limited_client, 1, key_id, case)
    validate_metrics(metrics_client)
    validate_init(admin_client.get("/self-test/init", auth=True))
    validate_routes_list(admin_client.get("/routes", auth=True))
    reload_config(ctx, admin_client)

    return [
        ("limited message key", "OK"),
        ("metrics key", "OK"),
        ("admin key", "OK"),
        ("root permissions list", "OK"),
        ("admin permissions list", "OK"),
        (f"limited ctx_hex_len {limited_result['ctx_hex_len']}", "OK"),
    ]


@cases('positive.permissions')
def run_permissions(ctx):
    key_id, case = ctx.artifacts["positive.keys"][0]
    rows = validate_permissions_flow(ctx, key_id, case)
    print_section("permissions", rows)
    return CaseResult(passed=len(rows))


CASES = cases.tuple()
