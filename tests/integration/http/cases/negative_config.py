"""Negative HTTP contract cases: config object validation.

Each case isolates one config section with a deliberately bad value and asserts
the unified reload rejects it. Reads key_id and ctx.fixtures.api_key_hashes
(produced by the authz bootstrap). restore-permissions runs last (weight 0) to put
the valid permission set back for the modules that follow.
"""

import copy

from lib.casekit import CaseSet
from lib.client import raw_request
from lib.fixtures import host_from_base_url
from .negative_support import (
    CONFIG_SIGN_PATH,
    require,
    require_config_sign_fails,
    require_hex,
    require_status,
    try_sign_config,
    valid_commitment_profile,
    valid_fpe_profile,
    valid_mac_profile,
    valid_masking_profile,
    valid_tokenization_profile,
)

cases = CaseSet()


def _peer_public_keys(ctx):
    status, response = ctx.http.get(f"/pub/{ctx.fixtures.key_id}")
    require_status("GET /pub for remote route public keys", status, 200)
    keys = response.get("keys")
    require(isinstance(keys, dict), "pub response keys must be an object")
    return copy.deepcopy(keys)


@cases('negative.config.permissions-invalid-action-pub')
def _(ctx):
    ctx.set_permissions(
        [
            {
                "client": "bad-action",
                "apikey_hash": ctx.fixtures.api_key_hashes["limited"],
                "status": "active",
                "permissions": [{"kid": ctx.fixtures.key_id, "actions": ["pub"]}],
            }
        ],
        sign=False,
    )
    require_config_sign_fails("permissions invalid action pub")


@cases('negative.config.permissions-invalid-action-routes')
def _(ctx):
    ctx.set_permissions(
        [
            {
                "client": "bad-action-routes",
                "apikey_hash": ctx.fixtures.api_key_hashes["limited"],
                "status": "active",
                "permissions": [{"kid": ctx.fixtures.key_id, "actions": ["routes"]}],
            }
        ],
        sign=False,
    )
    require_config_sign_fails("permissions invalid action routes")


@cases('negative.config.permissions-wildcard-non-global-action')
def _(ctx):
    ctx.set_permissions(
        [
            {
                "client": "bad-wildcard-message",
                "apikey_hash": ctx.fixtures.api_key_hashes["limited"],
                "status": "active",
                "permissions": [{"kid": "*", "actions": ["message"]}],
            }
        ],
        sign=False,
    )
    require_config_sign_fails("permissions wildcard non-global action")


@cases('negative.config.permissions-wildcard-fpe-encrypt')
def _(ctx):
    ctx.set_permissions(
        [
            {
                "client": "bad-wildcard-fpe",
                "apikey_hash": ctx.fixtures.api_key_hashes["limited"],
                "status": "active",
                "permissions": [{"kid": "*", "actions": ["fpe-encrypt"]}],
            }
        ],
        sign=False,
    )
    require_config_sign_fails("permissions wildcard fpe encrypt")


@cases('negative.config.permissions-wildcard-token-encode')
def _(ctx):
    ctx.set_permissions(
        [
            {
                "client": "bad-wildcard-token",
                "apikey_hash": ctx.fixtures.api_key_hashes["limited"],
                "status": "active",
                "permissions": [{"kid": "*", "actions": ["token-encode"]}],
            }
        ],
        sign=False,
    )
    require_config_sign_fails("permissions wildcard token encode")


@cases('negative.config.permissions-wildcard-mac-create')
def _(ctx):
    ctx.set_permissions(
        [
            {
                "client": "bad-wildcard-mac",
                "apikey_hash": ctx.fixtures.api_key_hashes["limited"],
                "status": "active",
                "permissions": [{"kid": "*", "actions": ["mac-create"]}],
            }
        ],
        sign=False,
    )
    require_config_sign_fails("permissions wildcard mac create")


@cases('negative.config.permissions-wildcard-index-create')
def _(ctx):
    ctx.set_permissions(
        [
            {
                "client": "bad-wildcard-index",
                "apikey_hash": ctx.fixtures.api_key_hashes["limited"],
                "status": "active",
                "permissions": [{"kid": "*", "actions": ["index-create"]}],
            }
        ],
        sign=False,
    )
    require_config_sign_fails("permissions wildcard index create")


@cases('negative.config.permissions-wildcard-mask')
def _(ctx):
    ctx.set_permissions(
        [
            {
                "client": "bad-wildcard-mask",
                "apikey_hash": ctx.fixtures.api_key_hashes["limited"],
                "status": "active",
                "permissions": [{"kid": "*", "actions": ["mask"]}],
            }
        ],
        sign=False,
    )
    require_config_sign_fails("permissions wildcard mask")


@cases('negative.config.permissions-wildcard-commit-create')
def _(ctx):
    ctx.set_permissions(
        [
            {
                "client": "bad-wildcard-commit",
                "apikey_hash": ctx.fixtures.api_key_hashes["limited"],
                "status": "active",
                "permissions": [{"kid": "*", "actions": ["commit-create"]}],
            }
        ],
        sign=False,
    )
    require_config_sign_fails("permissions wildcard commit create")


@cases('negative.config.fpe-profile-duplicate-name')
def _(ctx):
    profile = valid_fpe_profile(ctx.fixtures.key_id)
    ctx.only_fpe_profiles([profile, dict(profile, kid=ctx.fixtures.key_id)], sign=False)
    require_config_sign_fails("fpe profile duplicate name")


@cases('negative.config.fpe-profile-invalid-version')
def _(ctx):
    profile = valid_fpe_profile(ctx.fixtures.key_id)
    profile["fpe_version"] = "fpe-ff1-legacy"
    ctx.only_fpe_profiles([profile], sign=False)
    require_config_sign_fails("fpe profile invalid version")


@cases('negative.config.fpe-profile-duplicate-alphabet')
def _(ctx):
    profile = valid_fpe_profile(ctx.fixtures.key_id)
    profile["alphabet"] = "00123456789"
    ctx.only_fpe_profiles([profile], sign=False)
    require_config_sign_fails("fpe profile duplicate alphabet")


@cases('negative.config.fpe-profile-invalid-lengths')
def _(ctx):
    profile = valid_fpe_profile(ctx.fixtures.key_id)
    profile["min_len"] = 32
    profile["max_len"] = 6
    ctx.only_fpe_profiles([profile], sign=False)
    require_config_sign_fails("fpe profile invalid lengths")


@cases('negative.config.fpe-profile-max-len-too-large')
def _(ctx):
    profile = valid_fpe_profile(ctx.fixtures.key_id)
    profile["max_len"] = 1025
    ctx.only_fpe_profiles([profile], sign=False)
    require_config_sign_fails("fpe profile max len too large")


@cases('negative.config.fpe-profile-unloaded-kid')
def _(ctx):
    profile = valid_fpe_profile("00" * 32)
    ctx.only_fpe_profiles([profile], sign=False)
    require_config_sign_fails("fpe profile unloaded kid")


@cases('negative.config.token-profile-duplicate-name')
def _(ctx):
    profile = valid_tokenization_profile(ctx.fixtures.key_id)
    ctx.only_tokenization_profiles([profile, dict(profile, kid=ctx.fixtures.key_id)], sign=False)
    require_config_sign_fails("token profile duplicate name")


@cases('negative.config.token-profile-unknown-version-field')
def _(ctx):
    profile = valid_tokenization_profile(ctx.fixtures.key_id)
    profile["tokenization_version"] = "token-random-v1"
    ctx.only_tokenization_profiles([profile], sign=False)
    require_config_sign_fails("token profile unknown tokenization_version field")


@cases('negative.config.token-profile-missing-one-time')
def _(ctx):
    profile = valid_tokenization_profile(ctx.fixtures.key_id)
    del profile["one_time"]
    ctx.only_tokenization_profiles([profile], sign=False)
    require_config_sign_fails("token profile missing one_time")


@cases('negative.config.token-profile-invalid-lengths')
def _(ctx):
    profile = valid_tokenization_profile(ctx.fixtures.key_id)
    profile["token_len"] = 31
    ctx.only_tokenization_profiles([profile], sign=False)
    require_config_sign_fails("token profile invalid token_len")


@cases('negative.config.token-profile-unloaded-kid')
def _(ctx):
    profile = valid_tokenization_profile("00" * 32)
    ctx.only_tokenization_profiles([profile], sign=False)
    require_config_sign_fails("token profile unloaded kid")


@cases('negative.config.mac-profile-duplicate-name')
def _(ctx):
    profile = valid_mac_profile(ctx.fixtures.key_id)
    ctx.only_mac_profiles([profile, dict(profile, kid=ctx.fixtures.key_id)], sign=False)
    require_config_sign_fails("mac profile duplicate name")


@cases('negative.config.mac-profile-invalid-context')
def _(ctx):
    profile = valid_mac_profile(ctx.fixtures.key_id)
    profile["context"] = "tenant"
    ctx.only_mac_profiles([profile], sign=False)
    require_config_sign_fails("mac profile invalid context")


@cases('negative.config.mac-profile-unloaded-kid')
def _(ctx):
    profile = valid_mac_profile("00" * 32)
    ctx.only_mac_profiles([profile], sign=False)
    require_config_sign_fails("mac profile unloaded kid")


@cases('negative.config.masking-profile-duplicate-name')
def _(ctx):
    profile = valid_masking_profile(ctx.fixtures.key_id)
    ctx.only_masking_profiles([profile, dict(profile, kid=ctx.fixtures.key_id)], sign=False)
    require_config_sign_fails("masking profile duplicate name")


@cases('negative.config.masking-profile-invalid-mask-char')
def _(ctx):
    profile = valid_masking_profile(ctx.fixtures.key_id)
    profile["mask_char"] = "**"
    ctx.only_masking_profiles([profile], sign=False)
    require_config_sign_fails("masking profile invalid mask char")


@cases('negative.config.masking-profile-invalid-visible-bounds')
def _(ctx):
    profile = valid_masking_profile(ctx.fixtures.key_id)
    profile["visible_first"] = 8
    profile["visible_last"] = 4
    ctx.only_masking_profiles([profile], sign=False)
    require_config_sign_fails("masking profile invalid visible bounds")


@cases('negative.config.masking-profile-unloaded-kid')
def _(ctx):
    profile = valid_masking_profile("00" * 32)
    ctx.only_masking_profiles([profile], sign=False)
    require_config_sign_fails("masking profile unloaded kid")


@cases('negative.config.commitment-profile-duplicate-name')
def _(ctx):
    profile = valid_commitment_profile(ctx.fixtures.key_id)
    ctx.config_data["routes"] = []
    ctx.config_data["remote_routes"] = []
    ctx.config_data["permissions"] = []
    ctx.config_data["fpe_profiles"] = []
    ctx.config_data["tokenization_profiles"] = []
    ctx.config_data["mac_profiles"] = []
    ctx.config_data["masking_profiles"] = []
    ctx.config_data["commitment_profiles"] = [profile, dict(profile, kid=ctx.fixtures.key_id)]
    ctx.write_unsigned_config()
    require_config_sign_fails("commitment profile duplicate name")


@cases('negative.config.commitment-profile-invalid-context')
def _(ctx):
    profile = valid_commitment_profile(ctx.fixtures.key_id)
    profile["context"] = "tenant"
    ctx.config_data["routes"] = []
    ctx.config_data["remote_routes"] = []
    ctx.config_data["permissions"] = []
    ctx.config_data["fpe_profiles"] = []
    ctx.config_data["tokenization_profiles"] = []
    ctx.config_data["mac_profiles"] = []
    ctx.config_data["masking_profiles"] = []
    ctx.config_data["commitment_profiles"] = [profile]
    ctx.write_unsigned_config()
    require_config_sign_fails("commitment profile invalid context")


@cases('negative.config.commitment-profile-invalid-opening-len')
def _(ctx):
    profile = valid_commitment_profile(ctx.fixtures.key_id)
    profile["opening_len"] = 31
    ctx.config_data["routes"] = []
    ctx.config_data["remote_routes"] = []
    ctx.config_data["permissions"] = []
    ctx.config_data["fpe_profiles"] = []
    ctx.config_data["tokenization_profiles"] = []
    ctx.config_data["mac_profiles"] = []
    ctx.config_data["masking_profiles"] = []
    ctx.config_data["commitment_profiles"] = [profile]
    ctx.write_unsigned_config()
    require_config_sign_fails("commitment profile invalid opening_len")


@cases('negative.config.commitment-profile-unloaded-kid')
def _(ctx):
    profile = valid_commitment_profile("00" * 32)
    ctx.config_data["routes"] = []
    ctx.config_data["remote_routes"] = []
    ctx.config_data["permissions"] = []
    ctx.config_data["fpe_profiles"] = []
    ctx.config_data["tokenization_profiles"] = []
    ctx.config_data["mac_profiles"] = []
    ctx.config_data["masking_profiles"] = []
    ctx.config_data["commitment_profiles"] = [profile]
    ctx.write_unsigned_config()
    require_config_sign_fails("commitment profile unloaded kid")


@cases('negative.config.routes-missing-name')
def _(ctx):
    ctx.set_routes(
        [
            {
                "kid": ctx.fixtures.key_id,
                "final_app_addr": "localhost:3999",
                "final_app_path": "/message",
            }
        ],
        sign=False,
    )
    result = try_sign_config()
    require(result.returncode != 0, "routes missing name must fail config sign")
    require(
        "missing field `name`" in result.stderr,
        "routes missing name must report missing name",
    )


@cases('negative.config.routes-invalid-name')
def _(ctx):
    ctx.set_routes(
        [
            {
                "kid": ctx.fixtures.key_id,
                "name": "",
                "final_app_addr": "localhost:3999",
                "final_app_path": "/message",
            }
        ],
        sign=False,
    )
    require_config_sign_fails("routes invalid name")


@cases('negative.config.remote-routes-invalid-kid')
def _(ctx):
    ctx.set_remote_routes(
        [
            {
                "remote_kid": "not-hex",
                "name": "bad kid",
                "remote_addr": host_from_base_url(ctx.base_url),
                "allowed_local_kids": [ctx.fixtures.key_id],
                "status": "active",
            }
        ],
        sign=False,
    )
    require_config_sign_fails("remote routes invalid kid")


@cases('negative.config.remote-routes-invalid-addr')
def _(ctx):
    ctx.set_remote_routes(
        [
            {
                "remote_kid": ctx.fixtures.key_id,
                "name": "bad addr",
                "remote_addr": "not-a-socket-address",
                "allowed_local_kids": [ctx.fixtures.key_id],
                "status": "active",
            }
        ],
        sign=False,
    )
    require_config_sign_fails("remote routes invalid addr")


@cases('negative.config.remote-routes-invalid-signature')
def _(ctx):
    ctx.set_remote_routes(
        [
            {
                "remote_kid": ctx.fixtures.key_id,
                "name": "invalid signature",
                "remote_addr": host_from_base_url(ctx.base_url),
                "allowed_local_kids": [ctx.fixtures.key_id],
                "status": "active",
            }
        ]
    )
    CONFIG_SIGN_PATH.write_text('{"invalid":true}\n', encoding="utf-8")
    status, _ = ctx.http.post("/config/reload", {}, auth=True)
    require_status("remote routes invalid signature", status, 400)


@cases('negative.config.remote-routes-empty-allowed-local-kids')
def _(ctx):
    ctx.set_remote_routes(
        [
            {
                "remote_kid": ctx.fixtures.key_id,
                "name": "empty allowed",
                "remote_addr": host_from_base_url(ctx.base_url),
                "allowed_local_kids": [],
                "status": "active",
            }
        ],
        sign=False,
    )
    require_config_sign_fails("remote routes empty allowed local kids")


@cases('negative.config.remote-routes-wildcard-mixed-with-kid')
def _(ctx):
    ctx.set_remote_routes(
        [
            {
                "remote_kid": ctx.fixtures.key_id,
                "name": "mixed wildcard",
                "remote_addr": host_from_base_url(ctx.base_url),
                "allowed_local_kids": ["*", ctx.fixtures.key_id],
                "status": "active",
            }
        ],
        sign=False,
    )
    require_config_sign_fails("remote routes wildcard mixed with kid")


@cases('negative.config.remote-routes-invalid-allowed-local-kid')
def _(ctx):
    ctx.set_remote_routes(
        [
            {
                "remote_kid": ctx.fixtures.key_id,
                "name": "invalid allowed kid",
                "remote_addr": host_from_base_url(ctx.base_url),
                "allowed_local_kids": ["not-hex"],
                "status": "active",
            }
        ],
        sign=False,
    )
    require_config_sign_fails("remote routes invalid allowed local kid")


@cases('negative.config.remote-routes-unloaded-allowed-local-kid')
def _(ctx):
    ctx.set_remote_routes(
        [
            {
                "remote_kid": ctx.fixtures.key_id,
                "name": "unloaded allowed kid",
                "remote_addr": host_from_base_url(ctx.base_url),
                "allowed_local_kids": ["00" * 32],
                "status": "active",
            }
        ],
        sign=False,
    )
    require_config_sign_fails("remote routes unloaded allowed local kid")


@cases('negative.config.remote-routes-invalid-status')
def _(ctx):
    ctx.set_remote_routes(
        [
            {
                "remote_kid": ctx.fixtures.key_id,
                "name": "invalid status",
                "remote_addr": host_from_base_url(ctx.base_url),
                "allowed_local_kids": [ctx.fixtures.key_id],
                "status": "paused",
            }
        ],
        sign=False,
    )
    require_config_sign_fails("remote routes invalid status")


@cases('negative.config.remote-routes-invalid-public-key-alg')
def _(ctx):
    public_keys = _peer_public_keys(ctx)
    public_keys["eddsa"]["alg"] = "RSA"
    ctx.set_remote_routes(
        [
            {
                "remote_kid": ctx.fixtures.key_id,
                "name": "bad public key alg",
                "remote_addr": host_from_base_url(ctx.base_url),
                "allowed_local_kids": [ctx.fixtures.key_id],
                "status": "active",
                "public_keys": public_keys,
            }
        ],
        sign=False,
    )
    require_config_sign_fails("remote routes invalid public key alg")


@cases('negative.config.remote-routes-invalid-public-key-hex')
def _(ctx):
    public_keys = _peer_public_keys(ctx)
    public_keys["xecdh"]["public_key_hex"] = "zz"
    ctx.set_remote_routes(
        [
            {
                "remote_kid": ctx.fixtures.key_id,
                "name": "bad public key hex",
                "remote_addr": host_from_base_url(ctx.base_url),
                "allowed_local_kids": [ctx.fixtures.key_id],
                "status": "active",
                "public_keys": public_keys,
            }
        ],
        sign=False,
    )
    require_config_sign_fails("remote routes invalid public key hex")


@cases('negative.config.remote-routes-invalid-public-key-der')
def _(ctx):
    public_keys = _peer_public_keys(ctx)
    public_keys["eddsa"]["public_key_der_hex"] = "aa"
    ctx.set_remote_routes(
        [
            {
                "remote_kid": ctx.fixtures.key_id,
                "name": "bad public key der",
                "remote_addr": host_from_base_url(ctx.base_url),
                "allowed_local_kids": [ctx.fixtures.key_id],
                "status": "active",
                "public_keys": public_keys,
            }
        ],
        sign=False,
    )
    require_config_sign_fails("remote routes invalid public key der")


@cases('negative.config.permissions-missing-kid')
def _(ctx):
    ctx.set_permissions(
        [
            {
                "client": "missing-kid",
                "apikey_hash": ctx.fixtures.api_key_hashes["limited"],
                "status": "active",
                "permissions": [{"kid": "00" * 32, "actions": ["message"]}],
            }
        ],
        sign=False,
    )
    require_config_sign_fails("permissions missing kid")


@cases('negative.config.permissions-invalid-apikey-hash')
def _(ctx):
    ctx.set_permissions(
        [
            {
                "client": "bad-hash",
                "apikey_hash": "not-hex",
                "status": "active",
                "permissions": [{"kid": ctx.fixtures.key_id, "actions": ["message"]}],
            }
        ],
        sign=False,
    )
    require_config_sign_fails("permissions invalid apikey_hash")


@cases('negative.config.permissions-invalid-status')
def _(ctx):
    ctx.set_permissions(
        [
            {
                "client": "bad-status",
                "apikey_hash": ctx.fixtures.api_key_hashes["limited"],
                "status": "paused",
                "permissions": [{"kid": ctx.fixtures.key_id, "actions": ["message"]}],
            }
        ],
        sign=False,
    )
    require_config_sign_fails("permissions invalid status")


@cases('negative.config.permissions-invalid-signature')
def _(ctx):
    ctx.set_permissions(
        [
            {
                "client": "invalid-signature",
                "apikey_hash": ctx.fixtures.api_key_hashes["limited"],
                "status": "active",
                "permissions": [{"kid": ctx.fixtures.key_id, "actions": ["message"]}],
            }
        ]
    )
    CONFIG_SIGN_PATH.write_text('{"invalid":true}\n', encoding="utf-8")
    status, _ = ctx.http.post("/config/reload", {}, auth=True)
    require_status("permissions invalid signature", status, 400)


@cases("negative.config.restore-permissions", weight=0)
def _(ctx):
    ctx.set_permissions(
        [
            {
                "client": "negative-limited-message",
                "apikey_hash": ctx.fixtures.api_key_hashes["limited"],
                "status": "active",
                "permissions": [
                    {
                        "kid": ctx.fixtures.key_id,
                        "actions": ["message"],
                    }
                ],
            },
            {
                "client": "negative-admin",
                "apikey_hash": ctx.fixtures.api_key_hashes["admin"],
                "status": "active",
                "permissions": [
                    {
                        "kid": "*",
                        "actions": ["admin"],
                    }
                ],
            },
            {
                "client": "negative-metrics",
                "apikey_hash": ctx.fixtures.api_key_hashes["metrics"],
                "status": "active",
                "permissions": [
                    {
                        "kid": "*",
                        "actions": ["metrics"],
                    }
                ],
            },
        ]
    )
    ctx.reload_config()


CASES = cases.tuple()
