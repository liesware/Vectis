"""Negative HTTP contract cases: authorization enforcement.

Setup (negative.authz.bootstrap) builds the shared negative fixtures every later
module reuses: key_id, .api_key_hashes and the limited/metrics/admin/time
authz clients. Each case is a plain function taking ctx.
"""

import hashlib
import json

from lib.casekit import CaseSet
from lib.client import StatusClient, raw_http_request
from .negative_support import (
    HTTP_MAX_SIZE,
    VALID_MESSAGE,
    create_api_key_pair,
    create_valid_key,
    json_body_with_size,
    require,
    require_status,
    valid_commitment_profile,
    valid_fpe_profile,
    valid_mac_profile,
    valid_masking_profile,
    valid_sharing_profile,
    valid_tokenization_profile,
)

cases = CaseSet()


@cases("negative.authz.bootstrap", weight=0)
def _(ctx):
    key_id = create_valid_key(ctx.http)
    limited_api_key, limited_api_key_hash = create_api_key_pair()
    metrics_api_key, metrics_api_key_hash = create_api_key_pair()
    admin_api_key, admin_api_key_hash = create_api_key_pair()
    time_api_key, time_api_key_hash = create_api_key_pair()
    ctx.set_permissions(
        [
            {"client": "negative-limited-message", "apikey_hash": limited_api_key_hash,
             "status": "active", "permissions": [{"kid": key_id, "actions": ["message"]}]},
            {"client": "negative-metrics", "apikey_hash": metrics_api_key_hash,
             "status": "active", "permissions": [{"kid": "*", "actions": ["metrics"]}]},
            {"client": "negative-admin", "apikey_hash": admin_api_key_hash,
             "status": "active", "permissions": [{"kid": "*", "actions": ["admin"]}]},
            {"client": "negative-time-attest", "apikey_hash": time_api_key_hash,
             "status": "active", "permissions": [{"kid": "*", "actions": ["time-attest"]}]},
        ],
        # The profiles below are added to the same config_data and signed once by
        # the write_config() at the end of the bootstrap; signing here too would be
        # a wasted `cargo run -- config sign` on a config that is about to change.
        sign=False,
    )
    ctx.config_data["fpe_profiles"] = [valid_fpe_profile(key_id)]
    ctx.config_data["tokenization_profiles"] = [valid_tokenization_profile(key_id)]
    ctx.config_data["mac_profiles"] = [valid_mac_profile(key_id)]
    ctx.config_data["masking_profiles"] = [valid_masking_profile(key_id)]
    ctx.config_data["commitment_profiles"] = [valid_commitment_profile(key_id)]
    ctx.config_data["sharing_profiles"] = [valid_sharing_profile(key_id)]
    ctx.config_data["time_attestation"] = {"nts_server": "localhost", "roughtime_server": "127.0.0.1:9"}
    ctx.write_config()
    ctx.reload_config()
    fx = ctx.fixtures
    fx.key_id = key_id
    fx.api_key_hashes = {"limited": limited_api_key_hash, "metrics": metrics_api_key_hash, "admin": admin_api_key_hash}
    fx.limited = StatusClient(ctx.base_url, limited_api_key)
    fx.metrics = StatusClient(ctx.base_url, metrics_api_key)
    fx.admin = StatusClient(ctx.base_url, admin_api_key)
    fx.time = StatusClient(ctx.base_url, time_api_key)


@cases('negative.authz.limited-can-message')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        f"/message/internal/encrypt/{ctx.fixtures.key_id}",
        {"plaintext": "limited message permission"},
        auth=True,
    )
    require_status("limited client can message", status, 200)


@cases('negative.authz.limited-blocks-keys-reload')
def _(ctx):
    status, _ = ctx.fixtures.limited.post("/keys/reload", {}, auth=True)
    require_status("limited client blocks keys reload", status, 403)


@cases('negative.authz.limited-blocks-routes')
def _(ctx):
    status, _ = ctx.fixtures.limited.get("/routes", auth=True)
    require_status("limited client blocks routes", status, 403)


@cases('negative.authz.limited-blocks-self-test')
def _(ctx):
    status, _ = ctx.fixtures.limited.get("/self-test/init", auth=True)
    require_status("limited client blocks self-test init", status, 403)


@cases('negative.authz.limited-blocks-sign')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        f"/sign/{ctx.fixtures.key_id}",
        {
            "message_hash": {
                "alg": "SHA-256",
                "hex": hashlib.sha256(VALID_MESSAGE).hexdigest(),
            }
        },
        auth=True,
    )
    require_status("limited client blocks sign", status, 403)


@cases('negative.authz.limited-blocks-config-reload')
def _(ctx):
    status, _ = ctx.fixtures.limited.post("/config/reload", {}, auth=True)
    require_status("limited client blocks config reload", status, 403)


@cases('negative.authz.limited-blocks-metrics')
def _(ctx):
    status, _ = ctx.fixtures.limited.get("/metrics", auth=True)
    require_status("limited client blocks metrics", status, 403)


@cases('negative.authz.limited-blocks-fpe-encrypt')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        f"/fpe/encrypt/{ctx.fixtures.key_id}",
        {"ref": "fpe-limited", "profile": "patient-id-decimal-v1", "plaintext": "123456"},
        auth=True,
    )
    require_status("limited client blocks fpe encrypt", status, 403)


@cases('negative.authz.limited-blocks-fpe-decrypt')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        "/fpe/decrypt",
        {
            "ref": "fpe-limited",
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-decimal-v1",
            "ciphertext": "123456",
        },
        auth=True,
    )
    require_status("limited client blocks fpe decrypt", status, 403)


@cases('negative.authz.limited-blocks-fpe-encrypt-batch')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        f"/fpe/encrypt/batch/{ctx.fixtures.key_id}",
        {
            "profile": "patient-id-decimal-v1",
            "items": [{"ref": "fpe-limited", "plaintext": "123456"}],
        },
        auth=True,
    )
    require_status("limited client blocks fpe encrypt batch", status, 403)


@cases('negative.authz.limited-blocks-fpe-decrypt-batch')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        "/fpe/decrypt/batch",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-decimal-v1",
            "items": [{"ref": "fpe-limited", "ciphertext": "123456"}],
        },
        auth=True,
    )
    require_status("limited client blocks fpe decrypt batch", status, 403)


@cases('negative.authz.limited-blocks-token-encode')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        f"/token/encode/{ctx.fixtures.key_id}",
        {"ref": "token-limited", "profile": "patient-id-token-v1", "plaintext": "123456"},
        auth=True,
    )
    require_status("limited client blocks token encode", status, 403)


@cases('negative.authz.limited-blocks-token-encode-batch')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        f"/token/encode/batch/{ctx.fixtures.key_id}",
        {
            "profile": "patient-id-token-v1",
            "items": [{"ref": "token-limited", "plaintext": "123456"}],
        },
        auth=True,
    )
    require_status("limited client blocks token encode batch", status, 403)


@cases('negative.authz.limited-blocks-token-decode')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        "/token/decode",
        {
            "ref": "token-limited",
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-token-v1",
            "token": "tok_patient_missing",
        },
        auth=True,
    )
    require_status("limited client blocks token decode", status, 403)


@cases('negative.authz.limited-blocks-token-decode-batch')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        "/token/decode/batch",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-token-v1",
            "items": [{"ref": "token-limited", "token": "tok_patient_missing"}],
        },
        auth=True,
    )
    require_status("limited client blocks token decode batch", status, 403)


@cases('negative.authz.limited-blocks-mac-create')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        f"/mac/{ctx.fixtures.key_id}",
        {"ref": "mac-limited", "profile": "pan-blind-index-v1", "plaintext": "4111111111111111"},
        auth=True,
    )
    require_status("limited client blocks mac create", status, 403)


@cases('negative.authz.limited-blocks-mac-create-batch')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        f"/mac/batch/{ctx.fixtures.key_id}",
        {
            "profile": "pan-blind-index-v1",
            "items": [{"ref": "mac-limited", "plaintext": "4111111111111111"}],
        },
        auth=True,
    )
    require_status("limited client blocks mac create batch", status, 403)


@cases('negative.authz.limited-blocks-mac-verify')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        "/mac/verify",
        {
            "ref": "mac-limited",
            "kid": ctx.fixtures.key_id,
            "profile": "pan-blind-index-v1",
            "plaintext": "4111111111111111",
            "digest": "00" * 32,
        },
        auth=True,
    )
    require_status("limited client blocks mac verify", status, 403)


@cases('negative.authz.limited-blocks-mac-verify-batch')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        "/mac/verify/batch",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "pan-blind-index-v1",
            "items": [
                {
                    "ref": "mac-limited",
                    "plaintext": "4111111111111111",
                    "digest": "00" * 32,
                }
            ],
        },
        auth=True,
    )
    require_status("limited client blocks mac verify batch", status, 403)


@cases('negative.authz.limited-blocks-index-create')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        f"/index/{ctx.fixtures.key_id}",
        {"ref": "index-limited", "profile": "pan-blind-index-v1", "plaintext": "4111111111111111"},
        auth=True,
    )
    require_status("limited client blocks index create", status, 403)


@cases('negative.authz.limited-blocks-index-create-batch')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        f"/index/batch/{ctx.fixtures.key_id}",
        {
            "profile": "pan-blind-index-v1",
            "items": [{"ref": "index-limited", "plaintext": "4111111111111111"}],
        },
        auth=True,
    )
    require_status("limited client blocks index create batch", status, 403)


@cases('negative.authz.limited-blocks-index-verify')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        "/index/verify",
        {"ref": "index-limited", "kid": ctx.fixtures.key_id, "profile": "pan-blind-index-v1", "plaintext": "4111111111111111"},
        auth=True,
    )
    require_status("limited client blocks index verify", status, 403)


@cases('negative.authz.limited-blocks-index-verify-batch')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        "/index/verify/batch",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "pan-blind-index-v1",
            "items": [{"ref": "index-limited", "plaintext": "4111111111111111"}],
        },
        auth=True,
    )
    require_status("limited client blocks index verify batch", status, 403)


@cases('negative.authz.limited-blocks-mask')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        f"/mask/{ctx.fixtures.key_id}",
        {"ref": "mask-limited", "profile": "pan-display-v1", "plaintext": "4111111111111111"},
        auth=True,
    )
    require_status("limited client blocks mask", status, 403)


@cases('negative.authz.limited-blocks-mask-batch')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        f"/mask/batch/{ctx.fixtures.key_id}",
        {
            "profile": "pan-display-v1",
            "items": [{"ref": "mask-limited", "plaintext": "4111111111111111"}],
        },
        auth=True,
    )
    require_status("limited client blocks mask batch", status, 403)


@cases('negative.authz.limited-blocks-commit-create')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        f"/commit/{ctx.fixtures.key_id}",
        {"ref": "commit-limited", "profile": "pan-commitment-v1", "plaintext": "4111111111111111"},
        auth=True,
    )
    require_status("limited client blocks commit create", status, 403)


@cases('negative.authz.limited-blocks-commit-create-batch')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        f"/commit/batch/{ctx.fixtures.key_id}",
        {
            "profile": "pan-commitment-v1",
            "items": [{"ref": "commit-limited", "plaintext": "4111111111111111"}],
        },
        auth=True,
    )
    require_status("limited client blocks commit create batch", status, 403)


@cases('negative.authz.limited-blocks-commit-verify')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        "/commit/verify",
        {
            "ref": "commit-limited",
            "kid": ctx.fixtures.key_id,
            "profile": "pan-commitment-v1",
            "plaintext": "4111111111111111",
            "opening": "A" * 43,
            "commitment": "00" * 32,
        },
        auth=True,
    )
    require_status("limited client blocks commit verify", status, 403)


@cases('negative.authz.limited-blocks-commit-verify-batch')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        "/commit/verify/batch",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "pan-commitment-v1",
            "items": [
                {
                    "ref": "commit-limited",
                    "plaintext": "4111111111111111",
                    "opening": "A" * 43,
                    "commitment": "00" * 32,
                }
            ],
        },
        auth=True,
    )
    require_status("limited client blocks commit verify batch", status, 403)


@cases('negative.authz.limited-blocks-share-split')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        f"/shares/split/{ctx.fixtures.key_id}",
        {"profile": "customer-secret-3of5-v1", "plaintext": "customer-secret-value"},
        auth=True,
    )
    require_status("limited client blocks share split", status, 403)


@cases('negative.authz.limited-blocks-share-combine')
def _(ctx):
    status, _ = ctx.fixtures.limited.post(
        "/shares/combine",
        {
            "kid": ctx.fixtures.key_id,
            "profile": "customer-secret-3of5-v1",
            "shares": ["vectis-sss-v1.AAAA", "vectis-sss-v1.BBBB", "vectis-sss-v1.CCCC"],
        },
        auth=True,
    )
    require_status("limited client blocks share combine", status, 403)


@cases('negative.authz.metrics-client-allows-metrics')
def _(ctx):
    status, _ = ctx.fixtures.metrics.get("/metrics", auth=True)
    require_status("metrics client allows metrics", status, 200)


@cases('negative.authz.metrics-client-blocks-admin')
def _(ctx):
    status, _ = ctx.fixtures.metrics.get("/routes", auth=True)
    require_status("metrics client blocks admin", status, 403)


@cases('negative.authz.limited-blocks-permissions-list')
def _(ctx):
    status, _ = ctx.fixtures.limited.get("/permissions", auth=True)
    require_status("limited client blocks permissions list", status, 403)


@cases('negative.authz.time-attest-invalid-auth')
def _(ctx):
    status, _ = ctx.http.post(
        "/time/attest",
        None,
        headers={"X-API-Key": "00" * 32},
    )
    require_status("time attest invalid API key", status, 401)


@cases('negative.authz.limited-blocks-time-attest')
def _(ctx):
    status, _ = ctx.fixtures.limited.post("/time/attest", None, auth=True)
    require_status("limited client blocks time attest", status, 403)


@cases('negative.authz.time-attest-offline-source-failure')
def _(ctx):
    for path in ("/healthz/startup", "/healthz/live", "/healthz/ready"):
        status, _ = ctx.http.get(path)
        require_status(f"GET {path} before time attest", status, 200)
    status, response = ctx.fixtures.time.post("/time/attest", None, auth=True)
    require_status("time attest offline source failure", status, 502)
    require(
        response == {"error": "time attestation source unavailable"},
        "time attest source failure must not return partial observations",
    )
    for path in ("/healthz/startup", "/healthz/live", "/healthz/ready"):
        status, _ = ctx.http.get(path)
        require_status(f"GET {path} after time attest", status, 200)


@cases('negative.authz.http-protocol-contract')
def _(ctx):
    exact_body = json_body_with_size(HTTP_MAX_SIZE)
    status, response = raw_http_request(
        ctx.base_url,
        "POST",
        "/sign/verification",
        exact_body,
        {"Content-Type": "application/json"},
    )
    require_status("body at exact HTTP limit", status, 400)
    require(isinstance(response.get("error"), str), "exact-limit response must be JSON error")

    oversized_body = json_body_with_size(HTTP_MAX_SIZE + 1)
    status, response = raw_http_request(
        ctx.base_url,
        "POST",
        "/sign/verification",
        oversized_body,
        {"Content-Type": "application/json"},
    )
    require_status("body over HTTP limit", status, 413)
    require(
        response == {"error": "request body exceeds maximum allowed size"},
        "oversized body must use the exact 413 error contract",
    )

    for label, headers in (
        ("text content type", {"Content-Type": "text/plain"}),
        ("missing content type", {}),
    ):
        status, response = raw_http_request(
            ctx.base_url, "POST", "/sign/verification", b"{}", headers
        )
        require_status(f"{label} rejection", status, 415)
        require(
            response == {"error": "request content type must be application/json"},
            f"{label} must use the exact 415 error contract",
        )

    status, response = raw_http_request(
        ctx.base_url,
        "POST",
        "/sign/verification",
        b"",
        {"Content-Type": "application/json"},
    )
    require_status("empty JSON body", status, 400)
    require(isinstance(response.get("error"), str), "empty body response must be JSON error")

    for method in ("GET", "PUT", "DELETE", "PATCH", "HEAD"):
        status, _ = raw_http_request(
            ctx.base_url,
            method,
            "/sign/verification",
            b"{}",
            {"Content-Type": "application/json"},
        )
        require_status(f"{method} /sign/verification", status, 405)

    status, _ = ctx.http.get("/healthz/live")
    require_status("live after HTTP protocol contract", status, 200)


@cases('negative.authz.metrics-client-blocks-permissions-list')
def _(ctx):
    status, _ = ctx.fixtures.metrics.get("/permissions", auth=True)
    require_status("metrics client blocks permissions list", status, 403)


@cases('negative.authz.admin-allows-config-reload')
def _(ctx):
    status, response = ctx.fixtures.admin.post("/config/reload", {}, auth=True)
    require_status("admin client allows config reload", status, 200)
    require(response.get("status") == "reloaded", "admin config reload status")


@cases('negative.authz.admin-allows-permissions-list')
def _(ctx):
    status, response = ctx.fixtures.admin.get("/permissions", auth=True)
    require_status("admin client allows permissions list", status, 200)
    require(isinstance(response.get("clients"), list), "permissions.clients must be a list")
    require("apikey_hash" not in json.dumps(response), "permissions list must not expose apikey_hash")


@cases('negative.authz.admin-allows-fpe-round-trip')
def _(ctx):
    status, encrypted = ctx.fixtures.admin.post(
        f"/fpe/encrypt/{ctx.fixtures.key_id}",
        {"ref": "fpe-admin", "profile": "patient-id-decimal-v1", "plaintext": "123456"},
        auth=True,
    )
    require_status("admin client allows fpe encrypt", status, 200)
    require("fpe_version" not in encrypted, "fpe encrypt response must not include fpe_version")
    status, decrypted = ctx.fixtures.admin.post(
        "/fpe/decrypt",
        {
            "ref": "fpe-admin",
            "kid": ctx.fixtures.key_id,
            "profile": "patient-id-decimal-v1",
            "ciphertext": encrypted.get("ciphertext"),
        },
        auth=True,
    )
    require_status("admin client allows fpe decrypt", status, 200)
    require(decrypted.get("plaintext") == "123456", "admin fpe decrypt plaintext mismatch")



CASES = cases.tuple()
