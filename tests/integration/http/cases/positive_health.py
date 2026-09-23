"""Positive HTTP helpers for one capability domain."""

import base64
import hashlib
import json

from lib.assertions import require, require_request_id
from lib.casekit import CaseSet
from lib.results import CaseResult

cases = CaseSet()

def validate_init(response):
    require(response.get("timestamp"), "test init response must include timestamp")
    for field in ("hash", "symmetric", "eddsa", "xecdh", "ml-dsa", "ml-kem"):
        require(field in response, f"test init response must include {field}")


def validate_health(client):
    startup = client.get("/healthz/startup")
    require(startup.get("status") == "started", "health startup status must be started")
    require(startup.get("timestamp"), "health startup must include timestamp")

    live_status, live, live_headers = client.get_with_headers("/healthz/live")
    require(live_status == 200, "health live status code must be 200")
    require_request_id(live_headers)
    require(live.get("status") == "ok", "health live status must be ok")

    ready = client.get("/healthz/ready")
    require(ready.get("status") == "ready", "health ready status must be ready")
    require(ready.get("unsealed") is True, "health ready unsealed must be true")
    require(ready.get("storage") == "ok", "health ready storage must be ok")
    require(isinstance(ready.get("keys_loaded"), int), "health ready keys_loaded must be an integer")
    require(isinstance(ready.get("routes_loaded"), int), "health ready routes_loaded must be an integer")


def validate_metrics(client):
    metrics = client.get_text("/metrics", auth=True)
    require("http_requests_total" in metrics, "metrics must include http_requests_total")
    require(
        "http_request_duration_seconds" in metrics,
        "metrics must include http_request_duration_seconds",
    )
    require("auth_total" in metrics, "metrics must include auth_total")
    require("vectis_unsealed" in metrics, "metrics must include vectis_unsealed")
    require("vectis_keys_loaded" in metrics, "metrics must include vectis_keys_loaded")
    require("vectis_routes_loaded" in metrics, "metrics must include vectis_routes_loaded")
    require(
        "vectis_remote_routes_loaded" in metrics,
        "metrics must include vectis_remote_routes_loaded",
    )
    require(
        "vectis_permission_clients" in metrics,
        "metrics must include vectis_permission_clients",
    )
    require(
        "vectis_fpe_profiles_loaded" in metrics,
        "metrics must include vectis_fpe_profiles_loaded",
    )
    require(
        "vectis_tokenization_profiles_loaded" in metrics,
        "metrics must include vectis_tokenization_profiles_loaded",
    )
    require(
        "vectis_mac_profiles_loaded" in metrics,
        "metrics must include vectis_mac_profiles_loaded",
    )
    require(
        "vectis_masking_profiles_loaded" in metrics,
        "metrics must include vectis_masking_profiles_loaded",
    )
    require(
        "vectis_commitment_profiles_loaded" in metrics,
        "metrics must include vectis_commitment_profiles_loaded",
    )
    require(
        "vectis_sharing_profiles_loaded" in metrics,
        "metrics must include vectis_sharing_profiles_loaded",
    )


def validate_runtime_metrics(client):
    metrics = client.get_text("/metrics", auth=True)
    expected = [
        "vectis_config_reload_total",
        "vectis_config_last_reload_timestamp_seconds",
        "vectis_keys_reload_total",
        "vectis_permission_total",
        "vectis_message_total",
        "vectis_crypto_operation_total",
    ]
    for metric in expected:
        require(metric in metrics, f"metrics must include {metric}")

    require(
        'vectis_config_reload_total{result="success"}' in metrics,
        "metrics must include successful config reload count",
    )
    require(
        'vectis_keys_reload_total{result="success"}' in metrics,
        "metrics must include successful keys reload count",
    )
    require(
        'vectis_permission_total{result="allow"}' in metrics,
        "metrics must include allowed permission count",
    )
    require(
        'vectis_message_total{operation="send",result="success"}' in metrics,
        "metrics must include successful message send count",
    )
    require(
        'vectis_message_total{operation="receive",result="success"}' in metrics,
        "metrics must include successful message receive count",
    )
    require(
        'vectis_message_total{operation="decrypt",result="success"}' in metrics,
        "metrics must include successful message decrypt count",
    )
    require(
        'vectis_crypto_operation_total{operation="sign",result="success"}' in metrics,
        "metrics must include successful sign count",
    )
    require(
        'vectis_crypto_operation_total{operation="verify",result="success"}' in metrics,
        "metrics must include successful verify count",
    )
    require(
        'vectis_crypto_operation_total{operation="encrypt",result="success"}' in metrics,
        "metrics must include successful encrypt count",
    )
    require(
        'vectis_crypto_operation_total{operation="decrypt",result="success"}' in metrics,
        "metrics must include successful decrypt count",
    )
    require(
        'vectis_crypto_operation_total{operation="fpe_encrypt",result="success"}' in metrics,
        "metrics must include successful fpe encrypt count",
    )
    require(
        'vectis_crypto_operation_total{operation="fpe_decrypt",result="success"}' in metrics,
        "metrics must include successful fpe decrypt count",
    )
    require(
        'vectis_crypto_operation_total{operation="fpe_encrypt_batch",result="success"}' in metrics,
        "metrics must include successful fpe encrypt batch count",
    )
    require(
        'vectis_crypto_operation_total{operation="fpe_decrypt_batch",result="success"}' in metrics,
        "metrics must include successful fpe decrypt batch count",
    )
    require(
        'vectis_crypto_operation_total{operation="token_encode",result="success"}' in metrics,
        "metrics must include successful token encode count",
    )
    require(
        'vectis_crypto_operation_total{operation="token_decode",result="success"}' in metrics,
        "metrics must include successful token decode count",
    )
    require(
        'vectis_crypto_operation_total{operation="token_encode_batch",result="success"}' in metrics,
        "metrics must include successful token encode batch count",
    )
    require(
        'vectis_crypto_operation_total{operation="token_decode_batch",result="success"}' in metrics,
        "metrics must include successful token decode batch count",
    )
    require(
        'vectis_crypto_operation_total{operation="mac_create",result="success"}' in metrics,
        "metrics must include successful mac create count",
    )
    require(
        'vectis_crypto_operation_total{operation="mac_verify",result="success"}' in metrics,
        "metrics must include successful mac verify count",
    )
    require(
        'vectis_crypto_operation_total{operation="mac_create_batch",result="success"}' in metrics,
        "metrics must include successful mac create batch count",
    )
    require(
        'vectis_crypto_operation_total{operation="mac_verify_batch",result="success"}' in metrics,
        "metrics must include successful mac verify batch count",
    )
    require(
        'vectis_crypto_operation_total{operation="commit_create",result="success"}' in metrics,
        "metrics must include successful commit create count",
    )
    require(
        'vectis_crypto_operation_total{operation="commit_verify",result="success"}' in metrics,
        "metrics must include successful commit verify count",
    )
    require(
        'vectis_crypto_operation_total{operation="commit_create_batch",result="success"}' in metrics,
        "metrics must include successful commit create batch count",
    )
    require(
        'vectis_crypto_operation_total{operation="commit_verify_batch",result="success"}' in metrics,
        "metrics must include successful commit verify batch count",
    )
    require(
        'vectis_crypto_operation_total{operation="share_split",result="success"}' in metrics,
        "metrics must include successful share split count",
    )
    require(
        'vectis_crypto_operation_total{operation="share_combine",result="success"}' in metrics,
        "metrics must include successful share combine count",
    )
    require(
        'vectis_crypto_operation_total{operation="index_create",result="success"}' in metrics,
        "metrics must include successful index create count",
    )
    require(
        'vectis_crypto_operation_total{operation="index_verify",result="success"}' in metrics,
        "metrics must include successful index verify count",
    )
    require(
        'vectis_crypto_operation_total{operation="index_create_batch",result="success"}' in metrics,
        "metrics must include successful index create batch count",
    )
    require(
        'vectis_crypto_operation_total{operation="index_verify_batch",result="success"}' in metrics,
        "metrics must include successful index verify batch count",
    )


@cases('positive.health')
def run_health(ctx):
    validate_health(ctx.client)
    print("Health: OK\n")
    return CaseResult()


@cases('positive.metrics')
def run_metrics(ctx):
    validate_metrics(ctx.client)
    print("Metrics: OK\n")
    return CaseResult()


@cases('positive.init')
def run_init(ctx):
    validate_init(ctx.client.get("/self-test/init", auth=True))
    print("Test init: OK\n")
    return CaseResult()


@cases('positive.runtime-metrics')
def run_runtime_metrics(ctx):
    validate_runtime_metrics(ctx.client)
    print("Runtime metrics: OK\n")
    return CaseResult()


CASES = cases.tuple()
