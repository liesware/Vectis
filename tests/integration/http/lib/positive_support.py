"""HTTP-only constants and configuration helpers for positive cases."""

from .assertions import require
from .client import StatusClient


DEFAULT_BASE_URL = "http://127.0.0.1:3000"
DEFAULT_FINAL_APP_ADDR = "localhost:3999"
MESSAGE = "The things you own end up owning you."

KEY_CASES = (
    {
        "tag": "1", "profile": "hybrid-performance-v1", "hash_algorithm": "BLAKE2b(256)",
        "symmetric_algorithm": "ChaCha20Poly1305", "eddsa_algorithm": "Ed25519",
        "xecdh_algorithm": "X25519", "ml_dsa_variant": "ML-DSA-44", "ml_kem_variant": "ML-KEM-512",
    },
    {
        "tag": "2", "profile": "hybrid-standard-v1", "hash_algorithm": "SHA-3(256)",
        "symmetric_algorithm": "AES-128/GCM", "eddsa_algorithm": "Ed25519",
        "xecdh_algorithm": "X25519", "ml_dsa_variant": "ML-DSA-44", "ml_kem_variant": "ML-KEM-512",
    },
    {
        "tag": "3", "profile": "hybrid-high-assurance-v1", "hash_algorithm": "SHA-3(384)",
        "symmetric_algorithm": "AES-192/GCM", "eddsa_algorithm": "Ed25519",
        "xecdh_algorithm": "X25519", "ml_dsa_variant": "ML-DSA-65", "ml_kem_variant": "ML-KEM-768",
    },
    {
        "tag": "4", "profile": "hybrid-long-term-v1", "hash_algorithm": "SHA-3(512)",
        "symmetric_algorithm": "AES-256/GCM", "eddsa_algorithm": "Ed448",
        "xecdh_algorithm": "X448", "ml_dsa_variant": "ML-DSA-87", "ml_kem_variant": "ML-KEM-1024",
    },
)


def reload_config(ctx, client=None):
    """Reload the signed config through the root client or an authorized client."""
    if client is None or client is ctx.client:
        return ctx.reload_config()
    response = client.post("/config/reload", {}, auth=True)
    require(response.get("status") == "reloaded", "config reload status must be reloaded")
    return response


def write_test_routes(ctx, key_ids):
    ctx.config_data["routes"] = [
        {
            "kid": key_id,
            "name": f"final-app-{index}",
            "final_app_addr": ctx.final_app_addr,
            "final_app_path": "/message",
        }
        for index, key_id in enumerate(key_ids, start=1)
    ]
    ctx.write_config()


def write_test_remote_routes(ctx, key_ids, wildcard=False):
    ctx.config_data["remote_routes"] = [
        {
            "remote_kid": key_id,
            "name": f"positive-{index}",
            "remote_addr": ctx.artifacts["positive.recipient_host"],
            "allowed_local_kids": ["*"] if wildcard else [key_id],
            "status": "active",
            "public_keys": ctx.client.get(f"/pub/{key_id}")["keys"],
        }
        for index, key_id in enumerate(key_ids, start=1)
    ]
    ctx.write_config()


def set_profiles(ctx, section, profiles):
    ctx.config_data[section] = profiles
    ctx.write_config()
