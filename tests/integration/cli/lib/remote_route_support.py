"""Minimal runtime helper for the CLI remote-route integration case.

This stays local to the CLI suite: importing the HTTP integration library would
couple two independently runnable test families.
"""

import json
import urllib.error
import urllib.request

from .cli_support import CliTestError, require


REMOTE_ROUTE_KEY_CASE = {
    "tag": "cli-remote-route",
    "profile": "hybrid-performance-v1",
    "hash_algorithm": "BLAKE2b(256)",
    "symmetric_algorithm": "ChaCha20Poly1305",
    "eddsa_algorithm": "Ed25519",
    "xecdh_algorithm": "X25519",
    "ml_dsa_variant": "ML-DSA-44",
    "ml_kem_variant": "ML-KEM-512",
}


def create_remote_route_key(base_url, apikey):
    """Create one runtime key used solely to import a remote route."""
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/keys",
        data=json.dumps(REMOTE_ROUTE_KEY_CASE).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-API-Key": apikey},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        detail = err.read().decode("utf-8", errors="replace")
        raise CliTestError(f"runtime key creation failed with {err.code}: {detail}") from err
    except (urllib.error.URLError, json.JSONDecodeError) as err:
        raise CliTestError(f"runtime key creation failed: {err}") from err

    kid = payload.get("kid")
    require(isinstance(kid, str) and len(kid) == 64, "runtime key must return a KID")
    return kid
