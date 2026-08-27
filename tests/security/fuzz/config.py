import atexit
import json
import subprocess
from pathlib import Path

from oracle import _parse
from semantics import (
    COMMITMENT_PROFILE,
    FPE_PROFILE,
    MAC_PROFILE,
    MASKING_PROFILE,
    SHARING_PROFILE,
    TOKENIZATION_PROFILE,
)


DEFAULT_BASE_URL = "http://127.0.0.1:3000"
CONFIG_PATH = Path("config.json")
CONFIG_SIGN_PATH = Path("config_sign.json")
UNSEAL_KEY_FILE = Path(".unseal_key")


def sign_config_file():
    result = subprocess.run(
        ["cargo", "run", "--quiet", "--", "config", "sign", "--output", "json"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"config sign failed: {result.stderr or result.stdout}")


def empty_config():
    return {
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
    }


def read_config_or_empty():
    if not CONFIG_PATH.exists():
        return empty_config()
    parsed = _parse(CONFIG_PATH.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        return empty_config()
    config = empty_config()
    config.update(parsed)
    for key in (
        "routes",
        "remote_routes",
        "permissions",
        "fpe_profiles",
        "tokenization_profiles",
        "mac_profiles",
        "masking_profiles",
        "commitment_profiles",
        "sharing_profiles",
    ):
        if not isinstance(config.get(key), list):
            config[key] = []
    return config


def build_config_baseline():
    original_cfg = CONFIG_PATH.read_bytes() if CONFIG_PATH.exists() else None
    original_sig = CONFIG_SIGN_PATH.read_bytes() if CONFIG_SIGN_PATH.exists() else None
    CONFIG_PATH.write_text(
        json.dumps(empty_config(), indent=2),
        encoding="utf-8",
    )
    sign_config_file()
    baseline_cfg = CONFIG_PATH.read_bytes()
    baseline_sig = CONFIG_SIGN_PATH.read_bytes()

    def restore():
        if original_cfg is None:
            CONFIG_PATH.unlink(missing_ok=True)
        else:
            CONFIG_PATH.write_bytes(original_cfg)
        if original_sig is None:
            CONFIG_SIGN_PATH.unlink(missing_ok=True)
        else:
            CONFIG_SIGN_PATH.write_bytes(original_sig)

    atexit.register(restore)
    return baseline_cfg, baseline_sig


def configure_fpe_profile(client, kid):
    original_cfg = CONFIG_PATH.read_bytes() if CONFIG_PATH.exists() else None
    original_sig = CONFIG_SIGN_PATH.read_bytes() if CONFIG_SIGN_PATH.exists() else None
    config = read_config_or_empty()
    config["fpe_profiles"] = [
        {
            "name": FPE_PROFILE,
            "fpe_version": "fpe-ff1-2025",
            "alphabet": "0123456789",
            "min_len": 6,
            "max_len": 32,
            "tweak_aad": "tenant=fuzz;field=patient_id;version=1",
            "kid": kid,
        }
    ]
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    sign_config_file()
    status, body = client.post_json("/config/reload", {}, auth=True)
    if status != 200:
        raise RuntimeError(f"could not load fpe seed config: HTTP {status}: {body}")

    def restore():
        if original_cfg is None:
            CONFIG_PATH.unlink(missing_ok=True)
        else:
            CONFIG_PATH.write_bytes(original_cfg)
        if original_sig is None:
            CONFIG_SIGN_PATH.unlink(missing_ok=True)
        else:
            CONFIG_SIGN_PATH.write_bytes(original_sig)

    atexit.register(restore)


def configure_tokenization_profile(client, kid):
    original_cfg = CONFIG_PATH.read_bytes() if CONFIG_PATH.exists() else None
    original_sig = CONFIG_SIGN_PATH.read_bytes() if CONFIG_SIGN_PATH.exists() else None
    config = read_config_or_empty()
    config["tokenization_profiles"] = [
        {
            "name": TOKENIZATION_PROFILE,
            "kid": kid,
            "token_prefix": "tok_fuzz",
            "token_len": 32,
            "max_plaintext_len": 1024,
            "one_time": False,
        }
    ]
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    sign_config_file()
    status, body = client.post_json("/config/reload", {}, auth=True)
    if status != 200:
        raise RuntimeError(f"could not load tokenization seed config: HTTP {status}: {body}")

    def restore():
        if original_cfg is None:
            CONFIG_PATH.unlink(missing_ok=True)
        else:
            CONFIG_PATH.write_bytes(original_cfg)
        if original_sig is None:
            CONFIG_SIGN_PATH.unlink(missing_ok=True)
        else:
            CONFIG_SIGN_PATH.write_bytes(original_sig)

    atexit.register(restore)


def configure_mac_profile(client, kid):
    original_cfg = CONFIG_PATH.read_bytes() if CONFIG_PATH.exists() else None
    original_sig = CONFIG_SIGN_PATH.read_bytes() if CONFIG_SIGN_PATH.exists() else None
    config = read_config_or_empty()
    config["mac_profiles"] = [
        {
            "name": MAC_PROFILE,
            "kid": kid,
            "context": "tenant=fuzz;field=pan;purpose=blind_index;version=1",
        }
    ]
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    sign_config_file()
    status, body = client.post_json("/config/reload", {}, auth=True)
    if status != 200:
        raise RuntimeError(f"could not load mac seed config: HTTP {status}: {body}")

    def restore():
        if original_cfg is None:
            CONFIG_PATH.unlink(missing_ok=True)
        else:
            CONFIG_PATH.write_bytes(original_cfg)
        if original_sig is None:
            CONFIG_SIGN_PATH.unlink(missing_ok=True)
        else:
            CONFIG_SIGN_PATH.write_bytes(original_sig)

    atexit.register(restore)


def configure_masking_profile(client, kid):
    original_cfg = CONFIG_PATH.read_bytes() if CONFIG_PATH.exists() else None
    original_sig = CONFIG_SIGN_PATH.read_bytes() if CONFIG_SIGN_PATH.exists() else None
    config = read_config_or_empty()
    config["masking_profiles"] = [
        {
            "name": MASKING_PROFILE,
            "kid": kid,
            "visible_first": 0,
            "visible_last": 4,
            "mask_char": "*",
            "min_len": 12,
            "max_len": 19,
        }
    ]
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    sign_config_file()
    status, body = client.post_json("/config/reload", {}, auth=True)
    if status != 200:
        raise RuntimeError(f"could not load masking seed config: HTTP {status}: {body}")

    def restore():
        if original_cfg is None:
            CONFIG_PATH.unlink(missing_ok=True)
        else:
            CONFIG_PATH.write_bytes(original_cfg)
        if original_sig is None:
            CONFIG_SIGN_PATH.unlink(missing_ok=True)
        else:
            CONFIG_SIGN_PATH.write_bytes(original_sig)

    atexit.register(restore)


def configure_commitment_profile(client, kid):
    original_cfg = CONFIG_PATH.read_bytes() if CONFIG_PATH.exists() else None
    original_sig = CONFIG_SIGN_PATH.read_bytes() if CONFIG_SIGN_PATH.exists() else None
    config = read_config_or_empty()
    config["commitment_profiles"] = [
        {
            "name": COMMITMENT_PROFILE,
            "kid": kid,
            "context": "tenant=fuzz;field=pan;purpose=commitment;version=1",
            "max_plaintext_len": 128,
            "opening_len": 32,
        }
    ]
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    sign_config_file()
    status, body = client.post_json("/config/reload", {}, auth=True)
    if status != 200:
        raise RuntimeError(f"could not load commitment seed config: HTTP {status}: {body}")

    def restore():
        if original_cfg is None:
            CONFIG_PATH.unlink(missing_ok=True)
        else:
            CONFIG_PATH.write_bytes(original_cfg)
        if original_sig is None:
            CONFIG_SIGN_PATH.unlink(missing_ok=True)
        else:
            CONFIG_SIGN_PATH.write_bytes(original_sig)

    atexit.register(restore)


def configure_sharing_profile(client, kid):
    original_cfg = CONFIG_PATH.read_bytes() if CONFIG_PATH.exists() else None
    original_sig = CONFIG_SIGN_PATH.read_bytes() if CONFIG_SIGN_PATH.exists() else None
    config = read_config_or_empty()
    config["sharing_profiles"] = [
        {
            "name": SHARING_PROFILE,
            "kid": kid,
            "threshold": 3,
            "shares": 5,
            "max_secret_len": 4096,
            "context": "tenant=fuzz;purpose=secret_sharing;version=1",
        }
    ]
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    sign_config_file()
    status, body = client.post_json("/config/reload", {}, auth=True)
    if status != 200:
        raise RuntimeError(f"could not load sharing seed config: HTTP {status}: {body}")

    def restore():
        if original_cfg is None:
            CONFIG_PATH.unlink(missing_ok=True)
        else:
            CONFIG_PATH.write_bytes(original_cfg)
        if original_sig is None:
            CONFIG_SIGN_PATH.unlink(missing_ok=True)
        else:
            CONFIG_SIGN_PATH.write_bytes(original_sig)

    atexit.register(restore)

