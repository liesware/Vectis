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
    ONE_TIME_TOKENIZATION_PROFILE,
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


def configure_time_attestation_offline(client):
    """Install local-unavailable sources and return the exact restore snapshot."""
    original_cfg = CONFIG_PATH.read_bytes() if CONFIG_PATH.exists() else None
    original_sig = CONFIG_SIGN_PATH.read_bytes() if CONFIG_SIGN_PATH.exists() else None
    snapshot = (original_cfg, original_sig)
    try:
        config = read_config_or_empty()
        config["time_attestation"] = {
            "nts_server": "localhost",
            "roughtime_server": "127.0.0.1:9",
        }
        CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
        sign_config_file()
        status, body = client.post_json("/config/reload", {}, auth=True)
        if status != 200:
            raise RuntimeError(f"could not load offline time-attestation config: HTTP {status}: {body}")
        return snapshot
    except Exception:
        _restore_time_attestation_files(snapshot)
        try:
            client.post_json("/config/reload", {}, auth=True)
        except Exception:
            pass
        raise


def restore_time_attestation_config(client, snapshot):
    _restore_time_attestation_files(snapshot)
    status, body = client.post_json("/config/reload", {}, auth=True)
    if status != 200:
        raise RuntimeError(f"could not restore time-attestation config: HTTP {status}: {body}")


def _restore_time_attestation_files(snapshot):
    original_cfg, original_sig = snapshot
    if original_cfg is None:
        CONFIG_PATH.unlink(missing_ok=True)
    else:
        CONFIG_PATH.write_bytes(original_cfg)
    if original_sig is None:
        CONFIG_SIGN_PATH.unlink(missing_ok=True)
    else:
        CONFIG_SIGN_PATH.write_bytes(original_sig)


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


def _configure_tokenization_profiles(client, profiles, context):
    original_cfg = CONFIG_PATH.read_bytes() if CONFIG_PATH.exists() else None
    original_sig = CONFIG_SIGN_PATH.read_bytes() if CONFIG_SIGN_PATH.exists() else None
    config = read_config_or_empty()
    config["tokenization_profiles"] = profiles
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    sign_config_file()
    status, body = client.post_json("/config/reload", {}, auth=True)
    if status != 200:
        raise RuntimeError(f"could not load {context} config: HTTP {status}: {body}")

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
    _configure_tokenization_profiles(
        client,
        [
            {
                "name": TOKENIZATION_PROFILE,
                "kid": kid,
                "token_prefix": "tok_fuzz",
                "token_len": 32,
                "max_plaintext_len": 1024,
                "one_time": False,
            }
        ],
        "tokenization seed",
    )


def configure_one_time_tokenization_profiles(client, kid):
    _configure_tokenization_profiles(
        client,
        [
            {
                "name": TOKENIZATION_PROFILE,
                "kid": kid,
                "token_prefix": "tok_fuzz",
                "token_len": 32,
                "max_plaintext_len": 1024,
                "one_time": False,
            },
            {
                "name": ONE_TIME_TOKENIZATION_PROFILE,
                "kid": kid,
                "token_prefix": "tok_fuzz_once",
                "token_len": 32,
                "max_plaintext_len": 1024,
                "one_time": True,
            },
        ],
        "one-time tokenization seed",
    )


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


def configure_lifecycle_profiles(client, batches):
    """Load one complete, uniquely named profile set for every lifecycle KID
    across all iterations, signing and reloading the config a single time.

    `batches` is a list of {state: kid} maps (one per fuzz iteration). Each KID
    is bound only within its batch, so the profile names carry the batch index to
    stay globally unique. Returns the matching list of {state: {role: name}} maps.
    Signing the config spawns a `cargo` subprocess, so doing it once here — rather
    than once per iteration — is the whole point of taking every batch at once.
    """
    original_cfg = CONFIG_PATH.read_bytes() if CONFIG_PATH.exists() else None
    original_sig = CONFIG_SIGN_PATH.read_bytes() if CONFIG_SIGN_PATH.exists() else None
    config = read_config_or_empty()

    profiles_per_batch = []
    fpe_profiles = []
    tokenization_profiles = []
    mac_profiles = []
    masking_profiles = []
    commitment_profiles = []
    sharing_profiles = []
    state_codes = {
        "active": "a",
        "retired": "r",
        "disabled": "d",
        "compromised": "c",
        "destroyed": "x",
    }
    for batch_index, kids in enumerate(batches):
        batch_profiles = {}
        for label, kid in kids.items():
            names = {
                "fpe": f"lifecycle-{batch_index}-{label}-fpe-v1",
                "token": f"lifecycle-{batch_index}-{label}-token-v1",
                "mac": f"lifecycle-{batch_index}-{label}-mac-v1",
                "mask": f"lifecycle-{batch_index}-{label}-mask-v1",
                "commitment": f"lifecycle-{batch_index}-{label}-commitment-v1",
                "sharing": f"lifecycle-{batch_index}-{label}-sharing-3of5-v1",
            }
            batch_profiles[label] = names
            context_aad = f"tenant=fuzz;purpose=lifecycle;batch={batch_index};state={label};version=1"
            fpe_profiles.append({
                "name": names["fpe"],
                "fpe_version": "fpe-ff1-2025",
                "alphabet": "0123456789",
                "min_len": 6,
                "max_len": 32,
                "tweak_aad": context_aad,
                "kid": kid,
            })
            tokenization_profiles.append({
                "name": names["token"],
                "kid": kid,
                # Token prefixes are limited to 16 characters. Hex batch IDs
                # plus a one-letter lifecycle code remain unique and compact.
                "token_prefix": f"tl{batch_index:x}{state_codes[label]}",
                "token_len": 32,
                "max_plaintext_len": 1024,
                "one_time": False,
            })
            mac_profiles.append({
                "name": names["mac"],
                "kid": kid,
                "context": context_aad,
            })
            masking_profiles.append({
                "name": names["mask"],
                "kid": kid,
                "visible_first": 0,
                "visible_last": 4,
                "mask_char": "*",
                "min_len": 12,
                "max_len": 19,
            })
            commitment_profiles.append({
                "name": names["commitment"],
                "kid": kid,
                "context": context_aad,
                "max_plaintext_len": 128,
                "opening_len": 32,
            })
            sharing_profiles.append({
                "name": names["sharing"],
                "kid": kid,
                "threshold": 3,
                "shares": 5,
                "max_secret_len": 128,
                "context": context_aad,
            })
        profiles_per_batch.append(batch_profiles)

    config["fpe_profiles"] = fpe_profiles
    config["tokenization_profiles"] = tokenization_profiles
    config["mac_profiles"] = mac_profiles
    config["masking_profiles"] = masking_profiles
    config["commitment_profiles"] = commitment_profiles
    config["sharing_profiles"] = sharing_profiles
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    sign_config_file()
    status, body = client.post_json("/config/reload", {}, auth=True)
    if status != 200:
        raise RuntimeError(f"could not load lifecycle profile config: HTTP {status}: {body}")

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
    return profiles_per_batch
