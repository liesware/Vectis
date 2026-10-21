"""Signed fixture definitions private to the performance suite."""

import json
from pathlib import Path
import sys

from catalog import PROFILE_SPECS

ACTIONS = ["fpe-encrypt", "fpe-decrypt", "token-encode", "token-decode",
           "token-deterministic-encode", "token-deterministic-decode", "subject-create",
           "mac-create", "mac-verify", "index-create", "index-verify", "mask", "commit-create",
           "commit-verify", "share-split", "share-combine", "symmetric", "sign", "self-test"]


def read_env(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines()
                if line.strip() and not line.startswith("#"))


def build_fixtures(app):
    config = {"version": "v1", "routes": [], "remote_routes": [],
              "fpe_profiles": [], "tokenization_profiles": [], "deterministic_tokenization_profiles": [],
              "mac_profiles": [], "masking_profiles": [], "commitment_profiles": [], "sharing_profiles": []}
    specs = [spec for spec in PROFILE_SPECS if spec["kid_env"] in app]
    if not specs:
        raise ValueError("app.env has no performance KID")
    grants = [{"kid": app[spec["kid_env"]], "actions": ACTIONS} for spec in specs]
    config["permissions"] = [{"client": app["K6_CLIENT"], "apikey_hash": app["K6_APIKEY_HASH"],
                              "status": "active", "permissions": grants + [{"kid": "*", "actions": ["metrics"]}]}]
    context = "tenant=k6;purpose=performance;version=1"
    fixtures = {"version": 1, "url": app["K6_BASE_URL"], "apikey": app["K6_APIKEY"], "profiles": {}}
    for spec in specs:
        slug, kid = spec["slug"], app[spec["kid_env"]]
        profiles = {"fpe": {}, "token": {}, "token-deterministic": {}}
        for mode in ("none", "stored"):
            for auth in (False, True):
                name = f"{slug}-fpe-{mode}-{'auth' if auth else 'legacy'}"
                profiles["fpe"][f"{mode}-{'auth' if auth else 'legacy'}"] = name
                config["fpe_profiles"].append({
                    "name": name, "kid": kid,
                    "subject_mode": mode, "authenticated": auth, "fpe_version": "fpe-ff1-2025",
                    "alphabet_preset": "num", "min_len": 16, "max_len": 16, "tweak_aad": context})
            profiles["token"][mode] = f"{slug}-token-{mode}"
            profiles["token-deterministic"][mode] = f"{slug}-det-{mode}"
            config["tokenization_profiles"].append({
                "name": f"{slug}-token-{mode}", "kid": kid, "subject_mode": mode,
                "token_prefix": "k6", "token_len": 32, "max_plaintext_len": 128, "one_time": False})
            config["deterministic_tokenization_profiles"].append({
                "name": f"{slug}-det-{mode}", "kid": kid, "subject_mode": mode,
                "context": context, "min_plaintext_len": 1, "max_plaintext_len": 128})
        config["mac_profiles"].append({"name": f"{slug}-mac", "kid": kid, "context": context})
        config["masking_profiles"].append({"name": f"{slug}-mask", "kid": kid, "visible_first": 0,
                                           "visible_last": 4, "mask_char": "*", "min_len": 16, "max_len": 16})
        config["commitment_profiles"].append({"name": f"{slug}-commit", "kid": kid, "context": context,
                                              "max_plaintext_len": 128, "opening_len": 32})
        config["sharing_profiles"].append({"name": f"{slug}-share", "kid": kid, "context": context,
                                           "threshold": 3, "shares": 5, "max_secret_len": 128})
        profiles.update(mac=f"{slug}-mac", index=f"{slug}-mac", masking=f"{slug}-mask",
                        commitment=f"{slug}-commit", sharing=f"{slug}-share")
        fixtures["profiles"][spec["name"]] = {"kid": kid, "subject": None, "profiles": profiles}
    return config, fixtures


def profiles_config(app):
    return build_fixtures(app)[0]


if __name__ == "__main__":
    site = Path(sys.argv[1])
    config, fixtures = build_fixtures(read_env(site / "app.env"))
    (site / "config.json").write_text(json.dumps(config, indent=2))
    fixture_path = site / "fixtures.json"
    fixture_path.write_text(json.dumps(fixtures, indent=2))
    fixture_path.chmod(0o600)
