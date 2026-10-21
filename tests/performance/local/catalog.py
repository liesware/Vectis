"""Private shared metadata, not an endpoint/request definition language."""

import json
from pathlib import Path


def validate_catalog(value):
    def require(condition):
        if not condition:
            raise ValueError("invalid performance catalog")

    require(isinstance(value, dict) and type(value.get("version")) is int and value["version"] == 1)
    profiles, targets = value.get("profiles"), value.get("targets")
    require(isinstance(profiles, list) and bool(profiles))
    require(isinstance(targets, list) and bool(targets))
    for entries, fields in ((profiles, ("name", "slug", "kid_env")),
                            (targets, ("name", "family"))):
        for entry in entries:
            require(isinstance(entry, dict))
            require(all(isinstance(entry.get(field), str) and entry[field] for field in fields))
        for field in fields if entries is profiles else ("name",):
            require(len({entry[field] for entry in entries}) == len(entries))
    families = {}
    for target in targets:
        require(target["name"] != "all")
        require(all(type(target.get(field)) is bool for field in ("batch", "subject", "authenticated")))
        operations = target.get("operations")
        require(isinstance(operations, list) and bool(operations))
        require(all(isinstance(op, str) and op for op in operations))
        require(len(set(operations)) == len(operations) and "flow" not in operations)
        require(target["name"] == target["family"] + ("-batch" if target["batch"] else ""))
        signature = (target["subject"], target["authenticated"], tuple(operations))
        require(families.setdefault(target["family"], signature) == signature)
    require(len({t["name"].replace("-", "_") for t in targets}) == len(targets))
    return value


CATALOG = validate_catalog(json.loads((Path(__file__).resolve().parents[1] / "catalog.json").read_text()))
PROFILE_SPECS = tuple(CATALOG["profiles"])
PROFILES = tuple(profile["name"] for profile in PROFILE_SPECS)
TARGET_SPECS = {target["name"]: target for target in CATALOG["targets"]}
TARGETS = ("all", *TARGET_SPECS)
