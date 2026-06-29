import os
from pathlib import Path


def config_value(name):
    value = os.environ.get(name)
    if value:
        return value.strip()

    paths = [Path.cwd() / ".env", Path(__file__).resolve().parents[1] / ".env"]
    for path in paths:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() == name:
                return value.strip().strip('"').strip("'")

    return None


def require_apikey(cli_value=None):
    value = cli_value or config_value("VECTIS_APIKEY")
    if not value:
        raise RuntimeError("VECTIS_APIKEY must be provided with --apikey, environment, or .env")

    return value
