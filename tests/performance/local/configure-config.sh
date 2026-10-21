#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SITE_DIR="${K6_SITE_DIR:-${SCRIPT_DIR}/site}"
python3 "${SCRIPT_DIR}/provision.py" "${SITE_DIR}"
(cd "${SITE_DIR}" && ./bin/vectis config sign --output json >/dev/null)
echo "Signed performance config."
