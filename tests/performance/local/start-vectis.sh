#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${K6_SITE_DIR:-${SCRIPT_DIR}/site}"
exec ./bin/vectis serve
