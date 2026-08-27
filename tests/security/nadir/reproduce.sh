#!/usr/bin/env bash

# Rebuild the isolated Vectis fixture and reevaluate a Nadir v4 finding.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$#" -ne 1 ]]; then
  echo "usage: bash tests/security/nadir/reproduce.sh <finding.json>" >&2
  exit 2
fi

artifact="$1"
if [[ ! -f "${artifact}" ]]; then
  echo "Nadir finding artifact does not exist: ${artifact}" >&2
  exit 2
fi
artifact="$(cd "$(dirname "${artifact}")" && pwd)/$(basename "${artifact}")"

NADIR_COMMAND=reproduce \
NADIR_VERIFY_AUDIT_ALWAYS=true \
exec bash "${SCRIPT_DIR}/run.sh" --artifact "${artifact}"
